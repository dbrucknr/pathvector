//! Linux `setsockopt(TCP_MD5SIG)`.

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::TCP_MD5SIG_MAXKEYLEN;

// Mirror of the kernel's `tcp_md5sig` from `<linux/tcp.h>`.
//
// Defined locally rather than using `libc::tcp_md5sig` because the libc crate
// does not expose `tcp_md5sig` on all Linux target architectures in all
// released versions (e.g. aarch64 with libc 0.2.x).
//
// Layout (128 + 2 + 1 + 1 + 4 + 80 = 216 bytes):
//   struct __kernel_sockaddr_storage tcpm_addr;  // 128 bytes
//   u16  __tcpm_pad1;                            //   2 bytes
//   u8   tcpm_keylen;                            //   1 byte
//   u8   __tcpm_pad2;                            //   1 byte
//   u32  __tcpm_pad3;                            //   4 bytes
//   u8   tcpm_key[TCP_MD5SIG_MAXKEYLEN];         //  80 bytes
//
// The current UAPI header declares `__u8 tcpm_flags; __u8 tcpm_prefixlen;
// __u16 tcpm_keylen; int tcpm_ifindex;` in the middle bytes. With flags and
// prefixlen zero this encodes the same bytes on little-endian targets only;
// issue #60 tracks mirroring the UAPI exactly. Field names mirror the kernel
// struct (`tcpm_*`), so keep them.
#[allow(clippy::struct_field_names)]
#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_pad1: u16,
    tcpm_keylen: u8,
    tcpm_pad2: u8,
    tcpm_pad3: u32,
    tcpm_key: [u8; TCP_MD5SIG_MAXKEYLEN],
}

/// Sets `TCP_MD5SIG` for `peer` on `socket`. An empty `key` deletes the
/// peer's key (`tcp_v4_parse_md5_keys`: `if (!cmd.tcpm_keylen) return
/// tcp_md5_do_del(...)`).
pub(super) fn set_md5sig_v4(socket: BorrowedFd<'_>, peer: Ipv4Addr, key: &[u8]) -> io::Result<()> {
    assert!(
        key.len() <= TCP_MD5SIG_MAXKEYLEN,
        "TcpMd5Key guarantees at most {TCP_MD5SIG_MAXKEYLEN} bytes"
    );

    // SAFETY: TcpMd5Sig is a C struct of plain integers and fixed-size byte
    // arrays, for which all-zero bytes are a valid value.
    let mut sig: TcpMd5Sig = unsafe { mem::zeroed() };

    // AF_INET is 2 and always fits in sa_family_t (u16).
    #[allow(clippy::cast_possible_truncation)]
    let addr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        // The kernel ignores the port: a key applies to every connection
        // to or from this address.
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(peer).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_storage is large enough to hold sockaddr_in
    // (guaranteed by POSIX). Only sizeof(sockaddr_in) bytes are copied into
    // the start of the storage; the rest stays zeroed.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(addr_in).cast::<u8>(),
            std::ptr::addr_of_mut!(sig.tcpm_addr).cast::<u8>(),
            mem::size_of::<libc::sockaddr_in>(),
        );
    }

    sig.tcpm_keylen = u8::try_from(key.len()).expect("at most 80 bytes, asserted above");
    sig.tcpm_key[..key.len()].copy_from_slice(key);

    // TcpMd5Sig is 216 bytes, which fits in socklen_t (u32).
    #[allow(clippy::cast_possible_truncation)]
    let len = mem::size_of::<TcpMd5Sig>() as libc::socklen_t;
    // SAFETY: `socket` is a live descriptor for the duration of the borrow,
    // `sig` is fully initialised, and `len` is its exact size.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            std::ptr::addr_of!(sig).cast::<libc::c_void>(),
            len,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
