//! [`TcpMd5Key`]: a TCP MD5 signature key that is valid by construction.

use std::fmt;
use std::str::FromStr;

/// Longest key the Linux kernel accepts: `TCP_MD5SIG_MAXKEYLEN` in
/// `include/uapi/linux/tcp.h`.
///
/// RFC 2385 §4.5 asks implementations to support "at minimum a key composed
/// of a string of printable ASCII of 80 bytes or less", so this limit is also
/// the smallest one a conforming speaker may impose.
pub const TCP_MD5SIG_MAXKEYLEN: usize = 80;

/// A TCP MD5 signature key (RFC 2385): 1 to [`TCP_MD5SIG_MAXKEYLEN`] bytes.
///
/// The constructors reject the two lengths the kernel would not treat as
/// "sign with this key":
///
/// - **Empty.** Linux reads a zero `tcpm_keylen` as a request to *delete*
///   the key for that peer (`tcp_v4_parse_md5_keys`:
///   `if (!cmd.tcpm_keylen) return tcp_md5_do_del(...)`), so an empty
///   configured password would remove protection instead of enabling it.
///   Deleting a key is a separate operation:
///   [`remove_tcp_md5_key`](super::remove_tcp_md5_key).
/// - **Longer than 80 bytes.** The kernel returns `EINVAL`
///   (`if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN) return -EINVAL`).
///
/// RFC 2385 §2.0 leaves the key's form open ("The nature of the key is
/// deliberately left unspecified"), and the kernel stores it as binary, so
/// any bytes are accepted. Text keys come in through [`FromStr`] or
/// `TryFrom<&str>` and use their UTF-8 bytes.
///
/// `Debug` never prints the key. There is no `Display`.
///
/// # Examples
///
/// ```
/// use pathvector_sys::tcp::{TcpMd5Key, TcpMd5KeyError};
///
/// let key: TcpMd5Key = "s3cr3t".parse().unwrap();
/// assert_eq!(format!("{key:?}"), "TcpMd5Key(<redacted>)");
///
/// assert_eq!("".parse::<TcpMd5Key>(), Err(TcpMd5KeyError::Empty));
/// assert_eq!(
///     TcpMd5Key::new(&[b'x'; 81]),
///     Err(TcpMd5KeyError::TooLong { len: 81 }),
/// );
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct TcpMd5Key {
    bytes: [u8; TCP_MD5SIG_MAXKEYLEN],
    /// Always in `1..=TCP_MD5SIG_MAXKEYLEN`.
    len: u8,
}

impl TcpMd5Key {
    /// Builds a key from raw bytes.
    ///
    /// # Errors
    ///
    /// [`TcpMd5KeyError::Empty`] for zero bytes and
    /// [`TcpMd5KeyError::TooLong`] for more than [`TCP_MD5SIG_MAXKEYLEN`].
    pub fn new(key: &[u8]) -> Result<Self, TcpMd5KeyError> {
        if key.is_empty() {
            return Err(TcpMd5KeyError::Empty);
        }
        let too_long = TcpMd5KeyError::TooLong { len: key.len() };
        if key.len() > TCP_MD5SIG_MAXKEYLEN {
            return Err(too_long);
        }
        let len = u8::try_from(key.len()).map_err(|_| too_long)?;
        let mut bytes = [0u8; TCP_MD5SIG_MAXKEYLEN];
        bytes[..key.len()].copy_from_slice(key);
        Ok(Self { bytes, len })
    }

    /// The key bytes, for the OS adapter only.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for TcpMd5Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpMd5Key(<redacted>)")
    }
}

impl FromStr for TcpMd5Key {
    type Err = TcpMd5KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.as_bytes())
    }
}

impl TryFrom<&str> for TcpMd5Key {
    type Error = TcpMd5KeyError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s.as_bytes())
    }
}

impl TryFrom<&[u8]> for TcpMd5Key {
    type Error = TcpMd5KeyError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        Self::new(b)
    }
}

/// Why a byte string is not a valid [`TcpMd5Key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMd5KeyError {
    /// The key has no bytes. Linux would delete the peer's key instead of
    /// installing one.
    Empty,
    /// The key is longer than [`TCP_MD5SIG_MAXKEYLEN`].
    TooLong {
        /// Length of the rejected key, in bytes.
        len: usize,
    },
}

impl fmt::Display for TcpMd5KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str(
                "TCP MD5 key must not be empty (an empty key would delete the peer's key, \
                 not enable authentication)",
            ),
            Self::TooLong { len } => write!(
                f,
                "TCP MD5 key too long: {len} bytes (max {TCP_MD5SIG_MAXKEYLEN})"
            ),
        }
    }
}

impl std::error::Error for TcpMd5KeyError {}
