//! Non-Linux stub for [`FibWriter`].
//!
//! All methods are no-ops that return `Ok(())`. This file is compiled only on
//! non-Linux platforms (macOS for development); on Linux the compiler sees
//! `linux.rs` exclusively, so neither file produces dead-code warnings on the
//! other platform.

#![allow(clippy::unused_async)]

use std::net::{Ipv4Addr, Ipv6Addr};

/// No-op FIB writer for non-Linux platforms.
///
/// Preserves the API surface of the Linux [`FibWriter`] so `pathvectord` can
/// use `FibWriter` unconditionally without `#[cfg]` at call sites.
pub struct FibWriter;

impl FibWriter {
    /// Returns `Ok(Self)` unconditionally — no OS resources are acquired.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub fn new(_table: u32, _metric: u32) -> std::io::Result<Self> {
        Ok(Self)
    }

    /// No-op.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub async fn install_v4(
        &self,
        _dst: Ipv4Addr,
        _prefix_len: u8,
        _gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// No-op.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub async fn withdraw_v4(&self, _dst: Ipv4Addr, _prefix_len: u8) -> std::io::Result<()> {
        Ok(())
    }

    /// No-op.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub async fn install_v6(
        &self,
        _dst: Ipv6Addr,
        _prefix_len: u8,
        _gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// No-op.
    ///
    /// # Errors
    ///
    /// Never errors on non-Linux platforms.
    pub async fn withdraw_v6(&self, _dst: Ipv6Addr, _prefix_len: u8) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::FibWriter;

    #[test]
    fn new_returns_ok() {
        assert!(FibWriter::new(254, 20).is_ok());
    }

    #[tokio::test]
    async fn install_v4_is_noop() {
        let fw = FibWriter::new(254, 20).unwrap();
        assert!(
            fw.install_v4(Ipv4Addr::new(10, 0, 0, 0), 8, Ipv4Addr::new(192, 0, 2, 1))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn withdraw_v4_is_noop() {
        let fw = FibWriter::new(254, 20).unwrap();
        assert!(fw.withdraw_v4(Ipv4Addr::new(10, 0, 0, 0), 8).await.is_ok());
    }

    #[tokio::test]
    async fn install_v6_is_noop() {
        let fw = FibWriter::new(254, 20).unwrap();
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(
            fw.install_v6("2001:db8::".parse().unwrap(), 32, gw)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn withdraw_v6_is_noop() {
        let fw = FibWriter::new(254, 20).unwrap();
        assert!(
            fw.withdraw_v6("2001:db8::".parse().unwrap(), 32)
                .await
                .is_ok()
        );
    }
}
