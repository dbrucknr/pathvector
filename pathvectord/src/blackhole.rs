//! RFC 7999 BLACKHOLE authorization scope — a validated value, no I/O.
//!
//! RFC 7999 §3.3: "BGP speakers in a bilateral peering relationship using the
//! BLACKHOLE community MUST only accept and honor BGP announcements carrying
//! the BLACKHOLE community under the two following conditions:
//!
//! - The announced prefix is covered by an equal or shorter prefix that the
//!   neighboring network is authorized to advertise.
//! - The receiving party agreed to honor the BLACKHOLE community on the
//!   particular BGP session."
//!
//! [`BlackholeScope`] is the operator's statement of both conditions for one
//! session: configuring it *is* the agreement (condition 2), and its prefixes
//! are the authorized covering prefixes (condition 1). A session without a
//! scope honors no BLACKHOLE announcements — RFC 7999 §4: "Without an explicit
//! configuration directive set by the operator, network elements SHOULD NOT
//! discard traffic destined towards IP prefixes that are tagged with the
//! BLACKHOLE community."
//!
//! The type can only be built through [`BlackholeScope::new`] (or by
//! deserializing, which calls it), so an empty scope — "agreed, but nothing is
//! authorized", which can never honor anything and is almost certainly a
//! mistake — and a prefix with host bits set (which would silently authorize
//! a different range than written) cannot exist.

use std::net::{Ipv4Addr, Ipv6Addr};

use pathvector_types::{IpAddress, Nlri};
use serde::{Deserialize, Serialize};

/// Why a [`BlackholeScope`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlackholeScopeError {
    /// No prefix was given. Agreeing to honor BLACKHOLE on a session while
    /// authorizing no prefix honors nothing; omit the setting to deny instead.
    Empty,
    /// The text is not an IPv4 or IPv6 prefix in CIDR notation.
    NotAPrefix(String),
    /// The prefix has host bits set (`192.0.2.5/24`), so the written range is
    /// not the range it would authorize. Write the network address.
    HostBitsSet(String),
}

impl std::fmt::Display for BlackholeScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str(
                "blackhole_authorized_prefixes is empty; list the prefixes the peer may \
                 blackhole, or omit the setting to deny BLACKHOLE on this session",
            ),
            Self::NotAPrefix(s) => write!(f, "{s:?} is not an IPv4/IPv6 prefix in CIDR notation"),
            Self::HostBitsSet(s) => write!(
                f,
                "{s:?} has host bits set; write the network address (RFC 7999 §3.3 scopes a \
                 session by covering prefix)"
            ),
        }
    }
}

impl std::error::Error for BlackholeScopeError {}

/// The prefixes a peer is authorized to blackhole on one session (RFC 7999
/// §3.3), both address families, never empty, every prefix in canonical form.
///
/// A route is covered when some scope prefix is equal to or shorter than it
/// and contains it ([`covers`](Self::covers)); a /32 or /128 host blackhole
/// inside an authorized /24 or /48 is therefore covered, while a prefix
/// shorter than every scope entry is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackholeScope {
    // Boxed so the `Option<BlackholeScope>` in `PeerConfig` (carried in
    // `DaemonCommand::AddPeer`) costs one pointer, not two `Vec`s, per peer.
    entries: Box<Entries>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entries {
    v4: Vec<Nlri<Ipv4Addr>>,
    v6: Vec<Nlri<Ipv6Addr>>,
}

impl BlackholeScope {
    /// Builds a scope from CIDR strings (`"192.0.2.0/24"`, `"2001:db8::/32"`).
    ///
    /// # Errors
    ///
    /// [`BlackholeScopeError::Empty`] for no prefixes,
    /// [`NotAPrefix`](BlackholeScopeError::NotAPrefix) for text that is not an
    /// IPv4/IPv6 CIDR prefix, and [`HostBitsSet`](BlackholeScopeError::HostBitsSet)
    /// for a prefix that is not in canonical form.
    pub fn new<I, S>(prefixes: I) -> Result<Self, BlackholeScopeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for text in prefixes {
            let text = text.as_ref();
            if let Ok(n) = text.parse::<Nlri<Ipv4Addr>>() {
                if n.masked() != n {
                    return Err(BlackholeScopeError::HostBitsSet(text.to_owned()));
                }
                v4.push(n);
            } else if let Ok(n) = text.parse::<Nlri<Ipv6Addr>>() {
                if n.masked() != n {
                    return Err(BlackholeScopeError::HostBitsSet(text.to_owned()));
                }
                v6.push(n);
            } else {
                return Err(BlackholeScopeError::NotAPrefix(text.to_owned()));
            }
        }
        if v4.is_empty() && v6.is_empty() {
            return Err(BlackholeScopeError::Empty);
        }
        // Sorted and de-duplicated so equal scopes compare equal and the
        // sidecar round-trips byte-for-byte.
        v4.sort_unstable();
        v4.dedup();
        v6.sort_unstable();
        v6.dedup();
        Ok(Self {
            entries: Box::new(Entries { v4, v6 }),
        })
    }

    /// RFC 7999 §3.3 condition 1: is `announced` covered by an equal or shorter
    /// prefix in this scope?
    #[must_use]
    pub fn covers<A: ScopeFamily>(&self, announced: &Nlri<A>) -> bool {
        A::entries(self).iter().any(|s| covers(s, announced))
    }
}

/// `scope` equal to or shorter than `announced` and containing it.
fn covers<A: IpAddress>(scope: &Nlri<A>, announced: &Nlri<A>) -> bool {
    scope.prefix_len() <= announced.prefix_len() && scope.contains(announced.prefix().ip())
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for std::net::Ipv4Addr {}
    impl Sealed for std::net::Ipv6Addr {}
}

/// Address families a [`BlackholeScope`] holds entries for (IPv4 and IPv6).
/// Sealed: it only selects which of the scope's two lists to consult.
pub trait ScopeFamily: IpAddress + sealed::Sealed {
    #[doc(hidden)]
    fn entries(scope: &BlackholeScope) -> &[Nlri<Self>];
}

impl ScopeFamily for Ipv4Addr {
    fn entries(scope: &BlackholeScope) -> &[Nlri<Self>] {
        &scope.entries.v4
    }
}

impl ScopeFamily for Ipv6Addr {
    fn entries(scope: &BlackholeScope) -> &[Nlri<Self>] {
        &scope.entries.v6
    }
}

impl Serialize for BlackholeScope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let all: Vec<String> = self
            .entries
            .v4
            .iter()
            .map(ToString::to_string)
            .chain(self.entries.v6.iter().map(ToString::to_string))
            .collect();
        all.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BlackholeScope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let all = Vec::<String>::deserialize(d)?;
        Self::new(all).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Nlri<Ipv4Addr> {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> Nlri<Ipv6Addr> {
        s.parse().unwrap()
    }

    /// RFC 7999 §3.3: "covered by an equal or shorter prefix" — a /32 inside an
    /// authorized /24 is covered, the /24 itself is covered (equal), a sibling
    /// /24 and a *shorter* prefix are not.
    #[test]
    fn covers_is_equal_or_shorter_scope_prefix() {
        let s = BlackholeScope::new(["192.0.2.0/24", "2001:db8:1::/48"]).unwrap();
        assert!(s.covers(&v4("192.0.2.77/32")), "host route inside the /24");
        assert!(s.covers(&v4("192.0.2.0/24")), "equal prefix");
        assert!(s.covers(&v4("192.0.2.128/25")));
        assert!(!s.covers(&v4("192.0.3.1/32")), "outside the scope");
        assert!(
            !s.covers(&v4("192.0.0.0/16")),
            "shorter than the scope entry"
        );
        assert!(
            !s.covers(&v4("0.0.0.0/0")),
            "default route is never covered"
        );
        assert!(s.covers(&v6("2001:db8:1::1/128")));
        assert!(!s.covers(&v6("2001:db8:2::1/128")));
        assert!(!s.covers(&v6("2001:db8::/32")));
    }

    /// A family with no entry authorizes nothing in that family even if the
    /// other family is configured (no cross-family leakage).
    #[test]
    fn families_are_independent() {
        let only4 = BlackholeScope::new(["10.0.0.0/8"]).unwrap();
        assert!(only4.covers(&v4("10.1.2.3/32")));
        assert!(!only4.covers(&v6("::ffff:10.1.2.3/128")));
        assert!(!only4.covers(&v6("::/0")));
    }

    #[test]
    fn empty_scope_is_unrepresentable() {
        assert_eq!(
            BlackholeScope::new(Vec::<String>::new()),
            Err(BlackholeScopeError::Empty)
        );
    }

    #[test]
    fn rejects_non_prefix_text() {
        assert!(matches!(
            BlackholeScope::new(["not-a-prefix"]),
            Err(BlackholeScopeError::NotAPrefix(_))
        ));
        assert!(matches!(
            BlackholeScope::new(["192.0.2.0/33"]),
            Err(BlackholeScopeError::NotAPrefix(_))
        ));
    }

    /// `192.0.2.5/24` would authorize `192.0.2.0/24`, not what was written.
    #[test]
    fn rejects_host_bits() {
        assert!(matches!(
            BlackholeScope::new(["192.0.2.5/24"]),
            Err(BlackholeScopeError::HostBitsSet(_))
        ));
        assert!(matches!(
            BlackholeScope::new(["2001:db8::1/32"]),
            Err(BlackholeScopeError::HostBitsSet(_))
        ));
    }

    #[test]
    fn dedups_and_sorts() {
        let a = BlackholeScope::new(["10.0.0.0/8", "192.0.2.0/24", "10.0.0.0/8"]).unwrap();
        let b = BlackholeScope::new(["192.0.2.0/24", "10.0.0.0/8"]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.entries.v4.len(), 2);
    }

    #[test]
    fn serde_round_trips_through_toml() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct W {
            scope: BlackholeScope,
        }
        let w: W = toml::from_str(r#"scope = ["2001:db8::/32", "192.0.2.0/24"]"#).unwrap();
        let text = toml::to_string(&w).unwrap();
        assert_eq!(toml::from_str::<W>(&text).unwrap(), w);
        assert!(toml::from_str::<W>("scope = []").is_err());
        assert!(toml::from_str::<W>(r#"scope = ["192.0.2.1/24"]"#).is_err());
    }
}
