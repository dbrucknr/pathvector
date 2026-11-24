//! ROA validity cache — RFC 6811 §2 Route Origin Validation, built on
//! [`routemap::RouteMap`].
//!
//! `RouteMap` gives a single-winner longest-prefix-match (`longest_match`) and
//! an exact-prefix index (`get`/`insert`/`remove`). RFC 6811 needs something
//! subtly different: it must consider **every** ROA whose prefix covers the
//! announced prefix at any length ≤ the announced length, not just the most
//! specific one — a *less specific* ROA can validate an announcement even
//! when the most specific covering ROA does not. `RouteMap` alone doesn't
//! hand back that whole set in one call, but it composes correctly:
//!
//! 1. **Fast `NotFound` short-circuit** — `longest_match_entry` on the
//!    announced prefix's base address. If this returns `None`, there is
//!    provably no covering ROA at *any* length (LPM guarantees: if the
//!    best/longest match doesn't exist, no shorter match exists either) →
//!    return `NotFound` immediately.
//! 2. **Slow path — only when step 1 found something** — walk candidate ROA
//!    prefix lengths from the announced length down to 0, calling `get` (exact
//!    match) at each length. Each hit yields a `Vec<RoaEntry>` (multiple ROAs
//!    can share one exact prefix — different max-lengths/ASNs); check each
//!    for `(asn == origin_asn && prefix_len <= max_len)`.
//!
//! See `pathvector-rpki/README.md` for a note on a possible future
//! `routemap` API (`covering_matches`) that would let step 2 collapse to a
//! single trie walk instead of a sequence of `get()` calls — tracked as a
//! follow-up, not required for this to be correct.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetx::{interfaces::IpAddress, prefix::IpPrefix};
use routemap::RouteMap;

use crate::pdu::Pdu;

/// RFC 6811 §2 origin validation state for a `(prefix, origin AS)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoaValidity {
    /// A covering ROA authorizes this exact origin AS for this prefix length.
    Valid,
    /// At least one covering ROA exists, but none authorize this origin AS
    /// and prefix length combination.
    Invalid,
    /// No ROA covers this prefix at all.
    NotFound,
}

/// One Route Origin Authorization: the origin AS and maximum prefix length
/// it's allowed to announce, for the exact prefix it's stored under in the
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoaEntry {
    max_len: u8,
    asn: u32,
}

/// One address family's ROA table.
struct FamilyTable<A: IpAddress>(RouteMap<A, Vec<RoaEntry>>);

impl<A: IpAddress> FamilyTable<A> {
    fn new() -> Self {
        Self(RouteMap::new())
    }

    /// Adds one ROA at `prefix`. Deduplicates against any existing entry with
    /// the same `(max_len, asn)` at that exact prefix — Serial Query replay
    /// can re-announce an already-known ROA, and without dedup a later
    /// withdrawal would remove only one of the duplicate copies, silently
    /// leaving a phantom entry behind.
    fn insert(&mut self, prefix: IpPrefix<A>, entry: RoaEntry) {
        let mut entries = self.0.get(prefix).cloned().unwrap_or_default();
        if !entries.contains(&entry) {
            entries.push(entry);
        }
        self.0.insert(prefix, entries);
    }

    /// Removes one ROA at `prefix`. If it was the last entry at that exact
    /// prefix, removes the `RouteMap` node entirely rather than leaving an
    /// empty `Vec` behind (an empty-but-present node would make the fast
    /// `NotFound` short-circuit in `validate` incorrectly see "some
    /// coverage" via `longest_match_entry`).
    fn remove(&mut self, prefix: IpPrefix<A>, entry: RoaEntry) {
        let Some(mut entries) = self.0.get(prefix).cloned() else {
            return;
        };
        entries.retain(|e| *e != entry);
        if entries.is_empty() {
            self.0.remove(prefix);
        } else {
            self.0.insert(prefix, entries);
        }
    }

    fn len(&self) -> usize {
        self.0.iter().map(|(_, entries)| entries.len()).sum()
    }

    /// RFC 6811 §2, composed from `RouteMap` primitives — see module docs.
    fn validate(&self, prefix: A, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        // Fast path: `longest_match_entry` finds the most specific *registered*
        // prefix containing `prefix`'s address, at *any* length — including
        // lengths longer (more specific) than `prefix_len`, which are not
        // "covering" in RFC 6811's sense (a covering ROA must have
        // `mask <= prefix_len`). So this can only be trusted in the `None`
        // direction: if nothing in the trie contains the address at all, then
        // nothing can cover it at any shorter length either. A `Some` result
        // does NOT mean a covering ROA exists — it might be more specific
        // than our query — so we still must walk ancestors to confirm.
        if self.0.longest_match_entry(prefix).is_none() {
            return RoaValidity::NotFound;
        }
        let mut saw_covering = false;
        for len in (0..=prefix_len).rev() {
            let Ok(ancestor) = IpPrefix::new(prefix, len) else {
                continue;
            };
            if let Some(entries) = self.0.get(ancestor) {
                saw_covering = true;
                // RFC 6811 §2: "no valid Route can have an Origin ASN of
                // zero [AS0] ... no Route can be Matched by a VRP whose ASN
                // is zero" — excluded explicitly here (not just relied upon
                // as "no real VRP has ASN 0") because `origin_asn == 0` is
                // also this crate's sentinel for the "NONE" Route Origin ASN
                // (a terminal `AS_SET` — see `RoaValidityCondition`), which
                // per the same section "cannot be Matched by any VRP".
                if entries
                    .iter()
                    .any(|e| e.asn != 0 && e.asn == origin_asn && prefix_len <= e.max_len)
                {
                    return RoaValidity::Valid;
                }
            }
        }
        if saw_covering {
            RoaValidity::Invalid
        } else {
            RoaValidity::NotFound
        }
    }
}

/// One decoded VRP change: announce or withdraw one `(prefix, max_len, asn)`.
///
/// This is what a Prefix PDU becomes once it has been checked as
/// representable. Staged transfers hold these instead of raw PDUs, so a
/// staged delta can only ever contain prefix changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VrpOp {
    announce: bool,
    vrp: Vrp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vrp {
    V4(IpPrefix<Ipv4Addr>, RoaEntry),
    V6(IpPrefix<Ipv6Addr>, RoaEntry),
}

impl VrpOp {
    /// Decodes the change a Prefix PDU describes. `None` for any other PDU,
    /// and for a prefix length the address family cannot represent (such a
    /// record is skipped, exactly as before — whether it should instead be
    /// reported as corrupt data is the separate prefix-bounds validation
    /// issue, #91).
    pub(crate) fn from_pdu(pdu: &Pdu) -> Option<Self> {
        match *pdu {
            Pdu::Ipv4Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => Some(Self {
                announce: flags.announce,
                vrp: Vrp::V4(
                    IpPrefix::new(prefix, prefix_len).ok()?,
                    RoaEntry { max_len, asn },
                ),
            }),
            Pdu::Ipv6Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => Some(Self {
                announce: flags.announce,
                vrp: Vrp::V6(
                    IpPrefix::new(prefix, prefix_len).ok()?,
                    RoaEntry { max_len, asn },
                ),
            }),
            _ => None,
        }
    }
}

/// A complete VRP set built off to the side — no locks, invisible to
/// validation until [`RoaTable::install`] swaps it in. Used to stage a full
/// (Reset Query) load.
pub(crate) struct Snapshot {
    v4: FamilyTable<Ipv4Addr>,
    v6: FamilyTable<Ipv6Addr>,
}

impl Snapshot {
    pub(crate) fn new() -> Self {
        Self {
            v4: FamilyTable::new(),
            v6: FamilyTable::new(),
        }
    }

    pub(crate) fn apply(&mut self, op: VrpOp) {
        match op.vrp {
            Vrp::V4(p, e) => apply_flagged(&mut self.v4, p, e, op.announce),
            Vrp::V6(p, e) => apply_flagged(&mut self.v6, p, e, op.announce),
        }
    }
}

/// Combined IPv4 + IPv6 ROA cache. Uses interior mutability so an
/// [`crate::RtrHandle`] can hand out cheap `Arc` clones while the RTR client
/// task applies incremental diffs from the wire.
pub struct RoaTable {
    v4: std::sync::RwLock<FamilyTable<Ipv4Addr>>,
    v6: std::sync::RwLock<FamilyTable<Ipv6Addr>>,
}

impl RoaTable {
    pub(crate) fn new() -> Self {
        Self {
            v4: std::sync::RwLock::new(FamilyTable::new()),
            v6: std::sync::RwLock::new(FamilyTable::new()),
        }
    }

    /// # Panics
    ///
    /// Panics only if the internal table lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[must_use]
    pub fn validate_v4(&self, prefix: Ipv4Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.v4
            .read()
            .unwrap()
            .validate(prefix, prefix_len, origin_asn)
    }

    /// # Panics
    ///
    /// Panics only if the internal table lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[must_use]
    pub fn validate_v6(&self, prefix: Ipv6Addr, prefix_len: u8, origin_asn: u32) -> RoaValidity {
        self.v6
            .read()
            .unwrap()
            .validate(prefix, prefix_len, origin_asn)
    }

    /// Total ROA entry count across both address families.
    ///
    /// # Panics
    ///
    /// Panics only if an internal table lock is poisoned (a prior holder
    /// panicked while holding it) — not an expected runtime condition.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.read().unwrap().len() + self.v6.read().unwrap().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies one Prefix PDU's announce/withdraw to the table. No-ops for
    /// any other `Pdu` variant (the client only calls this for
    /// `Pdu::Ipv4Prefix`/`Pdu::Ipv6Prefix`, but taking the whole enum keeps
    /// the call site in `client.rs` a single match-free line).
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn apply_prefix_pdu(&self, pdu: &Pdu) {
        match *pdu {
            Pdu::Ipv4Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => {
                let Ok(p) = IpPrefix::new(prefix, prefix_len) else {
                    return;
                };
                let entry = RoaEntry { max_len, asn };
                let mut table = self.v4.write().unwrap();
                apply_flagged(&mut table, p, entry, flags.announce);
            }
            Pdu::Ipv6Prefix {
                flags,
                prefix_len,
                max_len,
                prefix,
                asn,
            } => {
                let Ok(p) = IpPrefix::new(prefix, prefix_len) else {
                    return;
                };
                let entry = RoaEntry { max_len, asn };
                let mut table = self.v6.write().unwrap();
                apply_flagged(&mut table, p, entry, flags.announce);
            }
            _ => {}
        }
    }

    /// Replaces the whole VRP set with `snapshot` in O(1): both family locks
    /// are taken (always v4 then v6) and the trees swapped, so a validation
    /// sees either the old set or the new one — never a mixture, and never a
    /// partially loaded one.
    ///
    /// The previous trees are *returned*, not dropped here: freeing a
    /// 500 000-VRP tree is O(size), and doing it while the write guards are
    /// held would block validation for that long. The caller drops the
    /// [`Retired`] value once no lock is held.
    #[must_use = "drop the retired trees after releasing locks, not while holding them"]
    pub(crate) fn install(&self, snapshot: Snapshot) -> Retired {
        let mut v4 = self.v4.write().unwrap();
        let mut v6 = self.v6.write().unwrap();
        Retired {
            v4: std::mem::replace(&mut *v4, snapshot.v4),
            v6: std::mem::replace(&mut *v6, snapshot.v6),
        }
    }

    /// Applies a staged change set in order under both family locks, so a
    /// concurrent validation sees either none of it or all of it. The lock
    /// hold is O(`ops.len()`); a typical RPKI serial-to-serial delta is a
    /// few hundred to a few thousand VRPs.
    pub(crate) fn apply_delta(&self, ops: &[VrpOp]) {
        let mut v4 = self.v4.write().unwrap();
        let mut v6 = self.v6.write().unwrap();
        for op in ops {
            match op.vrp {
                Vrp::V4(p, e) => apply_flagged(&mut v4, p, e, op.announce),
                Vrp::V6(p, e) => apply_flagged(&mut v6, p, e, op.announce),
            }
        }
    }

    /// Removes all ROA data in O(1), returning the old trees for the caller
    /// to drop once no lock is held (see [`RoaTable::install`]).
    #[must_use = "drop the retired trees after releasing locks, not while holding them"]
    pub(crate) fn take_all(&self) -> Retired {
        self.install(Snapshot::new())
    }

    /// Clears all ROA data. The old trees are freed after the table locks
    /// are released.
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        drop(self.take_all());
    }
}

/// The previous generation's trees, swapped out of the table so their
/// destruction (O(size)) happens outside any lock.
pub(crate) struct Retired {
    // Held only so that dropping `Retired` drops them.
    #[allow(dead_code)]
    v4: FamilyTable<Ipv4Addr>,
    #[allow(dead_code)]
    v6: FamilyTable<Ipv6Addr>,
}

impl Retired {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

fn apply_flagged<A: IpAddress>(
    table: &mut FamilyTable<A>,
    prefix: IpPrefix<A>,
    entry: RoaEntry,
    announce: bool,
) {
    if announce {
        table.insert(prefix, entry);
    } else {
        table.remove(prefix, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::PrefixFlags;

    fn p4(s: &str) -> IpPrefix<Ipv4Addr> {
        s.parse().unwrap()
    }

    fn p6(s: &str) -> IpPrefix<Ipv6Addr> {
        s.parse().unwrap()
    }

    // ── FamilyTable ──────────────────────────────────────────────────────

    #[test]
    fn empty_table_is_not_found() {
        let t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::NotFound
        );
    }

    #[test]
    fn exact_match_is_valid() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::Valid
        );
    }

    #[test]
    fn exceeds_max_len_is_invalid() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        // Announcing a /25 under a ROA whose max_len is /24.
        assert_eq!(
            t.validate("192.0.2.0".parse().unwrap(), 25, 65001),
            RoaValidity::Invalid
        );
    }

    #[test]
    fn asn_mismatch_is_invalid() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65002),
            RoaValidity::Invalid
        );
    }

    #[test]
    fn disjoint_prefix_is_not_found() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("198.51.100.1".parse().unwrap(), 24, 65001),
            RoaValidity::NotFound
        );
    }

    #[test]
    fn less_specific_roa_can_validate_when_more_specific_does_not() {
        // ROA at /16 authorizes AS 65001 up to /24; ROA at /24 (a subset)
        // authorizes only AS 65002. Announcing the exact /24 under AS 65001
        // must find the /16 ROA even though the /24 ROA doesn't match.
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("10.0.0.0/16"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        t.insert(
            p4("10.0.5.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65002,
            },
        );
        assert_eq!(
            t.validate("10.0.5.1".parse().unwrap(), 24, 65001),
            RoaValidity::Valid
        );
    }

    #[test]
    fn multiple_overlapping_roas_no_match_is_invalid_not_not_found() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("10.0.0.0/16"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        t.insert(
            p4("10.0.5.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65002,
            },
        );
        assert_eq!(
            t.validate("10.0.5.1".parse().unwrap(), 24, 65003),
            RoaValidity::Invalid
        );
    }

    #[test]
    fn multiple_roas_at_same_prefix_any_match_wins() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65001,
            },
        );
        t.insert(
            p4("192.0.2.0/24"),
            RoaEntry {
                max_len: 24,
                asn: 65002,
            },
        );
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65002),
            RoaValidity::Valid
        );
    }

    #[test]
    fn insert_then_withdraw_returns_to_not_found() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        let entry = RoaEntry {
            max_len: 24,
            asn: 65001,
        };
        t.insert(p4("192.0.2.0/24"), entry);
        t.remove(p4("192.0.2.0/24"), entry);
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::NotFound
        );
    }

    #[test]
    fn duplicate_insert_dedupes() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        let entry = RoaEntry {
            max_len: 24,
            asn: 65001,
        };
        t.insert(p4("192.0.2.0/24"), entry);
        t.insert(p4("192.0.2.0/24"), entry); // replay
        assert_eq!(t.len(), 1);
        // A single withdrawal now fully removes it — no phantom copy left.
        t.remove(p4("192.0.2.0/24"), entry);
        assert_eq!(t.len(), 0);
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::NotFound
        );
    }

    #[test]
    fn withdraw_of_one_of_several_leaves_others_intact() {
        let mut t: FamilyTable<Ipv4Addr> = FamilyTable::new();
        let a = RoaEntry {
            max_len: 24,
            asn: 65001,
        };
        let b = RoaEntry {
            max_len: 24,
            asn: 65002,
        };
        t.insert(p4("192.0.2.0/24"), a);
        t.insert(p4("192.0.2.0/24"), b);
        t.remove(p4("192.0.2.0/24"), a);
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::Invalid // a is gone, but the prefix still has coverage from b
        );
        assert_eq!(
            t.validate("192.0.2.1".parse().unwrap(), 24, 65002),
            RoaValidity::Valid
        );
    }

    // ── IPv6 equivalents ─────────────────────────────────────────────────

    #[test]
    fn v6_exact_match_is_valid() {
        let mut t: FamilyTable<Ipv6Addr> = FamilyTable::new();
        t.insert(
            p6("2001:db8::/32"),
            RoaEntry {
                max_len: 32,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("2001:db8::1".parse().unwrap(), 32, 65001),
            RoaValidity::Valid
        );
    }

    #[test]
    fn v6_exceeds_max_len_is_invalid() {
        let mut t: FamilyTable<Ipv6Addr> = FamilyTable::new();
        t.insert(
            p6("2001:db8::/32"),
            RoaEntry {
                max_len: 32,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("2001:db8::".parse().unwrap(), 48, 65001),
            RoaValidity::Invalid
        );
    }

    #[test]
    fn v6_disjoint_is_not_found() {
        let mut t: FamilyTable<Ipv6Addr> = FamilyTable::new();
        t.insert(
            p6("2001:db8::/32"),
            RoaEntry {
                max_len: 32,
                asn: 65001,
            },
        );
        assert_eq!(
            t.validate("2001:db9::1".parse().unwrap(), 32, 65001),
            RoaValidity::NotFound
        );
    }

    // ── RoaTable (combined v4/v6, apply_prefix_pdu, serial) ─────────────

    #[test]
    fn roa_table_dispatches_v4_and_v6_independently() {
        let table = RoaTable::new();
        table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 24,
            max_len: 24,
            prefix: "192.0.2.0".parse().unwrap(),
            asn: 65001,
        });
        table.apply_prefix_pdu(&Pdu::Ipv6Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 32,
            max_len: 32,
            prefix: "2001:db8::".parse().unwrap(),
            asn: 65002,
        });
        assert_eq!(
            table.validate_v4("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::Valid
        );
        assert_eq!(
            table.validate_v6("2001:db8::1".parse().unwrap(), 32, 65002),
            RoaValidity::Valid
        );
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn roa_table_withdraw_via_pdu() {
        let table = RoaTable::new();
        let announce = Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 24,
            max_len: 24,
            prefix: "192.0.2.0".parse().unwrap(),
            asn: 65001,
        };
        table.apply_prefix_pdu(&announce);
        let withdraw = Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: false },
            prefix_len: 24,
            max_len: 24,
            prefix: "192.0.2.0".parse().unwrap(),
            asn: 65001,
        };
        table.apply_prefix_pdu(&withdraw);
        assert_eq!(
            table.validate_v4("192.0.2.1".parse().unwrap(), 24, 65001),
            RoaValidity::NotFound
        );
        assert!(table.is_empty());
    }

    /// `install` hands the previous generation back instead of freeing it
    /// under the write locks (O(size) otherwise), and the new generation is
    /// what validation sees.
    #[test]
    fn install_returns_the_previous_generation_for_deferred_drop() {
        let table = RoaTable::new();
        for asn in [65001, 65002] {
            table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
                flags: PrefixFlags { announce: true },
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(192, 0, 2, 0),
                asn,
            });
        }
        let mut snap = Snapshot::new();
        snap.apply(
            VrpOp::from_pdu(&Pdu::Ipv6Prefix {
                flags: PrefixFlags { announce: true },
                prefix_len: 32,
                max_len: 32,
                prefix: "2001:db8::".parse().unwrap(),
                asn: 65009,
            })
            .unwrap(),
        );
        let retired = table.install(snap);
        assert_eq!(retired.len(), 2);
        assert_eq!(table.len(), 1);
        assert_eq!(table.take_all().len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn roa_table_clear_removes_data() {
        let table = RoaTable::new();
        table.apply_prefix_pdu(&Pdu::Ipv4Prefix {
            flags: PrefixFlags { announce: true },
            prefix_len: 24,
            max_len: 24,
            prefix: "192.0.2.0".parse().unwrap(),
            asn: 65001,
        });
        table.clear();
        assert!(table.is_empty());
    }

    /// Cost of staging vs applying records directly (issue #88's performance
    /// question). Not a pass/fail test — run with
    /// `cargo test --release -p pathvector-rpki -- --ignored --nocapture staging_cost`.
    #[test]
    #[ignore = "measurement, not an assertion"]
    fn staging_cost_report() {
        use std::time::Instant;

        fn pdus(n: u32, base: u32) -> Vec<Pdu> {
            (0..n)
                .map(|i| Pdu::Ipv4Prefix {
                    flags: PrefixFlags { announce: true },
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::from((base + i) << 8),
                    asn: 64_512 + (i % 1000),
                })
                .collect()
        }
        let full = pdus(500_000, 0x0A_0000);
        let delta = pdus(20_000, 0x2A_0000);

        // Before: every Prefix PDU applied to the live table as it arrived.
        let live = RoaTable::new();
        let t = Instant::now();
        for p in &full {
            live.apply_prefix_pdu(p);
        }
        println!(
            "direct apply   500k VRPs (old behaviour): {:?}",
            t.elapsed()
        );

        // After: build a private snapshot, then swap it in.
        let staged_target = RoaTable::new();
        let t = Instant::now();
        let mut snap = Snapshot::new();
        for p in &full {
            snap.apply(VrpOp::from_pdu(p).unwrap());
        }
        let build = t.elapsed();
        let t = Instant::now();
        let retired = staged_target.install(snap);
        println!(
            "stage+install  500k VRPs over an empty table: build {build:?}, install (both locks held) {:?}",
            t.elapsed()
        );
        drop(retired);

        // The full-reload path replaces an already-populated table: the
        // locks must be held only for the swap, not for freeing the old
        // trees.
        let mut replacement = Snapshot::new();
        for p in &full {
            replacement.apply(VrpOp::from_pdu(p).unwrap());
        }
        let t = Instant::now();
        let retired = staged_target.install(replacement);
        let held = t.elapsed();
        let t = Instant::now();
        drop(retired);
        println!(
            "replace populated 500k table: locks held {held:?}; old trees freed afterwards, lock-free: {:?}",
            t.elapsed()
        );

        // Incremental: 20k-op delta applied under both locks.
        let ops: Vec<VrpOp> = delta.iter().map(|p| VrpOp::from_pdu(p).unwrap()).collect();
        let t = Instant::now();
        staged_target.apply_delta(&ops);
        println!(
            "apply_delta    20k ops on a 500k table (both locks held): {:?}",
            t.elapsed()
        );
        println!("VrpOp size: {} bytes", std::mem::size_of::<VrpOp>());
    }

    #[test]
    fn non_prefix_pdu_is_a_no_op() {
        let table = RoaTable::new();
        table.apply_prefix_pdu(&Pdu::ResetQuery);
        assert!(table.is_empty());
    }
}

#[cfg(test)]
mod prop_tests {
    use proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone)]
    enum Op {
        Insert(IpPrefix<Ipv4Addr>, RoaEntry),
        Remove(IpPrefix<Ipv4Addr>, RoaEntry),
    }

    fn arb_prefix() -> impl Strategy<Value = IpPrefix<Ipv4Addr>> {
        (any::<u32>(), 0u8..=32)
            .prop_map(|(addr, len)| IpPrefix::new(Ipv4Addr::from(addr), len).unwrap().masked())
    }

    fn arb_entry() -> impl Strategy<Value = RoaEntry> {
        (0u8..=32, 1u32..=10).prop_map(|(max_len, asn)| RoaEntry { max_len, asn })
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (arb_prefix(), arb_entry()).prop_map(|(p, e)| Op::Insert(p, e)),
            (arb_prefix(), arb_entry()).prop_map(|(p, e)| Op::Remove(p, e)),
        ]
    }

    /// Naive reference model: a flat `Vec` of `(prefix, entry)`, validated by
    /// linear scan. Differential-tested against the `routemap`-backed
    /// `FamilyTable` to catch bugs in the short-circuit + ancestor-walk
    /// composition.
    fn naive_validate(
        entries: &[(IpPrefix<Ipv4Addr>, RoaEntry)],
        addr: Ipv4Addr,
        prefix_len: u8,
        origin_asn: u32,
    ) -> RoaValidity {
        let addr_prefix = IpPrefix::new(addr, prefix_len).unwrap();
        let covering: Vec<_> = entries
            .iter()
            .filter(|(p, _)| p.contains(addr) && p.mask() <= prefix_len)
            .collect();
        let _ = addr_prefix;
        if covering.is_empty() {
            return RoaValidity::NotFound;
        }
        if covering
            .iter()
            .any(|(_, e)| e.asn == origin_asn && prefix_len <= e.max_len)
        {
            RoaValidity::Valid
        } else {
            RoaValidity::Invalid
        }
    }

    proptest! {
        #[test]
        fn family_table_agrees_with_naive_model(
            ops in prop::collection::vec(arb_op(), 0..50),
            query_addr in any::<u32>(),
            query_len in 0u8..=32,
            query_asn in 1u32..=10,
        ) {
            let mut table: FamilyTable<Ipv4Addr> = FamilyTable::new();
            let mut naive: Vec<(IpPrefix<Ipv4Addr>, RoaEntry)> = Vec::new();

            for op in &ops {
                match op {
                    Op::Insert(p, e) => {
                        table.insert(*p, *e);
                        if !naive.contains(&(*p, *e)) {
                            naive.push((*p, *e));
                        }
                    }
                    Op::Remove(p, e) => {
                        table.remove(*p, *e);
                        naive.retain(|(np, ne)| !(np == p && ne == e));
                    }
                }
            }

            let query_addr = Ipv4Addr::from(query_addr);
            let expected = naive_validate(&naive, query_addr, query_len, query_asn);
            let actual = table.validate(query_addr, query_len, query_asn);
            prop_assert_eq!(actual, expected);
        }
    }
}
