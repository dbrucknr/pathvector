//! The Loc-RIB's best-path table: winner per prefix plus per-peer win counts.
//!
//! [`BestTable`] owns both the `prefix → winning peer` map and a
//! `peer → number of prefixes it wins` counter, and the *only* way to change
//! the former is [`BestTable::set`], which updates the latter in the same
//! call. The two cannot drift apart, so a reader asking "how many of the best
//! paths came from this peer" gets an O(1) answer instead of scanning the
//! table (issue #106: the management API used to do that scan once per peer
//! per call).
//!
//! The invariant — `wins[p] == |{ prefix : winners[prefix] == p }|`, with no
//! zero entries — is checked against a full recount by
//! [`BestTable::recount`] in this module's tests and in the property tests of
//! [`LocRib`](crate::LocRib).

use ahash::AHashMap;
use ipnetx::interfaces::IpAddress;
use pathvector_types::Nlri;
use routemap::RouteMap;

use crate::{canonical::CanonicalNlri, peer::PeerId};

/// Winning peer per prefix, with an incrementally maintained win count per
/// peer.
#[derive(Clone)]
pub(crate) struct BestTable<A: IpAddress> {
    winners: RouteMap<A, PeerId>,
    /// Number of prefixes each peer currently wins. A peer that wins nothing
    /// has no entry (counts never sit at zero), so the map is bounded by the
    /// number of peers, not by table size.
    wins: AHashMap<PeerId, usize>,
}

impl<A: IpAddress> BestTable<A> {
    pub(crate) fn new() -> Self {
        Self {
            winners: RouteMap::new(),
            wins: AHashMap::new(),
        }
    }

    /// The peer currently winning `key`.
    pub(crate) fn get(&self, key: CanonicalNlri<A>) -> Option<PeerId> {
        self.winners.get(key.prefix()).copied()
    }

    /// Makes `winner` the winner of `key` (`None` clears it), keeping the
    /// per-peer counts in step. The single mutation point of the table.
    ///
    /// The caller passes the winner it has just read as `previous` (every
    /// `LocRib` mutation already does, to classify the transition), which
    /// saves a second walk of the prefix tree on the insert hot path.
    /// `previous` must equal [`get`](Self::get) for `key`; debug builds
    /// assert it.
    pub(crate) fn set(
        &mut self,
        key: CanonicalNlri<A>,
        previous: Option<PeerId>,
        winner: Option<PeerId>,
    ) {
        debug_assert_eq!(previous, self.get(key), "stale `previous` winner");
        if previous == winner {
            return;
        }
        if let Some(old) = previous {
            self.decrement(old);
        }
        match winner {
            Some(new) => {
                self.winners.insert(key.prefix(), new);
                *self.wins.entry(new).or_insert(0) += 1;
            }
            None => {
                self.winners.remove(key.prefix());
            }
        }
    }

    fn decrement(&mut self, peer: PeerId) {
        if let Some(count) = self.wins.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.wins.remove(&peer);
            }
        }
    }

    /// Number of prefixes for which `peer` is the winner. O(1).
    pub(crate) fn win_count(&self, peer: PeerId) -> usize {
        self.wins.get(&peer).copied().unwrap_or(0)
    }

    /// Every `(key, winner)` pair, in prefix-tree order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (CanonicalNlri<A>, &PeerId)> {
        self.winners
            .iter()
            .map(|(prefix, peer)| (CanonicalNlri::new(Nlri::from_prefix(prefix)), peer))
    }

    /// The most specific prefix covering `addr`, and its winner.
    pub(crate) fn longest_match_entry(&self, addr: A) -> Option<(CanonicalNlri<A>, &PeerId)> {
        self.winners
            .longest_match_entry(addr)
            .map(|(prefix, peer)| (CanonicalNlri::new(Nlri::from_prefix(prefix)), peer))
    }

    /// Recomputes every peer's win count by scanning the table. O(table).
    ///
    /// Exists to prove the incremental counts correct; production code reads
    /// [`win_count`](Self::win_count).
    pub(crate) fn recount(&self) -> AHashMap<PeerId, usize> {
        let mut counts = AHashMap::new();
        for (_, peer) in &self.winners {
            *counts.entry(*peer).or_insert(0) += 1;
        }
        counts
    }

    /// `true` when the incremental counts equal a full recount.
    pub(crate) fn counts_consistent(&self) -> bool {
        self.recount() == self.wins
    }
}
