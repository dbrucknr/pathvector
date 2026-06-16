/// A single segment within a BGP AS path.
///
/// An AS path is not a flat list — it is composed of typed segments. Most routes
/// you encounter in practice have a single `Sequence` segment, but aggregation
/// and confederations introduce the other types.
///
/// # Segment types
///
/// | Variant | Wire type | Meaning |
/// |---|---|---|
/// | `Sequence` | `AS_SEQUENCE` (2) | Ordered list of ASNs; the normal case |
/// | `Set` | `AS_SET` (1) | Unordered group; produced by route aggregation |
/// | `ConfedSequence` | `AS_CONFED_SEQUENCE` (3) | Ordered list within a confederation |
/// | `ConfedSet` | `AS_CONFED_SET` (4) | Unordered group within a confederation |
///
/// # Path length contribution
///
/// Segment types contribute differently to the AS path length used in
/// best-path selection (RFC 4271 §9.1.2.2):
///
/// - `Sequence` — contributes one per ASN in the segment
/// - `Set` — contributes exactly 1, regardless of size
/// - `ConfedSequence` / `ConfedSet` — contribute 0 (confederation hops are internal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    /// An ordered list of ASNs. Each router prepends its own ASN here as a
    /// route travels across the internet.
    Sequence(Vec<crate::Asn>),
    /// An unordered group of ASNs. Created when an aggregating router
    /// combines routes from multiple origin ASes into a single prefix.
    Set(Vec<crate::Asn>),
    /// An ordered list of ASNs that are internal to a BGP confederation.
    /// These hops do not count toward the public AS path length.
    ConfedSequence(Vec<crate::Asn>),
    /// An unordered group of ASNs internal to a BGP confederation.
    ConfedSet(Vec<crate::Asn>),
}

impl AsPathSegment {
    /// Returns the ASNs contained in this segment.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPathSegment};
    ///
    /// let seg = AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002)]);
    /// assert_eq!(seg.asns(), &[Asn::new(65001), Asn::new(65002)]);
    /// ```
    #[must_use]
    pub fn asns(&self) -> &[crate::Asn] {
        match self {
            Self::Sequence(v) | Self::Set(v) | Self::ConfedSequence(v) | Self::ConfedSet(v) => v,
        }
    }

    /// Returns the number of ASNs this segment contributes to the BGP path
    /// length used in best-path selection.
    ///
    /// `Set` counts as 1 regardless of size. Confederation segments count as 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPathSegment};
    ///
    /// let seq = AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002), Asn::new(65003)]);
    /// assert_eq!(seq.path_length(), 3);
    ///
    /// let set = AsPathSegment::Set(vec![Asn::new(65001), Asn::new(65002)]);
    /// assert_eq!(set.path_length(), 1);
    ///
    /// let confed = AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]);
    /// assert_eq!(confed.path_length(), 0);
    /// ```
    #[must_use]
    pub fn path_length(&self) -> usize {
        match self {
            Self::Sequence(v) => v.len(),
            Self::Set(_) => 1,
            Self::ConfedSequence(_) | Self::ConfedSet(_) => 0,
        }
    }

    /// Returns `true` if this segment contains the given ASN.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPathSegment};
    ///
    /// let seg = AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002)]);
    /// assert!(seg.contains(Asn::new(65001)));
    /// assert!(!seg.contains(Asn::new(65003)));
    /// ```
    #[must_use]
    pub fn contains(&self, asn: crate::Asn) -> bool {
        self.asns().contains(&asn)
    }

    /// Returns `true` if this segment contains no ASNs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asns().is_empty()
    }
}

impl std::fmt::Display for AsPathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequence(asns) => {
                let parts: Vec<String> = asns.iter().map(|a| a.as_u32().to_string()).collect();
                write!(f, "{}", parts.join(" "))
            }
            Self::Set(asns) => {
                let parts: Vec<String> = asns.iter().map(|a| a.as_u32().to_string()).collect();
                write!(f, "{{{}}}", parts.join(", "))
            }
            Self::ConfedSequence(asns) => {
                let parts: Vec<String> = asns.iter().map(|a| a.as_u32().to_string()).collect();
                write!(f, "({})", parts.join(" "))
            }
            Self::ConfedSet(asns) => {
                let parts: Vec<String> = asns.iter().map(|a| a.as_u32().to_string()).collect();
                write!(f, "({{{}}})", parts.join(", "))
            }
        }
    }
}

/// A BGP AS path attribute — the sequence of autonomous systems a route has
/// traversed.
///
/// Every BGP UPDATE message carries an AS path. As the route propagates across
/// the internet, each router prepends its own ASN before re-advertising. The
/// result is an ordered record of every AS the route passed through, oldest
/// entry last.
///
/// AS paths serve two critical roles:
///
/// 1. **Loop prevention** — a BGP speaker rejects any route whose AS path
///    already contains its own ASN. If you see yourself in the path, the route
///    has looped back to you.
///
/// 2. **Path selection** — all else being equal, shorter paths are preferred.
///    The path length is computed from the segments, not the raw ASN count
///    (see [`AsPathSegment::path_length`]).
///
/// # Examples
///
/// ```
/// use pathvector_types::{Asn, AsPath};
///
/// // A route originating from AS 65001, passing through AS 65002
/// let path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
/// assert_eq!(path.path_length(), 2);
/// assert_eq!(path.origin_as(), Some(Asn::new(65001)));
///
/// // Loop detection: AS 65002 would reject this route
/// assert!(path.contains(Asn::new(65002)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Creates an empty AS path.
    ///
    /// An empty path is valid for locally originated routes — a route your own
    /// router is introducing into BGP for the first time.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::AsPath;
    ///
    /// let path = AsPath::new();
    /// assert!(path.is_empty());
    /// assert_eq!(path.path_length(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an AS path from a single ordered sequence of ASNs.
    ///
    /// This is the common case: most routes in the wild have a single
    /// `AS_SEQUENCE` segment. The ASNs should be ordered most-recent first
    /// (the originating AS is last).
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// // Route originated by AS 65001, re-advertised by AS 65002
    /// let path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
    /// assert_eq!(path.path_length(), 2);
    /// ```
    #[must_use]
    pub fn from_sequence(asns: Vec<crate::Asn>) -> Self {
        if asns.is_empty() {
            Self::new()
        } else {
            Self {
                segments: vec![AsPathSegment::Sequence(asns)],
            }
        }
    }

    /// Prepends an ASN to this AS path, following RFC 4271 §5.1.2.
    ///
    /// This is what a BGP router does before re-advertising a route to an
    /// eBGP peer: it adds its own ASN to the front of the path.
    ///
    /// The rules (per RFC 4271):
    /// - If the first segment is a `Sequence` with fewer than 255 entries,
    ///   the ASN is inserted at the front of that segment.
    /// - Otherwise, a new `Sequence` segment containing just the ASN is
    ///   prepended. This handles the 255-ASN segment limit and the case where
    ///   the first segment is a `Set`.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let mut path = AsPath::from_sequence(vec![Asn::new(65001)]);
    /// path.prepend(Asn::new(65002));
    ///
    /// assert_eq!(path.path_length(), 2);
    /// assert_eq!(path.origin_as(), Some(Asn::new(65001)));
    /// ```
    pub fn prepend(&mut self, asn: crate::Asn) {
        match self.segments.first_mut() {
            Some(AsPathSegment::Sequence(asns)) if asns.len() < 255 => {
                asns.insert(0, asn);
            }
            _ => {
                self.segments.insert(0, AsPathSegment::Sequence(vec![asn]));
            }
        }
    }

    /// Returns `true` if this AS path contains the given ASN in any segment.
    ///
    /// Used for loop detection: a router must reject any route whose AS path
    /// contains its own ASN.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
    /// assert!(path.contains(Asn::new(65001)));
    /// assert!(!path.contains(Asn::new(65003)));
    /// ```
    #[must_use]
    pub fn contains(&self, asn: crate::Asn) -> bool {
        self.segments.iter().any(|seg| seg.contains(asn))
    }

    /// Returns the BGP path length used in best-path selection.
    ///
    /// This is the sum of each segment's [`AsPathSegment::path_length`] —
    /// not a raw count of ASNs. `AS_SET` segments count as 1 regardless of
    /// size; confederation segments count as 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// // Sequence of 3 + Set (counts as 1) = length 4
    /// let path = AsPath::from_segments(vec![
    ///     AsPathSegment::Sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]),
    ///     AsPathSegment::Set(vec![Asn::new(64512), Asn::new(64513), Asn::new(64514)]),
    /// ]);
    /// assert_eq!(path.path_length(), 4);
    /// ```
    #[must_use]
    pub fn path_length(&self) -> usize {
        self.segments.iter().map(AsPathSegment::path_length).sum()
    }

    /// Returns the originating AS — the AS that first introduced this route
    /// into BGP.
    ///
    /// Because routers prepend their ASN at the front, the originator is the
    /// last ASN in the last `Sequence` segment. Returns `None` if the path is
    /// empty or contains only non-sequence segments.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let path = AsPath::from_sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]);
    /// assert_eq!(path.origin_as(), Some(Asn::new(65001)));
    ///
    /// assert_eq!(AsPath::new().origin_as(), None);
    /// ```
    #[must_use]
    pub fn origin_as(&self) -> Option<crate::Asn> {
        self.segments.iter().rev().find_map(|seg| match seg {
            AsPathSegment::Sequence(asns) => asns.last().copied(),
            _ => None,
        })
    }

    /// Returns `true` if this AS path has no segments (or all segments are empty).
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// assert!(AsPath::new().is_empty());
    /// assert!(!AsPath::from_sequence(vec![Asn::new(65001)]).is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty() || self.segments.iter().all(AsPathSegment::is_empty)
    }

    /// Returns the segments that make up this AS path.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// let path = AsPath::from_sequence(vec![Asn::new(65001)]);
    /// assert_eq!(path.segments().len(), 1);
    /// ```
    #[must_use]
    pub fn segments(&self) -> &[AsPathSegment] {
        &self.segments
    }

    /// Creates an AS path from an explicit list of segments.
    ///
    /// Use this when constructing paths with mixed segment types, such as
    /// a sequence followed by a set (common in aggregated routes).
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// let path = AsPath::from_segments(vec![
    ///     AsPathSegment::Sequence(vec![Asn::new(65002)]),
    ///     AsPathSegment::Set(vec![Asn::new(65000), Asn::new(65001)]),
    /// ]);
    /// assert_eq!(path.segments().len(), 2);
    /// assert_eq!(path.path_length(), 2); // 1 (sequence) + 1 (set)
    /// ```
    #[must_use]
    pub fn from_segments(segments: Vec<AsPathSegment>) -> Self {
        Self { segments }
    }

    /// Produces the wire representation for a 2-byte-only peer (RFC 6793 §4).
    ///
    /// Returns `(downgraded, Some(original))` when at least one 4-byte ASN was
    /// replaced, so the caller can attach the original as `AS4_PATH`. Returns
    /// `(original_clone, None)` when all ASNs fit in 16 bits (no downgrade needed).
    ///
    /// Confederation segments are treated like ordinary Sequence/Set segments for
    /// the purpose of downgrade — they are not stripped here; stripping is a
    /// separate concern.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// // All 2-byte → no AS4_PATH produced.
    /// let path = AsPath::from_sequence(vec![Asn::new(65001)]);
    /// let (down, as4) = path.downgrade_for_two_byte_peer();
    /// assert!(as4.is_none());
    ///
    /// // 4-byte ASN → downgrade substitutes AS_TRANS and returns original.
    /// let path4 = AsPath::from_sequence(vec![Asn::new(131072), Asn::new(65001)]);
    /// let (down4, as4_path) = path4.downgrade_for_two_byte_peer();
    /// assert_eq!(down4.segments()[0].asns()[0], Asn::TRANS);
    /// assert!(as4_path.is_some());
    /// ```
    #[must_use]
    pub fn downgrade_for_two_byte_peer(&self) -> (Self, Option<Self>) {
        let mut needs_downgrade = false;
        for seg in &self.segments {
            if seg.asns().iter().any(|a| a.is_four_byte()) {
                needs_downgrade = true;
                break;
            }
        }
        if !needs_downgrade {
            return (self.clone(), None);
        }
        let downgraded_segments: Vec<AsPathSegment> = self
            .segments
            .iter()
            .map(|seg| {
                let downgraded: Vec<crate::Asn> = seg
                    .asns()
                    .iter()
                    .map(|&a| if a.is_four_byte() { crate::Asn::TRANS } else { a })
                    .collect();
                match seg {
                    AsPathSegment::Sequence(_) => AsPathSegment::Sequence(downgraded),
                    AsPathSegment::Set(_) => AsPathSegment::Set(downgraded),
                    AsPathSegment::ConfedSequence(_) => AsPathSegment::ConfedSequence(downgraded),
                    AsPathSegment::ConfedSet(_) => AsPathSegment::ConfedSet(downgraded),
                }
            })
            .collect();
        (Self { segments: downgraded_segments }, Some(self.clone()))
    }

    /// Returns a new `AsPath` with all confederation segments removed.
    ///
    /// RFC 5065 §5.1 requires that `AS_CONFED_SEQUENCE` and `AS_CONFED_SET`
    /// segments are stripped before a route is advertised to an eBGP peer.
    /// Confederation topology is an internal implementation detail — external
    /// peers must not see it.
    ///
    /// The original path is not modified. Non-confederation segments
    /// (`Sequence`, `Set`) are preserved in their original order.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// let path = AsPath::from_segments(vec![
    ///     AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]),
    ///     AsPathSegment::Sequence(vec![Asn::new(100), Asn::new(200)]),
    ///     AsPathSegment::ConfedSet(vec![Asn::new(65003)]),
    /// ]);
    /// let stripped = path.strip_confed_segments();
    /// assert_eq!(stripped.segments().len(), 1);
    /// assert_eq!(stripped.path_length(), 2);
    /// ```
    #[must_use]
    pub fn strip_confed_segments(&self) -> Self {
        let segments = self
            .segments
            .iter()
            .filter(|seg| {
                !matches!(
                    seg,
                    AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)
                )
            })
            .cloned()
            .collect();
        Self { segments }
    }
}

impl std::fmt::Display for AsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .segments
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        write!(f, "{}", parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Asn;

    #[test]
    fn test_aspath_new_is_empty() {
        let path = AsPath::new();
        assert!(path.is_empty());
        assert_eq!(path.path_length(), 0);
        assert_eq!(path.origin_as(), None);
    }

    #[test]
    fn test_aspath_from_sequence() {
        let path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
        assert!(!path.is_empty());
        assert_eq!(path.path_length(), 2);
        assert_eq!(path.segments().len(), 1);
    }

    #[test]
    fn test_aspath_from_empty_sequence_is_empty() {
        let path = AsPath::from_sequence(vec![]);
        assert!(path.is_empty());
    }

    #[test]
    fn test_aspath_origin_as() {
        let path = AsPath::from_sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]);
        assert_eq!(path.origin_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn test_aspath_prepend_to_empty() {
        let mut path = AsPath::new();
        path.prepend(Asn::new(65001));
        assert_eq!(path.path_length(), 1);
        assert_eq!(path.origin_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn test_aspath_prepend_to_sequence() {
        let mut path = AsPath::from_sequence(vec![Asn::new(65001)]);
        path.prepend(Asn::new(65002));
        // Should grow the existing sequence, not add a new segment
        assert_eq!(path.segments().len(), 1);
        assert_eq!(path.path_length(), 2);
        assert_eq!(path.origin_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn test_aspath_prepend_to_set_creates_new_segment() {
        let mut path = AsPath::from_segments(vec![AsPathSegment::Set(vec![Asn::new(65001)])]);
        path.prepend(Asn::new(65002));
        // Set as first segment: must create a new Sequence in front
        assert_eq!(path.segments().len(), 2);
        assert!(matches!(path.segments()[0], AsPathSegment::Sequence(_)));
    }

    #[test]
    fn test_aspath_prepend_overflow_creates_new_segment() {
        let asns: Vec<Asn> = (1u32..=255).map(Asn::new).collect();
        let mut path = AsPath::from_sequence(asns);
        assert_eq!(path.segments().len(), 1);
        path.prepend(Asn::new(256));
        // First segment was full (255 ASNs), so a new segment must be created
        assert_eq!(path.segments().len(), 2);
    }

    #[test]
    fn test_aspath_contains() {
        let path = AsPath::from_sequence(vec![Asn::new(65002), Asn::new(65001)]);
        assert!(path.contains(Asn::new(65001)));
        assert!(path.contains(Asn::new(65002)));
        assert!(!path.contains(Asn::new(65003)));
    }

    #[test]
    fn test_aspath_contains_in_set() {
        let path = AsPath::from_segments(vec![AsPathSegment::Set(vec![
            Asn::new(65001),
            Asn::new(65002),
        ])]);
        assert!(path.contains(Asn::new(65001)));
        assert!(!path.contains(Asn::new(65003)));
    }

    #[test]
    fn test_aspath_path_length_sequence() {
        let path = AsPath::from_sequence(vec![Asn::new(1), Asn::new(2), Asn::new(3)]);
        assert_eq!(path.path_length(), 3);
    }

    #[test]
    fn test_aspath_path_length_set_counts_as_one() {
        let path = AsPath::from_segments(vec![AsPathSegment::Set(vec![
            Asn::new(1),
            Asn::new(2),
            Asn::new(3),
        ])]);
        assert_eq!(path.path_length(), 1);
    }

    #[test]
    fn test_aspath_path_length_confed_counts_as_zero() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]),
            AsPathSegment::Sequence(vec![Asn::new(100), Asn::new(200)]),
        ]);
        assert_eq!(path.path_length(), 2); // confed contributes 0
    }

    #[test]
    fn test_aspath_path_length_mixed() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65003), Asn::new(65002)]),
            AsPathSegment::Set(vec![Asn::new(65000), Asn::new(65001)]),
        ]);
        assert_eq!(path.path_length(), 3); // 2 (sequence) + 1 (set)
    }

    #[test]
    fn test_segment_display_sequence() {
        let seg = AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002)]);
        assert_eq!(seg.to_string(), "65001 65002");
    }

    #[test]
    fn test_segment_display_set() {
        let seg = AsPathSegment::Set(vec![Asn::new(65001), Asn::new(65002)]);
        assert_eq!(seg.to_string(), "{65001, 65002}");
    }

    #[test]
    fn test_segment_display_confed_sequence() {
        let seg = AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]);
        assert_eq!(seg.to_string(), "(65001 65002)");
    }

    #[test]
    fn test_segment_display_confed_set() {
        let seg = AsPathSegment::ConfedSet(vec![Asn::new(65001), Asn::new(65002)]);
        assert_eq!(seg.to_string(), "({65001, 65002})");
    }

    #[test]
    fn test_aspath_display() {
        let path = AsPath::from_sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]);
        assert_eq!(path.to_string(), "65003 65002 65001");
    }

    #[test]
    fn test_aspath_display_mixed() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65002)]),
            AsPathSegment::Set(vec![Asn::new(65000), Asn::new(65001)]),
        ]);
        assert_eq!(path.to_string(), "65002 {65000, 65001}");
    }

    #[test]
    fn test_aspath_origin_as_skips_non_sequence_segments() {
        // When iterating in reverse, a ConfedSequence appearing after the last
        // Sequence hits the `_ => None` arm of find_map before the Sequence is found.
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65003), Asn::new(65002)]),
            AsPathSegment::ConfedSequence(vec![Asn::new(65001)]),
        ]);
        // Reversed: ConfedSequence (→ None, continue), then Sequence (→ Some(65002))
        assert_eq!(path.origin_as(), Some(Asn::new(65002)));
    }

    #[test]
    fn test_aspath_origin_as_none_without_sequence() {
        // A path with only non-Sequence segments has no determinable origin AS.
        let path =
            AsPath::from_segments(vec![AsPathSegment::ConfedSequence(vec![Asn::new(65001)])]);
        assert_eq!(path.origin_as(), None);
    }

    // ── strip_confed_segments (RFC 5065 §5.1) ────────────────────────────────

    #[test]
    fn test_strip_confed_segments_removes_confed_sequence_and_set() {
        // RFC 5065 §5.1: both AS_CONFED_SEQUENCE and AS_CONFED_SET must be
        // removed; plain Sequence segments must be preserved.
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65001), Asn::new(65002)]),
            AsPathSegment::Sequence(vec![Asn::new(100), Asn::new(200)]),
            AsPathSegment::ConfedSet(vec![Asn::new(65003)]),
        ]);
        let stripped = path.strip_confed_segments();
        assert_eq!(stripped.segments().len(), 1);
        assert!(matches!(stripped.segments()[0], AsPathSegment::Sequence(_)));
        assert_eq!(stripped.path_length(), 2);
    }

    #[test]
    fn test_strip_confed_segments_preserves_sequence_and_set() {
        // Plain Sequence and Set segments must survive unchanged.
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(100)]),
            AsPathSegment::Set(vec![Asn::new(200), Asn::new(201)]),
        ]);
        let stripped = path.strip_confed_segments();
        assert_eq!(stripped.segments().len(), 2);
        assert_eq!(stripped.path_length(), path.path_length());
    }

    #[test]
    fn test_strip_confed_segments_all_confed_yields_empty() {
        // A path consisting only of confederation segments collapses to empty.
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65001)]),
            AsPathSegment::ConfedSet(vec![Asn::new(65002)]),
        ]);
        let stripped = path.strip_confed_segments();
        assert!(stripped.is_empty());
        assert_eq!(stripped.path_length(), 0);
    }

    #[test]
    fn test_strip_confed_segments_empty_path_stays_empty() {
        let stripped = AsPath::new().strip_confed_segments();
        assert!(stripped.is_empty());
    }

    #[test]
    fn test_strip_confed_segments_does_not_mutate_original() {
        // strip_confed_segments must return a new path; the original is unchanged.
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65001)]),
            AsPathSegment::Sequence(vec![Asn::new(100)]),
        ]);
        let stripped = path.strip_confed_segments();
        assert_eq!(path.segments().len(), 2, "original must not be modified");
        assert_eq!(stripped.segments().len(), 1);
    }

    #[test]
    fn test_strip_confed_segments_preserves_segment_order() {
        // The relative order of surviving segments must be maintained.
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(300)]),
            AsPathSegment::ConfedSequence(vec![Asn::new(65001)]),
            AsPathSegment::Set(vec![Asn::new(100), Asn::new(101)]),
            AsPathSegment::ConfedSet(vec![Asn::new(65002)]),
            AsPathSegment::Sequence(vec![Asn::new(200)]),
        ]);
        let stripped = path.strip_confed_segments();
        assert_eq!(stripped.segments().len(), 3);
        assert!(matches!(stripped.segments()[0], AsPathSegment::Sequence(_)));
        assert!(matches!(stripped.segments()[1], AsPathSegment::Set(_)));
        assert!(matches!(stripped.segments()[2], AsPathSegment::Sequence(_)));
    }

    #[test]
    fn downgrade_for_two_byte_peer_noop_when_all_two_byte() {
        let path = AsPath::from_sequence(vec![Asn::new(65001), Asn::new(65002)]);
        let (downgraded, orig) = path.downgrade_for_two_byte_peer();
        assert!(orig.is_none(), "no downgrade needed");
        assert_eq!(downgraded.segments(), path.segments());
    }

    #[test]
    fn downgrade_for_two_byte_peer_replaces_four_byte_with_trans() {
        let path =
            AsPath::from_sequence(vec![Asn::new(65001), Asn::new(131072), Asn::new(65002)]);
        let (downgraded, orig) = path.downgrade_for_two_byte_peer();
        assert!(orig.is_some(), "substitution occurred");
        // Original preserved intact.
        let orig = orig.unwrap();
        assert_eq!(orig.segments(), path.segments());
        // Downgraded has AS_TRANS in place of 131072.
        let segs = downgraded.segments();
        assert_eq!(segs.len(), 1);
        let asns = segs[0].asns();
        assert_eq!(asns[0], Asn::new(65001));
        assert_eq!(asns[1], Asn::TRANS);
        assert_eq!(asns[2], Asn::new(65002));
    }

    #[test]
    fn downgrade_for_two_byte_peer_all_four_byte() {
        let path = AsPath::from_sequence(vec![Asn::new(131072), Asn::new(200000)]);
        let (downgraded, orig) = path.downgrade_for_two_byte_peer();
        assert!(orig.is_some());
        let asns = downgraded.segments()[0].asns();
        assert!(asns.iter().all(|&a| a == Asn::TRANS));
    }

    #[test]
    fn downgrade_for_two_byte_peer_preserves_segment_type() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::Set(vec![Asn::new(131072), Asn::new(65001)]),
        ]);
        let (downgraded, _) = path.downgrade_for_two_byte_peer();
        assert!(matches!(downgraded.segments()[0], AsPathSegment::Set(_)));
        let asns = downgraded.segments()[0].asns();
        assert_eq!(asns[0], Asn::TRANS);
        assert_eq!(asns[1], Asn::new(65001));
    }
}
