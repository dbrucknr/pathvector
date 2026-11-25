/// A single segment within a BGP AS path.
///
/// An AS path is not a flat list — it is composed of typed segments. Most routes
/// you encounter in practice have a single `Sequence` segment, but aggregation
/// and confederations introduce the other types.
///
/// # Representation is not permission
///
/// `Set` and `ConfedSet` are deprecated: RFC 9774 forbids advertising them and
/// requires a received one to be treated as a withdrawal. These types still
/// represent them, so historical data and offending messages can be decoded and
/// inspected; the live session and the speaker enforce the rule. Likewise any
/// segment can hold AS 0, which RFC 7607 prohibits on the wire.
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

    /// Returns `true` for `AS_SET` and `AS_CONFED_SET`, the two segment types
    /// RFC 9774 deprecates.
    #[must_use]
    pub fn is_set(&self) -> bool {
        matches!(self, Self::Set(_) | Self::ConfedSet(_))
    }

    /// Returns `true` for `AS_CONFED_SEQUENCE` and `AS_CONFED_SET` (RFC 5065).
    #[must_use]
    pub fn is_confed(&self) -> bool {
        matches!(self, Self::ConfedSequence(_) | Self::ConfedSet(_))
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
/// assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
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
    /// assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
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

    /// Prepends an ASN into a leading `ConfedSequence` segment, following
    /// RFC 5065 §4.1(b).
    ///
    /// This is what a confederation Member-AS does before re-advertising a
    /// route to a fellow Member-AS peer: it adds its own Member-AS Number
    /// to the front of the path's confederation portion, rather than the
    /// public `AS_SEQUENCE` used for [`prepend`](Self::prepend).
    ///
    /// The rules mirror `prepend`'s, but target `ConfedSequence`:
    /// - If the first segment is a `ConfedSequence` with fewer than 255
    ///   entries, the ASN is inserted at the front of that segment.
    /// - Otherwise, a new `ConfedSequence` segment containing just the ASN
    ///   is prepended.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let mut path = AsPath::new();
    /// path.prepend_confed(Asn::new(65001));
    /// assert_eq!(path.path_length(), 0); // confed segments don't count
    /// ```
    pub fn prepend_confed(&mut self, asn: crate::Asn) {
        match self.segments.first_mut() {
            Some(AsPathSegment::ConfedSequence(asns)) if asns.len() < 255 => {
                asns.insert(0, asn);
            }
            _ => {
                self.segments
                    .insert(0, AsPathSegment::ConfedSequence(vec![asn]));
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

    /// Returns `true` if this path holds an `AS_SET` or `AS_CONFED_SET`
    /// segment.
    ///
    /// RFC 9774 §3: unless an operator configures otherwise, a speaker must
    /// not advertise such a path and must treat a received one as a
    /// withdrawal.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// assert!(!AsPath::from_sequence(vec![Asn::new(65001)]).contains_as_set());
    /// let aggregated = AsPath::from_segments(vec![AsPathSegment::Set(vec![Asn::new(65001)])]);
    /// assert!(aggregated.contains_as_set());
    /// ```
    #[must_use]
    pub fn contains_as_set(&self) -> bool {
        self.segments.iter().any(AsPathSegment::is_set)
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

    /// Returns the RFC 6811 §2 "Route Origin ASN" — the AS number used for
    /// Route Origin Validation lookups against the VRP database.
    ///
    /// Derived from the `AS_PATH`'s *final* segment only — never searches
    /// past it — per RFC 6811 §2's exact three-way rule:
    ///
    /// - `AS_SEQUENCE`-final: the rightmost ASN in that segment.
    /// - `AS_CONFED_SEQUENCE`/`AS_CONFED_SET`-final, or an empty `AS_PATH`:
    ///   `local_as` — the BGP speaker's own AS number, passed in here since
    ///   `AsPath` has no notion of "local" on its own.
    /// - Any other final segment type (`AS_SET`): `None`, RFC 6811's
    ///   distinguished "NONE" value — no VRP can ever match it.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let path = AsPath::from_sequence(vec![Asn::new(65003), Asn::new(65002), Asn::new(65001)]);
    /// assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
    ///
    /// assert_eq!(AsPath::new().origin_as(Asn::new(65000)), Some(Asn::new(65000)));
    /// ```
    #[must_use]
    pub fn origin_as(&self, local_as: crate::Asn) -> Option<crate::Asn> {
        match self.segments.last() {
            Some(AsPathSegment::Sequence(asns)) => asns.last().copied(),
            Some(AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_)) | None => {
                Some(local_as)
            }
            Some(AsPathSegment::Set(_)) => None,
        }
    }

    /// Returns the directly neighboring AS — the first ASN in the first
    /// `Sequence` segment.
    ///
    /// This is the AS that most recently prepended its number, i.e. the peer
    /// that sent us the route. Used for RFC 4271 §9.1.2.2 step 6: MED is only
    /// compared between routes received from the same neighboring AS.
    ///
    /// Returns `None` for locally originated routes (empty path) or paths that
    /// begin with a `Set` or confederation segment.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// let path = AsPath::from_sequence(vec![Asn::new(65001), Asn::new(65002)]);
    /// assert_eq!(path.neighboring_as(), Some(Asn::new(65001)));
    ///
    /// assert_eq!(AsPath::new().neighboring_as(), None);
    /// ```
    #[must_use]
    pub fn neighboring_as(&self) -> Option<crate::Asn> {
        self.segments.iter().find_map(|seg| match seg {
            AsPathSegment::Sequence(asns) => asns.first().copied(),
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
    /// a sequence followed by a set — the shape of historical aggregated
    /// routes, which RFC 9774 no longer lets a live speaker advertise or
    /// accept (see [`Self::contains_as_set`]).
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

    /// Produces what a NEW speaker sends a two-octet (OLD) peer for this path
    /// (RFC 6793 §4.2.2): the two-octet `AS_PATH` and, when one is required,
    /// the accompanying [`As4Path`].
    ///
    /// - The `AS_PATH` keeps every segment, confederation segments included,
    ///   with `AS_TRANS` standing in for each non-mappable ASN.
    /// - The [`As4Path`] is *not* a copy of this path: it is built by
    ///   [`As4Path::for_two_byte_peer`], which excludes confederation segments
    ///   and returns `None` when `AS4_PATH` must not be sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath, AsPathSegment};
    ///
    /// // All mappable → unchanged, no AS4_PATH.
    /// let path = AsPath::from_sequence(vec![Asn::new(65001)]);
    /// let (down, as4) = path.downgrade_for_two_byte_peer();
    /// assert_eq!(down, path);
    /// assert!(as4.is_none());
    ///
    /// // A non-mappable ASN → AS_TRANS in AS_PATH, the real value in AS4_PATH,
    /// // which never carries the confederation segment.
    /// let path = AsPath::from_segments(vec![
    ///     AsPathSegment::ConfedSequence(vec![Asn::new(65010)]),
    ///     AsPathSegment::Sequence(vec![Asn::new(131_072)]),
    /// ]);
    /// let (down, as4) = path.downgrade_for_two_byte_peer();
    /// assert_eq!(down.segments()[0], path.segments()[0]);
    /// assert_eq!(down.segments()[1].asns(), &[Asn::TRANS]);
    /// assert_eq!(
    ///     as4.unwrap().into_path(),
    ///     AsPath::from_sequence(vec![Asn::new(131_072)]),
    /// );
    /// ```
    #[must_use]
    pub fn downgrade_for_two_byte_peer(&self) -> (Self, Option<As4Path>) {
        if !self.has_non_mappable_asn() {
            return (self.clone(), None);
        }
        let to_two_octet = |asns: &[crate::Asn]| -> Vec<crate::Asn> {
            asns.iter()
                .map(|&a| {
                    if a.is_four_byte() {
                        crate::Asn::TRANS
                    } else {
                        a
                    }
                })
                .collect()
        };
        let segments = self
            .segments
            .iter()
            .map(|seg| match seg {
                AsPathSegment::Sequence(a) => AsPathSegment::Sequence(to_two_octet(a)),
                AsPathSegment::Set(a) => AsPathSegment::Set(to_two_octet(a)),
                AsPathSegment::ConfedSequence(a) => AsPathSegment::ConfedSequence(to_two_octet(a)),
                AsPathSegment::ConfedSet(a) => AsPathSegment::ConfedSet(to_two_octet(a)),
            })
            .collect();
        (Self { segments }, As4Path::for_two_byte_peer(self))
    }

    /// Returns `true` if any ASN in this path (in any segment type) is
    /// non-mappable to a two-octet AS number — i.e. does not fit in 16 bits
    /// (RFC 6793 §3: "non-mappable").
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// assert!(!AsPath::from_sequence(vec![Asn::new(65001)]).has_non_mappable_asn());
    /// assert!(AsPath::from_sequence(vec![Asn::new(65001), Asn::new(131_072)]).has_non_mappable_asn());
    /// ```
    #[must_use]
    pub fn has_non_mappable_asn(&self) -> bool {
        self.segments
            .iter()
            .any(|seg| seg.asns().iter().any(|a| a.is_four_byte()))
    }

    /// Reconstructs the true AS path from this `AS_PATH` (received from a
    /// two-octet-only peer, so non-mappable ASNs appear as `AS_TRANS`) and
    /// that peer's `AS4_PATH`, per RFC 6793 §4.2.3.
    ///
    /// RFC 6793 §4.2.3: "If the number of AS numbers in the `AS_PATH`
    /// attribute is less than the number of AS numbers in the `AS4_PATH`
    /// attribute, then the `AS4_PATH` attribute SHALL be ignored, and the
    /// `AS_PATH` attribute SHALL be taken as the AS path information. If the
    /// number of AS numbers in the `AS_PATH` attribute is larger than or equal
    /// to the number of AS numbers in the `AS4_PATH` attribute, then the AS
    /// path information SHALL be constructed by taking as many AS numbers
    /// and path segments as necessary from the leading part of the `AS_PATH`
    /// attribute, and then prepending them to the `AS4_PATH` attribute so that
    /// the AS path information has a number of AS numbers identical to that
    /// of the `AS_PATH` attribute. Note that a valid `AS_CONFED_SEQUENCE` or
    /// `AS_CONFED_SET` path segment SHALL be prepended if it is either the
    /// leading path segment or is adjacent to a path segment that is
    /// prepended."
    ///
    /// The AS-number counts use [`path_length`](Self::path_length) — the
    /// RFC 4271 §9.1.2.2 / RFC 5065 method the RFC names — so an `AS_SET`
    /// counts as one and confederation segments count as zero. An
    /// `AS_SEQUENCE` that straddles the boundary is split: only its leading
    /// ASNs are taken. Adjacent `AS_SEQUENCE` segments at the join are
    /// coalesced (up to the 255-ASN wire limit), so the result matches what
    /// a four-octet speaker would have produced.
    ///
    /// Confederation segments in `as4_path` are ignored (RFC 6793 §6 forbids
    /// them there; the wire decoder already discards them).
    ///
    /// # Examples
    ///
    /// ```
    /// use pathvector_types::{Asn, AsPath};
    ///
    /// // AS 131072 -> OLD AS 65001 -> us. The OLD speaker saw AS_TRANS and
    /// // prepended itself, so the wire AS_PATH is [65001, AS_TRANS] while
    /// // AS4_PATH still carries [131072].
    /// let as_path = AsPath::from_sequence(vec![Asn::new(65001), Asn::TRANS]);
    /// let as4_path = AsPath::from_sequence(vec![Asn::new(131_072)]);
    /// assert_eq!(
    ///     as_path.reconstruct_with_as4_path(&as4_path),
    ///     AsPath::from_sequence(vec![Asn::new(65001), Asn::new(131_072)]),
    /// );
    /// ```
    #[must_use]
    pub fn reconstruct_with_as4_path(&self, as4_path: &Self) -> Self {
        let as4 = as4_path.strip_confed_segments();
        if as4.segments.is_empty() {
            return self.clone();
        }
        let n = self.path_length();
        let m = as4.path_length();
        if n < m {
            return self.clone();
        }

        let mut remaining = n - m;
        let mut out: Vec<AsPathSegment> = Vec::new();
        // Walking from the front, every segment visited so far was taken, so
        // a confederation segment here is either leading or adjacent to a
        // prepended segment — exactly the RFC's condition for taking it.
        for seg in &self.segments {
            match seg {
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => {
                    out.push(seg.clone());
                }
                AsPathSegment::Sequence(asns) => {
                    if remaining == 0 {
                        break;
                    }
                    if asns.len() <= remaining {
                        remaining -= asns.len();
                        out.push(seg.clone());
                    } else {
                        out.push(AsPathSegment::Sequence(asns[..remaining].to_vec()));
                        break;
                    }
                }
                AsPathSegment::Set(_) => {
                    if remaining == 0 {
                        break;
                    }
                    remaining -= 1;
                    out.push(seg.clone());
                }
            }
        }

        let mut tail = as4.segments.into_iter();
        if let (Some(AsPathSegment::Sequence(head)), Some(AsPathSegment::Sequence(first))) =
            (out.last_mut(), tail.as_slice().first())
            && head.len() + first.len() <= 255
        {
            head.extend_from_slice(first);
            tail.next();
        }
        out.extend(tail);
        Self { segments: out }
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
            .filter(|seg| !seg.is_confed())
            .cloned()
            .collect();
        Self { segments }
    }
}

/// An `AS4_PATH` value that is valid to send to a two-octet peer
/// (RFC 6793 §4.2.2).
///
/// [`Self::for_two_byte_peer`] is the only constructor, so every value holds:
///
/// - no `AS_CONFED_SEQUENCE` / `AS_CONFED_SET` segment — "declared invalid for
///   the `AS4_PATH` attribute and MUST NOT be included" (§3);
/// - at least one non-mappable AS number — otherwise "the NEW BGP speaker MUST
///   NOT send the `AS4_PATH` attribute" (§4.2.2). It is therefore never empty.
///
/// A *received* `AS4_PATH` is raw wire data that may violate both, and stays an
/// [`AsPath`].
///
/// # Examples
///
/// ```
/// use pathvector_types::{As4Path, Asn, AsPath};
///
/// let mappable = AsPath::from_sequence(vec![Asn::new(65001)]);
/// assert!(As4Path::for_two_byte_peer(&mappable).is_none());
///
/// let wide = AsPath::from_sequence(vec![Asn::new(131_072)]);
/// assert_eq!(As4Path::for_two_byte_peer(&wide).unwrap().as_path(), &wide);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4Path(AsPath);

impl As4Path {
    /// Constructs the `AS4_PATH` for `path`, or `None` when none may be sent.
    ///
    /// Allocates only when it returns `Some`.
    #[must_use]
    pub fn for_two_byte_peer(path: &AsPath) -> Option<Self> {
        path.segments
            .iter()
            .any(|seg| !seg.is_confed() && seg.asns().iter().any(|a| a.is_four_byte()))
            .then(|| Self(path.strip_confed_segments()))
    }

    /// The path this `AS4_PATH` carries.
    #[must_use]
    pub fn as_path(&self) -> &AsPath {
        &self.0
    }

    /// Consumes the value, returning the path it carries.
    #[must_use]
    pub fn into_path(self) -> AsPath {
        self.0
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
        // RFC 6811 §2: an empty AS_PATH substitutes the local speaker's own
        // AS number as the Route Origin ASN, not "no origin."
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65000)));
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
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
    }

    #[test]
    fn test_aspath_prepend_to_empty() {
        let mut path = AsPath::new();
        path.prepend(Asn::new(65001));
        assert_eq!(path.path_length(), 1);
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
    }

    #[test]
    fn test_aspath_prepend_to_sequence() {
        let mut path = AsPath::from_sequence(vec![Asn::new(65001)]);
        path.prepend(Asn::new(65002));
        // Should grow the existing sequence, not add a new segment
        assert_eq!(path.segments().len(), 1);
        assert_eq!(path.path_length(), 2);
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65001)));
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

    // ── prepend_confed (RFC 5065 §4.1(b)) ────────────────────────────────

    #[test]
    fn test_prepend_confed_to_empty() {
        let mut path = AsPath::new();
        path.prepend_confed(Asn::new(65001));
        assert_eq!(path.segments().len(), 1);
        assert!(matches!(
            path.segments()[0],
            AsPathSegment::ConfedSequence(_)
        ));
        assert_eq!(path.segments()[0].asns(), &[Asn::new(65001)]);
        // Confed segments contribute 0 to path length.
        assert_eq!(path.path_length(), 0);
    }

    #[test]
    fn test_prepend_confed_extends_existing_leading_confed_sequence() {
        let mut path =
            AsPath::from_segments(vec![AsPathSegment::ConfedSequence(vec![Asn::new(65001)])]);
        path.prepend_confed(Asn::new(65002));
        // Should grow the existing confed sequence, not add a new segment.
        assert_eq!(path.segments().len(), 1);
        assert_eq!(
            path.segments()[0].asns(),
            &[Asn::new(65002), Asn::new(65001)]
        );
    }

    #[test]
    fn test_prepend_confed_to_non_confed_sequence_creates_new_segment() {
        let mut path = AsPath::from_sequence(vec![Asn::new(100)]);
        path.prepend_confed(Asn::new(65001));
        // First segment is a plain Sequence: must create a new ConfedSequence in front.
        assert_eq!(path.segments().len(), 2);
        assert!(matches!(
            path.segments()[0],
            AsPathSegment::ConfedSequence(_)
        ));
        assert_eq!(path.segments()[0].asns(), &[Asn::new(65001)]);
        assert!(matches!(path.segments()[1], AsPathSegment::Sequence(_)));
    }

    #[test]
    fn test_prepend_confed_overflow_creates_new_segment() {
        let asns: Vec<Asn> = (1u32..=255).map(Asn::new).collect();
        let mut path = AsPath::from_segments(vec![AsPathSegment::ConfedSequence(asns)]);
        assert_eq!(path.segments().len(), 1);
        path.prepend_confed(Asn::new(256));
        // First segment was full (255 ASNs), so a new segment must be created.
        assert_eq!(path.segments().len(), 2);
        assert_eq!(path.segments()[0].asns(), &[Asn::new(256)]);
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

    // ── origin_as (RFC 6811 §2 Route Origin ASN) ─────────────────────────────
    //
    // RFC 6811 §2 derives the Route Origin ASN from the AS_PATH's *final*
    // segment only — never searches past it. Each test below pins down one
    // of the three branches; see `RFC_AUDIT.md`'s RFC 6811 section for the
    // exact clause and the confirmed gap this once was.

    #[test]
    fn test_aspath_origin_as_confed_sequence_final_substitutes_local_as() {
        // RFC 6811 §2: "the BGP speaker's own AS number if that segment is
        // of type AS_CONFED_SEQUENCE" — regardless of what an earlier
        // Sequence segment contains. The old backward-search implementation
        // would have skipped past the trailing ConfedSequence and returned
        // 65002 (the last Sequence's final ASN) instead.
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65003), Asn::new(65002)]),
            AsPathSegment::ConfedSequence(vec![Asn::new(65001)]),
        ]);
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65000)));
    }

    #[test]
    fn test_aspath_origin_as_confed_set_final_substitutes_local_as() {
        // Same rule, AS_CONFED_SET variant.
        let path = AsPath::from_segments(vec![AsPathSegment::ConfedSet(vec![Asn::new(65001)])]);
        assert_eq!(path.origin_as(Asn::new(65000)), Some(Asn::new(65000)));
    }

    #[test]
    fn test_aspath_origin_as_set_final_is_none() {
        // RFC 6811 §2: "the distinguished value 'NONE' if the final segment
        // ... is of any other type" — i.e. AS_SET. `None` is this crate's
        // representation of "NONE": RFC 6811 notes no VRP can ever have
        // "NONE" as its ASN, so a route with this origin can never Match.
        let path = AsPath::from_segments(vec![
            AsPathSegment::Sequence(vec![Asn::new(65002)]),
            AsPathSegment::Set(vec![Asn::new(65001), Asn::new(64512)]),
        ]);
        assert_eq!(path.origin_as(Asn::new(65000)), None);
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
        let path = AsPath::from_sequence(vec![Asn::new(65001), Asn::new(131_072), Asn::new(65002)]);
        let (downgraded, orig) = path.downgrade_for_two_byte_peer();
        assert!(orig.is_some(), "substitution occurred");
        // No confederation segments here, so AS4_PATH carries the whole path.
        let orig = orig.unwrap();
        assert_eq!(orig.as_path(), &path);
        // Downgraded has AS_TRANS in place of 131072.
        let segs = downgraded.segments();
        assert_eq!(segs.len(), 1);
        let asns = segs[0].asns();
        assert_eq!(asns[0], Asn::new(65001));
        assert_eq!(asns[1], Asn::TRANS);
        assert_eq!(asns[2], Asn::new(65002));
    }

    // ── RFC 6793 §4.2.3 reconstruction ────────────────────────────────────────
    //
    // Expected values are derived by hand from the RFC text: take (N - M)
    // leading AS numbers/segments from AS_PATH and prepend them to AS4_PATH,
    // where N, M are the RFC 4271 §9.1.2.2 / RFC 5065 path lengths.

    fn seq(v: &[u32]) -> AsPathSegment {
        AsPathSegment::Sequence(v.iter().map(|&a| Asn::new(a)).collect())
    }
    fn set(v: &[u32]) -> AsPathSegment {
        AsPathSegment::Set(v.iter().map(|&a| Asn::new(a)).collect())
    }
    fn cseq(v: &[u32]) -> AsPathSegment {
        AsPathSegment::ConfedSequence(v.iter().map(|&a| Asn::new(a)).collect())
    }

    #[test]
    fn reconstruct_equal_length_takes_as4_path_wholesale() {
        // OLD speaker saw 131072 as AS_TRANS; no extra hops were added.
        let as_path = AsPath::from_segments(vec![seq(&[23456, 65001])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072, 65001])]);
        assert_eq!(as_path.reconstruct_with_as4_path(&as4), as4);
    }

    #[test]
    fn reconstruct_prepends_leading_as_path_hops_to_as4_path() {
        // N=3, M=2: one leading AS (the OLD speaker, 64512) is prepended.
        let as_path = AsPath::from_segments(vec![seq(&[64512, 23456, 65001])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072, 65001])]);
        assert_eq!(
            as_path.reconstruct_with_as4_path(&as4),
            AsPath::from_segments(vec![seq(&[64512, 131_072, 65001])]),
        );
    }

    #[test]
    fn reconstruct_ignores_as4_path_longer_than_as_path() {
        // §4.2.3: N < M -> AS4_PATH SHALL be ignored.
        let as_path = AsPath::from_segments(vec![seq(&[23456])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072, 131_073])]);
        assert_eq!(as_path.reconstruct_with_as4_path(&as4), as_path);
    }

    #[test]
    fn reconstruct_counts_as_set_as_one() {
        // AS_PATH: seq(64512) + set(23456, 65001) -> N = 2; AS4: set(...) -> M = 1.
        let as_path = AsPath::from_segments(vec![seq(&[64512]), set(&[23456, 65001])]);
        let as4 = AsPath::from_segments(vec![set(&[131_072, 65001])]);
        assert_eq!(
            as_path.reconstruct_with_as4_path(&as4),
            AsPath::from_segments(vec![seq(&[64512]), set(&[131_072, 65001])]),
        );
    }

    #[test]
    fn reconstruct_takes_leading_confed_segment() {
        // RFC 6793 §4.2.3: a leading AS_CONFED_SEQUENCE SHALL be prepended;
        // it counts as zero ASNs (RFC 5065) so N = 2, M = 1.
        let as_path = AsPath::from_segments(vec![cseq(&[65010]), seq(&[64512, 23456])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072])]);
        assert_eq!(
            as_path.reconstruct_with_as4_path(&as4),
            AsPath::from_segments(vec![cseq(&[65010]), seq(&[64512, 131_072])]),
        );
    }

    #[test]
    fn reconstruct_takes_confed_segment_adjacent_to_prepended_segment() {
        // [seq(64512)] is prepended (N=2, M=1); the confed segment that
        // follows is adjacent to it, so it is prepended too (§4.2.3).
        let as_path = AsPath::from_segments(vec![seq(&[64512]), cseq(&[65010]), seq(&[23456])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072])]);
        assert_eq!(
            as_path.reconstruct_with_as4_path(&as4),
            AsPath::from_segments(vec![seq(&[64512]), cseq(&[65010]), seq(&[131_072])]),
        );
    }

    #[test]
    fn reconstruct_does_not_take_confed_segment_beyond_the_prepended_region() {
        // N == M: nothing is prepended and the trailing confed segment is
        // not adjacent to a prepended segment, so it is replaced by AS4_PATH.
        let as_path = AsPath::from_segments(vec![seq(&[23456]), cseq(&[65010])]);
        let as4 = AsPath::from_segments(vec![seq(&[131_072])]);
        assert_eq!(as_path.reconstruct_with_as4_path(&as4), as4);
    }

    #[test]
    fn reconstruct_ignores_confed_segments_in_as4_path() {
        // RFC 6793 §6 forbids confed segments in AS4_PATH; they must not
        // contribute to M or be copied into the result.
        let as_path = AsPath::from_segments(vec![seq(&[64512, 23456])]);
        let as4 = AsPath::from_segments(vec![cseq(&[65010]), seq(&[131_072])]);
        assert_eq!(
            as_path.reconstruct_with_as4_path(&as4),
            AsPath::from_segments(vec![seq(&[64512, 131_072])]),
        );
    }

    #[test]
    fn reconstruct_with_empty_as4_path_is_identity() {
        let as_path = AsPath::from_segments(vec![seq(&[64512, 23456])]);
        assert_eq!(as_path.reconstruct_with_as4_path(&AsPath::new()), as_path);
        let confed_only = AsPath::from_segments(vec![cseq(&[65010])]);
        assert_eq!(as_path.reconstruct_with_as4_path(&confed_only), as_path);
    }

    #[test]
    fn reconstruct_does_not_coalesce_past_255_asns() {
        let head: Vec<u32> = (1..=200).collect();
        let tail: Vec<u32> = (1001..=1100).collect();
        let mut wire: Vec<u32> = head.clone();
        wire.extend(std::iter::repeat_n(23456, 100));
        let as_path = AsPath::from_segments(vec![seq(&wire)]);
        let as4 = AsPath::from_segments(vec![seq(&tail)]);
        let got = as_path.reconstruct_with_as4_path(&as4);
        assert_eq!(got.path_length(), 300);
        assert_eq!(got.segments(), &[seq(&head), seq(&tail)]);
    }

    #[test]
    fn has_non_mappable_asn_inspects_every_segment_type() {
        assert!(!AsPath::new().has_non_mappable_asn());
        assert!(!AsPath::from_segments(vec![seq(&[65535, 23456])]).has_non_mappable_asn());
        assert!(AsPath::from_segments(vec![seq(&[1]), set(&[65536])]).has_non_mappable_asn());
        assert!(AsPath::from_segments(vec![cseq(&[70000])]).has_non_mappable_asn());
    }

    #[test]
    fn downgrade_for_two_byte_peer_all_four_byte() {
        let path = AsPath::from_sequence(vec![Asn::new(131_072), Asn::new(200_000)]);
        let (downgraded, orig) = path.downgrade_for_two_byte_peer();
        assert!(orig.is_some());
        let asns = downgraded.segments()[0].asns();
        assert!(asns.iter().all(|&a| a == Asn::TRANS));
    }

    #[test]
    fn downgrade_for_two_byte_peer_preserves_segment_type() {
        let path = AsPath::from_segments(vec![AsPathSegment::Set(vec![
            Asn::new(131_072),
            Asn::new(65001),
        ])]);
        let (downgraded, _) = path.downgrade_for_two_byte_peer();
        assert!(matches!(downgraded.segments()[0], AsPathSegment::Set(_)));
        let asns = downgraded.segments()[0].asns();
        assert_eq!(asns[0], Asn::TRANS);
        assert_eq!(asns[1], Asn::new(65001));
    }

    #[test]
    fn downgrade_for_two_byte_peer_preserves_confed_sequence_type() {
        let path = AsPath::from_segments(vec![AsPathSegment::ConfedSequence(vec![
            Asn::new(131_072),
            Asn::new(65001),
        ])]);
        let (downgraded, _) = path.downgrade_for_two_byte_peer();
        assert!(matches!(
            downgraded.segments()[0],
            AsPathSegment::ConfedSequence(_)
        ));
        let asns = downgraded.segments()[0].asns();
        assert_eq!(asns[0], Asn::TRANS);
        assert_eq!(asns[1], Asn::new(65001));
    }

    #[test]
    fn downgrade_for_two_byte_peer_preserves_confed_set_type() {
        let path = AsPath::from_segments(vec![AsPathSegment::ConfedSet(vec![
            Asn::new(200_000),
            Asn::new(65002),
        ])]);
        let (downgraded, _) = path.downgrade_for_two_byte_peer();
        assert!(matches!(
            downgraded.segments()[0],
            AsPathSegment::ConfedSet(_)
        ));
        let asns = downgraded.segments()[0].asns();
        assert_eq!(asns[0], Asn::TRANS);
        assert_eq!(asns[1], Asn::new(65002));
    }

    // ── AS4_PATH construction (RFC 6793 §§3, 4.2.2; issue #109) ─────────────

    /// The `AS4_PATH` payload `path` produces toward a two-octet peer.
    fn as4_of(path: &AsPath) -> Option<AsPath> {
        path.downgrade_for_two_byte_peer().1.map(As4Path::into_path)
    }

    /// RFC 6793 §4.2.2: "Whenever the AS path information contains the
    /// `AS_CONFED_SEQUENCE` or `AS_CONFED_SET` path segment, the NEW BGP speaker
    /// MUST exclude such path segments from the `AS4_PATH` attribute being
    /// constructed." The two-octet `AS_PATH` keeps them.
    #[test]
    fn as4_path_excludes_confed_segments_but_as_path_keeps_them() {
        let path = AsPath::from_segments(vec![cseq(&[65010, 200_000]), seq(&[131_072, 65001])]);
        assert_eq!(
            as4_of(&path),
            Some(AsPath::from_segments(vec![seq(&[131_072, 65001])]))
        );
        assert_eq!(
            path.downgrade_for_two_byte_peer().0,
            AsPath::from_segments(vec![cseq(&[65010, 23456]), seq(&[23456, 65001])])
        );
    }

    /// RFC 6793 §3 declares `AS_CONFED_SET` invalid in `AS4_PATH` as well.
    /// (RFC 9774 additionally forbids advertising it at all; that is the
    /// speaker's export rule, not this construction rule.)
    #[test]
    fn as4_path_excludes_confed_set() {
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSet(vec![Asn::new(65010)]),
            seq(&[131_072]),
        ]);
        assert_eq!(
            as4_of(&path),
            Some(AsPath::from_segments(vec![seq(&[131_072])]))
        );
    }

    /// Nothing is left to carry once confederation segments are excluded: no
    /// `AS4_PATH` at all, never an empty one (RFC 6793 §6 calls an `AS4_PATH`
    /// shorter than 6 octets malformed).
    #[test]
    fn confed_only_path_has_no_as4_path() {
        let path = AsPath::from_segments(vec![cseq(&[200_000, 65010])]);
        assert_eq!(as4_of(&path), None);
    }

    /// The only non-mappable AS sits in a confederation segment, which
    /// `AS4_PATH` may not carry: what remains is all mappable, so "the NEW BGP
    /// speaker MUST NOT send the `AS4_PATH` attribute" (§4.2.2).
    #[test]
    fn non_mappable_asn_only_in_confed_segment_has_no_as4_path() {
        let path = AsPath::from_segments(vec![cseq(&[200_000]), seq(&[65001])]);
        assert_eq!(as4_of(&path), None);
        assert_eq!(
            path.downgrade_for_two_byte_peer().0,
            AsPath::from_segments(vec![cseq(&[23456]), seq(&[65001])])
        );
    }

    // ── neighboring_as (RFC 4271 §9.1 step 6 — MED comparison) ───────────────

    #[test]
    fn neighboring_as_returns_first_asn_of_first_sequence() {
        let path = AsPath::from_sequence(vec![Asn::new(65001), Asn::new(65002)]);
        assert_eq!(path.neighboring_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn neighboring_as_empty_path_is_none() {
        assert_eq!(AsPath::new().neighboring_as(), None);
    }

    #[test]
    fn neighboring_as_set_only_path_is_none() {
        // RFC 4271 §9.1 step 6: MED is only compared between routes from the
        // same neighboring AS. A Set-only path has no well-defined neighbor.
        let path = AsPath::from_segments(vec![AsPathSegment::Set(vec![
            Asn::new(65001),
            Asn::new(65002),
        ])]);
        assert_eq!(path.neighboring_as(), None);
    }

    #[test]
    fn neighboring_as_confed_segment_before_sequence_is_skipped() {
        // Confederation segments precede the regular AS_PATH. neighboring_as
        // must skip them and return the first ASN of the first Sequence segment.
        let path = AsPath::from_segments(vec![
            AsPathSegment::ConfedSequence(vec![Asn::new(65100)]),
            AsPathSegment::Sequence(vec![Asn::new(65001), Asn::new(65002)]),
        ]);
        assert_eq!(path.neighboring_as(), Some(Asn::new(65001)));
    }

    #[test]
    fn neighboring_as_single_asn_sequence() {
        let path = AsPath::from_sequence(vec![Asn::new(65099)]);
        assert_eq!(path.neighboring_as(), Some(Asn::new(65099)));
    }
}
