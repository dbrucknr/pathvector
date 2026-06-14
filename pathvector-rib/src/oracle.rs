//! Next-hop reachability oracle for RFC 4271 §9.1 decision steps 1 and 8.

use pathvector_types::NextHop;

/// Provides next-hop reachability and IGP metric information to the BGP
/// decision process.
///
/// # RFC context
///
/// RFC 4271 §9.1.2.1 (step 1): a route whose `NEXT_HOP` is not reachable
/// in the local FIB **must not** participate in best-path selection.
///
/// RFC 4271 §9.1.2.2 (step 8): among otherwise-equal routes, prefer the
/// one whose `NEXT_HOP` has the lowest IGP metric.
///
/// # Default implementation
///
/// [`AlwaysReachable`] treats every next-hop as reachable with no IGP
/// metric. This preserves pre-oracle behavior when no FIB integration is
/// available — step 1 never filters, step 8 is skipped.
///
/// # Implementing a real oracle
///
/// ```ignore
/// use pathvector_rib::oracle::NextHopOracle;
/// use pathvector_types::NextHop;
///
/// struct KernelOracle { /* netlink socket, etc. */ }
///
/// impl NextHopOracle for KernelOracle {
///     fn is_reachable(&self, next_hop: &NextHop) -> bool {
///         // consult kernel FIB via netlink
///         todo!()
///     }
///     fn igp_metric(&self, next_hop: &NextHop) -> Option<u32> {
///         // return IGP metric if available
///         todo!()
///     }
/// }
/// ```
pub trait NextHopOracle {
    /// Returns `true` if `next_hop` is reachable in the local FIB.
    ///
    /// Routes for which this returns `false` are excluded from best-path
    /// selection (RFC 4271 §9.1.2.1 step 1).
    fn is_reachable(&self, next_hop: &NextHop) -> bool;

    /// Returns the IGP metric to reach `next_hop`, or `None` if unknown.
    ///
    /// When both candidates have a known metric, the lower metric wins
    /// (RFC 4271 §9.1.2.2 step 8). When one or both are `None`, step 8
    /// is skipped for that comparison.
    fn igp_metric(&self, next_hop: &NextHop) -> Option<u32>;
}

/// A no-op oracle that marks every next-hop reachable and returns no IGP
/// metrics.
///
/// This is the default when no FIB integration exists. Steps 1 and 8 are
/// effectively bypassed: all candidates reach the comparison stage, and
/// the step-8 tiebreaker is never triggered.
pub struct AlwaysReachable;

impl NextHopOracle for AlwaysReachable {
    fn is_reachable(&self, _: &NextHop) -> bool {
        true
    }

    fn igp_metric(&self, _: &NextHop) -> Option<u32> {
        None
    }
}
