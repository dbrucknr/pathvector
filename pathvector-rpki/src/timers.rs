//! RFC 8210 §6 protocol timing parameters — pure, no clocks.
//!
//! The cache advertises Refresh, Retry and Expire intervals in End of Data
//! (v1 only). RFC 8210 §6 gives each a range:
//!
//! | Interval | Min | Max | Recommended default |
//! |---|---|---|---|
//! | Refresh | 1 s | 86 400 s (1 day) | 3 600 s |
//! | Retry | 1 s | 7 200 s (2 h) | 600 s |
//! | Expire | 600 s | 172 800 s (2 days) | 7 200 s |
//!
//! "Caches MUST set Expire Interval to a value larger than either Refresh
//! Interval or Retry Interval."
//!
//! A v0 End of Data (RFC 6810) carries no intervals, so the configured values
//! apply. A v1 End of Data's values replace the configured ones for that
//! sync, clamped into the ranges above: a hostile or broken cache must not be
//! able to make the router poll in a zero-delay loop (Refresh/Retry 0) or
//! empty the cache in seconds (Expire 5).

use std::{ops::RangeInclusive, time::Duration};

use crate::pdu::EndOfDataIntervals;

pub(crate) const REFRESH_SECS: RangeInclusive<u32> = 1..=86_400;
pub(crate) const RETRY_SECS: RangeInclusive<u32> = 1..=7_200;
pub(crate) const EXPIRE_SECS: RangeInclusive<u32> = 600..=172_800;

/// The effective timers for the sync that just completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timers {
    /// How long to wait after End of Data before polling again (unless a
    /// Serial Notify arrives first).
    pub(crate) refresh: Duration,
    /// How long to wait before retrying a failed query.
    pub(crate) retry: Duration,
    /// How long, from receipt of End of Data, the data may be retained
    /// without another completed sync.
    pub(crate) expire: Duration,
}

/// One advertised value that was outside its RFC 8210 §6 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Clamped {
    pub(crate) name: &'static str,
    pub(crate) advertised: u32,
    pub(crate) used: u32,
}

/// Result of applying an End of Data to the configured defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Effective {
    pub(crate) timers: Timers,
    pub(crate) clamped: Vec<Clamped>,
    /// The cache violated "Expire Interval larger than Refresh and Retry".
    /// The advertised Expire is still honoured (RFC: "MUST NOT retain the
    /// data past the time indicated").
    pub(crate) expire_not_after_poll_intervals: bool,
}

impl Timers {
    /// Timers as configured. Used as-is for v0 sessions.
    pub(crate) fn new(refresh: Duration, retry: Duration, expire: Duration) -> Self {
        Self {
            refresh,
            retry,
            expire,
        }
    }

    /// The timers in force after an End of Data carrying `intervals` (`None`
    /// for v0), given the configured `self`.
    pub(crate) fn after_end_of_data(self, intervals: Option<EndOfDataIntervals>) -> Effective {
        let Some(iv) = intervals else {
            return Effective {
                timers: self,
                clamped: Vec::new(),
                expire_not_after_poll_intervals: false,
            };
        };
        let mut clamped = Vec::new();
        let mut take = |name, advertised: u32, range: &RangeInclusive<u32>| {
            let used = advertised.clamp(*range.start(), *range.end());
            if used != advertised {
                clamped.push(Clamped {
                    name,
                    advertised,
                    used,
                });
            }
            used
        };
        let refresh = take("refresh", iv.refresh, &REFRESH_SECS);
        let retry = take("retry", iv.retry, &RETRY_SECS);
        let expire = take("expire", iv.expire, &EXPIRE_SECS);
        Effective {
            timers: Self {
                refresh: Duration::from_secs(u64::from(refresh)),
                retry: Duration::from_secs(u64::from(retry)),
                expire: Duration::from_secs(u64::from(expire)),
            },
            clamped,
            expire_not_after_poll_intervals: expire <= refresh.max(retry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn defaults() -> Timers {
        Timers::new(secs(3600), secs(600), secs(7200))
    }

    #[allow(clippy::unnecessary_wraps)] // mirrors `after_end_of_data`'s parameter
    fn iv(refresh: u32, retry: u32, expire: u32) -> Option<EndOfDataIntervals> {
        Some(EndOfDataIntervals {
            refresh,
            retry,
            expire,
        })
    }

    /// RFC 6810 End of Data has no intervals: configured values apply.
    #[test]
    fn v0_uses_the_configured_timers() {
        let e = defaults().after_end_of_data(None);
        assert_eq!(e.timers, defaults());
        assert!(e.clamped.is_empty());
    }

    /// RFC 8210 §6: the cache's values replace the configured ones, in either
    /// direction.
    #[test]
    fn v1_advertised_values_replace_configured_ones() {
        let e = defaults().after_end_of_data(iv(300, 120, 900));
        assert_eq!(e.timers, Timers::new(secs(300), secs(120), secs(900)));
        let e = defaults().after_end_of_data(iv(7200, 3600, 86_400));
        assert_eq!(e.timers, Timers::new(secs(7200), secs(3600), secs(86_400)));
        assert!(e.clamped.is_empty());
    }

    /// The RFC 8210 §6 boundary values are accepted as-is.
    #[test]
    fn range_boundaries_are_in_range() {
        for (r, t, x) in [(1, 1, 600), (86_400, 7_200, 172_800)] {
            let e = defaults().after_end_of_data(iv(r, t, x));
            assert!(e.clamped.is_empty(), "{r}/{t}/{x}");
            assert_eq!(e.timers.expire, secs(u64::from(x)));
        }
    }

    /// Out-of-range advertisements are clamped, and reported.
    #[test]
    fn out_of_range_values_are_clamped_to_the_rfc_ranges() {
        let e = defaults().after_end_of_data(iv(0, 0, 5));
        assert_eq!(e.timers, Timers::new(secs(1), secs(1), secs(600)));
        assert_eq!(e.clamped.len(), 3);
        let e = defaults().after_end_of_data(iv(u32::MAX, u32::MAX, u32::MAX));
        assert_eq!(
            e.timers,
            Timers::new(secs(86_400), secs(7_200), secs(172_800))
        );
        // One below / above each boundary.
        assert_eq!(
            defaults().after_end_of_data(iv(86_401, 7_201, 599)).timers,
            Timers::new(secs(86_400), secs(7_200), secs(600))
        );
    }

    #[test]
    fn clamp_report_names_the_field_and_values() {
        let e = defaults().after_end_of_data(iv(3600, 600, 5));
        assert_eq!(
            e.clamped,
            vec![Clamped {
                name: "expire",
                advertised: 5,
                used: 600
            }]
        );
    }

    /// §6: "Caches MUST set Expire Interval to a value larger than either
    /// Refresh Interval or Retry Interval." A cache that doesn't is flagged;
    /// its Expire is still honoured.
    #[test]
    fn expire_not_larger_than_poll_intervals_is_flagged_but_honoured() {
        let e = defaults().after_end_of_data(iv(3600, 600, 3600));
        assert!(e.expire_not_after_poll_intervals);
        assert_eq!(e.timers.expire, secs(3600));
        assert!(
            !defaults()
                .after_end_of_data(iv(3600, 600, 3601))
                .expire_not_after_poll_intervals
        );
    }
}
