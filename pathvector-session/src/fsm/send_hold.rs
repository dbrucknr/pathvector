//! The RFC 9687 `SendHoldTime` session attribute.
//!
//! RFC 9687 §4.1: "`SendHoldTime` determines how long a BGP speaker will stay
//! in the Established state before the TCP connection is dropped because no
//! BGP messages can be transmitted to its peer."

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

/// RFC 9687 §6: the default is "the greater of: 8 minutes or 2 times the
/// negotiated `HoldTime`".
const DEFAULT_FLOOR_SECS: u32 = 8 * 60;

/// A peer's `SendHoldTime` setting.
///
/// RFC 9687 §4.4: "If `SendHoldTime` is non-zero, then it MUST be greater than
/// the value of `HoldTime`". [`Self::from_secs`] rejects anything else.
///
/// The [`Default`] is enabled, as RFC 9687 §6 recommends.
///
/// ```
/// use pathvector_session::fsm::SendHoldTime;
///
/// assert!(SendHoldTime::from_secs(90, 90).is_err());
/// assert!(SendHoldTime::from_secs(91, 90).is_ok());
/// assert_eq!(SendHoldTime::from_secs(0, 90), Ok(SendHoldTime::DISABLED));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendHoldTime(Setting);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Setting {
    #[default]
    Recommended,
    Disabled,
    Seconds(NonZeroU32),
}

/// A `SendHoldTime` that is not greater than the `HoldTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSendHoldTime {
    /// The rejected `SendHoldTime`, in seconds.
    pub send_hold_time: u32,
    /// The `HoldTime` it was checked against, in seconds.
    pub hold_time: u16,
}

impl fmt::Display for InvalidSendHoldTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SendHoldTime {} s must be 0 or greater than the HoldTime of {} s (RFC 9687 §4.4)",
            self.send_hold_time, self.hold_time
        )
    }
}

impl std::error::Error for InvalidSendHoldTime {}

impl SendHoldTime {
    /// The greater of 8 minutes and twice the negotiated `HoldTime`
    /// (RFC 9687 §6).
    pub const RECOMMENDED: Self = Self(Setting::Recommended);

    /// No `SendHoldTimer`.
    pub const DISABLED: Self = Self(Setting::Disabled);

    /// A configured value, checked against the configured `HoldTime`. `0`
    /// disables the timer.
    ///
    /// The negotiated `HoldTime` is never larger than the configured one, so a
    /// value accepted here stays valid for every session.
    ///
    /// # Errors
    ///
    /// If `seconds` is non-zero and not greater than `hold_time`.
    pub fn from_secs(seconds: u32, hold_time: u16) -> Result<Self, InvalidSendHoldTime> {
        match NonZeroU32::new(seconds) {
            None => Ok(Self::DISABLED),
            Some(s) if s.get() > u32::from(hold_time) => Ok(Self(Setting::Seconds(s))),
            Some(_) => Err(InvalidSendHoldTime {
                send_hold_time: seconds,
                hold_time,
            }),
        }
    }

    /// The initial value of the `SendHoldTimer` for a session that negotiated
    /// `negotiated_hold_time`, or `None` if the timer does not run.
    ///
    /// With a negotiated `HoldTime` of zero there are no KEEPALIVEs, so an idle
    /// but healthy session sends nothing: RFC 9687 §4.3 stops the timer.
    ///
    /// A configured value that is not greater than the negotiated `HoldTime`
    /// (it was checked against a different one) falls back to the recommended
    /// value, so the result always satisfies §4.4.
    pub(crate) fn resolve(self, negotiated_hold_time: u16) -> Option<Duration> {
        if negotiated_hold_time == 0 {
            return None;
        }
        let seconds = match self.0 {
            Setting::Disabled => return None,
            Setting::Seconds(s) if s.get() > u32::from(negotiated_hold_time) => s.get(),
            Setting::Recommended | Setting::Seconds(_) => {
                DEFAULT_FLOOR_SECS.max(2 * u32::from(negotiated_hold_time))
            }
        };
        Some(Duration::from_secs(u64::from(seconds)))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// RFC 9687 §6: "the greater of: 8 minutes or 2 times the negotiated
    /// `HoldTime`".
    #[test]
    fn recommended_value_is_the_greater_of_8_minutes_and_twice_hold_time() {
        let r = SendHoldTime::RECOMMENDED;
        assert_eq!(r.resolve(3), Some(secs(480)));
        assert_eq!(r.resolve(90), Some(secs(480)));
        assert_eq!(r.resolve(240), Some(secs(480)));
        assert_eq!(r.resolve(241), Some(secs(482)));
        assert_eq!(r.resolve(u16::MAX), Some(secs(131_070)));
        assert_eq!(SendHoldTime::default(), r);
    }

    /// RFC 9687 §4.4: non-zero values MUST be greater than `HoldTime`.
    #[test]
    fn configured_value_must_exceed_hold_time() {
        for bad in [1, 89, 90] {
            assert_eq!(
                SendHoldTime::from_secs(bad, 90),
                Err(InvalidSendHoldTime {
                    send_hold_time: bad,
                    hold_time: 90
                })
            );
        }
        assert_eq!(
            SendHoldTime::from_secs(91, 90).unwrap().resolve(90),
            Some(secs(91))
        );
    }

    /// RFC 9687 §4.3: zero `SendHoldTime`, or a zero negotiated `HoldTime`,
    /// means no timer.
    #[test]
    fn zero_send_hold_or_zero_hold_time_disables_the_timer() {
        assert_eq!(SendHoldTime::from_secs(0, 90), Ok(SendHoldTime::DISABLED));
        assert_eq!(SendHoldTime::DISABLED.resolve(90), None);
        assert_eq!(SendHoldTime::RECOMMENDED.resolve(0), None);
        assert_eq!(SendHoldTime::from_secs(600, 90).unwrap().resolve(0), None);
    }

    #[test]
    fn error_message_names_both_values() {
        let err = SendHoldTime::from_secs(30, 90).unwrap_err().to_string();
        assert!(err.contains("30 s") && err.contains("90 s"), "{err}");
    }

    proptest! {
        /// §4.4 holds for every setting and negotiated `HoldTime`, including a
        /// value validated against a different `HoldTime`. Being greater than
        /// `HoldTime` it also exceeds the `KeepaliveTime`, so a session that is
        /// sending its KEEPALIVEs cannot expire.
        #[test]
        fn a_running_timer_always_exceeds_hold_time(
            configured in 0u32..200_000,
            checked_against in any::<u16>(),
            negotiated in 3u16..,
        ) {
            let settings = [
                Some(SendHoldTime::RECOMMENDED),
                Some(SendHoldTime::DISABLED),
                SendHoldTime::from_secs(configured, checked_against).ok(),
            ];
            for setting in settings.into_iter().flatten() {
                if let Some(d) = setting.resolve(negotiated) {
                    prop_assert!(d > Duration::from_secs(u64::from(negotiated)));
                }
            }
        }
    }
}
