/// The outcome of a single [`Term`](crate::Term) or [`Policy`](crate::Policy)
/// evaluation.
///
/// Actions return a `Decision` to tell the policy engine what to do next.
/// `Accept` and `Reject` are terminal — evaluation stops immediately.
/// `Next` signals that this term matched (and may have modified the route)
/// but defers the final verdict to subsequent terms or the default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Accept the route. Propagate it according to BGP rules.
    Accept,
    /// Reject the route. Do not propagate it.
    Reject,
    /// This term matched and may have modified the route, but the final
    /// decision is deferred to the next matching term or the default action.
    Next,
}

/// What a [`Policy`](crate::Policy) does when no term's condition matches.
///
/// In Junos the implicit default is to reject; in IOS route-maps the implicit
/// default is also to deny (reject). Most BGP implementations default to
/// reject, which is the safer choice — it is better to accidentally block a
/// route than to accidentally propagate one.
///
/// Set this explicitly on every [`Policy`](crate::Policy) to make intent clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// Accept the route if no term matched.
    Accept,
    /// Reject the route if no term matched.
    Reject,
}

impl From<DefaultAction> for Decision {
    fn from(d: DefaultAction) -> Self {
        match d {
            DefaultAction::Accept => Decision::Accept,
            DefaultAction::Reject => Decision::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_variants() {
        assert_eq!(Decision::Accept, Decision::Accept);
        assert_ne!(Decision::Accept, Decision::Reject);
        assert_ne!(Decision::Accept, Decision::Next);
    }

    #[test]
    fn test_default_action_into_decision() {
        assert_eq!(Decision::from(DefaultAction::Accept), Decision::Accept);
        assert_eq!(Decision::from(DefaultAction::Reject), Decision::Reject);
    }
}
