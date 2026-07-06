// daemon/origination.rs — Local route origination and withdrawal.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn originate_route(&mut self, route: Route<Ipv4Addr>) {
        self.originate_routes(vec![route]);
    }

    /// Injects a batch of routes into the Loc-RIB and advertises all of them
    /// to established peers in a single propagation pass.
    ///
    /// All routes are inserted before propagation begins — one `propagate_to_all_peers`
    /// call regardless of batch size. This matches GoBGP `AddPathStream` semantics.
    ///
    /// Originated routes bypass import policy; they go directly into Loc-RIB.
    /// Export policy still applies on the outbound side.
    pub(crate) fn originate_routes(&mut self, routes: Vec<Route<Ipv4Addr>>) {
        let mut nlris = Vec::with_capacity(routes.len());
        for route in routes {
            let nlri = route.nlri;
            self.rib_mut().originated_routes.insert(nlri);
            // Borrow for the event before moving into rib_insert_v4.
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
            self.rib_insert_v4(PeerId::from(LOCAL_ORIGIN_PEER), route);
            nlris.push(nlri);
        }
        self.propagate_to_all_peers(&nlris);
        self.flush_pending();
        crate::metrics::update_originated_routes(
            self.rib.originated_routes.len(),
            self.rib.originated_routes_v6.len(),
        );
    }

    /// Injects a single IPv6 route into `loc_rib_v6` and propagates it.
    pub(crate) fn originate_route_v6(&mut self, route: Route<Ipv6Addr>) {
        self.originate_routes_v6(vec![route]);
    }

    /// Injects a batch of IPv6 routes into `loc_rib_v6` and propagates all of
    /// them in a single pass (one `propagate_to_all_peers_v6` call).
    pub(crate) fn originate_routes_v6(&mut self, routes: Vec<Route<Ipv6Addr>>) {
        let mut nlris = Vec::with_capacity(routes.len());
        for route in routes {
            let nlri = route.nlri;
            self.rib_mut().originated_routes_v6.insert(nlri);
            // Borrow for the event before moving into rib_insert_v6.
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_v6_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
            let fib_change = self.rib_insert_v6(PeerId::from(LOCAL_ORIGIN_PEER), route);
            if let Some(fm) = &self.fib_manager {
                fm.apply_v6(fib_change);
            }
            nlris.push(nlri);
        }
        self.propagate_to_all_peers_v6(&nlris);
        self.flush_pending();
        crate::metrics::update_originated_routes(
            self.rib.originated_routes.len(),
            self.rib.originated_routes_v6.len(),
        );
    }

    /// Withdraws a single locally originated route.
    ///
    /// No-op if the prefix was not previously originated.
    pub(crate) fn withdraw_originated_route(&mut self, nlri: Nlri<Ipv4Addr>) {
        self.withdraw_originated_routes(&[nlri]);
    }

    /// Withdraws a batch of locally originated routes in a single propagation
    /// pass.
    pub(crate) fn withdraw_originated_routes(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        for nlri in nlris {
            self.rib_mut().originated_routes.remove(nlri);
            let fib_change = self.rib_withdraw_v4(&PeerId::from(LOCAL_ORIGIN_PEER), nlri);
            if let Some(fm) = &self.fib_manager {
                fm.apply_v4(fib_change);
            }
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Withdrawn as i32,
                route: None,
                withdrawn_prefix: Some(nlri.to_string()),
            });
        }
        self.propagate_to_all_peers(nlris);
        self.flush_pending();
        crate::metrics::update_originated_routes(
            self.rib.originated_routes.len(),
            self.rib.originated_routes_v6.len(),
        );
    }

    /// Withdraws a single locally originated IPv6 route.
    ///
    /// No-op if the prefix was not previously originated.
    pub(crate) fn withdraw_originated_route_v6(&mut self, nlri: Nlri<Ipv6Addr>) {
        self.withdraw_originated_routes_v6(&[nlri]);
    }

    /// Withdraws a batch of locally originated IPv6 routes in a single
    /// propagation pass.
    pub(crate) fn withdraw_originated_routes_v6(&mut self, nlris: &[Nlri<Ipv6Addr>]) {
        for nlri in nlris {
            self.rib_mut().originated_routes_v6.remove(nlri);
            let fib_change = self.rib_withdraw_v6(&PeerId::from(LOCAL_ORIGIN_PEER), nlri);
            if let Some(fm) = &self.fib_manager {
                fm.apply_v6(fib_change);
            }
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Withdrawn as i32,
                route: None,
                withdrawn_prefix: Some(nlri.to_string()),
            });
        }
        self.propagate_to_all_peers_v6(nlris);
        self.flush_pending();
        crate::metrics::update_originated_routes(
            self.rib.originated_routes.len(),
            self.rib.originated_routes_v6.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use pathvector_rib::BestPathChange;
    use pathvector_types::{AsPath, NextHop, Nlri, Origin};

    use super::*;
    use crate::daemon::tests::{make_state, with_recording_fib};

    const LOCAL_AS: u32 = 65001;
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER_AS: u32 = 65002;

    /// `(metric_name, sorted_labels) -> DebugValue`, as returned by `capture`.
    type MetricsSnapshot = std::collections::HashMap<(String, Vec<(String, String)>), DebugValue>;

    /// Runs `f` against a fresh, isolated recorder and returns every emitted
    /// metric as `(metric_name, sorted_labels) -> DebugValue`. Duplicated from
    /// `metrics.rs`'s private `capture()` — `metrics-util` is already a
    /// workspace dev-dependency, and this is simpler than exporting a private
    /// test helper across module boundaries.
    fn capture(f: impl FnOnce()) -> MetricsSnapshot {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(composite_key, _unit, _desc, value)| {
                let key = composite_key.key();
                let mut labels: Vec<(String, String)> = key
                    .labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect();
                labels.sort();
                ((key.name().to_string(), labels), value)
            })
            .collect()
    }

    fn route_v6(prefix: &str) -> Route<Ipv6Addr> {
        let nlri: Nlri<Ipv6Addr> = prefix.parse().unwrap();
        RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V6("2001:db8::1".parse().unwrap()))
            .build()
    }

    fn route_v4(prefix: &str) -> Route<Ipv4Addr> {
        let nlri: Nlri<Ipv4Addr> = prefix.parse().unwrap();
        RouteBuilder::new(nlri, Origin::Igp, AsPath::new())
            .next_hop(NextHop::V4("192.0.2.1".parse().unwrap()))
            .build()
    }

    /// `originate_routes_v6` must notify the FIB manager when one is set.
    #[test]
    fn originate_v6_notifies_fib_manager() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        state.originate_route_v6(route_v6("2001:db8::/32"));

        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Announced(..))),
            "originate_route_v6 must push an Announced FIB change"
        );
    }

    /// `withdraw_originated_routes` must notify the FIB manager for each withdrawn NLRI.
    #[test]
    fn withdraw_v4_notifies_fib_manager() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        let nlri: Nlri<Ipv4Addr> = "10.0.0.0/8".parse().unwrap();
        state.originate_route(route_v4("10.0.0.0/8"));
        fib.v4.lock().unwrap().clear();

        state.withdraw_originated_route(nlri);

        let changes = fib.v4.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "withdraw_originated_route must push a Withdrawn FIB change"
        );
    }

    /// `withdraw_originated_routes_v6` must notify the FIB manager for each withdrawn NLRI.
    #[test]
    fn withdraw_v6_notifies_fib_manager() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let fib = with_recording_fib(&mut state);

        state.originate_route_v6(route_v6("2001:db8::/32"));
        fib.v6.lock().unwrap().clear();

        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        state.withdraw_originated_route_v6(nlri);

        let changes = fib.v6.lock().unwrap().clone();
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, BestPathChange::Withdrawn(_))),
            "withdraw_originated_route_v6 must push a Withdrawn FIB change"
        );
    }

    fn originated_routes_gauge<'a>(snap: &'a MetricsSnapshot, afi: &str) -> Option<&'a DebugValue> {
        snap.get(&(
            "pathvectord_bgp_originated_routes".to_string(),
            vec![("afi".to_string(), afi.to_string())],
        ))
    }

    #[test]
    fn originate_routes_updates_originated_routes_gauge() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let snap = capture(|| {
            state.originate_routes(vec![route_v4("203.0.113.0/24")]);
        });
        assert_eq!(
            originated_routes_gauge(&snap, "ipv4"),
            Some(&DebugValue::Gauge(1.0.into())),
            "originate_routes must update the originated-routes gauge"
        );
        assert_eq!(
            originated_routes_gauge(&snap, "ipv6"),
            Some(&DebugValue::Gauge(0.0.into())),
            "the untouched family must still be (re-)reported, at its real count"
        );
    }

    #[test]
    fn originate_routes_v6_updates_originated_routes_gauge() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        let snap = capture(|| {
            state.originate_routes_v6(vec![route_v6("2001:db8::/32")]);
        });
        assert_eq!(
            originated_routes_gauge(&snap, "ipv6"),
            Some(&DebugValue::Gauge(1.0.into())),
            "originate_routes_v6 must update the originated-routes gauge"
        );
    }

    #[test]
    fn withdraw_originated_routes_updates_gauge_back_to_zero() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        state.originate_route(route_v4("203.0.113.0/24"));

        let nlri: Nlri<Ipv4Addr> = "203.0.113.0/24".parse().unwrap();
        let snap = capture(|| {
            state.withdraw_originated_route(nlri);
        });
        assert_eq!(
            originated_routes_gauge(&snap, "ipv4"),
            Some(&DebugValue::Gauge(0.0.into())),
            "withdraw_originated_routes must update the gauge back to 0"
        );
    }

    #[test]
    fn withdraw_originated_routes_v6_updates_gauge_back_to_zero() {
        let (mut state, _rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_IP), PEER_AS)]);
        state.originate_route_v6(route_v6("2001:db8::/32"));

        let nlri: Nlri<Ipv6Addr> = "2001:db8::/32".parse().unwrap();
        let snap = capture(|| {
            state.withdraw_originated_route_v6(nlri);
        });
        assert_eq!(
            originated_routes_gauge(&snap, "ipv6"),
            Some(&DebugValue::Gauge(0.0.into())),
            "withdraw_originated_routes_v6 must update the gauge back to 0"
        );
    }
}
