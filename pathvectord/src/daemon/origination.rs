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
            self.rib_insert_v4(PeerId::from(LOCAL_ORIGIN_PEER), route.clone());
            nlris.push(nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
        }
        self.propagate_to_all_peers(&nlris);
        self.flush_pending();
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
            let fib_change = self.rib_insert_v6(PeerId::from(LOCAL_ORIGIN_PEER), route.clone());
            if let Some(fm) = &self.fib_manager {
                fm.apply_v6(fib_change);
            }
            nlris.push(nlri);
            let _ = self.route_tx.send(proto::RouteEvent {
                r#type: proto::RouteEventType::Announced as i32,
                route: Some(grpc::route_v6_to_proto(
                    PeerId::from(LOCAL_ORIGIN_PEER),
                    nlri,
                    &route,
                )),
                withdrawn_prefix: None,
            });
        }
        self.propagate_to_all_peers_v6(&nlris);
        self.flush_pending();
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
    }
}
