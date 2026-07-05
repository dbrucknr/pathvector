// daemon/route.rs — Route processing: import/export, propagation, MRAI, handle_update.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    #[allow(clippy::similar_names)]
    pub(crate) fn on_route_update(
        &mut self,
        peer_ip: Ipv4Addr,
        mut msg: UpdateMessage,
    ) -> Option<NotificationMessage> {
        tracing::debug!(
            peer = %peer_ip,
            withdrawn = msg.withdrawn.len(),
            announced = msg.announced.len(),
            attrs = msg.attributes.len(),
            "on_route_update called"
        );
        // RFC 4724 §2 — detect End-of-RIB markers before any other processing.
        // IPv4 EOR: minimum-length UPDATE (all fields empty).
        if msg.withdrawn.is_empty() && msg.attributes.is_empty() && msg.announced.is_empty() {
            tracing::info!(peer = %peer_ip, "received IPv4 End-of-RIB marker (RFC 4724 §2)");
            Arc::make_mut(&mut self.rib).eor_received.insert(peer_ip);
            // RFC 4724 §4.2 — EOR ends the GR re-establishment window.  Any
            // NLRIs still in the stale set were not refreshed by the peer and
            // must be withdrawn now.
            if let Some(stale) = self.gr.stale_nlri.remove(&peer_ip) {
                let count = stale.len();
                if count > 0 {
                    tracing::info!(
                        peer = %peer_ip,
                        withdrawn = count,
                        "EOR received after GR re-establishment — withdrawing \
                         {count} stale NLRI(s) not refreshed by peer"
                    );
                    self.prune_stale_nlri(peer_ip, &stale);
                }
            }
            return None;
        }
        // IPv6 EOR: UPDATE with only an empty MP_UNREACH_NLRI for IPv6 unicast.
        if msg.withdrawn.is_empty()
            && msg.announced.is_empty()
            && matches!(
                msg.attributes.as_slice(),
                [PathAttribute::MpUnreachNlri(m)] if m.afi_safi == AfiSafi::IPV6_UNICAST && m.prefixes.is_empty()
            )
        {
            tracing::info!(peer = %peer_ip, "received IPv6 unicast End-of-RIB marker (RFC 4724 §2)");
            Arc::make_mut(&mut self.rib).eor_received_v6.insert(peer_ip);
            if let Some(stale) = self.gr.stale_nlri_v6.remove(&peer_ip) {
                let count = stale.len();
                if count > 0 {
                    tracing::info!(
                        peer = %peer_ip,
                        withdrawn = count,
                        "IPv6 EOR received after GR re-establishment — withdrawing \
                         {count} stale IPv6 NLRI(s) not refreshed by peer"
                    );
                    self.prune_stale_nlri_v6(peer_ip, &stale);
                }
            }
            return None;
        }

        let peer_id = PeerId::from(peer_ip);
        let peer_type = self
            .rib
            .peer_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);

        // Route reflection inbound processing (RFC 4456 §8).
        //
        // When acting as an RR and the source peer is iBGP (client or
        // non-client), we must:
        //   1. Perform loop detection on the ORIGINAL wire message.
        //   2. Inject ORIGINATOR_ID (if absent) and prepend CLUSTER_LIST.
        //
        // Loop detection must happen before injection so that cluster_id is
        // not detected in a CLUSTER_LIST that we just prepended ourselves.
        let is_rr = !self.rib.rr_clients.is_empty();
        if is_rr && peer_type == PeerType::Internal {
            let cluster_id = self.rib.cluster_id;
            let local_bgp_id = self.rib.local_bgp_id;

            // RFC 4456 §8: discard if ORIGINATOR_ID == our own BGP ID.
            // This means the route originated from one of our clients and has
            // been reflected back to us by another RR in the same cluster.
            let originator_loop = msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == local_bgp_id));
            if originator_loop {
                tracing::debug!(
                    peer = %peer_ip,
                    "RR loop: ORIGINATOR_ID matches local BGP ID — discarding UPDATE (RFC 4456)"
                );
                return None;
            }

            // RFC 4456 §8: discard if our cluster_id is already in CLUSTER_LIST.
            let cluster_loop = msg.attributes.iter().any(
                |a| matches!(a, PathAttribute::ClusterList(list) if list.contains(&cluster_id)),
            );
            if cluster_loop {
                tracing::debug!(
                    peer = %peer_ip,
                    cluster_id,
                    "RR loop: cluster_id in CLUSTER_LIST — discarding UPDATE (RFC 4456)"
                );
                return None;
            }

            // RFC 4456 §8: set ORIGINATOR_ID to the peer's BGP ID if absent.
            if !msg
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::OriginatorId(_)))
            {
                let bgp_id = self
                    .rib
                    .peer_bgp_ids
                    .get(&peer_ip)
                    .copied()
                    .unwrap_or(peer_ip);
                msg.attributes.push(PathAttribute::OriginatorId(bgp_id));
            }

            // RFC 4456 §8: prepend our cluster_id to CLUSTER_LIST.
            if let Some(PathAttribute::ClusterList(list)) = msg
                .attributes
                .iter_mut()
                .find(|a| matches!(a, PathAttribute::ClusterList(_)))
            {
                list.insert(0, cluster_id);
            } else {
                msg.attributes
                    .push(PathAttribute::ClusterList(vec![cluster_id]));
            }
        }

        // Collect all IPv4 prefixes that may change best-path: traditional
        // fields plus any IPv4 NLRIs carried in MP_REACH/MP_UNREACH attributes
        // (RFC 4760). These are used after `handle_update` to drive outbound
        // propagation, so they must be collected before `msg` is moved.
        let mut affected: Vec<Nlri<Ipv4Addr>> = msg
            .withdrawn
            .iter()
            .chain(msg.announced.iter())
            .copied()
            .collect();

        let mut affected_v6: Vec<Nlri<Ipv6Addr>> = Vec::new();

        for attr in &msg.attributes {
            match attr {
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV4_UNICAST =>
                {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV4_UNICAST => {
                    affected.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V4(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpUnreachNlri(MpUnreachNlri { afi_safi, prefixes })
                    if *afi_safi == AfiSafi::IPV6_UNICAST =>
                {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                PathAttribute::MpReachNlri(MpReachNlri {
                    afi_safi, prefixes, ..
                }) if *afi_safi == AfiSafi::IPV6_UNICAST => {
                    affected_v6.extend(prefixes.iter().filter_map(|p| {
                        if let Prefix::V6(nlri) = p {
                            Some(*nlri)
                        } else {
                            None
                        }
                    }));
                }
                _ => {}
            }
        }

        let Some(policy) = self.import_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies missing peer — skipping RouteUpdate");
            return None;
        };
        let Some(policy_v6) = self.import_policies_v6.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "import_policies_v6 missing peer — skipping RouteUpdate");
            return None;
        };
        let Some(adj_rib_in) = self.adj_ribs_in.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_in missing peer — skipping RouteUpdate");
            return None;
        };

        // IPv6 AdjRibIn may not exist for all peers (e.g. if capability was not
        // advertised); use a temporary empty table in that case so handle_update
        // can take ownership without a conditional.
        let mut scratch_v6 = AdjRibIn::new(peer_id);
        let adj_rib_in_v6 = self
            .adj_ribs_in_v6
            .get_mut(&peer_ip)
            .unwrap_or(&mut scratch_v6);

        // RFC 4724 §4.2 — during GR re-establishment, any NLRI the peer
        // re-announces is no longer stale.  Remove it from the tracking sets so
        // it is not withdrawn when EOR arrives.
        if let Some(stale) = self.gr.stale_nlri.get_mut(&peer_ip) {
            for nlri in &msg.announced {
                stale.remove(nlri);
            }
        }
        if let Some(stale_v6) = self.gr.stale_nlri_v6.get_mut(&peer_ip) {
            for attr in &msg.attributes {
                if let PathAttribute::MpReachNlri(m) = attr
                    && m.afi_safi == AfiSafi::IPV6_UNICAST
                {
                    for p in &m.prefixes {
                        if let Prefix::V6(nlri) = p {
                            stale_v6.remove(nlri);
                        }
                    }
                }
            }
        }

        // Split mutable borrows across distinct struct fields explicitly so the
        // borrow checker can verify they don't alias.
        let oracle_v4 = Arc::clone(&self.oracle_v4);
        let oracle_v6 = Arc::clone(&self.oracle_v6);
        let local_as = self.rib.local_as;
        let local_v4_addr = self.rib.local_addrs.get(&peer_ip).and_then(|a| match a {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        });
        let local_v6_addr = self.rib.local_ipv6;
        let rib = Arc::make_mut(&mut self.rib);
        let result = handle_update(
            peer_id,
            msg,
            adj_rib_in,
            &mut rib.loc_rib,
            adj_rib_in_v6,
            &mut rib.loc_rib_v6,
            policy,
            policy_v6,
            peer_type,
            &*oracle_v4,
            &*oracle_v6,
            local_as,
            local_v4_addr,
            local_v6_addr,
        );

        // RFC 4486 §4 — Maximum Prefix limit.
        //
        // Per-AFI max-prefix enforcement (RFC 4486 §4).
        //
        // Checked after handle_update so AdjRibIn reflects the routes just
        // accepted. Either limit firing causes an immediate CEASE; on_terminated
        // cleans up RIB state. Checks are independent — IPv4 and IPv6 each have
        // their own configured limit.
        let exceed_v4 = self
            .peer_max_prefixes_v4
            .get(&peer_ip)
            .is_some_and(|&lim| adj_rib_in.len() > lim as usize);
        let exceed_v6 = self
            .peer_max_prefixes_v6
            .get(&peer_ip)
            .is_some_and(|&lim| adj_rib_in_v6.len() > lim as usize);
        if exceed_v4 || exceed_v6 {
            let (afi, size, limit) = if exceed_v4 {
                (
                    "IPv4",
                    adj_rib_in.len(),
                    *self.peer_max_prefixes_v4.get(&peer_ip).unwrap(),
                )
            } else {
                (
                    "IPv6",
                    adj_rib_in_v6.len(),
                    *self.peer_max_prefixes_v6.get(&peer_ip).unwrap(),
                )
            };
            tracing::warn!(
                peer = %peer_ip,
                afi,
                adj_rib_size = size,
                limit,
                "max-prefix limit exceeded ({size} > {limit} {afi}) — \
                 sending CEASE/MaximumNumberOfPrefixesReached (RFC 4486 §4)"
            );
            if let Some(&restart_secs) = self.peer_max_prefixes_restart.get(&peer_ip) {
                let deadline =
                    Instant::now() + std::time::Duration::from_secs(u64::from(restart_secs));
                self.max_prefix_idle.insert(peer_ip, deadline);
                tracing::info!(
                    peer = %peer_ip,
                    restart_secs,
                    "max-prefix idle-hold: reconnect blocked for {restart_secs}s"
                );
            }
            return Some(NotificationMessage {
                error: NotificationError::Cease(CeaseError::MaximumNumberOfPrefixesReached),
                data: vec![],
            });
        }

        let notification = result.notification;

        if let Some(fm) = &self.fib_manager {
            for change in result.fib_changes {
                fm.apply_v4(change);
            }
            for change in result.fib_changes_v6 {
                fm.apply_v6(change);
            }
            for nlri in result.blackhole_announced_v4 {
                fm.apply_blackhole_v4(nlri);
            }
            for nlri in result.blackhole_announced_v6 {
                fm.apply_blackhole_v6(nlri);
            }
            for nlri in result.blackhole_withdrawn_v4 {
                fm.withdraw_blackhole_v4(nlri);
                // If another peer's unicast route survives in LocRib for this
                // NLRI, re-install it. The BLACKHOLE route bypassed LocRib, so
                // its withdrawal does not automatically trigger a FIB re-install
                // of any competing unicast best path.
                //
                // Known limitation: when apply_v4(Announced) is called here, the
                // FibManager coalescing map will overwrite the WithdrawBlackhole
                // entry with Install — meaning the RTN_BLACKHOLE delete is skipped
                // and the kernel receives RTM_NEWROUTE (unicast) while the blackhole
                // route still exists. This works if RTM_NEWROUTE uses replace
                // semantics (NLM_F_REPLACE), but has not been exercised by a
                // multi-peer e2e test where one peer sends BLACKHOLE and another
                // sends a unicast for the same prefix simultaneously.
                if let Some(route) = rib.loc_rib.best(&nlri) {
                    fm.apply_v4(BestPathChange::Announced(nlri, route.clone()));
                }
            }
            for nlri in result.blackhole_withdrawn_v6 {
                fm.withdraw_blackhole_v6(nlri);
                // Same coalescing caveat as the v4 path above.
                if let Some(route) = rib.loc_rib_v6.best(&nlri) {
                    fm.apply_v6(BestPathChange::Announced(nlri, route.clone()));
                }
            }
        }

        self.sync_received(peer_ip);

        // Propagate best-path changes for affected prefixes to all established
        // peers (iBGP split-horizon is enforced by AdjRibOut).
        self.propagate_to_all_peers(&affected);
        if !affected_v6.is_empty() {
            self.propagate_to_all_peers_v6(&affected_v6);
        }

        // Notify watchers so the dashboard reflects the updated Loc-RIB and
        // RCV/ADV counters.  `propagate_to_all_peers` already called
        // `sync_advertised`; the PeerEvent flushes that to the dashboard.
        self.emit_route_events(&affected);
        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });
        notification
    }

    /// Propagates best-path decisions for `nlris` to every currently established
    /// peer and flushes the resulting BGP UPDATE messages.
    ///
    /// Extracted to eliminate the identical loop body duplicated across
    /// `on_route_update`, `set_import_default`, `set_export_default`, and the
    /// origination methods.
    pub(super) fn propagate_to_all_peers(&mut self, nlris: &[Nlri<Ipv4Addr>]) {
        let established_peers: Vec<Ipv4Addr> = self.rib.peer_types.keys().copied().collect();
        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let is_rr = !self.rib.rr_clients.is_empty();
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let local_next_hop = self
                .rib
                .local_addrs
                .get(&peer_ip)
                .and_then(|a| match a {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                .unwrap_or(local_bgp_id);
            let Some(export_policy) = self.export_policies.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping propagation");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping propagation");
                continue;
            };
            let rr_clients = &self.rib.rr_clients;
            let peer_types = &self.rib.peer_types;
            let loc_rib = &self.rib.loc_rib;
            let dest_is_client = rr_clients.contains(&peer_ip);
            let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
            let decisions: Vec<PrefixDecision> = nlris
                .iter()
                .map(|&nlri| {
                    // RR split-horizon (RFC 4456 §8): when acting as an RR,
                    // block propagation between two non-client iBGP peers.
                    // All other source/dest combinations are allowed; the
                    // AdjRibOut `reflects` flag suppresses the regular iBGP
                    // split-horizon so it does not re-block reflected routes.
                    if is_rr
                        && peer_type == PeerType::Internal
                        && let Some(src) = loc_rib.best_peer(&nlri)
                        && let IpAddr::V4(src_ip) = src.ip()
                    {
                        let src_is_client = rr_clients.contains(&src_ip);
                        let src_is_ibgp =
                            peer_types.get(&src_ip).copied() == Some(PeerType::Internal);
                        if src_is_ibgp && !src_is_client && !dest_is_client {
                            return PrefixDecision::NoChange;
                        }
                    }
                    propagate_prefix(
                        nlri,
                        loc_rib,
                        adj_rib_out,
                        export_policy,
                        peer_type,
                        local_as,
                        local_next_hop,
                        next_hop_self,
                    )
                })
                .collect();
            // RFC 4271 §9.2.1.1: apply MRAI for eBGP peers.
            // Withdrawals bypass MRAI (must be sent immediately per the RFC).
            let now = Instant::now();
            let decisions = if peer_type == PeerType::External {
                let last_sent = self.mrai_last_sent.entry(peer_ip).or_default();
                let pending = self.mrai_pending.entry(peer_ip).or_default();
                decisions
                    .into_iter()
                    .map(|d| match d {
                        PrefixDecision::Announce(ref route) => {
                            let nlri = route.nlri;
                            let elapsed = last_sent
                                .get(&nlri)
                                .map_or(MRAI, |t| now.saturating_duration_since(*t));
                            if elapsed >= MRAI {
                                last_sent.insert(nlri, now);
                                pending.remove(&nlri);
                                d
                            } else {
                                pending.insert(nlri);
                                PrefixDecision::NoChange
                            }
                        }
                        // Withdrawals are always sent immediately; also clear any
                        // pending MRAI entry so we don't re-announce after withdrawal.
                        PrefixDecision::Withdraw(nlri) => {
                            pending.remove(&nlri);
                            last_sent.remove(&nlri);
                            d
                        }
                        PrefixDecision::NoChange => d,
                    })
                    .collect()
            } else {
                decisions
            };
            // Accumulate into the coalescing buffer; flush_pending() will drain
            // all peers at once when the event channel goes quiet.
            self.pending_decisions
                .entry(peer_ip)
                .or_default()
                .extend(decisions);
        }
        // Sync advertised counts after all propagation is complete.
        let peers: Vec<Ipv4Addr> = self.adj_ribs_out.keys().copied().collect();
        for peer_ip in peers {
            self.sync_advertised(peer_ip);
        }
        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None,
        });
    }

    /// Re-propagates NLRIs that were suppressed by MRAI and whose window has now elapsed.
    ///
    /// Should be called roughly every MRAI interval (30 s) by the event loop.
    /// For each eBGP peer with pending NLRIs, this re-runs `propagate_to_all_peers`
    /// for the pending set so routes reach the peer after the suppression window closes.
    pub(crate) fn flush_mrai_pending(&mut self) {
        let now = Instant::now();
        // Per-NLRI readiness check: only flush NLRIs whose individual MRAI window
        // has elapsed. A bulk "max of all last_sent" check would incorrectly
        // suppress a pending NLRI if any *other* (non-pending) NLRI was sent
        // recently enough to make the max appear within the window.
        let peers_with_pending: Vec<Ipv4Addr> = self
            .mrai_pending
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(&p, _)| p)
            .collect();

        for peer_ip in peers_with_pending {
            let Some(pending) = self.mrai_pending.get(&peer_ip) else {
                continue;
            };
            let (ready, not_ready): (Vec<Nlri<Ipv4Addr>>, Vec<Nlri<Ipv4Addr>>) =
                pending.iter().copied().partition(|nlri| {
                    self.mrai_last_sent
                        .get(&peer_ip)
                        .and_then(|m| m.get(nlri))
                        .is_none_or(|t| now.saturating_duration_since(*t) >= MRAI)
                });

            if ready.is_empty() {
                continue;
            }

            // Replace pending with the still-suppressed NLRIs before propagating,
            // so propagate_to_all_peers sees an accurate pending set.
            if let Some(p) = self.mrai_pending.get_mut(&peer_ip) {
                *p = not_ready.into_iter().collect();
            }
            self.propagate_to_all_peers(&ready);
        }
    }

    /// Returns `true` if any eBGP peer has NLRIs pending for MRAI flush.
    ///
    /// Used by the event loop to decide whether to schedule a wakeup timer.
    pub(crate) fn has_mrai_pending(&self) -> bool {
        self.mrai_pending.values().any(|s| !s.is_empty())
    }

    /// Emits a `RouteEvent` for each NLRI in `affected` based on the current
    /// Loc-RIB state: `Announced` when a best route exists, `Withdrawn` when
    /// the prefix has been removed.
    pub(super) fn emit_route_events(&self, affected: &[Nlri<Ipv4Addr>]) {
        for &nlri in affected {
            let event = match self.rib.loc_rib.best(&nlri) {
                Some(route) => {
                    let peer_id = self
                        .rib
                        .loc_rib
                        .best_peer(&nlri)
                        .unwrap_or_else(|| PeerId::from(Ipv4Addr::UNSPECIFIED));
                    proto::RouteEvent {
                        r#type: proto::RouteEventType::Announced as i32,
                        route: Some(grpc::route_to_proto(peer_id, nlri, route)),
                        withdrawn_prefix: None,
                    }
                }
                None => proto::RouteEvent {
                    r#type: proto::RouteEventType::Withdrawn as i32,
                    route: None,
                    withdrawn_prefix: Some(nlri.to_string()),
                },
            };
            let _ = self.route_tx.send(event);
        }
    }

    pub(super) fn propagate_to_all_peers_v6(&mut self, nlris: &[Nlri<Ipv6Addr>]) {
        // Only send IPv6 UPDATEs to peers that negotiated the Multi-Protocol
        // capability for IPv6 unicast (RFC 4760).
        let established_peers: Vec<Ipv4Addr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|ip| self.ipv6_capable_peers.contains(ip))
            .collect();
        let is_rr = !self.rib.rr_clients.is_empty();
        let local_as = self.rib.local_as;
        let local_ipv6 = self.rib.local_ipv6;
        for peer_ip in established_peers {
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let Some(export_policy_v6) = self.export_policies_v6.get(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "export_policies_v6 missing peer — skipping v6 propagation");
                continue;
            };
            let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip) else {
                tracing::error!(peer = %peer_ip, "adj_ribs_out_v6 missing peer — skipping v6 propagation");
                continue;
            };
            let rr_clients = &self.rib.rr_clients;
            let peer_types = &self.rib.peer_types;
            let loc_rib_v6 = &self.rib.loc_rib_v6;
            let dest_is_client = rr_clients.contains(&peer_ip);
            let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);
            let decisions: Vec<PrefixDecisionV6> = nlris
                .iter()
                .map(|&nlri| {
                    // RFC 4456 §8 split-horizon: block non-client iBGP →
                    // non-client iBGP for IPv6 routes (same rule as IPv4).
                    if is_rr
                        && peer_type == PeerType::Internal
                        && let Some(src) = loc_rib_v6.best_peer(&nlri)
                        && let IpAddr::V4(src_ip) = src.ip()
                    {
                        let src_is_client = rr_clients.contains(&src_ip);
                        let src_is_ibgp =
                            peer_types.get(&src_ip).copied() == Some(PeerType::Internal);
                        if src_is_ibgp && !src_is_client && !dest_is_client {
                            return PrefixDecisionV6::NoChange;
                        }
                    }
                    propagate_prefix_v6(
                        nlri,
                        loc_rib_v6,
                        adj_rib_out_v6,
                        export_policy_v6,
                        peer_type,
                        local_as,
                        local_ipv6,
                        next_hop_self,
                    )
                })
                .collect();
            self.pending_decisions_v6
                .entry(peer_ip)
                .or_default()
                .extend(decisions);
        }
        // Sync advertised counts after all v6 propagation is complete. Needed
        // here too (not just in `propagate_to_all_peers`): `sync_advertised`
        // reads both `adj_ribs_out` and `adj_ribs_out_v6`, but a caller may
        // invoke this v6 path without a preceding/following v4 call (e.g.
        // `on_route_update` when only `affected_v6` is non-empty) — without
        // this, `prefixes_advertised` would stay stale after a v6-only
        // propagation until some unrelated v4 event happened to resync it.
        let peers: Vec<Ipv4Addr> = self.adj_ribs_out_v6.keys().copied().collect();
        for peer_ip in peers {
            self.sync_advertised(peer_ip);
        }
    }

    /// Drains all per-peer coalescing buffers and sends the accumulated
    /// decisions as batched UPDATE messages.
    ///
    /// Called by the event loop when the event channel drains (natural
    /// quiescence after a burst), and before MRAI timer processing. Batching
    /// decisions across multiple `on_route_update` calls maximises the number
    /// of NLRIs packed per UPDATE message — particularly important during
    /// full-table sessions where many prefixes share the same attribute set.
    ///
    /// RFC 4271 §9.2: "the speaker SHOULD try to combine as many feasible
    /// routes as possible in the UPDATE messages."
    pub(crate) fn flush_pending(&mut self) {
        let peers: Vec<Ipv4Addr> = self
            .pending_decisions
            .keys()
            .chain(self.pending_decisions_v6.keys())
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        for peer_ip in peers {
            let decisions = self.pending_decisions.remove(&peer_ip).unwrap_or_default();
            let decisions_v6 = self
                .pending_decisions_v6
                .remove(&peer_ip)
                .unwrap_or_default();

            if decisions.is_empty() && decisions_v6.is_empty() {
                continue;
            }

            let Some(update_tx) = self.update_senders.get(&peer_ip) else {
                continue;
            };
            let peer_type = self
                .rib
                .peer_types
                .get(&peer_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&peer_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let peer_four_byte = self.four_byte_peers.contains(&peer_ip);

            if !decisions.is_empty()
                && !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte)
            {
                self.stalled_peers.push(peer_ip);
                continue;
            }
            if !decisions_v6.is_empty()
                && !flush_updates_v6(decisions_v6, max_len, update_tx, peer_type, peer_four_byte)
            {
                self.stalled_peers.push(peer_ip);
            }
        }
    }
}

pub(crate) fn reapply_import_policy(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    oracle: &dyn NextHopOracle,
) -> Vec<BestPathChange<Ipv4Addr>> {
    let mut fib_changes: Vec<BestPathChange<Ipv4Addr>> = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (nlri, raw_route) in adj_rib_in.routes() {
        let mut route = raw_route.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes.push(loc_rib.insert(peer, route, oracle));
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle));
                rejected += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        accepted,
        rejected,
        rib_size = loc_rib.len(),
        "soft reconfig complete"
    );
    fib_changes
}

/// IPv6 counterpart of [`reapply_import_policy`].
///
/// Re-evaluates all IPv6 routes stored in `adj_rib_in` against `policy` and
/// reconciles `loc_rib` with the result.  Called by [`DaemonState::set_import_default`]
/// so that a policy reload applies to both address families without a session reset.
pub(crate) fn reapply_import_policy_v6(
    peer: PeerId,
    adj_rib_in: &AdjRibIn<Ipv6Addr>,
    loc_rib: &mut LocRib<Ipv6Addr>,
    policy: &Policy<Route<Ipv6Addr>>,
    oracle: &dyn NextHopOracle,
) -> Vec<BestPathChange<Ipv6Addr>> {
    let mut fib_changes: Vec<BestPathChange<Ipv6Addr>> = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (nlri, raw_route) in adj_rib_in.routes() {
        let mut route = raw_route.clone();
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes.push(loc_rib.insert(peer, route, oracle));
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle));
                rejected += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        accepted,
        rejected,
        rib_size = loc_rib.len(),
        "soft reconfig v6 complete"
    );
    fib_changes
}

// RFC 4271 §5.1.3 / §9.1.2 — NEXT_HOP validation.
// Returns false for addresses that are forbidden as next-hops: unspecified,
// loopback, multicast, and broadcast. The "own address" check (receiving
// router's address) is left to the FIB oracle reachability gate because
// handle_update has no direct access to the local interface address.
// `own_addr`: the local interface address toward this peer; if the NEXT_HOP
// equals our own address the peer would be sending traffic to us, black-holing
// it. RFC 4271 §5.1.3 requires the NEXT_HOP to be reachable and not the
// receiving router's own address.
fn is_valid_next_hop_v4(addr: Ipv4Addr, own_addr: Option<Ipv4Addr>) -> bool {
    !addr.is_unspecified()
        && !addr.is_loopback()
        && !addr.is_multicast()
        && addr != Ipv4Addr::BROADCAST
        && own_addr.is_none_or(|own| addr != own)
}

// RFC 4291 §2.5 / RFC 4271 §5.1.3 for IPv6 next-hops carried in MP_REACH_NLRI.
// Unspecified (::) and multicast (ff00::/8) are not valid forwarding targets.
// Link-local (fe80::/10) is valid when paired with an interface (V6WithLinkLocal)
// and is handled by the FIB oracle; a bare link-local as a global next-hop is
// accepted here because GoBGP and BIRD both use it legitimately in single-hop sessions.
fn is_valid_next_hop_v6(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_multicast()
}

// UPDATE processing dispatches across all path attribute types in one pass.
// Splitting this function further would produce artificial helpers with no
// independent utility.
/// Return value of [`handle_update`], bundling FIB changes with RFC 7999
/// blackhole install/withdraw events that bypass the normal LocRib path.
pub(super) struct UpdateResult {
    pub(super) fib_changes: Vec<BestPathChange<Ipv4Addr>>,
    pub(super) fib_changes_v6: Vec<BestPathChange<Ipv6Addr>>,
    pub(super) notification: Option<NotificationMessage>,
    /// Prefixes with BLACKHOLE community that were accepted into AdjRibIn —
    /// the FIB manager should program a kernel null route for each.
    pub(super) blackhole_announced_v4: Vec<Nlri<Ipv4Addr>>,
    pub(super) blackhole_announced_v6: Vec<Nlri<Ipv6Addr>>,
    /// Previously-installed blackhole prefixes that were withdrawn by the peer.
    pub(super) blackhole_withdrawn_v4: Vec<Nlri<Ipv4Addr>>,
    pub(super) blackhole_withdrawn_v6: Vec<Nlri<Ipv6Addr>>,
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(super) fn handle_update(
    peer: PeerId,
    msg: UpdateMessage,
    adj_rib_in: &mut AdjRibIn<Ipv4Addr>,
    loc_rib: &mut LocRib<Ipv4Addr>,
    adj_rib_in_v6: &mut AdjRibIn<Ipv6Addr>,
    loc_rib_v6: &mut LocRib<Ipv6Addr>,
    policy: &Policy<Route<Ipv4Addr>>,
    policy_v6: &Policy<Route<Ipv6Addr>>,
    peer_type: PeerType,
    oracle_v4: &dyn NextHopOracle,
    oracle_v6: &dyn NextHopOracle,
    local_as: u32,
    local_v4_addr: Option<Ipv4Addr>,
    local_v6_addr: Option<Ipv6Addr>,
) -> UpdateResult {
    let mut fib_changes: Vec<BestPathChange<Ipv4Addr>> = Vec::new();
    let mut fib_changes_v6: Vec<BestPathChange<Ipv6Addr>> = Vec::new();
    let mut blackhole_announced_v4: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut blackhole_announced_v6: Vec<Nlri<Ipv6Addr>> = Vec::new();
    let mut blackhole_withdrawn_v4: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut blackhole_withdrawn_v6: Vec<Nlri<Ipv6Addr>> = Vec::new();
    let withdrawn_count = msg.withdrawn.len();

    // ── Traditional IPv4 withdrawals (RFC 4271 §4.3) ──────────────────────
    for nlri in &msg.withdrawn {
        // If this NLRI had a blackhole kernel route (bypassed LocRib), record
        // it for withdrawal before clearing from AdjRibIn.
        if adj_rib_in.get(nlri).is_some_and(|r| {
            r.rare_or_default()
                .communities
                .iter()
                .any(|c| c.is_blackhole())
        }) {
            blackhole_withdrawn_v4.push(*nlri);
        }
        adj_rib_in.withdraw(nlri);
        fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle_v4));
    }

    // ── Single pass over path attributes ─────────────────────────────────
    // Extracts scalar attributes shared by all announced NLRIs, and collects
    // IPv4 NLRIs from MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760). Non-IPv4
    // AFI/SAFIs are logged and skipped; the daemon is IPv4-only for now.
    let mut has_origin = false;
    let mut has_as_path = false;
    let mut origin = Origin::Incomplete;
    let mut as_path = AsPath::new();
    let mut next_hop: Option<NextHop> = None;
    let mut local_pref: Option<LocalPref> = None;
    let mut med: Option<Med> = None;
    let mut communities = Vec::new();
    let mut large_communities = Vec::new();
    let mut extended_communities = Vec::new();
    let mut atomic_aggregate = false;
    let mut aggregator = None;
    let mut originator_id: Option<Ipv4Addr> = None;
    let mut cluster_list: Vec<u32> = Vec::new();
    let mut otc: Option<Asn> = None;
    // (nlri, next_hop) pairs from MP_REACH_NLRI; next_hop is mandatory there.
    let mut mp_v4_announced: Vec<(Nlri<Ipv4Addr>, NextHop)> = Vec::new();
    let mut mp_v4_withdrawn: Vec<Nlri<Ipv4Addr>> = Vec::new();
    let mut mp_v6_announced: Vec<(Nlri<Ipv6Addr>, NextHop)> = Vec::new();
    let mut mp_v6_withdrawn: Vec<Nlri<Ipv6Addr>> = Vec::new();

    for attr in &msg.attributes {
        match attr {
            PathAttribute::Origin(o) => {
                origin = *o;
                has_origin = true;
            }
            PathAttribute::AsPath(p) => {
                as_path = p.clone();
                has_as_path = true;
            }
            PathAttribute::NextHop(ip) => next_hop = Some(NextHop::V4(*ip)),
            PathAttribute::LocalPref(lp) => local_pref = Some(LocalPref::new(*lp)),
            PathAttribute::Med(m) => med = Some(Med::new(*m)),
            PathAttribute::Communities(cs) => communities.clone_from(cs),
            PathAttribute::LargeCommunities(lcs) => large_communities.clone_from(lcs),
            PathAttribute::ExtendedCommunities(ecs) => extended_communities.clone_from(ecs),
            PathAttribute::AtomicAggregate => atomic_aggregate = true,
            PathAttribute::Aggregator(a) => aggregator = Some(*a),
            PathAttribute::OriginatorId(id) => originator_id = Some(*id),
            PathAttribute::ClusterList(list) => cluster_list.clone_from(list),
            PathAttribute::OnlyToCustomer(asn) => otc = Some(*asn),
            PathAttribute::MpReachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_announced.push((*nlri, mp.next_hop));
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_REACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            PathAttribute::MpUnreachNlri(mp) => {
                if mp.afi_safi == AfiSafi::IPV4_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V4(nlri) = prefix {
                            mp_v4_withdrawn.push(*nlri);
                        }
                    }
                } else if mp.afi_safi == AfiSafi::IPV6_UNICAST {
                    for prefix in &mp.prefixes {
                        if let Prefix::V6(nlri) = prefix {
                            mp_v6_withdrawn.push(*nlri);
                        }
                    }
                } else {
                    tracing::debug!(
                        peer = %peer,
                        afi_safi = %mp.afi_safi,
                        "MP_UNREACH_NLRI for unsupported AFI/SAFI — skipping"
                    );
                }
            }
            _ => {}
        }
    }

    // ── RFC 4271 §6.3: mandatory well-known attribute check ───────────────
    // When the UPDATE carries announcements, ORIGIN and AS_PATH MUST be present.
    // For conventional IPv4 NLRI, NEXT_HOP is also mandatory.
    // Violation → send NOTIFICATION (UpdateMessage/MissingWellKnownAttribute) and
    // tear down the session. Withdraw-only UPDATEs are exempt.
    let has_v4_announces = !msg.announced.is_empty() || !mp_v4_announced.is_empty();
    let has_any_announces = has_v4_announces || !mp_v6_announced.is_empty();
    if has_any_announces {
        let missing_attr = if !has_origin {
            Some(1u8) // ORIGIN type code
        } else if !has_as_path {
            Some(2u8) // AS_PATH type code
        } else if has_v4_announces && !msg.announced.is_empty() && next_hop.is_none() {
            // NEXT_HOP required for traditional (non-MP) IPv4 announcements.
            Some(3u8) // NEXT_HOP type code
        } else {
            None
        };
        if let Some(attr_type) = missing_attr {
            tracing::warn!(
                peer = %peer,
                attr_type,
                "mandatory well-known attribute missing (RFC 4271 §6.3) — sending NOTIFICATION"
            );
            // RFC 4271 §6.3: data field MUST contain the type code of the missing attribute.
            return UpdateResult {
                fib_changes,
                fib_changes_v6,
                notification: Some(NotificationMessage {
                    error: NotificationError::UpdateMessage(
                        UpdateMsgError::MissingWellKnownAttribute,
                    ),
                    data: vec![attr_type],
                }),
                blackhole_announced_v4,
                blackhole_announced_v6,
                blackhole_withdrawn_v4,
                blackhole_withdrawn_v6,
            };
        }
    }

    // ── RFC 7607: AS 0 in AS_PATH ────────────────────────────────────────
    // AS 0 is reserved and MUST NOT appear in AS_PATH. A route carrying it
    // is malformed; silently drop announces (withdrawals are still processed).
    let has_as_zero = as_path.contains(pathvector_types::Asn::new(0));
    if has_as_zero
        && (!msg.announced.is_empty() || !mp_v4_announced.is_empty() || !mp_v6_announced.is_empty())
    {
        tracing::warn!(
            peer = %peer,
            %as_path,
            "dropping UPDATE: AS_PATH contains reserved AS 0 (RFC 7607)"
        );
        mp_v4_announced.clear();
        mp_v6_announced.clear();
    }

    // ── RFC 4271 §9.1.2: AS_PATH loop detection ──────────────────────────
    // If our own AS appears in the received AS_PATH the route has looped back
    // to us. Silently ignore all announced NLRIs in this UPDATE (withdrawals
    // are still processed — they are safe and necessary).
    let has_loop = as_path.contains(pathvector_types::Asn::new(local_as));
    if has_loop
        && (!msg.announced.is_empty() || !mp_v4_announced.is_empty() || !mp_v6_announced.is_empty())
    {
        tracing::debug!(
            peer = %peer,
            local_as,
            %as_path,
            "dropping UPDATE: AS_PATH contains local AS (RFC 4271 §9.1.2)"
        );
        // Still process withdrawals below; clear the announce lists.
        mp_v4_announced.clear();
        mp_v6_announced.clear();
        // The traditional NLRI list is consumed by the iterator below; return
        // early after processing withdrawals by short-circuiting via a flag.
    }

    // ── MP_UNREACH_NLRI withdrawals (RFC 4760) ────────────────────────────
    let mp_withdrawn_count = mp_v4_withdrawn.len();
    for nlri in &mp_v4_withdrawn {
        if adj_rib_in.get(nlri).is_some_and(|r| {
            r.rare_or_default()
                .communities
                .iter()
                .any(|c| c.is_blackhole())
        }) {
            blackhole_withdrawn_v4.push(*nlri);
        }
        adj_rib_in.withdraw(nlri);
        fib_changes.push(loc_rib.withdraw(&peer, nlri, oracle_v4));
    }

    // ── Announcements: traditional NLRIs + MP_REACH_NLRI V4 prefixes ─────
    // Both paths share the same scalar attributes extracted above. The only
    // difference is the next-hop source: traditional NLRIs use the NEXT_HOP
    // path attribute (optional); MP_REACH_NLRI carries next-hop inline
    // (mandatory) and takes precedence when present.
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    // Wrap once; every route in this UPDATE shares the same Arc<AsPath>.
    let shared_as_path = Arc::new(as_path);

    let skip_announces = has_loop || has_as_zero;
    let all_announced = msg
        .announced
        .into_iter()
        .map(|nlri| (nlri, next_hop))
        .chain(
            mp_v4_announced
                .into_iter()
                .map(|(nlri, nh)| (nlri, Some(nh))),
        );

    for (nlri, nh) in all_announced {
        if skip_announces {
            rejected += 1;
            continue;
        }
        // RFC 4271 §5.1.3: validate NEXT_HOP before accepting the route.
        if let Some(NextHop::V4(addr)) = nh
            && !is_valid_next_hop_v4(addr, local_v4_addr)
        {
            tracing::warn!(peer = %peer, prefix = %nlri, next_hop = %addr,
                "dropping route: invalid NEXT_HOP (RFC 4271 §5.1.3)");
            rejected += 1;
            continue;
        }

        let mut builder =
            RouteBuilder::with_shared_as_path(nlri, origin, Arc::clone(&shared_as_path))
                .peer_type(peer_type);
        if let Some(nh) = nh {
            builder = builder.next_hop(nh);
        }
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }
        if let Some(asn) = otc {
            builder = builder.otc(asn);
        }

        let mut raw = builder.build();
        if originator_id.is_some() || !cluster_list.is_empty() {
            let r = raw.rare_mut();
            r.originator_id = originator_id;
            r.cluster_list.clone_from(&cluster_list);
        }

        // RFC 7999: routes tagged with the BLACKHOLE community bypass LocRib
        // and outbound advertisement. Store in AdjRibIn for soft-reconfig, and
        // program a kernel null route so the local box drops the traffic too.
        // If the prefix was previously a unicast route from this peer, evict it
        // from LocRib — a unicast FIB entry and a kernel null route must not
        // coexist for the same prefix.
        if raw
            .rare_or_default()
            .communities
            .iter()
            .any(|c| c.is_blackhole())
        {
            adj_rib_in.insert(raw.clone());
            fib_changes.push(loc_rib.withdraw(&peer, &nlri, oracle_v4));
            tracing::debug!(peer = %peer, prefix = %nlri, "programming kernel null route for BLACKHOLE prefix (RFC 7999)");
            blackhole_announced_v4.push(nlri);
            rejected += 1;
            continue;
        }

        // Store the pre-policy route for soft reconfiguration.
        adj_rib_in.insert(raw.clone());

        // Apply import policy to a working copy; only insert if accepted.
        let mut route = raw;
        match policy.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes.push(loc_rib.insert(peer, route, oracle_v4));
                accepted += 1;
            }
            Decision::Reject | Decision::Next => {
                rejected += 1;
            }
        }
    }

    // ── MP_UNREACH_NLRI IPv6 withdrawals (RFC 4760) ──────────────────────────
    let mp_v6_withdrawn_count = mp_v6_withdrawn.len();
    for nlri in &mp_v6_withdrawn {
        if adj_rib_in_v6.get(nlri).is_some_and(|r| {
            r.rare_or_default()
                .communities
                .iter()
                .any(|c| c.is_blackhole())
        }) {
            blackhole_withdrawn_v6.push(*nlri);
        }
        adj_rib_in_v6.withdraw(nlri);
        fib_changes_v6.push(loc_rib_v6.withdraw(&peer, nlri, oracle_v6));
    }

    // ── IPv6 announcements from MP_REACH_NLRI ─────────────────────────────
    // Same BLACKHOLE + import-policy gate as IPv4. RFC 8212: eBGP peers with no
    // explicit policy default to Reject via `policy_v6` default action.
    let mut accepted_v6 = 0usize;
    let mut rejected_v6 = 0usize;
    for (nlri, nh) in mp_v6_announced {
        // RFC 4271 §5.1.3 / RFC 4291 §2.5 / RFC 2545 §3: validate the IPv6 next-hop.
        // Own-address check: reject if global next-hop matches our configured IPv6 address.
        // Link-local addresses are not checked (interface-scoped; commonly used in eBGP).
        let bad_v6_nh = match nh {
            NextHop::V6(addr) => {
                !is_valid_next_hop_v6(addr) || local_v6_addr.is_some_and(|local| local == addr)
            }
            NextHop::V6WithLinkLocal { global, link_local } => {
                !is_valid_next_hop_v6(global)
                    || local_v6_addr.is_some_and(|local| local == global)
                    || link_local.is_multicast()
            }
            NextHop::V4(_) => false,
        };
        if bad_v6_nh {
            tracing::warn!(
                peer = %peer,
                prefix = %nlri,
                "dropping IPv6 route: invalid NEXT_HOP (RFC 4271 §5.1.3)"
            );
            rejected_v6 += 1;
            continue;
        }
        let mut builder =
            RouteBuilder::with_shared_as_path(nlri, origin, Arc::clone(&shared_as_path))
                .peer_type(peer_type);
        builder = builder.next_hop(nh);
        if let Some(lp) = local_pref {
            builder = builder.local_pref(lp);
        }
        if let Some(m) = med {
            builder = builder.med(m);
        }
        for &c in &communities {
            builder = builder.community(c);
        }
        for &lc in &large_communities {
            builder = builder.large_community(lc);
        }
        for &ec in &extended_communities {
            builder = builder.extended_community(ec);
        }
        if atomic_aggregate {
            builder = builder.atomic_aggregate();
        }
        if let Some(agg) = aggregator {
            builder = builder.aggregator(agg);
        }
        if let Some(asn) = otc {
            builder = builder.otc(asn);
        }

        let raw = builder.build();

        if raw
            .rare_or_default()
            .communities
            .iter()
            .any(|c| c.is_blackhole())
        {
            adj_rib_in_v6.insert(raw.clone());
            fib_changes_v6.push(loc_rib_v6.withdraw(&peer, &nlri, oracle_v6));
            tracing::debug!(peer = %peer, prefix = %nlri, "programming kernel null route for BLACKHOLE IPv6 prefix (RFC 7999)");
            blackhole_announced_v6.push(nlri);
            rejected_v6 += 1;
            continue;
        }

        adj_rib_in_v6.insert(raw.clone());

        let mut route = raw;
        match policy_v6.evaluate(&mut route) {
            Decision::Accept => {
                fib_changes_v6.push(loc_rib_v6.insert(peer, route, oracle_v6));
                accepted_v6 += 1;
            }
            Decision::Reject | Decision::Next => {
                rejected_v6 += 1;
            }
        }
    }

    tracing::info!(
        peer = %peer,
        withdrawn = withdrawn_count,
        mp_withdrawn = mp_withdrawn_count,
        mp_v6_withdrawn = mp_v6_withdrawn_count,
        accepted,
        rejected,
        accepted_v6,
        rejected_v6,
        rib_size = loc_rib.len(),
        rib_v6_size = loc_rib_v6.len(),
        "processed UPDATE"
    );
    UpdateResult {
        fib_changes,
        fib_changes_v6,
        notification: None,
        blackhole_announced_v4,
        blackhole_announced_v6,
        blackhole_withdrawn_v4,
        blackhole_withdrawn_v6,
    }
}
