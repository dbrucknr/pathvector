// daemon/peer.rs — Peer lifecycle: add, remove, establish, terminate; session listener and command processor.
#[allow(clippy::wildcard_imports)]
use super::*;

impl DaemonState {
    pub(crate) fn add_peer(
        &mut self,
        peer: &config::PeerConfig,
        update_sender: mpsc::Sender<UpdateMessage>,
    ) -> bool {
        if self.adj_ribs_in.contains_key(&peer.address) {
            return false;
        }

        let local_as = self.rib.local_as;
        let is_ebgp = peer.remote_as != local_as;
        let pt = config_peer_type(local_as, peer.remote_as);
        let peer_id = PeerId::from(peer.address);

        let is_rr = !self.rib.rr_clients.is_empty();
        let (adj_out, adj_out_v6) = make_adj_ribs_out_pair(peer_id, pt, is_rr);

        self.adj_ribs_in
            .insert(peer.address, AdjRibIn::new(peer_id));
        self.adj_ribs_in_v6
            .insert(peer.address, AdjRibIn::new(peer_id));
        self.adj_ribs_out.insert(peer.address, adj_out);
        self.adj_ribs_out_v6.insert(peer.address, adj_out_v6);
        self.peer_config_types.insert(peer.address, pt);
        self.import_policies.insert(
            peer.address,
            Policy::new(resolve_import_default(peer.import_default, is_ebgp)),
        );
        let default_v6 = peer.import_default_v6.or(peer.import_default);
        self.import_policies_v6.insert(
            peer.address,
            Policy::new(resolve_import_default(default_v6, is_ebgp)),
        );
        self.export_policies.insert(
            peer.address,
            Policy::new(resolve_export_default(peer.export_default, is_ebgp)),
        );
        self.update_senders.insert(peer.address, update_sender);
        if let Some(msg) = peer.shutdown_message.clone() {
            self.shutdown_messages.insert(peer.address, msg);
        }
        let rib = Arc::make_mut(&mut self.rib);
        rib.peer_remote_as.insert(peer.address, peer.remote_as);
        if peer.next_hop_self {
            rib.next_hop_self_peers.insert(peer.address);
        }
        true
    }

    /// Removes all per-peer state for a dynamically removed peer.
    ///
    /// Returns `true` if the peer existed and was removed, `false` if it was
    /// not found.  Callers must also send `SessionCommand::Stop` to the peer's
    /// session handle and update the BGP listener map.
    pub(crate) fn remove_peer(&mut self, peer_ip: Ipv4Addr) -> bool {
        if !self.adj_ribs_in.contains_key(&peer_ip) {
            return false;
        }
        self.adj_ribs_in.remove(&peer_ip);
        self.adj_ribs_in_v6.remove(&peer_ip);
        self.adj_ribs_out.remove(&peer_ip);
        self.adj_ribs_out_v6.remove(&peer_ip);
        self.peer_config_types.remove(&peer_ip);
        self.import_policies.remove(&peer_ip);
        self.import_policies_v6.remove(&peer_ip);
        self.export_policies.remove(&peer_ip);
        self.update_senders.remove(&peer_ip);
        self.negotiated_max_len.remove(&peer_ip);
        self.ipv6_capable_peers.remove(&peer_ip);
        self.four_byte_peers.remove(&peer_ip);
        self.route_refresh_peers.remove(&peer_ip);
        self.rib_mut().gr_capable_peers.remove(&peer_ip);
        self.gr.remove_peer(peer_ip);
        self.mrai_last_sent.remove(&peer_ip);
        self.mrai_pending.remove(&peer_ip);
        self.pending_decisions.remove(&peer_ip);
        self.pending_decisions_v6.remove(&peer_ip);
        self.shutdown_messages.remove(&peer_ip);
        let rib = Arc::make_mut(&mut self.rib);
        rib.peer_remote_as.remove(&peer_ip);
        rib.peer_types.remove(&peer_ip);
        rib.established_at.remove(&peer_ip);
        rib.hold_times.remove(&peer_ip);
        rib.prefixes_received.remove(&peer_ip);
        rib.prefixes_advertised.remove(&peer_ip);
        rib.local_addrs.remove(&peer_ip);
        rib.peer_bgp_ids.remove(&peer_ip);
        rib.next_hop_self_peers.remove(&peer_ip);
        true
    }

    /// Replaces both next-hop oracles once `KernelFib` is initialised.
    // Called only in Linux production code; tests call it on all platforms.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_oracles(
        &mut self,
        v4: impl NextHopOracle + Send + Sync + 'static,
        v6: impl NextHopOracle + Send + Sync + 'static,
    ) {
        self.oracle_v4 = Arc::new(v4);
        self.oracle_v6 = Arc::new(v6);
    }

    // ── LocRib mutation wrappers ──────────────────────────────────────────────
    //
    // These clone the oracle Arc before calling rib_mut() so the borrow checker
    // sees two independent borrows of `self` (oracle_v4 vs rib) rather than one
    // mutable borrow of the entire struct.

    pub(crate) fn sync_received(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_in.get(&peer_ip).map_or(0, AdjRibIn::len);
        let v6 = self.adj_ribs_in_v6.get(&peer_ip).map_or(0, AdjRibIn::len);
        self.rib_mut().prefixes_received.insert(peer_ip, v4 + v6);
    }

    /// Syncs the derived `prefixes_advertised` count for `peer_ip` from the
    /// current `adj_ribs_out` length.
    pub(super) fn sync_advertised(&mut self, peer_ip: Ipv4Addr) {
        let v4 = self.adj_ribs_out.get(&peer_ip).map_or(0, AdjRibOut::len);
        let v6 = self.adj_ribs_out_v6.get(&peer_ip).map_or(0, AdjRibOut::len);
        self.rib_mut().prefixes_advertised.insert(peer_ip, v4 + v6);
    }

    /// Drains and returns the list of peers whose outbound UPDATE channel
    /// overflowed during the most recent event.
    ///
    /// The event loop calls this after each event and sends
    /// [`SessionCommand::Stop`] to each returned peer so the session can
    /// re-establish and perform a fresh full-table dump.
    pub(super) fn take_stalled_peers(&mut self) -> Vec<Ipv4Addr> {
        std::mem::take(&mut self.stalled_peers)
    }

    /// Called when a BGP session reaches Established.
    ///
    /// Records the negotiated peer type, resets the peer's `AdjRibOut` to a
    /// clean slate, and performs a full-table dump of the current best routes
    /// subject to export policy.
    #[allow(clippy::similar_names)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_established(
        &mut self,
        peer_ip: Ipv4Addr,
        peer_bgp_id: Ipv4Addr,
        peer_type: PeerType,
        peer_as: u32,
        hold_time: u16,
        peer_capabilities: &[Capability],
        local_addr: Option<Ipv4Addr>,
    ) {
        let peer_id = PeerId::from(peer_ip);

        // RFC 4724 §4.2 — GR re-establishment: if we were holding stale routes
        // from this peer, cancel the deadline.  The peer will re-advertise its
        // full table; EOR receipt triggers `prune_stale_nlri` below.
        let was_in_gr = self.gr.deadlines.remove(&peer_ip).is_some();
        // Determine which families the peer supports GR for (from prior session).
        let gr_v4 = was_in_gr
            && self
                .gr
                .peer_families
                .get(&peer_ip)
                .is_some_and(|fs| fs.iter().any(|f| f.afi_safi == AfiSafi::IPV4_UNICAST));
        let gr_v6 = was_in_gr
            && self
                .gr
                .peer_families
                .get(&peer_ip)
                .is_some_and(|fs| fs.iter().any(|f| f.afi_safi == AfiSafi::IPV6_UNICAST));
        if was_in_gr {
            // Snapshot which NLRIs were held stale.  Any that aren't refreshed
            // by the peer before its EOR will be withdrawn in on_route_update.
            if gr_v4 {
                let stale_now: HashSet<Nlri<Ipv4Addr>> = self
                    .adj_ribs_in
                    .get(&peer_ip)
                    .map(|ari| ari.routes().map(|(nlri, _)| *nlri).collect())
                    .unwrap_or_default();
                if !stale_now.is_empty() {
                    self.gr.stale_nlri.insert(peer_ip, stale_now);
                }
            }
            if gr_v6 {
                let stale_now_v6: HashSet<Nlri<Ipv6Addr>> = self
                    .adj_ribs_in_v6
                    .get(&peer_ip)
                    .map(|ari| ari.routes().map(|(nlri, _)| *nlri).collect())
                    .unwrap_or_default();
                if !stale_now_v6.is_empty() {
                    self.gr.stale_nlri_v6.insert(peer_ip, stale_now_v6);
                }
            }
            tracing::info!(
                peer = %peer_ip,
                stale_v4 = self.gr.stale_nlri.get(&peer_ip).map_or(0, HashSet::len),
                stale_v6 = self.gr.stale_nlri_v6.get(&peer_ip).map_or(0, HashSet::len),
                "peer re-established within GR window — stale routes kept until EOR"
            );
        }

        // Update snapshot fields.
        {
            let rib = self.rib_mut();
            // Clear any stale EOR state from a previous session (RFC 4724 §2).
            rib.eor_received.remove(&peer_ip);
            rib.eor_received_v6.remove(&peer_ip);
            rib.peer_types.insert(peer_ip, peer_type);
            rib.peer_bgp_ids.insert(peer_ip, peer_bgp_id);
            rib.established_at
                .insert(peer_ip, std::time::Instant::now());
            rib.hold_times.insert(peer_ip, hold_time);
            if let Some(addr) = local_addr {
                rib.local_addrs.insert(peer_ip, addr);
            }
        }

        // Record negotiated message size limit for NLRI batching.
        let max_len = if peer_capabilities.contains(&Capability::ExtendedMessage)
            && self
                .config_capabilities
                .contains(&Capability::ExtendedMessage)
        {
            MAX_LEN_EXTENDED
        } else {
            MAX_LEN
        };
        self.negotiated_max_len.insert(peer_ip, max_len);

        let is_rr = !self.rib.rr_clients.is_empty();
        let (new_aro, new_aro_v6) = make_adj_ribs_out_pair(peer_id, peer_type, is_rr);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = new_aro;
        }
        // Reset v6 AdjRibIn only when NOT holding stale v6 routes for this peer.
        // In GR re-establishment with v6, the stale routes stay until EOR prune.
        if !gr_v6 {
            self.adj_ribs_in_v6.insert(peer_ip, AdjRibIn::new(peer_id));
        }
        self.adj_ribs_out_v6.insert(peer_ip, new_aro_v6);

        let all_nlris: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();
        let all_nlris_v6: Vec<Nlri<Ipv6Addr>> =
            self.rib.loc_rib_v6.best_routes().map(|(n, _)| n).collect();
        let rib_prefixes = all_nlris.len() + all_nlris_v6.len();

        let Some(export_policy) = self.export_policies.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "export_policies missing peer — skipping Established event");
            return;
        };
        let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "adj_ribs_out missing peer — skipping Established event");
            return;
        };
        let Some(update_tx) = self.update_senders.get(&peer_ip) else {
            tracing::error!(peer = %peer_ip, "update_senders missing peer — skipping Established event");
            return;
        };

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let local_next_hop = local_addr.unwrap_or(local_bgp_id);
        let local_ipv6 = self.rib.local_ipv6;
        let next_hop_self = self.rib.next_hop_self_peers.contains(&peer_ip);

        // RFC 4456 §8 split-horizon: when acting as an RR, a non-client iBGP
        // peer must not receive routes learned from other non-client iBGP peers
        // in the initial full-table dump. The same check applies in
        // propagate_to_all_peers for incremental updates.
        let is_rr = !self.rib.rr_clients.is_empty();
        let dest_is_client = self.rib.rr_clients.contains(&peer_ip);
        let rr_clients = &self.rib.rr_clients;
        let peer_types = &self.rib.peer_types;
        let loc_rib = &self.rib.loc_rib;

        let decisions: Vec<PrefixDecision> = all_nlris
            .into_iter()
            .map(|nlri| {
                if is_rr
                    && peer_type == PeerType::Internal
                    && let Some(src) = loc_rib.best_peer(&nlri)
                    && let IpAddr::V4(src_ip) = src.ip()
                {
                    let src_is_client = rr_clients.contains(&src_ip);
                    let src_is_ibgp = peer_types.get(&src_ip).copied() == Some(PeerType::Internal);
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

        // RFC 6793: track whether this peer supports 4-byte ASNs.
        let peer_four_byte = peer_capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourByteAsn(_)));
        if peer_four_byte {
            self.four_byte_peers.insert(peer_ip);
        } else {
            self.four_byte_peers.remove(&peer_ip);
        }

        // RFC 2918: track whether this peer negotiated Route Refresh.
        // Both sides must advertise the capability for ROUTE-REFRESH to be valid.
        let peer_route_refresh = peer_capabilities.contains(&Capability::RouteRefresh)
            && self.config_capabilities.contains(&Capability::RouteRefresh);
        if peer_route_refresh {
            self.route_refresh_peers.insert(peer_ip);
        } else {
            self.route_refresh_peers.remove(&peer_ip);
        }

        // RFC 4724: record whether the peer advertised GracefulRestart with a
        // non-zero restart_time. A zero restart_time means the peer does not
        // participate in the GR restart window (capability present for EOR only).
        let (peer_gr_time, peer_gr_families): (Option<u16>, Vec<GracefulRestartFamily>) =
            peer_capabilities
                .iter()
                .find_map(|c| {
                    if let Capability::GracefulRestart {
                        restart_time,
                        families,
                        ..
                    } = c
                    {
                        if *restart_time > 0 {
                            Some((*restart_time, families.clone()))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .map_or((None, vec![]), |(t, f)| (Some(t), f));
        let mut stalled = !flush_updates(decisions, max_len, update_tx, peer_type, peer_four_byte);
        if stalled {
            self.stalled_peers.push(peer_ip);
        }

        // Full-table dump for IPv6 — only for peers that negotiated IPv6 unicast
        // (RFC 4760): sending MP_REACH_NLRI to a peer that did not advertise the
        // Multi-Protocol capability for IPv6 unicast violates the capability
        // negotiation contract and the peer would silently discard the routes.
        let peer_supports_ipv6 =
            peer_capabilities.contains(&Capability::MultiProtocol(AfiSafi::IPV6_UNICAST));
        if peer_supports_ipv6 {
            self.ipv6_capable_peers.insert(peer_ip);
        } else {
            self.ipv6_capable_peers.remove(&peer_ip);
        }
        if !stalled
            && peer_supports_ipv6
            && !all_nlris_v6.is_empty()
            && let Some(adj_rib_out_v6) = self.adj_ribs_out_v6.get_mut(&peer_ip)
        {
            let loc_rib_v6 = &self.rib.loc_rib_v6;
            let decisions_v6: Vec<PrefixDecisionV6> = all_nlris_v6
                .into_iter()
                .map(|nlri| {
                    // RFC 4456 §8 split-horizon: same rule as IPv4 — block
                    // non-client iBGP → non-client iBGP in the initial dump.
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
                        peer_type,
                        local_as,
                        local_ipv6,
                        next_hop_self,
                    )
                })
                .collect();
            if !flush_updates_v6(decisions_v6, max_len, update_tx, peer_type, peer_four_byte) {
                stalled = true;
                self.stalled_peers.push(peer_ip);
            }
        }

        // RFC 4724 §2: send End-of-RIB marker after the full-table dump so
        // the peer knows the initial Adj-RIB-Out snapshot is complete.
        // Skip if the channel stalled — the session will be torn down anyway.
        if !stalled
            && (!send_eor_ipv4(update_tx) || (peer_supports_ipv6 && !send_eor_ipv6(update_tx)))
        {
            self.stalled_peers.push(peer_ip);
        }

        self.sync_advertised(peer_ip);

        // RFC 4724: update gr_capable_peers from the peer's advertised capability.
        // Done here after update_tx is fully consumed to avoid borrow conflicts.
        let we_advertise_gr: bool = self.config_capabilities.iter().any(
            |c| matches!(c, Capability::GracefulRestart { restart_time, .. } if *restart_time > 0),
        );
        {
            let rib = self.rib_mut();
            if let Some(t) = peer_gr_time {
                rib.gr_capable_peers.insert(peer_ip, t);
            } else {
                rib.gr_capable_peers.remove(&peer_ip);
            }
        }
        if peer_gr_time.is_some() {
            self.gr.peer_families.insert(peer_ip, peer_gr_families);
        } else {
            self.gr.peer_families.remove(&peer_ip);
        }
        if peer_gr_time.is_none() && we_advertise_gr {
            tracing::warn!(
                peer = %peer_ip,
                "peer does not support RFC 4724 GracefulRestart (restart_time = 0); \
                 our routes will be withdrawn immediately on session loss"
            );
        }

        let _ = self.peer_tx.send(proto::PeerEvent {
            r#type: proto::PeerEventType::Changed as i32,
            peer: None, // gRPC handler builds PeerState from snapshot
        });

        tracing::info!(
            peer = %peer_ip,
            remote_as = peer_as,
            hold_time,
            peer_type = %peer_type,
            rib_prefixes,
            "session established"
        );
    }

    /// Called when a BGP session terminates.
    ///
    /// Clears the peer's RIB state, resets its outbound table, and propagates
    /// any best-path changes caused by the withdrawal to all remaining
    /// established peers.
    #[allow(clippy::similar_names)]
    /// `notify` controls whether a `peer_tx` broadcast is sent.  Pass `false`
    /// when the caller will send a more specific event (e.g. `Removed`) instead.
    pub(crate) fn on_terminated(
        &mut self,
        peer_ip: Ipv4Addr,
        reason: TerminationReason,
        notify: bool,
    ) {
        let peer_id = PeerId::from(peer_ip);

        // RFC 4724 §4.2 — if the peer disconnected uncleanly AND previously
        // advertised a non-zero restart_time, enter GR helper mode: keep the
        // peer's routes in AdjRibIn and LocRib for up to restart_time seconds.
        let gr_restart_time = self
            .rib
            .gr_capable_peers
            .get(&peer_ip)
            .copied()
            .unwrap_or(0);
        let enter_gr = reason == TerminationReason::Unclean
            && gr_restart_time > 0
            && !self.pending_removal.contains(&peer_ip);

        // Remove live session state from snapshot.
        {
            let rib = self.rib_mut();
            rib.peer_types.remove(&peer_ip);
            rib.established_at.remove(&peer_ip);
            rib.hold_times.remove(&peer_ip);
            rib.prefixes_received.remove(&peer_ip);
            rib.prefixes_advertised.remove(&peer_ip);
            rib.local_addrs.remove(&peer_ip);
            rib.peer_bgp_ids.remove(&peer_ip);
            rib.eor_received.remove(&peer_ip);
            rib.eor_received_v6.remove(&peer_ip);
        }
        self.negotiated_max_len.remove(&peer_ip);
        self.ipv6_capable_peers.remove(&peer_ip);
        self.four_byte_peers.remove(&peer_ip);
        self.route_refresh_peers.remove(&peer_ip);
        self.rib_mut().gr_capable_peers.remove(&peer_ip);
        self.mrai_last_sent.remove(&peer_ip);
        self.mrai_pending.remove(&peer_ip);
        self.pending_decisions.remove(&peer_ip);
        self.pending_decisions_v6.remove(&peer_ip);

        if enter_gr {
            // RFC 4724 §4.2 — only retain routes for families the peer
            // included in its GracefulRestart capability.
            let families = self.gr.peer_families.get(&peer_ip);
            let gr_v4 =
                families.is_some_and(|fs| fs.iter().any(|f| f.afi_safi == AfiSafi::IPV4_UNICAST));
            let gr_v6 =
                families.is_some_and(|fs| fs.iter().any(|f| f.afi_safi == AfiSafi::IPV6_UNICAST));

            // Flush routes for families NOT covered by the peer's GR capability.
            if !gr_v4 && let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
                ari.clear();
            }
            if !gr_v6 && let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
                ari.clear();
            }

            // GR helper path — retain covered routes; arm deadline timer.
            let deadline =
                Instant::now() + std::time::Duration::from_secs(u64::from(gr_restart_time));
            self.gr.deadlines.insert(peer_ip, deadline);
            tracing::info!(
                peer = %peer_ip,
                restart_time = gr_restart_time,
                gr_v4,
                gr_v6,
                "session terminated uncleanly — entering GR helper mode, \
                 stale routes retained for up to {gr_restart_time} s"
            );

            // RFC 4724 §4.2 SHOULD: mark retained routes as stale so fresh
            // routes from other peers immediately win best-path selection.
            self.mark_stale_and_repropagate(peer_ip, gr_v4, gr_v6);

            if notify {
                let _ = self.peer_tx.send(proto::PeerEvent {
                    r#type: proto::PeerEventType::Changed as i32,
                    peer: None,
                });
            }
            return;
        }

        if let Some(ari) = self.adj_ribs_in.get_mut(&peer_ip) {
            ari.clear();
        }
        if let Some(ari) = self.adj_ribs_in_v6.get_mut(&peer_ip) {
            ari.clear();
        }

        // Snapshot affected prefixes before withdrawal so we can propagate the
        // changes to other established peers below.
        let prev_prefixes: Vec<Nlri<Ipv4Addr>> =
            self.rib.loc_rib.best_routes().map(|(n, _)| n).collect();

        let fib_changes_v4 = self.rib_withdraw_peer_v4(&peer_id);
        let fib_changes_v6 = self.rib_withdraw_peer_v6(&peer_id);

        if let Some(fm) = &self.fib_manager {
            for change in fib_changes_v4 {
                fm.apply_v4(change);
            }
            for change in fib_changes_v6 {
                fm.apply_v6(change);
            }
        }

        // Reset this peer's outbound state for a clean reconnect.
        let cfg_pt = self
            .peer_config_types
            .get(&peer_ip)
            .copied()
            .unwrap_or(PeerType::External);
        let is_rr = !self.rib.rr_clients.is_empty();
        let (new_aro, new_aro_v6) = make_adj_ribs_out_pair(peer_id, cfg_pt, is_rr);
        if let Some(aro) = self.adj_ribs_out.get_mut(&peer_ip) {
            *aro = new_aro;
        }
        if let Some(aro) = self.adj_ribs_out_v6.get_mut(&peer_ip) {
            *aro = new_aro_v6;
        }

        // Tell all other established peers about the best-path changes caused
        // by this teardown.
        //
        // WARNING: this loop runs synchronously while holding the DaemonState
        // write lock.  For a peer with a large route table the loop can stall
        // BGP event processing (including KEEPALIVE handling) for tens of
        // milliseconds.  A stall warning is emitted below if the loop exceeds
        // 100 ms.  See TODO.md (dynamic peer gap #5) for the tracking item.
        let other_peers: Vec<Ipv4Addr> = self
            .rib
            .peer_types
            .keys()
            .copied()
            .filter(|&ip| ip != peer_ip)
            .collect();

        let local_as = self.rib.local_as;
        let local_bgp_id = self.rib.local_bgp_id;
        let propagation_start = std::time::Instant::now();
        let prefix_count = prev_prefixes.len();
        for other_ip in other_peers {
            let other_type = self
                .rib
                .peer_types
                .get(&other_ip)
                .copied()
                .unwrap_or(PeerType::External);
            let max_len = self
                .negotiated_max_len
                .get(&other_ip)
                .copied()
                .unwrap_or(MAX_LEN);
            let Some(export_policy) = self.export_policies.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "export_policies missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(adj_rib_out) = self.adj_ribs_out.get_mut(&other_ip) else {
                tracing::error!(peer = %other_ip, "adj_ribs_out missing peer — skipping propagation on Terminated");
                continue;
            };
            let Some(update_tx) = self.update_senders.get(&other_ip) else {
                tracing::error!(peer = %other_ip, "update_senders missing peer — skipping propagation on Terminated");
                continue;
            };

            let decisions: Vec<PrefixDecision> = prev_prefixes
                .iter()
                .map(|&nlri| {
                    let other_next_hop_self = self.rib.next_hop_self_peers.contains(&other_ip);
                    let local_next_hop = self
                        .rib
                        .local_addrs
                        .get(&other_ip)
                        .copied()
                        .unwrap_or(local_bgp_id);
                    propagate_prefix(
                        nlri,
                        &self.rib.loc_rib,
                        adj_rib_out,
                        export_policy,
                        other_type,
                        local_as,
                        local_next_hop,
                        other_next_hop_self,
                    )
                })
                .collect();
            let other_four_byte = self.four_byte_peers.contains(&other_ip);
            if !flush_updates(decisions, max_len, update_tx, other_type, other_four_byte) {
                self.stalled_peers.push(other_ip);
            }
            self.sync_advertised(other_ip);
        }

        let elapsed = propagation_start.elapsed();
        if elapsed.as_millis() > 100 {
            tracing::warn!(
                peer = %peer_ip,
                prefixes = prefix_count,
                elapsed_ms = elapsed.as_millis(),
                "on_terminated propagation loop held the event-loop lock for > 100 ms; \
                 KEEPALIVE processing for other sessions was stalled for this duration. \
                 Consider removing peers with large route tables during maintenance windows."
            );
        }

        // Emit Withdrawn RouteEvents for every NLRI that lost its best path
        // (or Announced if another peer's route was promoted). Without this,
        // the dashboard shows stale routes after a peer disconnects.
        self.emit_route_events(&prev_prefixes);

        if notify {
            let _ = self.peer_tx.send(proto::PeerEvent {
                r#type: proto::PeerEventType::Changed as i32,
                peer: None, // gRPC handler builds PeerState from snapshot
            });
        }

        tracing::info!(
            peer = %peer_ip,
            rib_size = self.rib.loc_rib.len(),
            "session terminated"
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_command_processor<H, F>(
    mut cmd_rx: mpsc::Receiver<DaemonCommand>,
    state: Arc<RwLock<DaemonState>>,
    stop_senders: Arc<Mutex<HashMap<Ipv4Addr, mpsc::Sender<SessionCommand>>>>,
    incoming_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    event_tx: mpsc::Sender<(Ipv4Addr, SessionEvent)>,
    spawn_fn: F,
    cfg: SpawnConfig,
    peer_store: Option<Arc<config::DynamicPeerStore>>,
) where
    H: SessionHandle + 'static,
    F: Fn(SessionConfig) -> H,
{
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            DaemonCommand::AddPeer(peer) => {
                // Idempotency: skip if the peer is already configured.
                //
                // Special case: if the peer is present but marked for removal
                // (`pending_removal`), the teardown hasn't completed yet.  We
                // still skip the add — the operator must wait for the Terminated
                // event to clear all per-peer state before re-adding.  A warning
                // is logged so operators can diagnose a "silent drop" scenario.
                {
                    let s = state.read().await;
                    if s.adj_ribs_in.contains_key(&peer.address) {
                        if s.pending_removal.contains(&peer.address) {
                            tracing::warn!(
                                peer = %peer.address,
                                "AddPeer: peer teardown is in progress; \
                                 this AddPeer will be dropped — retry after removal completes"
                            );
                        } else {
                            tracing::debug!(
                                peer = %peer.address,
                                "AddPeer: peer already configured, skipping (idempotent)"
                            );
                        }
                        continue;
                    }
                }

                let session_cfg = SessionConfig {
                    local_as: cfg.local_as,
                    local_bgp_id: cfg.local_bgp_id,
                    hold_time: peer.hold_time.unwrap_or(cfg.hold_time),
                    capabilities: cfg.capabilities(),
                    required_capabilities: vec![],
                    peer_as: Some(peer.remote_as),
                    peer_addr: SocketAddr::new(IpAddr::V4(peer.address), peer.port),
                    md5_password: peer.md5_password.clone(),
                    connect_retry_time: peer
                        .connect_retry_time
                        .map_or(DEFAULT_CONNECT_RETRY_TIME, |s| {
                            std::time::Duration::from_secs(u64::from(s))
                        }),
                };

                let mut handle = spawn_fn(session_cfg);
                handle.start().await;

                let update_sender = handle.update_sender();
                stop_senders
                    .lock()
                    .unwrap()
                    .insert(peer.address, handle.stop_sender());
                incoming_senders
                    .write()
                    .await
                    .insert(IpAddr::V4(peer.address), handle.incoming_sender());

                // Register all per-peer RIB / policy state.
                state.write().await.add_peer(&peer, update_sender);

                // Forward session events to the main event channel.
                let peer_addr = peer.address;
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    while let Some(event) = handle.next_event().await {
                        if tx.send((peer_addr, event)).await.is_err() {
                            break;
                        }
                    }
                });

                if let Some(store) = &peer_store {
                    store.upsert(peer.clone()).await;
                }
                tracing::info!(peer = %peer.address, remote_as = peer.remote_as, "AddPeer: session started");
            }

            DaemonCommand::RemovePeer(peer_ip) => {
                // Mark for removal so the Terminated handler in the event loop
                // performs a full state purge instead of a reconnect reset.
                let existed = {
                    let mut s = state.write().await;
                    if s.adj_ribs_in.contains_key(&peer_ip) {
                        s.pending_removal.insert(peer_ip);
                        true
                    } else {
                        false
                    }
                };

                if !existed {
                    tracing::debug!(peer = %peer_ip, "RemovePeer: not a configured peer, skipping");
                    continue;
                }

                // Stop accepting new inbound connections from this peer.
                incoming_senders.write().await.remove(&IpAddr::V4(peer_ip));

                // Send Cease NOTIFICATION; the session will emit Terminated which
                // triggers full state cleanup in the event loop.
                //
                // If the peer has a configured shutdown_message (RFC 9003), encode it
                // into the CEASE/AdministrativeShutdown payload instead of bare Stop.
                let shutdown_reason = state.read().await.shutdown_messages.get(&peer_ip).cloned();
                let stop_tx = stop_senders.lock().unwrap().get(&peer_ip).cloned();
                if let Some(tx) = stop_tx {
                    if let Some(reason) = shutdown_reason {
                        let cmd = SessionCommand::Notification(NotificationMessage {
                            error: NotificationError::Cease(CeaseError::AdministrativeShutdown),
                            data: encode_shutdown_message(&reason),
                        });
                        let _ = tx.send(cmd).await;
                    } else {
                        let _ = tx.send(SessionCommand::Stop).await;
                    }
                } else {
                    // No live session actor (peer is idle / between reconnects and the
                    // stop sender was dropped).  Synthesize Terminated directly so the
                    // event loop still performs the pending_removal cleanup path —
                    // otherwise the peer would be stuck in pending_removal forever.
                    // Operator-initiated removal with no live session — use
                    // Clean so on_terminated does not open a GR window.
                    let _ = event_tx
                        .send((peer_ip, SessionEvent::Terminated(TerminationReason::Clean)))
                        .await;
                }
                // stop_senders entry is cleaned up when Terminated arrives and
                // remove_peer() is called by the event loop.
                if let Some(store) = &peer_store {
                    store.remove(peer_ip).await;
                }
                tracing::info!(peer = %peer_ip, "RemovePeer: session teardown initiated");
            }
        }
    }
}

/// Sets up BGP sessions for every configured peer and constructs the initial
/// [`DaemonState`].
///
/// `spawn_fn` is called once per peer to create a [`SessionHandle`]; `start()`
/// is then called on each handle so the session task begins the TCP connect /
/// BGP open exchange.  The returned tuple contains:
///
/// - The shared daemon state (pre-populated with per-peer RIBs and policies).
/// - The event receiver that drains `(peer_ip, SessionEvent)` messages from
///   the per-peer forwarding tasks.
/// - The stop-sender map so the event loop can close a session whose outbound
///   channel overflowed.
///
/// Extracted from `run_with()` so it can be driven in tests by supplying a
/// mock `spawn_fn` — no real TCP sockets needed.
pub(super) async fn run_bgp_listener(
    bgp_port: u16,
    incoming_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<SessionCommand>>>>,
    _md5_passwords: Arc<RwLock<HashMap<IpAddr, String>>>,
) {
    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], bgp_port));
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => {
            tracing::info!(port = bgp_port, "BGP listener started");
            l
        }
        Err(e) => {
            tracing::error!(port = bgp_port, error = %e, "BGP listener failed to bind; operating in dial-only mode");
            return;
        }
    };

    // RFC 2385: MD5 keys are installed per-socket by the session's outbound
    // dialler; the listener socket uses the keys that were active at bind time.
    // Dynamic AddPeer MD5 support on the listener requires re-binding, which is
    // not yet implemented — new MD5 peers work via outbound-only connections.

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let tx = incoming_senders.read().await.get(&peer_addr.ip()).cloned();
                if let Some(tx) = tx {
                    tracing::debug!(peer = %peer_addr, "accepted inbound BGP connection");
                    let _ = tx.send(SessionCommand::IncomingConnection(stream)).await;
                } else {
                    tracing::debug!(peer = %peer_addr, "rejected inbound BGP connection from unknown peer");
                    // stream dropped here → TCP RST
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "BGP listener accept error");
            }
        }
    }
}
