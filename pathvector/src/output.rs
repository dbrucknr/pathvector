//! Human-readable table and detail formatting for peers and routes.
//!
//! All output goes to stdout via `println!`.  Functions are kept pure (no I/O
//! side-effects beyond printing) so they are easy to unit-test.

use pathvector_client::types::{
    AsSegment, AsSegmentType, PeerEvent, PeerEventType, PeerState, Route, RouteEvent,
    RouteEventType, SessionState,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format an uptime in seconds as `HH:MM:SS`, or `—` when the session is not
/// established (uptime is zero).
pub fn format_uptime(secs: u64) -> String {
    if secs == 0 {
        return "\u{2014}".to_owned(); // em-dash
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Render a BGP `AS_PATH` as a space-separated string of ASNs.  `AS_SET` segments
/// are enclosed in braces: `{65001 65002}`.  Confederation segments are
/// included as-is.
pub fn format_as_path(segments: &[AsSegment]) -> String {
    if segments.is_empty() {
        return "\u{2014}".to_owned();
    }
    segments
        .iter()
        .map(|seg| {
            let asns: Vec<String> = seg
                .asns
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            match seg.kind {
                AsSegmentType::Set | AsSegmentType::ConfedSet => {
                    format!("{{{}}}", asns.join(" "))
                }
                _ => asns.join(" "),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format an optional `u32` metric value, using `—` for absent.
pub fn format_opt_u32(v: Option<u32>) -> String {
    v.map_or_else(|| "\u{2014}".to_owned(), |n| n.to_string())
}

/// Format the peer type abbreviation for table display.
fn fmt_peer_type(state: &PeerState) -> &'static str {
    match state.peer_type {
        Some(pathvector_client::types::PeerType::External) => "eBGP",
        Some(pathvector_client::types::PeerType::Internal) => "iBGP",
        Some(_) | None => "—",
    }
}

/// Format the session state for table display.
fn fmt_session_state(state: &PeerState) -> &'static str {
    match state.session_state {
        SessionState::Established => "Established",
        SessionState::Idle => "Idle",
        _ => "Unknown",
    }
}

// ── Peer output ───────────────────────────────────────────────────────────────

/// Print a compact table of all configured BGP peers.
///
/// ```text
/// ADDRESS      REMOTE-AS  TYPE  STATE        UPTIME    RCV  ACC  ADV
/// 10.0.0.1     65001      eBGP  Established  00:03:45    5    4    3
/// 10.0.0.2     65003      eBGP  Idle         —           0    0    0
/// ```
pub fn print_peer_table(peers: &[PeerState]) {
    if peers.is_empty() {
        println!("No peers configured.");
        return;
    }
    println!(
        "{:<16} {:>10}  {:<4}  {:<11}  {:>8}  {:>4} {:>4} {:>4}",
        "ADDRESS", "REMOTE-AS", "TYPE", "STATE", "UPTIME", "RCV", "ACC", "ADV"
    );
    for p in peers {
        println!(
            "{:<16} {:>10}  {:<4}  {:<11}  {:>8}  {:>4} {:>4} {:>4}",
            p.address.to_string(),
            p.remote_as,
            fmt_peer_type(p),
            fmt_session_state(p),
            format_uptime(p.uptime_seconds),
            p.prefixes_received,
            p.prefixes_accepted,
            p.prefixes_advertised,
        );
    }
}

/// Print a detailed key-value view of a single peer.
pub fn print_peer_detail(peer: &PeerState) {
    println!("Address:    {}", peer.address);
    println!("Local AS:   {}", peer.local_as);
    println!("Remote AS:  {}", peer.remote_as);
    println!(
        "Type:       {}",
        match peer.peer_type {
            Some(pathvector_client::types::PeerType::External) => "eBGP (External)",
            Some(pathvector_client::types::PeerType::Internal) => "iBGP (Internal)",
            Some(_) | None => "—",
        }
    );
    println!("State:      {}", fmt_session_state(peer));
    println!("Uptime:     {}", format_uptime(peer.uptime_seconds));
    println!("Hold time:  {}s", peer.hold_time);
    println!("Received:   {} prefix(es)", peer.prefixes_received);
    println!("Accepted:   {} prefix(es)", peer.prefixes_accepted);
    println!("Advertised: {} prefix(es)", peer.prefixes_advertised);
}

// ── Route output ──────────────────────────────────────────────────────────────

/// Print a compact table of routes.
///
/// ```text
/// PREFIX             PEER        NEXT-HOP    AS-PATH         ORIGIN  MED
/// 192.168.1.0/24     10.0.0.1    10.0.0.1    65001           IGP     —
/// 10.0.0.0/8         10.0.0.2    10.0.0.2    65003 65100     EGP     100
/// ```
pub fn print_route_table(routes: &[Route]) {
    if routes.is_empty() {
        println!("No routes.");
        return;
    }
    println!(
        "{:<20} {:<16} {:<16} {:<20} {:<6}  MED",
        "PREFIX", "PEER", "NEXT-HOP", "AS-PATH", "ORIGIN"
    );
    for r in routes {
        let next_hop = r
            .next_hop
            .map_or_else(|| "\u{2014}".to_owned(), |ip| ip.to_string());
        println!(
            "{:<20} {:<16} {:<16} {:<20} {:<6}  {}",
            r.prefix,
            r.peer_address
                .map_or_else(|| "local".to_owned(), |a| a.to_string()),
            next_hop,
            format_as_path(&r.as_path),
            format_origin(r.origin),
            format_opt_u32(r.med),
        );
    }
}

/// Print a detailed key-value view of a single route.
pub fn print_route_detail(route: &Route) {
    let next_hop = route
        .next_hop
        .map_or_else(|| "\u{2014}".to_owned(), |ip| ip.to_string());

    println!("Prefix:     {}", route.prefix);
    let peer_addr_str = route
        .peer_address
        .map_or_else(|| "local".to_owned(), |a| a.to_string());
    println!("Peer:       {} ({})", peer_addr_str, {
        match route.peer_type {
            pathvector_client::types::PeerType::External => "eBGP",
            pathvector_client::types::PeerType::Internal => "iBGP",
            _ => "—",
        }
    });
    println!("Next-hop:   {next_hop}");
    println!("AS-path:    {}", format_as_path(&route.as_path));
    println!("Origin:     {}", format_origin(route.origin));
    println!("Local-pref: {}", format_opt_u32(route.local_pref));
    println!("MED:        {}", format_opt_u32(route.med));

    if !route.communities.is_empty() {
        let communities: Vec<String> = route
            .communities
            .iter()
            .map(|c| {
                let high = c >> 16;
                let low = c & 0xFFFF;
                format!("{high}:{low}")
            })
            .collect();
        println!("Communities: {}", communities.join(" "));
    }

    if !route.large_communities.is_empty() {
        let lc: Vec<String> = route
            .large_communities
            .iter()
            .map(|lc| format!("{}:{}:{}", lc.global_admin, lc.local_data1, lc.local_data2))
            .collect();
        println!("Large communities: {}", lc.join(" "));
    }

    if route.atomic_aggregate {
        println!("Atomic-aggregate: yes");
    }

    if let Some(agg) = &route.aggregator {
        println!("Aggregator: AS{} {}", agg.asn, agg.address);
    }
}

// ── Watch event output ────────────────────────────────────────────────────────

/// Print a single route event as one line to stdout.
///
/// ```text
/// CURRENT     10.0.0.0/8         via 192.0.2.1
/// END_INITIAL
/// ANNOUNCED   198.51.100.1/32    via local
/// WITHDRAWN   10.2.0.0/24
/// ```
pub fn print_route_event(event: &RouteEvent) {
    if event.event_type == RouteEventType::EndInitial {
        println!("END_INITIAL");
    } else if event.event_type == RouteEventType::Withdrawn {
        let prefix = event.withdrawn_prefix.as_deref().unwrap_or("?");
        println!("{:<12} {prefix}", "WITHDRAWN");
    } else {
        let label = if event.event_type == RouteEventType::Current {
            "CURRENT"
        } else {
            "ANNOUNCED"
        };
        if let Some(route) = &event.route {
            let via = route
                .peer_address
                .map_or_else(|| "local".to_owned(), |a| a.to_string());
            println!("{:<12} {:<22} via {via}", label, route.prefix);
        } else {
            println!("{label}");
        }
    }
}

/// Print a single peer event as one line to stdout.
///
/// ```text
/// CURRENT     192.0.2.1          AS65001  Established
/// END_INITIAL
/// CHANGED     192.0.2.1          AS65001  Idle
/// ```
pub fn print_peer_event(event: &PeerEvent) {
    if event.event_type == PeerEventType::EndInitial {
        println!("END_INITIAL");
    } else {
        let label = if event.event_type == PeerEventType::Current {
            "CURRENT"
        } else {
            "CHANGED"
        };
        if let Some(peer) = &event.peer {
            let state = match peer.session_state {
                SessionState::Established => "Established",
                SessionState::Idle => "Idle",
                _ => "Unknown",
            };
            println!(
                "{:<12} {:<22} AS{:<8} {state}",
                label,
                peer.address.to_string(),
                peer.remote_as,
            );
        } else {
            println!("{label}");
        }
    }
}

pub(crate) fn format_origin(origin: pathvector_client::types::Origin) -> &'static str {
    match origin {
        pathvector_client::types::Origin::Igp => "IGP",
        pathvector_client::types::Origin::Egp => "EGP",
        _ => "?",
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use pathvector_client::types::{
        Aggregator, AsSegment, AsSegmentType, LargeCommunity, Origin, PeerEvent, PeerEventType,
        PeerState, PeerType, Route, RouteEvent, RouteEventType, SessionState,
    };

    // ── Scalar helpers ────────────────────────────────────────────────────────

    #[test]
    fn uptime_zero_is_dash() {
        assert_eq!(format_uptime(0), "\u{2014}");
    }

    #[test]
    fn uptime_formats_correctly() {
        assert_eq!(format_uptime(3661), "01:01:01");
        assert_eq!(format_uptime(86399), "23:59:59");
    }

    #[test]
    fn as_path_empty_is_dash() {
        assert_eq!(format_as_path(&[]), "\u{2014}");
    }

    #[test]
    fn as_path_sequence() {
        let seg = AsSegment {
            kind: AsSegmentType::Sequence,
            asns: vec![65001, 65002],
        };
        assert_eq!(format_as_path(&[seg]), "65001 65002");
    }

    #[test]
    fn as_path_set_uses_braces() {
        let seg = AsSegment {
            kind: AsSegmentType::Set,
            asns: vec![65001, 65002],
        };
        assert_eq!(format_as_path(&[seg]), "{65001 65002}");
    }

    #[test]
    fn as_path_confed_set_uses_braces() {
        let seg = AsSegment {
            kind: AsSegmentType::ConfedSet,
            asns: vec![65003],
        };
        assert_eq!(format_as_path(&[seg]), "{65003}");
    }

    #[test]
    fn as_path_multiple_segments() {
        let segs = vec![
            AsSegment {
                kind: AsSegmentType::Sequence,
                asns: vec![65001],
            },
            AsSegment {
                kind: AsSegmentType::Set,
                asns: vec![65002, 65003],
            },
        ];
        assert_eq!(format_as_path(&segs), "65001 {65002 65003}");
    }

    #[test]
    fn opt_u32_none_is_dash() {
        assert_eq!(format_opt_u32(None), "\u{2014}");
    }

    #[test]
    fn opt_u32_some_is_value() {
        assert_eq!(format_opt_u32(Some(100)), "100");
    }

    #[test]
    fn format_origin_variants() {
        assert_eq!(format_origin(Origin::Igp), "IGP");
        assert_eq!(format_origin(Origin::Egp), "EGP");
        assert_eq!(format_origin(Origin::Incomplete), "?");
    }

    // ── Peer table helpers ────────────────────────────────────────────────────

    fn make_peer(session_state: SessionState, peer_type: Option<PeerType>) -> PeerState {
        PeerState {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_as: 65001,
            local_as: 65002,
            session_state,
            peer_type,
            hold_time: 90,
            uptime_seconds: 3661,
            prefixes_received: 5,
            prefixes_accepted: 4,
            prefixes_advertised: 3,
            eor_ipv4_received: false,
            eor_ipv6_received: false,
        }
    }

    #[test]
    fn print_peer_table_empty() {
        // Must not panic; emits "No peers configured." to stdout.
        print_peer_table(&[]);
    }

    #[test]
    fn print_peer_table_established_external() {
        let peers = vec![make_peer(
            SessionState::Established,
            Some(PeerType::External),
        )];
        print_peer_table(&peers);
    }

    #[test]
    fn print_peer_table_idle_internal() {
        let peers = vec![make_peer(SessionState::Idle, Some(PeerType::Internal))];
        print_peer_table(&peers);
    }

    #[test]
    fn print_peer_table_unknown_type() {
        // peer_type = None → "—" column
        let peers = vec![make_peer(SessionState::Idle, None)];
        print_peer_table(&peers);
    }

    #[test]
    fn print_peer_detail_smoke() {
        let peer = make_peer(SessionState::Established, Some(PeerType::External));
        print_peer_detail(&peer);
    }

    #[test]
    fn print_peer_detail_internal() {
        let peer = make_peer(SessionState::Idle, Some(PeerType::Internal));
        print_peer_detail(&peer);
    }

    #[test]
    fn print_peer_detail_unknown_type() {
        let peer = make_peer(SessionState::Idle, None);
        print_peer_detail(&peer);
    }

    // ── Route table helpers ───────────────────────────────────────────────────

    fn make_route_minimal() -> Route {
        Route {
            prefix: "192.0.2.0/24".to_owned(),
            peer_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer_type: PeerType::External,
            next_hop: None,
            as_path: vec![],
            origin: Origin::Igp,
            local_pref: None,
            med: None,
            communities: vec![],
            large_communities: vec![],
            extended_communities: vec![],
            atomic_aggregate: false,
            aggregator: None,
        }
    }

    fn make_route_full() -> Route {
        Route {
            prefix: "10.0.0.0/8".to_owned(),
            peer_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            peer_type: PeerType::Internal,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            as_path: vec![AsSegment {
                kind: AsSegmentType::Sequence,
                asns: vec![65001, 65002],
            }],
            origin: Origin::Egp,
            local_pref: Some(100),
            med: Some(50),
            communities: vec![(65001 << 16) | 0x64],
            large_communities: vec![LargeCommunity {
                global_admin: 65001,
                local_data1: 1,
                local_data2: 2,
            }],
            extended_communities: vec![[0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64]],
            atomic_aggregate: true,
            aggregator: Some(Aggregator {
                asn: 65001,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            }),
        }
    }

    #[test]
    fn print_route_table_empty() {
        print_route_table(&[]);
    }

    #[test]
    fn print_route_table_minimal() {
        print_route_table(&[make_route_minimal()]);
    }

    #[test]
    fn print_route_table_full_attrs() {
        print_route_table(&[make_route_full()]);
    }

    #[test]
    fn print_route_detail_minimal() {
        // No next-hop, no path attrs, no optional fields.
        print_route_detail(&make_route_minimal());
    }

    #[test]
    fn print_route_detail_full() {
        // Exercises communities, large_communities, atomic_aggregate, aggregator.
        print_route_detail(&make_route_full());
    }

    #[test]
    fn print_route_detail_incomplete_origin() {
        let mut r = make_route_minimal();
        r.origin = Origin::Incomplete;
        print_route_detail(&r);
    }

    #[test]
    fn print_route_detail_internal_peer_type() {
        let mut r = make_route_minimal();
        r.peer_type = PeerType::Internal;
        print_route_detail(&r);
    }

    // ── Watch event output ────────────────────────────────────────────────────

    fn make_route_event_current() -> RouteEvent {
        RouteEvent {
            event_type: RouteEventType::Current,
            route: Some(make_route_minimal()),
            withdrawn_prefix: None,
        }
    }

    #[test]
    fn print_route_event_end_initial() {
        print_route_event(&RouteEvent {
            event_type: RouteEventType::EndInitial,
            route: None,
            withdrawn_prefix: None,
        });
    }

    #[test]
    fn print_route_event_current_with_peer() {
        print_route_event(&make_route_event_current());
    }

    #[test]
    fn print_route_event_current_local_origin() {
        let mut ev = make_route_event_current();
        if let Some(ref mut r) = ev.route {
            r.peer_address = None;
        }
        print_route_event(&ev);
    }

    #[test]
    fn print_route_event_announced() {
        print_route_event(&RouteEvent {
            event_type: RouteEventType::Announced,
            route: Some(make_route_minimal()),
            withdrawn_prefix: None,
        });
    }

    #[test]
    fn print_route_event_announced_no_route() {
        print_route_event(&RouteEvent {
            event_type: RouteEventType::Announced,
            route: None,
            withdrawn_prefix: None,
        });
    }

    #[test]
    fn print_route_event_withdrawn_with_prefix() {
        print_route_event(&RouteEvent {
            event_type: RouteEventType::Withdrawn,
            route: None,
            withdrawn_prefix: Some("192.0.2.0/24".to_owned()),
        });
    }

    #[test]
    fn print_route_event_withdrawn_no_prefix() {
        print_route_event(&RouteEvent {
            event_type: RouteEventType::Withdrawn,
            route: None,
            withdrawn_prefix: None,
        });
    }

    #[test]
    fn print_peer_event_end_initial() {
        print_peer_event(&PeerEvent {
            event_type: PeerEventType::EndInitial,
            peer: None,
        });
    }

    #[test]
    fn print_peer_event_current_established() {
        print_peer_event(&PeerEvent {
            event_type: PeerEventType::Current,
            peer: Some(make_peer(
                SessionState::Established,
                Some(PeerType::External),
            )),
        });
    }

    #[test]
    fn print_peer_event_current_idle() {
        print_peer_event(&PeerEvent {
            event_type: PeerEventType::Current,
            peer: Some(make_peer(SessionState::Idle, Some(PeerType::External))),
        });
    }

    #[test]
    fn print_peer_event_changed() {
        print_peer_event(&PeerEvent {
            event_type: PeerEventType::Changed,
            peer: Some(make_peer(
                SessionState::Established,
                Some(PeerType::External),
            )),
        });
    }

    #[test]
    fn print_peer_event_no_peer() {
        print_peer_event(&PeerEvent {
            event_type: PeerEventType::Changed,
            peer: None,
        });
    }
}
