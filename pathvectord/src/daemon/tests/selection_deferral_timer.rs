//! ── RFC 4724 §4.1 — Restarting-Speaker Selection_Deferral_Timer ─────────────

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use pathvector_session::message::{PathAttribute, UpdateMessage};
use pathvector_types::{AfiSafi, AsPath, Asn, Nlri, Origin, PeerType};

use crate::daemon::deferral::SelectionDeferral;
use crate::daemon::tests::make_state;
use crate::daemon::{Capability, GracefulRestartFamily};

const PEER_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const AS_A: u32 = 65002;
const AS_B: u32 = 65003;
const LOCAL_AS: u32 = 65001;

fn nlri(s: &str) -> Nlri<Ipv4Addr> {
    s.parse().unwrap()
}

fn gr_caps() -> Vec<Capability> {
    vec![Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 120,
        families: vec![GracefulRestartFamily {
            afi_safi: AfiSafi::IPV4_UNICAST,
            forwarding_preserved: true,
        }],
    }]
}

/// RFC 4724 §3: a peer MAY advertise GracefulRestart with
/// `restart_time == 0` and no `<AFI, SAFI>` families specifically to
/// signal "I don't preserve forwarding state, but I will still
/// generate End-of-RIB" — not the same as never advertising GR at all.
fn eor_only_gr_caps() -> Vec<Capability> {
    vec![Capability::GracefulRestart {
        restart_flags: 0,
        restart_time: 0,
        families: vec![],
    }]
}

fn establish(state: &mut super::DaemonState, peer: Ipv4Addr, remote_as: u32, caps: &[Capability]) {
    state.on_established(
        IpAddr::V4(peer),
        peer,
        PeerType::External,
        remote_as,
        90,
        caps,
        None,
    );
}

fn ipv4_eor() -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![],
        announced: vec![],
    }
}

fn announce(prefix: &str, peer_as: u32) -> UpdateMessage {
    UpdateMessage {
        withdrawn: vec![],
        attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath::from_sequence(vec![Asn::new(peer_as)])),
            PathAttribute::NextHop("192.0.2.1".parse().unwrap()),
        ],
        announced: vec![nlri(prefix)],
    }
}

/// Nonzero `selection_deferral_time`, two configured peers, both
/// established. Only peer A is GR-capable; peer B is not, so it never
/// contributes to the v4 wait-set (RFC 4724 §4.1 excludes non-GR-capable
/// peers). Peer A announces a route with no EOR yet — the gate must
/// still be closed, so peer B's outbound stays empty despite the route
/// existing in Loc-RIB. Once A sends its EOR, the wait-set is fully
/// satisfied (B never counted), the gate opens, and B receives a
/// catch-up dump ending in its own EOR.
#[test]
fn deferred_gate_blocks_propagation_until_eor_then_catches_up() {
    let (mut state, mut rxs) = make_state(
        LOCAL_AS,
        &[(IpAddr::V4(PEER_A), AS_A), (IpAddr::V4(PEER_B), AS_B)],
    );
    state.selection_deferral = SelectionDeferral::new(Instant::now(), 120);

    establish(&mut state, PEER_A, AS_A, &gr_caps());
    establish(&mut state, PEER_B, AS_B, &[]); // not GR-capable
    assert!(state.selection_deferral.v4_deferred(), "gate starts closed");

    // Drain the (empty) dumps from establishment.
    let rx_b = rxs.get_mut(&IpAddr::V4(PEER_B)).unwrap();
    assert!(rx_b.try_recv().is_err(), "no dump while deferred");

    // A announces a route — Loc-RIB updates immediately (scope is
    // outbound-only), but propagation to B must stay suppressed.
    state.on_route_update(IpAddr::V4(PEER_A), announce("10.0.0.0/24", AS_A));
    state.flush_pending();
    assert!(
        rx_b.try_recv().is_err(),
        "B must receive nothing while the v4 gate is still closed"
    );

    // A's EOR satisfies the wait-set (B was never a member) — gate opens.
    state.on_route_update(IpAddr::V4(PEER_A), ipv4_eor());
    assert!(
        !state.selection_deferral.v4_deferred(),
        "gate must open once the only GR-capable configured peer EORs"
    );

    // B must now receive a catch-up dump: the announced route, followed
    // by B's own EOR.
    let msg = rx_b
        .try_recv()
        .expect("B must receive the catch-up dump once the gate opens");
    assert_eq!(msg.announced, vec![nlri("10.0.0.0/24")]);
    let eor = rx_b.try_recv().expect("B must also receive its own EOR");
    assert!(eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty());
}

/// A configured peer that never establishes conservatively blocks
/// release — even after the only established peer sends its EOR, the
/// gate must stay closed until the unestablished peer either connects
/// or the deadline fires.
#[test]
fn unestablished_configured_peer_keeps_gate_closed() {
    let (mut state, _rxs) = make_state(
        LOCAL_AS,
        &[(IpAddr::V4(PEER_A), AS_A), (IpAddr::V4(PEER_B), AS_B)],
    );
    state.selection_deferral = SelectionDeferral::new(Instant::now(), 120);

    establish(&mut state, PEER_A, AS_A, &gr_caps());
    // PEER_B is configured but never established.

    state.on_route_update(IpAddr::V4(PEER_A), ipv4_eor());
    assert!(
        state.selection_deferral.v4_deferred(),
        "gate must stay closed while a configured peer has never connected"
    );
}

/// RFC 4724 §4.1 excludes only peers that "do not advertise the
/// graceful restart capability" — not peers that advertise it with
/// `restart_time == 0` (EOR-only mode). A single such peer must still
/// block the gate until it sends EOR, exactly like a full GR peer.
#[test]
fn eor_only_gr_peer_keeps_gate_closed_until_its_eor() {
    let (mut state, mut rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_A), AS_A)]);
    state.selection_deferral = SelectionDeferral::new(Instant::now(), 120);

    establish(&mut state, PEER_A, AS_A, &eor_only_gr_caps());
    assert!(
        state.selection_deferral.v4_deferred(),
        "an EOR-only (restart_time=0) GR peer must still block the gate \
         until its own EOR, not be treated as non-GR"
    );

    let rx_a = rxs.get_mut(&IpAddr::V4(PEER_A)).unwrap();
    assert!(rx_a.try_recv().is_err(), "no dump while deferred");

    state.on_route_update(IpAddr::V4(PEER_A), ipv4_eor());
    assert!(
        !state.selection_deferral.v4_deferred(),
        "gate must open once the sole configured (EOR-only) peer sends EOR"
    );
}

/// The Selection_Deferral_Timer (path (b)) overrides an unsatisfied
/// wait-set unconditionally, and still runs the gate-open catch-up for
/// whichever peers are currently established.
#[test]
fn force_release_overrides_unsatisfied_wait_set_and_catches_up() {
    let (mut state, mut rxs) = make_state(
        LOCAL_AS,
        &[(IpAddr::V4(PEER_A), AS_A), (IpAddr::V4(PEER_B), AS_B)],
    );
    state.selection_deferral = SelectionDeferral::new(Instant::now(), 120);

    establish(&mut state, PEER_A, AS_A, &gr_caps());
    // PEER_B never connects — would block release forever without (b).
    assert!(state.selection_deferral.v4_deferred());

    state.force_release_selection_deferral();
    assert!(
        !state.selection_deferral.v4_deferred(),
        "force_release must open the gate regardless of the wait-set"
    );

    // A (currently established) must receive its own catch-up EOR.
    let rx_a = rxs.get_mut(&IpAddr::V4(PEER_A)).unwrap();
    let eor = rx_a
        .try_recv()
        .expect("A must receive a catch-up EOR after forced release");
    assert!(eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty());
}

/// Regression guard: `selection_deferral_time == 0` (the
/// `DaemonState::new()` default) must behave exactly as before this
/// feature existed — no deferral, immediate full-table dump on establish.
#[test]
fn disabled_deferral_dumps_immediately_on_establish() {
    let (mut state, mut rxs) = make_state(LOCAL_AS, &[(IpAddr::V4(PEER_A), AS_A)]);
    assert!(!state.selection_deferral.v4_deferred());
    assert!(!state.selection_deferral.v6_deferred());

    establish(&mut state, PEER_A, AS_A, &gr_caps());

    // No routes exist yet, so the only message is A's own EOR — but it
    // must arrive immediately, not be withheld.
    let rx_a = rxs.get_mut(&IpAddr::V4(PEER_A)).unwrap();
    let eor = rx_a
        .try_recv()
        .expect("disabled deferral must still dump (here: just EOR) immediately");
    assert!(eor.withdrawn.is_empty() && eor.attributes.is_empty() && eor.announced.is_empty());
}
