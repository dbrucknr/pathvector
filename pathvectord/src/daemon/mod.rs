//! BGP daemon core: routing state, event dispatch, and session management.
//!
//! The modules are arranged along ports-and-adapters lines:
//!
//! | Layer | Modules |
//! |---|---|
//! | Domain rules (no I/O) | `peering`, `ingress`, `blackhole` |
//! | State and use cases | `state`, `rib_snapshot`, `peer_stats`, `peer`, `route`, `import`, `fib`, `policy`, `origination`, `gr`, `deferral` |
//! | Driving adapters | `event_loop` (sessions and timers), `command` (management port), `rpki_feed` |
//! | Composition root | `bootstrap` |
//!
//! The driven ports are the traits `SessionHandle`, `ApplyFibChange` and
//! `NextHopOracle`. [`DaemonState`] is declared in `state`; each use-case module
//! adds its own `impl DaemonState` block.
//!
//! The layering is not yet strict:
//!
//! - the state layer builds `proto` event messages and holds session `mpsc`
//!   senders directly;
//! - `peer` also hosts the BGP listener and command processor tasks;
//! - `capabilities` mixes OPEN capability construction with the listener's
//!   TCP MD5 keys.
//!
//! The `use` list below is the shared prelude: older submodules pull it in with
//! `use super::*`. Newer ones import what they need directly.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use pathvector_policy::{Decision, DefaultAction, Policy};
use pathvector_rib::{
    AdjRibIn, AdjRibOut, BestPathChange, LocRib, PeerId, Route, RouteBuilder, oracle::NextHopOracle,
};
use pathvector_session::{
    message::{
        Capability, CeaseError, GracefulRestartFamily, MAX_LEN, MAX_LEN_EXTENDED, MpReachNlri,
        MpUnreachNlri, NotificationError, NotificationMessage, PathAttribute, Prefix,
        UpdateMessage, UpdateMsgError, encode_shutdown_message,
    },
    transport::{
        DEFAULT_CONNECT_RETRY_TIME, SendHoldTime, SessionCommand, SessionConfig, SessionEvent,
        SessionHandle, TerminationReason,
        listener::{BgpListener, Inbound, ListenerKeys, ListenerProtection},
        tcp_md5::{KernelTcpMd5, Md5Enforcement, TcpMd5Auth, TcpMd5Port},
    },
};
use pathvector_types::{
    AfiSafi, AsPath, Asn, LocalPref, Med, NextHop, Nlri, Origin, PeerType, Role, UnknownAttribute,
};
use tokio::sync::{RwLock, mpsc};

use crate::outbound::{
    PrefixDecision, PrefixDecisionV6, flush_updates, flush_updates_v6, propagate_prefix,
    propagate_prefix_v6, send_eor_ipv4, send_eor_ipv6,
};
use crate::{config, grpc, proto};

// Production modules. The layer each belongs to is in the table above.
mod blackhole;
mod bootstrap;
mod capabilities;
mod command;
mod deferral;
mod event_loop;
mod fib;
mod gr;
mod import;
mod ingress;
mod origination;
mod peer;
mod peer_stats;
mod peering;
mod policy;
mod rib_snapshot;
mod route;
mod rpki_feed;
mod state;

// Test modules. `tests` groups the topic suites and holds shared fixtures; the
// rest are per-issue regression suites.
#[cfg(test)]
mod import_reject_tests;
#[cfg(test)]
mod tests;
// Issue #138: announcements dropped before import policy still withdraw the
// peer's older route.
#[cfg(test)]
mod as_content_tests;
#[cfg(test)]
mod ingress_drop_tests;
#[cfg(test)]
mod last_feasible_tests;
#[cfg(test)]
mod listener_md5_tests;
#[cfg(test)]
mod mrai_flush_tests;
// Issue #160: session loss must withdraw or replace routes in both families.
#[cfg(test)]
mod session_loss_tests;
// Issue #178: UPDATEs stay within the negotiated maximum message size.
#[cfg(test)]
mod update_size_tests;
// Issues #81 and #82: BLACKHOLE authorization and import eligibility through
// Graceful Restart.
#[cfg(test)]
mod blackhole_tests;
#[cfg(test)]
mod issue_81_82_tests;
// Issue #68: conventional-GR stale routes keep their ordinary preference.
#[cfg(test)]
mod gr_preference_tests;
// Issue #69: RFC 4456 §9 reflected-route tie-breakers through ingestion.
#[cfg(test)]
mod rr_tie_break_tests;
// Issues #177 / #135: RFC 4456 §8 attributes are added on reflection.
#[cfg(test)]
mod rr_reflection_tests;
// Issue #168: RFC 4456 §6 non-client split-horizon on every send path.
#[cfg(test)]
mod rr_split_horizon_tests;
// Issue #159: UPDATEs sent to a peer, applied in order, match its Adj-RIB-Out.
#[cfg(test)]
mod outbound_order_tests;
// Sessions the daemon resets on its own authority must reconnect.
#[cfg(test)]
mod session_restart_tests;

pub(crate) use bootstrap::run;
pub(crate) use command::DaemonCommand;
pub(crate) use rib_snapshot::RibSnapshot;
pub(crate) use state::DaemonState;

// Re-exports so that sibling submodules using `use super::*` can call
// items defined in other sibling submodules.
use blackhole::{BlackholeBook, BlackholeBooks, BlackholeChange, PeerBlackhole};
use capabilities::{Md5Keys, SpawnConfig, remove_listener_key, session_tcp_md5, set_listener_key};
use fib::changed_nlris;
use import::{
    ImportPipeline, ImportTally, RibEffects, import_announcement, import_ineligible,
    reapply_import_policy, retire_routes, withdraw_route,
};
use ingress::{Disposition, IngressDrop, IngressGate};
use peering::{
    config_peer_type, effective_confederation_member, effective_role, effective_session_as,
    install_otc_export_term, install_otc_import_term, make_adj_ribs_out_pair, peer_blackhole,
    resolve_export_default, resolve_import_default,
};

// Used only by the test suites.
#[cfg(test)]
use crate::fib as crate_fib;
#[cfg(test)]
use bootstrap::build_daemon;
#[cfg(test)]
use capabilities::build_local_capabilities;
#[cfg(test)]
use event_loop::{handle_session_terminated, run_event_loop};
#[cfg(test)]
use fib::withdraw_stale_bgp_routes;
#[cfg(test)]
use gr::GracefulRestartState;
#[cfg(test)]
use import::reapply_without_blackholes;
#[cfg(test)]
use pathvector_policy::BgpRoute;
#[cfg(test)]
use pathvector_rib::oracle::AlwaysReachable;
#[cfg(test)]
use peer::{run_bgp_listener, run_command_processor};
#[cfg(test)]
use route::MraiTracker;
#[cfg(test)]
use route::handle_update;
#[cfg(test)]
use rpki_feed::install_rpki;
#[cfg(test)]
use tests::must_v4;
#[cfg(test)]
use tokio::sync::watch;

/// Synthetic `PeerId` used as the source for locally originated routes.
///
/// Must not collide with any real peer address. `0.0.0.0` is unassignable as
/// a BGP peer, so it is safe as a sentinel here.
pub(crate) const LOCAL_ORIGIN_PEER: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// RFC 4271 §9.2.1.1: default Minimum Route Advertisement Interval for eBGP.
pub(crate) const MRAI: std::time::Duration = std::time::Duration::from_secs(30);
