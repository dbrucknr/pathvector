use std::net::Ipv4Addr;

use proptest::prelude::*;

use super::{SessionConfig, SessionHandle, spawn};

fn arb_config() -> impl Strategy<Value = SessionConfig> {
    (1u32..=u32::MAX, 0u16..=65535u16, any::<bool>()).prop_map(
        |(local_as, hold_time, has_peer_as)| SessionConfig {
            local_as,
            local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            hold_time,
            capabilities: vec![],
            required_capabilities: vec![],
            peer_as: if has_peer_as { Some(65002) } else { None },
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        },
    )
}

proptest! {
    /// spawn initializes without panicking for any combination of AS, hold time,
    /// and peer_as configuration.
    #[test]
    fn prop_spawn_does_not_panic(config in arb_config()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let _handle = spawn(config);
            // Spawned task does not run until we yield; dropping the handle here
            // causes the runtime to abort it on drop.
        });
    }

    /// start and stop commands can always be sent without panicking,
    /// regardless of local_as.
    #[test]
    fn prop_start_and_stop_do_not_panic(local_as in 1u32..=u32::MAX) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let handle = spawn(SessionConfig {
                local_as,
                local_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                hold_time: 90,
                capabilities: vec![],
                required_capabilities: vec![],
                peer_as: None,
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
            handle.start().await;
            handle.stop().await;
        });
    }
}
