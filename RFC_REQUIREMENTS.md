# RFC Requirements Index

Per-crate RFC requirements are documented in each crate's `RFC.md`. This file is a
one-line-per-RFC index showing which crate(s) own each RFC and the aggregate status.

**Status:** ✅ All requirements implemented | ⚠️ Partial | ❌ Not started

| RFC | Title | Owner crate(s) | Status | Detail |
|---|---|---|---|---|
| RFC 1997 | BGP Communities Attribute | pathvector-types, pathvector-policy | ✅ | [types](pathvector-types/RFC.md#rfc-1997--bgp-communities-attribute) · [policy](pathvector-policy/RFC.md#rfc-1997--bgp-communities-attribute-policy-layer) |
| RFC 1930 | AS Number Guidelines (2-byte private range) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-1930--as-number-guidelines-private-range-2-byte) |
| RFC 2385 | BGP TCP MD5 Protection | pathvector-session | ❌ | [session](pathvector-session/RFC.md#rfc-2385--protection-of-bgp-sessions-via-md5-deferred) |
| RFC 2918 | Route Refresh Capability | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-2918--route-refresh-capability-for-bgp-4) |
| RFC 3107 | MPLS Label in BGP (SAFI constant) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-3107-rfc-4364-rfc-4761-rfc-7432-rfc-5575--safi-constants-encoding-deferred) |
| RFC 4271 §4 | BGP Message Formats | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-4271-4--message-formats) |
| RFC 4271 §5 | Path Attribute Types | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-4271-5--path-attribute-types) |
| RFC 4271 §8 | BGP Finite State Machine | pathvector-session, pathvectord | ✅ | [session](pathvector-session/RFC.md#rfc-4271-8--bgp-finite-state-machine) · [daemon](pathvectord/RFC.md#rfc-4271-8--connection-collision-coordination) |
| RFC 4271 §9.1 | Best-Path Decision Process (steps 1, 8 deferred) | pathvector-rib | ⚠️ | [rib](pathvector-rib/RFC.md#rfc-4271-91--decision-process-best-path-selection) |
| RFC 4271 §9.2 | Update-Send Process / RIB Structures | pathvector-rib, pathvectord | ✅ | [rib](pathvector-rib/RFC.md#rfc-4271-92--update-send-process-rib-structures) · [daemon](pathvectord/RFC.md#rfc-4271-92--update-send-process) |
| RFC 4360 | Extended Communities Attribute | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-4360--bgp-extended-communities-attribute) |
| RFC 4364 | BGP/MPLS IP VPNs (SAFI constant) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-3107-rfc-4364-rfc-4761-rfc-7432-rfc-5575--safi-constants-encoding-deferred) |
| RFC 4456 | BGP Route Reflection | pathvector-rib | ❌ | [rib](pathvector-rib/RFC.md#rfc-4456--bgp-route-reflection-deferred) |
| RFC 4486 | Cease NOTIFICATION Subcodes | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-4486--subcodes-for-bgp-cease-notification-message) |
| RFC 4724 | Graceful Restart | pathvector-session, pathvector-rib | ⚠️ | [session](pathvector-session/RFC.md#rfc-4724--graceful-restart-mechanism-for-bgp) · [rib](pathvector-rib/RFC.md#rfc-4724--graceful-restart-stale-route-timer-deferred) |
| RFC 4760 | Multiprotocol Extensions (AFI/SAFI) | pathvector-types, pathvector-session, pathvectord | ✅ | [types](pathvector-types/RFC.md#rfc-4760--multiprotocol-extensions-for-bgp-4-afisafi-registry) · [session](pathvector-session/RFC.md#rfc-4760--multiprotocol-extensions-for-bgp-4-codec) · [daemon](pathvectord/RFC.md#rfc-4760--multiprotocol-extensions-daemon-processing) |
| RFC 4761 | VPLS Using BGP (SAFI constant) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-3107-rfc-4364-rfc-4761-rfc-7432-rfc-5575--safi-constants-encoding-deferred) |
| RFC 5065 | AS Confederations | pathvector-types, pathvector-rib | ✅ | [types](pathvector-types/RFC.md#rfc-5065--as-confederations-for-bgp) · [rib](pathvector-rib/RFC.md#rfc-5065--as-confederations-for-bgp-rib-layer) |
| RFC 5492 | Capabilities Advertisement | pathvector-session | ⚠️ | [session](pathvector-session/RFC.md#rfc-5492--capabilities-advertisement-with-bgp-4) |
| RFC 5575 | FlowSpec (SAFI constant) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-3107-rfc-4364-rfc-4761-rfc-7432-rfc-5575--safi-constants-encoding-deferred) |
| RFC 6286 | AS-Wide Unique BGP Identifier | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-6286--autonomous-system-wide-unique-bgp-identifier) |
| RFC 6608 | FSM Error Subcodes | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-6608--subcodes-for-bgp-finite-state-machine-error) |
| RFC 6793 | Four-Octet AS Numbers | pathvector-types, pathvector-session | ⚠️ | [types](pathvector-types/RFC.md#rfc-6793--bgp-support-for-four-octet-as-numbers) · [session](pathvector-session/RFC.md#rfc-6793--four-octet-as-number-capability) |
| RFC 6996 | Private AS Reservation (4-byte) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-6996--as-reservation-for-private-use-4-byte-range) |
| RFC 7432 | BGP EVPN (SAFI constant) | pathvector-types | ✅ | [types](pathvector-types/RFC.md#rfc-3107-rfc-4364-rfc-4761-rfc-7432-rfc-5575--safi-constants-encoding-deferred) |
| RFC 7606 | Revised Error Handling for UPDATE | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-7606--revised-error-handling-for-bgp-update-messages) |
| RFC 7854 | BGP Monitoring Protocol (BMP) | pathvector-bmp | ❌ | [bmp](pathvector-bmp/RFC.md#rfc-7854--bgp-monitoring-protocol-bmp) |
| RFC 7911 | Advertisement of Multiple Paths (ADD-PATH) | pathvector-session, pathvector-rib | ❌ | — |
| RFC 7947 | Internet Exchange BGP Route Server | pathvectord | ❌ | — |
| RFC 7999 | BLACKHOLE Community | pathvector-types, pathvector-policy, pathvectord | ✅ | [types](pathvector-types/RFC.md#rfc-7999--blackhole-community) · [policy](pathvector-policy/RFC.md#rfc-7999--blackhole-community-policy-integration) · [daemon](pathvectord/RFC.md#rfc-7999--blackhole-community-discard-action) |
| RFC 8092 | BGP Large Communities | pathvector-types, pathvector-policy | ✅ | [types](pathvector-types/RFC.md#rfc-8092--bgp-large-communities-attribute) · [policy](pathvector-policy/RFC.md#rfc-8092--bgp-large-communities-attribute-policy-layer) |
| RFC 8205 | BGPsec_PATH | pathvector-types, pathvector-session | ❌ | — |
| RFC 8212 | Default eBGP Route Propagation | pathvectord | ✅ | [daemon](pathvectord/RFC.md#rfc-8212--default-external-bgp-route-propagation-without-policy) |
| RFC 8654 | Extended Message Support | pathvector-session | ✅ | [session](pathvector-session/RFC.md#rfc-8654--extended-message-support-for-bgp) |
| RFC 6396 | MRT Routing Information Export Format | pathvectord | ❌ | — |
