# Download a RIPE RIS full-table dump (~100MB gz)
curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz

# One-shot replay (builds release binaries, starts pathvectord, runs MRT replayer)
just mrt MRT=./latest-bview.gz

Parsing MRT dump: ./latest-bview.gz
  Prefixes: 912,849
  Parse time: 3.4s

Connecting to 127.0.0.1:1179 as AS65001 (router-id 10.0.0.1)
  Session established

Announcing 912,849 prefixes...
  Done: 912,849 prefixes in 4,321 UPDATE messages (2.1s, 434,689/s)
  Unique attribute sets: 1,284

Polling pathvectord gRPC at http://127.0.0.1:51200 for convergence...
  912,849

── Results ──────────────────────────────────────────────────────
  Announcement:   2.10s (912,849 prefixes)
  Convergence:    2.35s (announcement + RIB processing)
  Final RIB count: 912,849 / 912,849 expected
─────────────────────────────────────────────────────────────────
