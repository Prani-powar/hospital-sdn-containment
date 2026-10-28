# Custom controller: user-reported Mint validation, 26 October 2026

These results are transcribed from terminal output supplied by the team. They are
not independent authoring-workspace measurements. Raw artifacts remain on the laptop.

- Custom image `99dda2a6f664` built; 17 original local tests and four Ryu adapter
  tests passed on Mint. Controller epoch `b51cb5c7c3004947bb8c5740d8ddfcd6`.
- All-pairs output showed 0% dropped; the pasted final count was truncated.
- Read API showed six connected switches, complete flow telemetry and ingress rows
  for monitor1 and central_mon during a targeted ping.
- Restriction run `a84107f9e488445dae5e7c0b8bf2e357`: PASS. Before ping 2/2,
  restricted 0/2, recovered 2/2. Three monitor sources each had 40/40, 50/50,
  40/40 replies across the three measured phases: 390/390 combined. This is
  measured-phase coverage, not an entire 60-second service run.
- Drop cookie `0xc140000000000001`, priority 40000, timeout 10s, two packets,
  196 bytes. Expiry/recovery and clean worker/Mininet shutdown were reported.
- Finite UDP workload offered 4,814 sends in 10.001s (~481.35/s), zero local
  send errors. No receiver-delivery metric was collected.
- All 15 controller samples showed six connections and complete flow snapshots;
  peak sampled CPU was 74.71% of one core. This does not exclude brief unsampled
  disconnects/errors or establish service preservation during load.
- During that sample interval: aggregate admission denials rose 1,811 -> 4,766
  (+2,955), source guard drops reached 2,754, observation evictions rose
  598 -> 2,784 (+2,186), peak RSS reached 68,362,240 bytes. Request/completion
  totals differ because of in-flight requests and earlier connection generations;
  the difference alone is not a poll-loss count.
- Post-load monitor1 -> central_mon ping: 3/3, mean RTT 7.803ms. Clean teardown
  confirmed 24 hosts, six switches, 29 links.

The original aggregate denial counter could not distinguish rate versus capacity,
and duplicate installs reserved extra slots. The subsequent accounting patch adds
that distinction and match-keyed leases. It has 22 passing unprivileged tests in the
authoring workspace; updated real-Ryu build and live Mint regression are pending.
Do not use the old load measurements as evidence of improvement from the patch.
