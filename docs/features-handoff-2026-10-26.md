# Controller regression and feature-extraction handoff

User-supplied Mint terminal evidence, 26 October 2026:

- Accounting update: 22 tests passed. Updated controller image `d5cd4db63235`
  built with four real-Ryu adapter tests passing.
- Controller epoch: `2c2b6c88464044d4b7d278c2d58a1816`.
- Full hospital ping: 552/552, 0% dropped.
- Idle inspection: six connected switches, complete telemetry. Aggregate 1,552
  admission denials split into 1,121 rate and 431 capacity denials. Initial reader
  reported 592 historical observation evictions; subsequent reads had no new gaps.
- Updated load capture had 15 healthy complete samples and peak sampled CPU
  61.18% of one core. It began several seconds before traffic and did not capture
  the whole offered-load interval. Probe send summary was not supplied for this
  run, so offered rate and a full before/after performance improvement are unverified.
  During capture the rate-denial counter rose 1,121 -> 2,949 (+1,828), capacity
  denials 431 -> 2,649 (+2,218). Reader guard deltas invalidated observation
  continuity without a new admitted-sequence gap. Health and stats are separate
  HTTP reads, so their near-contemporaneous cumulative counters can differ slightly.
- Post-load monitor1 -> central_mon: 3/3 replies, mean RTT 3.247 ms.
- Clinical restriction run `1606fe9010944d54bf7a727c9556cd25`: PASS.
  Before ping 2/2, during 0/2, recovery 2/2. Each monitor had 40/40,
  51/51 and 40/40 replies across measured phases: 393/393 combined.
  This is measured-phase coverage, not a full 60-second throughput measurement.
- Drop cookie `0xc140000000000001`, priority 40000, hard timeout 10s:
  two matched packets, 196 bytes. Timed recovery and clean teardown confirmed.

The feature module is a separate, read-only increment. Its authoring-workspace
unprivileged tests pass; live extraction on Mint and the target Python 3.11 image
still need verification. No detection model, automatic action or new clinical
policy is claimed by these results.
