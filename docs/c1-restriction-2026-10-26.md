# User-observed C1 restriction result — 2026-10-26

Run ID: 2a6839cf0c32498e9396f0df7e0231c0.
Variant: C1-functional-rule-test with upstream simple_switch_13.
These results were supplied by the user from the Mint laptop; no raw report
was independently retrieved. Do not attribute them to the new custom controller.

| Phase | monitor1 → reception1 ping | C1 successes per monitor |
|---|---|---|
| Before | 2/2 replies | 40/40 for each of three monitors |
| Restricted | 0/2 replies | 51/51 for each of three monitors |
| Recovered | 2/2 replies | 40/40 for each of three monitors |

The ingress drop readback showed cookie 0xc140000000000001, priority 40000,
IPv4 source 10.20.0.16, hard_timeout 10, n_packets 2 and n_bytes 196.
The runner reported restriction_demo PASS and all four worker exit codes were
zero. Mininet stopped six switches, 24 hosts and 29 links.

393/393 application probes succeeded across these measured phases. This count
is not the entire 60-second traffic run; the automated test stopped workers after
the recovery phase. Phase lengths include different ping durations, so do not
compare raw phase counts as throughput changes.

This verifies one synthetic UDP preservation case and timed IPv4 restriction.
It is not attack detection, complete host isolation, multi-seed evaluation or a
proof of all hospital safety invariants.

Raw report on the user's laptop:
artifacts/clinical/2a6839cf0c32498e9396f0df7e0231c0/restriction-report.json
