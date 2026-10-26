# Implementation roadmap

Next module: the config-driven hospital topology. Planned work is not implemented.

1. 24-host flat-L2 hospital, five access switches and one core, validated config.
2. Normal role traffic and C1-C5 clinical-service probes.
3. Custom Ryu app: OpenFlow 1.3, stats, REST, bounded state and storm guard.
4. Decision service: role policy, hysteresis, serialized/versioned host actions,
   leases, reconciliation and one SQLite writer.
5. Role Isolation Forest, fan-out threshold and supervised comparison; train/test
   split by run/seed.
6. Live visual dashboard: topology, status labels, critical health, event timeline
   and human controls tied to real events.
7. B0-B3 evaluation using harmless S1-S3 scenarios, at least 10 seeds, timing,
   blast radius, disruption and confidence intervals.

Resolve PROTECT malicious-source semantics, human override scope, B3a critical
flow metering and B3b connection-state requirements before implementation.
Preserve supplied shared contracts or propose explicit diffs.
