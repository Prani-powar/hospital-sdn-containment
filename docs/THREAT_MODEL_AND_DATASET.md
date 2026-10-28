# Threat model, dataset and validity

The adversary is an emulated endpoint producing unusual contacts and ports.
A valid run marker received by another endpoint represents synthetic infection
in process memory. This is neither exploitation nor proof that a real device
is infected. No remote command execution, persistence, credential theft or
patient information is involved. Hosts, topology, controller and experiment
operator are trusted. MAC/IP source attachment is checked by the controller;
endpoint credentials, encrypted application contents and host integrity are not
verified by this research prototype.

The system studies bounded lateral-contact detection and selective forwarding
restrictions. It does not defend against a compromised controller, malicious
root operator, an attacker using only permitted clinical paths, or attacks
that remain below the selected observation thresholds. Preserving synthetic
UDP replies does not establish clinical safety, DICOM/HL7 interoperability or
availability of real treatment equipment.

The local action API uses an environment-provided bearer token, bounded bodies,
versioned proposals, epoch checks and switch readback. The token is not persisted
in reports, URLs or browser storage. Loopback binding does not defend against
another malicious local privileged process. Joblib models are trusted executable
artifacts, never accepted through a browser upload. The public dashboard is a
simulation and cannot reach the operator's laptop.

## Dataset card

Inputs: configured RFC1918 hospital endpoints; 12, 24 or 48 hosts, six switches;
all five synthetic clinical groups; normal per-role peer profiles. Normal
agents send harmless request/replies approximately once per second with seeded
jitter. Clinical sources send five requests/s by default on synthetic UDP ports
18001–18005. S1/S3 use four attack packets/s per infected agent. S2 sweeps
0.5/1/2/4. Each run retains the exact configs, seed, implementation hashes,
CPU affinity, package/image versions and monotonic boot identifier.

Labels come from in-memory marker receipts. Infection-boundary windows and
post-containment censored windows are omitted. Run-level partitions prevent
overlapping windows leaking between model splits. Controlled labels measure
this artificial task, not real-world malware accuracy. Archive raw agent,
clinical and decision logs with every dataset release, include hashes and a
license chosen by the repository owners. Dataset publication is not automatic.

## Literature rationale and limits

NIST SP 800-207 (Rose et al., 2020),
https://www.nist.gov/publications/zero-trust-architecture , motivates resource
and workflow protection rather than trusting network location alone.
NHS England's network segmentation introduction,
https://digital.nhs.uk/cyber-and-data-security/guidance-and-resources/network-segmentation/introduction ,
discusses containing lateral movement and avoiding disruption to required
healthcare communication. These sources motivate resource-specific policy and
continuity measurement. They do NOT validate our packet rates, peer lists,
feature distributions or thresholds. Those are declared experimental choices;
claims of realistic hospital traffic require independent traces or validation.

## Threats to validity

Synthetic traffic can make ML classification artificially easy. Scanning and
marker spreading are correlated by construction. Selected thresholds can fail
on slow or permitted traffic. Overlapping windows are dependent observations;
confidence intervals must use run/seed units, not individual windows. Fit and
calibration must exclude held-out seeds. Repeated inspection of test results
invalidates the holdout even if the software enforces separate run IDs.

Mininet shares a kernel and CPU resources. Affinity reduces scheduling variation
but not OVS daemon interference, SMT, frequency changes, VM scheduling or host
load. Record clock resolution and retain failure/missing-event counts alongside
latencies. Scaling keeps six switches and changes clinical-source counts at
12 hosts; report that explicitly. Static B1 and blind B2 are specified baselines,
not representative of every commercial segmentation deployment. Benchmark-only
OVS writes intentionally have different enforcement machinery from B3; latency
comparisons include that architectural difference.
