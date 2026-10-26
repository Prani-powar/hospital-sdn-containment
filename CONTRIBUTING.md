# Team contribution guide

Invite teammates using repository Settings → Collaborators. Each person needs
their own GitHub account and local clone. No invitations are sent automatically.
Copy the HTTPS clone URL from the actual repository's Code button and clone it.

## Work on a branch

From the cloned repository:

```bash
git switch main
git pull --ff-only
git switch -c feature/hospital-topology
```

Choose a different descriptive branch name for each task. After making changes:

```bash
python3 -m unittest discover -s infra/tests -v
git diff --check
git diff
git status --short
```

Stage the specific files you changed, commit, and push your branch. Open a pull
request and ask a teammate to review it before merging. Branch protection has
not been configured; review is a team convention until enforced in Settings.

## Suggested ownership

| Member | Main area |
|---|---|
| CS 1 | Topology, normal traffic, clinical probes |
| CS 2 | Controller, OpenFlow, stats, REST boundary |
| AIML 1 | Features, datasets and anomaly detection |
| AIML 2 | Policy decisions, evaluation and metrics |

Share dashboard integration after interfaces are stable. Windows can be used
for much of the ML/dashboard work; emulator testing needs compatible Linux.

Agree on shared contracts before working in parallel. Preserve critical allow
rules, expire all containment rules, and split ML data by run/seed. Keep tokens,
passwords, private documents and actual patient data out of git. Clearly label
manual observations, automated tests and anything not yet verified.
