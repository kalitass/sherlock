# Experiment — Repeatability (same hypothesis, run twice)

_Generated 2026-10-20T07:57:07.263496+00:00 · temperature 0 · evidence-derived verdict_

Dataset manifest hash `69132fb197be`, **unchanged across all runs: True** — so any difference is agent variance, not data drift.

| Hypothesis | Verdict run 1 | Verdict run 2 | Match | Finding Jaccard | Query-plan Jaccard |
|---|---|---|---|---|---|
| adduser.create | confirmed | confirmed | ✅ | 0.6 | 0.113 |
| lsass.dump | confirmed | confirmed | ✅ | 0.75 | 0.375 |
| benign.nobrute | refuted | refuted | ✅ | 0.6 | 0.089 |
| adv.logclear | refuted | refuted | ✅ | 1.0 | 0.111 |

- **Verified-verdict agreement:** 4/4
- **Mean finding-set Jaccard** (verified MITRE techniques): 0.738
- **Mean query-plan Jaccard** (index+DSL digests): 0.172

Convergence is engineered, not assumed: (1) **temperature 0** for near-deterministic decoding; (2) a **coverage-first system contract** that fixes the order of investigation (enumerate sources → quantify → pull records); (3) a **forced final answer** so a run that exhausts its tool budget still emits a verdict from the evidence gathered instead of defaulting to inconclusive; and (4) the **evidence gate**, which discards any claim not tied to a real query — so even when the free-text narrative differs slightly between runs, the *verified* findings and the verdict converge.
