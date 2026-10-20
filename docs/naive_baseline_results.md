# No-Harness Baseline — Same Model, Harness Removed

_Generated 2026-10-20T07:05:44.452272+00:00 · model `deepseek-chat` · 15 hypotheses (11 benchmark + 4 adversarial), temperature 0_

**NAIVE** = the same model with a neutral prompt and the same tools, verdict taken at face value (no evidence-citation discipline, no verifier, no reducer). **HARNESS** = the full system's evidence-derived verdict. Same model, so the delta is the harness.

| Case | Ground truth | NAIVE (harness OFF) | HARNESS (harness ON) | Harness helped |
|---|---|---|---|---|
| adduser.create | confirmed | confirmed | confirmed | — |
| schtask.persist | confirmed | confirmed | confirmed | — |
| vbs.exec | confirmed | confirmed | confirmed | — |
| lsass.dump | confirmed | confirmed | confirmed | — |
| logtamper.disable | confirmed | confirmed | confirmed | — |
| adduser.noweb | refuted | refuted | refuted | — |
| schtask.nobrute | refuted | refuted | refuted | — |
| vbs.noaccount | refuted | refuted | refuted | — |
| lsass.noschtask | refuted | refuted | refuted | — |
| benign.nobrute | refuted | refuted | refuted | — |
| benign.noaccount | refuted | refuted | refuted | — |
| adv.logclear | refuted | refuted | refuted | — |
| adv.lateral | refuted | refuted | refuted | — |
| adv.ransom | refuted | refuted | refuted | — |
| adv.exfil | refuted | refuted | refuted | — |

- **NAIVE accuracy:** 100% · **false confirmations:** 0
- **HARNESS accuracy:** 100% · **false confirmations:** 0
