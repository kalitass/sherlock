# Data Sources & Provenance

Sherlock uses **only public, third-party-labelled attack telemetry** — no
hand-synthesised attacks. All datasets come from one authoritative source:

> **OTRF Security-Datasets** (formerly *Mordor*), by the Open Threat Research Forum.
> Repository: <https://github.com/OTRF/Security-Datasets> · Licence: **MIT**.
> Each dataset is real Windows Security / Sysmon / PowerShell event telemetry,
> captured in a lab while a specific MITRE ATT&CK technique was executed, and
> published with that technique as a label — which is what makes it usable as
> ground truth for the accuracy benchmark.

Datasets are downloaded on demand by `datasets/mordor_import.py` and cached under
`datasets/mordor_cache/` (git-ignored — nothing large is committed). Every ingested
record carries its origin in the `_ingest.source` field as
`OTRF/Security-Datasets:<path>`.

## Datasets used (14 techniques, 7 ATT&CK tactics)

Each path below is relative to
`https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows/`.

| Index (`sherlock-logs-…`) | ATT&CK | Technique | Source path |
|---|---|---|---|
| `mordor_adduser` | T1136.001 | Create Account: Local Account | `defense_evasion/host/empire_wmic_add_user_backdoor.zip` |
| `mordor_schtask` | T1053.005 | Scheduled Task | `persistence/host/empire_schtasks_creation_standard_user.zip` |
| `mordor_vbs_exec` | T1059.005 | Scripting: Visual Basic | `execution/host/empire_launcher_vbs.zip` |
| `mordor_lsass_dump` | T1003.001 | OS Credential Dumping: LSASS Memory | `credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip` |
| `mordor_logtamper` | T1562.002 | Impair Defenses: Disable Windows Event Logging | `defense_evasion/host/psh_disable_eventlog_service_startuptype_modification.zip` |
| `mordor_localgroup_disc` | T1069.001 | Permission Groups Discovery: Local Groups | `discovery/host/empire_shell_net_localgroup_administrators.zip` |
| `mordor_localuser_disc` | T1087.001 | Account Discovery: Local Account | `discovery/host/empire_shell_net_local_users.zip` |
| `mordor_sam_dump` | T1003.002 | OS Credential Dumping: SAM | `credential_access/host/cmd_sam_copy_esentutl.zip` |
| `mordor_lsa_secrets` | T1003.004 | OS Credential Dumping: LSA Secrets | `credential_access/host/cmd_psexec_lsa_secrets_dump.zip` |
| `mordor_uac_bypass` | T1548.002 | Abuse Elevation Control: Bypass UAC | `privilege_escalation/host/empire_uac_shellapi_fodhelper.zip` |
| `mordor_svc_mod` | T1543.003 | Create/Modify System Process: Windows Service | `privilege_escalation/host/cmd_service_mod_fax.zip` |
| `mordor_fw_disable` | T1562.004 | Impair Defenses: Disable/Modify System Firewall | `defense_evasion/host/cmd_netsh_fw_mod_open_ports.zip` |
| `mordor_mshta_exec` | T1218.005 | System Binary Proxy Execution: Mshta | `defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip` |
| `mordor_remote_svc` | T1021.002 | Remote Services: SMB/Windows Admin Shares | `lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl.zip` |

Tactics covered: Credential Access · Defense Evasion · Persistence · Discovery ·
Execution · Privilege Escalation · Lateral Movement.

The full OTRF library holds 150+ Windows atomic captures plus Linux, cloud and
multi-stage APT datasets; the pipeline can ingest any of them with no code change
(`datasets/mordor_import.py` MANIFEST), so coverage is bounded by effort, not
capability. The 14 above were chosen as distinct, non-overlapping techniques so a
hunt against one dataset is a clean negative control for the others.

## Citation

```
Open Threat Research Forum (OTRF). Security-Datasets.
https://github.com/OTRF/Security-Datasets (MIT License).
```
