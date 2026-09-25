# Detections

Rules live in [`sigma/`](sigma/) as vendor-neutral Sigma. Each rule carries ATT&CK tags, false-positive notes and a level.
Rules are **experimental** until the matching step in [`../attack/plan.yaml`](../attack/plan.yaml) is marked `detected`.

| Rule | Technique | Level |
|------|-----------|-------|
| `proc_creation_win_office_spawn_shell` | T1204.002 | high |
| `proc_creation_win_powershell_encoded_command` | T1059.001 | medium |
| `proc_creation_win_mshta_remote_or_script` | T1218.005 | high |
| `proc_creation_win_certutil_download` | T1105 | high |
| `proc_creation_win_rundll32_comsvcs_minidump` | T1003.001 | high |
| `proc_access_win_lsass_suspicious_access` | T1003.001 | high |
| `registry_set_win_run_key_persistence` | T1547.001 | medium |
| `proc_creation_win_schtasks_persistence` | T1053.005 | medium |
| `proc_creation_win_net_use_admin_share` | T1021.002 | medium |
| `proc_creation_win_evtlog_clear` | T1070.001 | high |

## Tuning workflow

1. Run the step in the lab and record whether the rule fired.
2. Run the rule against normal activity in the lab (software installs, admin tasks) and note false positives.
3. Add exclusions as `filter_main_*` selections with a comment explaining why, and update `falsepositives`.
4. Promote `status` from `experimental` to `test` and then `stable` only after both checks.

## Porting a rule to Wazuh

Wazuh matches on decoded event fields, so a Sigma rule is translated by hand. Example for the comsvcs MiniDump rule
(see [`wazuh/local_rules_example.xml`](wazuh/local_rules_example.xml)). Field names and parent rule ids depend on your
Wazuh version, so verify them in your own ruleset and test with `wazuh-logtest` before enabling.
