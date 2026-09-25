# Incident Report - <short title>

> Template structured after NIST SP 800-61. Fill every section from **real lab evidence** and delete this line.
> Placeholders are written as `<...>`. Do not publish invented data.

| Field | Value |
|-------|-------|
| Incident ID | `<LAB-YYYY-NNN>` |
| Date / time of detection (with timezone) | `<...>` |
| Reported by | `<name>` |
| Severity | `<low / medium / high / critical>` and why |
| Status | `<open / contained / closed>` |

## 1. Executive summary
Three to five sentences: what happened, what was affected, how it was detected, how it was resolved, what decision is needed.

## 2. Scope and affected assets
| Asset | Role | Impact |
|-------|------|--------|
| `<host>` | `<role>` | `<...>` |

## 3. Timeline
| Time (UTC+7) | Event | Source (log / alert) |
|--------------|-------|----------------------|
| `<hh:mm:ss>` | `<initial access>` | `<Sysmon EID 1 / Wazuh rule id>` |

## 4. Attack narrative mapped to MITRE ATT&CK
| Tactic | Technique | Evidence | Detected? (rule / hunt / missed) |
|--------|-----------|----------|-----------------------------------|
| `<...>` | `<Txxxx.xxx>` | `<...>` | `<...>` |

## 5. Indicators of compromise
| Type | Value | Context |
|------|-------|---------|
| SHA256 | `<...>` | `<file, path>` |
| Command line | `<...>` | `<process>` |

## 6. Detection and analysis
How the alert was raised, how it was validated, which queries and artifacts led to the conclusion. Include the rule ids that fired and the ones that should have fired but did not.

## 7. Containment, eradication and recovery
- **Containment:** `<what, when, by whom>`
- **Eradication:** `<...>`
- **Recovery:** `<...>`

## 8. Root cause
`<how the attacker got in and which control failed or was missing>`

## 9. Metrics
| Metric | Value |
|--------|-------|
| Time to detect | `<...>` |
| Time to contain | `<...>` |
| Techniques executed / detected / missed | `<x / y / z>` |

## 10. Lessons learned and recommendations
| Action | Owner | Priority | Due |
|--------|-------|----------|-----|
| `<new or tuned detection>` | `<...>` | `<...>` | `<...>` |

## Appendix
Log excerpts, query text, screenshots, hashes of collected evidence.
