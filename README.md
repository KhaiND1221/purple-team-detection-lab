# Security Policy

## Maintainers and security contact

| Role                | Name                                          |
| ------------------- | --------------------------------------------- |
| Maintainer          | [@KhaiND1221](https://github.com/KhaiND1221) |
| Security maintainer | [@KhaiND1221](https://github.com/KhaiND1221) |

The security maintainer triages vulnerability reports, coordinates fixes and publishes advisories for this repository.

## Supported versions

Only the latest commit on `main` is supported. There are no tagged releases yet.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub:
**Security** tab → **Report a vulnerability**
(<https://github.com/KhaiND1221/purple-team-detection-lab/security/advisories/new>)

Include:
- what is affected (file, rule, script or workflow)
- steps to reproduce
- the impact you expect

You can expect an acknowledgement within 7 days. Confirmed issues are fixed on `main` and, where relevant, published as a GitHub Security Advisory with credit to the reporter.

## Scope

In scope:
- code in `tools/`, `automation/` and `ci/` (for example unsafe parsing of input files, command injection, dependency issues in `requirements.txt`)
- Sigma or Wazuh rules that are broken in a way that silently hides the activity they claim to detect
- anything in the repository that leaks secrets or real data

Out of scope:
- the attack techniques in `attack/plan.yaml`; these are public MITRE ATT&CK / Atomic Red Team techniques used on purpose, inside an isolated lab
- detection gaps that are already listed as `missed` in `attack/plan.yaml`
