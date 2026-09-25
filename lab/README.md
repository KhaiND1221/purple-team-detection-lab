# Lab build notes

Target: a small isolated lab that runs on one laptop or PC with about 16 GB RAM.

## Machines

| VM | Role | Suggested spec |
|----|------|----------------|
| `attacker` | Runs the test steps, hosts a small web server for download tests | Linux or Windows, 2 vCPU, 2-4 GB |
| `win-victim` | Windows 10/11 with Sysmon and the Wazuh agent | 2 vCPU, 4 GB |
| `win-target` (optional) | Second Windows VM, target for the lateral movement step (S8) | 2 vCPU, 4 GB |
| `wazuh` | Wazuh manager, indexer and dashboard | 2-4 vCPU, 6-8 GB (see the Wazuh sizing guide) |

## Network isolation

- Put all VMs on one **host-only / internal** network (for example `192.168.56.0/24`).
- Give the internet to a VM only while installing tools, then remove that route before running attack steps.
- Snapshot every VM after the clean install. Revert after each step or after the full run.

## Telemetry

1. Install **Sysmon** on the Windows VMs with a maintained configuration
   ([SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or
   [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)):
   `sysmon64.exe -accepteula -i sysmonconfig.xml`
2. Make sure the config logs the events the rules rely on: process creation (EID 1), network connection (3),
   process access to LSASS (10) and registry value set (13). Some community configs exclude or filter these; check yours.
3. Tell the Wazuh agent to read the Sysmon channel (`ossec.conf` on the Windows VM):

   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

4. Enable command-line auditing and PowerShell script block logging (Group Policy) so EID 4688 and 4104 are available.
5. Confirm events reach the Wazuh dashboard **before** running any attack step.

## Attack tooling

Install [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) on `win-victim`, then list the tests for a step:

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

Read the details of each test before running it, and always run the cleanup afterwards.
Endpoint protection may block or quarantine some tests. Decide in advance whether real-time protection is on or off
for the lab, and write that decision in the report so the results can be interpreted.

## Rule delivery

Sigma is the source of truth. Wazuh uses its own XML rule format, so a Sigma rule is either ported by hand
(see [`../detections/README.md`](../detections/README.md)) or converted for a backend that pySigma supports
(for example Elasticsearch/OpenSearch queries) using [sigma-cli](https://github.com/SigmaHQ/sigma-cli).
Run `sigma list targets` and `sigma list pipelines` to see what your installation offers.
