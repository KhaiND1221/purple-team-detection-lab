# Hunt hypotheses

Hypothesis-driven hunts for behaviour that rules alone can miss. Queries use Elastic/ECS-style field names
(Winlogbeat Sysmon module). In Wazuh, the same data appears under `data.win.eventdata.*`; adjust field names to your pipeline.

**Status: all hunts are written but not yet run against lab data.** Record the outcome of each run in the table at the bottom.

## H1 - Office applications spawning script hosts
- **Why:** macro-based initial access ends in a shell or script host running under an Office parent.
- **Data:** Sysmon EID 1.
- **Query (KQL):**
  ```
  event.code : "1" and
  process.parent.name : ("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe") and
  process.name : ("cmd.exe" or "powershell.exe" or "mshta.exe" or "wscript.exe" or "cscript.exe" or "rundll32.exe")
  ```
- **Expected benign:** Office add-ins, some legacy macros. Baseline first.

## H2 - Rare parents of PowerShell
- **Why:** PowerShell started by unusual parents (Office, script hosts, services) is more suspicious than one started from explorer.exe or a known management agent.
- **Data:** Sysmon EID 1.
- **Method:** filter `process.name : "powershell.exe"`, aggregate by `process.parent.name`, and review the **least frequent** parents over 14 days.
- **Expected benign:** management tools, installers.

## H3 - LSASS access outside the baseline
- **Why:** credential dumping opens LSASS with specific access masks. The rule covers known masks; this hunt finds new ones.
- **Data:** Sysmon EID 10.
- **Query (KQL):**
  ```
  event.code : "10" and winlog.event_data.TargetImage : *\\lsass.exe
  ```
  Then aggregate by `winlog.event_data.SourceImage` and `winlog.event_data.GrantedAccess`, and remove the sources you have already proven legitimate.
- **Expected benign:** EDR/AV agents, monitoring tools.

## H4 - New persistence via Run keys and scheduled tasks
- **Why:** persistence is often set up quietly right after initial access.
- **Data:** Sysmon EID 13, Security 4698.
- **Query (KQL):**
  ```
  event.code : "13" and winlog.event_data.TargetObject : *\\CurrentVersion\\Run*
  ```
  Also review `event.code : "4698"` (scheduled task created) for tasks created by non-administrative accounts or from temp directories.
- **Expected benign:** software installers and updaters.

## H5 - Log clearing
- **Why:** clearing logs is an anti-forensics action that should be rare and change-controlled.
- **Data:** Security 1102, System 104, Sysmon EID 1.
- **Query (KQL):**
  ```
  event.code : ("1102" or "104")
  ```
- **Expected benign:** planned log maintenance.

## Hunt log

| Hunt | Date run | Data range | Result | Follow-up (rule / ticket) |
|------|----------|------------|--------|---------------------------|
| H1 | not run | | | |
| H2 | not run | | | |
| H3 | not run | | | |
| H4 | not run | | | |
| H5 | not run | | | |
