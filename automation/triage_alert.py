#!/usr/bin/env python3
"""Turn Wazuh alert JSON into a short markdown triage note.

Usage:
  python automation/triage_alert.py alerts.json [--min-level 7] [--vt]

Input: one alert object, a JSON array, or JSON Lines (Wazuh alerts.json).
--vt looks up extracted file hashes on VirusTotal. It needs the VT_API_KEY environment
variable and sends ONLY the hashes, never file contents or hostnames.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

NEXT_STEPS = {
    "T1003.001": [
        "Isolate the host from the network (keep it powered on to preserve memory).",
        "Identify every account that was logged on; treat their credentials as compromised and reset them.",
        "Collect a memory image and the dump file, and note the parent process chain.",
        "Hunt the fleet for the same command line and for other LSASS access events.",
    ],
    "T1059.001": [
        "Decode the encoded command and record the decoded script as evidence.",
        "Check the parent process and how the user or process launched PowerShell.",
        "Look for follow-on network connections (Sysmon EID 3) from the same process.",
    ],
    "T1218.005": [
        "Retrieve the referenced URL or script and analyse it in a sandbox.",
        "Block the URL or domain at the proxy and search for other hosts that contacted it.",
    ],
    "T1105": [
        "Identify the downloaded file, hash it and check reputation.",
        "Block the source URL or domain and search proxy logs for other requesters.",
    ],
    "T1547.001": [
        "Inspect the referenced binary or script, and its signature and hash.",
        "Remove the Run key value after evidence is captured; check the same host for other persistence.",
    ],
    "T1053.005": [
        "Export the task definition (schtasks /query /xml) before deleting it.",
        "Check who created it and from which parent process.",
    ],
    "T1021.002": [
        "Identify the source host and account; verify whether the access is expected administration.",
        "Look for file writes or service creation on the target share after the connection.",
    ],
    "T1070.001": [
        "Treat as likely anti-forensics: find out what happened just before the clear using forwarded logs.",
        "Confirm the events were already forwarded to the SIEM before the local log was wiped.",
    ],
    "T1204.002": [
        "Recover the document and its macro for analysis; identify how it arrived (mail gateway logs).",
        "Search mailboxes for the same attachment hash or sender.",
    ],
}
DEFAULT_STEPS = [
    "Validate the alert against raw logs and decide true positive or false positive.",
    "Scope: search for the same indicators on other hosts.",
]
HASH_RE = re.compile(r"(SHA256|SHA1|MD5|IMPHASH)=([0-9A-Fa-f]{16,64})")


def dig(obj, path, default=""):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def load_alerts(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def extract_hashes(hash_field):
    return {algo.upper(): value.lower() for algo, value in HASH_RE.findall(hash_field or "")}


def vt_lookup(sha256):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return "VT_API_KEY not set, lookup skipped"
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
        return "VirusTotal: {} malicious, {} suspicious, {} harmless".format(
            stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0))
    except urllib.error.HTTPError as err:
        return "VirusTotal: not found" if err.code == 404 else f"VirusTotal error: HTTP {err.code}"
    except (urllib.error.URLError, KeyError, ValueError) as err:
        return f"VirusTotal lookup failed: {err}"


def triage(alert, use_vt):
    rule = alert.get("rule", {})
    mitre_ids = dig(alert, "rule.mitre.id", []) or []
    tactics = dig(alert, "rule.mitre.tactic", []) or []
    ev = dig(alert, "data.win.eventdata", {}) or {}
    hashes = extract_hashes(ev.get("hashes", ""))

    lines = [f"## [level {rule.get('level', '?')}] {rule.get('description', 'no description')}"]
    lines.append(f"- **Host:** {dig(alert, 'agent.name', 'unknown')} ({dig(alert, 'agent.ip', 'no ip')})")
    lines.append(f"- **Time:** {alert.get('timestamp', 'unknown')}")
    lines.append(f"- **Rule id:** {rule.get('id', '?')}")
    lines.append("- **ATT&CK:** " + (", ".join(mitre_ids) or "none") + (f" ({', '.join(tactics)})" if tactics else ""))
    if ev.get("user"):
        lines.append(f"- **User:** {ev['user']}")
    if ev.get("image"):
        lines.append(f"- **Process:** `{ev['image']}`")
    if ev.get("parentImage"):
        lines.append(f"- **Parent:** `{ev['parentImage']}`")
    if ev.get("commandLine"):
        lines.append(f"- **Command line:** `{ev['commandLine']}`")
    if hashes:
        lines.append("- **Hashes:** " + ", ".join(f"{k}={v}" for k, v in sorted(hashes.items())))
        if use_vt and "SHA256" in hashes:
            lines.append(f"- **Reputation:** {vt_lookup(hashes['SHA256'])}")
    steps = []
    for tid in mitre_ids:
        steps.extend(NEXT_STEPS.get(tid, []))
    lines.append("")
    lines.append("**Suggested next steps**")
    for i, step in enumerate(steps or DEFAULT_STEPS, 1):
        lines.append(f"{i}. {step}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", help="Wazuh alert JSON / JSON Lines file")
    parser.add_argument("--min-level", type=int, default=0, help="skip alerts below this rule level")
    parser.add_argument("--vt", action="store_true", help="look up SHA256 hashes on VirusTotal")
    args = parser.parse_args()

    shown = 0
    for alert in load_alerts(args.file):
        if int(dig(alert, "rule.level", 0) or 0) < args.min_level:
            continue
        print(triage(alert, args.vt))
        print()
        shown += 1
    print(f"_{shown} alert(s) triaged_", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
