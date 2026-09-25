#!/usr/bin/env python3
"""Map Sigma rules to the attack plan and build an ATT&CK Navigator layer.

Usage:
  python tools/attack_coverage.py                                   # print coverage table
  python tools/attack_coverage.py --check                           # validate rules + plan (used by CI); exit 1 on problems
  python tools/attack_coverage.py --layer reports/attack-navigator-layer.json

Layer scores:  1 = a Sigma rule exists (written, not verified)
               2 = a plan step for the technique has status "detected" (verified in the lab)
"""
import argparse
import glob
import json
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "detections", "sigma")
PLAN_FILE = os.path.join(ROOT, "attack", "plan.yaml")
ATTACK_VERSION = "16"  # set to the ATT&CK version used by your Navigator instance
REQUIRED = ("title", "id", "status", "description", "tags", "logsource", "detection", "level")
LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("planned", "executed", "detected", "missed")
TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$")
CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all"}


def load_rules():
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        tags = data.get("tags") or []
        techniques = []
        for tag in tags:
            match = TAG.match(str(tag))
            if match:
                techniques.append(match.group(1).upper())
        rules.append({"file": os.path.basename(path), "data": data, "techniques": techniques})
    return rules


def load_steps():
    with open(PLAN_FILE, encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("steps", [])


def check(rules, steps):
    """Return a list of human-readable problems (empty list = OK)."""
    errors = []
    ids = {}
    by_file = {r["file"]: r for r in rules}

    for rule in rules:
        name, data = rule["file"], rule["data"]
        for key in REQUIRED:
            if key not in data:
                errors.append(f"{name}: missing required field '{key}'")
        if data.get("level") and data["level"] not in LEVELS:
            errors.append(f"{name}: invalid level '{data['level']}'")
        rid = str(data.get("id", ""))
        if rid in ids:
            errors.append(f"{name}: duplicate id, already used by {ids[rid]}")
        ids[rid] = name
        if not rule["techniques"]:
            errors.append(f"{name}: no attack.tNNNN technique tag")

        detection = data.get("detection") or {}
        condition = str(detection.get("condition", ""))
        if not condition:
            errors.append(f"{name}: detection has no condition")
        keys = [k for k in detection if k != "condition"]
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", condition):
            if token in CONDITION_KEYWORDS:
                continue
            if token.endswith("*"):
                if not any(k.startswith(token[:-1]) for k in keys):
                    errors.append(f"{name}: condition pattern '{token}' matches no selection")
            elif token not in keys:
                errors.append(f"{name}: condition references undefined selection '{token}'")

    step_ids = set()
    for step in steps:
        sid = step.get("id", "?")
        if sid in step_ids:
            errors.append(f"plan: duplicate step id {sid}")
        step_ids.add(sid)
        if step.get("status") not in STATUSES:
            errors.append(f"plan {sid}: status must be one of {STATUSES}")
        listed = step.get("rules") or []
        if not listed:
            errors.append(f"plan {sid}: no detection rule listed for {step.get('technique')}")
        for fname in listed:
            rule = by_file.get(fname)
            if rule is None:
                errors.append(f"plan {sid}: rule file not found: {fname}")
            elif step.get("technique") not in rule["techniques"]:
                errors.append(f"plan {sid}: {fname} is not tagged with {step.get('technique')}")
    return errors


def print_table(rules, steps):
    print(f"{'Step':<4} {'Technique':<10} {'Rules':<5} {'Status':<9} Name")
    print("-" * 78)
    for step in steps:
        print(f"{step['id']:<4} {step['technique']:<10} {len(step.get('rules') or []):<5} "
              f"{step.get('status', '?'):<9} {step['name']}")
    covered = {t for r in rules for t in r["techniques"]}
    detected = sum(1 for s in steps if s.get("status") == "detected")
    executed = sum(1 for s in steps if s.get("status") in ("executed", "detected", "missed"))
    print("-" * 78)
    print(f"Rules written: {len(rules)} | ATT&CK techniques with a rule: {len(covered)} | "
          f"Plan steps: {len(steps)} | Executed: {executed}/{len(steps)} | Verified detected: {detected}/{len(steps)}")


def build_layer(rules, steps):
    tech = {}
    for rule in rules:
        for t in rule["techniques"]:
            tech.setdefault(t, {"rules": set(), "status": set()})["rules"].add(rule["file"])
    for step in steps:
        tech.setdefault(step["technique"], {"rules": set(), "status": set()})["status"].add(step.get("status", "planned"))
    items = []
    for tid, info in sorted(tech.items()):
        if "detected" in info["status"]:
            score = 2
        elif info["rules"]:
            score = 1
        else:
            score = 0
        items.append({
            "techniqueID": tid,
            "score": score,
            "enabled": True,
            "comment": "rules: {} | lab: {}".format(
                ", ".join(sorted(info["rules"])) or "none",
                ", ".join(sorted(info["status"])) or "not in plan"),
        })
    return {
        "name": "Purple Team Detection Lab - detection coverage",
        "versions": {"attack": ATTACK_VERSION, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Score 1 = Sigma rule written. Score 2 = detection verified in the lab.",
        "sorting": 0,
        "hideDisabled": False,
        "techniques": items,
        "gradient": {"colors": ["#ffffff", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 2},
        "legendItems": [
            {"label": "Rule written, not yet verified in lab", "color": "#ffe766"},
            {"label": "Detection verified in lab", "color": "#8ec843"},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="validate rules and plan; exit 1 on problems")
    parser.add_argument("--layer", metavar="FILE", help="write an ATT&CK Navigator layer JSON to FILE")
    args = parser.parse_args()

    rules, steps = load_rules(), load_steps()
    errors = check(rules, steps)
    if args.check:
        for err in errors:
            print("ERROR:", err)
        print(f"checked {len(rules)} rules and {len(steps)} plan steps: "
              f"{'OK' if not errors else str(len(errors)) + ' problem(s)'}")
        return 1 if errors else 0

    print_table(rules, steps)
    if errors:
        print(f"\n{len(errors)} problem(s) found, run with --check for details", file=sys.stderr)
    if args.layer:
        out = args.layer if os.path.isabs(args.layer) else os.path.join(ROOT, args.layer)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(build_layer(rules, steps), fh, indent=2)
            fh.write("\n")
        print(f"layer written to {args.layer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
