#!/usr/bin/env python3
"""Parse every rule in detections/sigma with the official pySigma parser. Exit 1 on any error."""
import glob
import os
import sys

from sigma.collection import SigmaCollection

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    failed = 0
    paths = sorted(glob.glob(os.path.join(ROOT, "detections", "sigma", "*.yml")))
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            collection = SigmaCollection.from_yaml(fh.read())
        if collection.errors:
            failed += 1
            for err in collection.errors:
                print(f"ERROR {os.path.basename(path)}: {err}")
    print(f"pySigma parsed {len(paths)} rule file(s): {'OK' if not failed else str(failed) + ' with errors'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
