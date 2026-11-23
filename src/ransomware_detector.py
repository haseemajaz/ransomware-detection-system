#!/usr/bin/env python3
"""Ransomware Detection System - safe educational demo.

Scans a local folder for ransomware-like behaviour: high entropy,
unknown extensions, ransom-note text, and YARA-style string rules.
Reads files only; never deletes, encrypts, or modifies anything.
Standard library only.
"""
import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
SUSPICIOUS_EXTS = {".locked", ".encrypted", ".xyz", ".crypt", ".ransom"}
NOTE_WORDS = ("ransom", "decrypt", "recover", "bitcoin")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())


def parse_yar(path):
    """Parse a tiny YARA-style subset: rule NAME { strings: $a = "..." condition: any of them }"""
    rules = []
    text = open(path, encoding="utf-8").read()
    for m in re.finditer(r"rule\s+(\w+)\s*\{(.*?)\}", text, re.S):
        strings = re.findall(r'\$\w+\s*=\s*"([^"]+)"', m.group(2))
        if strings:
            rules.append({"name": m.group(1), "strings": strings})
    return rules


def scan_file(path, rules):
    data = open(path, "rb").read()
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    reasons, matched = [], []
    ent = entropy(data)
    if ent > 7.0:
        reasons.append(f"high entropy {ent:.2f} bits/byte")
    if ext in SUSPICIOUS_EXTS:
        reasons.append(f"suspicious extension {ext}")
    if any(w in name.lower() for w in NOTE_WORDS):
        reasons.append("ransom-note-like filename")
    for rule in rules:
        hits = [s for s in rule["strings"] if s in text]
        if hits:
            matched.append(rule["name"])
            reasons.append(f"matched rule {rule['name']}: {hits[0][:40]}")
    risk = "High" if matched or (ent > 7.0 and ext in SUSPICIOUS_EXTS) else "Medium" if reasons else "Low"
    return {"file": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16],
            "entropy": round(ent, 2), "extension": ext, "risk": risk,
            "matched_rules": matched, "reasons": reasons}


def main():
    p = argparse.ArgumentParser(description="Ransomware Detection System (safe demo)")
    p.add_argument("--scan", default=os.path.join(HERE, "..", "demo_files"))
    p.add_argument("--rules", default=os.path.join(HERE, "..", "rules", "demo.yar"))
    p.add_argument("--out", default=os.path.join(HERE, "..", "out", "report.json"))
    args = p.parse_args()

    rules = parse_yar(args.rules)
    results = []
    for name in sorted(os.listdir(args.scan)):
        path = os.path.join(args.scan, name)
        if os.path.isfile(path):
            results.append(scan_file(path, rules))

    high = sum(1 for r in results if r["risk"] == "High")
    overall = "High" if high else "Medium" if any(r["risk"] == "Medium" for r in results) else "Low"
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"scanned": len(results), "high_risk": high, "overall_risk": overall, "files": results}, f, indent=2)

    print(f"Files scanned: {len(results)}  Overall risk: {overall}")
    for r in results:
        print(f" [{r['risk']:6}] {r['file']:24} entropy={r['entropy']}  {'; '.join(r['reasons']) or 'clean'}")
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
