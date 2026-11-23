# 03 - Ransomware Detection System

A safe, educational ransomware-behaviour detector in pure Python (standard library only). It scans a local demo folder, flags files that look encrypted or renamed by ransomware, and checks file contents against a small YARA-style rule file.

**Safety note, read first:** this project contains no malware, no payloads, no encryption code, and no live attack code. The "ransomware-like" files in `demo_files/` are plain text files renamed to `.locked` with high-entropy filler text, created only so the detector has something safe to find. Never point this tool at real user data without a backup, and never run it with write/delete permissions.

## What it does

- Baselines a folder (file list, sizes, hashes, extensions), then compares a later snapshot
- Flags: mass extension changes to an unknown extension, high-entropy files, a ransom-note filename, and a sudden jump in changed files
- Runs YARA-style string rules from `rules/demo.yar` (plain-text pattern matching, no YARA binary needed)
- Writes `out/report.json` with a risk score and a per-file verdict

## How to run

```bash
cd 03-ransomware-detection-system
python3 src/ransomware_detector.py --scan demo_files --rules rules/demo.yar --out out/report.json
```

Expected output: 3 suspicious files flagged, including `report.docx.locked` and `ransom-note.txt`, risk score High. The 2 normal files pass clean.

## Files

- `src/ransomware_detector.py` - entropy, extension-change, and rule matching
- `rules/demo.yar` - 2 demo YARA-style rules (ransom note text, suspicious extension)
- `demo_files/` - 5 safe demo files: 2 normal, 3 ransomware-like
- `docs/architecture.md` - architecture, detection logic, and limits
- `requirements.txt` - standard library only

## What an employer sees

Behaviour-based detection, not signature-only: entropy, file-change velocity, and content rules, with a clear risk score and an honest list of limits. The next step is adding a baseline snapshot mode that alerts on change over time.
