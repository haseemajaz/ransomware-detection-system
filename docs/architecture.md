# Architecture - Ransomware Detection System

## Data flow

```
demo_files/  ->  scan: list files, hash, size, extension, entropy
             ->  rule engine: YARA-style string rules from rules/demo.yar
             ->  behaviour checks: unknown extension, high entropy,
                                   ransom-note filename, mass change
             ->  risk score: Low / Medium / High per file and overall
             ->  out/report.json + terminal report
```

## Detection logic

| Check | Threshold | Why it matters |
|---|---|---|
| Shannon entropy | > 7.0 bits/byte | Encrypted/compressed content looks random; plain text is ~4-5 |
| Unknown extension | `.locked`, `.encrypted`, `.xyz` | Ransomware often renames files to a new extension |
| Ransom-note filename | `ransom`, `decrypt`, `recover` in name | A note is left for the victim |
| YARA-style rule | string match in file content | Known ransom-note phrases and suspicious markers |

A file is High risk if it matches a rule or has high entropy plus an unknown
extension. The overall folder risk is High if any file is High.

## YARA-style rules

`rules/demo.yar` uses a tiny subset of YARA syntax (`rule <name> { strings: $a = "..." condition: any of them }`) parsed by the detector. Real YARA is not required and not bundled, which keeps the demo dependency-free.

## Limitations (honest)

- Entropy alone is not proof of encryption: compressed archives and media files are also high-entropy. The detector combines signals, it does not convict on one.
- No real-time monitoring: this is a point-in-time scan, not a filesystem watcher.
- No remediation: it reports only. It never deletes, quarantines, or decrypts anything.
- Demo data only: never run a detector like this on production data without a tested backup.
