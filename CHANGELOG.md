# 0.1.0 — 2026-10-08

first release.

- timeline: filesystem chronology in mactime body format, plus json/csv,
  time bounds and an optional md5 column
- hash: parallel sha256/md5 digests, sha256sum-compatible output,
  known-bad matching against a hash list (exit 3 on hit)
- strings: ascii + utf-16le extraction with min length and size caps
- hunt: 14-rule ransomware IOC pack over names, paths and content,
  custom json rules, severity-ranked output
- sweep: live-response artifact collection (histories, cron, persistence,
  temp dirs, modules, logs) with sha256 manifest
