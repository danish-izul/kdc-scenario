#!/usr/bin/env bash
# e2e.sh - non-interactive end-to-end run on localhost.
# Starts the KDC and Bob in the background, runs Alice with piped input,
# then checks the logs. Usage: scripts/e2e.sh [-v|-vv]
set -u
cd "$(dirname "$0")/.."
V="${1:-}"
LOG=build/e2e
mkdir -p "$LOG"
KPORT=15000 BPORT=16000

# KDC registers alice and bob; Bob uses the same passphrase as the KDC has for him.
(printf 'alice-secret\nbob-secret\n'; sleep 30) | ./build/kdc $V --no-color --port $KPORT > "$LOG/kdc.log" 2>&1 &
KDC=$!
(printf 'bob-secret\n'; sleep 2.5; printf 'Hi Alice, Bob here.\n'; sleep 30) |
    ./build/bob $V --no-color --port $BPORT > "$LOG/bob.log" 2>&1 &
BOB=$!
sleep 0.5

(printf 'alice-secret\n'; sleep 1.5; printf 'Hello Bob, this is Alice!\n'; sleep 2.5; printf '/quit\n') |
    ./build/alice $V --no-color --kdc 127.0.0.1:$KPORT --bob 127.0.0.1:$BPORT > "$LOG/alice.log" 2>&1
ALICE_RC=$?
sleep 0.5
kill $KDC $BOB 2>/dev/null; wait 2>/dev/null

fail=0
expect() {   # expect <log> <pattern> <description>
    if grep -q -- "$2" "$LOG/$1.log"; then echo "  [ OK ] $3"; else echo "  [FAIL] $3"; fail=1; fi
}
echo "alice exit code: $ALICE_RC"
expect kdc   "FLOW 2 : KDC -> A"                   "KDC answered flow 1 with flow 2"
expect alice "N1 matches"                          "Alice verified N1 in flow 2"
expect bob   "decrypted with K_B"                  "Bob decrypted the ticket (flow 3)"
expect alice "accepted f(N2)"                      "Alice got Bob's OK after flow 5"
expect bob   "f(N2) = N2 - 1 is correct"           "Bob verified flow 5"
expect bob   "alice says: Hello Bob, this is Alice!" "Bob decrypted Alice's chat message"
expect alice "bob says: Hi Alice, Bob here."       "Alice decrypted Bob's chat message"
expect bob   "alice ended the chat"                "Bob saw /quit"
if grep -q "\[FAIL\]" "$LOG"/*.log; then echo "  [FAIL] a party logged an error:"; grep -h "\[FAIL\]" "$LOG"/*.log; fail=1; fi
echo "logs: $LOG/{kdc,bob,alice}.log"
exit $fail