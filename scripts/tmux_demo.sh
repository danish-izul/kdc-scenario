#!/usr/bin/env bash
# tmux_demo.sh - rehearse the demo on one machine: KDC, Bob and Alice in three panes.
# Usage: scripts/tmux_demo.sh [-v|-vv] [--step]
set -eu
cd "$(dirname "$0")/.."
make -s
ARGS="$*"
S=ns-demo
tmux kill-session -t "$S" 2>/dev/null || true
tmux new-session -d -s "$S" -n demo "./build/kdc $ARGS; read"
tmux split-window -h -t "$S" "./build/bob $ARGS; read"
tmux split-window -v -t "$S" "./build/alice $ARGS --kdc 127.0.0.1:5000 --bob 127.0.0.1:6000; read"
tmux select-layout -t "$S" tiled
tmux attach -t "$S"
