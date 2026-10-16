#!/usr/bin/env bash
# Runs the Paper D held out injections and output audit once the Paper C ablation has finished,
# so that the two model runs never compete for the two cores or the memory.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
log(){ echo "[$(date +%H:%M:%S)] $*"; }
log "waiting for the Paper C ablation"
while ! grep -q "STATIC ABLATION DONE" /home/claude/ss/C/results/static_ablation.log 2>/dev/null; do sleep 30; done
log "held out run start"
cd "$HERE" && python3 -u run_heldout.py --model /home/claude/models/phi4mini-Q4_K_M.gguf --n-classify 50 --n-explain 30 --n-audit 10 --threads 2
log "HELDOUT DONE"
