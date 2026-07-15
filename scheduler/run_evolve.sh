#!/usr/bin/env bash
# CyberSentinel Evolver — weekly evolution loop
# Runs: scenarios → tournament → gap-analysis → evolve (auto-promote)
# Logs to /var/log/cs-evolver.log
set -euo pipefail

EVOLVER_DIR="/home/dtfrost/cybersentinel-evolver"
DB="${EVOLVER_DIR}/data.db"
LOG="/var/log/cs-evolver.log"
VENV_ACTIV="${EVOLVER_DIR}/../~hermes-venv/bin/activate"

echo "=== $(date -u '+%Y-%m-%d %H:%M:%S UTC') evolution cycle start ===" >> "$LOG"

# Activate the venv that has the cybersentinel-evolver package installed
# shellcheck disable=SC1091
source "$VENV_ACTIV"

cd "$EVOLVER_DIR"

# 1. Generate fresh scenarios from threat feeds
echo "[1/5] Generating scenarios..." >> "$LOG"
python -m cybersentinel_evolver.cli --db "$DB" scenarios >> "$LOG" 2>&1

# 2. Run tournament between all detectors
echo "[2/5] Running tournament..." >> "$LOG"
python -m cybersentinel_evolver.cli --db "$DB" tournament \
  --detectors rule_based,behavioral,random >> "$LOG" 2>&1

# 3. Identify escaped mutations via gap analysis
echo "[3/5] Running gap analysis..." >> "$LOG"
python -m cybersentinel_evolver.cli --db "$DB" gap-analysis \
  --type mutations >> "$LOG" 2>&1

# 4. Evolve — mutate survivors + re-run tournament for one week
echo "[4/5] Evolving..." >> "$LOG"
python -m cybersentinel_evolver.cli --db "$DB" evolve --weeks 1 >> "$LOG" 2>&1

# 5. Auto-promote winner
echo "[5/5] Promoting winner..." >> "$LOG"
python -m cybersentinel_evolver.cli --db "$DB" evolve --weeks 1 \
  --auto-promote >> "$LOG" 2>&1

echo "=== $(date -u '+%Y-%m-%d %H:%M:%S UTC') evolution cycle complete ===" >> "$LOG"
