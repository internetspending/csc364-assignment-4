#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CPE-321 Hash Lab — one-command runner
#
# Usage:
#   ./run.sh            → install deps, run task1, then crack wf<=8 users
#   ./run.sh task1      → only run task1 (SHA256 + collision graphs)
#   ./run.sh task2      → crack ALL users (warning: hours for high workfactors)
#   ./run.sh fast       → crack only workfactor <=8 users (Bilbo/Gandalf/Thorin)
#   ./run.sh demo       → task1 + fast crack (good for a live demo)
# ─────────────────────────────────────────────────────────────────────────────
set -e

MODE="${1:-demo}"

echo "============================================================"
echo " CPE-321 Hash Lab"
echo " Mode: $MODE"
echo "============================================================"

# ── 1. Install dependencies ───────────────────────────────────────────────────
echo ""
echo "[setup] Installing Python dependencies..."
pip install --quiet bcrypt nltk matplotlib
python -c "import nltk; nltk.download('words', quiet=True)"
echo "[setup] Done."

# ── 2. Run tasks based on mode ────────────────────────────────────────────────

case "$MODE" in

  task1)
    echo ""
    echo "[task1] Running SHA256 exploration + collision graphs..."
    python task1.py
    ;;

  task2)
    echo ""
    echo "[task2] Cracking ALL users (this will take many hours for wf>=11)..."
    python task2.py
    ;;

  fast)
    echo ""
    echo "[task2-fast] Cracking workfactor<=8 users only (Bilbo, Gandalf, Thorin)..."
    python task2.py --wf-max 8
    ;;

  demo)
    echo ""
    echo "[task1] Running SHA256 exploration..."
    python task1.py

    echo ""
    echo "[task2] Cracking workfactor<=8 users for demo (Bilbo, Gandalf, Thorin)..."
    python task2.py --wf-max 8
    ;;

  *)
    echo "Unknown mode: $MODE"
    echo "Valid modes: task1 | task2 | fast | demo"
    exit 1
    ;;

esac

echo ""
echo "============================================================"
echo " Done!"
echo "============================================================"
