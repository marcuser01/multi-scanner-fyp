#!/bin/bash
set -e

echo "[Riskwise] Bootstrapping Environment..."

# 1. Initialize SQLite Database Tables
python -c "from app.core.database import init_db; init_db()"

# 2. Seed ChromaDB Knowledge Base (Only adds docs if they don't exist)
if [ -f "scripts/seed_kb.py" ]; then
    echo "[Riskwise] Verifying Knowledge Base..."
    python scripts/seed_kb.py
fi

echo "[Riskwise] Starting FastAPI Server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000