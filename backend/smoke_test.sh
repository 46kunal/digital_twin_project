#!/usr/bin/env bash

set -euo pipefail



BASE="http://127.0.0.1:5000"



echo "1) Check Flask process (port 5000)"

if ss -ltnp | grep -q ':5000'; then

  echo "  OK: Something lllistening on 5000"

else

  echo "  WARN: Nothing listening on 5000. Start the server: python app.py or flask run"

fi



echo

echo "2) Basic health / root check (GET /)"

echo "curl -sS ${BASE}/ | head -n 10"

curl -sS "${BASE}/" || echo "  NOTE: root endpoint failed (may be normal). Try /api/summary"



echo

echo "3) API: /api/summary (expect JSON)"

echo "curl -sS ${BASE}/api/summary | python3 -m json.tool"

curl -sS "${BASE}/api/summary" | python3 -m json.tool || echo "  FAIL: /api/summary error"



echo

echo "4) API: /api/scans/recent (expect list)"

echo "curl -sS ${BASE}/api/scans/recent | python3 -m json.tool"

curl -sS "${BASE}/api/scans/recent" | python3 -m json.tool || echo "  FAIL: /api/scans/recent error"



echo

echo "5) API: /api/vulnerabilities/by-severity (expect grouped counts)"

echo "curl -sS ${BASE}/api/vulnerabilities/by-severity (expect grouped counts)"

echo "curl -sS ${BASE}/api/vulnerabilities/by-severity | python3 -m json.tool"

curl -sS "${BASE}/api/vulnnerabilities/by-severity" | python3 -m json.tool || echo "  FAIL: /api/vulnerabilities/by-severity error"



echo

echo "6) Start a quick safe scan (fast) against localhost (only if you trust scanner to run)"

read -p "Do you want to start a test scan against 127.0.0.1? (y/N) " RESP

if [[ "${RESP,,}" == "y" ]]; then

  echo "Posting /api/scan/start {target:127.0.0.1, mode: fast}"

  curl -sS -X POST "${BASE}/api/scan/start" -H "Content-Type: application/json" \

    -d '{"target":"127.0.0.1","mode":"fast"}' | python3 -m json.tool || echo "  FAIL: start scan request"

  echo "  Wait a few seconds then check /api/scans/recent"

  sleep 4

  curl -sS "${BASE}/api/scans/recent" | python3 -m json.tool

else

  echo "Skipping scan start"

fi



echo

echo "7) DB quick check (sqlite or POSTGRES) - prints counts (requires python and SQLAlchemy models import)"

python3 - <<'PY'

import os,sys

proj = os.getcwd()

sys.path.insert(0, proj)

try:

    from models import db, User, Scan, VM, Vulnerability

    from app import create_app

except Exception as e:

    print("Cannot import project models/app:", e)

    raise SystemExit(1)

app = create_app()

with app.app_context():

    # safe prints

    def safe_count(model):

        try:

            return model.query.count()

        except Exception as e:

            return f"ERROR: {e}"

    print("Users:", safe_count(User))

    print("Scans:", safe_count(Scan))

    print("VMs:", safe_count(VM))

    print("Vulnerabilities:", safe_count(Vulnerability))

PY



echo

echo "8) Check recent scan raw_output saved (if any)."

curl -sS "${BASE}/api/scans" | python3 -m json.tool || echo "  /api/scans listing may be different in your app"

echo

echo "SMOKE TEST COMPLETE"
