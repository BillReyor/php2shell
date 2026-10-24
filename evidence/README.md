# Evidence — sanitized run logs

Target IP redacted (`<target>`); local paths redacted (`<repo>`). These are the raw
console/log output of `exploit.py` runs.

| File | What it shows |
|---|---|
| `live_run_20261024_121124.log` / `live_run_console.txt` | **The live RCE.** Full chain (stages 1→2→3) against an authorized WordPress target on PHP 8.5.11 x86_64, Apache prefork mod_php, stock config. Cycle 1, every stage attempt 1, ~33 s total: heap leak → libphp leak (dtor gate OK) → `RCE CONFIRMED` — `GET /p` returns `uid=33(www-data) gid=33(www-data) groups=33(www-data)` served by Apache. |
| `live_run_20261024_121636.log` | **Patched-build control.** Stage 1 of the same chain against PHP **8.5.12** (`php:8.5.12-apache-bookworm`): no leak on any attempt — the official patch closes this RCE (8.5.12 additionally aborts parsing at `max_input_vars` overflow before reaching the OOM field). |
| `live_run_20261024_150436.log` | **Long-command run on the same live target.** Extended carrier (`HTDATA_EXT`) with a 19-byte command plus marker wrapper: cycle 1, every stage attempt 1; `GET /pp` returns the marker and `GET /q` returned the command's own output (`uid=33(www-data)…` + `whoami`). Confirms the extended-carrier offset is stable across lab and live. |
| `lab_8510_rce.log` | **PHP 8.5.10 reproduction (lab).** Full chain against a stock WordPress replica on PHP 8.5.10 x86_64 (`php:8.5.10-apache`, amd64): version auto-detected from `X-Powered-By`, profile selected, cycle 1 — preflight shows `GET /p` → 404, post-exploit `GET /p` → 200 with `uid=33(www-data)`. Only the two per-build offsets differ from 8.5.11; carrier geometry and calibration carried over unchanged. Log is localhost-only by construction (no target IPs). |
