# Detecting php2shell (CVE-2026-109618 / CVE-2026-109619)

Detection engineering notes and ready-to-adapt rules for the PHP core
`session.upload_progress` / RFC1867 handler chain demonstrated in this repo.

> **Scope.** These detect *attempts* and *success*, not a specific PoC. The
> public exploits (`exploit/php2shell.py`, `alvaro/`, `ninebie/`) share fixed
> cosmetics — boundaries like `OOMBOUNDARY1867`, `User-Agent: php2shell-109618`,
> the `JACKALPOC` marker, SID prefixes. **Do not write production rules against
> those.** They are 100% attacker-controlled and catch the sample scripts and
> nothing a real operator ships. Every rule here anchors on something the
> attacker *cannot* freely change.

---

## Why this is more detectable than it looks

The bug lives in PHP core and fires during request-body parsing, before any app
code — bad for prevention, but it means the attack is forced through a narrow,
observable protocol shape and lands in predictable places. There are three
durable, high-fidelity anchors plus one catch-all:

1. **The upload-progress field name is mandatory and server-fixed.** The callback
   only engages when the multipart body contains a field named
   `session.upload_progress.name` (default `PHP_SESSION_UPLOAD_PROGRESS`). Against
   a default-config target the attacker cannot rename it. Presence of this field
   in a multipart POST is rare in normal traffic and is the best *attempt* anchor.
2. **The leak is forced to over-fill a cookie.** The in-band ASLR bypass
   exfiltrates heap/libphp pointers through an oversized `Set-Cookie: PHPSESSID=`
   value (hundreds–thousands of URL-encoded bytes vs. the normal 26/32 chars).
   Best *response-side* anchor; essentially an invariant of the disclosure.
3. **Session IDs become attacker-chosen form fields, not cookies.** Cookie-less
   SID injection sends `PHPSESSID` as a body part with no `Cookie` header —
   `use_only_cookies=On` does **not** prevent this.
4. **RCE ends in a worker-spawned shell.** Vector-independent and survives every
   in-band evasion below.

## Fidelity / telemetry map

| Signal | Layer | Rule | Fidelity | Evasion resistance |
|---|---|---|---|---|
| `name="PHP_SESSION_UPLOAD_PROGRESS"` in multipart body | WAF / req body | Suricata `2000001`, Sigma `upload_progress_injection` | High | High (ini-fixed) |
| Cookie-less `PHPSESSID` form field + progress field | WAF / req body | Suricata `2000002`, Sigma `upload_progress_injection` | High | High |
| Oversized `Set-Cookie: PHPSESSID=` | Net / resp headers | Suricata `2000005` | **Very high** | High |
| Nested empty-file flood (`files0[a][b]…`, `filename=""`) | WAF / req body | Suricata `2000003`, Sigma `upload_progress_injection` | Med-high | Med |
| Forged call record / `system\x00` in body | WAF / req body | Suricata `2000004`, YARA `forged_call_record` | Med | Med (build-specific) |
| `…exhausted… in Unknown on line 0` | PHP error log | Sigma `oom_unknown_line0` | Low-med | **Low** (see below) |
| `sess_*` with `upload_progress_` + `<?php` / exec | Host / FS | YARA `poisoned_session_file`, `session_webshell` | High | Med |
| PHP worker → shell/interpreter | EDR | Sigma `rce_webshell_spawn` | High | High (end-state) |

## Recommended minimum deployment

Three cheap rules cover attempt → leak → success and none relies on error output
being visible:

1. **Request:** Suricata `2000001` (+`2000002`) or the Sigma body rule — the
   mandatory progress field, ideally paired with cookie-less `PHPSESSID`.
2. **Response:** Suricata `2000005` — oversized `Set-Cookie: PHPSESSID=`.
3. **Host:** Sigma `rce_webshell_spawn` — PHP worker spawning a shell.

Add YARA `poisoned_session_file` as a scheduled sweep of `session.save_path` for
forensics/persistence.

## What NOT to rely on

**The OOM error-log line (`…exhausted… in Unknown on line 0`) is the weakest
signal, despite being the obvious one.** Three independent ways it fails:

- The official partial mitigation is `memory_limit=-1`, which removes the OOM
  entirely — no line is logged, and defenders may read its absence as "safe."
- `display_errors=0` plus a quiet OOM inside `php_session_send_cookie`
  (`headers_sent=0`) emits no warning at all — this repo's own research notes
  (`ninebie/DISPLAY_ERRORS_OFF.md`) exist specifically to prove the chain works
  without it.
- Legitimate memory exhaustion produces the identical string (noise).

Keep it only as a corroborating/forensic signal, never as a primary detector.

## Tuning & false positives

- **Legit upload-progress users.** Some apps use `session.upload_progress` for
  progress bars and will send the field. They almost never do so *cookie-less*
  and never with the nested empty-file flood — baseline the legitimate callers
  per endpoint and allowlist them; keep rules `2000002`/`2000003` (the compound
  conditions), not a bare field-name match, as the alerting rules.
- **Worker-spawns-shell.** PHP apps that legitimately shell out (imagemagick,
  deploy hooks, queue workers) will fire `rce_webshell_spawn`. Baseline command
  lines per host and allowlist.
- **Request-body rules need body capture.** Standard access logs don't have POST
  bodies. Feed ModSecurity audit logs, a body-logging WAF, or a Zeek/HTTP sensor.
  Raise Suricata `request-body-limit` to ≥16 KB (OOM bodies are ~100 KB+).
- **TLS.** Request/response rules need TLS interception or matching at a
  terminating proxy.

## Files

```
detections/
├── DETECTION.md                               # this file
├── suricata/
│   └── php2shell.rules                         # sids 2000001–2000005 (req + resp)
├── sigma/
│   ├── php2shell_upload_progress_injection.yml # request body (WAF/modsec pipeline)
│   ├── php2shell_oom_unknown_line0.yml         # PHP error log (corroborating only)
│   └── php2shell_rce_webshell_spawn.yml        # process_creation end-state
└── yara/
    └── php2shell_artifacts.yar                 # sess_ poison, webshell, forge, tooling
```

## Validation against this repo

Run the demonstrator against a lab target and confirm the rules fire:

```bash
# request-side anchors (progress field + cookie-less PHPSESSID)
python3 exploit/php2shell.py probe  --port 8080
# OOM producer (nested empty-file flood)
python3 exploit/php2shell.py calif  --port 8080 --parts 1000 --depth 3
# on-disk poison (scan session.save_path afterwards with the YARA rules)
python3 exploit/php2shell.py rce    --port 8080 --save-path ./sessions
```

For Suricata `2000005` (the leak) and the full forged-structure path, drive the
weaponized chains (`alvaro/exploit.py`, `ninebie/exploit.py`) against their
Apache/mod_php lab image — the demonstrator's `probe/fixate/rce` logic path does
not produce the oversized `Set-Cookie`.

## References

- https://calif.io/php2shell/ — discoverers' write-up (Calif, OpenAI, Wiz)
- https://www.php.net/archive/2026.php — official PHP advisory (2026-10-21)
- `../README.md` — attack mechanics and phase breakdown
- `../ninebie/DISPLAY_ERRORS_OFF.md` — why the OOM-log signal is unreliable
