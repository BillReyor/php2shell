# php2shell — quick demonstrator

Runnable demo of the **php2shell** attack surface: CVE-2026-109618 / CVE-2026-109619,
the two critical pre-auth RCE vulnerabilities in PHP core's session upload-progress
handler (`php_session_rfc1867_callback`, `ext/session/session.c`), disclosed 2026-10-21.

```
./run.sh              lab config: probe, fixate, RCE (any SAPI)
./run.sh --stock      stock PHP defaults: probe + abort persistence
./run.sh --calif      the official calif.io chain: OOM fatal -> stale session state
./run.sh --uaf        best-effort heap-UAF RCE (the eness PoC)
./run.sh --keep       keep sessions/ for inspection
```

Needs PHP (any 5.4+; tested on Homebrew 8.5.11) or Docker, plus Python 3 (stdlib only).

## What php2shell is

The discoverers' write-up ([calif.io/php2shell](https://calif.io/php2shell/), by Calif,
OpenAI and Wiz) describes two **OOM-fatal-triggered** bugs, both confirmed by the
[PHP security team](https://www.php.net/archive/2026.php) (CVSS v4.0 9.2):

| CVE | Official name | Mechanism | SAPI profile |
|---|---|---|---|
| **109618** | RCE via OOM corruption | An allocation exceeding `memory_limit` (or another fatal) interrupts PHP while request data is only partially initialized; request cleanup then treats the invalid data as valid (initial finding in `_zend_hash_str_add_or_update_i`) | RCE on **Apache mod_php** (PHP ≥ 5.4.0/7.3); PHP-FPM worker exits (DoS) |
| **109619** | RCE via stale global state | A startup fatal (OOM during multipart parsing) skips the session cleanup + RSHUTDOWN; the worker survives with dangling `PS(id)` / `PS(http_session_vars)`. A **later** file-less upload-progress request consumes the stale state | RCE on mod_php (PHP ≥ 5.4.0); FPM worker exits on startup fatal, but a decode-interruption variant (OOM during `session_start()`/`unserialize()`) gives app-dependent RCE on FPM |

The OOM is produced remotely with a multipart request that stays under
`post_max_size`: **nested empty file parts** (`files[a][b][c]…`, `filename=""`) —
each expands into six separate nested `$_FILES` hierarchies, so enough of them
exhaust `memory_limit` during parsing. The discoverers confirmed pre-auth RCE on
WordPress, Drupal, Joomla, MediaWiki, Roundcube, Magento, phpMyAdmin, Nextcloud,
**Laravel 13.11**, Symfony 8.1 and WHMCS.

The same handler also carries **normal-flow logic bugs** (no OOM needed) that this
demo exercises: cookie-less session-ID injection, attacker-controlled session
content, orphaned persistence, and end-to-end session fixation — verified by
independent research (19h) on stock builds, exploitable under default config on
**any SAPI**.

## What each phase demonstrates

| Phase | Bug | Mechanism | You will see |
|---|---|---|---|
| `probe` (P1+P2) | handler logic | multipart POST, **no Cookie**: attacker-chosen `PHPSESSID` field + progress marker create a session with attacker-controlled content, pre-auth | the injected `upload_progress_*` key in the victim app's session inspector |
| `fixate` (P4) | handler logic | plant a session under an attacker-chosen ID → victim "logs in" with it → attacker reads back | the victim's `user`/`role`/`api_key` in a session the attacker chose |
| `rce` (R) | handler logic + app LFI | poison a session file at the deterministic path `<save_path>/sess_<sid>` (payload in an upload filename, persisted via parse-bail) → app includes it | `uid=…` output from the included session file — **pre-auth RCE** |
| `abort` (P3, stock) | handler logic | same poison, but the client dies mid-upload so `MULTIPART_EVENT_END` cleanup never fires | orphaned poisoned entry surviving a dead request (works with stock `max_multipart_body_parts`) |
| `calif` (109618/19) | **the official chain** | request A: 1000 nested empty file parts → OOM fatal during parsing (worker survives with dangling session globals); request B: progress field, no file → cleanup reads the stale state | `Allowed memory size … exhausted … in Unknown on line 0`; worker survival; consumption effect is allocator-dependent (RCE on mod_php per calif) |
| `uaf` (bonus) | eness PoC variant | single-request heap UAF: 149-part spray reclaims a freed progress block, forged `zend_call_function` call | command output in the response — build/allocator sensitive, needs a leaked `zval_ptr_dtor` |

## The official chain in detail (`--calif`)

```
Request A (OOM producer)                 Request B (stale-state consumption)
─────────────────────────────            ────────────────────────────────────
multipart POST                           multipart POST
├ PHPSESSID = <sid>                      ├ PHPSESSID = <sid>
├ PHP_SESSION_UPLOAD_PROGRESS = zed      └ PHP_SESSION_UPLOAD_PROGRESS = zed
└ 1000 × filesN[a][b] filename=""        (NO file part)
   → six nested $_FILES hierarchies each
   → heap exhausts memory_limit DURING      → no FILE_START (no php_rinit_session reset)
     parsing → fatal before module          → MULTIPART_EVENT_END cleanup calls
     activation                             php_session_initialize() on the DANGLING
   → early session init already ran         PS(id) / PS(http_session_vars)
     (FILE_START: php_rinit_session(0),
      PS(id)=copy of the field)
   → END cleanup + session RSHUTDOWN skipped
     (modules_activated = false)
   → request heap freed; worker survives
     with dangling session globals
```

SAPI outcomes (per calif.io): **mod_php** reuses the worker → RCE against
arbitrary PHP scripts (PHP ≥ 5.4.0). **PHP-FPM** exits the worker on a startup
fatal (`FPM_EXIT_SOFTWARE`) → DoS; its RCE variant needs an OOM *during script
execution* that interrupts a reachable decode (`session_start()`, `unserialize()`).
On `php -S` (this demo) the single process survives, so request B's effect is
allocator-dependent — crash or silent.

The demo server runs with `memory_limit=8M` for speed (1000 parts × depth 3
exhausts it in ~100 KB of HTTP body). Against the default **128M** limit the same
shape works with deeper nesting (≈ depth 50) — still well under `post_max_size`.
Note PHP 8.5's default `max_multipart_body_parts=1020` caps the part count; the
producer is tuned to OOM *before* that cap.

## Pointing it at your own app

```bash
python3 exploit/php2shell.py probe  --host app.example.com --port 443
python3 exploit/php2shell.py rce    --host app.example.com --port 80 \
    --save-path /var/lib/php/sessions --payload 'system("id"); //'
python3 exploit/php2shell.py calif  --host app.example.com --port 80 \
    --parts 1000 --depth 50        # against a default 128M memory_limit
```

The victim app (`app/`) is deliberately ordinary: stock `session_start()`, a
login that stamps identity, an LFI sink (`lfi_sink.php` — the common dynamic-
include pattern), and a bare endpoint (`naked.php`) proving the trigger fires in
PHP core before any application code runs.

## Mitigations & patch status (as of 2026-10-21)

**Patch.** Fixed releases shipped today: **8.5.12, 8.4.27, 8.3.36, 8.2.35**, plus
source-backport branches for EOL **7.4 / 8.0 / 8.1**. The PHP security team:
*"There are no complete mitigations, updating is the only safe choice."*

Temporary partial mitigations (from calif.io / PHP advisory):
- **PHP-FPM:** `session.upload_progress.enabled=0` + `memory_limit=-1`
  (php.ini / FPM pool — must apply before request parsing; `ini_set()`/`.user.ini`
  won't do). Blocks the confirmed session paths, not other variants.
- **mod_php:** `memory_limit=-1` (removes the OOM trigger; raises exhaustion risk).
- On PHP 8.5: `fatal_error_backtraces=0`.

Detection (in-band): `PHP Warning/Fatal: … in Unknown on line 0` in error logs;
on disk: orphaned `sess_*` files containing `upload_progress_`; process-wise:
shells/interpreters spawned by PHP workers.

## Caveats

- The `calif` phase reproduces the official *setup + consumption*; whether that
  becomes RCE depends on SAPI (mod_php) and allocator layout. On `php -S` expect
  the OOM + worker survival; request B may be silent.
- The `uaf` phase (eness PoC) is a third, un-CVE'd variant of the handler —
  independent research (19h) found it not exploitable on stock builds; treat as
  best-effort. It needs a leaked `zval_ptr_dtor` (`run.sh --uaf` auto-detects via
  lldb/gdb when possible).
- Lab ini (`ini/zz-lab.ini`) uses 19h's verified settings (parts=4, min_freq=0,
  cleanup=0) to make the logic chain easy to observe; `--stock` and the calif
  server use stock settings.

## Sources

- [calif.io/php2shell](https://calif.io/php2shell/) — discoverers' write-up (Calif, OpenAI, Wiz)
- [PHP security advisory](https://www.php.net/archive/2026.php) — official, 21 Oct 2026
- [eness PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) — heap-UAF variant + WAF rules
- [19h verified exploit report](https://github.com/19h/CVE-2026-109618) — handler logic primitives P1–P5
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq) · [Huntress rapid response](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
