# php2shell — pre-auth RCE on WordPress / PHP 8.5.x (x86_64)

Full unauthenticated remote code execution against a stock WordPress site running
**PHP 8.5.x x86_64** under Apache prefork + mod_php, **with ASLR enabled**, via
CVE-2026-109618 / CVE-2026-109619 ("php2shell") — memory-safety bugs in PHP core's
RFC 1867 multipart path.

**Status.** Full RCE demonstrated against an authorized live target (PHP 8.5.11, every
stage on attempt 1, ~33 s) and reproduced in-lab on stock replicas of **every release in
the vulnerable series — 8.5.0 through 8.5.11** — RCE cycle 1 on all twelve, every stage
on attempt 1. Fixed in **8.5.12**. Every profile self-validates through stages 1–2 (leak
checks with build gates) before stage 3 can run, so a mismatched build fails safely instead
of firing blind. The chain is HTTP-only: no debugger, no `/proc`, no binary blobs.

**Contents:** [Quick start](#quick-start) · [Target requirements](#target-requirements) ·
[How it works](#how-it-works) · [DoS mode](#dos-mode-when-rce-is-unavailable) ·
[Evasion & detection](#evasion--detection) · [Porting to other versions](#porting-to-other-versions) ·
[Evidence](#evidence) · [Patch status](#patch-status--mitigations) · [Credits](#credits--prior-work)

## Quick start

```bash
git clone <this repo> && cd php2shell
python3 exploit.py -u http://<your-authorized-target>/index.php
```

Expected output on a matching target (~30 s):

```
[stage1] LEAK chunk base = 0x7f… (cluster n=…)        ← heap ASLR bypass
[stage2] LEAK libphp base = 0x7f… (dtor gate OK)      ← code ASLR bypass
[stage3] RCE CONFIRMED cycle 1: GET /p -> HTTP/1.1 200 OK body=b'uid=33(www-data)…'
=== FULL RCE CONFIRMED ===
```

| Flag | Meaning |
|---|---|
| `--stage 1` / `--stage 2` | run only the leak stages (validates offsets against your build without executing code) |
| `-c 'cmd'` | custom command; default `id>p`. ≤ 14 bytes uses the standard carrier; longer commands (up to ~305 chars) use an extended carrier with a marker write appended so success is provable black-box. No NUL bytes. On targets you've already run against, pick a fresh redirect path (`-c 'id>r'`) — proof verification checks that file |
| `--cycles N` | stage-3 retry budget (default 3; live runs needed 1) |
| `--version X.Y.Z` | pin a version profile instead of auto-detecting from `X-Powered-By` (needed when `exposed_php_version=Off`) |
| `--evasive` | randomize per-request fingerprints to break static/behavioral clustering — see [Evasion & detection](#evasion--detection) |
| `--dos` | DoS mode only (skip RCE): permanently wedge session file(s) via the encode-OOM flock leak — works even when RCE is unavailable, needs no version profile. See [DoS mode](#dos-mode-when-rce-is-unavailable) |
| `--saturate N` | after confirming a wedge, fire N additional probes to exhaust `MaxRequestWorkers` (full outage); 0 = off |
| `--no-dos` | disable the automatic DoS fallback when RCE is unavailable (stage-1 no-leak / unsupported version) |

`http://` and `https://` URLs both work — TLS is transparent to this chain (validated on an
Apache-native-TLS replica, both carrier types; cert verification off by default, SNI set). A
timestamped log is written to the current directory. There is deliberately no default target:
`-u` is required, and you should only point it at systems you are authorized to test.

## Target requirements

The chain is calibrated for one specific environment — all rows must match:

| Requirement | Why it matters |
|---|---|
| **PHP 8.5.x x86_64** (stock `php:8.5.x-apache` builds; every release validated to RCE) | libphp offsets are nm-derived per build and were gate-validated against each real build in the series sweep; a mismatched build fails at stage 2's dtor gate instead of firing blind |
| **`display_errors=On`** (or equivalent early output) | required for the leak channel — with `Off`, no leak and no RCE (DoS only). [Why](#why-display_errorson-is-required-and-why-off-is-not-a-mitigation) |
| **Apache prefork + mod_php** | RCE needs the OOM'd worker to survive and be reused; PHP-FPM exits it (DoS only) |
| **`memory_limit=128M`** (stock default) | arming size and pad calibration are tuned to this value; other values need re-calibration ([LESSONS_LEARNED.md](LESSONS_LEARNED.md)) |
| **`session.upload_progress.enabled=On`** (default) | the vulnerable handler |
| docroot writable by `www-data` (stock WP) | default proof writes `/p` into the docroot; otherwise use `-c 'id>/tmp/x'` + SSH read, or a callback |

WordPress was the demonstrated application stack, but the trigger fires in PHP core **before
any application code runs** — any mod_php app works. WordPress matters for two practical
reasons: its stock `.htaccess` serves existing files directly (so `GET /p` is a clean proof),
and its background activity (wp-cron, bots) is what the keep-alive targeting pins out.

## How it works

Three stages, each a `multipart/form-data` POST parsed by PHP core before application code runs:

1. **Heap ASLR bypass** — an OOM fatal during multipart parsing (a ~140 MB chunked upload
   exhausting the 128 M `memory_limit`) interrupts request setup with session state only
   partially initialized; a follow-up on the same connection makes PHP emit a forged
   `zend_string` in `Set-Cookie`, disclosing the Zend-MM heap base.
2. **Code ASLR bypass** — a second arming + a 56-byte HashTable overlap puts a libphp code
   pointer into `Set-Cookie`; its page-offset gate validates the leak against the expected
   build before anything proceeds.
3. **RCE** — the dangling `PS(http_session_vars)` reference is reclaimed with a forged
   array/`execute_data` frame whose destructor is `zif_system`; at request shutdown PHP
   calls it with the attacker's command.

### Defeating ASLR in-band

ASLR randomizes two things we need: where the Zend memory-manager arena lives, and where
`libphp.so` is mapped. Both are defeated **in-band** — the target discloses its own addresses
over HTTP, so no kernel-layout assumptions are needed:

- **Stage 1 → heap base.** The OOM arming interrupts request setup with the session-ID string
  freed but still referenced (`PS(id)` dangles). A crafted field in the follow-up overwrites
  that freed string's header — rewriting its length to `0x1000` and marking it valid — so when
  PHP emits `Set-Cookie: PHPSESSID=…`, it copies **4 KB of live heap** into the cookie. The
  leaked bytes contain many pointers; counting their 2 MB-aligned values (`v & ~0x1FFFFF`) and
  taking the densest cluster yields the arena base. Range filtering + clustering is what makes
  this kernel-independent: it works wherever ASLR put the heap.
- **Stage 2 → libphp base.** Arming with a different fill size shifts where the OOM lands, so
  that a specific HashTable allocation overlaps the dangling region; its `pDestructor` field is
  a **libphp code pointer** (`zval_ptr_dtor`) and rides out in the same cookie. The leak must
  pass a page-offset gate — `(ptr & 0xfff) == (DTOR & 0xfff)` against the expected build —
  before anything proceeds; a mismatched build fails here instead of firing blind, and a match
  gives `libphp_base = ptr − DTOR`.
- **One leak covers all workers.** Prefork children fork from the same parent, so every worker
  shares an identical address-space layout: bases leaked on any connection are valid for every
  worker — which is what lets stage 3 run on a different keep-alive-pinned worker.
- **Stage 3** then needs no further leaks: with both bases known it computes absolute addresses
  (`zif_system`, the carrier slot) and reclaims the dangling reference so request shutdown calls
  `system(cmd)` through the forged destructor. The reclaim alignment is what the `PADS`
  calibration fixes — see [LESSONS_LEARNED.md](LESSONS_LEARNED.md) for the slot-grid arithmetic.

Two engineering pieces make this reliable in the wild (details + calibration math in
[LESSONS_LEARNED.md](LESSONS_LEARNED.md)): **keep-alive arm→follow-up targeting** — each stage
opens one persistent connection, arms over it and sends its follow-up on the same socket;
prefork binds a keep-alive connection to a single child, so the armed worker is guaranteed to
process the exploit and stays busy for the whole cycle (wp-cron/bots cannot clear the armed
state mid-cycle); and **chunked-transfer arming** — `Transfer-Encoding: chunked` bypasses
`post_max_size` entirely and stops sending at the first response byte, keeping the post-OOM
connection in sync. Commands longer than 14 bytes use an extended carrier with its own
calibrated offset (`HTDATA_EXT`, measured with the LD_PRELOAD interposer in
[`tools/interposer/`](tools/interposer/)) plus a marker write so success stays provable black-box.

### Why `display_errors=On` is required — and why Off is not a mitigation

The leak channel depends on one state transition that only happens when PHP displays errors to
the client (verified against source and an Off-target replica):

- During arming, the `max_input_vars` overflow warning is emitted **before** the file part that
  initializes the session. With `display_errors=On`, that warning writes output mid-parse,
  sending response headers early; the session module's subsequent cookie send then fails
  ("headers already sent") and `php_session_reset_id()` returns on that failure **without
  clearing `PS(send_cookie)`**. That flag dangles into the next request — which is what lets the
  follow-up emit the forged 4 KB `Set-Cookie` (stages 1–2).
- With `display_errors=Off`, nothing can produce client-visible output in that window, so the
  arming request's own cookie sends successfully and clears the flag. The dangling state still
  survives (the UAF is fully present — verified on an Off-target replica), but no byte of it
  reaches the client: arming returns `HTTP/1.0 500` + `Connection: close`, and the follow-up
  gets a clean response with no `Set-Cookie`.

Consequences for triage (consistent with the advisory's "no complete mitigations" stance):

- **`display_errors=Off` is not a mitigation** — the dangling-state bug remains fully present;
  only this leak channel is closed. Patching is the only fix. Any per-directory
  `display_errors=On` reachable by the worker re-arms the full chain (multipart parsing happens
  during request startup, before script selection matters).
- **Off-target impact without a leak is still severe** — the same rfc1867 surface drives a
  pre-auth, display_errors-independent availability attack; see [DoS mode](#dos-mode-when-rce-is-unavailable)
  (the tool falls back to it automatically when RCE is unavailable).
- **Detection:** alert on `Set-Cookie: PHPSESSID=` values containing bytes outside the session-id
  alphabet (`[0-9a-f]` at default `sid_bits_per_character=4`) — a clean in-band signature of an
  active stage-1/2 attempt. Full guidance: [DETECTION.md](DETECTION.md).

## DoS mode (when RCE is unavailable)

`--dos` runs the availability attack described above instead of the RCE chain. It needs no
version profile and works regardless of `display_errors`; it also runs automatically when the
default flow can't get a stage-1 leak (e.g. `display_errors=Off`) or detects an unsupported
PHP version — pass `--no-dos` to keep the old fail-only behavior.

```bash
python3 exploit.py -u http://<authorized-target>/index.php --dos            # wedge 1 sid + confirm
python3 exploit.py -u ... --dos --saturate 200                             # full outage (exhaust workers)
```

How it works, in one paragraph: an rfc1867 upload whose `PHP_SESSION_UPLOAD_PROGRESS` value is
a ~4 MB string registers a session variable *named* after that string — so each request plants
one ~4.2 MB entry in the target's own session file (written mid-parse by PHP's progress-flush,
which also adopts your attacker-chosen `PHPSESSID`). After ~8 entries (~35 MB, stock
`memory_limit=128M`) the next request dies inside `php_session_encode()` with the session fd
still open and `flock(LOCK_EX)`-held; module shutdown is skipped on that path, so the lock is
orphaned — a later RINIT nulls the struct without closing the leaked fd, and PHP code can never
release it again. Every subsequent rfc1867 request to that sid blocks forever in `flock()`
(self-deadlock if the same worker, cross-process otherwise), permanently consuming one Apache
worker per request; parallel sids exhaust `MaxRequestWorkers` = full outage. Recovery requires
an Apache restart, and the attacker re-wedges a sid in ~30 s.

Operational notes:

- **Confirmation costs one worker.** Black-box confirmation is "a minimal rfc1867 probe to that
  sid hangs" — and that probe's worker stays consumed. `--probes N` adds more (each = one more
  dead worker); `--saturate N` fires N fire-and-forget probes round-robin across wedged sids
  and then polls `GET /` until the target stops responding.
- **Calibration.** The default arm count (`--dos-arms 9`) is calibrated for stock
  `memory_limit=128M`. Scale it proportionally for larger limits; if the confirmation probe
  responds normally, the tool tells you to raise it. Non-stock `post_max_size`/`session.save_path`
  setups may need tuning.
- **Impact is permanent until restart.** Treat this mode like any destructive test: authorized
  targets only, and expect to ask the operator for an Apache restart afterward (or let the
  secondary ZendMM-corruption failure mode kill orphan-holding workers one by one — slower).
- Detection signatures for defenders are in [DETECTION.md](DETECTION.md) (§3c).

## Evasion & detection

`--evasive` randomizes per-request fingerprints that honeypots/WAFs use to cluster this attack
family (fixed decoded-body hashes, absent User-Agent, repeated boundaries, consistent header
order): multipart boundary **content** at identical lengths, browser-like headers with rotating
order, UA-bearing preflight GETs, and the `PHPSESSID` field **value** in stage-1/2 follow-ups —
random content at a fixed length (the value is stored by PHP without validation and never becomes
the live session id, so only its *length* matters to the exploit). All of these are layout-neutral
— validated end-to-end in-lab and live (2026-10-26), including both carrier types on 8.5.3 and
8.5.11 with randomized SIDs. What it deliberately does **not** change: field names (numeric names
register as integer hash keys; stringifying them perturbs the calibrated heap pattern and kills
the leak), part counts/sizes, or anything structural.

Evasion cannot hide what the exploit *is*: a >`memory_limit` chunked multipart upload that OOMs
the worker, followed by an oversized `Set-Cookie`. Defenders: see [DETECTION.md](DETECTION.md) for
network, log and process-level signatures — including ones that work regardless of `--evasive`.

## Porting to other versions

| Piece | Depends on | How to get it |
|---|---|---|
| `ZIF` / `DTOR` offsets | the **build** (not even the version) | derive from the target binary: full `nm` on `libphp.so` (`zif_system` is a *local* symbol — `nm -D` misses it). The stage-2 dtor gate rejects a wrong build before any code runs |
| Stage 1–2 leaks | version + SAPI | **self-validating**: run them first against any candidate target; a clustered heap leak + gated libphp leak means the ASLR bypass works on that build |
| Stage-3 geometry (`HTDATA`, frame layout) | version (struct layouts) + config | decode from php-src at the exact tag with allocator ground truth (interposer). Status: **every release in the vulnerable series RCE-OK** (this repo, cycle 1); 8.4.26 RCE OK (@alvarodh5's chain) |
| Arming calibration (`PADS`) | `memory_limit` + arming shape | the dangling slot index must satisfy `k ≡ 6 mod 7`; pad count shifts `k` by a measured constant — scan once per target config (minutes), don't brute-force payloads |

**Worked data points.** Porting to **8.5.10** cost exactly two nm lookups: the php-src diff was
clean in everything that shapes this chain, offsets were re-derived from the replica's own
`libphp.so`, and with *unchanged* `HTDATA`/`PADS` both carriers RCE'd on cycle 1. Porting to
**8.5.9** added one twist: unrelated RINIT-time heap consumption shifted where the OOM lands by
one bin-3 slot, moving the dangling reference from k=76 (≡ 6, aligned) to **k=75 (≡ 5 —
geometrically dead)**; a two-pad bump (`PADS=114` → k=83 ≡ 6) fixed it with geometry unchanged.
So the honest net cost for an adjacent version is: **two nm lookups + one replica + a stage-3
smoke test** — and if that misses, one interposer measurement of `k mod 7` tells you exactly
which pad count to try. Versions further apart (8.4.x, 8.3.x) need the full diff-and-decode path;
the complete playbook is in [LESSONS_LEARNED.md](LESSONS_LEARNED.md).

## Evidence

[`evidence/`](evidence/) holds sanitized run logs (target IP redacted), indexed per-file in
[evidence/README.md](evidence/README.md). Highlights: the **live RCE** on the authorized 8.5.11
WordPress target (cycle 1, ~33 s) and a long-command extended-carrier run against it; an
**evasive-mode live run**; lab reproductions of **every release 8.5.0–8.5.11** (full-series sweep
plus the clean 8.5.3 re-run after this repo's cookie-decode fix); the **patched-build control** on
8.5.12 (no leak — the official fix closes it); and an **HTTPS/TLS validation**.

## Patch status & mitigations

Fixed in **8.5.12, 8.4.27, 8.3.36, 8.2.35** (plus EOL backports for 7.4/8.0/8.1), shipped
2026-10-21. The PHP security team: *"There are no complete mitigations, updating is the only
safe choice."* Partial stopgaps from the official advisory (none is complete; `ini_set()` /
`.user.ini` are too late — parsing precedes them): `memory_limit=-1` + low `post_max_size` for
CVE-2026-109618, `session.upload_progress.enabled=0` (and on 8.5, `fatal_error_backtraces=0`)
for CVE-2026-109619, or rejecting `multipart/form-data` at the proxy (breaks uploads).

One triage-relevant property: **`display_errors=Off` incidentally closes this chain's leak
channel** (leaving DoS-only impact) but is *not* a mitigation — see
[why](#why-display_errorson-is-required-and-why-off-is-not-a-mitigation).

## Credits & prior work

This chain builds directly on **@alvarodh5's** single-file, ASLR-bypassing RCE PoC for PHP 8.5.x
(MIT; the relevant code is inlined into `exploit.py` with attribution), which extends **@9bie's**
original pure-HTTP 8.4.26 chain and **@dinosn's** reclaim geometry; the underlying CVEs were
discovered by **Calif, OpenAI and Wiz**. Full credit — including context sources (VulnCheck,
CrowdStrike) and this project's development — is in [CREDITS.md](CREDITS.md).

## Disclaimer

For **lawful, authorized** security assessment, research and education only — run it against
systems you own or have explicit written permission to test. Each arming request OOMs a worker
(a brief per-request disruption); coordinate with the owner before running, prefer non-destructive
proof commands (`id>p`), and remove proof files afterwards unless the owner wants them kept.

## Sources

- [calif.io/php2shell](https://calif.io/php2shell/) — discoverers' write-up (Calif, OpenAI, Wiz)
- [PHP security advisory](https://www.php.net/archive/2026.php) — official, 21 Oct 2026
- @alvarodh5 — foundation single-file PoC (MIT); full attribution in [CREDITS.md](CREDITS.md)
- [VulnCheck analysis](https://www.vulncheck.com/blog/php2shell-vulnerabilities) · [CrowdStrike: obstacles to weaponizing php2shell](https://www.crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation/)
- [KillaBoi/StealMyBitcoin-PoC](https://github.com/KillaBoi/StealMyBitcoin-PoC) — independent live exploitation (PHP 8.4.26 cli-server, CTF); corroborates the `display_errors` requirement for the leak channel
