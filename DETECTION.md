# Detecting php2shell exploitation attempts (CVE-2026-109618 / CVE-2026-109619)

Defensive companion to this repository. The exploit chain here is HTTP-only and leaves
multiple independent traces; no single signal is required — the signatures below are
layered so that **any one layer catches an attempt even when the others are evaded**.
Everything in this document was verified against source (PHP 8.5.11) and lab replicas of
the target build, including runs with `--evasive` enabled.

## TL;DR for defenders

1. **Patch.** Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (shipped 2026-10-21). The PHP
   security team states there are no complete mitigations; `display_errors=Off` closes this
   chain's leak channel but is *not* a mitigation (the dangling-state bug remains, DoS-only
   residual).
2. **If you cannot patch immediately**, the two strongest signals — both immune to
   `--evasive` — are:
   - an oversized / non-alphabetic `Set-Cookie: PHPSESSID=` in responses (§1.2), and
   - a pre-script OOM fatal (`…exhausted… in Unknown on line 0`) correlated with session
     warnings from the same worker within seconds (§2).
3. **For RCE confirmation**, watch for an Apache child spawning `/bin/sh` (§3) — that is
   `system()` firing, and it cannot be hidden by any HTTP-layer evasion.

## Threat model & what is detectable

The attack is three multipart POSTs per stage (arming → follow-up), all pre-auth, all
parsed in PHP core before application code runs. The arming upload **must** exceed
`memory_limit` to trigger the OOM — that size requirement is structural and cannot be
shrunk without re-engineering the whole chain. A successful leak **must** emit an oversized
`Set-Cookie`. Evasion (`--evasive`) only randomizes cosmetic per-request fingerprints; it
cannot touch these two facts, the server-side log trail, or process-level effects. TLS
transport changes none of this for a defender with visibility into decrypted traffic
(reverse proxy, eBPF on socket buffers) — it only raises the bar against passive network
capture.

## 1. Network-layer signatures

### 1.1 The arming request (works with or without `--evasive`)

A single request matching **all** of the following is a near-certain php2shell attempt:

- `POST` to a PHP page, `Content-Type: multipart/form-data`,
  `Transfer-Encoding: chunked`;
- body size **> `memory_limit`** (stock: >128 MB) — legitimate web uploads rarely exceed
  this on a stock-config site;
- the multipart contains both `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` fields. These
  names are structural: the vulnerable handler (`php_session_rfc1867_update`) only fires for
  them, so every working variant of this attack family must include them. They cannot be
  renamed without breaking the exploit;
- hundreds to thousands of small filler parts with **sequential numeric names** (e.g.
  `f0000`–`f1000`, `a0000[0]…`). `--evasive` deliberately does not randomize field names —
  doing so changes PHP's internal allocation pattern and kills the exploit (§1.3).

Expected response distinguishes target class:

- **On-target** (`display_errors=On`): `HTTP/1.1 200` whose body contains the OOM fatal
  text (the error is displayed to the client);
- **Off-target**: `HTTP/1.0 500` + `Connection: close`, empty body, a *normal* session
  cookie — the worker OOM'd but nothing leaks.

### 1.2 The leak / follow-up request (the in-band proof of an active attempt)

Immediately after arming (sub-second to seconds), on the **same connection**, the attacker's
follow-up receives `Set-Cookie: PHPSESSID=<value>` where `<value>` is a URL-encoded dump of
~4 KB of live heap. Detect it at egress (reverse proxy / WAF response inspection):

- length far beyond a real session id (default sid = 32 hex chars; the leak is thousands of
  characters), and/or
- any character outside `[0-9a-f]` — with `sid_bits_per_character=4` a legitimate value is
  pure lowercase hex. The leaked heap contains NULs, high-bit bytes and pointers, so the
  wire value will contain percent-escapes (`%XX`) or other non-hex characters.

This signature is **immune to `--evasive`**: if the exploit works at all, PHP itself emits
the oversized cookie; the attacker cannot suppress it without breaking the chain. It also
catches attempts against *any* public PoC variant of this family, not just this tool.

### 1.3 What `--evasive` changes — and what it cannot change

| Fingerprint | Static/public PoCs | With `--evasive` | Still detectable? |
|---|---|---|---|
| Multipart boundary content | fixed (`B×10`, `S×17`) | random, **same length** per request | decoded-body-hash matching broken; length + structure intact |
| User-Agent / Accept headers | absent (bare socket) | browser-like, rotating order | UA-absence rules broken |
| Header order | consistent | rotates between layouts | order-based rules broken |
| Preflight/proof GETs | no UA | UA-bearing | same as above |
| `PHPSESSID` field value | fixed per tool (e.g. `attacksessionid0001` in the foundation PoC) | random, **same length** under `--evasive` | constant-value matching broken; presence + structure intact |
| **Field names** (sequential numeric fillers, `PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`) | fixed | **unchanged — structural** | ✅ name-pattern rules still work |
| **Part counts / sizes / body shape** | fixed | **unchanged — calibrated** | ✅ size/shape rules still work |
| **Arming upload > memory_limit** | ~128 MB+ chunked | **unchanged — it is the trigger** | ✅ size rule still works |
| **Oversized `Set-Cookie` on success** | emitted by PHP | **unchanged — it is the leak** | ✅ cookie rule still work |

Practical consequence: static body-hash clustering (the technique used in public honeypot
reports) is defeated; **structural, size-based and response-side rules are not.**

### 1.4 Access-log response-size oracle (lab-measured example)

On the lab replica (stock config), access-log byte counts cleanly separate outcomes:
~733 B = armed request A on-target; ~12 KB = successful leak follow-up B; ~295 B = normal
session cookie; a 232 B `"OK"` body = multipart not parsed at all. Exact numbers vary per
build, but the *technique* — alerting on response-size anomalies correlated with preceding
>memory_limit requests from the same client — is portable and requires no payload knowledge.

## 2. Server-log indicators (immune to `--evasive`)

All strings below are exact PHP 8.5.x messages (verified in source at tag `php-8.5.11`);
they appear in Apache's error log / PHP `error_log`. A single line is suspicious; the
**sequence from one client within seconds is an active exploitation attempt**:

| Log line | When it appears | Source |
|---|---|---|
| `PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 81791383 bytes) in Unknown on line 0` | every arming request, On- and Off-targets alike. Two markers make it distinctive: **"in Unknown"** = OOM before any script ran (normal app OOMs name a file), and the **deterministic allocation size** for a given arming shape + `memory_limit` (reproduced byte-identical across runs) | Zend allocator fatal, pre-script |
| `PHP Warning: Session cookie cannot be sent after headers have already been sent` | On-targets only, during arming — the exact state transition that opens the leak channel | `session.c:1380` |
| `PHP Warning: Failed to read session data: Files (path: …)` | follow-up request carrying a garbage/forged sid | `session.c:498` |
| `PHP Warning: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, "-", and "," characters are allowed` | any attempt to persist a forged/oversized sid (Off-target follow-ups; On-target save path) | `mod_files.c:169` |

Recommended correlation rule (SIEM-style): **OOM-in-Unknown + any of the session warnings
above from the same worker/client within N seconds ⇒ stage 1–2 attempt in progress.** If an
oversized `Set-Cookie` (§1.2) is observed for that client, the ASLR bypass succeeded and
stage 3 (RCE) should be assumed possible until disproven.

Note: with `display_errors=Off` there is no oversized cookie to catch in-band — log and
process-level detection are the only channels against Off-targets, which is why §2/§3 matter
even when §1.2 cannot fire.

## 3. Process-level & filesystem detection (RCE stage)

Stage 3 executes `system(cmd)` inside an Apache worker at request shutdown. Two
independent signals:

**a) Apache child spawning a shell.** mod_php workers do not normally fork `/bin/sh`. An
`execve("/bin/sh", …)` whose parent is an `apache2`/httpd child (or, for FPM variants, a
php-fpm pool worker) is `system()` firing — this cannot be hidden by any HTTP-layer evasion.

- eBPF/Tetragon sketch: alert on `execve` where `parent.comm == "apache2"` and
  `args[0] in {"/bin/sh", "/bin/bash"}`; log the full argv (the attacker's command is in it)
  and the parent PID.
- auditd alternative: `-a always,exit -F arch=b64 -S execve -F a1=...` filtered by parent
  comm via `key=` + post-processing, or simply alert on any `apache2 → /bin/sh` fork/exec pair.

**b) Proof artifacts appearing in the docroot.** Public tooling (including this one) writes
small proof files (`p`, `pp`, `r`, …) into the web root as `www-data`. Filesystem monitoring
(inotify/fanotify on `/var/www/html`) for **new small text files owned by www-data with no
corresponding application write** is a cheap, high-signal tripwire; treat any such file's
content as attacker-controlled output.

## 4. Recommended layered stack

| Layer | Control | Catches |
|---|---|---|
| Patch management | upgrade to 8.5.12+ / 8.4.27+ / 8.3.36+ / 8.2.35+ | everything (the only complete fix) |
| WAF / reverse proxy | reject chunked multipart POSTs > `memory_limit` to PHP pages; require sane sizes for uploads; alert on `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS` co-occurrence with huge bodies | arming, all variants, evasion-proof |
| Response inspection (proxy/WAF) | flag `Set-Cookie: PHPSESSID=` values > 128 chars or containing non-`[0-9a-f]` bytes/escapes | successful leaks, all variants, evasion-proof |
| Log monitoring | §2 correlation rule (OOM-in-Unknown + session warnings, same client, seconds) | attempts on Off-targets where no cookie is emitted |
| Runtime (eBPF/Tetragon or auditd) | Apache-child → `/bin/sh` execve alert with argv capture | RCE execution, evasion-proof |
| Filesystem monitoring | new www-data files in docroot without app writes | proof artifacts / post-exploitation file drops |

## 5. Honest limitations

- A single arming request, viewed alone, resembles a large upload; **correlation** (size +
  session fields + follow-up behavior) is what makes the network signature reliable.
- On `display_errors=Off` targets there is no in-band leak signal at all — only §2/§3 apply,
  and an attacker who never reaches stage 3 leaves just OOM log lines (indistinguishable
  from a memory bug without the session-warning correlation).
- `--evasive` defeats static body-hash clustering and UA/order heuristics; it does not
  defeat any control in §1.1–§1.2, §2 or §3.
- Legitimate large uploads (media imports) can trip size-based rules; tune thresholds to
  your real upload maxima rather than blanket-blocking multipart.
- **Patching closes this chain family, not every PHP bug.** Third-party research reports
  other surviving classes (e.g. a var_destroy re-entry UAF and session-handling gaps that
  reportedly reach RCE on patched builds) — but they require an application-level
  pre-auth unserialize / session-decode surface plus a usable gadget class. Stock WordPress
  core exposes neither, so these do not apply to the stock-WP target class this document is
  written for; non-WP mod_php apps may.
