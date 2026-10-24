# php2shell — full pre-auth RCE on WordPress / PHP 8.5.x (x86_64)

Demonstration and reproduction kit for **full unauthenticated remote code execution**
against a stock WordPress site running **PHP 8.5.x x86_64** under Apache prefork +
mod_php, with ASLR enabled — via CVE-2026-109618 / CVE-2026-109619 (the "php2shell"
memory-safety bugs in PHP core's RFC 1867 multipart path). Version profiles are
shipped for **8.5.9, 8.5.10 and 8.5.11**; the target's version is auto-detected from
`X-Powered-By` (override with `--version`).

The chain was executed against an authorized live target on PHP 8.5.11 and succeeded
on the first cycle, every stage on attempt 1 (~33 s end-to-end; proof:
`uid=33(www-data)` served by Apache — see [`evidence/`](evidence/)). The same chain was
reproduced in-lab against stock WordPress replicas of PHP **8.5.10** (only the two
per-build offsets re-derived) and **8.5.9** (offsets plus a one-slot arming
calibration shift — see the worked example below), each on cycle 1, both carrier
types. It is HTTP-only (no debugger, no `/proc`, no binary blobs) and reproducible
against any matching target you own or are explicitly permitted to test.

## Target requirements

The chain is calibrated for one specific environment. All of the following must match:

| Requirement | Why it matters |
|---|---|
| **PHP 8.5.x, x86_64** — profiles shipped: 8.5.9, 8.5.10, 8.5.11 (stock `php:8.5.x-apache` image builds) | libphp offsets (`ZIF`, `DTOR`) are nm-derived per build; a different build fails safely at stage 2's dtor gate instead of firing blind. Note `zif_system` is a *local* symbol in these builds — use full `nm`, not just `nm -D` (see the adaptation section) |
| **Apache prefork + mod_php** | RCE depends on the OOM'd worker *surviving* and being reused (PHP-FPM exits the worker → DoS only) |
| **`memory_limit=128M`** (stock default) | arming size (`HUGE_MB=140`) and pad calibration (`PADS=112`) are tuned to this value; other values need re-calibration (the math is in [LESSONS_LEARNED.md](LESSONS_LEARNED.md)) |
| **`session.upload_progress.enabled=On`** (default) | the vulnerable handler |
| docroot writable by `www-data` (stock WP) | default proof writes `/p` into the docroot; otherwise use `-c 'id>/tmp/x'` + SSH read, or a callback |

WordPress was the demonstrated application stack (validated on WP 7.x), but the trigger
fires in PHP core **before any application code runs** — any mod_php app works. WordPress
matters for two practical reasons: its stock `.htaccess` serves existing files directly
(so `GET /p` bypasses the front controller as proof), and its background activity
(wp-cron, bots) is what the keep-alive targeting strategy pins out (see below).

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

Options:

| Flag | Meaning |
|---|---|
| `--stage 1` / `--stage 2` | run only the leak stages (validates offsets against your build without executing code) |
| `-c 'cmd'` | custom command; default `id>p`. ≤ 14 bytes runs on the standard carrier; longer commands (up to ~305 chars) use an extended carrier and get a marker write appended (`>pp`) so success is provable black-box. No NUL bytes. |
| `--cycles N` | stage-3 retry budget (default 3; live run needed 1) |
| `--version X.Y.Z` | pin a version profile instead of auto-detecting from `X-Powered-By` (needed when `exposed_php_version=Off`) |

A timestamped log of the run is written to the current directory. There is deliberately
no default target — `-u` is required, and you should only point it at systems you are
authorized to test.

## How it works

Three stages, each a `multipart/form-data` POST parsed by PHP core before application
code runs:

1. **Heap ASLR bypass.** An OOM fatal during multipart parsing (a ~140 MB chunked upload
   that exhausts the 128 M `memory_limit`) interrupts request setup with session state
   only partially initialized; a follow-up request on the same connection makes PHP emit
   a forged `zend_string` in `Set-Cookie`, disclosing the Zend-MM chunk base.
2. **Code ASLR bypass.** A second arming + a 56-byte HashTable overlap puts a libphp
   pointer (`zval_ptr_dtor`) into `Set-Cookie`; its page-offset gate validates the leak
   against the expected build before anything proceeds.
3. **RCE.** The dangling `PS(http_session_vars)` reference is reclaimed with a forged
   array/`execute_data` frame whose destructor is `zif_system`; at request shutdown PHP
   calls it with the attacker's command.

Two engineering pieces make this reliable in the wild (details + calibration math in
[LESSONS_LEARNED.md](LESSONS_LEARNED.md)):

- **Keep-alive arm→follow-up targeting.** Each stage opens one persistent HTTP/1.1
  connection, arms over it, and sends its follow-up on the same socket — prefork binds a
  keep-alive connection to a single child, so the armed worker is guaranteed to process
  the exploit, and stays busy with our connection for the whole cycle (wp-cron/bots
  cannot clear the armed state mid-cycle). No worker-pinning infrastructure.
- **Chunked-transfer arming.** The OOM upload uses `Transfer-Encoding: chunked`, which
  bypasses `post_max_size` entirely, and stops sending the moment the first response byte
  arrives (the post-OOM connection stays in sync — verified empirically).
- **Extended command carrier.** Commands longer than 14 bytes use a larger final
  allocation with its own calibrated offset (`HTDATA_EXT`, measured in-lab with an
  LD_PRELOAD allocator interposer); the appended marker write keeps success provable
  black-box. The standard ≤ 14-byte path is untouched and remains the proven geometry.

The request bodies and stage-3 forged-frame geometry derive from @alvarodh5's single-file
PoC (MIT; credited in [CREDITS.md](CREDITS.md)) and are inlined here with attribution;
this repo adds the stock-config calibration (`PADS=112`), keep-alive live targeting,
black-box proof, and the extended-carrier long-command support.

### How the ASLR bypass actually works

ASLR randomizes two things we need: where PHP's heap (the Zend memory manager arena)
lives, and where `libphp.so` is mapped. Both are defeated **in-band** — the target tells
us its own addresses over HTTP, so no assumptions about kernel layout are needed:

- **Stage 1 → heap base.** The OOM arming interrupts request setup with the session-ID
  string already freed but still referenced (`PS(id)` dangles). A crafted multipart field
  in the follow-up is positioned so its bytes overwrite that freed string's header —
  rewriting its length to `0x1000` and marking it a valid string. When PHP then emits
  `Set-Cookie: PHPSESSID=…`, it copies **4 KB of live heap** into the cookie value.
  The leaked bytes contain many pointers; counting their 2 MB-aligned values
  (`v & ~0x1FFFFF`) and taking the densest cluster yields the Zend-MM arena base. The
  range filter (typical x86_64 user-space) plus clustering is what makes this
  kernel-independent — it works wherever ASLR put the heap.
- **Stage 2 → libphp base.** Arming with a different fill size (`x`*39 instead of `x`)
  shifts where the OOM lands during parsing, so that a specific HashTable allocation
  overlaps the dangling session-ID region. That table's `pDestructor` field is a **libphp
  code pointer** (`zval_ptr_dtor`), and it rides out in the same `Set-Cookie`. Before
  anything proceeds, the leak must pass a page-offset gate — `(ptr & 0xfff) ==
  (DTOR & 0xfff)` against the expected build. A mismatched build fails here instead of
  firing blind; a match gives `libphp_base = ptr − DTOR`.
- **Why one leak covers all workers.** Prefork children are forked from the same parent,
  so every worker shares the identical address-space layout (and arena state). The bases
  leaked on any connection are valid for every worker — which is what lets stage 3 run on
  a different, keep-alive-pinned worker than the one that leaked.
- **Stage 3** then needs no further leaks: with both bases known, it computes absolute
  addresses (`zif_system`, the carrier slot) and reclaims the dangling
  `PS(http_session_vars)` reference so request shutdown calls `system(cmd)` through a
  forged destructor. The reclaim alignment is what the `PADS=112` calibration fixes —
  see [LESSONS_LEARNED.md](LESSONS_LEARNED.md) for the slot-grid arithmetic.

### How this builds on prior work

- **@9bie** built the original pure-HTTP chain (PHP 8.4.26): the in-band `Set-Cookie`
  leaks plus a `zif_system` reclaim, and worker-pinning techniques. The concept that made
  x64 + ASLR exploitable at all is his.
- **@dinosn** published the PHP 8.5.11 dangling-reference reclaim geometry that the 8.5
  stage 3 is based on.
- **@alvarodh5** (MIT) unified this into a single-file, multi-version PoC with an offset
  inventory — the direct foundation of this repo; its leak stages and forged-frame code
  are inlined here with attribution. His lab used `memory_limit=16M` and a single pinned
  worker; **his stage 3 did not work against stock config**, for an allocator reason no
  public write-up documented.
- **This project** closed that gap: source-level decoding of the failure (a one-slot
  misalignment in the Zend-MM slot grid, fixed by the `k ≡ 6 mod 7` condition and the
  `pads=112` request-shape knob), keep-alive arm→follow-up targeting that replaces worker
  pinning and survives WordPress background traffic, chunked-TE arming to bypass stock
  `post_max_size`, black-box proof design, the extended carrier for long commands,
  and a patched-build control proving the official fix closes it. Discovery of the
  underlying CVEs is by **Calif, OpenAI and Wiz**; the patch is from the PHP security team.

### Adapting to other vulnerable versions

What changes per target, and how:

| Piece | Depends on | How to get it |
|---|---|---|
| `ZIF` / `DTOR` offsets | the **build** (not even the version) | derive from the target binary: `nm -D /usr/lib/apache2/modules/libphp.so \| grep -E 'zif_system\|zval_ptr_dtor'` (or parse the ELF symbol tables; @alvarodh5's original multi-version PoC ships such an auto-derive mode). The stage-2 dtor gate rejects a wrong build before any code runs |
| Stage 1–2 leaks | version + SAPI | **self-validating**: run them first against any candidate target. A valid clustered heap leak and a gated libphp leak mean the ASLR bypass works on that build, no further assumptions needed |
| Stage-3 geometry (`HTDATA`, frame layout) | version (struct layouts) + config | decode from php-src at the exact tag with allocator ground truth (LD_PRELOAD interposer); this is the per-version work. Known status: **8.5.11 RCE OK** (this repo, live + lab), **8.5.10 RCE OK** and **8.5.9 RCE OK** (this repo, lab — see worked example below), 8.4.26 RCE OK (@alvarodh5's chain), 8.3.35 leak-only (stage-3 geometry pending), 8.2.34 pending, arm64 partial |
| Arming calibration (`PADS`) | `memory_limit` + arming shape | the dangling slot index must satisfy `k ≡ 6 mod 7`; pad count shifts `k` by a measured constant — scan once per target config (minutes), don't brute-force payloads |

### Worked example: porting to PHP 8.5.10 (what actually changed)

The 8.5.10 profile in `exploit.py` was produced by the procedure above; here is what it
turned out to cost, as a concrete data point for adjacent versions:

1. **Source diff first.** The php-src diff between tags `php-8.5.10` and `php-8.5.11`
is clean in everything that shapes this chain: `zend_list.h` / `zend_hash.h` /
   `zend_execute.h` / `zend_string.h` struct layouts, the Zend allocator
   (`zend_alloc.c`), RFC 1867 parsing (`main/main.c`) — all unchanged; the only
   session changes are an unrelated cookie-header return-value fix and a sid-creation
   NULL check. Prediction: forged-frame geometry carries over verbatim; only
   build-specific constants need re-derivation.
2. **Re-derive the two offsets** from the target's own binary (in-container `nm` on
   `/usr/lib/apache2/modules/libphp.so`): `zif_system` 0x598d60, `zval_ptr_dtor`
   0x7b3860. (`zif_system` is a local symbol — full `nm`, not `-D`; that's why the
   naive one-liner in the table above only finds half of them.)
3. **Validate self-validatingly.** Stages 1–2 are their own test: the heap leak must
   cluster and the libphp pointer must pass the dtor page-offset gate — on 8.5.10 it
   did, attempt 1, and the leaked pointer resolved to exactly `base + zval_ptr_dtor`.
4. **Confirm stage 3 behaviorally.** With the *unchanged* `HTDATA` / `PADS`, both the
   standard carrier (`id>p`) and the extended carrier (long command + marker) achieved
   RCE on cycle 1 against a stock-config WP replica. That behavioral confirmation made
   interposer re-measurement of the carrier offsets unnecessary — if stage 3 had missed,
   the interposer in [`tools/interposer/`](tools/interposer/) is how you find out why.

### Second data point: PHP 8.5.9 — where calibration, not geometry, moved

Porting to 8.5.9 followed the same procedure, with one twist worth knowing about:

1. **Source diff again clean** for everything that shapes the chain (RFC1867 parsing,
   allocator, struct layouts all identical to 8.5.10); the .9→.10 release is a normal
   bugfix patch across unrelated extensions.
2. Offsets re-derived: `zif_system` 0x598160, `zval_ptr_dtor` 0x7b29a0. Stages 1–2
   validated on attempt 1 (the stage-2 pointer resolved to exactly `base + zval_ptr_dtor`).
3. **Stage 3 missed with the carried-over `PADS=112`.** Interposer ground truth showed why:
   unrelated RINIT-time heap consumption changed between .9 and .10, shifting where the
   OOM lands during arming by one bin-3 slot — the dangling reference moved from k=76
   (≡ 6 mod 7, aligned) to **k=75 (≡ 5, dead)**: no recycled 56 B slot can place its data
   region at `ref − 24`, so the reclaim is geometrically impossible regardless of payload.
   The fix was a two-pad bump: **`PADS=114` → k=83 (≡ 6)**, after which both carriers RCE'd
   on cycle 1 with `HTDATA`/`HTDATA_EXT` unchanged.

So the honest net cost for an adjacent vulnerable version is: **two nm lookups + one
replica, plus a stage-3 smoke test** — and if that misses, one interposer measurement of
the reference slot index (k mod 7) tells you exactly which pad count to try. Versions
further apart (8.4.x, 8.3.x) need the full diff-and-decode path because their struct
layouts and allocator behavior differ.

Recommended procedure for a new version: build an exact replica first (same image, same
app stack), instrument with the interposer for allocator ground truth, decode the trigger
from source at that tag, make every stage self-validating, and only then touch a live
target. The full 8-phase playbook — including what didn't work (blind grooming,
untested signal mechanisms, over-engineered pinning) — is in
[LESSONS_LEARNED.md](LESSONS_LEARNED.md).

## Evidence

[`evidence/`](evidence/) contains sanitized logs (target IP redacted) from:

- **the live run** — full chain against an authorized WordPress target on PHP 8.5.11
  x86_64: cycle 1, every stage attempt 1, ~33 s total; `GET /p` →
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)`;
- **the 8.5.10 lab reproduction** — full chain (auto-detected profile) against a stock
  WordPress replica on PHP 8.5.10 x86_64: cycle 1, both carrier types; log is
  localhost-only by construction.
- **the 8.5.9 lab reproduction** (`lab_8509_rce.log`) — full chain against a stock
  WordPress replica on PHP 8.5.9 x86_64: cycle 1, both carrier types; uses the
  re-calibrated `PADS=114` (see worked example). Preflight shows `GET /p` → 404,
  post-exploit → 200 with `uid=33(www-data)`.
- **the patched-build control** — the same chain against PHP **8.5.12**: no leak on any
  attempt (8.5.12 also aborts parsing at `max_input_vars` overflow before reaching the
  OOM field). The official patch closes this RCE.

## Patch status & mitigations

Fixed in **8.5.12, 8.4.27, 8.3.36, 8.2.35** (plus EOL backport branches for 7.4/8.0/8.1),
shipped 2026-10-21. The PHP security team: *"There are no complete mitigations, updating
is the only safe choice."* Partial stopgaps from the official advisory (none is complete;
`ini_set()`/`.user.ini` are too late — parsing precedes them): `memory_limit=-1` + low
`post_max_size` for CVE-2026-109618, `session.upload_progress.enabled=0` (and on 8.5,
`fatal_error_backtraces=0`) for CVE-2026-109619, or rejecting `multipart/form-data` at the
proxy (breaks uploads).

## Credits & prior work

See [CREDITS.md](CREDITS.md) — this chain stands directly on @alvarodh5's single-file
ASLR-bypassing RCE (MIT; inlined into `exploit.py` with attribution), which builds on
@9bie's and @dinosn's public work; discovery of the underlying CVEs is by Calif, OpenAI
and Wiz.

## Disclaimer

For **lawful, authorized** security assessment, research and education only — run it
against systems you own or have explicit written permission to test. Each arming request
OOMs a worker (a brief per-request disruption); coordinate with the owner before running,
prefer non-destructive proof commands (`id>p`), and remove proof files afterwards unless
the owner wants them kept.

## Sources

- [calif.io/php2shell](https://calif.io/php2shell/) — discoverers' write-up (Calif, OpenAI, Wiz)
- [PHP security advisory](https://www.php.net/archive/2026.php) — official, 21 Oct 2026
- @alvarodh5 — foundation single-file PoC (MIT); full attribution in [CREDITS.md](CREDITS.md)
- [VulnCheck analysis](https://www.vulncheck.com/blog/php2shell-vulnerabilities) · [CrowdStrike: obstacles to weaponizing php2shell](https://www.crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation/)
