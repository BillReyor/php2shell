# Lessons Learned — php2shell RCE Research (CVE-2026-109618 / CVE-2026-109619)

> Field notes from taking a pre-auth PHP memory-safety bug from "public PoCs don't work on
> our target" to **full RCE against an x64 + ASLR internet workload, HTTP-only** — and then
> proving the official patch closes it. Written for future exploit research: what worked,
> what didn't, and a reusable playbook.

## Outcome in one paragraph

~3 weeks of multi-session work. The public PoCs (Zer061 et al.) could not be made to work on
the target's stock Apache prefork + mod_php config — source analysis showed their core
primitive cannot survive request boundaries there. A different public chain (@alvarodh5) did
work in a lab replica, but its stage-3 RCE failed on *stock* config for a subtle allocator
reason nobody had documented. The breakthrough was **source-level mechanism decoding +
interposer ground truth**, which turned the failure into arithmetic (a slot-grid alignment
condition with a request-shape calibration knob). Live porting then reduced to two problems —
worker targeting and proof observability — both solved with simple, lab-validated primitives
(keep-alive connection reuse; `id>p` → web-readable file). Final live run: cycle 1, every
stage attempt-1. Patched-build control: no leak, RCE closed.

---

## What worked (do this)

### 1. Build an exact replica of the target before touching it
Docker with the *exact* image (`php:8.5.11-apache`), stock ini, and — critically — a replica
of the **application stack** on top (stock WordPress + MariaDB). Every assumption we tested in
the lab transferred to live 1:1, including the most delicate one: the heap-alignment
calibration was *identical* on WP-warmed workers (`ref=…7a980`, k=76) as on pristine ones.
Cost: a few hours of setup (WP install gotchas included — see pitfalls). Benefit: zero wasted
live cycles, safe iteration, and the ability to instrument freely (LD_PRELOAD interposer,
docker exec proof reads) that live black-box testing forbids.

### 2. Decode the mechanism from source; measure with ground truth
Blind heap-grooming iteration ("add more fields", "change sizes") burned many sessions with no
progress. Once we read the actual php-src at the target's tag and identified the *exact* RCE
trigger — request-shutdown `zval_ptr_dtor(&PS(http_session_vars))` → GC_DELREF on a forged
reference → `zend_array_destroy` → `pDestructor = zif_system` called with a forged
execute_data frame — and measured real allocation geometry with an LD_PRELOAD interposer, the
problem became **arithmetic**:

- The dangling reference is a 32-byte Zend-MM bin-3 slot at page offset `k*32`.
- The reclaiming 56-byte string's data region starts at `j*56 + 24`.
- Reclaim alignment requires `k*32 − 24 ≡ 0 (mod 56)` ⟺ **`k ≡ 6 (mod 7)`**.
- Pad-field count in the arming request shifts k by a measured constant (4 slots/pad) →
  deterministic calibration knob. One scan found `pads=112`; every subsequent run was attempt-1.

**Rule: when an exploit "almost works" nondeterministically, stop guessing and instrument.**
The interposer log of one successful run + the source is worth a hundred blind attempts.

### 3. Make every stage self-validating
Stage 1's leak only appears in the response if the request hit the armed worker with valid
state; stage 2 validates via a page-offset gate (`ptr & 0xfff == dtor & 0xfff`); stage 3 via
the proof file. No external oracle (no SSH, no docker exec) was needed on live because each
stage *proves itself in-band*. This is what made the whole live run robust to unknowns we
couldn't measure (worker count, dispatch behavior).

### 4. Use the simplest targeting primitive that works — and validate it empirically first
We designed elaborate worker-pinning infrastructure (N−1 holder connections, stale-state
discriminator binary search for N) before trying the trivial option: **arm + follow-up over
one keep-alive connection**. Prefork binds a persistent connection to one child; the OOM'd
worker survives and Apache keeps the connection in sync (verified empirically — it did *not*
desync despite ~12MB of unread body at OOM time). Bonus: the pinned worker is busy with our
connection for the whole cycle, so wp-cron/bots physically cannot clear the armed state
mid-cycle. **Rule: cheapest deterministic primitive first; validate its failure modes in lab
before trusting it on live.**

### 5. Turn assumptions into tests using app-stack replicas
"Stock WordPress doesn't call `session_start()`, so planted objects survive to shutdown" was
an *assumption* for weeks. A 30-minute WP replica install turned it into a tested fact — and
the same run confirmed alignment transfer on warmed heaps. Two of the three "big unknowns"
for live porting were closed in one lab afternoon. **Rule: any claim about what the target's
application does between parse and shutdown must be tested against a replica, not reasoned
about.**

### 6. Get an independent second opinion before expensive steps — then adjudicate empirically
Before spending live cycles, we ran the full strategy through a different model (glm-5.3:cloud
via `ollama launch claude`, framed as authorized defensive research). Results:
- **Adopted:** build the WP replica first; burst-spray fallback; treat crash-signatures
  diagnostically. All good calls.
- **Refuted by testing:** its `sleep 9` response-latency RCE detector — sounded airtight, but
  mod_php flushes the full response *before* `php_request_shutdown` runs `system()`. Lab test:
  ~1s response, RCE still fired. Never ship an untested signal mechanism.
- **Verified before use:** its keep-alive recommendation rested on an assumption (post-OOM
  connections stay clean) that we had *predicted* would fail; the lab test showed it working.

**Rule: treat LLM second opinions as hypothesis generators, not authorities — every claim gets
a lab verdict.** (Also: framing the task as authorized cyber-defense research on our own lab
targets made the tool far more useful.)

### 7. Design proof for black-box observability *before* the live run
`id>p` works because (a) mod_php worker cwd = docroot — verified in lab first, and (b) WP's
stock `.htaccess` serves existing files directly (`!-f` condition), so `GET /p` bypasses WP.
Fallbacks were pre-planned (SSH read of a `/tmp` variant; short-URL callback). The live docroot
turned out to be www-data-writable, but we would have known the plan B path regardless.

### 8. Run the patched-build control
Running stage 1 against `php:8.5.12-apache-bookworm`: **no leak on any attempt** (and a bonus
finding — 8.5.12 aborts parsing at the max_input_vars overflow before reaching our OOM field).
This proves the exploit targets the vulnerable code path specifically, and that the official
patch closes it. A write-up without this control is incomplete.

### 9. Keep canonical artifacts out of volatile storage
`/tmp` was wiped by a reboot mid-project, taking session-3's demo scripts with it (we had to
reconstruct — imperfectly — later). Everything that matters lives in the project directory;
container-local logs are fine only if regenerable.

---

## What didn't work (don't do this)

### 1. Assuming public PoCs transfer to your target's config
Zer061's cross-request dangling-`PS(id)` primitive **cannot work under stock Apache prefork +
mod_php**: `php_request_shutdown()` clears session globals between requests, and the
OOM-pre-RINIT path doesn't leave what their chain needs. Their lab conditions remain unexplained
by the public repo. We spent days trying to make it work before source analysis showed why it
couldn't. **Rule: re-derive every primitive against the target's actual SAPI/MPM/config; treat
public chains as starting hypotheses.**

### 2. Blind heap grooming without a model
Weeks of "add fields / change sizes / try another arming shape" with no understanding of *why*
stage 3 failed on stock config (it was a one-slot misalignment in the Zend-MM slot grid, caused
by where the OOM lands relative to `memory_limit`). The moment we had source + interposer
ground truth, the fix was a two-digit number (`pads=112`) found by a 5-minute scan.

### 3. Tooling blind spots (the interposer saga)
The allocator interposer went silent and burned hours of misdiagnosis. Root causes, in order:
- **PHP 8.5 routes nearly all small allocations through size-specialized symbols** —
  `_emalloc_8 … _emalloc_3072`, `_efree_N` (no-arg allocators / ptr-arg freeers). Hooking only
  the generic `_emalloc/_efree` sees almost nothing during request handling. Check `nm -D` on
  the target's libphp for the *full* symbol family before trusting an interposer.
- `setvbuf(f, NULL, _IOLBF, 0)` is a latent bug (size=0) — use an explicit buffer size or
  `_IONBF`.
- Inside containers Apache listens on **:80**, not the host-mapped port; curling the mapped
  port from *inside* the container returns 000 and looks like a dead tool.
- `docker exec`'d tools (sh, curl) also load `/etc/ld.so.preload` — constructor lines in your
  log are not proof of worker activity; check for actual M/R/F/S entries.
- Never run `apache2ctl stop` inside these containers: Apache is PID 1 and the container exits.

### 4. Plausible-but-wrong signal mechanisms
The `sleep 9` latency detector (see §6 above) is the canonical example: a theoretically sound
idea that fails because of one implementation detail you can only find by testing. **Any
detection/proof mechanism gets a lab validation run before it's trusted.**

### 5. Over-engineered targeting infrastructure
Holder-connection pinning, worker-count discovery via stale-state discriminators, cgroup-OOM
analysis — all designed and half-built *before* trying keep-alive reuse, which made the whole
class of problems disappear. **Rule: enumerate targeting options from cheapest to most complex;
stop at the first one that validates in lab.**

### 6. Letting a wrong dispatch model drive design
An LLM second opinion asserted prefork dispatch is "same worker always" under quiet traffic —
a claim that contradicted its own accept-mutex analysis and was never testable cheaply. It
turned out to be *moot* (keep-alive makes dispatch irrelevant), but had we built spray logic on
that model, retry semantics would have been wrong. **Rule: identify which of your assumptions
are load-bearing; if one is both untestable and load-bearing, redesign so it isn't.**

---

## Playbook for future exploit research

**Phase 0 — Scope & authorization.** Written authorization; fingerprint the target exactly
(version *and* build era, SAPI, MPM, ini values, app stack); define success criteria and a
black-box-observable proof strategy up front; measure/accept outage risk with the owner.

**Phase 1 — Exact replica.** Docker with the exact image + stock config + the real application
stack on top (WordPress etc.). Instrument early: LD_PRELOAD interposer for allocator ground
truth, PS()/global-state tracking via `/proc/self/maps` base + `offsetof`. Keep artifacts in
the project dir, never /tmp.

**Phase 2 — Mechanism decoding.** Read source at the target's exact tag. Identify: the precise
trigger point; which state dangles and *why* (which cleanup is skipped); what consumes it later;
what frees/reclaims the slots involved. Validate every claim against runtime ground truth
(interposer/gdb), not just code reading — code reading alone got us wrong about object sizes
and free-list behavior in earlier sessions.

**Phase 3 — Self-validating primitives.** Design each stage to prove itself in-band (leak =
success signal; validity gates like page-offset checks and pointer clustering). This removes the
need for oracles on live and makes retry logic trivial.

**Phase 4 — Targeting.** Cheapest deterministic primitive first: keep-alive connection reuse →
pinning → spray. Empirically validate post-fatal connection behavior (does the worker survive?
does the connection stay in sync?) before trusting it.

**Phase 5 — App-stack interference + calibration as arithmetic.** Test what the application does
between parse and shutdown on a replica. Derive alignment conditions from allocator geometry
(block sizes, page recycling rules) and find request-shape knobs that control slot indices; scan
for the calibrated value instead of brute-forcing payloads.

**Phase 6 — Independent review before live.** Feed full context to a different model/agent as an
authorized-defensive-research second opinion. Adjudicate *every* claim empirically in lab: adopt,
refute, or verify-before-use.

**Phase 7 — Live execution.** Preflight (baseline response, confirm proof path absent); run
stages in order with leaks first (they validate offsets against the real build); detect success
via web-observable side effects; measure impact after each arming; clean up afterwards (remove
proof files or leave by owner's choice).

**Phase 8 — Control + write-up.** Run the chain against the patched version and document the
failure mode. Write up: mechanism with source citations, calibration math, evidence logs, what
the patch changes, and detection guidance.

## PHP/mod_php-specific notes (reusable facts)

- **Zend MM geometry:** small-bin block size = `(bin+1)*8`; RUNs are page-aligned; a page can
  only be reused by a different bin after its entire old RUN is freed and GC reclaims it.
  Reclaim alignment across bins is modular arithmetic on slot indices — derive, don't guess.
- **mod_php prefork behavior (empirical):** workers survive OOM fatals and keep connections
  alive; the OOM page returns `200 OK` with `Connection: Keep-Alive`; ~12MB of unread chunked
  body at OOM time does *not* desync the connection; worker cwd = docroot; the full response is
  flushed **before** `php_request_shutdown` (no latency-based RCE signal); `POST /index.php` on
  WordPress gets a canonical 301 — harmless, because multipart parsing (and any pre-RINIT cookie
  emission) precedes application code.
- **PHP 8.5 allocator symbols:** the size-specialized `_emalloc_N`/`_efree_N` family carries
  nearly all small allocations; interpose the whole family or your ground truth is blind.
- **The 8.5.12 patch** adds early session-globals clearing at `MULTIPART_EVENT_START` and aborts
  parsing at max_input_vars overflow — stage 1 of this chain dies immediately on it (no leak).

## Operational & ethical notes

- Authorized targets only; keep the owner informed before each arming cycle (each one OOMs a
  worker); prefer non-destructive proof commands (`id>p` over anything that modifies app state).
- Keep a running progress log in the project dir — it is what makes handoffs between sessions,
  agents, and humans possible, and it is the raw material for the write-up.
- Don't leave proof files on targets without the owner's OK; don't store target IPs in shared
  artifacts (this repo uses placeholders / explicit `-u` arguments).
