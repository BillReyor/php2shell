# Allocator interposer (`alloc_all`)

LD_PRELOAD ground-truth tool used during this project's exploit development: it logs
every PHP memory-API call (size + address) and tracks the session globals `PS(id)` /
`PS(http_session_vars)` as they change. This is how the stage-3 carrier offsets
(`HTDATA`, `HTDATA_EXT`) were measured, and how the Zend-MM slot-grid calibration was
validated — see [../../LESSONS_LEARNED.md](../../LESSONS_LEARNED.md).

**Why it exists:** PHP 8.5 routes nearly all small allocations through size-specialized
symbols (`_emalloc_8` … `_emalloc_3072`, `_efree_N`) instead of the generic
`_emalloc`/`_efree`. Hooking only the generics sees almost nothing during request
handling — this interposer hooks the full family (63 symbols) plus
`_erealloc`/`_estrdup`/`_estrndup`/`_safe_emalloc`/`_safe_erealloc`.

## Files

- `alloc_all.c` — source; this is the exact code that
  produced the validated measurements
- `alloc_all.so` — compiled binary, x86_64 Linux/glibc (Debian bookworm base), built for
  the official `php:8.5.x-apache` images; includes the forensic extensions below.
  md5 `e5e84021c2e41766260f896e791a3bd5`. Rebuild with:
  `gcc -shared -fPIC -O2 -o alloc_all.so alloc_all.c -ldl` (add `-DPSG_OFF=0x…` for other builds).

## Installing in a target container (lab only)

```sh
docker cp alloc_all.so <container>:/usr/local/lib/alloc_all.so
docker exec <container> sh -c 'echo /usr/local/lib/alloc_all.so > /etc/ld.so.preload'
chown root:root /usr/local/lib/alloc_all.so && chmod 755 ...   # via docker exec
docker restart <container>        # apache is PID 1; a plain `apache2ctl stop` kills the container
```

Verify by watching the log grow after a request (do **not** rely on reading worker
`/proc/<pid>/maps` — containers without `CAP_SYS_PTRACE` deny it):

```sh
docker exec <container> wc -l /tmp/alloc_all.log   # before
curl -s http://localhost:<port>/ >/dev/null
docker exec <container> wc -l /tmp/alloc_all.log   # after: must have grown
```

## Log format

| Line | Meaning |
|---|---|
| `M <size> 0x<addr>` | allocation (generic or size-specialized; the specialized hooks log their fixed size) |
| `R 0x<old> <size> 0x<new>` | realloc |
| `F 0x<ptr>` | free |
| `S <len> 0x<addr>` | string dup (`_estrdup`/`_estrndup`) |
| `PS id=0x<ptr> old@0x<old>:<64 hex bytes>` | `PS(id)` (session ID pointer) changed; also dumps 64B of the OLD block — what a later Set-Cookie would read from it |
| `PS http_session_vars type=<t> ref=0x<p>` | `PS(http_session_vars)` zval state changed — the dangling-reference signal this exploit reclaims |
| `SLOT @0x<addr> val=0x<v> rel=0x<r> block@PS-0x10:<56 hex bytes>` | slot monitor: value at PS(id)+0x20 (= stage-2 cookie bytes 8..15, the pDestructor of the per-part HashTable) changed; `rel` = offset from libphp base |
| `PRE urlenc str=… len=… slot=… in16:<hex>` / `POST urlenc result len=… bytes:<hex>` | `php_url_encode` wrapper: exact input bytes at call time + encoded output (leak-channel forensics) |
| `DBG libphp_base=0x<base> psg_off=0x<off>` | one-time: libphp base parsed from `/proc/self/maps` + the compiled-in ps_globals offset |

## Forensic extensions (added while solving the 8.5.3 cookie-decode mystery)

- **Slot monitor** (`SLOT …` lines): watches the pDestructor slot of the per-part HashTable at
  PS(id)−0x10 — exactly the bytes that become stage-2 cookie offset 8..15 — and logs every change
  with the full 56-byte table block. This proved the slot holds *exactly* `zval_ptr_dtor` at read
  time on every version, including 8.5.3 (the apparent "+11" was a bug in our own cookie parser —
  see `parse_cookie` in exploit.py).
- **`php_url_encode` / `php_session_reset_id` wrappers** (`PRE/POST urlenc …` lines): dump the
  exact input bytes and encoded output of the leak channel. This is what showed PHP emits space
  as a literal `+` (form encoding) — the root cause of the 8.5.3 mis-decode.

The slot monitor runs inside `ps_dump()` (before every hooked call, logs only on change); the
wrappers fire only when those functions are called. Optional forensics — not needed for normal
measurement runs.

## Caveats

- **Build-specific offset:** `ps_dump()` reads the session globals at `libphp_base + PSG_OFF`,
  a compile-time parameter (`gcc -DPSG_OFF=0x…`; default `0x01771a40` = php:8.5.11-apache).
  For another version/build, re-derive it with
  `nm /usr/lib/apache2/modules/libphp.so | grep -w ps_globals` before trusting the
  `PS …`/`SLOT …` lines; the `M/R/F/S` allocation lines are unaffected and work on any
  PHP 8.5 x86_64 build exporting the same symbols.
- **Volatile log:** `/tmp/alloc_all.log` is container-local — wiped if the container is
  recreated, and never store anything important in `/tmp`. Copy logs out after use.
- **Noise:** every `docker exec`'d process also loads the preload; filter by timing
  windows or worker activity when correlating allocations to a specific request.
- Rebuild (inside any Debian-based container with build tools):
  `gcc -shared -fPIC -O2 -o alloc_all.so alloc_all.c -ldl`
