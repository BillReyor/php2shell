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

- `alloc_all.c` — source (recovered from project history; this is the exact code that
  produced the validated measurements)
- `alloc_all.so` — compiled binary, x86_64 Linux/glibc (Debian bookworm base), built for
  the official `php:8.5.x-apache` images. md5 `2fb47022208c1be41ee90f0719b5b202`.

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
| `PS id=0x<ptr>` | `PS(id)` (session ID pointer) changed |
| `PS http_session_vars type=<t> ref=0x<p>` | `PS(http_session_vars)` zval state changed — the dangling-reference signal this exploit reclaims |
| `DBG libphp_base=0x<base>` | one-time: libphp base parsed from `/proc/self/maps` |

## Caveats

- **Build-specific offset:** `ps_dump()` reads the session globals at a fixed offset
  (`libphp_base + 0x01771a40`) that is valid for the `php:8.5.11-apache` build only. For
  another version/build, re-derive it from that libphp's symbol table (the session
  globals struct offset) before trusting the `PS …` lines; the `M/R/F/S` allocation
  lines are unaffected and work on any PHP 8.5 x86_64 build exporting the same symbols.
- **Volatile log:** `/tmp/alloc_all.log` is container-local — wiped if the container is
  recreated, and never store anything important in `/tmp`. Copy logs out after use.
- **Noise:** every `docker exec`'d process also loads the preload; filter by timing
  windows or worker activity when correlating allocations to a specific request.
- Rebuild (inside any Debian-based container with build tools):
  `gcc -shared -fPIC -O2 -o alloc_all.so alloc_all.c -ldl`
