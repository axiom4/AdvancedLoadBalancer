#!/usr/bin/env python3
"""Keep-alive HA client: verifies every response byte-for-byte; counts failures and reconnects."""
import socket, sys, threading, time

HOST, PORT = sys.argv[1], int(sys.argv[2])
CONC, DURATION = int(sys.argv[3]), float(sys.argv[4])
SIZE = int(sys.argv[5]) if len(sys.argv) > 5 else 65536
BODY = bytes(i % 251 for i in range(SIZE))
stats = {"ok": 0, "fail": 0, "reconnect": 0}
fails = []
lock = threading.Lock()
t0 = time.time()

def read_response(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            raise IOError("EOF in headers")
        buf += d
    hdr, rest = buf.split(b"\r\n\r\n", 1)
    clen = 0
    for line in hdr.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            clen = int(v)
    body = rest
    while len(body) < clen:
        d = s.recv(65536)
        if not d:
            raise IOError("EOF in body at %d/%d" % (len(body), clen))
        body += d
    if body != BODY:
        raise IOError("body mismatch (len %d)" % len(body))

def worker(i):
    s = None
    while time.time() - t0 < DURATION:
        try:
            if s is None:
                s = socket.create_connection((HOST, PORT), timeout=5)
                s.settimeout(5)
            s.sendall(b"GET /x HTTP/1.1\r\nHost: vip\r\n\r\n")
            read_response(s)
            with lock:
                stats["ok"] += 1
        except Exception as e:
            with lock:
                stats["fail"] += 1
                stats["reconnect"] += 1
                fails.append("t=%.2fs conn%d: %s" % (time.time() - t0, i, e))
            try:
                s and s.close()
            except Exception:
                pass
            s = None
            time.sleep(0.05)

ts = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(CONC)]
[t.start() for t in ts]
[t.join() for t in ts]
print("RESULT ok=%d fail=%d" % (stats["ok"], stats["fail"]))
for f in fails[:40]:
    print("  FAIL", f)
