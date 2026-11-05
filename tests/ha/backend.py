#!/usr/bin/env python3
"""Slow keep-alive HTTP backend for HA tests: each response streams a verifiable body in chunks."""
import sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

SIZE = int(sys.argv[2]) if len(sys.argv) > 2 else 65536
DELAY = float(sys.argv[3]) if len(sys.argv) > 3 else 0.005
BODY = bytes(i % 251 for i in range(SIZE))

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(SIZE))
        self.end_headers()
        for off in range(0, SIZE, 4096):
            self.wfile.write(BODY[off:off + 4096])
            self.wfile.flush()
            time.sleep(DELAY)
    def log_message(self, *a):
        pass

ThreadingHTTPServer.daemon_threads = True
ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
