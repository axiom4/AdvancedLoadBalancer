#!/usr/bin/env python3
"""
Lightweight high-concurrency multi-threaded HTTP server for ADLB load testing.
Usage:
    python3 tools/mock_server.py [port]
"""

import sys
import signal
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class BenchmarkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        body = f"Hello from Python backend on port {port}\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend-Port", str(port))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    # Disable stdout logging on each request for maximum throughput
    def log_message(self, format, *args):
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    server = ThreadingHTTPServer(("0.0.0.0", port), BenchmarkHandler)
    server.daemon_threads = True

    print(f"\033[1;32m[MOCK BACKEND]\033[0m Multi-threaded HTTP server running on http://127.0.0.1:{port} (Ctrl+C to stop)")

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[1;33m[STOPPED]\033[0m Server shutting down.")

if __name__ == "__main__":
    main()

