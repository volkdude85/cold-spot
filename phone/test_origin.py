#!/usr/bin/env python3
"""Test origin for the gate: serves a fixed-size blob and echoes request headers."""
import http.server
import os
import socketserver
import sys

SIZE = 1024 * 1024
BLOB = b"x" * SIZE
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "origin.log")


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        ua = self.headers.get("User-Agent", "-")
        with open(LOG, "a") as f:
            f.write(f"{self.client_address[0]} {self.path} UA={ua}\n")
        if self.path.startswith("/blob"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(BLOB)))
            self.end_headers()
            self.wfile.write(BLOB)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            body = f"ua={ua}\n".encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    S(("0.0.0.0", port), H).serve_forever()
