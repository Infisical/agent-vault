#!/usr/bin/env python3
"""A deliberately tiny logging HTTP proxy — the "corporate egress proxy" stand-in.

The demo needs something that (a) speaks enough proxy protocol for the broker
to route through it and (b) leaves a durable trace proving a request actually
transited this process. Real egress proxies do policy enforcement here; this
one just appends a line per request to a log file.

Supported request forms:

  * absolute-form ``http://host/path`` (what an HTTP forward proxy receives)
  * ``CONNECT host:port`` (tunnelled verbatim, used by HTTPS upstreams)

Usage:

    python3 egress_proxy.py <listen-port> <log-path>
"""

import select
import socket
import socketserver
import sys
import threading
from http.client import HTTPConnection
from urllib.parse import urlsplit, urlunsplit

# Hop-by-hop headers must never be forwarded, and Proxy-Authorization belongs
# to the broker<->proxy hop rather than the proxy<->target hop.
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline()
        if not request_line:
            return
        parts = request_line.decode("latin-1").split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]

        headers = self._read_headers()

        if method == "CONNECT":
            self._tunnel(target)
        else:
            self._forward(method, target, headers)

    # ---- request parsing ----

    def _read_headers(self):
        headers = []
        while True:
            line = self.rfile.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            name, sep, value = line.decode("latin-1").partition(":")
            if sep:
                headers.append((name.strip(), value.strip()))
        return headers

    # ---- CONNECT: raw bidirectional tunnel ----

    def _tunnel(self, target):
        host, _, port = target.partition(":")
        try:
            upstream = socket.create_connection((host, int(port or 443)), timeout=10)
        except OSError as exc:
            self._log("CONNECT", target, f"failed: {exc}")
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        self._log("CONNECT", target, "tunnelled")
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()

        socks = [self.connection, upstream]
        try:
            while True:
                readable, _, errored = select.select(socks, [], socks, 30)
                if errored:
                    break
                if not readable:
                    break
                done = False
                for src in readable:
                    dst = upstream if src is self.connection else self.connection
                    chunk = src.recv(65536)
                    if not chunk:
                        done = True
                        break
                    dst.sendall(chunk)
                if done:
                    break
        finally:
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass

    # ---- absolute-form requests ----

    def _forward(self, method, target, headers):
        parts = urlsplit(target)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not host:
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        body_len = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
        body = self.rfile.read(body_len) if body_len else b""

        forward_headers = {
            k: v for k, v in headers if k.lower() not in HOP_BY_HOP
        }
        forward_headers["Host"] = parts.netloc

        origin_form = urlunsplit(("", "", parts.path or "/", parts.query, ""))

        try:
            conn = HTTPConnection(host, port, timeout=10)
            conn.request(method, origin_form, body=body or None, headers=forward_headers)
            resp = conn.getresponse()
            payload = resp.read()

            status_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode()
            out_headers = [
                f"{k}: {v}\r\n".encode()
                for k, v in resp.getheaders()
                if k.lower() not in HOP_BY_HOP
            ]
            self._log(method, target, str(resp.status))
            self.wfile.write(status_line)
            for line in out_headers:
                self.wfile.write(line)
            self.wfile.write(f"Content-Length: {len(payload)}\r\n".encode())
            self.wfile.write(b"Connection: close\r\n\r\n")
            self.wfile.write(payload)
            self.wfile.flush()
        except OSError as exc:
            self._log(method, target, f"failed: {exc}")
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ---- evidence ----

    def _log(self, method, target, outcome):
        with open(self.server.log_path, "a", encoding="utf-8") as fh:
            fh.write(f"{method} {target} -> {outcome}\n")


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port, log_path):
        self.log_path = log_path
        super().__init__(("127.0.0.1", port), Handler)


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip())
        sys.exit(2)
    port, log_path = int(sys.argv[1]), sys.argv[2]

    open(log_path, "w", encoding="utf-8").close()
    print(f"egress proxy listening on 127.0.0.1:{port} (logging to {log_path})", flush=True)
    with Proxy(port, log_path) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
