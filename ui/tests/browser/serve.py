#!/usr/bin/env python3
"""Serve the built vault under the same Content-Security-Policy the gateway
applies to sandboxed webapp content.

A plain static server is not a faithful stand-in. The gateway sends

    default-src <origin> 'unsafe-inline' 'unsafe-eval' blob: data:;
    connect-src <origin> blob: data:

(freenet-core `sandbox_csp_for_origin`), which permits nothing from any other
host. So a CDN stylesheet, webfont, or script silently works under `dx serve`
and under a plain `http.server`, and is blocked for every real user.

That is not hypothetical: the vault shipped a `fonts.googleapis.com` @import
that had never once loaded in production. It was found by hand on 2026-08-03,
not by any test, because no test had ever loaded the page under a CSP.

Serving with the real header means the browser suite's console-is-clean
assertion catches it instead.
"""

import sys
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler


class CspHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        origin = f"http://{self.headers.get('Host', '127.0.0.1')}"
        self.send_header(
            "Content-Security-Policy",
            f"default-src {origin} 'unsafe-inline' 'unsafe-eval' blob: data:; "
            f"connect-src {origin} blob: data:",
        )
        super().end_headers()

    def log_message(self, *args):
        pass  # The harness prints what matters; request noise buries it.


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8977
    root = sys.argv[2] if len(sys.argv) > 2 else "."
    handler = partial(CspHandler, directory=root)
    HTTPServer(("127.0.0.1", port), handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
