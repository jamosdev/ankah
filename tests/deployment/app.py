"""Isolated application returning the exact path and received forwarding headers."""
import http.server
import json
import os
from pathlib import Path
import time


class Application(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            Path("/tmp/slow-started").touch()
            time.sleep(2)
        body = json.dumps({"application": True, "path": self.path,
                           "headers": dict(self.headers)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.ThreadingHTTPServer((os.environ.get("APP_BIND", "0.0.0.0"),
                                int(os.environ.get("APP_PORT", "8001"))),
                               Application).serve_forever()
