"""TV-EYE Self-Test Lab: a tiny intentionally-vulnerable web app on localhost.

This server exists ONLY so you can verify TV-EYE's scanners work correctly,
with zero external traffic. It listens on 127.0.0.1 only. Everything in it is
fake data. Start it with start_lab() and stop it with stop_lab().
"""

import json
import threading
import urllib.parse
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_ENV = "DB_HOST=127.0.0.1\nDB_USER=fakeuser\nDB_PASS=fakepassword123\nAPI_KEY=FAKE-not-a-real-key\n"

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>TV-EYE Lab</title>
<script src="/app.js"></script>
<link rel="stylesheet" href="/style.css">
</head><body>
<h1>TV-EYE Self-Test Lab</h1>
<p>This is a safe local target for testing TV-EYE. Built by Mr_TV.</p>
<a href="/search?q=hello">search</a>
<a href="/item?id=3">item</a>
<a href="/view?page=about">view</a>
<form action="/login" method="post">
  <input name="username" type="text">
  <input name="password" type="password">
  <input type="submit">
</form>
<!-- TODO: remove admin panel before production -->
</body></html>
"""

APP_JS = """
// lab app js (fake secrets for scanner validation)
var config = {
  apiKey: "AKIAIOSFODNN7EXAMPLE",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  internalUrl: "http://10.0.0.42:8080/internal",
  password: "SuperSecretLabValue123"
};
console.log("lab app loaded");
"""


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence request logging

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "TV-EYE-Lab/1.0 (Python)")
        self.send_header("Set-Cookie", "labsession=abc123")
        self.send_header("Access-Control-Allow-Origin", "*")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif path == "/style.css":
            self._send(200, "body{background:#111;color:#eee}", "text/css")
        elif path == "/search":
            q = qs.get("q", "")
            # intentionally reflects raw (reflected XSS lab behavior)
            self._send(200, "<html><body>Results for: %s</body></html>" % q)
        elif path == "/item":
            item_id = qs.get("id", "")
            if "'" in item_id or '"' in item_id or "UNION" in item_id.upper() \
                    or " OR " in item_id.upper() or "--" in item_id:
                self._send(200, "<html><body>Warning: mysql error: you have an "
                                "error in your SQL syntax near '%s'</body></html>" % item_id)
            else:
                self._send(200, "<html><body>Item page for id %s (name: Lab Item)</body></html>" % item_id)
        elif path == "/view":
            page = qs.get("page", "")
            if "etc/passwd" in page:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\n"
                                "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n")
            elif "win.ini" in page:
                self._send(200, "[fonts]\n[extensions]\n")
            else:
                self._send(200, "<html><body>Page: %s</body></html>" % page)
        elif path == "/template":
            name = qs.get("name", "")
            rendered = name
            for expr, out in (("{{7*7}}", "49"), ("${7*7}", "49"),
                              ("<%= 7*7 %>", "49"), ("#{7*7}", "49")):
                if expr in name:
                    rendered = name.replace(expr, out)
            self._send(200, "<html><body>Hello %s</body></html>" % rendered)
        elif path == "/redirect":
            nxt = qs.get("next", "/")
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/.env" or path == "/env":
            self._send(200, FAKE_ENV, "text/plain")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /.env\n",
                       "text/plain")
        elif path == "/admin":
            self._send(200, "<html><body><h1>Lab Admin Panel</h1></body></html>")
        elif path == "/graphql":
            self.do_POST()
        elif path == "/gqlid":
            self._send(200, "lab")
        else:
            self._send(404, "<html><body>404 - not found in lab</body></html>")

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if parsed.path == "/login":
            if "username=tveyeowner&password=labpass" in urllib.parse.unquote_plus(body):
                self._send(200, "<html><body>Welcome back, owner!</body></html>")
            else:
                self._send(200, "<html><body>Login failed: bad credentials</body></html>")
        elif parsed.path == "/graphql":
            try:
                data = json.loads(body)
            except ValueError:
                self._send(400, '{"errors":[{"message":"invalid json"}]}',
                           "application/json")
                return
            q = data.get("query", "")
            if "__schema" in q:
                self._send(200, json.dumps(
                    {"data": {"__schema": {"queryType": {"name": "Query"}}}}),
                    "application/json")
            elif "__typename" in q:
                self._send(200, '{"data":{"__typename":"Query"}}', "application/json")
            elif "__typenamexyz" in q:
                self._send(200, '{"errors":[{"message":"Cannot query field '
                                '__typenamexyz. Did you mean __typename?"}]}',
                           "application/json")
            else:
                self._send(200, '{"data":{}}', "application/json")
        else:
            self._send(404, '{"error":"unknown lab path"}', "application/json")


class LabServer(object):
    def __init__(self, port=0):
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), LabHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
