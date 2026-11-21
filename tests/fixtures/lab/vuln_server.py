"""Deliberately vulnerable lab page for Stage 2 validation. Local use only.

Known by construction:
  /item?id=<value>   SQL injection in `id` (string concatenated into a SQLite query)
  /reflect?q=<value> Reflected XSS in `q` (value written into HTML unescaped)

Binds to 127.0.0.1 only. Never expose this server beyond the lab.
"""

from __future__ import annotations

import argparse
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("create table items (id integer primary key, name text)")
    conn.executemany("insert into items values (?, ?)", [(1, "widget"), (2, "gadget")])
    return conn


DB = _database()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # keep test output quiet
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        url = urlparse(self.path)
        params = parse_qs(url.query)
        if url.path == "/item":
            value = params.get("id", ["1"])[0]
            try:
                # Deliberately injectable: this is the lab SQLi under test.
                rows = DB.execute(f"select name from items where id = {value}").fetchall()  # noqa: S608
                body = "".join(f"<p>{name}</p>" for (name,) in rows)
                status = 200
            except sqlite3.Error as exc:
                body = f"<p>database error: {exc}</p>"
                status = 500
        elif url.path == "/reflect":
            q = params.get("q", [""])[0]
            body = f"<p>You searched for: {q}</p>"
            status = 200
        elif url.path == "/":
            body = '<a href="/item?id=1">item</a> <a href="/reflect?q=hello">search</a>'
            status = 200
        else:
            body = "not found"
            status = 404
        payload = f"<html><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
