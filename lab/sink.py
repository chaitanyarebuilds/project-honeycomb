"""Lab stand-in for a server on the internet. It records what it is sent and nothing else.

``/_count`` tells the lab runner how many requests arrived, so a scenario can prove that
nothing got through. ``/health`` is not counted.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

received: list[str] = []


class Handler(BaseHTTPRequestHandler):
    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 1_000_000))
        if self.path == "/_count":
            body = json.dumps({"requests": len(received)}).encode()
        else:
            if self.path != "/health":
                received.append(f"{self.command} {self.path}")
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = _answer

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
