"""Mock GCE metadata server for local dev.

Lets the Rust `google-cloud-auth` MDS path produce *some* Bearer token so that
`zk-verifier` can use the same Application-Default-Credentials code path in
dev as it does in production. fake-gcs-server does not validate the token, so
the value here is arbitrary.

Pointed at by `GCE_METADATA_HOST=mock-gce-metadata:8080` on the zk-verifier
service in docker-compose.yml. **Not** for any other use.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = {"access_token": "mock", "expires_in": 3600, "token_type": "Bearer"}
SA_EMAIL = b"mock-sa@example.iam.gserviceaccount.com"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # Required header; ADC clients reject responses without it.
        self.send_header("Metadata-Flavor", "Google")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path.endswith("/token"):
            self._send(200, json.dumps(TOKEN).encode(), "application/json")
        elif "/service-accounts/" in self.path:
            # Catch-all for SA-info paths (email, scopes, identity, etc.).
            self._send(200, SA_EMAIL, "text/plain")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args) -> None:
        # Quiet by default; uncomment for debugging endpoint coverage.
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
