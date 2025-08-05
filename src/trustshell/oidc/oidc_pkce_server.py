#!/usr/bin/env python3

import json
import os
from http.server import SimpleHTTPRequestHandler
import socketserver
from typing import Any
from urllib.parse import (
    parse_qs,
    urlparse,
)

try:
    # When run as part of the trustshell package
    from .oidc_pkce_authcode import (
        code_to_token,
        gen_things,
        get_fresh_token,
        AUTH_ENDPOINT,
    )
except ImportError:
    # When run as a standalone script
    from oidc_pkce_authcode import (  # type: ignore[import-not-found,no-redef]
        code_to_token,
        gen_things,
        get_fresh_token,
        AUTH_ENDPOINT,
    )

PORT: int = int(os.getenv("LISTEN_PORT", "8080"))

# These can remain global as they are generated once and don't change
code_verifer: str
code_challenge: str
state: str
code_verifer, code_challenge, state = gen_things()


# 1. Custom HTTPServer to hold the refresh_token
class CustomHTTPServer(socketserver.TCPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[SimpleHTTPRequestHandler],
        bind_and_activate: bool = True,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.refresh_token: str = ""  # Initialize refresh_token on the server instance
        self.access_token: str = ""


class Handler(SimpleHTTPRequestHandler):
    server: CustomHTTPServer  # Type hint for the server attribute

    def do_GET(self) -> None:
        query: dict[str, list[str]] = parse_qs(urlparse(self.path).query)
        codes: list[str] = query.get("code", [])
        access_token: str
        refresh_token: str

        if not codes:
            # Check refresh_token on the server instance
            if not self.server.refresh_token:
                response_data: dict[str, str] = {
                    "code_challenge": code_challenge,
                    "state": state,
                    "auth_server": AUTH_ENDPOINT,
                }
            else:
                # Use the refresh_token from the server instance to get a fresh token
                access_token, refresh_token = get_fresh_token(self.server.refresh_token)
                # Update the access_token and refresh_token on the server instance
                self.server.refresh_token = refresh_token
                response_data = {"access_token": access_token}

            response_content: str = json.dumps(response_data)
            response_bytes: bytes = response_content.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)  # Write response bytes to client
            return

        # This handles the callback with the authorization code
        # Store the access_token and refresh_token on the server instance

        access_token, refresh_token, _ = code_to_token(codes[0], code_verifer)
        self.server.access_token = access_token
        self.server.refresh_token = refresh_token

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><h2>Auth server initialized re-run the command in TrustShell</h2></html>\n"
        )

    def log_message(self, format: str, *args: Any) -> None:
        # Enhanced logging for clarity
        refresh_populated: bool = False
        if self.server.refresh_token:
            refresh_populated = True
        print(
            f"[{self.log_date_time_string()}] {self.command} {self.path} - refresh populated?: {refresh_populated}"
        )


def main() -> None:
    """Main function to start the OIDC PKCE server."""
    # Use the CustomHTTPServer for your server instance
    with CustomHTTPServer(("", PORT), Handler) as httpd:
        print(f"Serving HTTP on port {PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
