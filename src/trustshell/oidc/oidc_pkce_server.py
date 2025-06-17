import json
import os
from http.server import SimpleHTTPRequestHandler
import socketserver
from urllib.parse import (
    parse_qs,
    urlparse,
)

from oidc_pkce_authcode import code_to_token, gen_things, get_fresh_token, AUTH_ENDPOINT

PORT = int(os.getenv("LISTEN_PORT"))

# These can remain global as they are generated once and don't change
code_verifer, code_challenge, state = gen_things()


# 1. Custom HTTPServer to hold the refresh_token
class CustomHTTPServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.refresh_token = ""  # Initialize refresh_token on the server instance


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        codes = query.get("code", [])

        if not codes:
            # Check refresh_token on the server instance
            if not self.server.refresh_token:
                response_data = {
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

            response_content = json.dumps(response_data)
            response_bytes = response_content.encode("utf-8")

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

    def log_message(self, format, *args):
        # Enhanced logging for clarity
        refresh_populated = False
        if self.server.refresh_token:
            refresh_populated = True
        print(
            f"[{self.log_date_time_string()}] {self.command} {self.path} - refresh populated?: {refresh_populated}"
        )


# Use the CustomHTTPServer for your server instance
with CustomHTTPServer(("", PORT), Handler) as httpd:
    print(f"Serving HTTP on port {PORT}")
    httpd.serve_forever()
