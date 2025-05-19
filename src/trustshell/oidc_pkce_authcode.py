#!/usr/bin/env python

import json
import logging
import os
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import (
    parse_qs,
    urlparse,
)

import urllib.parse

import jwt
import pkce
import httpx

logger = logging.getLogger("trustshell")
client_id = "atlas-frontend"
# this script will spawn an HTTP server to capture the code your browser gets from the SSO server
local_server_port = 8650
redirect_uri = "http://localhost:" + str(local_server_port) + "/index.html"
# other oidc things you generally shouldnt have to touch
scope = "openid"
code_challenge_mehtod = "S256"
response_type = "code"
grant_type = "authorization_code"

auth_endpoint = os.getenv("AUTH_ENDPOINT")

authz_endpoint = f"{auth_endpoint}/auth"
token_endpoint = f"{auth_endpoint}/token"


def gen_things():
    logging.debug("Generating verifier, challenge, state")
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    logging.debug(f"Code Verifier: {code_verifier}")
    logging.debug(f"Code Challenge: {code_challenge}")
    logging.debug(f"state: {state}")
    return code_verifier, code_challenge, state


def local_http_server(code_challenge, state):
    logger.info(
        f"Starting the local web server on {local_server_port}. Your web browser will send the code"
        " to it."
    )

    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            SimpleHTTPRequestHandler.code = parse_qs(urlparse(self.path).query)["code"][
                0
            ]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            # if debug:
            #    print(f"Path your browser hit on the local web server: {self.path}")
            #    print(f"Code the local webserver found: {SimpleHTTPRequestHandler.code}")
            self.wfile.write(b"<html><h2>You may now return to psirt_cli</h2></html>\n")

        def log_message(self, format, *args):
            logger.info("Received response from Auth Server")

    httpd = HTTPServer(("localhost", local_server_port), SimpleHTTPRequestHandler)
    launch_browser(code_challenge, state)
    httpd.handle_request()
    logger.debug(
        f"Local web server got this code from your browser: {SimpleHTTPRequestHandler.code}"
    )
    return SimpleHTTPRequestHandler.code


def launch_browser(code_challenge, state):
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_mehtod,
        "state": state,
    }
    encoded_params = urllib.parse.urlencode(params)
    url = f"{authz_endpoint}?{encoded_params}"
    logger.debug(
        f"Launching your browser to go to {url}.  "
        f"Code will be returned to the script spawned local http server via redirect_uri"
    )
    webbrowser.open(url)


def code_to_token(code, code_verifier):
    logger.debug(
        "Exchanging the code for a token via http calls inside of this script."
    )
    data = {
        "grant_type": grant_type,
        "client_id": client_id,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    c2t = httpx.post(url=token_endpoint, data=data)
    c2t_json = json.loads(c2t.text)
    access_token = c2t_json["access_token"]
    refresh_token = c2t_json["refresh_token"]
    id_token = c2t_json["id_token"]
    # print_web_request(c2t)
    logger.debug("Each raw part of the response body:")
    for k, v in c2t_json.items():
        logger.debug(f"{k}:{v}")
    logger.debug("User readable access_token:")
    logger.debug(
        json.dumps(
            jwt.decode(access_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug("User readable refresh_token:")
    logger.debug(
        json.dumps(
            jwt.decode(refresh_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug("User readable id_token:")
    logger.debug(
        json.dumps(
            jwt.decode(id_token, options={"verify_signature": False}),
            indent=4,
            sort_keys=True,
        )
    )
    logger.debug(f"Access Token: {access_token}")
    return access_token, refresh_token, id_token


def get_access_token():
    # code verifier, code_challenge are part of PKCE standard.  state is a CSRF prevention.
    code_verifier, code_challenge, state = gen_things()
    # launch the local web server.  then launch a browser that auths you and sends the code to the
    # local web server.
    code = local_http_server(code_challenge, state)
    # swap the code for a token via http calls inside of this script
    access_token, _, _ = code_to_token(code, code_verifier)
    return access_token


def get_fresh_token(refresh_token):
    logger.debug(
        "Exchange the refresh token for a new access token via http calls inside of this script."
    )
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    r2a = httpx.post(url=token_endpoint, data=data)
    r2a_json = json.loads(r2a.text)
    access_token = r2a_json["access_token"]
    refresh_token = r2a_json["refresh_token"]

    logger.debug("Each raw part of the response body:")
    for k, v in r2a_json.items():
        logger.debug(f"{k}:{v}")
    else:
        logger.debug(f"Access Token: {access_token}")
    return access_token, refresh_token
