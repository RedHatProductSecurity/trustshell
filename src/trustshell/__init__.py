import time
import importlib.metadata
import logging
import os
from urllib.parse import urlparse, urlunparse, quote, parse_qs

import httpx
import jwt
from packageurl import PackageURL
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
import webbrowser

from http.server import BaseHTTPRequestHandler, HTTPServer

from trustshell.oidc.oidc_pkce_authcode import (
    LOCAL_SERVER_PORT,
    REDIRECT_URI,
    build_url,
    code_to_token,
    gen_things,
)

CONFIG_DIR = os.path.expanduser("~/.config/trustshell/")
os.makedirs(CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(CONFIG_DIR, "access_token.jwt")
HEADLESS = "DISPLAY" not in os.environ
LOCAL_AUTH_SERVER_PORT = ""
if "LOCAL_AUTH_SERVER_PORT" in os.environ:
    LOCAL_AUTH_SERVER_PORT = os.getenv("LOCAL_AUTH_SERVER_PORT")


TRUSTIFY_URL_PATH = "/api/v2/"
if "TRUSTIFY_URL" in os.environ:
    url_env = os.getenv("TRUSTIFY_URL")
    parsed_url = urlparse(url_env)
    if not parsed_url.path or parsed_url.path != TRUSTIFY_URL_PATH:
        TRUSTIFY_URL = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, TRUSTIFY_URL_PATH, "", "", "")
        )
    else:
        TRUSTIFY_URL = url_env
    AUTH_ENABLED = True
else:
    TRUSTIFY_URL = "http://localhost:8080/api/v2/"
    AUTH_ENABLED = False

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
version = importlib.metadata.version("trustshell")
logger = logging.getLogger("trustshell")


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    console.print(f"Current version: {version}")
    ctx.exit()


def config_logging(level="INFO"):
    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
    logging.basicConfig(
        level=level, format=message_format, datefmt="[%X]", handlers=[RichHandler()]
    )

    logging.basicConfig(level=level)
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    httpx_logger.setLevel("WARNING")
    if level == "DEBUG":
        httpx_logger.setLevel("INFO")
        httpcore_logger.setLevel("INFO")


def urlencoded(base_purl: str) -> str:
    """urlencode a string, excluding the slash character"""
    return quote(base_purl, safe="")


def get_tag_from_purl(purl: PackageURL) -> str:
    """Extract tag from OCI purl"""
    tag = ""
    if purl.type != "oci":
        return tag
    qualifiers = purl.qualifiers
    if isinstance(qualifiers, dict) and "tag" in qualifiers:
        tag = qualifiers["tag"]
    else:
        logger.debug(f"Did not find tag qualifier in {purl.to_string()}")
    return tag


def check_or_get_access_token() -> str:
    if not os.path.exists(TOKEN_FILE):
        logger.debug("Access token not found. Getting a new one...")
        access_token = _get_and_store_access_token()
    else:
        logger.debug("Access token found. Checking its validity...")
        with open(TOKEN_FILE, "r") as f:
            stored_token = f.read().strip()
        try:
            decoded_token = jwt.decode(
                stored_token, options={"verify_signature": False}
            )
            if int(time.time()) > decoded_token["exp"]:
                logger.debug("Access token is expired. Getting a new one...")
                access_token = _get_and_store_access_token()
            else:
                logger.debug("Access token is valid.")
                access_token = stored_token
        except jwt.ExpiredSignatureError:
            logger.debug("Access token is expired. Getting a new one...")
            access_token = _get_and_store_access_token()
        except jwt.InvalidTokenError:
            logger.debug("Access token is invalid. Getting a new one...")
            access_token = _get_and_store_access_token()
    if not access_token:
        console.print(
            "Unable to authenticate to Atlas, please try again after authenticating in the browser."
        )
        exit(0)
    return access_token


def _get_and_store_access_token() -> str:
    access_token = get_access_token()
    if not access_token:
        return ""
    with open(TOKEN_FILE, "w") as f:
        f.write(access_token)
        os.chmod(TOKEN_FILE, 0o600)
    return access_token


def local_http_server(code_challenge, state):
    logger.info(
        f"Starting the local web server on {LOCAL_SERVER_PORT}. Your web browser will send the code"
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
            self.wfile.write(
                b"<html><h2>You may now return to trustshell</h2></html>\n"
            )

        def log_message(self, format, *args):
            logger.info("Received response from Auth Server")

    httpd = HTTPServer(("localhost", LOCAL_SERVER_PORT), SimpleHTTPRequestHandler)

    launch_browser(code_challenge, state)
    httpd.handle_request()
    logger.debug(
        f"Local web server got this code from your browser: {SimpleHTTPRequestHandler.code}"
    )
    return SimpleHTTPRequestHandler.code


def get_access_token():
    if HEADLESS or LOCAL_AUTH_SERVER_PORT:
        logger.debug(
            f"Running in HEADLESS mode, trying OIDC PKCE flow with {REDIRECT_URI}"
        )
        # Use an existing refresh token to get a new access token
        response = httpx.get(REDIRECT_URI)
        response.raise_for_status()
        response_data = response.json()
        if "access_token" in response_data:
            return response_data["access_token"]
        code_challenge = response_data["code_challenge"]
        state = response_data["state"]
        auth_server = response_data["auth_server"]
        url = build_url(code_challenge, state, auth_server)
        console.print("Open a webbrowser and go to:")
        print(url)
        return ""
    # code verifier, code_challenge are part of PKCE standard.  state is a CSRF prevention.
    code_verifier, code_challenge, state = gen_things()
    # Check if the local web server is running. If it's not, launch it
    # launch the local web server.  then launch a browser that auths you and sends the code to the
    # local web server.

    code = local_http_server(code_challenge, state)
    # swap the code for a token via http calls inside of this script
    access_token, _, _ = code_to_token(code, code_verifier)
    return access_token


def launch_browser(code_challenge, state):
    url = build_url(code_challenge, state)
    logger.debug(
        f"Launching your browser to go to {url}.  "
        f"Code will be returned to the script spawned local http server via redirect_uri"
    )
    webbrowser.open(url)
