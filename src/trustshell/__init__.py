import time
import importlib.metadata
import logging
import os
import urllib
from urllib.parse import urlparse, urlunparse

import jwt
from packageurl import PackageURL
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from trustshell.oidc_pkce_authcode import get_access_token

CONFIG_DIR = os.path.expanduser("~/.config/trustshell/")
os.makedirs(CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(CONFIG_DIR, "access_token.jwt")

TRUSTIFY_URL_PATH = "/api/v2/"
if "TRUSTIFY_URL" in os.environ:
    url_env = os.getenv("TRUSTIFY_URL")
    parsed_url = urlparse(url_env)
    if not parsed_url.path or parsed_url.path != TRUSTIFY_URL_PATH:
        TRUSTIFY_URL = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, TRUSTIFY_URL_PATH, "", "", "")
        )
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
    return urllib.parse.quote(base_purl, safe="")


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
            access_token = _get_and_store_access_token
    return access_token


def _get_and_store_access_token() -> str:
    access_token = get_access_token()
    with open(TOKEN_FILE, "w") as f:
        f.write(access_token)
        os.chmod(TOKEN_FILE, 0o600)
    return access_token
