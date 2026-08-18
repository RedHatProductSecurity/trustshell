import time
import importlib.metadata
import logging
import os
import sys
from urllib.parse import urlparse, urlunparse, quote, parse_qs, urlencode
from typing import Optional, Any

import httpx
import jwt
from packageurl import PackageURL
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
import webbrowser
from univers.versions import RpmVersion
from anytree import Node, RenderTree

from http.server import BaseHTTPRequestHandler, HTTPServer

from trustshell.oidc.oidc_pkce_authcode import (
    LOCAL_SERVER_PORT,
    REDIRECT_URI,
    build_url,
    code_to_token,
    gen_things,
    get_client_credentials_token,
)

CONFIG_DIR = os.path.expanduser(
    os.getenv("TRUSTSHELL_SCRATCH", "~/.config/trustshell/")
)
os.makedirs(CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(CONFIG_DIR, "access_token.jwt")
HEADLESS = "DISPLAY" not in os.environ
LOCAL_AUTH_SERVER_PORT: str = ""
if "LOCAL_AUTH_SERVER_PORT" in os.environ:
    LOCAL_AUTH_SERVER_PORT = os.getenv("LOCAL_AUTH_SERVER_PORT", "")


TRUSTIFY_API_VERSION = os.getenv("TRUSTIFY_API_VERSION", "v3")
TRUSTIFY_URL_PATH = f"/api/{TRUSTIFY_API_VERSION}/"
if "TRUSTIFY_URL" in os.environ:
    url_env = os.getenv("TRUSTIFY_URL", "")
    parsed_url = urlparse(url_env)
    if not parsed_url.path or parsed_url.path != TRUSTIFY_URL_PATH:
        TRUSTIFY_URL = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, TRUSTIFY_URL_PATH, "", "", "")
        )
    else:
        TRUSTIFY_URL = url_env
    AUTH_ENABLED = bool(os.getenv("AUTH_ENDPOINT"))
else:
    TRUSTIFY_URL = f"http://localhost:8080/api/{TRUSTIFY_API_VERSION}/"
    AUTH_ENABLED = False

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
version = importlib.metadata.version("trustshell")
logger = logging.getLogger("trustshell")


def print_version(ctx: Any, param: Any, value: Any) -> None:
    if not value or ctx.resilient_parsing:
        return
    console.print(f"Current version: {version}")
    ctx.exit()


def config_logging(level: str = "INFO") -> None:
    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"

    # Log to stderr
    rich_handler = RichHandler(console=Console(stderr=True))
    logging.basicConfig(
        level=level,
        format=message_format,
        datefmt="[%X]",
        handlers=[rich_handler],
    )

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


def build_node_purl(
    purls: list[str], show_versions: bool = False
) -> Optional[PackageURL]:
    """
    Generate a base purl with a version or tag qualifier from a list of purls with homogenous
    type/namespace, and name

    Parameters:
    purls (list[str]): A list of purls.

    Returns:
    Optional[PackageURL]: A PackageURL object or None
    """
    node_purls, type = _build_node_names_by_type(purls, show_versions)
    if not node_purls:
        return None
    elif len(node_purls) > 1:
        if type == "oci":
            purl_tags: dict[str, PackageURL] = {}
            for purl in node_purls:
                qualifiers = purl.qualifiers
                if qualifiers and isinstance(qualifiers, dict) and "tag" in qualifiers:
                    purl_tags[qualifiers["tag"]] = purl
            if purl_tags:
                sorted_purls = sorted(
                    purl_tags.keys(), key=lambda x: RpmVersion(x), reverse=True
                )
                return purl_tags[sorted_purls[0]]
        else:
            console.print(f"multiple node purls found: {node_purls}", style="warning")
    return node_purls.pop()


def _build_node_names_by_type(
    purls: list[str], show_versions: bool
) -> tuple[set[PackageURL], str]:
    """
    Given some purl strings, return a unique set of base purls with versions or tag qualifiers
    """
    types = set()
    node_purls: dict[PackageURL, str] = {}
    for purl in purls:
        purl_obj = PackageURL.from_string(purl)
        tag = get_tag_from_purl(purl_obj)
        base_purl = _remove_qualifiers(purl_obj, tag, show_versions)
        node_purls[base_purl] = purl_obj.type
    types = set(node_purls.values())
    if not types:
        return (set(), "")
    if len(types) > 1:
        console.print("Non homogenous types when calculating node name", style="error")
        sys.exit(1)
    return set(node_purls.keys()), types.pop()


def _remove_qualifiers(purl: PackageURL, tag: str, show_versions: bool) -> PackageURL:
    """Remove all qualifiers from a purl keeping repository_url, optionally setting a tag"""
    qualifiers = {}
    if purl.type == "oci" and "repository_url" in purl.qualifiers:
        # remove other oci qualifiers, but keep repository_url in order to record namespace
        qualifiers["repository_url"] = purl.qualifiers["repository_url"]
    elif purl.type == "maven" and purl.qualifiers:
        qualifiers = purl.qualifiers
        # repository_url is superfluous for maven purls, remove it in the interest of brevity
        qualifiers.pop("repository_url", None)
    version = ""
    if tag:
        qualifiers["tag"] = tag
    elif show_versions and purl.version:
        version = purl.version
    return PackageURL(
        type=purl.type,
        name=purl.name,
        namespace=purl.namespace,
        version=version,
        qualifiers=qualifiers,
    )


def purl_sans_version(purl: PackageURL) -> PackageURL:
    """Return a copy of the purl with version set to empty string"""
    purl_data = purl.to_dict()
    purl_data["version"] = ""
    purl_sans_version = PackageURL(**purl_data)
    return purl_sans_version


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


def local_http_server(code_challenge: str, state: str) -> str:
    logger.info(
        f"Starting the local web server on {LOCAL_SERVER_PORT}. Your web browser will send the code"
        " to it."
    )

    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
        code: str  # Class variable to store the code

        def do_GET(self) -> None:
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

        def log_message(self, format: str, *args: Any) -> None:
            logger.info("Received response from Auth Server")

    httpd = HTTPServer(("localhost", LOCAL_SERVER_PORT), SimpleHTTPRequestHandler)

    launch_browser(code_challenge, state)
    httpd.handle_request()
    logger.debug(
        f"Local web server got this code from your browser: {SimpleHTTPRequestHandler.code}"
    )
    return SimpleHTTPRequestHandler.code


def get_access_token() -> str:
    # Client credentials flow: no browser or callback URL required
    if cc_token := get_client_credentials_token():
        return cc_token
    if HEADLESS or LOCAL_AUTH_SERVER_PORT:
        logger.debug(
            f"Running in HEADLESS mode, trying OIDC PKCE flow with {REDIRECT_URI}"
        )
        # Use an existing refresh token to get a new access token
        response = httpx.get(REDIRECT_URI)
        response.raise_for_status()
        response_data = response.json()
        if "access_token" in response_data:
            return str(response_data["access_token"])
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


def launch_browser(code_challenge: str, state: str) -> None:
    url = build_url(code_challenge, state)
    logger.debug(
        f"Launching your browser to go to {url}.  "
        f"Code will be returned to the script spawned local http server via redirect_uri"
    )
    webbrowser.open(url)


def paginated_trustify_query(
    endpoint: str,
    base_params: dict[str, Any],
    auth_header: dict[str, str],
    component_name: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """
    Perform a paginated query to a Trustify API endpoint using sequential requests.

    Args:
        endpoint: The API endpoint URL
        base_params: Base query parameters (will add limit/offset)
        auth_header: Authentication headers
        component_name: Component name for progress messages (optional)
        limit: Number of items per request

    Returns:
        dict with 'items' and 'total' keys containing all paginated results
    """

    def make_request_with_retry(
        client: httpx.Client, query_params: dict[str, Any], headers: dict[str, str]
    ) -> httpx.Response:
        """Make HTTP request with 401 retry logic"""
        if logger.isEnabledFor(logging.DEBUG):
            full_url = (
                f"{endpoint}?{urlencode(query_params)}" if query_params else endpoint
            )
            logger.debug(f"Request URL: {full_url}")

        try:
            response = client.get(
                endpoint, params=query_params, headers=headers, timeout=2400
            )
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and AUTH_ENABLED:
                # Get new access token and retry once
                logger.debug("Got 401 response, refreshing access token...")
                new_access_token = get_access_token()
                if new_access_token:
                    headers["Authorization"] = f"Bearer {new_access_token}"
                    response = client.get(
                        endpoint, params=query_params, headers=headers, timeout=300
                    )
                    response.raise_for_status()
                    return response
            raise

    with httpx.Client() as client:
        # First request to get total count
        query_params = {**base_params, "limit": limit, "offset": 0}
        first_response = make_request_with_retry(client, query_params, auth_header)
        first_result = first_response.json()

        all_items = first_result.get("items", [])
        total_available = first_result.get("total")
        total_known = total_available is not None

        if not all_items and (not total_known or total_available == 0):
            if component_name:
                console.print(f"No items found for {component_name}")
            return {"items": [], "total": 0}

        if total_known:
            total_pages = (total_available + limit - 1) // limit
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"Paginated request: {total_available} total items, "
                    f"{total_pages} page(s), page 1/{total_pages} complete"
                )
        else:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"Paginated request: total unknown, "
                    f"page 1 returned {len(all_items)} items"
                )

        offset = limit
        page_num = 2
        while True:
            if total_known and offset >= total_available:
                break
            if not total_known and len(all_items) - (offset - limit) < limit:
                break

            page_params = {**base_params, "limit": limit, "offset": offset}
            if logger.isEnabledFor(logging.DEBUG):
                if total_known:
                    total_pages = (total_available + limit - 1) // limit
                    logger.debug(
                        f"Fetching page {page_num}/{total_pages} (offset {offset})..."
                    )
                else:
                    logger.debug(
                        f"Fetching page {page_num} (offset {offset})..."
                    )
            try:
                response = make_request_with_retry(client, page_params, auth_header)
                result = response.json()
                page_items = result.get("items", [])
                all_items.extend(page_items)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        f"Page {page_num} complete "
                        f"({len(all_items)} items so far)"
                    )
                if not page_items or len(page_items) < limit:
                    break
                offset += limit
                page_num += 1
            except Exception as e:
                logger.error(f"Error fetching page at offset {offset}: {e}")
                break

        total_count = total_available if total_known else len(all_items)
        if component_name:
            console.print(
                f"Retrieved {len(all_items)} items out of {total_count} total for {component_name}"
            )

        return {"items": all_items, "total": total_count}


def render_tree_to_string(root: Node) -> str:
    """Return tree as string (for testing and composition)."""
    return "\n".join(f"{pre}{node.name}" for pre, _, node in RenderTree(root))


def render_tree(root: Node) -> None:
    """Pretty print a tree using name only"""
    console.print(render_tree_to_string(root))
