import importlib.metadata
import logging
import urllib

from packageurl import PackageURL
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
import os

if "TRUSTIFY_URL" in os.environ:
    TRUSTIFY_URL = os.getenv("TRUSTIFY_URL")
else:
    TRUSTIFY_URL = "http://localhost:8080/api/v2/"


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
