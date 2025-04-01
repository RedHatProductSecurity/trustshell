import click
import httpx
import logging
from rich.console import Console
from rich.theme import Theme

from trustshell import print_version, config_logging

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("psirt_cli")

ATLAS_2_URL = "http://localhost:8080/api/v2/"
PURL_BASE_ENDPOINT = f"{ATLAS_2_URL}purl/base"
ANALYSIS_ENDPOINT = f"{ATLAS_2_URL}analysis/component"
MAX_I64 = 2**63 - 1


@click.command()
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
@click.argument(
    "component",
    type=click.STRING,
)
def search(component: str, debug: bool):
    """Search for a component in Trustify"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    purls = _query_trustify_packages(component)
    console.print(purls)

def _query_trustify_packages(component: str) -> list[str]:
    """
    Given a search string 'component' use the Trustify PURL Base endpoint to find packages in PURL
    format matching the given package. Accepts requests such as k8s.io/api that have both a PURL
    namespace and name.
    """
    package_query = {"q": component}
    console.print(f"Querying Trustify for packages matching {component}")
    package_response = httpx.get(PURL_BASE_ENDPOINT, params=package_query)
    package_response.raise_for_status()
    package_result = package_response.json()
    if len(package_result["items"]) == 0:
        console.print(f"No packages found for {component}")
    return [item["purl"] for item in package_result["items"]]