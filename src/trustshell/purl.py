import click
import httpx
import logging

from rich.console import Console
from rich.theme import Theme

from trustshell import (
    AUTH_ENABLED,
    TRUSTIFY_URL,
    check_or_get_access_token,
    print_version,
    config_logging,
)
from trustshell.products import LATEST_ENDPOINT


custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")

PURL_BASE_ENDPOINT = f"{TRUSTIFY_URL}purl/base"


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
@click.option("--all-versions", "-a", is_flag=True, help="Include all versions")
@click.argument(
    "component",
    type=click.STRING,
)
def search(component: str, all_versions: bool, debug: bool):
    """Search for a component in Trustify"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}

    purls = _query_trustify_packages(component, auth_header)
    # if all_versions:
    #     purls_with_version = _latest_package_versions(purls, auth_header)
    #     console.print(
    #         "Found these matching packages in Trustify, including the highest version found:"
    #     )
    #     for package_summary, package_details in purls_with_version.items():
    #         console.print(f"{package_summary}@{package_details[0].string}")
    # else:
    console.print("Found these matching packages in Trustify:")
    for purl in purls:
        console.print(purl)


def _query_trustify_packages(component: str, auth_header: dict[str, str]) -> list[str]:
    """
    Given a search string 'component' use the Trustify PURL Base endpoint to find packages in PURL
    format matching the given package. Accepts requests such as k8s.io/api that have both a PURL
    namespace and name.
    """
    package_query = {"q": f"purl~{component}"}
    console.print(f"Querying Trustify for packages matching {component}")
    package_response = httpx.get(
        LATEST_ENDPOINT, params=package_query, headers=auth_header, timeout=300
    )
    package_response.raise_for_status()
    package_result = package_response.json()
    if len(package_result["items"]) == 0:
        console.print(f"No packages found for {component}")
    return [item["purl"] for item in package_result["items"]]
