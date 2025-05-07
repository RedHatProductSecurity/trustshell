import click
import httpx
import logging

from packageurl import PackageURL
from rich.console import Console
from rich.theme import Theme
from typing import Any
from univers.versions import (
    GenericVersion,
    GolangVersion,
    MavenVersion,
    PypiVersion,
    RpmVersion,
    SemverVersion,
    Version,
)

from trustshell import (
    TRUSTIFY_URL,
    get_tag_from_purl,
    print_version,
    config_logging,
    urlencoded,
)
from trustshell.oidc_pkce_authcode import get_access_token

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")

PURL_BASE_ENDPOINT = f"{TRUSTIFY_URL}purl/base"


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
@click.option("--latest_version", "-l", is_flag=True, help="Include latest versions")
@click.argument(
    "component",
    type=click.STRING,
)
def search(component: str, latest_version: bool, debug: bool):
    """Search for a component in Trustify"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    access_token, _, _ = get_access_token()
    auth_header = {"Authorization": f"Bearer {access_token}"}

    purls = _query_trustify_packages(component, auth_header)
    if latest_version:
        purls_with_version = _latest_package_versions(purls, auth_header)
        console.print(
            "Found these matching packages in Trustify, including the highest version found:"
        )
        for package_summary, package_details in purls_with_version.items():
            console.print(f"{package_summary}@{package_details[0].string}")
    else:
        console.print("Found these matching packages in Trustify:")
        for purl in purls:
            console.print(purl)


def _query_trustify_packages(component: str, auth_header: dict[str, str]) -> list[str]:
    """
    Given a search string 'component' use the Trustify PURL Base endpoint to find packages in PURL
    format matching the given package. Accepts requests such as k8s.io/api that have both a PURL
    namespace and name.
    """
    package_query = {"q": component}
    console.print(f"Querying Trustify for packages matching {component}")
    package_response = httpx.get(
        PURL_BASE_ENDPOINT, params=package_query, headers=auth_header
    )
    package_response.raise_for_status()
    package_result = package_response.json()
    if len(package_result["items"]) == 0:
        console.print(f"No packages found for {component}")
    return [item["purl"] for item in package_result["items"]]


def _latest_package_versions(
    base_purls: list[str], auth_header: dict[str, str]
) -> dict[str, tuple[Version, PackageURL]]:
    """Get the latest version from a list of purls"""
    packages: dict[str, tuple[Version, PackageURL]] = {}
    for base_purl in base_purls:
        versions = _get_package_versions(base_purl, auth_header)
        purl = PackageURL.from_string(base_purl)
        for version in versions:
            # Use lexicographic ordering for OCI once KONFLUX-6210 is resolved
            if purl.type in ("rpm", "oci"):
                typed_version = RpmVersion(version)
            elif purl.type == "maven":
                typed_version = MavenVersion(version)
            elif purl.type == "go":
                typed_version = GolangVersion(version)
            elif purl.type == "npm":
                typed_version = SemverVersion(version)
            elif purl.type == "pypi":
                typed_version = PypiVersion(version)
            else:
                typed_version = GenericVersion(version)

            if base_purl in packages:
                current_version = packages[base_purl][0]
                if current_version < typed_version:
                    packages[base_purl] = typed_version, purl
            else:
                packages[base_purl] = typed_version, purl

    return packages


def _get_package_versions(base_purl: str, auth_header: dict[str, str]) -> set[str]:
    """
    If an OCI base_purl is passed in, get it's version from purl tags. Otherwise return the
    purl versions reported by Trustify
    """

    logger.debug(f"Finding versions for {base_purl}")
    purl = PackageURL.from_string(base_purl)
    purl_versions = _lookup_base_purl(base_purl, auth_header)
    versions: set[str] = set()
    if "versions" not in purl_versions:
        return versions
    if purl.type == "oci":
        for version in purl_versions["versions"]:
            for version_purl in version.get("purls", []):
                tag = get_tag_from_purl(PackageURL.from_string(version_purl["purl"]))
                if tag:
                    versions.add(tag)
    else:
        versions = {v["version"] for v in purl_versions["versions"]}
    return versions


def _lookup_base_purl(base_purl: str, auth_header: dict[str, str]) -> dict[str, Any]:
    """Get the details of a base purl from Atlas"""
    encoded_base_purl = urlencoded(base_purl)
    # TODO use asyncio
    base_purl_response = httpx.get(
        f"{PURL_BASE_ENDPOINT}/{encoded_base_purl}", headers=auth_header
    )
    base_purl_response.raise_for_status()
    return base_purl_response.json()
