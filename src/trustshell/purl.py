import click
import httpx
import logging
from collections import defaultdict

from anytree import Node
from rich.console import Console
from rich.theme import Theme
from packageurl import PackageURL

from trustshell import (
    AUTH_ENABLED,
    TRUSTIFY_URL,
    build_node_purl,
    check_or_get_access_token,
    print_version,
    config_logging,
    get_tag_from_purl,
    render_tree,
)
from trustshell.products import LATEST_ENDPOINT


custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")

PURL_BASE_ENDPOINT = f"{TRUSTIFY_URL}purl/base"


def _create_base_purl(purl_obj: PackageURL) -> str:
    """Create a base PURL string without version and qualifiers"""
    return PackageURL(
        type=purl_obj.type,
        namespace=purl_obj.namespace,
        name=purl_obj.name,
        version="",
        qualifiers={},
    ).to_string()


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
def search(component: str, all_versions: bool, debug: bool) -> None:
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

    if all_versions:
        # Group purls by their base form (sans version) to create trees
        purl_groups = defaultdict(list)

        for purl_obj in purls:
            # Create base_key without version and qualifiers
            base_key = _create_base_purl(purl_obj)

            # Extract version or tag for the child node
            if purl_obj.type == "oci":
                tag = get_tag_from_purl(purl_obj)
                version_info = tag if tag else purl_obj.version
            else:
                version_info = purl_obj.version

            if version_info:
                purl_groups[base_key].append(version_info)

        if purl_groups:
            console.print("Found these matching packages in Trustify:")
            for base_purl, versions in purl_groups.items():
                # Create anytree structure
                root = Node(base_purl)
                for version in sorted(set(versions)):  # Remove duplicates and sort
                    Node(version, parent=root)

                # Print the tree
                render_tree(root)
        else:
            console.print(f"No packages found for {component}")
    else:
        # Original behavior: show unique base purls without versions and qualifiers
        distinct_purls = set()
        for purl_obj in purls:
            # Create base purl without version and qualifiers
            base_purl_string = _create_base_purl(purl_obj)
            distinct_purls.add(base_purl_string)

        console.print("Found these matching packages in Trustify:")
        for purl in distinct_purls:
            console.print(purl)


def _query_trustify_packages(
    component: str, auth_header: dict[str, str]
) -> list[PackageURL]:
    """
    Given a search string 'component' use the Trustify analysis/latest/component endpoint to find packages in PURL
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
    results = []
    for item in package_result["items"]:
        purl_obj = build_node_purl(item["purl"])
        if purl_obj:
            results.append(purl_obj)
    return results
