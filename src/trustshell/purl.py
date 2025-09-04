import click
import logging
from collections import defaultdict
from typing import Any

import httpx
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
    paginated_trustify_query,
    urlencoded,
)
from trustshell.products import ANALYSIS_ENDPOINT, LATEST_ENDPOINT


custom_theme = Theme({"warning": "magenta", "error": "bold red", "info": "cyan"})
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
@click.option("--include-versions", "-i", is_flag=True, help="Include all versions")
@click.option("--non-latest", "-l", is_flag=True, help="Search non-latest SBOMs")
@click.option(
    "--use-base-purl",
    "-b",
    is_flag=True,
    help="Use base_purl endpoint instead of analysis endpoint, faster but less accurate",
)
@click.argument(
    "component",
    type=click.STRING,
)
def search(
    component: str,
    include_versions: bool,
    debug: bool,
    non_latest: bool,
    use_base_purl: bool,
) -> None:
    """Search for a component in Trustify

    Examples:
        # Standard search using analysis endpoint
        trustshell purl search openssl

        # Alternative search using base_purl endpoint (faster, good for timeouts)
        trustshell purl search --use-base-purl openssl
        trustshell purl search -b openssl

        # Include version information with base_purl method
        # This will lookup detailed version info for each base PURL found
        trustshell purl search -b -i openssl

        # Combine with other options
        trustshell purl search -b -i -d openssl  # with debug output

        # If you encounter timeouts, try the base_purl option:
        # trustshell purl search -b jenkins
    """
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}

    try:
        if use_base_purl:
            purls = _query_trustify_packages_base_purl(
                component, auth_header, include_versions
            )
        else:
            purls = _query_trustify_packages(component, auth_header, non_latest)
    except httpx.ReadTimeout:
        if use_base_purl:
            console.print(
                f"Request timed out while querying base_purl endpoint for '{component}'. "
                f"The server may be experiencing high load.",
                style="error",
            )
        else:
            console.print(
                f"Request timed out while querying for '{component}'. "
                f"For faster results, try using the --use-base-purl (-b) option:",
                style="error",
            )
            console.print(f"  trust-purl search -b {component}", style="info")
        raise click.Abort()  # Clean exit without stack trace

    if include_versions:
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

            # Include all PURLs, even those without version information
            if version_info:
                purl_groups[base_key].append(version_info)
            else:
                # Add base PURL to the groups even if it has no versions
                # This ensures it appears in the output
                if base_key not in purl_groups:
                    purl_groups[base_key] = []

        if purl_groups:
            console.print("Found these matching packages in Trustify:")
            for base_purl, versions in sorted(purl_groups.items()):
                # Create anytree structure
                root = Node(base_purl)
                if versions:
                    # Add version nodes if versions exist
                    for version in sorted(set(versions)):  # Remove duplicates and sort
                        Node(version, parent=root)
                # If no versions, leave the root node without children

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
        for purl in sorted(distinct_purls):
            console.print(purl)


def _lookup_base_purl(base_purl: str, auth_header: dict[str, str]) -> dict[str, Any]:
    """Get the details of a base purl from Atlas"""
    encoded_base_purl = urlencoded(base_purl)
    # TODO use asyncio
    base_purl_response = httpx.get(
        f"{PURL_BASE_ENDPOINT}/{encoded_base_purl}", headers=auth_header
    )
    base_purl_response.raise_for_status()
    return base_purl_response.json()  # type: ignore[no-any-return]


def _query_trustify_packages_base_purl(
    component: str, auth_header: dict[str, str], include_versions: bool = False
) -> list[PackageURL]:
    """
    Alternative method to query packages using the base_purl endpoint directly.
    This uses a simple text search against base purls rather than the analysis endpoints.
    Uses pagination to handle large result sets efficiently.

    Parameters:
    component (str): The component name to search for
    auth_header (dict[str, str]): Authentication headers
    include_versions (bool): If True, lookup detailed version information for each base PURL

    Returns:
    list[PackageURL]: List of PackageURL objects found
    """
    package_query = {"q": component}
    console.print(f"Querying Trustify for packages matching {component}")

    try:
        # Use the paginated query function to handle large result sets
        response_data = paginated_trustify_query(
            PURL_BASE_ENDPOINT,
            package_query,
            auth_header,
            component_name=f"base PURLs matching '{component}'",
        )

        results = []
        items = response_data.get("items", [])
        total = response_data.get("total", 0)

        console.print(f"Found {total} base purls matching {component}")

        if not include_versions:
            # Original behavior: return base PURLs only
            for item in items:
                base_purl_str = item.get("purl", "")
                if base_purl_str:
                    try:
                        purl_obj = PackageURL.from_string(base_purl_str)
                        results.append(purl_obj)
                    except Exception as e:
                        logger.debug(f"Failed to parse PURL '{base_purl_str}': {e}")
        else:
            # Enhanced behavior: lookup version details for each base PURL
            for item in items:
                base_purl_str = item.get("purl", "")
                if base_purl_str:
                    try:
                        console.print(f"Looking up versions for {base_purl_str}")
                        base_purl_details = _lookup_base_purl(
                            base_purl_str, auth_header
                        )

                        # Extract all versions from the detailed response
                        versions = base_purl_details.get("versions", [])
                        for version_info in versions:
                            version_purl_str = version_info.get("purl", "")
                            if version_purl_str:
                                try:
                                    version_purl_obj = PackageURL.from_string(
                                        version_purl_str
                                    )
                                    results.append(version_purl_obj)
                                except Exception as e:
                                    logger.debug(
                                        f"Failed to parse version PURL '{version_purl_str}': {e}"
                                    )

                            # Also extract individual PURLs from the purls array within each version
                            purls_list = version_info.get("purls", [])
                            for purl_entry in purls_list:
                                individual_purl_str = purl_entry.get("purl", "")
                                if individual_purl_str:
                                    try:
                                        individual_purl_obj = PackageURL.from_string(
                                            individual_purl_str
                                        )
                                        results.append(individual_purl_obj)
                                    except Exception as e:
                                        logger.debug(
                                            f"Failed to parse individual PURL '{individual_purl_str}': {e}"
                                        )

                    except Exception as e:
                        logger.debug(
                            f"Failed to lookup base PURL '{base_purl_str}': {e}"
                        )
                        # Fall back to just the base PURL if lookup fails
                        try:
                            purl_obj = PackageURL.from_string(base_purl_str)
                            results.append(purl_obj)
                        except Exception as parse_e:
                            logger.debug(
                                f"Failed to parse base PURL '{base_purl_str}': {parse_e}"
                            )

        return results

    except httpx.ReadTimeout:
        # Let timeout exceptions propagate to be handled at higher level
        raise
    except httpx.HTTPStatusError as e:
        console.print(f"HTTP error querying base purls: {e}", style="error")
        return []
    except Exception as e:
        console.print(f"Error querying base purls: {e}", style="error")
        return []


def _query_trustify_packages(
    component: str, auth_header: dict[str, str], non_latest: bool
) -> list[PackageURL]:
    """
    Given a search string 'component' use the Trustify analysis/latest/component endpoint to find packages in PURL
    format matching the given package. Accepts requests such as k8s.io/api that have both a PURL
    namespace and name.
    """
    console.print(f"Querying Trustify for packages matching {component}")
    if non_latest:
        endpoint = ANALYSIS_ENDPOINT
    else:
        endpoint = LATEST_ENDPOINT

    # Use the paginated query function
    base_params = {"q": f"purl~{component}"}
    package_result = paginated_trustify_query(
        endpoint, base_params, auth_header, component_name=component
    )

    # Check if we got fewer results than expected (indicating partial failures)
    retrieved_count = len(package_result["items"])
    total_available = package_result.get("total", 0)

    if total_available > 0 and retrieved_count < total_available:
        missing_count = total_available - retrieved_count
        console.print(
            f"Warning: Only retrieved {retrieved_count} out of {total_available} results "
            f"({missing_count} missing due to server errors). "
            f"For more reliable results, try using the --use-base-purl (-b) option:",
            style="warning",
        )
        console.print(f"  trust-purl search -b {component}", style="info")

    # Process all items and build PURL objects
    results = []
    for item in package_result["items"]:
        purl_obj = build_node_purl(item["purl"])
        if purl_obj:
            results.append(purl_obj)

    return results
