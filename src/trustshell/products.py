from collections import defaultdict
import click
import httpx
import logging
import sys

from anytree import Node, RenderTree
from packageurl import PackageURL
from rich.console import Console
from rich.theme import Theme
from typing import Any, Optional
from univers.versions import RpmVersion
from trustshell import (
    TRUSTIFY_URL,
    config_logging,
    get_tag_from_purl,
    print_version,
    urlencoded,
)

ANALYSIS_ENDPOINT = f"{TRUSTIFY_URL}analysis/component"
MAX_I64 = 2**63 - 1

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")


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

    try:
        PackageURL.from_string(component)
    except ValueError:
        console.print(f"{component} is not a valid Package URL", style="error")
        sys.exit(1)

    ancestor_tree = _get_roots(component)
    _render_tree(ancestor_tree)


def _render_tree(root: Node):
    """Pretty print a tree using name only"""
    if root:
        for pre, _, node in RenderTree(root):
            console.print("%s%s" % (pre, node.name))
    else:
        console.print("No results")


def _get_roots(base_purl: str):
    """Lookup base_purl ancestors in Trustify"""
    # TODO if a purl does not have a namespace add another '/', see
    # https://github.com/trustification/trustify/issues/1440
    # TODO change back to purl~ (like) query?
    request_url = (
        f"{ANALYSIS_ENDPOINT}?ancestors={MAX_I64}&q={urlencoded(f'{base_purl}@')}"
    )
    ancestors_response = httpx.get(request_url)
    ancestors_response.raise_for_status()
    ancestors = ancestors_response.json()
    return _build_root_tree(base_purl, ancestors)


def _build_root_tree(base_name, ancestor_data: dict[str, Any]) -> Node:
    """Builds a tree of ancestors with a target component root"""
    if "items" not in ancestor_data or not ancestor_data["items"]:
        return
    base_node = Node(base_name)
    build_ancestor_tree(base_node, ancestor_data["items"])
    base_node = _consolidate_duplicate_nodes(base_node)
    return base_node


def build_ancestor_tree(parent: Node, ancestors):
    """
    Recursive function to build an ancestor tree from a nested set of purls, or CPEs. Assumes that
    CPE only only occurs at the root of the tree.
    """
    for component in ancestors:
        base_purl = _build_node_purl(component["purl"])
        if base_purl:
            node = Node(base_purl.to_string(), parent=parent)
            build_ancestor_tree(node, component["ancestors"])
        else:
            # Top level product components don't have purls, but might have multiples CPEs
            cpes = component["cpe"]
            if not cpes:
                # Reached the top of the tree
                return
            for cpe in cpes:
                Node(cpe, parent=parent)


def _consolidate_duplicate_nodes(root):
    """Consolidate duplicate nodes in the tree"""
    # First, collect nodes by name
    name_to_nodes = defaultdict(list)

    def collect_nodes(node):
        name_to_nodes[node.name].append(node)
        for child in node.children:
            collect_nodes(child)

    collect_nodes(root)

    # Process nodes with duplicates
    consolidation_count = 0
    children_moved_count = 0

    for name, duplicate_nodes in name_to_nodes.items():
        if len(duplicate_nodes) > 1:
            logger.debug(f"Found {len(duplicate_nodes)} nodes with name '{name}'")
            # Keep the first node
            primary_node = duplicate_nodes[0]

            # Collect all children from duplicate nodes
            for duplicate in duplicate_nodes[1:]:
                logger.debug(f"Consolidating duplicate node: {duplicate.name}")
                consolidation_count += 1
                # Reparent children
                for child in list(duplicate.children):
                    logger.debug(f"Moving child '{child.name}' to primary node")
                    child.parent = primary_node
                    children_moved_count += 1

                # Remove the duplicate node
                duplicate.parent = None

    # Log summary of consolidation
    logger.debug("Consolidation Summary:")
    logger.debug(f"- Total nodes consolidated: {consolidation_count}")
    logger.debug(f"- Total children moved: {children_moved_count}")

    return root


def _build_node_purl(purls: list[str]) -> Optional[PackageURL]:
    """
    Generate a base purl with a version or tag qualifier from a list of purls with homogenous
    type/namespace, and name

    Parameters:
    purls (list[str]): A list of purls.

    Returns:
    set[str]: A set of base purls
    """
    node_purls, type = _build_node_names_by_type(purls)
    if not node_purls:
        return None
    elif len(node_purls) > 1:
        if type == "oci":
            purl_tags: dict[str, PackageURL] = {}
            for purl in node_purls:
                qualifiers = purl.qualifiers
                if qualifiers and isinstance(qualifiers, dict) and "tag" in qualifiers:
                    purl_tags[qualifiers["tag"]] = purl
            sorted_purls = sorted(
                purl_tags.keys(), key=lambda x: RpmVersion(x), reverse=True
            )
            return purl_tags[sorted_purls[0]]
        else:
            console.print(f"multiple node purls found: {node_purls}", style="warning")
    return node_purls.pop()


def _build_node_names_by_type(purls: list[str]) -> tuple[set[PackageURL], str]:
    """
    Given some purl strings, return a unique set of base purls with versions or tag qualifiers
    """
    types = set()
    node_purls: dict[PackageURL, str] = {}
    for purl in purls:
        purl_obj = PackageURL.from_string(purl)
        tag = get_tag_from_purl(purl_obj)
        base_purl = _remove_qualifiers(purl_obj, tag)
        node_purls[base_purl] = purl_obj.type
    types = set(node_purls.values())
    if not types:
        return (set(), "")
    if len(types) > 1:
        console.print("Non homogenous types when calculating node name", style="error")
        sys.exit(1)
    return set(node_purls.keys()), types.pop()


def _remove_qualifiers(purl: PackageURL, tag: str) -> PackageURL:
    """Remove all qualifiers from a purl optionally setting a tag"""
    qualifiers = {}
    version = ""
    if tag:
        qualifiers = {"tag": tag}
    elif purl.version:
        version = purl.version
    return PackageURL(
        type=purl.type,
        name=purl.name,
        namespace=purl.namespace,
        version=version,
        qualifiers=qualifiers,
    )
