from collections import defaultdict
import click
import httpx
import logging
import sys

from anytree import Node, RenderTree, PreOrderIter
from anytree.walker import Walker, WalkError
from packageurl import PackageURL
from rich.console import Console
from rich.theme import Theme
from typing import Any, Optional
from univers.versions import RpmVersion
from trustshell import (
    AUTH_ENABLED,
    TRUSTIFY_URL,
    check_or_get_access_token,
    config_logging,
    get_tag_from_purl,
    print_version,
    urlencoded,
)
from trustshell.product_definitions import ProdDefs

LATEST_ENDPOINT = f"{TRUSTIFY_URL}analysis/latest/component"
ANALYSIS_ENDPOINT = f"{TRUSTIFY_URL}analysis/component"
ANCESTOR_COUNT = 10000

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--check", "-c", is_flag=True, help="Check the status only, don't prime")
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
def prime_cache(check: bool, debug: bool):
    """Prime the analysis/component graph cache"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}
    status_response = httpx.get(
        f"{TRUSTIFY_URL}analysis/status", headers=auth_header, timeout=300
    )
    status_response.raise_for_status()
    status = status_response.json()
    graph_count = status["graph_count"]
    sbom_count = status["sbom_count"]
    console.print("Status before prime:")
    console.print(f"graph count: {graph_count}")
    console.print(f"sbom_count: {sbom_count}")
    if not check:
        console.print("Priming graph cache...")
        httpx.get(f"{TRUSTIFY_URL}analysis/component", headers=auth_header, timeout=300)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option("--latest", "-l", is_flag=True, default=True)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
@click.argument(
    "purl",
    type=click.STRING,
)
def search(purl: str, debug: bool, latest: bool):
    """Relate a purl to products in Trustify"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    try:
        PackageURL.from_string(purl)
    except ValueError:
        console.print(f"{purl} is not a valid Package URL", style="error")
        sys.exit(1)

    ancestor_trees = _get_roots(purl, latest)
    if not ancestor_trees or len(ancestor_trees) == 0:
        console.print("No results")
        return

    prod_defs = ProdDefs()
    ancestor_trees = prod_defs.extend_with_product_mappings(ancestor_trees)

    for tree in ancestor_trees:
        render_tree(tree.root)


def render_tree(root: Node):
    """Pretty print a tree using name only"""
    if root:
        for pre, _, node in RenderTree(root):
            console.print("%s%s" % (pre, node.name))
    else:
        console.print("No results")


def _get_roots(base_purl: str, latest: bool = True) -> list[Node]:
    """Look up base_purl ancestors in Trustify"""

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}

    if latest:
        request_url = f"{LATEST_ENDPOINT}?ancestors={ANCESTOR_COUNT}&q={urlencoded(f'purl~{base_purl}@')}"
    else:
        request_url = f"{ANALYSIS_ENDPOINT}?ancestors={ANCESTOR_COUNT}&q={urlencoded(f'purl~{base_purl}@')}"
    ancestors_response = httpx.get(request_url, headers=auth_header, timeout=300)
    ancestors_response.raise_for_status()
    ancestors = ancestors_response.json()
    logger.debug(f"Number of matches for {base_purl}: {ancestors['total']}")
    return _trees_with_cpes(ancestors)


def build_ancestor_tree(parent: Node, ancestors) -> list[Node]:
    """
    Recursive function to build an ancestor tree from a nested set of purls, or CPEs.
    """
    for component in ancestors:
        base_purl = _build_node_purl(component["purl"])
        if not base_purl:
            cpes = component["cpe"]
            if not cpes:
                # Try the next ancestor
                continue
            for cpe in cpes:
                Node(cpe, parent=parent)
        else:
            node = Node(base_purl.to_string(), parent=parent)
            if "ancestors" in component:
                build_ancestor_tree(node, component["ancestors"])
            # else try the next ancestor


def _remove_root_return_children(root):
    """
    Removes the root node and returns a list of its direct children.

    Args:
        root (Node): The root node of the tree

    Returns:
        list: A list of the former root's direct children as independent trees
    """
    # Get all direct children of the root
    children = list(root.children)

    # Detach all children from the root
    for child in children:
        child.parent = None

    # Return the list of children
    return children


def _get_branch_signature(node):
    """
    Create a unique signature for a branch structure starting from the given node.
    The signature represents the structure and node names in the branch.

    Args:
        node (Node): Root node of the branch to signature

    Returns:
        str: A string signature representing the branch structure
    """
    # Use a list to collect branch elements in pre-order traversal
    elements = []

    def traverse(current_node, path=""):
        # Add node name and its level in the path
        node_sig = f"{path}{current_node.name}"
        elements.append(node_sig)

        # Process children in a consistent order (sort by name)
        for i, child in enumerate(sorted(current_node.children, key=lambda x: x.name)):
            # Use numbers to indicate branching structure
            traverse(child, f"{path}{i}.")

    traverse(node)
    return "|".join(elements)


def _has_cpe_node(node):
    """
    Check if the node or any of its descendants have a name starting with "cpe:/".

    Args:
        node (Node): The node to check

    Returns:
        bool: True if the node or any descendant has a name starting with "cpe:/", False otherwise
    """
    # Check if the current node's name starts with "cpe:/"
    if node.name.startswith("cpe:/"):
        return True

    # Check if any descendant node's name starts with "cpe:/"
    for descendant in PreOrderIter(node):
        if descendant.name.startswith("cpe:/"):
            return True

    return False


def _remove_non_cpe_branches(root):
    # Inspect all the leaves for ones not starting with cpe:/
    leaves_to_remove = set()
    leaves_to_keep = set()
    for leaf in root.leaves:
        if leaf.name.startswith("cpe:/"):
            leaves_to_keep.add(leaf)
        else:
            leaves_to_remove.add(leaf)
    while leaves_to_remove:
        to_remove = leaves_to_remove.pop()
        if leaves_to_keep:
            to_keep = next(iter(leaves_to_keep))
            # remove all leaves and branches up to common ancestores
            w = Walker()
            try:
                up, common, _ = w.walk(to_remove, to_keep)
                for node in up:
                    if node != common:
                        node.parent = None
            except WalkError:
                continue
    return root


def _remove_duplicate_branches(root):
    """
    Removes duplicate branch structures from an Anytree tree

    Args:
        root (Node): The root node of the tree

    Returns:
        Node: The root node of the modified tree with duplicate branches removed
    """

    # Dictionary to store branches by their signatures
    branches_by_signature = defaultdict(list)

    # Collect branch signatures (skip the root node)
    for node in list(PreOrderIter(root))[1:]:
        # Only process nodes that have children (branches, not leaves)
        if node.children:
            signature = _get_branch_signature(node)
            branches_by_signature[signature].append(node)

    # Remove duplicate branches
    for signature, nodes in branches_by_signature.items():
        if len(nodes) > 1:
            # Keep the first occurrence of the branch
            for node in nodes[1:]:
                # Remove this duplicate branch
                if node.parent:
                    node.parent = None

    return root


def _trees_with_cpes(ancestor_data: dict[str, Any]) -> list[Node]:
    """Builds a tree of ancestors with a target component root"""
    if "items" not in ancestor_data or not ancestor_data["items"]:
        return
    base_node = Node("root")
    build_ancestor_tree(base_node, ancestor_data["items"])
    _remove_duplicate_branches(base_node)
    _remove_duplicate_parent_nodes(base_node)
    first_children = _remove_root_return_children(base_node)
    trees_with_cpes: list[Node] = []
    for tree in first_children:
        if not _has_cpe_node(tree):
            for leaf in tree.leaves:
                logger.debug(
                    f"Found result {tree.name} with ancestor: {leaf.name} but no CPE parent"
                )
        else:
            trees_with_cpes.append(tree)
    return [_remove_non_cpe_branches(tree) for tree in trees_with_cpes]


def _remove_duplicate_parent_nodes(node: Node):
    """
    Removes nodes in an anytree tree that have the same name as their direct parent,
    and reparents their children to the remaining node.

    :param node: The node to process.
    """
    for descandant in node.descendants:
        if descandant.name == descandant.parent.name:
            new_children = list(descandant.siblings)
            new_children.extend(descandant.children)
            descandant.parent.children = new_children
            descandant.parent = None


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
            if purl_tags:
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
