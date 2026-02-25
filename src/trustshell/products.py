from collections import defaultdict
import click
import httpx
import logging
import sys
from typing import Any, Optional

from anytree import NodeMixin, PreOrderIter
from anytree.walker import Walker, WalkError
from packageurl import PackageURL
from rich.console import Console
from rich.theme import Theme
from trustshell import (
    AUTH_ENABLED,
    TRUSTIFY_URL,
    build_node_purl,
    check_or_get_access_token,
    config_logging,
    print_version,
    purl_sans_version,
    paginated_trustify_query,
)
from trustshell.models import Affect, ProductResultRow, ProductSearchResult
from trustshell.osidb import OSIDB
from trustshell.product_definitions import ProdDefs, ProductModule, ProductStream

LATEST_ENDPOINT = f"{TRUSTIFY_URL}analysis/latest/component"
ANALYSIS_ENDPOINT = f"{TRUSTIFY_URL}analysis/component"
ANCESTOR_COUNT = 100

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")


class ComponentNode(NodeMixin):
    """Tree node with name and sbom_ids for component hierarchy from Trustify API."""

    def __init__(
        self,
        name: str,
        parent: Optional["ComponentNode"] = None,
        sbom_id: Optional[str] = None,
    ) -> None:
        self.name = name
        self.parent = parent
        self.sbom_ids: set[str] = set()
        if sbom_id:
            self.sbom_ids.add(sbom_id)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--check", "-c", is_flag=True, help="Check the status only, don't prime")
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
def prime_cache(check: bool, debug: bool) -> None:
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
        console.print(
            f"This may take a while with {sbom_count} SBOMs...", style="warning"
        )
        try:
            response = httpx.get(
                f"{TRUSTIFY_URL}analysis/component",
                headers=auth_header,
                timeout=1800,  # 30 minutes - increased for large SBOM counts
            )
            response.raise_for_status()
            console.print("Cache priming completed successfully!", style="bold green")
        except httpx.TimeoutException:
            console.print(
                f"Request timed out after 30 minutes. The server may need more time to process {sbom_count} SBOMs.",
                style="error",
            )
            sys.exit(1)
        except httpx.HTTPStatusError as e:
            console.print(f"HTTP error occurred: {e}", style="error")
            sys.exit(1)
        except Exception as e:
            console.print(f"An error occurred: {e}", style="error")
            sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
)
@click.option(
    "--versions", "-v", is_flag=True, default=False, help="Show PURL versions."
)
@click.option("--latest", "-l", is_flag=True, default=True)
@click.option("--cpes", "-c", is_flag=True, default=False)
@click.option(
    "--include-rpm-containers",
    "-i",
    is_flag=True,
    default=False,
    help="Include RPM packages found in container images.",
)
@click.option("--flaw", "-f", help="OSIDB flaw uuid or CVE")
@click.option(
    "--replace",
    "-r",
    is_flag=True,
    help="Replace flaw affects. Requires --flaw to be set.",
    callback=lambda ctx, param, value: _check_flaw(ctx, param, value, "replace"),
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format. Mutually exclusive with --flaw.",
)
@click.option(
    "--show-module",
    is_flag=True,
    default=True,
    help="Show ps_module in output (tree format).",
)
@click.option(
    "--show-sbom-ids",
    is_flag=True,
    default=False,
    help="Show sbom_ids in text output (tree format).",
)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
@click.argument(
    "purl",
    type=click.STRING,
)
def search(
    purl: str,
    flaw: Optional[str],
    replace: bool,
    output: str,
    show_module: bool,
    show_sbom_ids: bool,
    debug: bool,
    latest: bool,
    cpes: bool,
    versions: bool,
    include_rpm_containers: bool,
) -> None:
    """Relate a purl to products in Trustify"""
    if flaw and output == "json":
        raise click.UsageError("--flaw and --output are mutually exclusive.")

    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    try:
        PackageURL.from_string(purl)
    except ValueError:
        console.print(f"{purl} is not a valid Package URL", style="error")
        sys.exit(1)

    ancestor_trees = _get_roots(
        purl,
        latest,
        show_versions=versions,
        include_rpm_containers=include_rpm_containers,
    )
    if not ancestor_trees or len(ancestor_trees) == 0:
        console.print("No results")
        return

    prod_defs = ProdDefs()
    result = build_product_search_result(ancestor_trees, prod_defs, purl, cpes=cpes)

    if flaw:
        osidb = OSIDB()
        osidb.edit_flaw_affects(flaw, result.affects, replace)
        return

    result.render(
        output=output,
        include_modules=show_module,
        cpes=cpes,
        show_sbom_ids=show_sbom_ids,
    )


def _check_flaw(ctx: Any, param: Any, value: Any, dependent_option_name: str) -> Any:
    """
    Callback function to check if --flaw is set.
    """
    if value and ctx.params.get("flaw") is None:
        raise click.BadOptionUsage(
            param, f"Option '{param.name}' requires '--flaw' to be set.", ctx
        )
    return value


def _format_affect_purl(
    purl: PackageURL, root_name: str, root_is_maven: bool = False
) -> str:
    """Format purl for affects: OCI sans tag, maven/generic use root, else sans version."""
    if purl.type == "oci" and purl.qualifiers and "tag" in purl.qualifiers:
        purl = PackageURL(
            type=purl.type,
            namespace=purl.namespace,
            name=purl.name,
            version=purl.version,
            qualifiers={k: v for k, v in purl.qualifiers.items() if k != "tag"},
        )
    elif purl.type == "maven" or (purl.type == "generic" and root_is_maven):
        purl = PackageURL.from_string(root_name)
    else:
        purl = purl_sans_version(purl)
    return purl.to_string()


def build_product_search_result(
    ancestor_trees: list[ComponentNode],
    prod_defs: ProdDefs,
    searched_purl: str,
    cpes: bool = False,
) -> ProductSearchResult:
    """Build flat ProductSearchResult from component trees.

    Does not mutate trees. Uses get_product_mappings_for_cpe for product matching.
    """
    results: list[ProductResultRow] = []
    for tree in ancestor_trees:
        root_name = tree.root.name
        try:
            root_purl = PackageURL.from_string(root_name)
            root_is_maven = root_purl.type == "maven"
        except ValueError:
            root_is_maven = False
        for leaf in tree.leaves:
            if not leaf.name.startswith("cpe:/"):
                continue
            cpe = leaf.name
            mappings = prod_defs.get_product_mappings_for_cpe(cpe)
            if not mappings:
                continue
            pkg_ancestors = [a for a in leaf.ancestors if a.name.startswith("pkg:")]
            if not pkg_ancestors:
                continue
            shipped_purl_node = None
            for a in pkg_ancestors:
                try:
                    if PackageURL.from_string(a.name).type in ("rpm", "oci", "maven"):
                        shipped_purl_node = a
                        break
                except ValueError:
                    continue
            if shipped_purl_node is None:
                continue
            shipped_purl = PackageURL.from_string(shipped_purl_node.name)
            shipped_component = _format_affect_purl(
                shipped_purl, root_name, root_is_maven
            )
            matched_component = root_name
            cleaned_cpe = prod_defs._clean_cpe(cpe)
            # Collect sbom_ids from path (root to leaf)
            path_sbom_ids: set[str] = set()
            for node in list(leaf.ancestors) + [leaf]:
                if hasattr(node, "sbom_ids"):
                    path_sbom_ids.update(node.sbom_ids)
            sbom_ids_list = sorted(path_sbom_ids)
            for ps_update_stream, ps_module in mappings:
                results.append(
                    ProductResultRow(
                        cpe=cleaned_cpe,
                        ps_update_stream=ps_update_stream,
                        ps_module=ps_module,
                        matched_component=matched_component,
                        shipped_component=shipped_component,
                        sbom_ids=sbom_ids_list,
                    )
                )
    affects_unique = {
        Affect(ps_update_stream=row.ps_update_stream, purl=row.shipped_component)
        for row in results
    }
    results_sorted = sorted(
        results, key=lambda r: (r.ps_update_stream, r.shipped_component)
    )
    affects_sorted = sorted(affects_unique, key=lambda a: (a.ps_update_stream, a.purl))
    return ProductSearchResult(
        results=results_sorted,
        affects=affects_sorted,
        searched_purl=searched_purl,
    )


def extract_affects(ancestor_trees: list[ComponentNode]) -> set[tuple[str, str]]:
    """Collect all the leaf and root node tuples for OSIDB affects.

    Extracts (ps_update_stream, purl) tuples where:
    - ps_update_stream comes from ProductStream parent of ProductModule leaf nodes
    - purl comes from ancestor package components in the dependency tree
    """
    affects = set()
    seen_streams = set()
    for tree in ancestor_trees:
        ps_module_nodes = []
        for leaf in tree.leaves:
            if isinstance(leaf, ProductModule):
                ps_module_nodes.append(leaf)

        for ps_module_node in ps_module_nodes:
            # Extract ps_update_stream from ProductStream parent
            if not ps_module_node.parent or not isinstance(
                ps_module_node.parent, ProductStream
            ):
                logger.debug(
                    f"ProductModule {ps_module_node.name} has no ProductStream parent, skipping"
                )
                continue

            ps_update_stream = ps_module_node.parent.name

            if ps_update_stream in seen_streams:
                continue
            seen_streams.add(ps_update_stream)

            for ancestor in ps_module_node.ancestors:
                # Find the root component
                if ancestor.name.startswith("pkg:"):
                    purl = PackageURL.from_string(ancestor.name)
                else:
                    continue
                # Clean up the purl ready for use in affects
                if purl.type == "oci" and "tag" in purl.qualifiers:
                    purl.qualifiers.pop("tag")
                elif (
                    purl.type == "maven"
                    or purl.type == "generic"
                    and PackageURL.from_string(ps_module_node.root.name).type == "maven"
                ):
                    # If it's a maven type or a generic one based on maven,
                    # we set the purl to root
                    purl = PackageURL.from_string(ps_module_node.root.name)
                else:
                    purl = purl_sans_version(purl)

                affects.add(
                    (
                        ps_update_stream,
                        purl.to_string(),
                    )
                )
    return affects


def _get_roots(
    base_purl: str,
    latest: bool = True,
    show_versions: bool = False,
    include_rpm_containers: bool = False,
) -> list[ComponentNode]:
    """Look up base_purl ancestors in Trustify

    Uses purl~ query which Trustify automatically translates into optimized
    field-specific queries (purl:ty, purl:name, purl:namespace, etc.)
    """

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}

    if latest:
        endpoint = LATEST_ENDPOINT
    else:
        endpoint = ANALYSIS_ENDPOINT

    # purl~ is automatically translated by Trustify to field-specific queries
    # e.g., purl~pkg:npm/foo becomes purl:ty=npm&purl:name=foo
    base_params = {"ancestors": ANCESTOR_COUNT, "q": f"purl~{base_purl}"}
    ancestors = paginated_trustify_query(
        endpoint, base_params, auth_header, component_name=base_purl
    )
    logger.debug(f"Number of matches for {base_purl}: {ancestors['total']}")
    return _trees_with_cpes(ancestors, show_versions, include_rpm_containers)


def build_ancestor_tree(
    parent: ComponentNode, ancestors: list[dict[str, Any]], show_versions: bool
) -> None:
    """
    Recursive function to build an ancestor tree from a nested set of purls, or CPEs.
    Records sbom_id from each component on the corresponding node.
    """
    for component in ancestors:
        sbom_id = component.get("sbom_id")
        base_purl = build_node_purl(component["purl"], show_versions)
        if not base_purl:
            cpes = component["cpe"]
            if not cpes:
                # Try the next ancestor
                continue
            for cpe in cpes:
                ComponentNode(cpe, parent=parent, sbom_id=sbom_id)
        else:
            node = ComponentNode(base_purl.to_string(), parent=parent, sbom_id=sbom_id)
            if "ancestors" in component:
                build_ancestor_tree(node, component["ancestors"], show_versions)
            # else try the next ancestor


def _remove_root_return_children(root: ComponentNode) -> list[ComponentNode]:
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


def _get_branch_signature(node: ComponentNode) -> str:
    """
    Create a unique signature for a branch structure starting from the given node.
    The signature includes the root component to ensure different components
    with the same product mappings don't get deduplicated.

    Args:
        node (Node): Root node of the branch to signature

    Returns:
        str: A string signature representing the branch structure
    """
    # Always include the root component name to prevent deduplication
    # of different components with identical product mappings
    root_component = node.name

    # Use a list to collect branch elements in pre-order traversal
    elements = [f"ROOT:{root_component}"]

    def traverse(current_node: ComponentNode, path: str = "") -> None:
        # Add node name and its level in the path (skip root since it's already included)
        if current_node != node:
            node_sig = f"{path}{current_node.name}"
            elements.append(node_sig)

        # Process children in a consistent order (sort by name)
        for i, child in enumerate(sorted(current_node.children, key=lambda x: x.name)):
            # Use numbers to indicate branching structure
            traverse(child, f"{path}{i}.")

    traverse(node)
    return "|".join(elements)


def _has_cpe_node(node: ComponentNode) -> bool:
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


def _remove_non_cpe_branches(root: ComponentNode) -> ComponentNode:
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


def _merge_branch_sbom_ids(kept: ComponentNode, removed: ComponentNode) -> None:
    """Merge sbom_ids from removed branch into kept branch (same structure)."""
    kept.sbom_ids.update(removed.sbom_ids)
    kept_children = sorted(kept.children, key=lambda x: x.name)
    removed_children = sorted(removed.children, key=lambda x: x.name)
    for k, r in zip(kept_children, removed_children):
        _merge_branch_sbom_ids(k, r)  # type: ignore[arg-type]


def _remove_duplicate_branches(root: ComponentNode) -> ComponentNode:
    """
    Removes duplicate branch structures from an Anytree tree.
    Merges sbom_ids from removed branches into the kept branch.
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
            # Keep the first occurrence; merge sbom_ids from duplicates, then remove
            kept = nodes[0]
            for node in nodes[1:]:
                _merge_branch_sbom_ids(kept, node)
                if node.parent:
                    node.parent = None

    return root


def _trees_with_cpes(
    ancestor_data: dict[str, Any],
    show_versions: bool,
    include_rpm_containers: bool = False,
) -> list[ComponentNode]:
    """Builds a tree of ancestors with a target component root"""
    if "items" not in ancestor_data or not ancestor_data["items"]:
        return []
    base_node = ComponentNode("root")
    build_ancestor_tree(base_node, ancestor_data["items"], show_versions)
    _remove_duplicate_branches(base_node)
    _remove_duplicate_parent_nodes(base_node)
    # re-parenting the tree can introduce new duplicate branches
    _remove_duplicate_branches(base_node)
    first_children = _remove_root_return_children(base_node)
    trees_with_cpes: list[ComponentNode] = []
    for tree in first_children:
        # Remove this once https://issues.redhat.com/browse/TC-2659 is implemented
        if tree.name.startswith("pkg:rpm/") and not include_rpm_containers:
            if container_in_tree(tree):
                continue
        _remove_non_cpe_branches(tree)
        if not _has_cpe_node(tree):
            for leaf in tree.leaves:
                logger.debug(
                    f"Found result {tree.name} with ancestor: {leaf.name} but no CPE parent"
                )
        else:
            trees_with_cpes.append(tree)
    return trees_with_cpes


def container_in_tree(root: ComponentNode) -> bool:
    """
    Returns true if containers exist in tree descendants
    """
    for node in root.descendants:
        if node.name.startswith("pkg:oci/"):
            return True
    return False


def _remove_duplicate_parent_nodes(node: ComponentNode) -> None:
    """
    Removes nodes in an anytree tree that have the same name as their direct parent,
    and reparents their children to the remaining node.
    Merges sbom_ids from the removed node into the parent.
    """
    for descendant in node.descendants:
        if descendant.name == descendant.parent.name:
            # Merge sbom_ids before detaching (if both support it)
            if hasattr(descendant, "sbom_ids") and hasattr(
                descendant.parent, "sbom_ids"
            ):
                descendant.parent.sbom_ids.update(descendant.sbom_ids)
            new_children = list(descendant.siblings)
            new_children.extend(descendant.children)
            descendant.parent.children = new_children
            descendant.parent = None
