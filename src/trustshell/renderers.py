"""Output renderers for trust-products search results."""

import json
from typing import Any

from anytree import Node

from trustshell import render_tree_to_string
from trustshell.models import ProductResultRow, ProductSearchResult


def render_tree_format(
    result: ProductSearchResult,
    show_module: bool = True,
    cpes: bool = False,
    show_sbom_ids: bool = False,
) -> str:
    """Render text output as string. By default shows ps_update_stream; use cpes=True to show CPE."""
    seen_roots: set[str] = set()
    parts: list[str] = []
    for row in result.results:
        root_key = row.matched_component
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)
        rows_for_root = [r for r in result.results if r.matched_component == root_key]
        tree_str = _render_result_tree(
            root_key, rows_for_root, show_module, cpes, show_sbom_ids
        )
        parts.append(tree_str)
    return "\n".join(parts)


def _render_result_tree(
    root_name: str,
    rows: list[ProductResultRow],
    show_module: bool,
    cpes: bool,
    show_sbom_ids: bool = False,
) -> str:
    """Build and return tree as string from result rows. Root is matched_component."""
    root = Node(root_name)
    groups: dict[tuple[str, ...], list[ProductResultRow]] = {}
    for row in rows:
        if cpes:
            dedup_key: tuple[str, ...] = (
                row.cpe,
                row.ps_update_stream,
                row.ps_module or "",
            )
        else:
            dedup_key = (row.ps_update_stream, row.ps_module or "")
        groups.setdefault(dedup_key, []).append(row)

    for dedup_key, group_rows in groups.items():
        aggregated_sbom_ids = sorted(
            {sid for row in group_rows for sid in row.sbom_ids}
        )
        sbom_suffix = ""
        if show_sbom_ids and aggregated_sbom_ids:
            sbom_suffix = " [" + ", ".join(aggregated_sbom_ids) + "]"

        if cpes:
            cpe_node = Node(group_rows[0].cpe, parent=root)
            stream_node = Node(group_rows[0].ps_update_stream, parent=cpe_node)
            if show_module and group_rows[0].ps_module:
                leaf_name = (group_rows[0].ps_module or "") + sbom_suffix
            else:
                leaf_name = group_rows[0].shipped_component + sbom_suffix
            Node(leaf_name, parent=stream_node)
        else:
            stream_node = Node(group_rows[0].ps_update_stream, parent=root)
            if show_module and group_rows[0].ps_module:
                leaf_name = (group_rows[0].ps_module or "") + sbom_suffix
            else:
                leaf_name = group_rows[0].shipped_component + sbom_suffix
            Node(leaf_name, parent=stream_node)
    return render_tree_to_string(root)


def render_json_format(
    result: ProductSearchResult,
    include_module: bool = True,
) -> str:
    """Return flat JSON structure as string: results and affects. No tree."""
    output: dict[str, Any] = {
        "searched_purl": result.searched_purl,
        "results": [
            {
                "cpe": row.cpe,
                "ps_update_stream": row.ps_update_stream,
                "matched_component": row.matched_component,
                "shipped_component": row.shipped_component,
                "sbom_ids": row.sbom_ids,
            }
            for row in result.results
        ],
        "affects": [
            {"ps_update_stream": a.ps_update_stream, "purl": a.purl}
            for a in result.affects
        ],
    }
    if include_module:
        for i, row in enumerate(result.results):
            output["results"][i]["ps_module"] = row.ps_module

    return json.dumps(output, indent=2)
