"""Data models for trust-products search results."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Affect:
    """Single affect entry for OSIDB flaw affects."""

    ps_update_stream: str
    purl: str  # shipped_component PURL


@dataclass
class ProductResultRow:
    """Single result: CPE + product info + matched and shipped components."""

    cpe: str
    ps_update_stream: str
    ps_module: str | None
    matched_component: str  # PURL that matched (important for wildcard search)
    shipped_component: (
        str  # PURL for affects: image-index/arch-specific OCI, or SRPM/binary RPM
    )
    sbom_ids: list[str] = field(
        default_factory=list
    )  # SBOM IDs from path (root to leaf)


@dataclass
class ProductSearchResult:
    """Flat result model. No tree structure—just product info and components.

    results and affects are sorted by (ps_update_stream, purl/shipped_component)
    at creation time; consumers can iterate without re-sorting.
    """

    results: list[ProductResultRow]
    affects: list[Affect]
    searched_purl: str

    def render(
        self,
        output: str,
        include_modules: bool = True,
        cpes: bool = False,
        show_sbom_ids: bool = False,
    ) -> None:
        """Render result to stdout. output is 'text' or 'json'."""
        from trustshell import console
        from trustshell.renderers import render_json_format, render_tree_format

        if output == "text":
            console.print(
                render_tree_format(
                    self,
                    show_module=include_modules,
                    cpes=cpes,
                    show_sbom_ids=show_sbom_ids,
                )
            )
        else:
            console.print_json(render_json_format(self, include_module=include_modules))
