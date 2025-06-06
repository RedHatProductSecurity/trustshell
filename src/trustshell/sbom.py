
import logging
import click

from trustshell import config_logging, print_version
from trustshell.product_definitions import ProdDefs, ProductModule, ProductStream
from rich.console import Console
from rich.theme import Theme

from trustshell.products import render_tree

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")


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
@click.argument(
    "stream",
    type=click.STRING,
)
def generate(stream: str, debug: bool):
    """Generate an Manifest for the given stream"""
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    cpes, cpe_patterns = _get_cpes_and_patterns_for_stream(stream)
    if not cpes and not cpe_patterns:
        console.print(f"Did not find any CPEs matching stream", style="error")
        exit(1)
    logger.debug(f"Found cpes {cpes} or cpe_patterns {cpe_patterns}")


def _get_cpes_and_patterns_for_stream(stream) -> tuple[list[str, list[str]]]:
    prod_defs = ProdDefs()
    cpes = _get_stream_cpes(stream, prod_defs)
    cpe_patterns = set()
    # Check module matches only if we didn't get a direct match on the stream name
    if not cpes:
        for product_node in prod_defs.product_trees:
            if not product_node.name == stream:
                continue
            for child in product_node.children:
                if isinstance(child, ProductModule) and child.raw_cpe_patterns:
                    cpe_patterns.update(child.raw_cpe_patterns)
    return cpes, list(cpe_patterns)

def _get_stream_cpes(stream, prod_defs) -> list[str]:
    # Map a stream (used by ProdSec) to a list of CPEs
    for tree_root in prod_defs.product_trees:
        if tree_root.name == stream and isinstance(tree_root, ProductStream):
            return tree_root.cpes
    return []
