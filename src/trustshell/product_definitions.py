from collections import defaultdict
import copy
import json
import logging
import os
import re
from typing import Any, Optional
import httpx

from anytree import Node, NodeMixin, LevelOrderGroupIter
from trustshell import CONFIG_DIR, console

logger = logging.getLogger(__name__)


class ProductBase(object):
    def __init__(self, name: str) -> None:
        self.name = name

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ProductBase) and type(self) is type(other):
            return self.name == other.name
        return False


class ProductModule(ProductBase, NodeMixin):
    def __init__(self, name: str, cpe_patterns: list[str]) -> None:
        super().__init__(name)
        self.cpe_patterns = [
            pattern.replace(".", "\\.").replace("*", ".*") for pattern in cpe_patterns
        ]

    def match(self, cpe: str) -> bool:
        # First try to match exactly, then substring
        for suffix in ("$", ""):
            # We must try in descending-length order so that X:10 matches before X:1.
            for regex in sorted(self.cpe_patterns, key=len, reverse=True):
                if re.match(regex + suffix, cpe):
                    return True
        return False


class ProductStream(ProductBase, NodeMixin):
    def __init__(self, name: str, cpes: list[str] = [], active: bool = False) -> None:
        super().__init__(name)
        # In rhel 10 we don't use mainline CPEs, so we need to filter them out
        if name.startswith("rhel-") and not name.startswith("rhel-10"):
            self.cpes = self._filter_rhel_mainline_cpes(cpes)
        else:
            self.cpes = cpes
        self.active = active

    def set_active(self, active: bool) -> None:
        self.active = active

    @staticmethod
    def _filter_rhel_mainline_cpes(cpes: list[str]) -> list[str]:
        """Special logic for RHEL streams is required because during the lifetime of a RHEL
        release it will have the main line CPE (redhat:enterprise_linux:),
        and also EUS/AUS/TUS CPEs depending on it's lifecycle phase. The rule here is that
        if a stream has both main line and EUS/AUS/TUS ignore the main line one
        (which is less specific)"""
        cpe_set = set(cpes)
        if len(cpe_set) <= 1:
            return cpes
        has_eatus = False
        for cpe in cpes:
            for us in "eus", "aus", "tus", "e4s":
                if f":rhel_{us}:" in cpe:
                    has_eatus = True
                    break
            if has_eatus:
                break
        if not has_eatus:
            return cpes
        return [
            cpe for cpe in cpes if not re.search(r":redhat:enterprise_linux:\d:", cpe)
        ]


class ProdDefs:
    ETAG_FILE = os.path.join(CONFIG_DIR, "etag.txt")
    PRODUCT_FILE = os.path.join(CONFIG_DIR, "products.json")

    @classmethod
    def get_etag(cls, url: str) -> Optional[str]:
        response = httpx.head(url)
        etag = response.headers.get("etag")
        return str(etag) if etag is not None else None

    # Assisted by watsonx Code Assistant
    @classmethod
    def persist_etag(cls, etag: str, file_path: str) -> None:
        with open(file_path, "w") as f:
            f.write(etag)

    # Assisted by watsonx Code Assistant
    @classmethod
    def load_etag(cls, file_path: str) -> Optional[str]:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return f.read().strip()
        return None

    # Assisted by watsonx Code Assistant
    @classmethod
    def load_product_definitions(cls, url: str, file_path: str) -> None:
        response = httpx.get(url)
        with open(file_path, "w") as f:
            f.write(response.text)

    @classmethod
    def get_product_definitions_service(cls) -> dict[str, Any]:
        proddefs_url: Optional[str] = None
        if "PRODDEFS_URL" not in os.environ:
            console.print(
                "PRODDEFS_URL not set, not product mappings will be available",
                style="warning",
            )
            return {}
        else:
            proddefs_url = os.getenv("PRODDEFS_URL")

        if proddefs_url is None:
            return {}

        etag = cls.load_etag(cls.ETAG_FILE)
        url_etag = cls.get_etag(proddefs_url)

        if etag == url_etag:
            with open(cls.PRODUCT_FILE, "r") as f:
                product_definitions: dict[str, Any] = json.load(f)
        else:
            cls.load_product_definitions(proddefs_url, cls.PRODUCT_FILE)
            if url_etag is not None:
                cls.persist_etag(url_etag, cls.ETAG_FILE)
            with open(cls.PRODUCT_FILE, "r") as f:
                product_definitions = json.load(f)
        return product_definitions

    def __init__(self, active_only: bool = True) -> None:
        self.stream_nodes_by_cpe: dict[str, list[ProductStream]] = defaultdict(list)
        product_streams_by_name: dict[str, list[ProductStream]] = defaultdict(list)
        self.product_trees: list[NodeMixin] = []

        data = self.get_product_definitions_service()

        if not data:
            return

        for ps_update_stream, stream_data in data["ps_update_streams"].items():
            cpes = stream_data.get("cpe", [])
            stream_node = ProductStream(ps_update_stream, cpes)
            product_streams_by_name[ps_update_stream].append(stream_node)
            for cpe in cpes:
                # We need this check because RHEL mainline CPEs are filtered out
                if cpe in stream_node.cpes:
                    self.stream_nodes_by_cpe[cpe].append(stream_node)

        seen_stream_names: set[str] = set()
        for ps_module, module_data in data["ps_modules"].items():
            cpes = module_data.get("cpe", [])

            active_streams: set[str] = set()
            active_streams.update(module_data.get("active_ps_update_streams", []))
            for stream in module_data.get("ps_update_streams"):
                for stream_node in product_streams_by_name[stream]:
                    if stream in active_streams:
                        stream_node.set_active(True)
                    elif active_only:
                        if stream in self.stream_nodes_by_cpe:
                            # The stream is not active in the module, and we only want active streams
                            # Therefore lets remove this stream from the product_streams_by_cpe map
                            del self.stream_nodes_by_cpe[stream]
                        # don't add the stream to the product_trees
                        continue
                    self._check_stream_name(seen_stream_names, stream)
                    module_node = ProductModule(ps_module, cpes)
                    module_node.parent = stream_node
                    self.product_trees.append(stream_node)

    @staticmethod
    def _check_stream_name(seen_stream_names: set[str], stream: str) -> None:
        if stream in seen_stream_names:
            console.print(
                f"Warning: duplicate stream: {stream} detected.", style="warning"
            )
        seen_stream_names.add(stream)

    def match_module_pattern(self, cpe: str) -> list[ProductModule]:
        module_matches = []
        for module_tree in self.product_trees:
            for modules in LevelOrderGroupIter(module_tree, maxlevel=2):
                for module in modules:
                    if not isinstance(module, ProductModule):
                        continue
                    if module.match(cpe):
                        module_matches.append(module)
        return module_matches

    @staticmethod
    def _clean_cpe(cpe: str) -> str:
        """CPEs from SBOMs have extra characters added to them, clean them up here
        see https://github.com/trustification/trustify/issues/1621"""
        # Remove all '*' characters
        cleaned_cpe = cpe.replace("*", "")
        # Remove trailing ':' characters
        return cleaned_cpe.rstrip(":")

    def extend_with_product_mappings(self, ancestor_trees: list[Node]) -> list[Node]:
        """Create a new list of results with any matching streams or module as ancestors"""
        if not self.product_trees:
            # ProdDefs service is unavailable, don't attempt any product mapping
            return ancestor_trees
        ancestors_with_products: list[Node] = []
        for tree in ancestor_trees:
            for leaf in tree.leaves:
                cleaned_leaf_name = self._clean_cpe(leaf.name)
                leaf_with_products = self._check_streams(leaf, cleaned_leaf_name)
                if not leaf_with_products:
                    leaf_with_products = self._check_modules(leaf, cleaned_leaf_name)
                if not leaf_with_products:
                    console.print(
                        f"Warning, didn't find any products matching {cleaned_leaf_name}",
                        style="warning",
                    )
                ancestors_with_products.extend(leaf_with_products)
        return ancestors_with_products

    def _check_streams(self, leaf: Node, cpe: str) -> list[Node]:
        """Check if cpe matches exactly to any ProductStreams, if it does add the CPE as a parent
        of the stream. If more than one stream matches, create copies of the stream and leaf"""
        if cpe not in self.stream_nodes_by_cpe:
            return []
        stream_nodes = self.stream_nodes_by_cpe[cpe]
        # Create a copy so that pop in the _duplicate_leaves_and_set_parent function doesn't modify
        # the original stream_nodes_by_cpe map which should be preserved incase we encounter the
        # same CPE twice
        copy_of_stream_nodes = copy.deepcopy(stream_nodes)
        return self._duplicate_leaves_and_set_parents(leaf, copy_of_stream_nodes)

    def _check_modules(self, leaf: Node, cpe: str) -> list[Node]:
        """Check if the cpe matches any ProductModule"""
        module_nodes = self.match_module_pattern(cpe)
        return self._duplicate_leaves_and_set_parents(leaf, module_nodes)

    def _duplicate_leaves_and_set_parents(
        self, leaf: Node, product_nodes: list[Any]
    ) -> list[Node]:
        """Convert product modules to their parent streams and attach all streams as children of the leaf.
        Deduplicates streams to avoid multiple identical children. Returns the leaf in a list."""
        if not product_nodes:
            return []

        # Convert modules to their parent streams
        streams_to_attach: list[Any] = []
        for product in product_nodes:
            if isinstance(product, ProductModule):
                # For modules, find the stream that contains this module
                if product.parent:
                    streams_to_attach.append(product.parent)
            else:
                # For streams, use directly
                streams_to_attach.append(product)

        # Remove duplicates while preserving order
        unique_streams: list[Any] = []
        seen: set[Any] = set()
        for stream in streams_to_attach:
            if stream not in seen:
                unique_streams.append(stream)
                seen.add(stream)

        for stream in unique_streams:
            stream.parent = leaf

        return [leaf]

    def _add_ancestor(self, leaf: Node, product: Any) -> None:
        if product.parent:
            product.parent.parent = leaf
        else:
            product.parent = leaf
