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
from trustshell.rhel_releases import EnhancedProdDefs

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
        if name.startswith("rhel-"):
            # Remove any single digit like cpe:/a:redhat:enterprise_linux:9::appstream
            self.cpes = [
                cpe
                for cpe in cpes
                if not re.search(r":redhat:enterprise_linux:\d:", cpe)
            ]
        else:
            self.cpes = cpes
        self.active = active

    def set_active(self, active: bool) -> None:
        self.active = active


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

    def __init__(
        self,
        active_only: bool = True,
        rhel_git_branch: str = "main",
        rhel_releases_path: str = "",
    ) -> None:
        self.stream_nodes_by_cpe: dict[str, list[ProductStream]] = defaultdict(list)
        product_streams_by_name: dict[str, list[ProductStream]] = defaultdict(list)
        self.product_trees: list[NodeMixin] = []

        # Initialize enhanced RHEL release data
        self.enhanced_proddefs: Optional[EnhancedProdDefs] = None
        if rhel_releases_path:
            # Use local file for testing
            try:
                self.enhanced_proddefs = EnhancedProdDefs(
                    git_branch=rhel_git_branch, rhel_releases_path=rhel_releases_path
                )
            except Exception as e:
                logger.warning(
                    f"Could not initialize enhanced product definitions: {e}"
                )
                self.enhanced_proddefs = None
        else:
            self.enhanced_proddefs = self._load_rhel_release_data(rhel_git_branch)

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

    def _load_rhel_release_data(
        self, git_branch: str = "main", rhel_releases_path: str = ""
    ) -> Optional[EnhancedProdDefs]:
        """
        Load RHEL release data from GitLab repository or local file.

        Args:
            git_branch: Git branch to use for fetching data
            rhel_releases_path: Local file path (for testing)

        Returns:
            EnhancedProdDefs instance or None if failed
        """
        try:
            enhanced_proddefs = EnhancedProdDefs(
                git_branch=git_branch, rhel_releases_path=rhel_releases_path
            )
            if rhel_releases_path:
                logger.info(
                    f"Loaded RHEL release data from local file: {rhel_releases_path}"
                )
            else:
                logger.info(
                    f"Loaded RHEL release data from GitLab (branch: {git_branch})"
                )
            return enhanced_proddefs
        except Exception as e:
            logger.error(f"Could not load RHEL release data: {e}")
            return None

    @staticmethod
    def _clean_cpe(cpe: str) -> str:
        """CPEs from SBOMs have extra characters added to them, clean them up here
        see https://github.com/trustification/trustify/issues/1621"""
        # Remove all '*' characters
        cleaned_cpe = cpe.replace("*", "")
        # Remove trailing ':' characters
        return cleaned_cpe.rstrip(":")

    def extend_with_product_mappings(
        self, ancestor_trees: list[Node], keep_cpes: bool = False
    ) -> None:
        """Update the ancestor_trees with any matching streams or module as descendants

        Args:
            ancestor_trees: List of Node trees to extend with product mappings
            keep_cpes: If False, replace CPE leaf nodes with product streams. If True, keep CPE nodes as parents of streams.
        """
        if not self.product_trees:
            # ProdDefs service is unavailable, don't attempt any product mapping
            return None

        for tree in ancestor_trees:
            for leaf in tree.leaves:
                cleaned_leaf_name = self._clean_cpe(leaf.name)
                # Don't try and match single digit enterprise_linux CPEs
                if re.search(r":redhat:enterprise_linux:\d:", cleaned_leaf_name):
                    leaf.parent = None
                    continue
                leaf_with_products = self._check_streams(
                    leaf, cleaned_leaf_name, keep_cpes
                )
                if not leaf_with_products:
                    leaf_with_products = self._check_modules(
                        leaf, cleaned_leaf_name, keep_cpes
                    )
                if not leaf_with_products:
                    console.print(
                        f"Warning, didn't find any products matching {cleaned_leaf_name}",
                        style="warning",
                    )
                else:
                    # When keep_cpes=False, we need to remove the CPE leaf from the tree
                    # since it's been replaced by the product streams
                    if not keep_cpes:
                        # Remove the CPE leaf node from its parent
                        leaf.parent = None

    def _check_streams(self, leaf: Node, cpe: str, keep_cpes: bool) -> list[Node]:
        """Check if cpe matches exactly to any ProductStreams, if it does add the CPE as a parent
        of the stream. If more than one stream matches, create copies of the stream and leaf"""
        # First try enhanced matching if RHEL release data is available
        enhanced_streams = self._check_enhanced_streams(cpe)
        if enhanced_streams:
            return self._duplicate_leaves_and_set_parents(
                leaf, enhanced_streams, keep_cpes
            )
        # Fallback to original direct matching
        if cpe not in self.stream_nodes_by_cpe:
            return []
        stream_nodes = self.stream_nodes_by_cpe[cpe]
        # Create a copy so that pop in the _duplicate_leaves_and_set_parent function doesn't modify
        # the original stream_nodes_by_cpe map which should be preserved incase we encounter the
        # same CPE twice
        copy_of_stream_nodes = copy.deepcopy(stream_nodes)
        return self._duplicate_leaves_and_set_parents(
            leaf, copy_of_stream_nodes, keep_cpes
        )

    def _check_enhanced_streams(self, cpe: str) -> list[ProductStream]:
        """Check if CPE matches using enhanced RHEL release data logic."""
        if not self.enhanced_proddefs:
            return []

        # Get active streams and their CPEs
        active_streams = set()
        stream_cpes: dict[str, list[str]] = {}

        for stream_name, stream_nodes in self.stream_nodes_by_cpe.items():
            for stream_node in stream_nodes:
                if stream_node.active:
                    active_streams.add(stream_node.name)
                    if stream_node.name not in stream_cpes:
                        stream_cpes[stream_node.name] = []
                    stream_cpes[stream_node.name].extend(stream_node.cpes)

        # Use enhanced matching to find relevant active streams
        matching_stream_names = self.enhanced_proddefs.enhance_cpe_matching(
            cpe, active_streams, stream_cpes
        )

        # Return the actual ProductStream objects for the matching streams
        result_streams = []
        for stream_name in matching_stream_names:
            # Find ProductStream objects with this name
            for stream_nodes in self.stream_nodes_by_cpe.values():
                for stream_node in stream_nodes:
                    if stream_node.name == stream_name and stream_node.active:
                        result_streams.append(copy.deepcopy(stream_node))

        return result_streams

    def _check_modules(self, leaf: Node, cpe: str, keep_cpes: bool) -> list[Node]:
        """Check if the cpe matches any ProductModule"""
        module_nodes = self.match_module_pattern(cpe)
        return self._duplicate_leaves_and_set_parents(leaf, module_nodes, keep_cpes)

    def _duplicate_leaves_and_set_parents(
        self, leaf: Node, product_nodes: list[Any], keep_cpes: bool
    ) -> list[Node]:
        """Convert product modules to their parent streams and attach all streams as children of the leaf.
        Deduplicates streams to avoid multiple identical children.

        Args:
            leaf: The leaf node to process
            product_nodes: List of product nodes (modules or streams)
            keep_cpes: If False, replace the leaf with streams in the tree. If True, set streams as children of the leaf.

        Returns:
            If keep_cpes=True: Returns the leaf in a list.
            If keep_cpes=False: Returns the list of unique streams that replaced the leaf.
        """
        if not product_nodes:
            if keep_cpes:
                # Keep the CPE node even if no products match
                return [leaf]
            else:
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

        if keep_cpes:
            # Original behavior: set streams as children of the leaf
            # Create copies to avoid modifying shared objects
            stream_copies = []
            for stream in unique_streams:
                stream_copy = copy.deepcopy(stream)
                stream_copy.parent = leaf
                stream_copies.append(stream_copy)
            return [leaf]
        else:
            # New behavior: replace the leaf with the streams in the tree
            # Create copies to avoid modifying shared objects
            stream_copies = []
            for stream in unique_streams:
                stream_copy = copy.deepcopy(stream)
                stream_copy.parent = leaf.parent
                stream_copies.append(stream_copy)
            return stream_copies

    def get_all_cpes_for_rhel_stream(self, stream_name: str) -> set[str]:
        """
        Get all CPEs that should be associated with a given RHEL stream by traversing
        the RHEL release graph to include related releases.

        Args:
            stream_name: The ps_update_stream name (e.g., "rhel-9.2.0.z")

        Returns:
            Set of all CPEs that should be associated with this stream
        """
        if not self.enhanced_proddefs:
            # Fallback to direct stream CPEs only
            result = set()
            for stream_nodes in self.stream_nodes_by_cpe.values():
                for stream_node in stream_nodes:
                    if stream_node.name == stream_name:
                        result.update(stream_node.cpes)
            return result

        # Get stream CPEs mapping
        stream_cpes: dict[str, list[str]] = {}
        for stream_nodes in self.stream_nodes_by_cpe.values():
            for stream_node in stream_nodes:
                if stream_node.name not in stream_cpes:
                    stream_cpes[stream_node.name] = []
                stream_cpes[stream_node.name].extend(stream_node.cpes)

        # Use enhanced matching to get all related CPEs
        return self.enhanced_proddefs.get_all_cpes_for_stream(stream_name, stream_cpes)

    def _add_ancestor(self, leaf: Node, product: Any) -> None:
        if product.parent:
            product.parent.parent = leaf
        else:
            product.parent = leaf
