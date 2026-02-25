from collections import defaultdict
import copy
from datetime import datetime
import json
import logging
import os
import re
from typing import Any, Optional
import httpx

from anytree import NodeMixin, LevelOrderGroupIter
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
        check_lifecycle: bool = False,
    ) -> None:
        self.stream_nodes_by_cpe: dict[str, list[ProductStream]] = defaultdict(list)
        product_streams_by_name: dict[str, list[ProductStream]] = defaultdict(list)
        self.stream_to_module: dict[str, str] = {}  # stream_name -> ps_module
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

            # Check module-level active status based on lifecycle data
            module_is_active = True
            if check_lifecycle:
                lifecycle = module_data.get("lifecycle", {})
                if lifecycle:
                    supported_from = lifecycle.get("supported_from")
                    if supported_from:
                        try:
                            supported_from_date = datetime.strptime(
                                supported_from, "%Y-%m-%d"
                            ).date()
                            current_date = datetime.now().date()
                            # Module is only active if supported_from date is today or in the past
                            module_is_active = supported_from_date <= current_date
                        except ValueError as e:
                            logger.warning(
                                f"Invalid date format for {ps_module} supported_from: {supported_from}, error: {e}"
                            )

                # Skip this module if it's not active yet (based on lifecycle)
                if active_only and not module_is_active:
                    continue

            active_streams: set[str] = set()
            active_streams.update(module_data.get("active_ps_update_streams", []))
            for stream in module_data.get("ps_update_streams"):
                self.stream_to_module.setdefault(stream, ps_module)
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

    def get_product_mappings_for_cpe(self, cpe: str) -> list[tuple[str, Optional[str]]]:
        """Return (ps_update_stream, ps_module) for each product matching the CPE.

        Tries ps_update_stream direct CPE match first, then falls back to ps_module
        pattern match. Populates ps_module from stream's parent module when matching
        via stream.
        """
        if not self.product_trees:
            return []

        cleaned_cpe = self._clean_cpe(cpe)
        if re.search(r":redhat:enterprise_linux:\d:", cleaned_cpe):
            return []

        mappings: list[tuple[str, Optional[str]]] = []

        # Try stream matches first (direct CPE match or enhanced)
        enhanced_streams = self._check_enhanced_streams(cleaned_cpe)
        if enhanced_streams:
            for stream in enhanced_streams:
                ps_module = self.stream_to_module.get(stream.name)
                mappings.append((stream.name, ps_module))
        elif cleaned_cpe in self.stream_nodes_by_cpe:
            for stream in self.stream_nodes_by_cpe[cleaned_cpe]:
                ps_module = self.stream_to_module.get(stream.name)
                mappings.append((stream.name, ps_module))

        # Fall back to module matches only if no stream match
        if not mappings:
            module_matches = self.match_module_pattern(cleaned_cpe)
            for module in module_matches:
                if module.parent and isinstance(module.parent, ProductStream):
                    mappings.append((module.parent.name, module.name))

        return mappings

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
