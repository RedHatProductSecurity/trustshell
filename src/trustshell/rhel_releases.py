"""
RHEL Release Data Parser

This module handles parsing RHEL release data from YAML files and provides
functionality to match CPEs from SBOMs with active ps_update_streams based
on release hierarchy and relationships.
"""

from collections import defaultdict, deque
import logging
import os
import re
from typing import Any, Dict, List, Set, Optional
import httpx
import yaml

from trustshell import CONFIG_DIR

logger = logging.getLogger(__name__)


class RHELReleaseNode:
    """Represents a RHEL release node with its metadata and relationships."""

    def __init__(self, name: str, node_type: str, cpes: List[str]):
        self.name = name
        self.node_type = node_type  # main, eus, aus, e4s
        # Remove any single digit like cpe:/a:redhat:enterprise_linux:9::appstream
        self.cpes = [
            cpe for cpe in cpes if not re.search(r":redhat:enterprise_linux:\d:", cpe)
        ]
        self.children: Set[str] = set()
        self.parents: Set[str] = set()

    def __repr__(self) -> str:
        return f"RHELReleaseNode({self.name}, {self.node_type}, {len(self.cpes)} CPEs)"


class RHELReleaseData:
    """Parser and manager for RHEL release data from GitLab repository or local files."""

    # Default GitLab repository configuration
    DEFAULT_REPO_BASE = (
        "https://gitlab.cee.redhat.com/api/v4/projects/prodsec%2Frhel-release-graph"
    )
    DEFAULT_FILE_PATH = "rhel9-releases.yml"
    DEFAULT_BRANCH = "main"

    # Cache configuration
    CACHE_DIR = os.path.join(CONFIG_DIR, "rhel_release_cache")
    ETAG_FILE = "rhel_releases_etag.txt"
    DATA_FILE = "rhel_releases_data.yml"

    def __init__(
        self,
        git_branch: str = DEFAULT_BRANCH,
        file_path: str = DEFAULT_FILE_PATH,
        yaml_file_path: str = "",
    ):
        """
        Initialize RHEL release data from GitLab repository.

        Args:
            git_branch: Git branch to use (default: main)
            file_path: Path to file within repository (default: rhel9-releases.yml)
            yaml_file_path: Local file path (for testing only)
        """
        self.git_branch = git_branch
        self.file_path = file_path
        self.yaml_file_path = yaml_file_path  # Only for testing

        self.nodes: Dict[str, RHELReleaseNode] = {}
        self.cpe_to_nodes: Dict[str, List[RHELReleaseNode]] = defaultdict(list)

        # Ensure cache directory exists
        os.makedirs(self.CACHE_DIR, exist_ok=True)

        self._load_release_data()

    def _load_release_data(self) -> None:
        """Load and parse the RHEL release YAML file from GitLab or local file."""
        try:
            # Use local file if provided (for testing)
            if self.yaml_file_path:
                data = self._load_from_local_file()
            else:
                data = self._fetch_from_gitlab()

            if not data:
                logger.warning("No RHEL release data could be loaded")
                return

            self._parse_yaml_data(data)

        except Exception as e:
            logger.error(f"Error loading RHEL release data: {e}")

    def _load_from_local_file(self) -> Optional[Dict[str, Any]]:
        """Load YAML data from local file (for testing)."""
        if not os.path.exists(self.yaml_file_path):
            logger.warning(f"RHEL release data file not found: {self.yaml_file_path}")
            return None

        try:
            with open(self.yaml_file_path, "r") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return data
                else:
                    logger.error(
                        f"YAML file {self.yaml_file_path} does not contain a dictionary"
                    )
                    return None
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML file {self.yaml_file_path}: {e}")
            return None

    def _fetch_from_gitlab(self) -> Optional[Dict[str, Any]]:
        """Fetch YAML data from GitLab repository with caching."""
        cache_file = os.path.join(self.CACHE_DIR, self.DATA_FILE)
        etag_file = os.path.join(self.CACHE_DIR, self.ETAG_FILE)

        try:
            # Build GitLab API URL for the file
            # URL format: /projects/:id/repository/files/:file_path/raw?ref=:branch
            encoded_file_path = self.file_path.replace("/", "%2F")
            file_url = (
                f"{self.DEFAULT_REPO_BASE}/repository/files/{encoded_file_path}/raw"
            )

            # Load cached ETag if available
            cached_etag = self._load_cached_etag(etag_file)

            # Set up headers for conditional request
            headers = {}
            if cached_etag:
                headers["If-None-Match"] = cached_etag

            # Make request to GitLab
            # SSL certificate path can be set via SSL_CERT_FILE environment variable
            ssl_cert_file = os.environ.get("SSL_CERT_FILE")
            verify_ssl = ssl_cert_file if ssl_cert_file else True

            response = httpx.get(
                file_url,
                params={"ref": self.git_branch},
                headers=headers,
                timeout=30.0,
                verify=verify_ssl,
            )

            if response.status_code == 304:
                # Not modified, use cached data
                logger.info("RHEL release data not modified, using cached version")
                return self._load_cached_data(cache_file)

            elif response.status_code == 200:
                # New data available
                logger.info(
                    f"Fetched RHEL release data from GitLab (branch: {self.git_branch})"
                )

                # Parse the YAML content
                data = yaml.safe_load(response.text)
                if not isinstance(data, dict):
                    logger.error("YAML data from GitLab does not contain a dictionary")
                    return None

                # Cache the data and ETag
                self._cache_data(cache_file, response.text)

                # Cache ETag if provided
                etag = response.headers.get("etag")
                if etag:
                    self._cache_etag(etag_file, etag)

                return data

            else:
                logger.error(
                    f"Failed to fetch RHEL release data: {response.status_code} {response.reason_phrase}"
                )
                # Try to use cached data as fallback
                return self._load_cached_data(cache_file)

        except httpx.RequestError as e:
            logger.error(f"Network error fetching RHEL release data: {e}")
            # Try to use cached data as fallback
            return self._load_cached_data(cache_file)
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML from GitLab: {e}")
            return None

    def _load_cached_etag(self, etag_file: str) -> Optional[str]:
        """Load cached ETag value."""
        try:
            if os.path.exists(etag_file):
                with open(etag_file, "r") as f:
                    return f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load cached ETag: {e}")
        return None

    def _cache_etag(self, etag_file: str, etag: str) -> None:
        """Cache ETag value."""
        try:
            with open(etag_file, "w") as f:
                f.write(etag)
        except Exception as e:
            logger.debug(f"Could not cache ETag: {e}")

    def _load_cached_data(self, cache_file: str) -> Optional[Dict[str, Any]]:
        """Load cached YAML data."""
        try:
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        return data
                    else:
                        logger.debug(f"Cached data in {cache_file} is not a dictionary")
        except Exception as e:
            logger.debug(f"Could not load cached data: {e}")
        return None

    def _cache_data(self, cache_file: str, content: str) -> None:
        """Cache YAML data."""
        try:
            with open(cache_file, "w") as f:
                f.write(content)
        except Exception as e:
            logger.debug(f"Could not cache data: {e}")

    def _parse_yaml_data(self, data: Dict[str, Any]) -> None:
        """Parse YAML data and build node structures."""
        # Load nodes
        if "nodes" in data:
            for node_name, node_data in data["nodes"].items():
                node_type = node_data.get("type", "unknown")
                cpes = node_data.get("cpes", [])

                node = RHELReleaseNode(node_name, node_type, cpes)
                self.nodes[node_name] = node

                # Build CPE to node mapping (use node.cpes which are already filtered)
                for cpe in node.cpes:
                    self.cpe_to_nodes[cpe].append(node)

        # Load edges (relationships)
        if "edges" in data:
            for parent_name, children in data["edges"].items():
                if parent_name in self.nodes:
                    parent_node = self.nodes[parent_name]
                    for child_name in children:
                        if child_name in self.nodes:
                            parent_node.children.add(child_name)
                            self.nodes[child_name].parents.add(parent_name)

        logger.info(f"Loaded {len(self.nodes)} RHEL release nodes")

    def get_leaf_nodes(self) -> List[RHELReleaseNode]:
        """Get all leaf nodes (nodes with no children)."""
        return [node for node in self.nodes.values() if not node.children]

    def get_descendants(self, node_name: str) -> Set[str]:
        """Get all descendants (children, grandchildren, etc.) of a node."""
        if node_name not in self.nodes:
            return set()

        descendants = set()
        queue = deque([node_name])

        while queue:
            current = queue.popleft()
            if current in self.nodes:
                for child in self.nodes[current].children:
                    if child not in descendants:
                        descendants.add(child)
                        queue.append(child)

        return descendants

    def get_ancestors(self, node_name: str) -> Set[str]:
        """Get all ancestors (parents, grandparents, etc.) of a node."""
        if node_name not in self.nodes:
            return set()

        ancestors = set()
        queue = deque([node_name])

        while queue:
            current = queue.popleft()
            if current in self.nodes:
                for parent in self.nodes[current].parents:
                    if parent not in ancestors:
                        ancestors.add(parent)
                        queue.append(parent)

        return ancestors

    def find_matching_nodes_for_cpe(self, cpe: str) -> List[RHELReleaseNode]:
        """Find all RHEL release nodes that contain the given CPE."""
        return self.cpe_to_nodes.get(cpe, [])

    def find_active_streams_for_cpe(
        self, cpe: str, active_streams: Set[str], stream_cpes: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Find active ps_update_streams that should be associated with a given CPE.

        This implements the rules:
        1. If CPE matches directly to an active ps_update_stream, use it
        2. If CPE matches to a parent node, consider it part of each leaf node
           whose CPEs are in active streams

        Args:
            cpe: The CPE to match
            active_streams: Set of active ps_update_stream names
            stream_cpes: Mapping of stream names to their CPEs

        Returns:
            Set of active stream names that should be associated with this CPE
        """
        result_streams = set()

        # TODO once we add the other fake CPEs to the rhel release graph match all rhel streams here
        # Check if any active streams start with 'rhel-9' - if so, always use RHEL release graph
        has_rhel9_streams = any(
            stream_name.startswith("rhel-9") for stream_name in active_streams
        )

        if not has_rhel9_streams:
            # For non-RHEL 9 streams, use direct matching first
            for stream_name in active_streams:
                if stream_name in stream_cpes:
                    if cpe in stream_cpes[stream_name]:
                        result_streams.add(stream_name)

            # If we found direct matches for non-RHEL 9 streams, return them
            if result_streams:
                return result_streams

        # For RHEL 9 streams or when no direct matches found, use RHEL release graph
        matching_nodes = self.find_matching_nodes_for_cpe(cpe)

        for node in matching_nodes:
            # For each matching node, find its leaf descendants
            descendants = self.get_descendants(node.name)

            # Include the node itself if it's a leaf
            all_candidate_nodes = descendants | {node.name}

            # Check if any leaf descendants have CPEs in active streams
            for candidate_node_name in all_candidate_nodes:
                if candidate_node_name in self.nodes:
                    candidate_node = self.nodes[candidate_node_name]

                    # Check if this is effectively a leaf (or the original node)
                    # and if its CPEs are represented in active streams
                    for candidate_cpe in candidate_node.cpes:
                        for stream_name in active_streams:
                            if stream_name in stream_cpes:
                                if candidate_cpe in stream_cpes[stream_name]:
                                    result_streams.add(stream_name)

        return result_streams

    def get_all_cpes_for_stream(
        self, stream_name: str, stream_cpes: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Get all CPEs that should be associated with a given RHEL stream by traversing
        the release graph to find related nodes using CPE-based matching.

        Args:
            stream_name: The ps_update_stream name (e.g., "rhel-9.2.0.z")
            stream_cpes: Mapping of stream names to their direct CPEs

        Returns:
            Set of all CPEs that should be associated with this stream
        """
        all_cpes = set()

        # Start with the stream's direct CPEs
        if stream_name in stream_cpes:
            all_cpes.update(stream_cpes[stream_name])

        # Use the stream's CPEs to find matching nodes in the RHEL release graph
        if stream_name in stream_cpes:
            matching_nodes = set()

            # For each CPE in the stream, find matching nodes in the release graph
            for cpe in stream_cpes[stream_name]:
                nodes_for_cpe = self.find_matching_nodes_for_cpe(cpe)
                matching_nodes.update(nodes_for_cpe)

            # For each matching node, collect CPEs from the node and its ancestors
            for node in matching_nodes:
                # Add CPEs from this node
                all_cpes.update(node.cpes)

                # Add CPEs from ancestor nodes (parent releases)
                ancestors = self.get_ancestors(node.name)
                for ancestor_name in ancestors:
                    if ancestor_name in self.nodes:
                        all_cpes.update(self.nodes[ancestor_name].cpes)

        return all_cpes

    def get_node_hierarchy(self) -> str:
        """Get a string representation of the node hierarchy for debugging."""
        lines = []

        # Find root nodes (nodes with no parents)
        root_nodes = [node for node in self.nodes.values() if not node.parents]

        def traverse(node: RHELReleaseNode, indent: int = 0) -> None:
            prefix = "  " * indent
            lines.append(
                f"{prefix}{node.name} ({node.node_type}) - {len(node.cpes)} CPEs"
            )

            # Sort children for consistent output
            for child_name in sorted(node.children):
                if child_name in self.nodes:
                    traverse(self.nodes[child_name], indent + 1)

        for root in sorted(root_nodes, key=lambda x: x.name):
            traverse(root)

        return "\n".join(lines)


class EnhancedProdDefs:
    """Enhanced product definitions that incorporate RHEL release data."""

    def __init__(
        self,
        git_branch: str = RHELReleaseData.DEFAULT_BRANCH,
        rhel_releases_path: str = "",
    ):
        """
        Initialize enhanced product definitions.

        Args:
            git_branch: Git branch to use for RHEL release data
            rhel_releases_path: Local file path (for testing only)
        """
        self.rhel_releases: Optional[RHELReleaseData] = None

        try:
            # Only try to load if we have a valid file path that exists
            if rhel_releases_path and os.path.exists(rhel_releases_path):
                self.rhel_releases = RHELReleaseData(
                    git_branch=git_branch, yaml_file_path=rhel_releases_path
                )
            elif not rhel_releases_path:
                # No local file, try GitLab
                self.rhel_releases = RHELReleaseData(git_branch=git_branch)
            else:
                logger.warning(f"RHEL release file not found: {rhel_releases_path}")
                self.rhel_releases = None
        except Exception as e:
            logger.warning(f"Could not load RHEL release data: {e}")
            self.rhel_releases = None

    def enhance_cpe_matching(
        self, cpe: str, active_streams: Set[str], stream_cpes: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Enhance CPE matching using RHEL release hierarchy data.

        Returns the set of active streams that should be associated with the CPE.
        """
        if not self.rhel_releases:
            # Fallback to direct matching only
            result = set()
            for stream_name in active_streams:
                if stream_name in stream_cpes and cpe in stream_cpes[stream_name]:
                    result.add(stream_name)
            return result

        result = self.rhel_releases.find_active_streams_for_cpe(
            cpe, active_streams, stream_cpes
        )
        return result if result is not None else set()

    def get_all_cpes_for_stream(
        self, stream_name: str, stream_cpes: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Get all CPEs that should be associated with a given RHEL stream.

        Args:
            stream_name: The ps_update_stream name (e.g., "rhel-9.2.0.z")
            stream_cpes: Mapping of stream names to their direct CPEs

        Returns:
            Set of all CPEs that should be associated with this stream
        """
        if not self.rhel_releases:
            # Fallback to direct CPEs only
            return set(stream_cpes.get(stream_name, []))

        return self.rhel_releases.get_all_cpes_for_stream(stream_name, stream_cpes)
