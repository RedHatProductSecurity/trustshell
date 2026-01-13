"""
RHEL Release Data Parser

This module handles parsing RHEL release data from YAML files and provides
functionality to match CPEs from SBOMs with active ps_update_streams based
on release hierarchy and relationships.
"""

from collections import defaultdict, deque
import fnmatch
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

    def __init__(
        self,
        name: str,
        node_type: str,
        cpes: List[str],
        ps_update_stream: Optional[str] = None,
    ):
        self.name = name
        self.node_type = node_type  # main, eus, aus, e4s
        # Remove any single digit like cpe:/a:redhat:enterprise_linux:9::appstream
        self.cpes = [
            cpe for cpe in cpes if not re.search(r":redhat:enterprise_linux:\d:", cpe)
        ]
        self.ps_update_stream = (
            ps_update_stream  # The ps_update_stream associated with this node
        )
        self.children: Set[str] = set()
        self.parents: Set[str] = set()

    def __repr__(self) -> str:
        return f"RHELReleaseNode({self.name}, {self.node_type}, {len(self.cpes)} CPEs)"


class RHELReleaseData:
    """Parser and manager for RHEL release data from GitLab repository or local files.

    When loading from GitLab, this class automatically discovers and loads data from all
    YAML files matching the '*-releases.yml' pattern (e.g., rhel8-releases.yml,
    rhel9-releases.yml, rhel10-releases.yml) and combines them into a single unified
    data structure.

    When loading from a local file (for testing), only that single file is loaded.

    Caching is implemented using the latest Git commit hash to detect changes across
    all release files, rather than individual file ETags.
    """

    # GitLab repository configuration (can be overridden with RHEL_RELEASE_GRAPH_URL env var)
    RHEL_RELEASE_GRAPH_BASE = os.environ.get("RHEL_RELEASE_GRAPH_URL")
    DEFAULT_BRANCH = "main"
    DEFAULT_GLOB_PATTERN = "*-releases.yml"

    # Cache configuration
    CACHE_DIR = os.path.join(CONFIG_DIR, "rhel_release_cache")
    ETAG_FILE = (
        "rhel_releases_commit_hash.txt"  # Now stores commit hash instead of ETag
    )
    DATA_FILE = "rhel_releases_combined_data.yml"  # Now contains data from all *-releases.yml files

    def __init__(
        self,
        git_branch: str = DEFAULT_BRANCH,
        yaml_file_path: str = "",
    ):
        """
        Initialize RHEL release data from GitLab repository or local file.

        When loading from GitLab, the system will find all files matching the
        *-releases.yml pattern and combine their data. When using a local file,
        only that single file will be loaded.

        Args:
            git_branch: Git branch to use (default: main)
            file_path: Path to file within repository (default: rhel9-releases.yml)
            yaml_file_path: Local file path (for testing only)
        """
        self.git_branch = git_branch
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
        """Fetch YAML data from GitLab repository with caching.

        Supports loading from multiple files matching the *-releases.yml glob pattern.
        """
        cache_file = os.path.join(self.CACHE_DIR, self.DATA_FILE)
        commit_hash_file = os.path.join(self.CACHE_DIR, self.ETAG_FILE)

        try:
            # Get list of matching files from repository
            matching_files = self._list_matching_files("*-releases.yml")
            if not matching_files:
                logger.error("No files matching *-releases.yml pattern found")
                return None

            # Load cached commit hash if available
            cached_commit_hash = self._load_cached_commit_hash(commit_hash_file)

            # Check if any files have been modified using repository info
            # We use the latest commit hash for cache invalidation
            latest_commit = self._get_latest_commit_hash()
            if cached_commit_hash and cached_commit_hash == latest_commit:
                logger.info("RHEL release data not modified, using cached version")
                return self._load_cached_data(cache_file)

            # Fetch and combine data from all matching files
            combined_data = self._fetch_and_combine_files(matching_files)
            if not combined_data:
                logger.error("Failed to load data from any matching files")
                return self._load_cached_data(cache_file)

            logger.info(
                f"Fetched RHEL release data from {len(matching_files)} files "
                f"from GitLab (branch: {self.git_branch})"
            )

            # Cache the combined data
            self._cache_data(cache_file, yaml.dump(combined_data))

            # Cache the commit hash for future invalidation
            if latest_commit:
                self._cache_commit_hash(commit_hash_file, latest_commit)

            return combined_data

        except httpx.RequestError as e:
            logger.error(f"Network error fetching RHEL release data: {e}")
            # Try to use cached data as fallback
            return self._load_cached_data(cache_file)
        except Exception as e:
            logger.error(f"Error fetching RHEL release data: {e}")
            return self._load_cached_data(cache_file)

    def _list_matching_files(self, pattern: str) -> List[str]:
        """List files in the repository that match the given glob pattern."""
        try:
            # Build GitLab API URL for listing repository tree
            # URL format: /projects/:id/repository/tree?ref=:branch&recursive=true
            tree_url = f"{self.RHEL_RELEASE_GRAPH_BASE}/repository/tree"

            # SSL certificate path can be set via SSL_CERT_FILE environment variable
            ssl_cert_file = os.environ.get("SSL_CERT_FILE")
            verify_ssl = ssl_cert_file if ssl_cert_file else True

            response = httpx.get(
                tree_url,
                params={"ref": self.git_branch, "recursive": "true"},
                timeout=30.0,
                verify=verify_ssl,
            )

            if response.status_code != 200:
                logger.error(
                    f"Failed to list repository files: {response.status_code} {response.reason_phrase}"
                )
                return []

            files_data = response.json()

            # Filter files matching the pattern
            matching_files = []
            for item in files_data:
                if item.get("type") == "blob":  # Only include files, not directories
                    file_path = item.get("path", "")
                    filename = os.path.basename(file_path)
                    if fnmatch.fnmatch(filename, pattern):
                        matching_files.append(file_path)

            logger.info(
                f"Found {len(matching_files)} files matching pattern '{pattern}': {matching_files}"
            )
            return matching_files

        except httpx.RequestError as e:
            logger.error(f"Network error listing repository files: {e}")
            return []
        except Exception as e:
            logger.error(f"Error listing repository files: {e}")
            return []

    def _get_latest_commit_hash(self) -> Optional[str]:
        """Get the latest commit hash for the branch to use as cache invalidation."""
        try:
            # Build GitLab API URL for getting latest commit
            # URL format: /projects/:id/repository/commits?ref_name=:branch&per_page=1
            commits_url = f"{self.RHEL_RELEASE_GRAPH_BASE}/repository/commits"

            # SSL certificate path can be set via SSL_CERT_FILE environment variable
            ssl_cert_file = os.environ.get("SSL_CERT_FILE")
            verify_ssl = ssl_cert_file if ssl_cert_file else True

            response = httpx.get(
                commits_url,
                params={"ref_name": self.git_branch, "per_page": "1"},
                timeout=30.0,
                verify=verify_ssl,
            )

            if response.status_code != 200:
                logger.error(
                    f"Failed to get latest commit: {response.status_code} {response.reason_phrase}"
                )
                return None

            commits_data = response.json()
            if commits_data and len(commits_data) > 0:
                commit_id = commits_data[0].get("id")
                return commit_id if isinstance(commit_id, str) else None

        except httpx.RequestError as e:
            logger.error(f"Network error getting latest commit: {e}")
        except Exception as e:
            logger.error(f"Error getting latest commit: {e}")

        return None

    def _fetch_and_combine_files(
        self, file_paths: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Fetch multiple YAML files and combine their data."""
        combined_nodes: Dict[str, Any] = {}
        combined_edges: Dict[str, Any] = {}

        # SSL certificate path can be set via SSL_CERT_FILE environment variable
        ssl_cert_file = os.environ.get("SSL_CERT_FILE")
        verify_ssl = ssl_cert_file if ssl_cert_file else True

        for file_path in file_paths:
            try:
                # Build GitLab API URL for the file
                # URL format: /projects/:id/repository/files/:file_path/raw?ref=:branch
                encoded_file_path = file_path.replace("/", "%2F")
                file_url = f"{self.RHEL_RELEASE_GRAPH_BASE}/repository/files/{encoded_file_path}/raw"

                response = httpx.get(
                    file_url,
                    params={"ref": self.git_branch},
                    timeout=30.0,
                    verify=verify_ssl,
                )

                if response.status_code != 200:
                    logger.warning(
                        f"Failed to fetch file {file_path}: {response.status_code} {response.reason_phrase}"
                    )
                    continue

                # Parse the YAML content
                file_data = yaml.safe_load(response.text)
                if not isinstance(file_data, dict):
                    logger.warning(
                        f"YAML data from {file_path} does not contain a dictionary"
                    )
                    continue

                # Merge nodes data
                if "nodes" in file_data:
                    if not isinstance(file_data["nodes"], dict):
                        logger.warning(f"Nodes data in {file_path} is not a dictionary")
                    else:
                        # Check for conflicting node names
                        conflicting_nodes = set(combined_nodes.keys()) & set(
                            file_data["nodes"].keys()
                        )
                        if conflicting_nodes:
                            logger.warning(
                                f"File {file_path} contains nodes that conflict with previously loaded data: "
                                f"{conflicting_nodes}"
                            )
                        combined_nodes.update(file_data["nodes"])

                # Merge edges data
                if "edges" in file_data:
                    if not isinstance(file_data["edges"], dict):
                        logger.warning(f"Edges data in {file_path} is not a dictionary")
                    else:
                        # Check for conflicting edge sources
                        conflicting_edges = set(combined_edges.keys()) & set(
                            file_data["edges"].keys()
                        )
                        if conflicting_edges:
                            logger.warning(
                                f"File {file_path} contains edges that conflict with previously loaded data: "
                                f"{conflicting_edges}"
                            )
                        combined_edges.update(file_data["edges"])

                logger.info(f"Successfully loaded data from {file_path}")

            except yaml.YAMLError as e:
                logger.error(f"Failed to parse YAML from {file_path}: {e}")
                continue
            except httpx.RequestError as e:
                logger.error(f"Network error fetching {file_path}: {e}")
                continue
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                continue

        if not combined_nodes:
            logger.error("No valid node data found in any matching files")
            return None

        result = {}
        if combined_nodes:
            result["nodes"] = combined_nodes
        if combined_edges:
            result["edges"] = combined_edges

        logger.info(
            f"Combined data from {len(file_paths)} files: "
            f"{len(combined_nodes)} nodes, {len(combined_edges)} edge sources"
        )

        return result

    def _load_cached_commit_hash(self, commit_hash_file: str) -> Optional[str]:
        """Load cached commit hash value."""
        try:
            if os.path.exists(commit_hash_file):
                with open(commit_hash_file, "r") as f:
                    return f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load cached commit hash: {e}")
        return None

    def _cache_commit_hash(self, commit_hash_file: str, commit_hash: str) -> None:
        """Cache commit hash value."""
        try:
            with open(commit_hash_file, "w") as f:
                f.write(commit_hash)
        except Exception as e:
            logger.debug(f"Could not cache commit hash: {e}")

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
                ps_update_stream = node_data.get(
                    "ps_update_stream"
                )  # Extract stream field from YAML

                node = RHELReleaseNode(node_name, node_type, cpes, ps_update_stream)
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
        1. For non-RHEL streams: If CPE matches directly to an active ps_update_stream, use it
        2. For RHEL streams: Use the RHEL release graph to find nodes matching the CPE,
           then match nodes to streams using their ps_update_stream attribute

        Args:
            cpe: The CPE to match (typically from an SBOM)
            active_streams: Set of active ps_update_stream names
            stream_cpes: Mapping of stream names to their CPEs (from product-definitions)

        Returns:
            Set of active stream names that should be associated with this CPE
        """
        result_streams = set()

        # Check if any active streams start with 'rhel-' followed by a digit (e.g., rhel-9, rhel-8)
        # but exclude streams like 'rhel-br-' - if so, always use RHEL release graph
        has_active_rhel_streams = any(
            stream_name.startswith("rhel-")
            and len(stream_name) > 5
            and stream_name[5].isdigit()
            for stream_name in active_streams
        )

        if not has_active_rhel_streams:
            # For non-RHEL 9 streams, use direct matching first
            for stream_name in active_streams:
                if stream_name in stream_cpes:
                    if cpe in stream_cpes[stream_name]:
                        result_streams.add(stream_name)

            # If we found direct matches for non-RHEL streams, return them
            if result_streams:
                return result_streams

        # For RHEL streams or when no direct matches found, use RHEL release graph
        matching_nodes = self.find_matching_nodes_for_cpe(cpe)

        for node in matching_nodes:
            # For each matching node, find its leaf descendants
            descendants = self.get_descendants(node.name)

            # Include the node itself if it's a leaf
            all_candidate_nodes = descendants | {node.name}

            # Check if any leaf descendants match active streams by ps_update_stream
            for candidate_node_name in all_candidate_nodes:
                if candidate_node_name in self.nodes:
                    candidate_node = self.nodes[candidate_node_name]

                    # Check if this node's ps_update_stream matches any active stream
                    # This avoids relying on CPE matching between product-definitions and rhel_releases
                    if candidate_node.ps_update_stream:
                        if candidate_node.ps_update_stream in active_streams:
                            result_streams.add(candidate_node.ps_update_stream)

        return result_streams

    def get_all_cpes_for_stream(
        self, stream_name: str, stream_cpes: Dict[str, List[str]]
    ) -> Set[str]:
        """
        Get all CPEs that should be associated with a given RHEL stream by traversing
        the release graph to find related nodes using ps_update_stream attribute matching.

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

        # Find matching nodes by ps_update_stream attribute instead of CPE matching
        matching_nodes = set()
        for node in self.nodes.values():
            if node.ps_update_stream == stream_name:
                matching_nodes.add(node)

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
