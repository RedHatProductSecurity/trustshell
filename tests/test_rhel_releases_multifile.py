"""Tests for RHEL release data parsing with multiple files."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import yaml

from trustshell.rhel_releases import RHELReleaseData


def create_test_rhel8_data():
    """Create test RHEL 8 release data."""
    return """
nodes:
    RHEL-8.0.0.GA:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:8.0::appstream
        - cpe:/o:redhat:enterprise_linux:8.0::baseos

    RHEL-8.0.0.Z.EUS:
      type: eus
      cpes:
        - cpe:/a:redhat:rhel_eus:8.0::appstream
        - cpe:/o:redhat:rhel_eus:8.0::baseos

edges:
    RHEL-8.0.0.GA:
        - RHEL-8.0.0.Z.EUS
"""


def create_test_rhel9_data():
    """Create test RHEL 9 release data."""
    return """
nodes:
    RHEL-9.0.0.GA:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.0::appstream
        - cpe:/o:redhat:enterprise_linux:9.0::baseos

    RHEL-9.0.0.Z.EUS:
      type: eus
      cpes:
        - cpe:/a:redhat:rhel_eus:9.0::appstream
        - cpe:/o:redhat:rhel_eus:9.0::baseos

edges:
    RHEL-9.0.0.GA:
        - RHEL-9.0.0.Z.EUS
"""


class TestRHELReleaseDataMultiFile:
    """Test RHEL release data parsing with multiple files."""

    def test_local_multifile_loading(self):
        """Test loading from multiple local files to validate merge logic."""
        # This test simulates what would happen when loading multiple files
        # by manually combining the data
        rhel8_data = yaml.safe_load(create_test_rhel8_data())
        rhel9_data = yaml.safe_load(create_test_rhel9_data())

        # Create a combined dataset like what _fetch_and_combine_files would produce
        combined_data = {"nodes": {}, "edges": {}}

        # Merge the data
        combined_data["nodes"].update(rhel8_data["nodes"])
        combined_data["nodes"].update(rhel9_data["nodes"])
        combined_data["edges"].update(rhel8_data["edges"])
        combined_data["edges"].update(rhel9_data["edges"])

        # Write the combined data to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(combined_data, f)
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                # Check that nodes from both files were loaded
                assert len(rhel_data.nodes) == 4
                assert "RHEL-8.0.0.GA" in rhel_data.nodes
                assert "RHEL-8.0.0.Z.EUS" in rhel_data.nodes
                assert "RHEL-9.0.0.GA" in rhel_data.nodes
                assert "RHEL-9.0.0.Z.EUS" in rhel_data.nodes

                # Check CPE mappings work across versions
                # Use version-specific CPEs that won't be filtered out
                rhel8_matches = rhel_data.find_matching_nodes_for_cpe(
                    "cpe:/a:redhat:enterprise_linux:8.0::appstream"
                )
                assert len(rhel8_matches) == 1
                assert rhel8_matches[0].name == "RHEL-8.0.0.GA"

                rhel9_matches = rhel_data.find_matching_nodes_for_cpe(
                    "cpe:/a:redhat:enterprise_linux:9.0::appstream"
                )
                assert len(rhel9_matches) == 1
                assert rhel9_matches[0].name == "RHEL-9.0.0.GA"

            finally:
                os.unlink(f.name)

    @patch("trustshell.rhel_releases.httpx.get")
    def test_gitlab_multifile_listing(self, mock_get):
        """Test GitLab API calls for listing files matching pattern."""

        # Mock the tree listing response
        tree_response = MagicMock()
        tree_response.status_code = 200
        tree_response.json.return_value = [
            {"type": "blob", "path": "rhel8-releases.yml"},
            {"type": "blob", "path": "rhel9-releases.yml"},
            {"type": "blob", "path": "rhel10-releases.yml"},
            {"type": "blob", "path": "other-file.txt"},
            {"type": "tree", "path": "directory"},
        ]

        # Mock the commit response
        commit_response = MagicMock()
        commit_response.status_code = 200
        commit_response.json.return_value = [{"id": "new_commit_hash_123"}]

        # Mock file content responses
        file_response_8 = MagicMock()
        file_response_8.status_code = 200
        file_response_8.text = create_test_rhel8_data()

        file_response_9 = MagicMock()
        file_response_9.status_code = 200
        file_response_9.text = create_test_rhel9_data()

        file_response_10 = MagicMock()
        file_response_10.status_code = 200
        file_response_10.text = """
nodes:
    RHEL-10.0.0.GA:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:10::appstream

edges: {}
"""

        # Configure the mock to return different responses based on URL
        def mock_get_side_effect(url, **kwargs):
            if "/repository/tree" in url:
                return tree_response
            elif "/repository/commits" in url:
                return commit_response
            elif "rhel8-releases.yml" in url:
                return file_response_8
            elif "rhel9-releases.yml" in url:
                return file_response_9
            elif "rhel10-releases.yml" in url:
                return file_response_10
            return MagicMock(status_code=404)

        mock_get.side_effect = mock_get_side_effect

        # Create a temporary cache directory to ensure clean state
        import tempfile

        temp_cache_dir = tempfile.mkdtemp()

        try:
            # Set environment variable for GitLab URL
            with (
                patch.dict(
                    os.environ,
                    {
                        "RHEL_RELEASE_GRAPH_URL": "https://example.com/api/v4/projects/123"
                    },
                ),
                patch.object(
                    RHELReleaseData,
                    "RHEL_RELEASE_GRAPH_BASE",
                    "https://example.com/api/v4/projects/123",
                ),
                patch.object(RHELReleaseData, "CACHE_DIR", temp_cache_dir),
            ):
                rhel_data = RHELReleaseData()

                # Verify that all files were processed
                assert (
                    len(rhel_data.nodes) == 5
                )  # 2 from rhel8 + 2 from rhel9 + 1 from rhel10
                assert "RHEL-8.0.0.GA" in rhel_data.nodes
                assert "RHEL-9.0.0.GA" in rhel_data.nodes
                assert "RHEL-10.0.0.GA" in rhel_data.nodes

                # Verify the listing call was made
                tree_calls = [
                    call
                    for call in mock_get.call_args_list
                    if "/repository/tree" in str(call)
                ]
                assert len(tree_calls) == 1

                # Verify file fetching calls were made
                file_calls = [
                    call
                    for call in mock_get.call_args_list
                    if "/repository/files/" in str(call)
                ]
                assert len(file_calls) == 3  # Should fetch 3 *-releases.yml files

        finally:
            # Clean up temp directory
            import shutil

            shutil.rmtree(temp_cache_dir)

    def test_conflicting_nodes_handling(self):
        """Test handling of conflicting node names across files."""
        # Create data with conflicting node names
        conflicting_data1 = {
            "nodes": {
                "RHEL-9.0.0.GA": {
                    "type": "main",
                    "cpes": ["cpe:/a:redhat:enterprise_linux:9::appstream"],
                }
            },
            "edges": {},
        }

        conflicting_data2 = {
            "nodes": {
                "RHEL-9.0.0.GA": {  # Same node name
                    "type": "eus",  # Different type
                    "cpes": ["cpe:/a:redhat:rhel_eus:9::appstream"],
                }
            },
            "edges": {},
        }

        # Manually simulate the merge process
        combined_nodes = {}
        combined_nodes.update(conflicting_data1["nodes"])
        combined_nodes.update(conflicting_data2["nodes"])  # This should overwrite

        # The second file's data should win
        assert combined_nodes["RHEL-9.0.0.GA"]["type"] == "eus"
        assert (
            "cpe:/a:redhat:rhel_eus:9::appstream"
            in combined_nodes["RHEL-9.0.0.GA"]["cpes"]
        )

        # Create the combined data and test with RHELReleaseData
        combined_data = {"nodes": combined_nodes, "edges": {}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(combined_data, f)
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                # Verify the conflicting node was handled (second one wins)
                assert rhel_data.nodes["RHEL-9.0.0.GA"].node_type == "eus"

            finally:
                os.unlink(f.name)
