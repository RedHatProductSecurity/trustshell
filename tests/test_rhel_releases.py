"""Tests for RHEL release data parsing and CPE matching functionality."""

import os
import tempfile
from unittest.mock import patch

from trustshell.product_definitions import ProdDefs
from trustshell.rhel_releases import EnhancedProdDefs, RHELReleaseData


def create_test_rhel_data():
    """Create test RHEL release data similar to the actual structure."""
    return """
nodes:
    RHEL-9.0.0.GA:
      type: main
      ps_update_stream: rhel-9.0.0.z
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.0::appstream
        - cpe:/o:redhat:enterprise_linux:9.0::baseos
        - cpe:/a:redhat:enterprise_linux:9.0::crb

    RHEL-9.0.0.Z.MAIN+EUS:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.0::appstream
        - cpe:/o:redhat:enterprise_linux:9.0::baseos
        - cpe:/a:redhat:enterprise_linux:9.0::crb

    RHEL-9.0.0.Z.EUS:
      type: eus
      cpes:
        - cpe:/a:redhat:rhel_eus:9.0::appstream
        - cpe:/o:redhat:rhel_eus:9.0::baseos
        - cpe:/a:redhat:rhel_eus:9.0::crb

    RHEL-9.2.0.GA:
      type: main
      ps_update_stream: rhel-9.2.0.z
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.2::appstream
        - cpe:/o:redhat:enterprise_linux:9.2::baseos
        - cpe:/a:redhat:enterprise_linux:9.2::appstream

    RHEL-9.2.0.Z.EUS:
      type: eus
      cpes:
        - cpe:/a:redhat:rhel_eus:9.2::appstream
        - cpe:/o:redhat:rhel_eus:9.2::baseos

edges:
    RHEL-9.0.0.GA:
        - RHEL-9.0.0.Z.MAIN+EUS
    RHEL-9.0.0.Z.MAIN+EUS:
        - RHEL-9.0.0.Z.EUS
        - RHEL-9.2.0.GA
    RHEL-9.2.0.GA:
        - RHEL-9.2.0.Z.EUS
"""


def create_test_product_definitions():
    """Create test product definitions data."""
    return {
        "ps_modules": {
            "rhel-9": {
                "public_description": "Red Hat Enterprise Linux 9",
                "ps_update_streams": ["rhel-9.0.0.z", "rhel-9.2.0.z"],
                "active_ps_update_streams": ["rhel-9.0.0.z", "rhel-9.2.0.z"],
                "cpe": [
                    "cpe:/a:redhat:enterprise_linux:9",
                ],
            }
        },
        "ps_update_streams": {
            "rhel-9.0.0.z": {
                "pp_label": "rhel-9.0.0.z",
                "version": "rhel-9.0.0.z",
                "cpe": [
                    "cpe:/a:redhat:rhel_eus:9.0::appstream",
                    "cpe:/o:redhat:rhel_eus:9.0::baseos",
                    "cpe:/a:redhat:rhel_eus:9.0::crb",
                ],
            },
            "rhel-9.2.0.z": {
                "pp_label": "rhel-9.2.0.z",
                "version": "rhel-9.2.0.z",
                "cpe": [
                    "cpe:/a:redhat:rhel_eus:9.2::appstream",
                    "cpe:/o:redhat:rhel_eus:9.2::baseos",
                ],
            },
        },
    }


class TestRHELReleaseData:
    """Test RHEL release data parsing."""

    def test_load_rhel_data(self):
        """Test loading RHEL release data from YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                # Check nodes were loaded
                assert len(rhel_data.nodes) == 5
                assert "RHEL-9.0.0.GA" in rhel_data.nodes
                assert "RHEL-9.2.0.Z.EUS" in rhel_data.nodes

                # Check node types
                assert rhel_data.nodes["RHEL-9.0.0.GA"].node_type == "main"
                assert rhel_data.nodes["RHEL-9.0.0.Z.EUS"].node_type == "eus"

                # Check CPE mappings
                ga_node = rhel_data.nodes["RHEL-9.0.0.GA"]
                assert "cpe:/a:redhat:enterprise_linux:9.0::appstream" in ga_node.cpes
                assert "cpe:/o:redhat:enterprise_linux:9.0::baseos" in ga_node.cpes

                # Check relationships
                assert "RHEL-9.0.0.Z.MAIN+EUS" in ga_node.children
                assert (
                    "RHEL-9.0.0.GA" in rhel_data.nodes["RHEL-9.0.0.Z.MAIN+EUS"].parents
                )

            finally:
                os.unlink(f.name)

    def test_find_matching_nodes_for_cpe(self):
        """Test finding nodes that match a specific CPE."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                # Test exact CPE match
                matches = rhel_data.find_matching_nodes_for_cpe(
                    "cpe:/a:redhat:enterprise_linux:9.0::appstream"
                )
                assert len(matches) == 2  # GA, MAIN+EUS, both have this CPE

                # Test EUS-specific CPE
                eus_matches = rhel_data.find_matching_nodes_for_cpe(
                    "cpe:/a:redhat:rhel_eus:9.0::appstream"
                )
                assert len(eus_matches) == 1
                assert eus_matches[0].name == "RHEL-9.0.0.Z.EUS"

                # Test non-existent CPE
                no_matches = rhel_data.find_matching_nodes_for_cpe("cpe:/nonexistent")
                assert len(no_matches) == 0

            finally:
                os.unlink(f.name)

    def test_get_descendants_and_ancestors(self):
        """Test finding descendants and ancestors of nodes."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                # Test descendants
                ga_descendants = rhel_data.get_descendants("RHEL-9.0.0.GA")
                assert "RHEL-9.0.0.Z.MAIN+EUS" in ga_descendants
                assert "RHEL-9.0.0.Z.EUS" in ga_descendants
                assert "RHEL-9.2.0.GA" in ga_descendants
                assert "RHEL-9.2.0.Z.EUS" in ga_descendants

                # Test ancestors
                eus_ancestors = rhel_data.get_ancestors("RHEL-9.0.0.Z.EUS")
                assert "RHEL-9.0.0.Z.MAIN+EUS" in eus_ancestors
                assert "RHEL-9.0.0.GA" in eus_ancestors

            finally:
                os.unlink(f.name)

    def test_get_leaf_nodes(self):
        """Test finding leaf nodes (nodes with no children)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                rhel_data = RHELReleaseData(yaml_file_path=f.name)

                leaf_nodes = rhel_data.get_leaf_nodes()
                leaf_names = {node.name for node in leaf_nodes}

                # EUS nodes should be leaves
                assert "RHEL-9.0.0.Z.EUS" in leaf_names
                assert "RHEL-9.2.0.Z.EUS" in leaf_names

                # GA and MAIN+EUS should not be leaves (they have children)
                assert "RHEL-9.0.0.GA" not in leaf_names
                assert "RHEL-9.0.0.Z.MAIN+EUS" not in leaf_names

            finally:
                os.unlink(f.name)


class TestEnhancedProdDefs:
    """Test enhanced product definitions with RHEL release data."""

    def test_enhance_cpe_matching_direct_match(self):
        """Test enhanced CPE matching for direct matches using ps_update_stream."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                enhanced = EnhancedProdDefs(rhel_releases_path=f.name)

                active_streams = {"rhel-9.0.0.z", "rhel-9.2.0.z"}
                stream_cpes = {
                    "rhel-9.0.0.z": [
                        "cpe:/a:redhat:rhel_eus:9.0::appstream",
                        "cpe:/o:redhat:rhel_eus:9.0::baseos",
                    ],
                    "rhel-9.2.0.z": [
                        "cpe:/a:redhat:rhel_eus:9.2::appstream",
                        "cpe:/o:redhat:rhel_eus:9.2::baseos",
                    ],
                }

                # Test CPE that matches RHEL-9.0.0.GA node (which has ps_update_stream: rhel-9.0.0.z)
                # The CPE from the GA node should match via ps_update_stream
                result = enhanced.enhance_cpe_matching(
                    "cpe:/a:redhat:enterprise_linux:9.0::appstream",
                    active_streams,
                    stream_cpes,
                )
                assert "rhel-9.0.0.z" in result

            finally:
                os.unlink(f.name)

    def test_enhance_cpe_matching_parent_match(self):
        """Test enhanced CPE matching for parent node matches."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                enhanced = EnhancedProdDefs(rhel_releases_path=f.name)

                active_streams = {"rhel-9.0.0.z", "rhel-9.2.0.z"}
                stream_cpes = {
                    "rhel-9.0.0.z": [
                        "cpe:/a:redhat:rhel_eus:9.0::appstream",
                        "cpe:/o:redhat:rhel_eus:9.0::baseos",
                    ],
                    "rhel-9.2.0.z": [
                        "cpe:/a:redhat:rhel_eus:9.2::appstream",
                        "cpe:/o:redhat:rhel_eus:9.2::baseos",
                    ],
                }

                # Test parent node CPE that should match leaf nodes
                # The CPE "cpe:/a:redhat:enterprise_linux:9::appstream" appears in parent nodes
                # and should map to active streams that have corresponding leaf CPEs
                result = enhanced.enhance_cpe_matching(
                    "cpe:/a:redhat:enterprise_linux:9.0::appstream",
                    active_streams,
                    stream_cpes,
                )

                # Should map to active streams based on leaf node relationships
                assert len(result) >= 1

            finally:
                os.unlink(f.name)

    def test_enhance_cpe_matching_with_ps_update_stream(self):
        """Test enhanced CPE matching using ps_update_stream attribute."""
        test_data_with_streams = """
nodes:
    RHEL-9.2.0.GA:
      type: main
      ps_update_stream: rhel-9.2.0.z
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.2::appstream
        - cpe:/o:redhat:enterprise_linux:9.2::baseos

    RHEL-9.3.0.GA:
      type: main
      ps_update_stream: rhel-9.3.0.z
      cpes:
        - cpe:/a:redhat:enterprise_linux:9.3::appstream

edges:
    RHEL-9.2.0.GA:
        - RHEL-9.3.0.GA
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(test_data_with_streams)
            f.flush()

            try:
                enhanced = EnhancedProdDefs(rhel_releases_path=f.name)

                active_streams = {"rhel-9.2.0.z", "rhel-9.3.0.z"}
                # Note: stream_cpes may not have all CPEs if minor version CPEs are removed
                stream_cpes = {
                    "rhel-9.2.0.z": [
                        "cpe:/a:redhat:rhel_eus:9.2::appstream",
                    ],
                    "rhel-9.3.0.z": [
                        "cpe:/a:redhat:enterprise_linux:9.3::appstream",
                    ],
                }

                # Test CPE that matches both RHEL-9.2.0.GA and RHEL-9.3.0.GA nodes
                # Even though stream_cpes doesn't have all CPEs, it should still match
                # because nodes have ps_update_stream attributes
                result = enhanced.enhance_cpe_matching(
                    "cpe:/a:redhat:enterprise_linux:9.2::appstream",
                    active_streams,
                    stream_cpes,
                )

                # Should match both streams because:
                # - RHEL-9.2.0.GA has ps_update_stream: rhel-9.2.0.z and contains the 9.2 CPE
                # - RHEL-9.3.0.GA has ps_update_stream: rhel-9.3.0.z and contains the 9.2 CPE
                # - RHEL-9.2.0.GA is a parent of RHEL-9.3.0.GA, so descendants are checked
                assert "rhel-9.2.0.z" in result
                assert "rhel-9.3.0.z" in result

            finally:
                os.unlink(f.name)


class TestProdDefsIntegration:
    """Test integration with existing ProdDefs class."""

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_proddefs_with_rhel_releases(self, mock_service):
        """Test ProdDefs integration with RHEL release data."""
        mock_service.return_value = create_test_product_definitions()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(create_test_rhel_data())
            f.flush()

            try:
                # Create ProdDefs with RHEL release data
                proddefs = ProdDefs(active_only=True, rhel_releases_path=f.name)

                # Verify enhanced proddefs was initialized
                assert proddefs.enhanced_proddefs is not None
                assert proddefs.enhanced_proddefs.rhel_releases is not None

                # Verify normal functionality still works
                assert len(proddefs.product_trees) > 0

            finally:
                os.unlink(f.name)
