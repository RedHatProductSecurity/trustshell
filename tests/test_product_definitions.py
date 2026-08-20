import json
import os
import tempfile
import unittest
from unittest.mock import patch

from anytree import Node
from test_products import _check_node_names_at_depth

from trustshell import render_tree
from trustshell.product_definitions import ProdDefs
from trustshell.products import build_product_search_result


class TestProdDefs(unittest.TestCase):
    def setUp(self):
        with open("tests/testdata/products/product-definitions.json", "r") as file:
            self.mock_proddefs_data = json.load(file)

    def test_clean_cpe(self):
        cpe = "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*"
        result = ProdDefs._clean_cpe(cpe)
        assert result == "cpe:/a:redhat:rhel_eus:9.2::appstream"

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_prod_defs_stream_nodes_by_cpe(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        prod_defs = ProdDefs()
        assert (
            "cpe:/a:redhat:enterprise_linux:9.6::appstream"
            in prod_defs.stream_nodes_by_cpe
        )
        rhel_mainline_streams = prod_defs.stream_nodes_by_cpe[
            "cpe:/a:redhat:enterprise_linux:9.6::appstream"
        ]
        print([s.name for s in rhel_mainline_streams])
        assert len(rhel_mainline_streams) == 1
        assert rhel_mainline_streams[0].name == "rhel-9.6.z"

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_prod_defs_stream_nodes_by_cpe_rhel_10(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        prod_defs = ProdDefs()
        assert "cpe:/o:redhat:enterprise_linux:10.0" in prod_defs.stream_nodes_by_cpe
        assert (
            "cpe:/o:redhat:enterprise_linux_eus:10.0" in prod_defs.stream_nodes_by_cpe
        )
        rhel_mainline_streams = prod_defs.stream_nodes_by_cpe[
            "cpe:/o:redhat:enterprise_linux:10.0"
        ]
        print([s.name for s in rhel_mainline_streams])
        assert len(rhel_mainline_streams) == 1
        assert rhel_mainline_streams[0].name == "rhel-10.0.z"

    # Expected tree structure is:
    # rhel-9.2.0.z
    # └── rhel-9
    # rhel-9.4.z
    # └── rhel-9
    # rhel-9.6.z
    # └── rhel-9
    # quay-3.12
    # └── quay-3
    # quay-3.13
    # └── quay-3
    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_prod_defs_product_trees(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        prod_defs = ProdDefs()
        assert len(prod_defs.product_trees) == 7
        for tree in prod_defs.product_trees:
            render_tree(tree)
        rhel_9_2_z_stream = prod_defs.product_trees[1]
        assert rhel_9_2_z_stream.name == "rhel-9.2.0.z"
        _check_node_names_at_depth(rhel_9_2_z_stream, 1, ["rhel-9"])
        quay_3_12_stream = prod_defs.product_trees[4]
        assert quay_3_12_stream.name == "quay-3.12"
        _check_node_names_at_depth(quay_3_12_stream, 1, ["quay-3"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_rhel_eus(self, mock_service):
        """Tests that CPE is cleaned and matched to stream - same data as extend_with_product_mappings."""
        mock_service.return_value = self.mock_proddefs_data
        component = "pkg:rpm/redhat/openssl"
        component_node = Node(component)
        cpe = "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*"
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        prod_defs = ProdDefs()
        result = build_product_search_result(
            test_trees, prod_defs, component, cpes=True
        )
        assert len(result.results) == 1
        row = result.results[0]
        assert row.cpe == "cpe:/a:redhat:rhel_eus:9.2::appstream"
        assert row.ps_update_stream == "rhel-9.2.0.z"
        # Stream match populates ps_module from stream's parent module
        assert row.ps_module == "rhel-9"
        assert row.matched_component == component
        assert row.shipped_component == "pkg:rpm/redhat/openssl"
        assert len(result.affects) == 1
        assert next(iter(result.affects)).purl == "pkg:rpm/redhat/openssl"

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_multi_products(self, mock_service):
        """Tests that duplicate CPEs produce multiple result rows - same data as extend_with_product_mappings_multi_products.
        CPE matches rhel-9 module (prefix), yielding multiple streams; 2 components × N streams = 2N rows."""
        mock_service.return_value = self.mock_proddefs_data
        component_1 = "pkg:rpm/redhat/openssl"
        component_2 = "pkg:rpm/redhat/openssl-debug"
        cpe = "cpe:/a:redhat:enterprise_linux:9.6::appstream"
        component_node_1 = Node(component_1)
        Node(cpe, parent=component_node_1)
        component_node_2 = Node(component_2)
        Node(cpe, parent=component_node_2)
        test_trees = [component_node_1, component_node_2]
        prod_defs = ProdDefs()
        result = build_product_search_result(
            test_trees, prod_defs, "pkg:rpm/redhat/openssl", cpes=True
        )
        matched = {row.matched_component for row in result.results}
        assert matched == {component_1, component_2}
        ps_streams = {row.ps_update_stream for row in result.results}
        assert "rhel-9.6.z" in ps_streams
        assert all(row.ps_module == "rhel-9" for row in result.results)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_quay_module_match(self, mock_service):
        """Tests that CPE matching module returns multiple streams - same data as extend_with_product_mapping_module_match."""
        mock_service.return_value = self.mock_proddefs_data
        cpe = "cpe:/a:redhat:quay:3"
        component = "pkg:oci/quay"
        component_node = Node(component)
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        prod_defs = ProdDefs()
        result = build_product_search_result(
            test_trees, prod_defs, component, cpes=True
        )
        assert len(result.results) == 2
        ps_streams = {row.ps_update_stream for row in result.results}
        assert ps_streams == {"quay-3.12", "quay-3.13"}
        assert all(row.ps_module == "quay-3" for row in result.results)
        assert all(row.matched_component == component for row in result.results)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_multi_module_match(self, mock_service):
        """Test multiple components with different CPEs - same data as extend_with_product_mapping_multi_module_match."""
        mock_service.return_value = self.mock_proddefs_data
        component_1 = "pkg:oci/quay@sha256:123"
        component_1_node = Node(component_1)
        component_2 = "pkg:oci/quay@sha256:345"
        component_2_node = Node(component_2)
        module_cpe = "cpe:/a:redhat:quay:3"
        Node(module_cpe, parent=component_1_node)
        stream_cpe = "cpe:/a:redhat:quay:3.13"
        Node(stream_cpe, parent=component_2_node)
        test_trees = [component_1_node, component_2_node]
        prod_defs = ProdDefs()
        result = build_product_search_result(
            test_trees, prod_defs, "pkg:oci/quay", cpes=True
        )
        rows_by_cpe = {}
        for row in result.results:
            rows_by_cpe.setdefault(row.cpe, []).append(row)
        assert "cpe:/a:redhat:quay:3" in rows_by_cpe
        assert "cpe:/a:redhat:quay:3.13" in rows_by_cpe
        module_rows = rows_by_cpe["cpe:/a:redhat:quay:3"]
        assert len(module_rows) == 2
        assert {r.ps_update_stream for r in module_rows} == {"quay-3.12", "quay-3.13"}
        stream_rows = rows_by_cpe["cpe:/a:redhat:quay:3.13"]
        assert len(stream_rows) >= 1
        assert {r.ps_update_stream for r in stream_rows} >= {"quay-3.13"}

    def _create_test_rhel_releases_yaml(self):
        """Create a temporary RHEL releases YAML file for testing."""
        test_data = """
nodes:
    RHEL-9.0.0.GA:
      type: main
      ps_update_stream: rhel-9.0.0.z
      cpes:
        - cpe:/a:redhat:enterprise_linux:9::appstream
        - cpe:/o:redhat:enterprise_linux:9::baseos
        - cpe:/a:redhat:enterprise_linux:9::crb
        - cpe:/a:redhat:enterprise_linux:9.0::appstream
        - cpe:/o:redhat:enterprise_linux:9.0::baseos
        - cpe:/a:redhat:enterprise_linux:9.0::crb

    RHEL-9.0.0.Z.MAIN+EUS:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:9::appstream
        - cpe:/o:redhat:enterprise_linux:9::baseos
        - cpe:/a:redhat:enterprise_linux:9::crb

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
        - cpe:/a:redhat:enterprise_linux:9::appstream
        - cpe:/o:redhat:enterprise_linux:9::baseos
        - cpe:/a:redhat:enterprise_linux:9.2::appstream

    RHEL-9.2.0.Z.EUS:
      type: eus
      cpes:
        - cpe:/a:redhat:rhel_eus:9.2::appstream
        - cpe:/o:redhat:rhel_eus:9.2::baseos

    RHEL-9.2.0.Z.MAIN+EUS:
      type: main
      cpes:
        - cpe:/a:redhat:enterprise_linux:9::appstream
        - cpe:/a:redhat:enterprise_linux:9.2::appstream

    RHEL-9.3.0.GA:
        type: main
        ps_update_stream: rhel-9.3.0.z
        cpes:
          - cpe:/a:redhat:enterprise_linux:9::appstream
          - cpe:/a:redhat:enterprise_linux:9.2::appstream
          - cpe:/a:redhat:enterprise_linux:9.3::appstream

edges:
    RHEL-9.0.0.GA:
        - RHEL-9.0.0.Z.MAIN+EUS
    RHEL-9.0.0.Z.MAIN+EUS:
        - RHEL-9.0.0.Z.EUS
        - RHEL-9.2.0.GA
    RHEL-9.2.0.GA:
        - RHEL-9.2.0.Z.EUS
        - RHEL-9.2.0.Z.MAIN+EUS
    RHEL-9.2.0.Z.MAIN+EUS:
        - RHEL-9.2.0.Z.EUS
        - RHEL-9.3.0.GA
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as temp_file:
            temp_file.write(test_data)
            temp_file.flush()
            return temp_file.name

    def _create_enhanced_product_definitions(self):
        """Create product definitions with enhanced RHEL streams for testing."""
        return {
            "ps_modules": {
                "rhel-9": {
                    "public_description": "Red Hat Enterprise Linux 9",
                    "ps_update_streams": ["rhel-9.0.0.z", "rhel-9.2.0.z"],
                    "active_ps_update_streams": ["rhel-9.0.0.z", "rhel-9.2.0.z"],
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
                "rhel-9.3.0.z": {
                    "pp_label": "rhel-9.3.0.z",
                    "version": "rhel-9.3.0.z",
                    "cpe": [
                        "cpe:/a:redhat:enterprise_linux:9::appstream",
                        "cpe:/a:redhat:enterprise_linux:9.3::appstream",
                    ],
                },
            },
        }

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_direct_cpe_match(self, mock_service):
        """Test that direct CPE matches work with RHEL release data."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Test direct CPE match - get_product_mappings_for_cpe
            # Stream matches populate ps_module from stream's parent module
            cpe = "cpe:/a:redhat:rhel_eus:9.0::appstream"
            mappings = prod_defs.get_product_mappings_for_cpe(cpe)
            assert len(mappings) == 1
            assert mappings[0] == ("rhel-9.0.0.z", "rhel-9")

            # Also verify build_product_search_result produces correct result
            component = "pkg:rpm/redhat/openssl"
            component_node = Node(component)
            Node(cpe, parent=component_node)
            test_trees = [component_node]
            result = build_product_search_result(
                test_trees, prod_defs, component, cpes=True
            )
            assert len(result.results) == 1
            assert result.results[0].ps_update_stream == "rhel-9.0.0.z"

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_parent_cpe_match(self, mock_service):
        """Test that single-digit CPEs are filtered out - get_product_mappings_for_cpe returns []."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Single-digit CPE cpe:/a:redhat:enterprise_linux:9::appstream is filtered
            cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
            mappings = prod_defs.get_product_mappings_for_cpe(cpe)
            assert mappings == []

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_versioned_cpe_still_works(self, mock_service):
        """Test that versioned CPEs (like 9.2::appstream) still work with RHEL release data."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Versioned CPE cpe:/a:redhat:enterprise_linux:9.2::appstream should match
            cpe = "cpe:/a:redhat:enterprise_linux:9.2::appstream"
            mappings = prod_defs.get_product_mappings_for_cpe(cpe)
            assert len(mappings) >= 1
            stream_names = [m[0] for m in mappings]
            assert "rhel-9.2.0.z" in stream_names

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_no_match_behavior(self, mock_service):
        """Test that get_product_mappings_for_cpe returns [] for unknown CPE."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            cpe = "cpe:/a:unknown:product:1.0"
            mappings = prod_defs.get_product_mappings_for_cpe(cpe)
            assert mappings == []

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_with_missing_file(self, mock_service):
        """Test that ProdDefs handles missing RHEL release file gracefully."""
        mock_service.return_value = self.mock_proddefs_data

        # Try to create ProdDefs with non-existent RHEL release file
        non_existent_path = "/path/that/does/not/exist.yml"
        prod_defs = ProdDefs(active_only=True, rhel_releases_path=non_existent_path)

        # Should create enhanced_proddefs but with no RHEL release data
        assert prod_defs.enhanced_proddefs is not None
        assert prod_defs.enhanced_proddefs.rhel_releases is None

        # Should still work normally
        assert len(prod_defs.product_trees) > 0

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_get_all_cpes_for_rhel_stream_enhanced(self, mock_service):
        """Test getting all CPEs for a RHEL stream using the release graph."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            # Test with RHEL release data
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Get all CPEs for rhel-9.0.0.z stream
            all_cpes = prod_defs.get_all_cpes_for_rhel_stream("rhel-9.0.0.z")

            # Should include direct stream CPEs
            assert "cpe:/a:redhat:rhel_eus:9.0::appstream" in all_cpes
            assert "cpe:/o:redhat:rhel_eus:9.0::baseos" in all_cpes

            # Should also include CPEs from related RHEL release nodes
            # The implementation should find RHEL-9.0.0.* nodes and their ancestors
            assert len(all_cpes) > 2  # Should be more than just the direct CPEs

            print(f"Enhanced CPEs for rhel-9.0.0.z: {sorted(all_cpes)}")

            # Get all CPEs for rhel-9.3.0.z stream
            all_93_cpes = prod_defs.get_all_cpes_for_rhel_stream("rhel-9.3.0.z")
            print(f"Enhanced CPEs for rhel-9.3.0.z: {sorted(all_93_cpes)}")

            assert "cpe:/a:redhat:enterprise_linux:9.2::appstream" in all_93_cpes
            assert "cpe:/a:redhat:enterprise_linux:9.3::appstream" in all_93_cpes

        finally:
            os.unlink(rhel_yaml_path)
