import json
import tempfile
import os
import unittest
from anytree import Node
from unittest.mock import patch
from test_products import _check_node_names_at_depth
from trustshell.product_definitions import ProdDefs
from trustshell.products import render_tree


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
        assert len(prod_defs.product_trees) == 6
        for tree in prod_defs.product_trees:
            render_tree(tree)
        rhel_9_2_z_stream = prod_defs.product_trees[1]
        assert rhel_9_2_z_stream.name == "rhel-9.2.0.z"
        _check_node_names_at_depth(rhel_9_2_z_stream, 1, ["rhel-9"])
        quay_3_12_stream = prod_defs.product_trees[4]
        assert quay_3_12_stream.name == "quay-3.12"
        _check_node_names_at_depth(quay_3_12_stream, 1, ["quay-3"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings(self, mock_service):
        """Tests that the CPE is cleaned and matched directly to stream"""
        mock_service.return_value = self.mock_proddefs_data
        component = "pkg:rpm/redhat/openssl"
        component_node = Node(component)
        cpe = "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*"
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees, keep_cpes=True)
        assert len(test_trees) == 1
        root = test_trees[0].root
        render_tree(root)
        assert root.name == component
        _check_node_names_at_depth(root, 1, [cpe])
        _check_node_names_at_depth(root, 2, ["rhel-9.2.0.z"])
        _check_node_names_at_depth(root, 3, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings_no_cpes(self, mock_service):
        """Tests that the CPE is cleaned and matched directly to stream"""
        mock_service.return_value = self.mock_proddefs_data
        component = "pkg:rpm/redhat/openssl"
        component_node = Node(component)
        cpe = "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*"
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees)
        assert len(test_trees) == 1
        root = test_trees[0].root
        render_tree(root)
        assert root.name == component
        _check_node_names_at_depth(root, 1, ["rhel-9.2.0.z"])
        _check_node_names_at_depth(root, 2, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings_multi_products(self, mock_service):
        """Tests that duplicate CPEs return duplicates branches"""
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
        prod_defs.extend_with_product_mappings(test_trees, keep_cpes=True)
        assert len(test_trees) == 2
        for r in test_trees:
            root = r.root
            render_tree(root)
            assert root.name in (component_1, component_2)
            _check_node_names_at_depth(root, 1, [cpe])
            _check_node_names_at_depth(root, 2, ["rhel-9.6.z"])
            _check_node_names_at_depth(root, 3, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings_multi_products_no_cpes(self, mock_service):
        """Tests that duplicate CPEs return duplicates branches"""
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
        prod_defs.extend_with_product_mappings(test_trees)
        assert len(test_trees) == 2
        for r in test_trees:
            root = r.root
            render_tree(root)
            assert root.name in (component_1, component_2)
            _check_node_names_at_depth(root, 1, ["rhel-9.6.z"])
            _check_node_names_at_depth(root, 2, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mapping_module_match(self, mock_service):
        """Tests that if a CPE matches multiple streams there is a result returned for each"""
        mock_service.return_value = self.mock_proddefs_data
        cpe = "cpe:/a:redhat:quay:3"
        component = "oci:quay"
        component_node = Node(component)
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees, keep_cpes=True)
        for r in test_trees:
            render_tree(r)
        assert len(test_trees) == 1
        first_root = test_trees[0].root
        assert first_root.name == component
        _check_node_names_at_depth(first_root, 1, [cpe])
        _check_node_names_at_depth(first_root, 2, ["quay-3.13", "quay-3.12"])
        _check_node_names_at_depth(first_root, 3, ["quay-3", "quay-3"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mapping_module_match_no_cpes(self, mock_service):
        """Tests that if a CPE matches multiple streams with keep_cpes=False, CPE nodes are replaced by streams"""
        mock_service.return_value = self.mock_proddefs_data
        cpe = "cpe:/a:redhat:quay:3"
        component = "oci:quay"
        component_node = Node(component)
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees)
        for r in test_trees:
            render_tree(r)
        assert len(test_trees) == 1

        # Both results should have the same root (component)
        first_root = test_trees[0].root
        assert first_root.name == component

        _check_node_names_at_depth(first_root, 1, ["quay-3.12", "quay-3.13"])
        _check_node_names_at_depth(first_root, 2, ["quay-3", "quay-3"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mapping_multi_module_match(self, mock_service):
        """Test that when multiple components match a stream and module in the same product tree,
        that we get a result for each"""
        mock_service.return_value = self.mock_proddefs_data
        component_1 = "oci:quay@123"
        component_1_node = Node(component_1)
        component_2 = "oci:quay@345"
        component_2_node = Node(component_2)
        module_cpe = "cpe:/a:redhat:quay:3"
        Node(module_cpe, parent=component_1_node)
        stream_cpe = "cpe:/a:redhat:quay:3.13"
        Node(stream_cpe, parent=component_2_node)
        test_trees = [component_1_node, component_2_node]
        ProdDefs().extend_with_product_mappings(test_trees, keep_cpes=True)
        for r in test_trees:
            render_tree(r.root)
        # oci:quay@123
        # └── cpe:/a:redhat:quay:3
        #     └── quay-3.13
        #         └── quay-3
        #     └── quay-3.12
        #         └── quay-3
        # oci:quay@345
        # └── cpe:/a:redhat:quay:3.13
        #     └── quay-3.13
        #         └── quay-3
        assert len(test_trees) == 2
        first_root = test_trees[0].root
        second_root = test_trees[1].root
        assert first_root.name == component_1
        assert second_root.name == component_2
        _check_node_names_at_depth(first_root, 1, [module_cpe])
        _check_node_names_at_depth(first_root, 2, ["quay-3.13", "quay-3.12"])
        _check_node_names_at_depth(first_root, 3, ["quay-3", "quay-3"])
        _check_node_names_at_depth(second_root, 1, [stream_cpe])
        _check_node_names_at_depth(second_root, 2, ["quay-3.13"])
        _check_node_names_at_depth(second_root, 3, ["quay-3"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mapping_multi_module_match_no_cpes(self, mock_service):
        """Test that when multiple components match a stream and module in the same product tree,
        that we get a result for each"""
        mock_service.return_value = self.mock_proddefs_data
        component_1 = "oci:quay@123"
        component_1_node = Node(component_1)
        component_2 = "oci:quay@345"
        component_2_node = Node(component_2)
        module_cpe = "cpe:/a:redhat:quay:3"
        Node(module_cpe, parent=component_1_node)
        stream_cpe = "cpe:/a:redhat:quay:3.13"
        Node(stream_cpe, parent=component_2_node)
        test_trees = [component_1_node, component_2_node]
        ProdDefs().extend_with_product_mappings(test_trees)
        for r in test_trees:
            render_tree(r.root)
        # oci:quay@123
        #     └── quay-3.13
        #         └── quay-3
        #     └── quay-3.12
        #         └── quay-3
        # oci:quay@345
        #     └── quay-3.13
        #         └── quay-3
        assert len(test_trees) == 2
        first_root = test_trees[0].root
        second_root = test_trees[1].root
        assert first_root.name == component_1
        assert second_root.name == component_2
        _check_node_names_at_depth(first_root, 1, ["quay-3.13", "quay-3.12"])
        _check_node_names_at_depth(first_root, 2, ["quay-3", "quay-3"])
        _check_node_names_at_depth(second_root, 1, ["quay-3.13"])
        _check_node_names_at_depth(second_root, 2, ["quay-3"])

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
        temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
        temp_file.write(test_data)
        temp_file.flush()
        temp_file.close()
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
            # Create ProdDefs with RHEL release data
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Test direct CPE match
            component = "pkg:rpm/redhat/openssl"
            component_node = Node(component)
            # This CPE exists directly in the rhel-9.0.0.z stream
            cpe = "cpe:/a:redhat:rhel_eus:9.0::appstream"
            Node(cpe, parent=component_node)
            test_trees = [component_node]

            prod_defs.extend_with_product_mappings(test_trees, keep_cpes=True)

            # Verify the mapping worked
            root = test_trees[0].root
            render_tree(root)
            assert root.name == component
            _check_node_names_at_depth(root, 1, [cpe])
            _check_node_names_at_depth(root, 2, ["rhel-9.0.0.z"])
            _check_node_names_at_depth(root, 3, ["rhel-9"])

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_parent_cpe_match(self, mock_service):
        """Test that parent CPE matches work and map to leaf streams."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            # Create ProdDefs with RHEL release data
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Test parent CPE match
            component = "pkg:rpm/redhat/httpd"
            component_node = Node(component)
            # This CPE appears in parent nodes (GA, MAIN+EUS) but should now be filtered out
            # so no matches should occur with single digit CPEs
            cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
            Node(cpe, parent=component_node)
            test_trees = [component_node]

            prod_defs.extend_with_product_mappings(test_trees, keep_cpes=True)

            # Verify that single digit CPE is now filtered out and doesn't match
            root = test_trees[0].root
            render_tree(root)
            assert root.name == component
            _check_node_names_at_depth(root, 1, [])

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_versioned_cpe_still_works(self, mock_service):
        """Test that versioned CPEs (like 9.0::appstream) still work with RHEL release data."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            # Create ProdDefs with RHEL release data
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Test versioned CPE that should work (not filtered out)
            component = "pkg:rpm/redhat/httpd"
            component_node = Node(component)
            # This CPE has version (9.2) so should NOT be filtered out
            cpe = "cpe:/a:redhat:enterprise_linux:9.2::appstream"
            Node(cpe, parent=component_node)
            test_trees = [component_node]

            prod_defs.extend_with_product_mappings(test_trees, keep_cpes=True)

            # Verify the versioned CPE can still map to streams through RHEL release data
            root = test_trees[0].root
            render_tree(root)
            assert root.name == component
            _check_node_names_at_depth(root, 1, [cpe])

            # Should map to active streams since versioned CPE exists in RHEL release data
            stream_names = [node.name for node in root.children[0].children]
            assert "rhel-9.2.0.z" in stream_names

        finally:
            os.unlink(rhel_yaml_path)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_rhel_releases_no_match_behavior(self, mock_service):
        """Test behavior when CPE doesn't match any RHEL release data."""
        mock_service.return_value = self._create_enhanced_product_definitions()
        rhel_yaml_path = self._create_test_rhel_releases_yaml()

        try:
            # Create ProdDefs with RHEL release data
            prod_defs = ProdDefs(active_only=True, rhel_releases_path=rhel_yaml_path)

            # Test with a CPE that doesn't match RHEL release data
            component = "pkg:rpm/unknown/package"
            component_node = Node(component)
            # This CPE doesn't exist in our test RHEL release data
            cpe = "cpe:/a:unknown:product:1.0"
            Node(cpe, parent=component_node)
            test_trees = [component_node]

            prod_defs.extend_with_product_mappings(test_trees, keep_cpes=True)

            # Should fall back to module pattern matching (which should also fail)
            # and display a warning about no matching products
            root = test_trees[0].root
            assert root.name == component
            # Should still have the original CPE node
            assert len(root.children) == 1
            assert root.children[0].name == cpe
            # But no product mappings should be added
            assert len(root.children[0].children) == 0

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
