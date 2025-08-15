import json
import unittest
from anytree import Node
from unittest.mock import patch
from test_products import _check_node_names_at_depth
from trustshell.product_definitions import ProdDefs, ProductStream
from trustshell import render_tree


class TestProdDefs(unittest.TestCase):
    def setUp(self):
        with open("tests/testdata/product-definitions.json", "r") as file:
            self.mock_proddefs_data = json.load(file)

    def test_clean_cpe(self):
        cpe = "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*"
        result = ProdDefs._clean_cpe(cpe)
        assert result == "cpe:/a:redhat:rhel_eus:9.2::appstream"

    def test_filter_rhel_mainline_cpes(self):
        mainline_cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
        eus_cpe = "cpe:/a:redhat:rhel_eus:9.4::appstream"
        test_cpes = [mainline_cpe, eus_cpe]
        ps = ProductStream("test")
        result = ps._filter_rhel_mainline_cpes(test_cpes)
        assert mainline_cpe not in result
        assert eus_cpe in result

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_prod_defs_stream_nodes_by_cpe(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        prod_defs = ProdDefs()
        assert (
            "cpe:/a:redhat:enterprise_linux:9::appstream"
            in prod_defs.stream_nodes_by_cpe
        )
        rhel_mainline_streams = prod_defs.stream_nodes_by_cpe[
            "cpe:/a:redhat:enterprise_linux:9::appstream"
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
    def test_extend_with_product_mappings_rhel_mainline_filter(self, mock_service):
        """Tests that the mainline cpe is only matched against streams without (e)us CPEs"""
        mock_service.return_value = self.mock_proddefs_data
        component = "pkg:rpm/redhat/openssl"
        component_node = Node(component)
        cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees, keep_cpes=True)
        assert len(test_trees) == 1
        root = test_trees[0].root
        render_tree(root)
        assert root.name == component
        _check_node_names_at_depth(root, 1, [cpe])
        _check_node_names_at_depth(root, 2, ["rhel-9.6.z"])
        _check_node_names_at_depth(root, 3, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings_rhel_mainline_filter_no_cpes(
        self, mock_service
    ):
        """Tests that the mainline cpe is only matched against streams without (e)us CPEs"""
        mock_service.return_value = self.mock_proddefs_data
        component = "pkg:rpm/redhat/openssl"
        component_node = Node(component)
        cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
        Node(cpe, parent=component_node)
        test_trees = [component_node]
        ProdDefs().extend_with_product_mappings(test_trees)
        assert len(test_trees) == 1
        root = test_trees[0].root
        render_tree(root)
        assert root.name == component
        _check_node_names_at_depth(root, 1, ["rhel-9.6.z"])
        _check_node_names_at_depth(root, 2, ["rhel-9"])

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extend_with_product_mappings_multi_products(self, mock_service):
        """Tests that duplicate CPEs return duplicates branches"""
        mock_service.return_value = self.mock_proddefs_data
        component_1 = "pkg:rpm/redhat/openssl"
        component_2 = "pkg:rpm/redhat/openssl-debug"
        cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
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
        cpe = "cpe:/a:redhat:enterprise_linux:9::appstream"
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
