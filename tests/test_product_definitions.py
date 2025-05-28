import json
import unittest
from anytree import Node
from unittest.mock import patch
from test_products import _check_node_names_at_depth
from trustshell.product_definitions import ProdDefs, ProductStream
from trustshell.products import _render_tree

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
            assert "cpe:/a:redhat:enterprise_linux:9::appstream" in prod_defs.stream_nodes_by_cpe
            rhel_mainline_streams = prod_defs.stream_nodes_by_cpe["cpe:/a:redhat:enterprise_linux:9::appstream"]
            print([s.name for s in rhel_mainline_streams])
            assert len(rhel_mainline_streams) == 1
            assert rhel_mainline_streams[0].name == "rhel-9.6.z"


        # Expected tree structure is:
        # rhel-9
        # ├── rhel-9.2.0.z
        # └── rhel-9.4.z
        # quay-3
        # ├── quay-3.12
        # └── quay-3.13
        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_prod_defs_module_trees(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            prod_defs = ProdDefs()
            assert len(prod_defs.module_trees) == 2
            first_module = prod_defs.module_trees[0]
            assert first_module.name == "rhel-9"
            _check_node_names_at_depth(first_module, 1, ["rhel-9.2.0.z", "rhel-9.4.z", "rhel-9.6.z"])
            second_module = prod_defs.module_trees[1]
            assert second_module.name == "quay-3"
            _check_node_names_at_depth(second_module, 1, ["quay-3.12", "quay-3.13"])


        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_extend_with_product_mappings(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            test_trees = [Node("cpe:/a:redhat:rhel_eus:9.2:*:appstream:*")]
            prod_defs = ProdDefs()
            results = prod_defs.extend_with_product_mappings(test_trees)
            assert len(results) == 1
            _render_tree(results[0])
            assert results[0].name == "rhel-9"

        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_extend_with_product_mappings_rhel_mainline_filter(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            product_node = Node("cpe:/a:redhat:enterprise_linux:9::appstream")
            test_trees = [product_node]
            prod_defs = ProdDefs()
            result = prod_defs.extend_with_product_mappings(test_trees)
            assert len(result) == 1
            _render_tree(result[0])
            _check_node_names_at_depth(result[0], 1, ["rhel-9.6.z"])
            _check_node_names_at_depth(result[0], 2, ["cpe:/a:redhat:enterprise_linux:9::appstream"])

        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_extend_with_product_mappings_multi_products(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            product_node = Node("cpe:/a:redhat:enterprise_linux:9::appstream")
            # Simulates 2 different matches for the same product
            test_trees = [product_node, product_node]
            prod_defs = ProdDefs()
            result = prod_defs.extend_with_product_mappings(test_trees)
            assert len(result) == 1
            _render_tree(result[0])

        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_extend_with_product_mapping_module_match(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            product_node = Node("cpe:/a:redhat:quay:3")
            test_trees = [product_node]
            prod_defs = ProdDefs()
            result = prod_defs.extend_with_product_mappings(test_trees)
            _render_tree(result[0])
            assert len(result) == 1
            assert result[0].name == "quay-3"
            _check_node_names_at_depth(result[0], 1, ["cpe:/a:redhat:quay:3"])


        @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
        def test_extend_with_product_mapping_multi_module_match(self, mock_service):
            mock_service.return_value = self.mock_proddefs_data
            module_match = Node("cpe:/a:redhat:quay:3")
            stream_match = Node("cpe:/a:redhat:quay:3.13")
            test_trees = [module_match, stream_match]
            prod_defs = ProdDefs()
            result = prod_defs.extend_with_product_mappings(test_trees)
            _render_tree(result[0])
            assert len(result) == 2
            assert result[0].name == "quay-3"
            _check_node_names_at_depth(result[0], 1, ["cpe:/a:redhat:quay:3", "quay-3.13"])
            _check_node_names_at_depth(result[0], 2, ["cpe:/a:redhat:quay:3.13"])