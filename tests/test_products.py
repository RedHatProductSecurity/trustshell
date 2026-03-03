import json
import unittest
from parameterized import parameterized
from unittest.mock import patch

from anytree import Node

from packageurl import PackageURL

from trustshell import build_node_purl, purl_to_bare, render_tree
from trustshell.products import (
    ComponentNode,
    _get_branch_signature,
    _remove_duplicate_parent_nodes,
    _remove_non_cpe_branches,
    get_generic_purl_from_search_term,
    get_redhat_purl_from_generic,
    _trees_with_cpes,
    _has_cpe_node,
    container_in_tree,
    build_product_search_result,
)
from trustshell.product_definitions import ProdDefs


class TestProducts(unittest.TestCase):
    def setUp(self):
        with open("tests/testdata/products/product-definitions.json", "r") as file:
            self.mock_proddefs_data = json.load(file)

    @parameterized.expand(
        [
            (False, "pkg:rpm/redhat/webkit2gtk3"),
            (True, "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9"),
        ],
    )
    def test_build_node_purl_rpm(self, show_versions, expected_purl):
        purls = [
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-aarch64-appstrea"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-ppc64le-appstrea"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-aarch64-appstrea"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-s390x-appstream-"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-s390x-appstream-"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-ppc64le-appstrea"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-x86_64-appstream"
            "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9?arch=src&repository_id=rhel-9-for-x86_64-appstream"
        ]
        result = build_node_purl(purls, show_versions=show_versions).to_string()
        assert result == expected_purl

    def test_build_node_purl_oci(self):
        purls = [
            "pkg:oci/quay@sha256:9",
            "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8-1",
            "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8",
            "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12",
        ]
        result = build_node_purl(purls).to_string()
        print(result)
        assert result == "pkg:oci/quay?tag=v3.12.8-1"

    @parameterized.expand(
        [
            (False, "pkg:maven/io.agroal/agroal-api?hash=sha256:1234567890&type=jar"),
            (
                True,
                "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?hash=sha256:1234567890&type=jar",
            ),
        ],
    )
    def test_build_node_purl_maven_type(self, show_versions, expected_purl):
        purls = [
            "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar&hash=sha256:1234567890"
        ]
        result = build_node_purl(purls, show_versions=show_versions).to_string()
        print(result)
        assert result == expected_purl

    def test_trees_with_cpes_srpm(self):
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        assert result[0].name == "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"
        expected_cpes = [
            "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
            "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
        ]
        _check_node_names_at_depth(result[0], 1, expected_cpes)

    def test_trees_with_cpes_sbom_ids(self):
        """Verify sbom_ids are collected on nodes from API data."""
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        tree = result[0]
        assert isinstance(tree, ComponentNode)
        # openssl.json has sbom_id at component and product levels
        for node in list(tree.descendants) + [tree]:
            assert hasattr(node, "sbom_ids")
        # Collect all sbom_ids from the tree (openssl has component + product levels)
        all_sbom_ids = {
            sid for node in list(tree.descendants) + [tree] for sid in node.sbom_ids
        }
        assert len(all_sbom_ids) >= 1
        # RHEL 9.2 EUS product-level sbom_id from ancestor
        assert "0195d531-b2ea-7031-af29-72de8330e51f" in all_sbom_ids

    def test_trees_with_cpes_binary_rpm(self):
        with open("tests/testdata/openssl-libs.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        assert result[0].name == "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2"
        _check_node_names_at_depth(
            result[0], 1, ["pkg:rpm/redhat/openssl@3.0.7-18.el9_2"]
        )
        expected_cpes = [
            "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
            "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
        ]
        _check_node_names_at_depth(result[0], 2, expected_cpes)

    def test_trees_with_cpes_container_cdx(self):
        with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        assert (
            result[0].name
            == "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8-1"
        )
        expected_cpe = ["cpe:/a:redhat:quay:3:*:el8:*"]
        _check_node_names_at_depth(result[0], 1, expected_cpe)

    def test_trees_with_cpes_dependency(self):
        with open("tests/testdata/chardet.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        _check_node_names_at_depth(
            result[0],
            1,
            [
                "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8-1"
            ],
        )
        expected_cpe = ["cpe:/a:redhat:quay:3:*:el8:*"]
        _check_node_names_at_depth(result[0], 2, expected_cpe)

    def test_trees_with_cpes_spdx_dependency(self):
        with open("tests/testdata/NGX.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        _check_node_names_at_depth(
            result[0],
            1,
            [
                "pkg:oci/bootc-nvidia-rhel9?repository_url=registry.redhat.io/rhelai1&tag=1.4.3-1743086940"
            ],
        )
        _check_node_names_at_depth(
            result[0], 2, ["cpe:/a:redhat:enterprise_linux_ai:1.4:*:el9:*"]
        )

    def test_trees_with_cpes_multi_versions(self):
        with open("tests/testdata/quay-builder-qemu-multi.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 2

        print("first_result")
        render_tree(result[0])
        assert (
            result[0].name
            == "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.14.0-4"
        )
        expected_cpes = ["cpe:/a:redhat:quay:3:*:el8:*"]
        _check_node_names_at_depth(result[0], 1, expected_cpes)

        print("second_result")
        render_tree(result[1])
        assert (
            result[1].name
            == "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8-1"
        )
        _check_node_names_at_depth(result[1], 1, expected_cpes)

    def test_trees_with_cpes_quarkus_agroal(self):
        with open("tests/testdata/quarkus-3.20-agroal-api.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)

        print("first_result")
        render_tree(result[0])
        assert len(result) == 1
        assert (
            result[0].name
            == "pkg:maven/io.agroal/agroal-api@2.5.0.redhat-00002?type=jar"
        )
        _check_node_names_at_depth(
            result[0],
            1,
            ["pkg:maven/io.quarkus/quarkus-agroal@3.20.0.redhat-00002?type=jar"],
        )
        _check_node_names_at_depth(
            result[0],
            2,
            [
                "pkg:maven/org.apache.camel.quarkus/camel-quarkus-sql@3.15.0.redhat-00007?type=jar"
            ],
        )
        _check_node_names_at_depth(
            result[0],
            3,
            [
                "pkg:maven/com.redhat.quarkus.platform/quarkus-camel-bom@3.20.0.redhat-00001?type=pom"
            ],
        )
        _check_node_names_at_depth(
            result[0], 4, ["cpe:/a:redhat:camel_quarkus:3:*:*:*"]
        )

    def test_trees_with_cpes_quarkus_xmlsec(self):
        with open("tests/testdata/quarkus-3.15-xmlsec.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)

        print("first_result")
        render_tree(result[0])
        assert len(result) == 1
        assert result[0].name == "pkg:maven/org.apache.santuario/xmlsec@3.0.4?type=jar"
        _check_node_names_at_depth(
            result[0],
            1,
            [
                "pkg:maven/io.quarkiverse.cxf/quarkus-cxf-santuario-xmlsec@3.15.3?type=jar"
            ],
        )
        _check_node_names_at_depth(
            result[0],
            2,
            [
                "pkg:maven/io.quarkiverse.cxf/quarkus-cxf-santuario-xmlsec-deployment@3.15.3?type=jar"
            ],
        )
        _check_node_names_at_depth(
            result[0],
            3,
            [
                "pkg:maven/io.quarkiverse.cxf/quarkus-cxf-rt-ws-security-deployment@3.15.3.redhat-00008?type=jar"
            ],
        )
        _check_node_names_at_depth(
            result[0],
            4,
            [
                "pkg:maven/com.redhat.quarkus.platform/quarkus-cxf-bom@3.15.4.redhat-00001?type=pom"
            ],
        )
        _check_node_names_at_depth(
            result[0], 5, ["cpe:/a:redhat:camel_quarkus:3:*:*:*"]
        )

    def test_trees_with_cpes_firefox(self):
        with open("tests/testdata/firefox.json") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=True)
        assert len(result) == 1
        render_tree(result[0])
        assert result[0].name == "pkg:rpm/redhat/firefox@128.12.0-1.el8_10"
        _check_node_names_at_depth(
            result[0],
            1,
            [
                "cpe:/a:redhat:enterprise_linux:8.10:*:appstream:*",
                "cpe:/a:redhat:enterprise_linux:8:*:appstream:*",
            ],
        )

    def test_has_cpe_node_with_cpe_name(self):
        root = Node("cpe:/a", children=[Node("cpe:/b"), Node("d")])
        assert _has_cpe_node(root)

    def test_has_cpe_node_without_cpe_name(self):
        root = Node("d", children=[Node("cpe:/a"), Node("b")])
        assert _has_cpe_node(root)

    def test_has_cpe_node_with_cpe_descendant(self):
        root = Node("d", children=[Node("b"), Node("cpe:/a")])
        assert _has_cpe_node(root)

    def test_has_cpe_node_with_multiple_cpe_descendants(self):
        root = Node("d", children=[Node("b"), Node("cpe:/a"), Node("cpe:/b")])
        assert _has_cpe_node(root)

    def test_has_cpe_node_with_no_descendants(self):
        root = Node("d")
        assert not _has_cpe_node(root)

    def test_has_cpe_node_with_empty_children(self):
        root = Node("d")
        assert not _has_cpe_node(root)

    def test_remove_non_cpe_branches(self):
        # Create a tree with duplicate parent nodes
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        # └── base
        #     └── srpm
        root = Node("root")
        base1 = Node("base", parent=root)
        base2 = Node("base", parent=root)
        srpm = Node("srpm", parent=base1)
        Node("srpm", parent=base2)
        Node("cpe:/", parent=srpm)
        _remove_non_cpe_branches(root)
        render_tree(root)

        # Assert that the tree structure is as expected
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        _check_node_names_at_depth(root, 1, ["base"])
        _check_node_names_at_depth(root, 2, ["srpm"])
        _check_node_names_at_depth(root, 3, ["cpe:/"])

    def test_remove_multi_non_cpe_branches(self):
        # Create a tree with duplicate parent nodes
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        # └── base
        #     └── srpm
        # └── base
        #     └── srpm
        root = Node("root")
        base1 = Node("base", parent=root)
        base2 = Node("base", parent=root)
        base3 = Node("base", parent=root)
        srpm = Node("srpm", parent=base1)
        Node("srpm", parent=base2)
        Node("srpm", parent=base3)
        Node("cpe:/", parent=srpm)
        _remove_non_cpe_branches(root)
        render_tree(root)

        # Assert that the tree structure is as expected
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        _check_node_names_at_depth(root, 1, ["base"])
        _check_node_names_at_depth(root, 2, ["srpm"])
        _check_node_names_at_depth(root, 3, ["cpe:/"])

    def test_remove_non_cpe_branches_multi_cpe(self):
        # Create a tree with duplicate parent nodes
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        # └── base
        #     └── srpm
        # └── base
        #     └── srpm
        # │       └── cpe:/
        root = Node("root")
        base1 = Node("base", parent=root)
        base2 = Node("base", parent=root)
        base3 = Node("base", parent=root)
        srpm = Node("srpm", parent=base1)
        Node("srpm", parent=base2)
        srpm3 = Node("srpm", parent=base3)
        Node("cpe:/", parent=srpm)
        Node("cpe:/", parent=srpm3)
        _remove_non_cpe_branches(root)
        render_tree(root)

        # Assert that the tree structure is as expected
        # root
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        # ├── base
        # │   └── srpm
        # │       └── cpe:/
        _check_node_names_at_depth(root, 1, ["base", "base"])
        _check_node_names_at_depth(root, 2, ["srpm", "srpm"])
        _check_node_names_at_depth(root, 3, ["cpe:/", "cpe:/"])

    def test_remove_duplicate_parent_nodes(self):
        # Create a tree with duplicate parent nodes
        root = Node("root")
        child1 = Node("child1", parent=root)
        child2 = Node("child1", parent=child1)
        child3 = Node("child1", parent=child2)
        Node("grandchild1", parent=child3)
        _remove_duplicate_parent_nodes(root)
        render_tree(root)
        # Assert that the tree structure is as expected
        _check_node_names_at_depth(root, 1, ["child1"])
        _check_node_names_at_depth(root, 2, ["grandchild1"])

    def test_remove_rpms_in_containers(self):
        # Create a tree with an rpm in a container
        # pkg:rpm/redhat/openssl-libs
        # └── pkg:oci/quay-builder-qemu-rhcos-rhel8
        root = Node("pkg:rpm/redhat/openssl-libs")
        Node("pkg:oci/quay-builder-qemu-rhcos-rhel8", parent=root)
        assert container_in_tree(root)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_go_crypto_shipped_components(
        self, mock_service
    ):
        mock_service.return_value = self.mock_proddefs_data
        """Test PSDEVOPS-4563: affects use shipped components, not searched dependency."""
        with open("tests/testdata/go-crypto.json") as file:
            data = json.load(file)
        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:golang/golang.org/x/crypto"
        )
        assert len(result.affects) > 0
        for affect in result.affects:
            assert affect.purl.startswith("pkg:rpm/") or affect.purl.startswith(
                "pkg:oci/"
            ), (
                f"Affect should be shipped component (rpm/oci), not dependency: {affect.purl}"
            )

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_quay(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test build_product_search_result with quay data - shipped_component is root when top-level."""
        with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
            data = json.load(file)
        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:oci/quay-builder-qemu-rhcos-rhel8"
        )
        assert len(result.results) >= 1
        assert len(result.affects) >= 1
        for affect in result.affects:
            assert affect.purl.startswith("pkg:oci/")
            assert "quay" in affect.purl.lower()

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_build_product_search_result_sbom_ids(self, mock_service):
        """Verify result rows include sbom_ids when built from API data."""
        mock_service.return_value = self.mock_proddefs_data
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"
        )
        assert len(result.results) >= 1
        # All rows should have sbom_ids list
        for row in result.results:
            assert hasattr(row, "sbom_ids")
            assert isinstance(row.sbom_ids, list)
            assert len(row.sbom_ids) >= 1

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    @patch("trustshell.console")
    def test_render_json_includes_sbom_ids(self, mock_console, mock_service):
        """Verify JSON output includes sbom_ids per result row."""
        mock_service.return_value = self.mock_proddefs_data
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"
        )
        result.render(output="json", include_modules=True)
        call_args = mock_console.print_json.call_args[0][0]
        output = json.loads(call_args)
        assert "results" in output
        assert len(output["results"]) >= 1
        for row_out in output["results"]:
            assert "sbom_ids" in row_out
            assert isinstance(row_out["sbom_ids"], list)
            assert len(row_out["sbom_ids"]) >= 1

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extract_affects_container_cdx(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test build_product_search_result affects using quay-builder-qemu-rhcos-rhel-8.json data"""
        with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
            data = json.load(file)

        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:oci/quay-builder-qemu-rhcos-rhel8"
        )

        assert len(result.affects) == 2
        for affect in result.affects:
            assert affect.ps_update_stream in ["quay-3.12", "quay-3.13"]
            assert (
                affect.purl
                == "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8"
            )

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extract_affects_container_cdx_no_cpes(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test build_product_search_result affects (no cpes flag) using quay-builder-qemu-rhcos-rhel-8.json"""
        with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
            data = json.load(file)

        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees,
            prod_defs,
            "pkg:oci/quay-builder-qemu-rhcos-rhel8",
            cpes=False,
        )

        assert len(result.affects) == 2
        for affect in result.affects:
            assert affect.ps_update_stream in ["quay-3.12", "quay-3.13"]
            assert (
                affect.purl
                == "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8"
            )

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_extract_affects_maven(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test build_product_search_result maven special handling - root maven PURL in affects"""
        with open("tests/testdata/maven-special-handling.json") as file:
            data = json.load(file)

        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        # Maven root - use the root component from the tree
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:maven/io.quay/hey", cpes=False
        )

        assert len(result.affects) == 2
        for affect in result.affects:
            assert affect.ps_update_stream in ["quay-3.12", "quay-3.13"]
            assert affect.purl == "pkg:maven/io.quay/hey@1.2.3.redhat-00001?type=jar"

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_no_duplicates_from_product_mappings(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test that build_product_search_result produces unique affects (no duplicate stream+purl)"""
        with open("tests/testdata/libxml2.json") as file:
            data = json.load(file)

        ancestor_trees = _trees_with_cpes(data, show_versions=True)
        prod_defs = ProdDefs()
        result = build_product_search_result(
            ancestor_trees, prod_defs, "pkg:rpm/redhat/libxml2"
        )

        # affects is a set - no duplicates by design
        assert len(result.affects) > 0
        seen = set()
        for affect in result.affects:
            key = (affect.ps_update_stream, affect.purl)
            assert key not in seen, f"Duplicate affect: {key}"
            seen.add(key)

    @patch("trustshell.product_definitions.ProdDefs.get_product_definitions_service")
    def test_no_duplicates_from_unsorted_branches(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """
        Test that there are duplicates from unsorted branches - eg.

        ...
        --- Tree 41 ---
        pkg:rpm/redhat/libxml2@2.9.7-16.el8_8.12
        ├── cpe:/o:redhat:rhel_e4s:8.8:*:baseos:*
        ├── cpe:/a:redhat:rhel_e4s:8.8:*:appstream:*
        ├── cpe:/a:redhat:rhel_tus:8.8:*:appstream:*
        └── cpe:/o:redhat:rhel_tus:8.8:*:baseos:*

        --- Tree 42 ---
        pkg:rpm/redhat/libxml2@2.9.7-16.el8_8.12
        ├── cpe:/a:redhat:rhel_tus:8.8:*:appstream:*
        ├── cpe:/o:redhat:rhel_tus:8.8:*:baseos:*
        ├── cpe:/o:redhat:rhel_e4s:8.8:*:baseos:*
        └── cpe:/a:redhat:rhel_e4s:8.8:*:appstream:*
        """
        # with open("tests/testdata/remove-duplicate-trees.json") as file:
        with open("tests/testdata/libxml2.json") as file:
            data = json.load(file)

        # Build the initial trees
        ancestor_trees = _trees_with_cpes(data, show_versions=True)

        # Print the tree structure for debugging
        for i, tree in enumerate(ancestor_trees):
            print(f"\n--- Tree {i} ---")
            render_tree(tree.root)

        def sort_tree_recursively(node):
            if node.children:
                node.children = sorted(node.children, key=lambda child: child.name)
                for child in node.children:
                    sort_tree_recursively(child)

        sorted_tree_signatures = {
            _get_branch_signature(tree) for tree in ancestor_trees
        }
        # We expect that the signatures of the sorted tree
        # will preserve the count even when put into a set
        assert len(ancestor_trees) == len(sorted_tree_signatures)

    @parameterized.expand(
        [
            (False, "pkg:rpm/redhat/openssl"),
            (True, "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"),
        ],
    )
    def test_trees_with_cpes_srpm_no_versions(self, show_versions, expected_purl):
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data, show_versions=show_versions)
        assert len(result) == 1
        render_tree(result[0])
        assert result[0].name == expected_purl
        expected_cpes = [
            "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
            "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
        ]
        _check_node_names_at_depth(result[0], 1, expected_cpes)

    def test_purl_to_bare(self):
        """purl_to_bare strips version and qualifiers."""
        full = "pkg:rpm/redhat/python3.12@3.12.9-1.el9?arch=src&repository_id=rhel-9-for-s390x-appstream-source-rpms__9"
        assert purl_to_bare(full) == "pkg:rpm/redhat/python3.12"
        assert purl_to_bare("pkg:pypi/chardet@3.0.4") == "pkg:pypi/chardet"
        assert purl_to_bare("pkg:generic/Python@3.12.9?checksum=SHA-256:abc") == "pkg:generic/Python"

    @parameterized.expand(
        [
            (
                "www.python.org",
                "www.python.org-search.json",
                "pkg:generic/Python",
            ),
            (
                "Python",
                "www.python.org-search.json",
                "pkg:generic/Python",
            ),
            (
                "nonexistent",
                None,
                None,
            ),
        ]
    )
    @patch("trustshell.products.httpx.get")
    def test_get_generic_purl_from_search_term(
        self, search_term, data_file, expected, mock_get
    ):
        """get_generic_purl_from_search_term returns first result's purl stripped to bare or None."""
        if data_file is None:
            mock_get.return_value.json.return_value = {"items": []}
        else:
            with open(f"tests/testdata/{data_file}") as f:
                mock_get.return_value.json.return_value = json.load(f)
        mock_get.return_value.raise_for_status = lambda: None
        result = get_generic_purl_from_search_term(search_term, latest=True)
        assert result == expected
        mock_get.assert_called_once()
        if expected is not None:
            assert mock_get.call_args.kwargs["params"]["q"] == search_term

    @patch("trustshell.products.httpx.get")
    def test_get_redhat_purl_from_generic(self, mock_get):
        """purl~pkg:generic/Python with descendants returns items[0].descendants[0].purl[0] stripped to bare."""
        with open("tests/testdata/pkg-generic-python-descendants.json") as f:
            data = json.load(f)
        mock_get.return_value.json.return_value = data
        mock_get.return_value.raise_for_status = lambda: None
        result = get_redhat_purl_from_generic("pkg:generic/Python", latest=True)
        assert result == "pkg:rpm/redhat/python3.12"
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args.kwargs["params"]["q"] == "purl~pkg:generic/Python"
        assert call_args.kwargs["params"]["descendants"] == 10
        assert call_args.kwargs["params"]["relationships"] == "ancestor_of"

    @patch("trustshell.products.httpx.get")
    def test_get_redhat_purl_from_generic_empty_descendants_returns_none(
        self, mock_get
    ):
        """When items[0] has no descendants, get_redhat_purl_from_generic returns None."""
        mock_get.return_value.json.return_value = {
            "items": [{"purl": ["pkg:generic/Python@3.12.9"], "descendants": []}]
        }
        mock_get.return_value.raise_for_status = lambda: None
        result = get_redhat_purl_from_generic("pkg:generic/Python", latest=True)
        assert result is None

    @patch("trustshell.products.httpx.get")
    def test_search_term_www_python_org_resolves_to_redhat_purl(self, mock_get):
        """Search 'www.python.org' -> generic then redhat PURL (same as trust-products input)."""
        with open("tests/testdata/www.python.org-search.json") as f:
            search_data = json.load(f)
        with open("tests/testdata/pkg-generic-python-descendants.json") as f:
            descendants_data = json.load(f)
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.json.side_effect = [search_data, descendants_data]
        generic = get_generic_purl_from_search_term("www.python.org", latest=True)
        assert generic == "pkg:generic/Python"
        redhat = get_redhat_purl_from_generic(generic, latest=True)
        assert redhat == "pkg:rpm/redhat/python3.12"

    @patch("trustshell.products.httpx.get")
    def test_search_term_python_resolves_to_same_redhat_purl(self, mock_get):
        """Search 'Python' -> same generic then redhat PURL as www.python.org."""
        with open("tests/testdata/www.python.org-search.json") as f:
            search_data = json.load(f)
        with open("tests/testdata/pkg-generic-python-descendants.json") as f:
            descendants_data = json.load(f)
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.json.side_effect = [search_data, descendants_data]
        generic = get_generic_purl_from_search_term("Python", latest=True)
        assert generic == "pkg:generic/Python"
        redhat = get_redhat_purl_from_generic(generic, latest=True)
        assert redhat == "pkg:rpm/redhat/python3.12"


def _check_node_names_at_depth(result, depth, expected):
    node_names = [node.name for node in result.descendants if node.depth == depth]
    assert sorted(expected) == sorted(node_names)
