import json
import unittest
from unittest.mock import patch

from anytree import Node

from trustshell import build_node_purl
from trustshell.products import (
    _remove_duplicate_parent_nodes,
    _remove_non_cpe_branches,
    _trees_with_cpes,
    render_tree,
    _has_cpe_node,
    container_in_tree,
    extract_affects,
)
from trustshell.product_definitions import ProdDefs


class TestProducts(unittest.TestCase):
    def setUp(self):
        with open("tests/testdata/product-definitions.json", "r") as file:
            self.mock_proddefs_data = json.load(file)

    def test_build_node_purl_rpm(self):
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
        result = build_node_purl(purls).to_string()
        assert result == "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9"

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

    def test_build_node_purl_maven_type(self):
        purls = [
            "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar"
            "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=jar&hash=sha256:1234567890"
        ]
        result = build_node_purl(purls).to_string()
        print(result)
        assert (
            result
            == "pkg:maven/io.agroal/agroal-api@1.3.0.redhat-00001?hash=sha256:1234567890&type=jar"
        )

    def test_trees_with_cpes_srpm(self):
        with open("tests/testdata/openssl.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data)
        assert len(result) == 1
        render_tree(result[0])
        assert result[0].name == "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"
        expected_cpes = [
            "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
            "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
        ]
        _check_node_names_at_depth(result[0], 1, expected_cpes)

    def test_trees_with_cpes_binary_rpm(self):
        with open("tests/testdata/openssl-libs.json", "r") as file:
            data = json.load(file)
        result = _trees_with_cpes(data)
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
        result = _trees_with_cpes(data)
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
        result = _trees_with_cpes(data)
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
        result = _trees_with_cpes(data)
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
        result = _trees_with_cpes(data)
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
        result = _trees_with_cpes(data)

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
        result = _trees_with_cpes(data)

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
        result = _trees_with_cpes(data)
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
    def test_extract_affects_container_cdx(self, mock_service):
        mock_service.return_value = self.mock_proddefs_data
        """Test extract_affects using quay-builder-qemu-rhcos-rhel-8.json data"""
        with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
            data = json.load(file)

        # Build the initial trees
        ancestor_trees = _trees_with_cpes(data)

        # Extend with product mappings to add ProductModule nodes
        prod_defs = ProdDefs()
        ancestor_trees = prod_defs.extend_with_product_mappings(ancestor_trees)

        # Print the tree structure for debugging
        for i, tree in enumerate(ancestor_trees):
            print(f"\n--- Tree {i} ---")
            render_tree(tree.root)

        # Call extract_affects and print the result
        affects = extract_affects(ancestor_trees)
        print(f"\nExtracted affects: {affects}")

        # For now, just assert that we got some result
        # The user will adjust assertions based on the printed output
        assert affects == {
            (
                "quay-3",
                "pkg:oci/quay-builder-qemu-rhcos-rhel8?repository_url=registry.access.redhat.com/quay/quay-builder-qemu-rhcos-rhel8",
            )
        }


def _check_node_names_at_depth(result, depth, expected):
    node_names = [node.name for node in result.descendants if node.depth == depth]
    assert sorted(expected) == sorted(node_names)
