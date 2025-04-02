import json
from unittest.mock import patch

from anytree import Node

from trustshell.products import (
    _build_node_purl,
    _build_root_tree,
    _consolidate_duplicate_nodes,
    _render_tree,
)


def test_build_root_tree_srpm():
    base_purl = "pkg:rpm/redhat/openssl"
    with open("tests/testdata/openssl.json", "r") as file:
        data = json.load(file)
    result = _build_root_tree(base_purl, data)
    _render_tree(result)
    assert result.name == base_purl
    _check_node_names_at_depth(result, 1, ["pkg:rpm/redhat/openssl@3.0.7-18.el9_2"])
    expected_cpes = [
        "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
        "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
    ]
    _check_node_names_at_depth(result, 2, expected_cpes)



def test_build_root_tree_binary_rpm():
    base_purl = "pkg:rpm/redhat/openssl"
    with open("tests/testdata/openssl-libs.json", "r") as file:
        data = json.load(file)
    result = _build_root_tree(base_purl, data)
    _render_tree(result)
    _check_node_names_at_depth(result, 1, ["pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2"])
    _check_node_names_at_depth(result, 2, ["pkg:rpm/redhat/openssl@3.0.7-18.el9_2"])
    expected_cpes = [
        "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
        "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
    ]
    _check_node_names_at_depth(result, 3, expected_cpes)



def test_build_root_tree_container_cdx():
    base_purl = "pkg:oci/quay-builder-qemu-rhcos-rhel-8"
    with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
        data = json.load(file)
    result = _build_root_tree(base_purl, data)
    _render_tree(result)
    assert result.name == base_purl
    _check_node_names_at_depth(result, 1, ["pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1"])



def test_build_root_tree_dependency():
    base_purl = "pkg:pypi/chardet"
    with open("tests/testdata/chardet.json") as file:
        data = json.load(file)
    result = _build_root_tree(base_purl, data)
    _render_tree(result)
    assert result.name == base_purl
    _check_node_names_at_depth(result, 2, ["pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1"])
    expected_cpe = ["cpe:/a:redhat:quay:3:*:el8:*"]
    _check_node_names_at_depth(result, 3, expected_cpe)


def test_build_root_tree_spdx_dependency():
    base_purl = "pkg:nuget/NGX"
    with open("tests/testdata/NGX.json") as file:
        data = json.load(file)
    result = _build_root_tree(base_purl, data)
    _render_tree(result)
    assert result.name == base_purl
    _check_node_names_at_depth(result, 3, ["cpe:/a:redhat:enterprise_linux_ai:1.4:*:el9:*"])


def _check_node_names_at_depth(result, depth, expected):
    node_names = [node.name for node in result.descendants if node.depth == depth]
    assert sorted(expected) == sorted(node_names)



def test_consolidate_duplicate_nodes():
    # Create a sample tree
    root = Node("root")
    create_node(root, "A", ["A1", "A2"])
    create_node(root, "B", ["B1", "B2"])
    create_node(root, "A", ["A3"])

    _render_tree(root)

    # Call the function
    consolidated_root = _consolidate_duplicate_nodes(root)

    _render_tree(consolidated_root)

    # Check if the root node remains the same
    assert consolidated_root.name == "root"
    # Check if the first node A is consolidated
    assert len(consolidated_root.children) == 2
    # Check if the children of node A are still present
    consolidated_a_node = consolidated_root.children[0]
    assert consolidated_a_node.children[0].name == "A1"
    assert consolidated_a_node.children[1].name == "A2"
    assert consolidated_a_node.children[2].name == "A3"

def create_node(root, name, children):
    node_a = Node(name, parent=root)
    for child in children:
        Node(child, parent=node_a)