import json

from anytree import Node

from trustshell.products import (
    _build_node_purl,
    _remove_duplicate_parent_nodes,
    _trees_with_cpes,
    _render_tree,
    _has_cpe_node,
)


def test_build_node_purl_rpm():
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
    result = _build_node_purl(purls).to_string()
    assert result == "pkg:rpm/redhat/webkit2gtk3@2.42.5-1.el9"


def test_build_node_purl_oci():
    purls = [
        "pkg:oci/quay@sha256:9",
        "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8-1",
        "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12.8",
        "pkg:oci/quay@sha256:9?repo_url=x.com/quay/quay-builder-qemu-rhcos-rhel8&tag=v3.12",
    ]
    result = _build_node_purl(purls).to_string()
    print(result)
    assert result == "pkg:oci/quay?tag=v3.12.8-1"


def test_trees_with_cpes_srpm():
    with open("tests/testdata/openssl.json", "r") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 1
    _render_tree(result[0])
    assert result[0].name == "pkg:rpm/redhat/openssl@3.0.7-18.el9_2"
    expected_cpes = [
        "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
        "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
    ]
    _check_node_names_at_depth(result[0], 1, expected_cpes)


def test_trees_with_cpes_binary_rpm():
    with open("tests/testdata/openssl-libs.json", "r") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 1
    _render_tree(result[0])
    assert result[0].name == "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2"
    _check_node_names_at_depth(result[0], 1, ["pkg:rpm/redhat/openssl@3.0.7-18.el9_2"])
    expected_cpes = [
        "cpe:/a:redhat:rhel_eus:9.2:*:appstream:*",
        "cpe:/a:redhat:rhel_eus:9.2:*:baseos:*",
    ]
    _check_node_names_at_depth(result[0], 2, expected_cpes)


def test_trees_with_cpes_container_cdx():
    with open("tests/testdata/quay-builder-qemu-rhcos-rhel-8.json") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 1
    _render_tree(result[0])
    assert result[0].name == "pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1"
    expected_cpe = ["cpe:/a:redhat:quay:3:*:el8:*"]
    _check_node_names_at_depth(result[0], 1, expected_cpe)


def test_trees_with_cpes_dependency():
    with open("tests/testdata/chardet.json") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 1
    _render_tree(result[0])
    _check_node_names_at_depth(
        result[0], 1, ["pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1"]
    )
    expected_cpe = ["cpe:/a:redhat:quay:3:*:el8:*"]
    _check_node_names_at_depth(result[0], 2, expected_cpe)


def test_trees_with_cpes_spdx_dependency():
    with open("tests/testdata/NGX.json") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 1
    _render_tree(result[0])
    _check_node_names_at_depth(
        result[0], 1, ["pkg:oci/bootc-nvidia-rhel9?tag=1.4.3-1743086940"]
    )
    _check_node_names_at_depth(
        result[0], 2, ["cpe:/a:redhat:enterprise_linux_ai:1.4:*:el9:*"]
    )


def test_trees_with_cpes_multi_versions():
    with open("tests/testdata/quay-builder-qemu-multi.json") as file:
        data = json.load(file)
    result = _trees_with_cpes(data)
    assert len(result) == 2

    print("first_result")
    _render_tree(result[0])
    assert result[0].name == "pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.14.0-4"
    expected_cpes = ["cpe:/a:redhat:quay:3:*:el8:*"]
    _check_node_names_at_depth(result[0], 1, expected_cpes)

    print("second_result")
    _render_tree(result[1])
    assert result[1].name == "pkg:oci/quay-builder-qemu-rhcos-rhel8?tag=v3.12.8-1"
    _check_node_names_at_depth(result[1], 1, expected_cpes)


def _check_node_names_at_depth(result, depth, expected):
    node_names = [node.name for node in result.descendants if node.depth == depth]
    assert sorted(expected) == sorted(node_names)


def test_has_cpe_node_with_cpe_name():
    root = Node("cpe:/a", children=[Node("cpe:/b"), Node("d")])
    assert _has_cpe_node(root)


def test_has_cpe_node_without_cpe_name():
    root = Node("d", children=[Node("cpe:/a"), Node("b")])
    assert _has_cpe_node(root)


def test_has_cpe_node_with_cpe_descendant():
    root = Node("d", children=[Node("b"), Node("cpe:/a")])
    assert _has_cpe_node(root)


def test_has_cpe_node_with_multiple_cpe_descendants():
    root = Node("d", children=[Node("b"), Node("cpe:/a"), Node("cpe:/b")])
    assert _has_cpe_node(root)


def test_has_cpe_node_with_no_descendants():
    root = Node("d")
    assert not _has_cpe_node(root)


def test_has_cpe_node_with_empty_children():
    root = Node("d")
    assert not _has_cpe_node(root)


def test_remove_duplicate_parent_nodes():
    # Create a tree with duplicate parent nodes
    root = Node("root")
    child1 = Node("child1", parent=root)
    child2 = Node("child1", parent=child1)
    child3 = Node("child1", parent=child2)
    Node("grandchild1", parent=child3)
    _remove_duplicate_parent_nodes(root)
    _render_tree(root)
    # Assert that the tree structure is as expected
    _check_node_names_at_depth(root, 1, ["child1"])
    _check_node_names_at_depth(root, 2, ["grandchild1"])


def create_node(root, name, children) -> list[Node]:
    node_a = Node(name, parent=root)
    new_nodes = []
    for child in children:
        new_nodes.append(Node(child, parent=node_a))
    return new_nodes
