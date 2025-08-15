import unittest
from unittest.mock import patch, call

from anytree import Node

from trustshell import process_and_render_tree


class TestInit(unittest.TestCase):
    @patch("trustshell.console.print")
    def test_process_and_render_tree_with_cpes(self, mock_print):
        """Test that CPEs are pruned by default"""
        root = Node("pkg:rpm/redhat/openssl@1.2.3")
        cpe1 = Node("cpe:/a:redhat:rhel_eus:9.2", parent=root)
        Node("rhel-9.2.z", parent=cpe1)
        cpe2 = Node("cpe:/o:redhat:rhel_eus:9.2", parent=root)
        Node("rhel-9.2.z", parent=cpe2)

        process_and_render_tree(root, show_cpe=False)

        expected_calls = [
            call("pkg:rpm/redhat/openssl@1.2.3"),
            call("├── rhel-9.2.z"),
            call("└── rhel-9.2.z"),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=True)
        # Verify that no CPEs were printed
        for mock_call in mock_print.call_args_list:
            self.assertFalse(mock_call.args[0].startswith("cpe:/"))

    @patch("trustshell.console.print")
    def test_process_and_render_tree_show_cpes(self, mock_print):
        """Test that CPEs are shown when show_cpe is True"""
        root = Node("pkg:rpm/redhat/openssl@1.2.3")
        cpe1 = Node("cpe:/a:redhat:rhel_eus:9.2", parent=root)
        Node("rhel-9.2.z", parent=cpe1)

        process_and_render_tree(root, show_cpe=True)

        expected_calls = [
            call("pkg:rpm/redhat/openssl@1.2.3"),
            call("└── cpe:/a:redhat:rhel_eus:9.2"),
            call("    └── rhel-9.2.z"),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=False)

    @patch("trustshell.console.print")
    def test_process_and_render_tree_root_is_cpe(self, mock_print):
        """Test that children are rendered as roots if the root is a CPE"""
        root = Node("cpe:/a:redhat:rhel_eus:9.2")
        Node("rhel-9.2.z", parent=root)
        Node("another-child", parent=root)

        process_and_render_tree(root, show_cpe=False)

        expected_calls = [
            call("rhel-9.2.z"),
            call("another-child"),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=True)

    @patch("trustshell.console.print")
    def test_process_and_render_tree_no_cpes(self, mock_print):
        """Test that a tree with no CPEs is rendered correctly"""
        root = Node("pkg:rpm/redhat/openssl@1.2.3")
        child = Node("some-child", parent=root)
        Node("grandchild", parent=child)

        process_and_render_tree(root, show_cpe=False)

        expected_calls = [
            call("pkg:rpm/redhat/openssl@1.2.3"),
            call("└── some-child"),
            call("    └── grandchild"),
        ]
        mock_print.assert_has_calls(expected_calls, any_order=False)
