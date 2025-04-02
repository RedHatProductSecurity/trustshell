import json
from unittest.mock import patch
from trustshell.purl import _get_package_versions


@patch("trustshell.purl._lookup_base_purl")
def test_package_versions(mock_lookup):
    base_purl = "pkg:oci/quay-builder-qemu-rhcos-rhel-8"
    expected_output = {"v3.12.8-1", "v3.12.8", "v3.12"}
    with open("tests/testdata/base_purl-quay-builder-qemu-rhcos-rhel-8.json") as file:
        mock_lookup.return_value = json.load(file)
    assert _get_package_versions(base_purl) == expected_output
