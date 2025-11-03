import unittest

import pytest

from trustshell.osidb import OSIDB


class TestOSIDB(unittest.TestCase):
    def test_parse_stream_purl_tuples(self):
        input_list = ["rhel-9.4.z,purl1", "rhel-9.2.z,purl2"]
        expected_output = {("rhel-9.4.z", "purl1"), ("rhel-9.2.z", "purl2")}
        assert OSIDB.parse_stream_purl_tuples(input_list) == expected_output

    def test_parse_stream_purl_tuples_invalid_format(self):
        input_list = ["rhel-9.4.z", "rhel-9.2.z,purl2"]
        with pytest.raises(SystemExit):
            OSIDB.parse_stream_purl_tuples(input_list)

    def test_parse_stream_purl_empty_ps_update_stream(self):
        input_list = [",purl1"]
        with pytest.raises(SystemExit):
            OSIDB.parse_stream_purl_tuples(input_list)

    def test_parse_stream_purl_empty_purl(self):
        input_list = ["rhel-9.4.z,"]
        with pytest.raises(SystemExit):
            OSIDB.parse_stream_purl_tuples(input_list)
