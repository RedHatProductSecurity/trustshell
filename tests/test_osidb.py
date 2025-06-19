import unittest

import pytest

from trustshell.osidb import OSIDB


class TestOSIDB(unittest.TestCase):
    def test_parse_module_purl_tuples(self):
        input_list = ["ps_module1,purl1", "ps_module2,purl2"]
        expected_output = {("ps_module1", "purl1"), ("ps_module2", "purl2")}
        assert OSIDB.parse_module_purl_tuples(input_list) == expected_output

    def test_parse_module_purl_tuples_invalid_format(self):
        input_list = ["ps_module1", "ps_module2,purl2"]
        with pytest.raises(SystemExit):
            OSIDB.parse_module_purl_tuples(input_list)

    def test_parse_module_purl_empty_ps_module(self):
        input_list = [",purl1"]
        with pytest.raises(SystemExit):
            OSIDB.parse_module_purl_tuples(input_list)

    def test_parse_module_purl_empty_purl(self):
        input_list = ["ps_module1,"]
        with pytest.raises(SystemExit):
            OSIDB.parse_module_purl_tuples(input_list)
