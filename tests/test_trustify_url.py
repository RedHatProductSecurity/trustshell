import importlib
import os
from unittest.mock import patch

import trustshell


def _reload_trustshell() -> None:
    importlib.reload(trustshell)


class TestTrustifyUrl:
    def test_default_appends_v2_when_no_path(self) -> None:
        with patch.dict(
            os.environ,
            {"TRUSTIFY_URL": "https://atlas.example.com"},
            clear=False,
        ):
            _reload_trustshell()
            assert trustshell.TRUSTIFY_URL == "https://atlas.example.com/api/v2/"

    def test_preserves_explicit_v3_path(self) -> None:
        with patch.dict(
            os.environ,
            {"TRUSTIFY_URL": "https://atlas.example.com/api/v3/"},
            clear=False,
        ):
            _reload_trustshell()
            assert trustshell.TRUSTIFY_URL == "https://atlas.example.com/api/v3/"

    def test_preserves_explicit_v2_path(self) -> None:
        with patch.dict(
            os.environ,
            {"TRUSTIFY_URL": "https://atlas.example.com/api/v2/"},
            clear=False,
        ):
            _reload_trustshell()
            assert trustshell.TRUSTIFY_URL == "https://atlas.example.com/api/v2/"

    def teardown_method(self) -> None:
        os.environ.pop("TRUSTIFY_URL", None)
        _reload_trustshell()
