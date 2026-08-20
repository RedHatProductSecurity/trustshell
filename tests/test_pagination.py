from unittest.mock import MagicMock, patch

from trustshell import paginated_trustify_query


def _mock_response(json_data: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = json_data
    response.raise_for_status = MagicMock()
    return response


def _item(n: int) -> dict[str, int]:
    return {"id": n}


@patch("trustshell.AUTH_ENABLED", False)
@patch("trustshell.httpx.Client")
class TestPaginatedTrustifyQuery:
    endpoint = "http://localhost:8080/api/v2/analysis/latest/component"

    def test_does_not_add_total_by_default(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value = _mock_response({"items": [_item(1)], "total": 1})

        paginated_trustify_query(self.endpoint, {"q": "purl~foo"}, {}, limit=100)

        first_call_params = mock_client.get.call_args_list[0].kwargs["params"]
        assert "total" not in first_call_params
        assert first_call_params["limit"] == 100
        assert first_call_params["offset"] == 0

    def test_known_total_fetches_all_pages(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = [
            _mock_response({"items": [_item(i) for i in range(100)], "total": 150}),
            _mock_response(
                {"items": [_item(i) for i in range(100, 150)], "total": 150}
            ),
        ]

        result = paginated_trustify_query(
            self.endpoint, {"q": "purl~foo"}, {}, limit=100
        )

        assert len(result["items"]) == 150
        assert result["total"] == 150
        assert mock_client.get.call_count == 2

    def test_null_total_fetches_until_short_page(
        self, mock_client_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = [
            _mock_response({"items": [_item(i) for i in range(100)], "total": None}),
            _mock_response(
                {"items": [_item(i) for i in range(100, 125)], "total": None}
            ),
        ]

        result = paginated_trustify_query(
            self.endpoint, {"q": "purl~foo"}, {}, limit=100
        )

        assert len(result["items"]) == 125
        assert result["total"] == 125
        assert mock_client.get.call_count == 2

    def test_empty_response_with_null_total(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value = _mock_response({"items": [], "total": None})

        result = paginated_trustify_query(
            self.endpoint, {"q": "purl~missing"}, {}, limit=100
        )

        assert result == {"items": [], "total": 0}
        assert mock_client.get.call_count == 1

    def test_respects_explicit_total_param(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value = _mock_response({"items": [_item(1)], "total": 1})

        paginated_trustify_query(
            self.endpoint,
            {"q": "purl~foo", "total": True},
            {},
            limit=100,
        )

        first_call_params = mock_client.get.call_args_list[0].kwargs["params"]
        assert first_call_params["total"] is True

    def test_numeric_total_pagination(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = [
            _mock_response({"items": [_item(0)], "total": 2}),
            _mock_response({"items": [_item(1)], "total": 2}),
        ]

        result = paginated_trustify_query(self.endpoint, {"q": "purl~foo"}, {}, limit=1)

        assert len(result["items"]) == 2
        assert result["total"] == 2
        assert mock_client.get.call_count == 2
