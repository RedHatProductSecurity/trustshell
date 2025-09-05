from unittest.mock import Mock, patch
from packageurl import PackageURL

from trustshell.purl import _query_trustify_packages_base_purl


class TestBasePurlQuery:
    """Test the alternative base_purl endpoint query method"""

    @patch("trustshell.purl.paginated_trustify_query")
    def test_query_trustify_packages_base_purl_success(self, mock_paginated_query):
        """Test successful query using base_purl endpoint with pagination"""
        # Mock response data similar to the test data structure
        mock_response_data = {
            "items": [
                {"purl": "pkg:oci/quay-builder-qemu-rhcos-rhel8"},
                {"purl": "pkg:rpm/rhel/openssl@3.0.7-18.el9_2"},
                {"purl": "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14"},
            ],
            "total": 3,
        }

        mock_paginated_query.return_value = mock_response_data

        # Test the function
        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages_base_purl("openssl", auth_header)

        # Verify the results
        assert len(result) == 3
        assert all(isinstance(purl, PackageURL) for purl in result)

        # Check that paginated_trustify_query was called with correct parameters
        mock_paginated_query.assert_called_once()
        call_args = mock_paginated_query.call_args
        # Check endpoint URL (first argument)
        assert "purl/base" in call_args[0][0]
        # Check query parameters (second argument)
        assert call_args[0][1] == {"q": "openssl"}
        # Check auth header (third argument)
        assert call_args[0][2] == auth_header
        # Check component name (fourth argument)
        assert call_args[1]["component_name"] == "base PURLs matching 'openssl'"

    @patch("trustshell.purl.paginated_trustify_query")
    def test_query_trustify_packages_base_purl_empty_response(
        self, mock_paginated_query
    ):
        """Test handling of empty response"""
        mock_response_data = {"items": [], "total": 0}

        mock_paginated_query.return_value = mock_response_data

        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages_base_purl("nonexistent", auth_header)

        assert len(result) == 0
        assert isinstance(result, list)

    @patch("trustshell.purl.paginated_trustify_query")
    def test_query_trustify_packages_base_purl_http_error(self, mock_paginated_query):
        """Test handling of HTTP errors"""
        import httpx

        # Mock paginated_trustify_query to raise an HTTPStatusError
        mock_paginated_query.side_effect = httpx.HTTPStatusError(
            "404 Not Found", request=Mock(), response=Mock()
        )

        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages_base_purl("test", auth_header)

        # Should return empty list on error
        assert len(result) == 0
        assert isinstance(result, list)

    @patch("trustshell.purl.paginated_trustify_query")
    def test_query_trustify_packages_base_purl_invalid_purl(self, mock_paginated_query):
        """Test handling of invalid PURL strings"""
        mock_response_data = {
            "items": [
                {"purl": "pkg:oci/valid-package"},
                {"purl": "invalid-purl-string"},  # This should be skipped
                {"purl": "pkg:rpm/rhel/another-valid@1.0.0"},
            ],
            "total": 3,
        }

        mock_paginated_query.return_value = mock_response_data

        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages_base_purl("test", auth_header)

        # Should return only valid PURLs (invalid one skipped)
        assert len(result) == 2
        assert all(isinstance(purl, PackageURL) for purl in result)

    @patch("trustshell.purl._lookup_base_purl")
    @patch("trustshell.purl.paginated_trustify_query")
    def test_query_trustify_packages_base_purl_with_versions(
        self, mock_paginated_query, mock_lookup
    ):
        """Test base_purl query with include_versions=True"""
        # Mock the base search response
        mock_response_data = {"items": [{"purl": "pkg:rpm/redhat/openssl"}], "total": 1}

        mock_paginated_query.return_value = mock_response_data

        # Mock the detailed lookup response (based on provided example)
        mock_lookup_data = {
            "uuid": "4260c624-c8a1-5dad-a4a4-dafd6a73405b",
            "purl": "pkg:rpm/redhat/openssl",
            "versions": [
                {
                    "uuid": "ed948a1a-c751-52c4-9b6f-d2ae925d188f",
                    "purl": "pkg:rpm/redhat/openssl@3.0.7-28.el9_4",
                    "version": "3.0.7-28.el9_4",
                    "purls": [
                        {
                            "uuid": "899c4eaf-7ea5-5e37-ba6e-db2492425192",
                            "purl": "pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=x86_64&distro=rhel-9.4&epoch=1&upstream=openssl-3.0.7-28.el9_4.src.rpm",
                        },
                        {
                            "uuid": "9c0b264e-f738-58b3-bf1e-70ec69f7c334",
                            "purl": "pkg:rpm/redhat/openssl@3.0.7-28.el9_4?arch=aarch64&distro=rhel-9.4&epoch=1&upstream=openssl-3.0.7-28.el9_4.src.rpm",
                        },
                    ],
                }
            ],
        }
        mock_lookup.return_value = mock_lookup_data

        # Test the function with include_versions=True
        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages_base_purl(
            "openssl", auth_header, include_versions=True
        )

        # Should return version PURLs and individual variant PURLs
        assert len(result) == 3  # 1 version PURL + 2 individual PURLs
        assert all(isinstance(purl, PackageURL) for purl in result)

        # Verify _lookup_base_purl was called
        mock_lookup.assert_called_once_with("pkg:rpm/redhat/openssl", auth_header)

        # Check that we got the expected PURLs
        purl_strings = [purl.to_string() for purl in result]
        assert "pkg:rpm/redhat/openssl@3.0.7-28.el9_4" in purl_strings
        assert any("arch=x86_64" in purl_str for purl_str in purl_strings)
        assert any("arch=aarch64" in purl_str for purl_str in purl_strings)

    @patch("trustshell.purl.paginated_trustify_query")
    @patch("trustshell.purl.console.print")
    def test_search_timeout_suggestion_analysis_endpoint(
        self, mock_console_print, mock_paginated_query
    ):
        """Test that timeout errors from analysis endpoint suggest using --use-base-purl option"""
        from trustshell.purl import search
        from click.testing import CliRunner
        import httpx

        # Mock a timeout error
        mock_paginated_query.side_effect = httpx.ReadTimeout("Request timed out")

        runner = CliRunner()

        # Should exit cleanly with Abort (exit code 1) - NOT using base_purl
        result = runner.invoke(search, ["jenkins"])

        # Should exit with code 1 (click.Abort)
        assert result.exit_code == 1

        # Verify the helpful message was printed
        assert mock_console_print.called

        # Check that the error message mentions --use-base-purl
        call_args = [
            call[0][0] for call in mock_console_print.call_args_list if call[0]
        ]
        error_messages = " ".join(str(arg) for arg in call_args)
        assert "--use-base-purl" in error_messages or "-b" in error_messages

    @patch("trustshell.purl.paginated_trustify_query")
    @patch("trustshell.purl.console.print")
    def test_search_timeout_base_purl_endpoint(
        self, mock_console_print, mock_paginated_query
    ):
        """Test that timeout errors from base_purl endpoint show different message"""
        from trustshell.purl import search
        from click.testing import CliRunner
        import httpx

        # Mock a timeout error from base_purl endpoint
        mock_paginated_query.side_effect = httpx.ReadTimeout("Request timed out")

        runner = CliRunner()

        # Should exit cleanly with Abort (exit code 1) - USING base_purl
        result = runner.invoke(search, ["--use-base-purl", "jenkins"])

        # Should exit with code 1 (click.Abort)
        assert result.exit_code == 1

        # Verify the message was printed
        assert mock_console_print.called

        # Check that the error message does NOT suggest --use-base-purl (since already using it)
        call_args = [
            call[0][0] for call in mock_console_print.call_args_list if call[0]
        ]
        error_messages = " ".join(str(arg) for arg in call_args)
        assert "--use-base-purl" not in error_messages and "-b" not in error_messages
        assert "server may be experiencing high load" in error_messages.lower()

    @patch("trustshell.purl.paginated_trustify_query")
    @patch("trustshell.purl.console.print")
    def test_partial_results_warning(self, mock_console_print, mock_paginated_query):
        """Test that partial results due to page failures show warning"""
        from trustshell.purl import _query_trustify_packages

        # Mock partial results - got some but not all
        mock_paginated_query.return_value = {
            "items": [{"purl": ["pkg:maven/io.jenkins/jenkins@1.0"]}]
            * 100,  # 100 items
            "total": 6820,  # but 6820 were available
        }

        auth_header = {"Authorization": "Bearer test-token"}
        result = _query_trustify_packages("jenkins", auth_header, False)

        # Should have results
        assert len(result) == 100

        # Should have printed a warning
        assert mock_console_print.called

        # Check that warning mentions missing results and suggests --use-base-purl
        call_args = [
            call[0][0] for call in mock_console_print.call_args_list if call[0]
        ]
        warning_messages = " ".join(str(arg) for arg in call_args)
        assert "Warning:" in warning_messages
        assert "6720 missing" in warning_messages  # 6820 - 100 = 6720
        assert "--use-base-purl" in warning_messages or "-b" in warning_messages
