"""Unit tests for API clients."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.utils.api_clients import (
    APIResponse,
    GitHubClient,
    NVDClient,
    RateLimitInfo,
)


class TestRateLimitInfo:
    """Tests for RateLimitInfo dataclass."""

    def test_reset_datetime(self) -> None:
        """Test conversion of timestamp to datetime."""
        # Use a known timestamp
        timestamp = 1706745600  # 2024-02-01 00:00:00 UTC
        info = RateLimitInfo(limit=5000, remaining=4999, reset_timestamp=timestamp)

        result = info.reset_datetime
        assert result.year == 2024
        assert result.month == 2
        assert result.day == 1

    def test_should_wait_when_exhausted(self) -> None:
        """Test should_wait when rate limit is exhausted."""
        info = RateLimitInfo(limit=5000, remaining=0, reset_timestamp=9999999999)
        assert info.should_wait is True

    def test_should_not_wait_when_available(self) -> None:
        """Test should_wait when requests are available."""
        info = RateLimitInfo(limit=5000, remaining=100, reset_timestamp=0)
        assert info.should_wait is False


class TestAPIResponse:
    """Tests for APIResponse dataclass."""

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        response = APIResponse(
            data={"key": "value"},
            status_code=200,
            headers={"Content-Type": "application/json"},
            source="test",
            endpoint="/test",
        )

        result = response.to_dict()

        assert result["data"] == {"key": "value"}
        assert result["status_code"] == 200
        assert result["source"] == "test"
        assert result["endpoint"] == "/test"
        assert "fetched_at" in result
        assert "_metadata" in result
        assert result["_metadata"]["headers"]["Content-Type"] == "application/json"

    def test_default_fetched_at(self) -> None:
        """Test that fetched_at is automatically set."""
        response = APIResponse(
            data={},
            status_code=200,
            headers={},
        )

        # Should be a valid ISO format timestamp
        datetime.fromisoformat(response.fetched_at)


class TestGitHubClient:
    """Tests for GitHubClient."""

    def test_init_without_token(self) -> None:
        """Test initialization without API token."""
        client = GitHubClient()
        assert client.api_key is None

    def test_init_with_token(self) -> None:
        """Test initialization with API token."""
        client = GitHubClient(api_key="test_token")
        assert client.api_key == "test_token"

    def test_headers_without_token(self) -> None:
        """Test request headers without token."""
        client = GitHubClient()
        headers = client._get_headers()

        assert "Accept" in headers
        assert "X-GitHub-Api-Version" in headers
        assert "Authorization" not in headers

    def test_headers_with_token(self) -> None:
        """Test request headers with token."""
        client = GitHubClient(api_key="test_token")
        headers = client._get_headers()

        assert headers["Authorization"] == "Bearer test_token"

    @patch("requests.Session.get")
    def test_get_repository(self, mock_get: MagicMock) -> None:
        """Test fetching repository metadata."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "stargazers_count": 145000,
            "forks_count": 5000,
        }
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": "1706745600",
        }
        mock_get.return_value = mock_response

        client = GitHubClient()
        result = client.get_repository()

        assert result.data["stargazers_count"] == 145000
        assert result.status_code == 200

    @patch("requests.Session.get")
    def test_get_issues_with_labels(self, mock_get: MagicMock) -> None:
        """Test fetching issues with label filter."""
        mock_response = MagicMock()
        mock_response.json.return_value = [{"id": 1, "title": "Security issue"}]
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_get.return_value = mock_response

        client = GitHubClient()
        result = client.get_issues(labels="security,vulnerability")

        assert result.status_code == 200
        # Verify the labels parameter was passed
        call_args = mock_get.call_args
        assert "labels" in call_args.kwargs.get("params", {})


class TestNVDClient:
    """Tests for NVDClient."""

    def test_init_rate_limit_without_key(self) -> None:
        """Test rate limit interval without API key."""
        client = NVDClient()
        assert client._min_request_interval == 6.0

    def test_init_rate_limit_with_key(self) -> None:
        """Test rate limit interval with API key."""
        client = NVDClient(api_key="test_key")
        assert client._min_request_interval == 0.6

    def test_headers_without_key(self) -> None:
        """Test request headers without API key."""
        client = NVDClient()
        headers = client._get_headers()

        assert headers["Accept"] == "application/json"
        assert "apiKey" not in headers

    def test_headers_with_key(self) -> None:
        """Test request headers with API key."""
        client = NVDClient(api_key="test_key")
        headers = client._get_headers()

        assert headers["apiKey"] == "test_key"

    @patch("requests.Session.get")
    @patch("time.sleep")
    def test_search_cves(self, mock_sleep: MagicMock, mock_get: MagicMock) -> None:
        """Test CVE search."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-25253"}}],
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        client = NVDClient()
        result = client.search_cves(keyword_search="openclaw")

        assert result.data["totalResults"] == 1
        assert len(result.data["vulnerabilities"]) == 1


class TestDataSerialization:
    """Tests for data serialization helpers."""

    def test_api_response_json_serializable(self) -> None:
        """Test that APIResponse.to_dict() is JSON serializable."""
        response = APIResponse(
            data={"nested": {"key": "value"}, "list": [1, 2, 3]},
            status_code=200,
            headers={"X-Custom": "header"},
            source="test",
            endpoint="/test",
        )

        # Should not raise
        json_str = json.dumps(response.to_dict())
        assert json_str is not None

        # Should be deserializable
        parsed = json.loads(json_str)
        assert parsed["data"]["nested"]["key"] == "value"
