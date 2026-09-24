"""
API clients for external data sources.

This module provides typed, rate-limit-aware clients for:
- GitHub API (repository stats, issues, releases)
- NVD API (CVE database)

All clients return raw JSON responses for Bronze layer ingestion.
Transformation to structured data happens in Silver layer.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """Track API rate limit status."""

    limit: int = 0
    remaining: int = 0
    reset_timestamp: int = 0

    @property
    def reset_datetime(self) -> datetime:
        """Convert reset timestamp to datetime."""
        return datetime.fromtimestamp(self.reset_timestamp, tz=timezone.utc)

    @property
    def should_wait(self) -> bool:
        """Check if we should wait before making requests."""
        return self.remaining <= 1 and self.reset_timestamp > 0


@dataclass
class APIResponse:
    """Standardized API response wrapper."""

    data: Any
    status_code: int
    headers: dict[str, str]
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ""
    endpoint: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for Bronze layer storage."""
        return {
            "data": self.data,
            "status_code": self.status_code,
            "fetched_at": self.fetched_at,
            "source": self.source,
            "endpoint": self.endpoint,
            "_metadata": {
                "headers": dict(self.headers),
            },
        }


class BaseAPIClient(ABC):
    """Base class for API clients with retry and rate limiting."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit = RateLimitInfo()

        # Configure session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @abstractmethod
    def _get_headers(self) -> dict[str, str]:
        """Return headers for API requests."""
        pass

    def _handle_rate_limit(self, response: requests.Response) -> None:  # noqa: B027
        """Update rate limit info from response headers. No-op unless overridden."""

    def _wait_for_rate_limit(self) -> None:
        """Wait if rate limited."""
        if self.rate_limit.should_wait:
            wait_time = self.rate_limit.reset_timestamp - int(time.time()) + 1
            if wait_time > 0:
                logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> APIResponse:
        """Make GET request with rate limiting and retries."""
        self._wait_for_rate_limit()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        logger.info(f"Fetching: {url}")

        response = self.session.get(
            url,
            headers=self._get_headers(),
            params=params,
            timeout=self.timeout,
        )

        self._handle_rate_limit(response)
        response.raise_for_status()

        return APIResponse(
            data=response.json(),
            status_code=response.status_code,
            headers=dict(response.headers),
            source=self.__class__.__name__,
            endpoint=endpoint,
        )


class GitHubClient(BaseAPIClient):
    """
    GitHub API client for OpenClaw repository data.

    Endpoints used:
    - /repos/{owner}/{repo} - Repository metadata
    - /repos/{owner}/{repo}/issues - Issues (including PRs)
    - /repos/{owner}/{repo}/releases - Release information
    - /repos/{owner}/{repo}/events - Repository events

    Rate limits:
    - Unauthenticated: 60 requests/hour
    - Authenticated: 5,000 requests/hour
    """

    OWNER = "steipete"
    REPO = "openclaw"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            base_url="https://api.github.com",
            api_key=api_key,
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _handle_rate_limit(self, response: requests.Response) -> None:
        """Parse GitHub rate limit headers."""
        self.rate_limit = RateLimitInfo(
            limit=int(response.headers.get("X-RateLimit-Limit", 0)),
            remaining=int(response.headers.get("X-RateLimit-Remaining", 0)),
            reset_timestamp=int(response.headers.get("X-RateLimit-Reset", 0)),
        )
        logger.debug(f"GitHub rate limit: {self.rate_limit.remaining}/{self.rate_limit.limit}")

    def get_repository(self) -> APIResponse:
        """Get repository metadata (stars, forks, etc.)."""
        return self.get(f"/repos/{self.OWNER}/{self.REPO}")

    def get_issues(
        self,
        state: str = "all",
        labels: str | None = None,
        per_page: int = 100,
        page: int = 1,
    ) -> APIResponse:
        """
        Get repository issues.

        Args:
            state: 'open', 'closed', or 'all'
            labels: Comma-separated label names (e.g., 'security,bug')
            per_page: Results per page (max 100)
            page: Page number
        """
        params: dict[str, Any] = {
            "state": state,
            "per_page": per_page,
            "page": page,
            "sort": "updated",
            "direction": "desc",
        }
        if labels:
            params["labels"] = labels
        return self.get(f"/repos/{self.OWNER}/{self.REPO}/issues", params=params)

    def get_security_issues(self, per_page: int = 100, page: int = 1) -> APIResponse:
        """Get issues labeled with security-related tags."""
        return self.get_issues(
            state="all",
            labels="security,vulnerability,cve",
            per_page=per_page,
            page=page,
        )

    def get_releases(self, per_page: int = 100, page: int = 1) -> APIResponse:
        """Get repository releases."""
        params = {"per_page": per_page, "page": page}
        return self.get(f"/repos/{self.OWNER}/{self.REPO}/releases", params=params)

    def get_events(self, per_page: int = 100, page: int = 1) -> APIResponse:
        """Get repository events (limited to last 90 days by GitHub)."""
        params = {"per_page": per_page, "page": page}
        return self.get(f"/repos/{self.OWNER}/{self.REPO}/events", params=params)

    def get_contributors(self, per_page: int = 100, page: int = 1) -> APIResponse:
        """Get repository contributors."""
        params = {"per_page": per_page, "page": page}
        return self.get(f"/repos/{self.OWNER}/{self.REPO}/contributors", params=params)


class NVDClient(BaseAPIClient):
    """
    NIST National Vulnerability Database (NVD) API client.

    Endpoints used:
    - /cves/2.0 - CVE records

    Rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds

    Note: The NVD API is free and doesn't require authentication,
    but an API key increases rate limits.
    """

    def __init__(self, api_key: str | None = None):
        super().__init__(
            base_url="https://services.nvd.nist.gov/rest/json",
            api_key=api_key,
            timeout=60,  # NVD can be slow
        )
        self._last_request_time = 0.0
        self._min_request_interval = 6.0 if not api_key else 0.6  # Rate limit buffer

    def _get_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _wait_for_rate_limit(self) -> None:
        """Enforce minimum interval between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            wait_time = self._min_request_interval - elapsed
            logger.debug(f"NVD rate limit: waiting {wait_time:.1f}s")
            time.sleep(wait_time)
        self._last_request_time = time.time()

    def search_cves(
        self,
        keyword_search: str | None = None,
        cve_id: str | None = None,
        cvss_v3_severity: str | None = None,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> APIResponse:
        """
        Search CVE database.

        Args:
            keyword_search: Search in CVE descriptions (e.g., 'openclaw')
            cve_id: Specific CVE ID (e.g., 'CVE-2026-25253')
            cvss_v3_severity: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'
            pub_start_date: ISO 8601 format (e.g., '2026-01-01T00:00:00.000')
            pub_end_date: ISO 8601 format
            results_per_page: Max 2000
            start_index: For pagination
        """
        params: dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }
        if keyword_search:
            params["keywordSearch"] = keyword_search
        if cve_id:
            params["cveId"] = cve_id
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date

        return self.get("/cves/2.0", params=params)

    def get_cve_by_id(self, cve_id: str) -> APIResponse:
        """Get a specific CVE by ID."""
        return self.search_cves(cve_id=cve_id)

    def get_openclaw_cves(self) -> APIResponse:
        """Search for CVEs mentioning OpenClaw or related terms."""
        return self.search_cves(keyword_search="openclaw OR moltbot OR clawdbot")


# Convenience function for Databricks notebooks
def create_clients(
    github_token: str | None = None,
    nvd_api_key: str | None = None,
) -> dict[str, BaseAPIClient]:
    """
    Create API clients with provided credentials.

    In Databricks, retrieve secrets like:
        github_token = dbutils.secrets.get(scope="openclaw", key="github_token")

    Returns:
        Dictionary of client instances
    """
    clients: dict[str, BaseAPIClient] = {
        "github": GitHubClient(api_key=github_token),
        "nvd": NVDClient(api_key=nvd_api_key),
    }
    return clients
