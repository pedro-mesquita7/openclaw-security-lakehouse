-- Dashboard Query: Key Metrics
-- Use as: Separate counter tiles for each metric

-- GitHub Stars
-- SELECT repo_stars as value FROM openclaw_security.daily_security_summary ORDER BY summary_date DESC LIMIT 1

-- Forks
-- SELECT repo_forks as value FROM openclaw_security.daily_security_summary ORDER BY summary_date DESC LIMIT 1

-- Open Issues
-- SELECT repo_open_issues as value FROM openclaw_security.daily_security_summary ORDER BY summary_date DESC LIMIT 1

-- All metrics in one query (for reference)
SELECT
    repo_stars as "GitHub Stars",
    repo_forks as "Forks",
    repo_open_issues as "Open Issues",
    total_packages as "Total Packages",
    suspicious_packages as "Suspicious Packages",
    total_cves as "CVEs Tracked",
    critical_cves as "Critical CVEs",
    open_security_issues as "Open Security Issues"
FROM openclaw_security.daily_security_summary
ORDER BY summary_date DESC
LIMIT 1
