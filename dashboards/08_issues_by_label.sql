-- Dashboard Query: GitHub Issues Overview
-- Use as: Counter or table

SELECT
    SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as "Open Issues",
    SUM(CASE WHEN state = 'closed' THEN 1 ELSE 0 END) as "Closed Issues",
    SUM(CASE WHEN is_pull_request THEN 1 ELSE 0 END) as "Pull Requests",
    SUM(CASE WHEN is_security_related THEN 1 ELSE 0 END) as "Security Related",
    COUNT(*) as "Total"
FROM openclaw_security.github_issues
