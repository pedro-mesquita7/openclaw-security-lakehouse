-- Dashboard Query: GitHub Repository Stats
-- Use as: Counter tiles

SELECT
    stars as "Stars",
    forks as "Forks",
    open_issues as "Open Issues",
    watchers as "Watchers",
    snapshot_date as "Last Updated"
FROM openclaw_security.github_repo_metrics
ORDER BY snapshot_at DESC
LIMIT 1
