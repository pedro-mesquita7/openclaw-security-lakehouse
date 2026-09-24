-- Dashboard Query: CVE Severity Distribution
-- Use as: Pie chart or donut chart

SELECT
    severity,
    COUNT(*) as count
FROM openclaw_security.cve_details
WHERE severity IS NOT NULL
GROUP BY severity
ORDER BY count DESC
