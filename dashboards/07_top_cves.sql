-- Dashboard Query: Top CVEs by Severity
-- Use as: Table visualization

SELECT
    cve_id as "CVE",
    cvss_score as "CVSS",
    severity as "Severity",
    LEFT(description, 80) as "Description"
FROM openclaw_security.cve_details
WHERE cvss_score IS NOT NULL
ORDER BY cvss_score DESC
LIMIT 10
