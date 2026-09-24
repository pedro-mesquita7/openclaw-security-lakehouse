-- Dashboard Query: Suspicious Packages Table
-- Use as: Table visualization

SELECT
    name as "Package",
    risk_score as "Score",
    downloads as "Downloads",
    CONCAT_WS(', ', risk_flags) as "Risk_Flags"
FROM openclaw_security.suspicious_packages
ORDER BY risk_score DESC, downloads DESC
LIMIT 15
