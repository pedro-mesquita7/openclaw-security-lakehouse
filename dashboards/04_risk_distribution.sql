-- Dashboard Query: Package Risk Distribution
-- Use as: Bar chart (risk_level on X, packages on Y)

SELECT
    CONCAT('Risk Score ', risk_score) as risk_level,
    COUNT(*) as packages
FROM openclaw_security.package_risk_scores
GROUP BY risk_score
ORDER BY risk_score
