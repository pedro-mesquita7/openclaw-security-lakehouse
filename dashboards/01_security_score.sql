-- Dashboard Query: Security Health Score
-- Use as: Counter visualization
-- Shows the pre-computed security score from the daily summary

SELECT
    CONCAT(CAST(security_score AS STRING), '/100') as "Security Score",
    CASE
        WHEN security_score >= 80 THEN 'Good'
        WHEN security_score >= 60 THEN 'Moderate'
        WHEN security_score >= 40 THEN 'Elevated Risk'
        ELSE 'Critical'
    END as "Status"
FROM openclaw_security.daily_security_summary
ORDER BY summary_date DESC
LIMIT 1
