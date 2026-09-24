# Dashboard Queries

These SQL queries power the OpenClaw Security Dashboard in Databricks.

## Setup Instructions

1. In Databricks, go to **SQL** → **Dashboards** → **Create Dashboard**
2. Name it "OpenClaw Security Intelligence"
3. Add widgets using these queries:

| Widget | Query File | Visualization Type | Size |
|--------|------------|-------------------|------|
| Security Score | `01_security_score.sql` | Counter | 2x1 |
| Key Metrics | `02_key_metrics.sql` | Counter (multi) | 4x1 |
| Suspicious Packages | `03_suspicious_packages.sql` | Table | 4x3 |
| Risk Distribution | `04_risk_distribution.sql` | Pie Chart | 2x2 |
| CVE Severity | `05_cve_severity.sql` | Bar Chart | 2x2 |
| GitHub Activity | `06_github_activity.sql` | Counter | 2x1 |
| Top CVEs | `07_top_cves.sql` | Table | 4x2 |
| Issues by Label | `08_issues_by_label.sql` | Bar Chart | 2x2 |

## Query Descriptions

### 01_security_score.sql
Single metric showing overall security health (0-100 scale).

### 02_key_metrics.sql
Key performance indicators: stars, packages, suspicious count, CVEs.

### 03_suspicious_packages.sql
Table of flagged packages sorted by risk score.

### 04_risk_distribution.sql
Pie chart showing package distribution by risk level.

### 05_cve_severity.sql
Bar chart of CVE counts by severity (CRITICAL, HIGH, MEDIUM, LOW).

### 06_github_activity.sql
GitHub repository metrics (stars, forks, issues).

### 07_top_cves.sql
Table of highest severity CVEs with descriptions.

### 08_issues_by_label.sql
Issue breakdown by label category.

## Refresh Schedule

The dashboard uses data from Gold layer tables that are refreshed daily at 6 AM UTC via the `daily_refresh` workflow.

Set dashboard auto-refresh to **1 hour** for near-real-time updates after the daily job completes.
