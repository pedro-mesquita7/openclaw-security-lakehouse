# Data Dictionary

This document describes all tables in the OpenClaw Security Intelligence Lakehouse.

## Table Naming Convention

- **Bronze**: `{source}_raw` (e.g., `github_repository_raw`)
- **Silver**: `{entity}` or `{entity}_scd` (e.g., `packages`, `packages_scd`)
- **Gold**: `{metric}_summary` or `{entity}_scores` (e.g., `daily_security_summary`)

---

## Bronze Layer Tables

### `github_repository_raw`

Daily snapshots of OpenClaw repository metadata.

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON string of GitHub API response |
| source | STRING | Always `github_api_repository` |
| fetched_at | TIMESTAMP | When data was fetched (UTC) |
| ingestion_date | STRING | Partition key (YYYY-MM-DD) |
| status_code | INT | HTTP status code |
| record_count | INT | Always 1 for repository endpoint |

**Key fields in raw_data:**
- `stargazers_count`: Number of stars
- `forks_count`: Number of forks
- `open_issues_count`: Open issues + PRs
- `subscribers_count`: Watchers

---

### `github_issues_raw`

All issues and PRs from the repository.

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON array of issue objects |
| source | STRING | Always `github_api_issues` |
| fetched_at | TIMESTAMP | When data was fetched |
| ingestion_date | STRING | Partition key |
| status_code | INT | HTTP status code |
| record_count | INT | Number of issues in batch |

**Key fields per issue in raw_data:**
- `id`: Issue ID
- `number`: Issue number
- `title`: Issue title
- `state`: `open` or `closed`
- `labels[]`: Array of label objects
- `created_at`, `updated_at`, `closed_at`: Timestamps

---

### `github_releases_raw`

Repository releases/versions.

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON array of release objects |
| source | STRING | Always `github_api_releases` |
| fetched_at | TIMESTAMP | When data was fetched |
| ingestion_date | STRING | Partition key |
| status_code | INT | HTTP status code |
| record_count | INT | Number of releases |

**Key fields per release:**
- `id`: Release ID
- `tag_name`: Version tag (e.g., `v1.2.3`)
- `name`: Release name
- `published_at`: Release timestamp
- `prerelease`: Boolean

---

### `github_events_raw`

Repository activity events (last 90 days).

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON array of event objects |
| source | STRING | Always `github_api_events` |
| fetched_at | TIMESTAMP | When data was fetched |
| ingestion_date | STRING | Partition key |
| status_code | INT | HTTP status code |
| record_count | INT | Number of events |

**Key fields per event:**
- `id`: Event ID
- `type`: Event type (e.g., `PushEvent`, `IssuesEvent`)
- `actor`: User who triggered event
- `created_at`: Event timestamp

---

### `github_contributors_raw`

Repository contributors.

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON array of contributor objects |
| source | STRING | Always `github_api_contributors` |
| fetched_at | TIMESTAMP | When data was fetched |
| ingestion_date | STRING | Partition key |
| status_code | INT | HTTP status code |
| record_count | INT | Number of contributors |

---

### `cve_raw`

CVE vulnerability records from NVD.

| Column | Type | Description |
|--------|------|-------------|
| raw_data | STRING | JSON from NVD API |
| source | STRING | Source identifier (e.g., `nvd_api_cve_CVE-2026-25253`) |
| fetched_at | TIMESTAMP | When data was fetched |
| ingestion_date | STRING | Partition key |
| status_code | INT | HTTP status code |
| record_count | INT | Number of CVEs in response |

**Key fields in raw_data:**
- `vulnerabilities[]`: Array of CVE objects
- `cve.id`: CVE ID (e.g., `CVE-2026-25253`)
- `cve.descriptions[]`: Descriptions in multiple languages
- `cve.metrics.cvssMetricV31[]`: CVSS scores

---

## Gold Layer Tables

### `daily_security_summary`

Daily aggregated security metrics.

| Column | Type | Description |
|--------|------|-------------|
| summary_date | DATE | Primary key |
| repo_stars | INT | GitHub stars |
| repo_forks | INT | GitHub forks |
| open_issues | INT | Open issues/PRs |
| open_security_issues | INT | Security-labeled issues |
| total_packages | INT | Package count |
| suspicious_packages | INT | Flagged packages |
| new_packages_7d | INT | New packages in last 7 days |
| known_cves | INT | CVEs affecting OpenClaw |
| critical_cves | INT | CRITICAL severity CVEs |
| unpatched_cves | INT | CVEs without patch |
| security_score | INT | Computed score (0-100) |
| _computed_at | TIMESTAMP | When computed |

---

### `package_risk_scores`

Risk assessment per package.

| Column | Type | Description |
|--------|------|-------------|
| package_id | STRING | Primary key |
| name | STRING | Package name |
| risk_score | INT | Composite risk score (0-100) |
| risk_flags | ARRAY<STRING> | Active risk flags |
| is_suspicious | BOOLEAN | Flagged for review |
| download_zscore | DECIMAL(5,2) | Download velocity z-score |
| description_changed | BOOLEAN | Description edited recently |
| publisher_changed | BOOLEAN | Ownership transferred |
| days_since_creation | INT | Age in days |
| _scored_at | TIMESTAMP | When scored |

**Risk Flags:**
- `CRYPTO_KEYWORDS`: Contains crypto-related terms
- `SUSPICIOUS_DESCRIPTION`: Generic/short description
- `RAPID_DOWNLOADS`: Unusual download velocity
- `UNVERIFIED_PUBLISHER`: Not verified
- `RECENT_DESCRIPTION_CHANGE`: Description edited

---

### `vulnerability_timeline`

CVE lifecycle tracking.

| Column | Type | Description |
|--------|------|-------------|
| cve_id | STRING | Primary key |
| disclosed_date | DATE | Public disclosure |
| severity | STRING | CVSS severity |
| patch_released_date | DATE | When patch available (nullable) |
| days_to_patch | INT | Days from disclosure to patch |
| adoption_rate_7d | DECIMAL(5,2) | % users on patched version after 7d |
| adoption_rate_30d | DECIMAL(5,2) | % users on patched version after 30d |
| status | STRING | OPEN/PATCHED/MITIGATED |
| _updated_at | TIMESTAMP | Last update |

---

### `suspicious_packages`

Packages flagged for manual review.

| Column | Type | Description |
|--------|------|-------------|
| package_id | STRING | Primary key |
| name | STRING | Package name |
| publisher_id | STRING | Publisher |
| risk_score | INT | Risk score |
| risk_flags | ARRAY<STRING> | Why flagged |
| downloads | BIGINT | Download count |
| created_at | TIMESTAMP | When published |
| flagged_at | TIMESTAMP | When flagged |
| review_status | STRING | PENDING/REVIEWED/CLEARED/BLOCKED |
| reviewer_notes | STRING | Manual review notes |

---

## Data Lineage

```
GitHub API ──► github_*_raw ──► github_events ──┐
                                                │
NVD API ────► cve_raw ─────────► cve_details ──┼──► daily_security_summary
                                                │
Registry ───► packages_raw ────► packages ─────┼──► package_risk_scores
                               │               │
                               └► packages_scd ┘──► suspicious_packages
```
