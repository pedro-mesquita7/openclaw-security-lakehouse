# Databricks notebook source
# MAGIC %md
# MAGIC # Scheduled Daily Refresh
# MAGIC
# MAGIC This notebook refreshes all data in the lakehouse.
# MAGIC Schedule this to run daily via Databricks Workflows.
# MAGIC
# MAGIC **What it does:**
# MAGIC 1. Ingests fresh data from GitHub API
# MAGIC 2. Ingests CVE data from NVD
# MAGIC 3. Rebuilds Silver tables with risk flags
# MAGIC 4. Rebuilds Gold aggregations
# MAGIC 5. Updates security score

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

SCHEMA = "openclaw_security"

# Get secrets
try:
    GITHUB_TOKEN = dbutils.secrets.get(scope="openclaw", key="github_token")
    print("✓ GitHub token loaded")
except:
    GITHUB_TOKEN = None
    print("⚠ No GitHub token - using unauthenticated access")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Ingest GitHub Data

# COMMAND ----------

import requests
import json
from datetime import datetime, timezone
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, TimestampType

raw_schema = StructType([
    StructField("raw_data", StringType(), False),
    StructField("source", StringType(), False),
    StructField("fetched_at", TimestampType(), False),
    StructField("ingestion_date", StringType(), False),
    StructField("status_code", IntegerType(), True),
    StructField("record_count", IntegerType(), True),
])

def fetch_github(endpoint, token=None):
    """Fetch data from GitHub API."""
    url = f"https://api.github.com{endpoint}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json(), response.status_code

def write_bronze(data, source, status_code, table_name):
    """Write to Bronze table."""
    now = datetime.now(timezone.utc)
    record = {
        "raw_data": json.dumps(data),
        "source": source,
        "fetched_at": now,
        "ingestion_date": now.strftime("%Y-%m-%d"),
        "status_code": status_code,
        "record_count": len(data) if isinstance(data, list) else 1,
    }
    df = spark.createDataFrame([record], schema=raw_schema)
    df.write.format("delta").mode("append").partitionBy("ingestion_date").saveAsTable(f"{SCHEMA}.{table_name}")

# Fetch GitHub data
print("📥 Fetching GitHub data...")
try:
    repo_data, status = fetch_github("/repos/openclaw/openclaw", GITHUB_TOKEN)
    write_bronze(repo_data, "github_api_repository", status, "github_repository_raw")
    print(f"   ⭐ Stars: {repo_data.get('stargazers_count', 0):,}")

    issues_data, status = fetch_github("/repos/openclaw/openclaw/issues?state=all&per_page=100", GITHUB_TOKEN)
    write_bronze(issues_data, "github_api_issues", status, "github_issues_raw")
    print(f"   📋 Issues: {len(issues_data)}")
except Exception as e:
    print(f"   ❌ GitHub error: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Ingest CVE Data

# COMMAND ----------

import time

def fetch_nvd(endpoint, params=None):
    """Fetch data from NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json{endpoint}"
    response = requests.get(url, params=params, timeout=60)
    response.raise_for_status()
    return response.json(), response.status_code

print("📥 Fetching CVE data...")
try:
    # Fetch recent CVEs
    from datetime import timedelta
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=30)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100
    }

    cve_data, status = fetch_nvd("/cves/2.0", params)
    write_bronze(cve_data, "nvd_api_recent", status, "cve_raw")
    print(f"   🔒 CVEs fetched: {cve_data.get('totalResults', 0)}")
except Exception as e:
    print(f"   ❌ CVE error: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Rebuild Silver Packages Table

# COMMAND ----------

print("🔄 Rebuilding Silver packages...")

spark.sql(f"""
CREATE OR REPLACE TABLE {SCHEMA}.packages AS
WITH latest_snapshot AS (
    SELECT raw_data, fetched_at
    FROM {SCHEMA}.packages_raw
    ORDER BY fetched_at DESC
    LIMIT 1
),
parsed_packages AS (
    SELECT
        explode(from_json(raw_data, 'ARRAY<STRUCT<
            id: STRING,
            name: STRING,
            description: STRING,
            version: STRING,
            publisher: STRUCT<id: STRING, name: STRING, verified: BOOLEAN>,
            downloads: BIGINT,
            stars: INT,
            created_at: STRING,
            updated_at: STRING,
            license: STRING,
            repository: STRING,
            keywords: ARRAY<STRING>,
            _synthetic: BOOLEAN,
            _is_suspicious: BOOLEAN
        >>')) as pkg,
        fetched_at
    FROM latest_snapshot
),
flattened AS (
    SELECT
        pkg.id as package_id,
        pkg.name as name,
        pkg.description as description,
        pkg.version as version,
        pkg.publisher.id as publisher_id,
        pkg.publisher.name as publisher_name,
        pkg.publisher.verified as is_verified,
        pkg.downloads as downloads,
        pkg.stars as stars,
        to_timestamp(pkg.created_at) as created_at,
        to_timestamp(pkg.updated_at) as updated_at,
        pkg.license as license,
        pkg.repository as repository_url,
        pkg.keywords as keywords,
        pkg._is_suspicious as source_flagged,
        fetched_at as _ingested_at
    FROM parsed_packages
),
with_flags AS (
    SELECT
        *,
        ARRAY_COMPACT(ARRAY(
            CASE WHEN LOWER(name) RLIKE 'crypto|wallet|bitcoin|ethereum|seed|mnemonic|private'
                 OR LOWER(COALESCE(description,'')) RLIKE 'crypto|wallet|bitcoin|ethereum|seed|mnemonic|private'
                 THEN 'CRYPTO_KEYWORDS' END,
            CASE WHEN LENGTH(COALESCE(description,'')) < 30
                 THEN 'SHORT_DESCRIPTION' END,
            CASE WHEN is_verified = false AND downloads > 3000
                 THEN 'UNVERIFIED_HIGH_DOWNLOADS' END,
            CASE WHEN source_flagged = true
                 THEN 'SOURCE_FLAGGED' END
        )) as risk_flags
    FROM flattened
)
SELECT
    package_id, name, description, version, publisher_id, publisher_name, is_verified,
    downloads, stars, license, repository_url, keywords, risk_flags,
    SIZE(risk_flags) as risk_score,
    SIZE(risk_flags) > 0 as is_suspicious,
    created_at, updated_at, _ingested_at
FROM with_flags
""")

count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.packages").collect()[0].cnt
suspicious = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.packages WHERE is_suspicious").collect()[0].cnt
print(f"   ✓ Packages: {count} total, {suspicious} suspicious")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Rebuild Silver CVE Table

# COMMAND ----------

print("🔄 Rebuilding Silver CVE details...")

spark.sql(f"""
CREATE OR REPLACE TABLE {SCHEMA}.cve_details AS
WITH parsed AS (
    SELECT
        explode(from_json(raw_data, 'STRUCT<vulnerabilities: ARRAY<STRUCT<cve: STRUCT<
            id: STRING,
            descriptions: ARRAY<STRUCT<lang: STRING, value: STRING>>,
            published: STRING,
            lastModified: STRING,
            vulnStatus: STRING,
            metrics: STRUCT<
                cvssMetricV31: ARRAY<STRUCT<cvssData: STRUCT<baseScore: DOUBLE, baseSeverity: STRING, vectorString: STRING>>>
            >
        >>>>').vulnerabilities) as vuln,
        fetched_at
    FROM {SCHEMA}.cve_raw
    WHERE raw_data LIKE '%vulnerabilities%'
)
SELECT DISTINCT
    vuln.cve.id as cve_id,
    filter(vuln.cve.descriptions, x -> x.lang = 'en')[0].value as description,
    vuln.cve.vulnStatus as status,
    to_timestamp(vuln.cve.published) as published_date,
    to_timestamp(vuln.cve.lastModified) as last_modified,
    vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore as cvss_score,
    vuln.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity as severity,
    vuln.cve.metrics.cvssMetricV31[0].cvssData.vectorString as cvss_v3_vector,
    LOWER(filter(vuln.cve.descriptions, x -> x.lang = 'en')[0].value) LIKE '%agent%'
        OR LOWER(filter(vuln.cve.descriptions, x -> x.lang = 'en')[0].value) LIKE '%llm%' as is_relevant,
    fetched_at as _ingested_at
FROM parsed
WHERE vuln.cve.id IS NOT NULL
""")

cve_count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.cve_details").collect()[0].cnt
print(f"   ✓ CVEs: {cve_count}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Rebuild Silver GitHub Tables

# COMMAND ----------

print("🔄 Rebuilding Silver GitHub metrics...")

spark.sql(f"""
CREATE OR REPLACE TABLE {SCHEMA}.github_repo_metrics AS
SELECT
    get_json_object(raw_data, '$.full_name') as repo_name,
    CAST(get_json_object(raw_data, '$.stargazers_count') AS INT) as stars,
    CAST(get_json_object(raw_data, '$.forks_count') AS INT) as forks,
    CAST(get_json_object(raw_data, '$.open_issues_count') AS INT) as open_issues,
    CAST(get_json_object(raw_data, '$.subscribers_count') AS INT) as watchers,
    CAST(get_json_object(raw_data, '$.size') AS INT) as repo_size_kb,
    get_json_object(raw_data, '$.language') as primary_language,
    fetched_at as snapshot_at,
    ingestion_date as snapshot_date
FROM {SCHEMA}.github_repository_raw
""")

print("   ✓ GitHub repo metrics updated")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Rebuild Gold Tables

# COMMAND ----------

print("🔄 Rebuilding Gold tables...")

# Package risk scores
spark.sql(f"""
CREATE OR REPLACE TABLE {SCHEMA}.package_risk_scores AS
SELECT
    package_id, name, description, publisher_name, is_verified, downloads, stars,
    risk_flags, risk_score, is_suspicious, created_at, updated_at,
    DATEDIFF(current_date(), created_at) as days_since_creation,
    CASE WHEN DATEDIFF(current_date(), created_at) > 0
         THEN downloads / DATEDIFF(current_date(), created_at) ELSE downloads END as downloads_per_day,
    false as has_history_changes,
    current_timestamp() as scored_at
FROM {SCHEMA}.packages
""")

# Suspicious packages
spark.sql(f"""
CREATE OR REPLACE TABLE {SCHEMA}.suspicious_packages AS
SELECT
    package_id, name, description, publisher_name, is_verified, downloads, risk_score, risk_flags,
    DATEDIFF(current_date(), created_at) as days_since_creation,
    CASE WHEN DATEDIFF(current_date(), created_at) > 0
         THEN downloads / DATEDIFF(current_date(), created_at) ELSE downloads END as downloads_per_day,
    created_at, 'PENDING' as review_status, CAST(NULL AS STRING) as reviewer_notes,
    current_timestamp() as flagged_at
FROM {SCHEMA}.packages
WHERE is_suspicious = true
ORDER BY risk_score DESC, downloads DESC
""")

# Daily security summary - Use MERGE to handle duplicates for same day
spark.sql(f"""
MERGE INTO {SCHEMA}.daily_security_summary AS target
USING (
    SELECT
        CAST(current_date() AS DATE) as summary_date,
        r.stars as repo_stars, r.forks as repo_forks, r.open_issues as repo_open_issues,
        CAST(i.total_issues AS BIGINT) as total_issues,
        CAST(i.open_issues AS BIGINT) as open_issues,
        CAST(i.security_issues AS BIGINT) as security_issues,
        CAST(i.open_security_issues AS BIGINT) as open_security_issues,
        CAST(p.total_packages AS BIGINT) as total_packages,
        CAST(p.suspicious_packages AS BIGINT) as suspicious_packages,
        CAST(p.new_packages_7d AS BIGINT) as new_packages_7d,
        CAST(p.avg_risk_score AS DOUBLE) as avg_risk_score,
        CAST(c.total_cves AS BIGINT) as total_cves,
        CAST(c.critical_cves AS BIGINT) as critical_cves,
        CAST(c.high_cves AS BIGINT) as high_cves,
        CAST(c.relevant_cves AS BIGINT) as relevant_cves,
        CAST(c.max_cvss_score AS DOUBLE) as max_cvss_score,
        CAST(GREATEST(0, 100 - (c.critical_cves * 3) - (c.high_cves * 1.5) - (p.suspicious_packages * 0.3) - i.open_security_issues) AS INT) as security_score,
        current_timestamp() as computed_at
    FROM
        (SELECT stars, forks, open_issues FROM {SCHEMA}.github_repo_metrics ORDER BY snapshot_at DESC LIMIT 1) r,
        (SELECT COUNT(*) as total_issues, SUM(CASE WHEN state='open' THEN 1 ELSE 0 END) as open_issues,
                SUM(CASE WHEN is_security_related THEN 1 ELSE 0 END) as security_issues,
                SUM(CASE WHEN is_security_related AND state='open' THEN 1 ELSE 0 END) as open_security_issues
         FROM {SCHEMA}.github_issues) i,
        (SELECT COUNT(*) as total_packages, SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_packages,
            SUM(CASE WHEN created_at >= date_sub(current_date(), 7) THEN 1 ELSE 0 END) as new_packages_7d,
            AVG(risk_score) as avg_risk_score FROM {SCHEMA}.packages) p,
        (SELECT COUNT(*) as total_cves, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_cves,
                SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high_cves,
                SUM(CASE WHEN is_relevant THEN 1 ELSE 0 END) as relevant_cves,
                MAX(cvss_score) as max_cvss_score FROM {SCHEMA}.cve_details) c
) AS source
ON target.summary_date = source.summary_date
WHEN MATCHED THEN UPDATE SET *
WHEN NOT MATCHED THEN INSERT *
""")

print("   ✓ Gold tables updated")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary

# COMMAND ----------

print("\n" + "="*60)
print("✅ DAILY REFRESH COMPLETE")
print("="*60)

summary = spark.sql(f"""
    SELECT security_score, repo_stars, suspicious_packages, critical_cves, computed_at
    FROM {SCHEMA}.daily_security_summary
    ORDER BY summary_date DESC LIMIT 1
""").collect()[0]

print(f"""
📊 Security Score: {summary.security_score}/100
⭐ GitHub Stars: {summary.repo_stars:,}
🚨 Suspicious Packages: {summary.suspicious_packages}
🔴 Critical CVEs: {summary.critical_cves}
🕐 Updated: {summary.computed_at}
""")
