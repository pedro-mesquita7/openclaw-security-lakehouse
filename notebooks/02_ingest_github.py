# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer: GitHub Ingestion
# MAGIC
# MAGIC This notebook fetches data from the GitHub API for the OpenClaw repository.
# MAGIC
# MAGIC **Data Collected:**
# MAGIC - Repository metadata (stars, forks, watchers)
# MAGIC - Issues and PRs
# MAGIC - Releases
# MAGIC - Contributors
# MAGIC
# MAGIC **Architecture:**
# MAGIC - Uses shared API clients from `src/utils/api_clients.py`
# MAGIC - Implements rate limiting and retry logic
# MAGIC - Stores raw JSON in Bronze layer for full fidelity

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

import sys
import json
from datetime import datetime, timezone
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, TimestampType

# Add src to path for shared module imports
# In DAB deployment, this is handled by wheel installation
sys.path.insert(0, "/Workspace/Repos/openclaw-security-lakehouse/src")

# Schema configuration
SCHEMA = "openclaw_security"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Load Shared API Client

# COMMAND ----------

from utils.api_clients import GitHubClient, create_clients

# Get GitHub token from secrets (optional, but recommended for higher rate limits)
GITHUB_TOKEN = None
try:
    GITHUB_TOKEN = dbutils.secrets.get(scope="openclaw", key="github_token")
    print("✓ GitHub token loaded from secrets")
except Exception:
    print("⚠ No GitHub token found - using unauthenticated access (60 requests/hour limit)")
    print("  To add a token: Create a secret scope named 'openclaw' with key 'github_token'")

# Initialize the shared GitHubClient
client = GitHubClient(api_key=GITHUB_TOKEN)
print(f"✓ GitHubClient initialized for {client.OWNER}/{client.REPO}")
print(f"  Rate limit handling: {'Authenticated (5000/hr)' if GITHUB_TOKEN else 'Unauthenticated (60/hr)'}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Bronze Table Schema
# MAGIC
# MAGIC All Bronze tables share a common schema for raw API data storage.

# COMMAND ----------

# Schema for raw Bronze tables
raw_schema = StructType([
    StructField("raw_data", StringType(), False),
    StructField("source", StringType(), False),
    StructField("fetched_at", TimestampType(), False),
    StructField("ingestion_date", StringType(), False),
    StructField("status_code", IntegerType(), True),
    StructField("record_count", IntegerType(), True),
])


def create_raw_record(data, source: str, status_code: int) -> dict:
    """Create a Bronze layer record from API response."""
    now = datetime.now(timezone.utc)
    record_count = len(data) if isinstance(data, list) else 1

    return {
        "raw_data": json.dumps(data),
        "source": source,
        "fetched_at": now,
        "ingestion_date": now.strftime("%Y-%m-%d"),
        "status_code": status_code,
        "record_count": record_count,
    }


def write_to_bronze(records: list, table_name: str) -> None:
    """Write records to a Bronze Delta table with partitioning."""
    df = spark.createDataFrame(records, schema=raw_schema)

    (df.write
        .format("delta")
        .mode("append")
        .partitionBy("ingestion_date")
        .option("mergeSchema", "true")
        .saveAsTable(f"{SCHEMA}.{table_name}"))

    print(f"✓ Wrote {len(records)} record(s) to {SCHEMA}.{table_name}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingest Repository Metadata

# COMMAND ----------

print(f"Fetching repository: {client.OWNER}/{client.REPO}")
try:
    response = client.get_repository()
    repo_data = response.data

    record = create_raw_record(repo_data, response.source, response.status_code)
    write_to_bronze([record], "github_repository_raw")

    # Display key metrics
    print(f"\n📊 Repository Stats:")
    print(f"   Stars: {repo_data.get('stargazers_count', 0):,}")
    print(f"   Forks: {repo_data.get('forks_count', 0):,}")
    print(f"   Open Issues: {repo_data.get('open_issues_count', 0):,}")
    print(f"   Watchers: {repo_data.get('subscribers_count', 0):,}")
    print(f"   Rate Limit: {client.rate_limit.remaining}/{client.rate_limit.limit} remaining")
except Exception as e:
    print(f"❌ Error fetching repository: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingest Issues
# MAGIC
# MAGIC Paginate through issues to capture security-related discussions.

# COMMAND ----------

print("Fetching issues...")
try:
    all_issues = []
    page = 1
    max_pages = 5  # Limit to avoid rate limit exhaustion

    while page <= max_pages:
        response = client.get_issues(page=page)
        issues = response.data

        if not issues:
            break

        all_issues.extend(issues)
        print(f"  Page {page}: {len(issues)} issues (Rate limit: {client.rate_limit.remaining} remaining)")
        page += 1

        if len(issues) < 100:
            break

    if all_issues:
        record = create_raw_record(all_issues, "github_api_issues", 200)
        write_to_bronze([record], "github_issues_raw")

        # Count by state
        open_count = sum(1 for i in all_issues if i.get("state") == "open")
        closed_count = len(all_issues) - open_count

        # Count security-related issues
        security_labels = {"security", "vulnerability", "cve", "exploit", "malicious"}
        security_issues = [
            issue for issue in all_issues
            if any(label.get("name", "").lower() in security_labels
                   for label in issue.get("labels", []))
        ]

        print(f"\n📊 Issues Summary:")
        print(f"   Total: {len(all_issues)} ({open_count} open, {closed_count} closed)")
        print(f"   Security-tagged: {len(security_issues)}")
except Exception as e:
    print(f"❌ Error fetching issues: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingest Releases

# COMMAND ----------

print("Fetching releases...")
try:
    response = client.get_releases()
    releases = response.data

    if releases:
        record = create_raw_record(releases, "github_api_releases", response.status_code)
        write_to_bronze([record], "github_releases_raw")

        print(f"\n📊 Releases: {len(releases)} total")
        if releases:
            print(f"   Latest: {releases[0].get('tag_name', 'N/A')}")
    else:
        print("   No releases found")
except Exception as e:
    print(f"❌ Error fetching releases: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Ingest Contributors

# COMMAND ----------

print("Fetching contributors...")
try:
    response = client.get_contributors()
    contributors = response.data

    if contributors:
        record = create_raw_record(contributors, "github_api_contributors", response.status_code)
        write_to_bronze([record], "github_contributors_raw")

        print(f"\n📊 Contributors: {len(contributors)} total")
        print("   Top contributors:")
        for c in contributors[:5]:
            print(f"     - {c.get('login')}: {c.get('contributions')} commits")
except Exception as e:
    print(f"❌ Error fetching contributors: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Data

# COMMAND ----------

print("\n" + "="*60)
print("INGESTION SUMMARY")
print("="*60)

tables = ["github_repository_raw", "github_issues_raw", "github_releases_raw", "github_contributors_raw"]

for table in tables:
    try:
        count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.{table}").collect()[0].cnt
        print(f"✓ {table}: {count} record(s)")
    except Exception:
        print(f"✗ {table}: not found or error")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Sample Data Preview

# COMMAND ----------

# Preview repository data
print("Repository data sample:")
df = spark.sql(f"SELECT * FROM {SCHEMA}.github_repository_raw ORDER BY fetched_at DESC LIMIT 1")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Run `03_ingest_cve` to fetch vulnerability data
# MAGIC 2. Run `04_ingest_packages` to fetch package registry data
# MAGIC 3. Run Silver transformation notebooks to clean and structure the data
