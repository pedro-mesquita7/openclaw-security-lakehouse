# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer: CVE Database Ingestion
# MAGIC
# MAGIC This notebook fetches vulnerability data from the NIST National Vulnerability Database (NVD).
# MAGIC
# MAGIC **Data Collected:**
# MAGIC - Known CVEs related to AI agents and coding tools
# MAGIC - Recent high-severity vulnerabilities
# MAGIC - Search for specific CVE IDs
# MAGIC
# MAGIC **Architecture:**
# MAGIC - Uses shared API clients from `src/utils/api_clients.py`
# MAGIC - Implements rate limiting (5 req/30s without key)
# MAGIC - Stores raw JSON in Bronze layer for full fidelity

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

import sys
import json
from datetime import datetime, timezone, timedelta
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, TimestampType

# Add src to path for shared module imports
sys.path.insert(0, "/Workspace/Repos/openclaw-security-lakehouse/src")

# Schema configuration
SCHEMA = "openclaw_security"

# Keywords to search for
SEARCH_KEYWORDS = [
    "code assistant",
    "AI agent",
    "LLM",
    "vscode extension",
]

# Example known CVEs (these are real CVEs for context)
EXAMPLE_CVES = [
    "CVE-2024-3094",   # XZ Utils backdoor (major supply chain attack)
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
]

# COMMAND ----------

# MAGIC %md
# MAGIC ## Load Shared API Client

# COMMAND ----------

from utils.api_clients import NVDClient

# NVD API doesn't require authentication, but has rate limits
# Without API key: 5 requests per 30 seconds
# With API key: 50 requests per 30 seconds
NVD_API_KEY = None
try:
    NVD_API_KEY = dbutils.secrets.get(scope="openclaw", key="nvd_api_key")
    print("✓ NVD API key loaded from secrets")
except Exception:
    print("⚠ No NVD API key found - using lower rate limits (5 req/30s)")
    print("  Request an API key at https://nvd.nist.gov/developers/request-an-api-key")

# Initialize the shared NVDClient
client = NVDClient(api_key=NVD_API_KEY)
print(f"✓ NVDClient initialized")
print(f"  Rate limit: {'50 req/30s (authenticated)' if NVD_API_KEY else '5 req/30s (unauthenticated)'}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Bronze Table Schema

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

    # Count CVEs in response
    if isinstance(data, dict) and "vulnerabilities" in data:
        record_count = len(data["vulnerabilities"])
    elif isinstance(data, list):
        record_count = len(data)
    else:
        record_count = 1

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


def print_cve_summary(cve_data: dict) -> None:
    """Print summary of CVE data for logging."""
    if "vulnerabilities" not in cve_data or not cve_data["vulnerabilities"]:
        return

    for vuln in cve_data["vulnerabilities"][:3]:  # Show first 3
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Get English description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description")

        # Get CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = "N/A"
        severity = "N/A"
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", "N/A")

        print(f"\n   {cve_id}")
        print(f"   CVSS: {cvss_score} ({severity})")
        print(f"   {desc[:100]}...")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Fetch Example CVEs
# MAGIC
# MAGIC Let's fetch some real CVEs to demonstrate the pipeline.

# COMMAND ----------

print("Fetching example CVEs...")
records = []

for cve_id in EXAMPLE_CVES:
    print(f"\n📥 Fetching {cve_id}...")
    try:
        response = client.get_cve_by_id(cve_id)
        data = response.data
        record = create_raw_record(data, f"nvd_api_cve_{cve_id}", response.status_code)
        records.append(record)

        total = data.get("totalResults", 0)
        print(f"   Found: {total} result(s)")
        print_cve_summary(data)

    except Exception as e:
        print(f"   ❌ Error: {e}")

if records:
    write_to_bronze(records, "cve_raw")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Search Recent CVEs
# MAGIC
# MAGIC Search for recently published CVEs to provide context.

# COMMAND ----------

print("Searching for recent CVEs...")

# Get CVEs from the last 7 days
end_date = datetime.now(timezone.utc)
start_date = end_date - timedelta(days=7)

pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

try:
    response = client.search_cves(
        pub_start_date=pub_start,
        pub_end_date=pub_end,
        results_per_page=20
    )
    data = response.data

    total = data.get("totalResults", 0)
    print(f"\n📊 Recent CVEs (last 7 days): {total} total")

    if data.get("vulnerabilities"):
        record = create_raw_record(data, "nvd_api_recent", response.status_code)
        write_to_bronze([record], "cve_raw")

        # Show severity breakdown
        severities = {}
        for vuln in data.get("vulnerabilities", []):
            metrics = vuln.get("cve", {}).get("metrics", {})
            if "cvssMetricV31" in metrics:
                sev = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                severities[sev] = severities.get(sev, 0) + 1

        print("\n   Severity breakdown:")
        for sev, count in sorted(severities.items()):
            print(f"     {sev}: {count}")

except Exception as e:
    print(f"❌ Error searching recent CVEs: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Search Keyword-Based CVEs

# COMMAND ----------

print("Searching for security-related CVEs by keyword...")

for keyword in SEARCH_KEYWORDS[:2]:  # Limit to 2 to avoid rate limits
    print(f"\n📥 Searching: '{keyword}'")
    try:
        response = client.search_cves(keyword_search=keyword, results_per_page=10)
        data = response.data
        total = data.get("totalResults", 0)
        print(f"   Found: {total} CVE(s)")

        if total > 0:
            record = create_raw_record(data, f"nvd_api_search_{keyword.replace(' ', '_')}", response.status_code)
            write_to_bronze([record], "cve_raw")
            print_cve_summary(data)

    except Exception as e:
        print(f"   ❌ Error: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Data

# COMMAND ----------

print("\n" + "="*60)
print("CVE INGESTION SUMMARY")
print("="*60)

try:
    count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.cve_raw").collect()[0].cnt
    print(f"✓ cve_raw: {count} record(s)")

    # Show sources
    sources = spark.sql(f"""
        SELECT source, COUNT(*) as cnt, SUM(record_count) as total_cves
        FROM {SCHEMA}.cve_raw
        GROUP BY source
    """).collect()

    print("\n   By source:")
    for row in sources:
        print(f"     {row.source}: {row.cnt} record(s), {row.total_cves} CVE(s)")

except Exception as e:
    print(f"❌ cve_raw: error - {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Sample Data Preview

# COMMAND ----------

# Preview CVE data
print("CVE data sample:")
df = spark.sql(f"SELECT source, fetched_at, record_count FROM {SCHEMA}.cve_raw ORDER BY fetched_at DESC LIMIT 5")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Run `04_ingest_packages` to fetch package registry data
# MAGIC 2. Run Silver transformation notebooks
