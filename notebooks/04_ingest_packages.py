# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer: Package Registry Ingestion
# MAGIC
# MAGIC This notebook generates sample package data to demonstrate the pipeline.
# MAGIC
# MAGIC **Note:** Since the OpenClaw package registry API isn't publicly documented yet,
# MAGIC we generate realistic sample data that simulates:
# MAGIC - Normal packages
# MAGIC - Suspicious/potentially malicious packages
# MAGIC - Various publisher types
# MAGIC
# MAGIC This allows us to build and test the full pipeline including anomaly detection.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

import json
import random
import hashlib
from datetime import datetime, timezone, timedelta
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, TimestampType

# Schema configuration
SCHEMA = "openclaw_security"

# Number of sample packages to generate
NUM_PACKAGES = 200

print(f"Schema: {SCHEMA}")
print(f"Generating {NUM_PACKAGES} sample packages")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Package Generator

# COMMAND ----------

def generate_sample_packages(count: int = 100) -> list:
    """
    Generate realistic sample package data.

    Creates a mix of:
    - Normal, legitimate-looking packages (90%)
    - Suspicious packages with red flags (10%)
    """

    # Legitimate patterns
    prefixes = ["claw-", "agent-", "tool-", "util-", "ai-", "llm-", "auto-", "smart-", "open-", "data-"]
    suffixes = ["-client", "-sdk", "-helper", "-utils", "-core", "-pro", "-lite", ""]
    keywords = ["formatter", "parser", "validator", "generator", "converter", "analyzer",
                "monitor", "logger", "cache", "queue", "auth", "config", "http", "json"]

    # Suspicious patterns (for testing anomaly detection)
    suspicious_names = ["crypto-helper", "wallet-util", "bitcoin-agent", "eth-tool",
                        "seed-manager", "private-key-util", "mnemonic-helper", "token-grabber"]
    suspicious_descriptions = [
        "A helpful tool for managing your crypto assets",
        "Securely handle your wallet private keys",
        "Easy bitcoin integration for your agent",
        "Manage your seed phrases efficiently",
    ]

    packages = []
    base_date = datetime.now(timezone.utc) - timedelta(days=90)

    for i in range(count):
        # 10% chance of suspicious package
        is_suspicious = random.random() < 0.10

        if is_suspicious:
            name = random.choice(suspicious_names) + f"-{random.randint(1, 99)}"
            description = random.choice(suspicious_descriptions)
            downloads = random.randint(100, 5000)  # Inflated downloads
            days_old = random.randint(1, 7)  # Very recent
            verified = False
        else:
            name = f"{random.choice(prefixes)}{random.choice(keywords)}{random.choice(suffixes)}"
            description = f"A {random.choice(['useful', 'powerful', 'simple', 'efficient', 'lightweight'])} {random.choice(keywords)} for AI agent workflows"
            downloads = random.randint(10, 50000)
            days_old = random.randint(7, 90)
            verified = random.random() > 0.3  # 70% verified

        created_date = base_date + timedelta(days=random.randint(0, 90 - days_old))
        updated_date = created_date + timedelta(days=random.randint(0, min(days_old, 30)))

        # Generate consistent IDs
        package_id = hashlib.md5(f"{name}-{i}".encode()).hexdigest()[:16]
        publisher_id = hashlib.md5(f"publisher-{i % 50}".encode()).hexdigest()[:12]

        package = {
            "id": package_id,
            "name": name,
            "description": description,
            "version": f"{random.randint(0, 3)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
            "publisher": {
                "id": publisher_id,
                "name": f"dev-{publisher_id[:8]}",
                "verified": verified,
            },
            "downloads": downloads,
            "stars": random.randint(0, downloads // 10) if downloads > 100 else 0,
            "created_at": created_date.isoformat(),
            "updated_at": updated_date.isoformat(),
            "license": random.choice(["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0", None]),
            "repository": f"https://github.com/{publisher_id}/{name}" if random.random() > 0.2 else None,
            "keywords": random.sample(keywords, k=random.randint(2, 5)),
            "_synthetic": True,  # Flag indicating sample data
            "_is_suspicious": is_suspicious,  # For validation
        }

        packages.append(package)

    return packages

# COMMAND ----------

# MAGIC %md
# MAGIC ## Generate Sample Data

# COMMAND ----------

print(f"Generating {NUM_PACKAGES} sample packages...")
packages = generate_sample_packages(NUM_PACKAGES)

# Statistics
suspicious_count = sum(1 for p in packages if p.get("_is_suspicious"))
verified_count = sum(1 for p in packages if p.get("publisher", {}).get("verified"))
total_downloads = sum(p.get("downloads", 0) for p in packages)

print(f"\n📊 Package Statistics:")
print(f"   Total packages: {len(packages)}")
print(f"   Verified publishers: {verified_count} ({100*verified_count/len(packages):.1f}%)")
print(f"   Suspicious packages: {suspicious_count} ({100*suspicious_count/len(packages):.1f}%)")
print(f"   Total downloads: {total_downloads:,}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Write to Bronze Layer

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

now = datetime.now(timezone.utc)

record = {
    "raw_data": json.dumps(packages),
    "source": "sample_registry",
    "fetched_at": now,
    "ingestion_date": now.strftime("%Y-%m-%d"),
    "status_code": 200,
    "record_count": len(packages),
}

df = spark.createDataFrame([record], schema=raw_schema)

(df.write
    .format("delta")
    .mode("append")
    .partitionBy("ingestion_date")
    .option("mergeSchema", "true")
    .saveAsTable(f"{SCHEMA}.packages_raw"))

print(f"✓ Wrote {len(packages)} packages to {SCHEMA}.packages_raw")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Preview Suspicious Packages

# COMMAND ----------

print("\n🚨 Sample Suspicious Packages (for anomaly detection testing):")
print("-" * 60)

for p in packages:
    if p.get("_is_suspicious"):
        print(f"\n   📦 {p['name']}")
        print(f"      Description: {p['description'][:60]}...")
        print(f"      Downloads: {p['downloads']:,}")
        print(f"      Created: {p['created_at'][:10]}")
        print(f"      Verified: {p['publisher']['verified']}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Data

# COMMAND ----------

print("\n" + "="*60)
print("PACKAGE INGESTION SUMMARY")
print("="*60)

try:
    count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.packages_raw").collect()[0].cnt
    print(f"✓ packages_raw: {count} record(s)")

    # Get total packages across all snapshots
    total = spark.sql(f"SELECT SUM(record_count) as total FROM {SCHEMA}.packages_raw").collect()[0].total
    print(f"   Total packages ingested: {total}")

except Exception as e:
    print(f"❌ packages_raw: error - {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Sample Data Preview

# COMMAND ----------

# Preview the raw data
print("Package data sample:")
df = spark.sql(f"SELECT source, fetched_at, record_count FROM {SCHEMA}.packages_raw ORDER BY fetched_at DESC LIMIT 5")
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC All Bronze data is now loaded! Run the Silver transformation notebooks:
# MAGIC 1. `05_silver_packages` - Transform package data with SCD Type 2
# MAGIC 2. `06_silver_cve` - Structure CVE records
# MAGIC 3. `07_silver_github` - Process GitHub data
