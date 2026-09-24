# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer: Package Transformations
# MAGIC
# MAGIC This notebook transforms raw package data into structured Silver tables with:
# MAGIC - **Risk flag analysis**: Multi-factor security risk detection
# MAGIC - **SCD Type 2**: Full change history tracking for audit/compliance
# MAGIC - **Data quality checks**: Using shared DQ framework
# MAGIC
# MAGIC **Output Tables:**
# MAGIC - `packages` - Current state of all packages with risk flags
# MAGIC - `packages_scd` - Historical changes (SCD Type 2) for tracking metadata changes

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

import sys
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, BooleanType,
    LongType, IntegerType, ArrayType, TimestampType
)
from pyspark.sql.window import Window
from datetime import datetime, timezone
from delta.tables import DeltaTable

# Add src to path for shared module imports
sys.path.insert(0, "/Workspace/Repos/openclaw-security-lakehouse/src")

SCHEMA = "openclaw_security"
print(f"Schema: {SCHEMA}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Load Shared Modules

# COMMAND ----------

from utils.data_quality import DataQualityChecker, detect_suspicious_package_patterns

# Initialize DQ checker (don't raise on failure for demo purposes)
dq = DataQualityChecker(spark, raise_on_failure=False)
print("✓ DataQualityChecker initialized")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read Bronze Data

# COMMAND ----------

bronze_df = spark.sql(f"""
    SELECT raw_data, fetched_at, ingestion_date
    FROM {SCHEMA}.packages_raw
    ORDER BY fetched_at DESC
    LIMIT 1
""")

print(f"Bronze records: {bronze_df.count()}")

# Data quality: Check we have data
dq.assert_row_count_range(bronze_df, min_rows=1, max_rows=100)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parse JSON Data

# COMMAND ----------

# Define the schema for package JSON
package_schema = ArrayType(StructType([
    StructField("id", StringType()),
    StructField("name", StringType()),
    StructField("description", StringType()),
    StructField("version", StringType()),
    StructField("publisher", StructType([
        StructField("id", StringType()),
        StructField("name", StringType()),
        StructField("verified", BooleanType()),
    ])),
    StructField("downloads", LongType()),
    StructField("stars", IntegerType()),
    StructField("created_at", StringType()),
    StructField("updated_at", StringType()),
    StructField("license", StringType()),
    StructField("repository", StringType()),
    StructField("keywords", ArrayType(StringType())),
    StructField("_synthetic", BooleanType()),
    StructField("_is_suspicious", BooleanType()),
]))

# Parse JSON
parsed_df = bronze_df.withColumn(
    "packages",
    F.from_json(F.col("raw_data"), package_schema)
).select(
    F.explode("packages").alias("pkg"),
    "fetched_at"
)

# Flatten the structure
packages_df = parsed_df.select(
    F.col("pkg.id").alias("package_id"),
    F.col("pkg.name").alias("name"),
    F.col("pkg.description").alias("description"),
    F.col("pkg.version").alias("version"),
    F.col("pkg.publisher.id").alias("publisher_id"),
    F.col("pkg.publisher.name").alias("publisher_name"),
    F.col("pkg.publisher.verified").alias("is_verified"),
    F.col("pkg.downloads").alias("downloads"),
    F.col("pkg.stars").alias("stars"),
    F.to_timestamp("pkg.created_at").alias("created_at"),
    F.to_timestamp("pkg.updated_at").alias("updated_at"),
    F.col("pkg.license").alias("license"),
    F.col("pkg.repository").alias("repository_url"),
    F.col("pkg.keywords").alias("keywords"),
    F.col("pkg._is_suspicious").alias("source_flagged_suspicious"),
    F.col("fetched_at").alias("_ingested_at"),
)

print(f"Parsed packages: {packages_df.count()}")

# Data quality: Check primary key uniqueness
dq.assert_unique(packages_df, ["package_id"])
dq.assert_not_null(packages_df, ["package_id", "name"])

# COMMAND ----------

# MAGIC %md
# MAGIC ## Add Risk Flags
# MAGIC
# MAGIC Multi-factor risk assessment detecting patterns commonly seen in malicious packages:
# MAGIC - `CRYPTO_KEYWORDS`: Crypto/wallet/seed keywords often indicate credential theft attempts
# MAGIC - `SHORT_DESCRIPTION`: Malicious packages often have minimal documentation
# MAGIC - `UNVERIFIED_HIGH_DOWNLOADS`: Suspicious popularity without verification
# MAGIC - `NEW_WITH_HIGH_DOWNLOADS`: Rapid adoption of new packages (potential artificial inflation)
# MAGIC - `SOURCE_FLAGGED`: Already flagged by upstream source

# COMMAND ----------

# Create individual flag columns first, then combine
packages_with_flags = packages_df.withColumn(
    "flag_crypto",
    F.when(
        F.lower(F.col("name")).rlike("crypto|wallet|bitcoin|ethereum|eth|seed|mnemonic|private") |
        F.lower(F.coalesce(F.col("description"), F.lit(""))).rlike("crypto|wallet|bitcoin|ethereum|seed|mnemonic|private"),
        F.lit("CRYPTO_KEYWORDS")
    )
).withColumn(
    "flag_short_desc",
    F.when(
        F.length(F.coalesce(F.col("description"), F.lit(""))) < 30,
        F.lit("SHORT_DESCRIPTION")
    )
).withColumn(
    "flag_unverified_popular",
    F.when(
        (F.col("is_verified") == False) & (F.col("downloads") > 3000),
        F.lit("UNVERIFIED_HIGH_DOWNLOADS")
    )
).withColumn(
    "flag_new_popular",
    F.when(
        (F.col("downloads") > 500) & (F.datediff(F.current_date(), F.col("created_at")) < 14),
        F.lit("NEW_WITH_HIGH_DOWNLOADS")
    )
).withColumn(
    "flag_source",
    F.when(F.col("source_flagged_suspicious") == True, F.lit("SOURCE_FLAGGED"))
)

# Combine flags into array (filter out nulls)
packages_with_flags = packages_with_flags.withColumn(
    "risk_flags",
    F.array_except(
        F.array(
            F.col("flag_crypto"),
            F.col("flag_short_desc"),
            F.col("flag_unverified_popular"),
            F.col("flag_new_popular"),
            F.col("flag_source")
        ),
        F.array(F.lit(None).cast(StringType()))
    )
)

# Calculate risk score and suspicious flag
packages_with_flags = packages_with_flags.withColumn(
    "risk_score",
    F.size(F.col("risk_flags"))
).withColumn(
    "is_suspicious",
    F.col("risk_score") > 0
)

# Show stats
total = packages_with_flags.count()
suspicious_count = packages_with_flags.filter(F.col("is_suspicious")).count()
print(f"\n📊 Package Risk Analysis:")
print(f"   Total packages: {total}")
print(f"   Suspicious packages: {suspicious_count} ({100*suspicious_count/total:.1f}%)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Preview Flagged Packages

# COMMAND ----------

print("🚨 Packages with risk flags:")
display(
    packages_with_flags
    .filter(F.col("is_suspicious"))
    .select("name", "description", "downloads", "is_verified", "risk_flags", "risk_score")
    .orderBy(F.desc("risk_score"), F.desc("downloads"))
    .limit(20)
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Write Silver `packages` Table (Current State)

# COMMAND ----------

# Select final columns for current state table
silver_packages = packages_with_flags.select(
    "package_id",
    "name",
    "description",
    "version",
    "publisher_id",
    "publisher_name",
    "is_verified",
    "downloads",
    "stars",
    "license",
    "repository_url",
    "keywords",
    "risk_flags",
    "risk_score",
    "is_suspicious",
    "created_at",
    "updated_at",
    "_ingested_at",
)

# Write to Silver table (overwrite for current state)
(silver_packages.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.packages"))

print(f"✓ Wrote {silver_packages.count()} packages to {SCHEMA}.packages")

# COMMAND ----------

# MAGIC %md
# MAGIC ## SCD Type 2: Track Historical Changes
# MAGIC
# MAGIC SCD Type 2 maintains full history of package metadata changes:
# MAGIC - **Business key**: `package_id`
# MAGIC - **Tracked attributes**: `description`, `publisher_id`, `is_verified`, `version`
# MAGIC - **Change detection**: MD5 hash of tracked attributes
# MAGIC
# MAGIC This enables:
# MAGIC - Audit trail for security investigations
# MAGIC - Detecting when packages change ownership (publisher_id)
# MAGIC - Tracking verification status changes
# MAGIC - Historical analysis of package evolution

# COMMAND ----------

# Prepare incoming data with SCD columns
incoming_df = packages_with_flags.select(
    "package_id",
    "name",
    "description",
    "version",
    "publisher_id",
    "publisher_name",
    "is_verified",
    "downloads",
    "risk_flags",
    "risk_score",
    # Create hash of attributes we want to track for changes
    F.md5(F.concat_ws("||",
        F.coalesce(F.col("description"), F.lit("")),
        F.coalesce(F.col("publisher_id"), F.lit("")),
        F.col("is_verified").cast(StringType()),
        F.coalesce(F.col("version"), F.lit(""))
    )).alias("record_hash"),
)

# Add SCD metadata columns for new/changed records
incoming_with_scd = incoming_df.withColumn(
    "valid_from", F.current_timestamp()
).withColumn(
    "valid_to", F.lit(None).cast(TimestampType())
).withColumn(
    "is_current", F.lit(True)
).withColumn(
    "_updated_at", F.current_timestamp()
)

scd_table_name = f"{SCHEMA}.packages_scd"

# COMMAND ----------

# MAGIC %md
# MAGIC ### SCD Type 2 MERGE Operation
# MAGIC
# MAGIC The merge handles three scenarios:
# MAGIC 1. **New packages**: Insert with `is_current=True`
# MAGIC 2. **Changed packages**: Close old record (`valid_to`, `is_current=False`), insert new
# MAGIC 3. **Unchanged packages**: Update `_updated_at` only (for freshness tracking)

# COMMAND ----------

# Check if SCD table exists
try:
    spark.sql(f"SELECT 1 FROM {scd_table_name} LIMIT 1")
    table_exists = True
    print(f"✓ Table {scd_table_name} exists, performing SCD Type 2 merge...")
except Exception:
    table_exists = False
    print(f"Table {scd_table_name} does not exist, creating with initial load...")

if not table_exists:
    # Initial load - create table with all records as current
    (incoming_with_scd.write
        .format("delta")
        .mode("overwrite")
        .saveAsTable(scd_table_name))

    new_count = incoming_with_scd.count()
    print(f"✓ Created {scd_table_name} with {new_count} initial records")
else:
    # Get the Delta table for merge
    scd_table = DeltaTable.forName(spark, scd_table_name)

    # Step 1: Find records that have changed (different hash)
    # Join incoming with current records to detect changes
    current_records = spark.sql(f"""
        SELECT package_id, record_hash
        FROM {scd_table_name}
        WHERE is_current = TRUE
    """)

    changes_df = incoming_df.alias("incoming").join(
        current_records.alias("current"),
        F.col("incoming.package_id") == F.col("current.package_id"),
        "left"
    ).select(
        F.col("incoming.package_id"),
        F.col("incoming.record_hash").alias("new_hash"),
        F.col("current.record_hash").alias("old_hash")
    ).withColumn(
        "change_type",
        F.when(F.col("old_hash").isNull(), "INSERT")
         .when(F.col("new_hash") != F.col("old_hash"), "UPDATE")
         .otherwise("NO_CHANGE")
    )

    # Count changes
    change_counts = changes_df.groupBy("change_type").count().collect()
    change_summary = {row["change_type"]: row["count"] for row in change_counts}

    print(f"\n📊 SCD Type 2 Change Detection:")
    print(f"   New packages: {change_summary.get('INSERT', 0)}")
    print(f"   Changed packages: {change_summary.get('UPDATE', 0)}")
    print(f"   Unchanged packages: {change_summary.get('NO_CHANGE', 0)}")

    # Step 2: Close out changed records (set valid_to and is_current=False)
    changed_ids = changes_df.filter(F.col("change_type") == "UPDATE").select("package_id")

    if changed_ids.count() > 0:
        # Use merge to close old records
        scd_table.alias("target").merge(
            changed_ids.alias("changes"),
            "target.package_id = changes.package_id AND target.is_current = TRUE"
        ).whenMatchedUpdate(set={
            "valid_to": F.current_timestamp(),
            "is_current": F.lit(False),
            "_updated_at": F.current_timestamp()
        }).execute()

        print(f"✓ Closed {changed_ids.count()} historical records")

    # Step 3: Insert new and changed records as current
    records_to_insert = incoming_with_scd.join(
        changes_df.filter(F.col("change_type").isin("INSERT", "UPDATE")).select("package_id"),
        "package_id"
    )

    if records_to_insert.count() > 0:
        (records_to_insert.write
            .format("delta")
            .mode("append")
            .saveAsTable(scd_table_name))

        print(f"✓ Inserted {records_to_insert.count()} new/changed records")

    # Step 4: Update unchanged records timestamp (for freshness)
    unchanged_ids = changes_df.filter(F.col("change_type") == "NO_CHANGE").select("package_id")

    if unchanged_ids.count() > 0:
        scd_table.alias("target").merge(
            unchanged_ids.alias("unchanged"),
            "target.package_id = unchanged.package_id AND target.is_current = TRUE"
        ).whenMatchedUpdate(set={
            "_updated_at": F.current_timestamp()
        }).execute()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify SCD Type 2 Results

# COMMAND ----------

# Show SCD statistics
scd_stats = spark.sql(f"""
    SELECT
        COUNT(*) as total_records,
        SUM(CASE WHEN is_current THEN 1 ELSE 0 END) as current_records,
        SUM(CASE WHEN NOT is_current THEN 1 ELSE 0 END) as historical_records,
        COUNT(DISTINCT package_id) as unique_packages
    FROM {scd_table_name}
""").collect()[0]

print(f"\n📊 SCD Type 2 Table Statistics:")
print(f"   Total records: {scd_stats.total_records}")
print(f"   Current records: {scd_stats.current_records}")
print(f"   Historical records: {scd_stats.historical_records}")
print(f"   Unique packages: {scd_stats.unique_packages}")

# Show packages with history (changed over time)
packages_with_history = spark.sql(f"""
    SELECT package_id, name, COUNT(*) as version_count
    FROM {scd_table_name}
    GROUP BY package_id, name
    HAVING COUNT(*) > 1
    ORDER BY version_count DESC
    LIMIT 10
""")

if packages_with_history.count() > 0:
    print("\n📜 Packages with historical changes:")
    display(packages_with_history)
else:
    print("\n📜 No packages have changed yet (first run or no changes detected)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Data Quality Summary

# COMMAND ----------

# Print DQ check summary
dq_summary = dq.get_summary()
print("\n" + "="*60)
print("DATA QUALITY SUMMARY")
print("="*60)
print(f"Total checks: {dq_summary['total_checks']}")
print(f"Passed: {dq_summary['passed']}")
print(f"Failed: {dq_summary['failed']}")
print(f"Pass rate: {dq_summary['pass_rate']*100:.1f}%")

for result in dq_summary['results']:
    status = "✓" if result['passed'] else "✗"
    print(f"\n{status} {result['check_name']}: {result['message']}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Final Summary

# COMMAND ----------

print("\n" + "="*60)
print("SILVER PACKAGES SUMMARY")
print("="*60)

# packages table stats
stats = spark.sql(f"""
    SELECT
        COUNT(*) as total,
        SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious,
        SUM(CASE WHEN is_verified THEN 1 ELSE 0 END) as verified,
        AVG(risk_score) as avg_risk_score,
        MAX(risk_score) as max_risk_score
    FROM {SCHEMA}.packages
""").collect()[0]

print(f"\n✓ {SCHEMA}.packages (Current State)")
print(f"   Total: {stats.total}")
print(f"   Suspicious: {stats.suspicious} ({100*stats.suspicious/stats.total:.1f}%)")
print(f"   Verified publishers: {stats.verified}")
print(f"   Avg risk score: {stats.avg_risk_score:.2f}")
print(f"   Max risk score: {stats.max_risk_score}")

print(f"\n✓ {SCHEMA}.packages_scd (Historical)")
print(f"   Records: {scd_stats.total_records}")
print(f"   With history: {scd_stats.historical_records}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Run `06_silver_cve` to transform CVE data
# MAGIC 2. Run `07_silver_github` to transform GitHub data
# MAGIC 3. Run `08_gold_aggregations` to create analytics tables
# MAGIC
# MAGIC ### Querying Historical Data
# MAGIC
# MAGIC ```sql
# MAGIC -- Get current state of a package
# MAGIC SELECT * FROM openclaw_security.packages_scd
# MAGIC WHERE package_id = 'pkg_001' AND is_current = TRUE;
# MAGIC
# MAGIC -- Get full history of a package
# MAGIC SELECT * FROM openclaw_security.packages_scd
# MAGIC WHERE package_id = 'pkg_001'
# MAGIC ORDER BY valid_from;
# MAGIC
# MAGIC -- Point-in-time query (what was state on a specific date?)
# MAGIC SELECT * FROM openclaw_security.packages_scd
# MAGIC WHERE package_id = 'pkg_001'
# MAGIC   AND valid_from <= '2024-06-15'
# MAGIC   AND (valid_to > '2024-06-15' OR valid_to IS NULL);
# MAGIC ```
