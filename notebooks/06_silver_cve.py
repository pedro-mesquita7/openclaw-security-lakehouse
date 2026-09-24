# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer: CVE Transformations
# MAGIC
# MAGIC This notebook transforms raw CVE data into structured records.
# MAGIC
# MAGIC **Output Tables:**
# MAGIC - `cve_details` - Structured CVE records with CVSS scores

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window
from datetime import datetime, timezone

SCHEMA = "openclaw_security"
print(f"Schema: {SCHEMA}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Read Bronze Data

# COMMAND ----------

# Read all CVE records from Bronze
bronze_df = spark.sql(f"""
    SELECT raw_data, source, fetched_at
    FROM {SCHEMA}.cve_raw
    ORDER BY fetched_at DESC
""")

print(f"Bronze CVE records: {bronze_df.count()}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parse CVE JSON

# COMMAND ----------

# Define schema for NVD API response
vulnerability_schema = StructType([
    StructField("cve", StructType([
        StructField("id", StringType()),
        StructField("sourceIdentifier", StringType()),
        StructField("published", StringType()),
        StructField("lastModified", StringType()),
        StructField("vulnStatus", StringType()),
        StructField("descriptions", ArrayType(StructType([
            StructField("lang", StringType()),
            StructField("value", StringType()),
        ]))),
        StructField("metrics", StructType([
            StructField("cvssMetricV31", ArrayType(StructType([
                StructField("cvssData", StructType([
                    StructField("version", StringType()),
                    StructField("vectorString", StringType()),
                    StructField("baseScore", DoubleType()),
                    StructField("baseSeverity", StringType()),
                ])),
            ]))),
            StructField("cvssMetricV2", ArrayType(StructType([
                StructField("cvssData", StructType([
                    StructField("version", StringType()),
                    StructField("vectorString", StringType()),
                    StructField("baseScore", DoubleType()),
                ])),
            ]))),
        ])),
        StructField("references", ArrayType(StructType([
            StructField("url", StringType()),
            StructField("source", StringType()),
        ]))),
    ])),
])

nvd_response_schema = StructType([
    StructField("resultsPerPage", IntegerType()),
    StructField("startIndex", IntegerType()),
    StructField("totalResults", IntegerType()),
    StructField("vulnerabilities", ArrayType(vulnerability_schema)),
])

# Parse JSON
parsed_df = bronze_df.withColumn(
    "nvd_response",
    F.from_json(F.col("raw_data"), nvd_response_schema)
).filter(
    F.col("nvd_response.vulnerabilities").isNotNull()
).select(
    F.explode("nvd_response.vulnerabilities").alias("vuln"),
    "source",
    "fetched_at"
)

print(f"Parsed vulnerabilities: {parsed_df.count()}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Extract CVE Details

# COMMAND ----------

# Extract and flatten CVE data
cve_df = parsed_df.select(
    # Core fields
    F.col("vuln.cve.id").alias("cve_id"),
    F.col("vuln.cve.vulnStatus").alias("status"),

    # Get English description
    F.expr("""
        filter(vuln.cve.descriptions, x -> x.lang = 'en')[0].value
    """).alias("description"),

    # Timestamps
    F.to_timestamp("vuln.cve.published").alias("published_date"),
    F.to_timestamp("vuln.cve.lastModified").alias("last_modified"),

    # CVSS v3.1 scores (preferred)
    F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseScore"].alias("cvss_v3_score"),
    F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["baseSeverity"].alias("cvss_v3_severity"),
    F.col("vuln.cve.metrics.cvssMetricV31")[0]["cvssData"]["vectorString"].alias("cvss_v3_vector"),

    # CVSS v2 as fallback
    F.col("vuln.cve.metrics.cvssMetricV2")[0]["cvssData"]["baseScore"].alias("cvss_v2_score"),

    # References (extract URLs)
    F.expr("""
        transform(vuln.cve.references, x -> x.url)
    """).alias("reference_urls"),

    # Source info
    F.col("source").alias("data_source"),
    F.col("fetched_at").alias("_ingested_at"),
)

# Add derived fields
cve_enriched = cve_df.withColumn(
    # Use v3 score, fall back to v2
    "cvss_score",
    F.coalesce(F.col("cvss_v3_score"), F.col("cvss_v2_score"))
).withColumn(
    # Derive severity if not present
    "severity",
    F.coalesce(
        F.col("cvss_v3_severity"),
        F.when(F.col("cvss_score") >= 9.0, "CRITICAL")
         .when(F.col("cvss_score") >= 7.0, "HIGH")
         .when(F.col("cvss_score") >= 4.0, "MEDIUM")
         .when(F.col("cvss_score") > 0, "LOW")
         .otherwise("UNKNOWN")
    )
).withColumn(
    # Check if related to our project
    "is_relevant",
    F.lower(F.col("description")).contains("agent") |
    F.lower(F.col("description")).contains("llm") |
    F.lower(F.col("description")).contains("ai") |
    F.lower(F.col("description")).contains("code")
).withColumn(
    # Days since published
    "days_since_published",
    F.datediff(F.current_date(), F.col("published_date"))
)

# Deduplicate (keep most recent fetch per CVE)
window = Window.partitionBy("cve_id").orderBy(F.desc("_ingested_at"))
cve_deduped = cve_enriched.withColumn(
    "row_num", F.row_number().over(window)
).filter(
    F.col("row_num") == 1
).drop("row_num")

print(f"Unique CVEs: {cve_deduped.count()}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Write Silver Table

# COMMAND ----------

# Select final columns
silver_cve = cve_deduped.select(
    "cve_id",
    "description",
    "status",
    "published_date",
    "last_modified",
    "cvss_score",
    "severity",
    "cvss_v3_vector",
    "reference_urls",
    "is_relevant",
    "days_since_published",
    "_ingested_at",
)

# Write to Silver table
(silver_cve.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.cve_details"))

print(f"✓ Wrote {silver_cve.count()} CVEs to {SCHEMA}.cve_details")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Silver Table

# COMMAND ----------

print("\n" + "="*60)
print("SILVER CVE SUMMARY")
print("="*60)

# Overall stats
total = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.cve_details").collect()[0].cnt
print(f"\n✓ {SCHEMA}.cve_details: {total} CVEs")

# Severity breakdown
print("\n📊 Severity Breakdown:")
display(spark.sql(f"""
    SELECT
        severity,
        COUNT(*) as count,
        ROUND(AVG(cvss_score), 1) as avg_score
    FROM {SCHEMA}.cve_details
    GROUP BY severity
    ORDER BY avg_score DESC
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Preview CVE Data

# COMMAND ----------

# Show high-severity CVEs
print("🔴 High/Critical Severity CVEs:")
display(spark.sql(f"""
    SELECT
        cve_id,
        cvss_score,
        severity,
        days_since_published,
        LEFT(description, 100) as description_preview
    FROM {SCHEMA}.cve_details
    WHERE severity IN ('HIGH', 'CRITICAL')
    ORDER BY cvss_score DESC
    LIMIT 10
"""))

# COMMAND ----------

# Show relevant CVEs (AI/code related)
print("\n🎯 Relevant CVEs (AI/code/agent related):")
display(spark.sql(f"""
    SELECT
        cve_id,
        cvss_score,
        severity,
        LEFT(description, 150) as description_preview
    FROM {SCHEMA}.cve_details
    WHERE is_relevant = true
    ORDER BY cvss_score DESC
    LIMIT 10
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Run `07_silver_github` to transform GitHub data
# MAGIC 2. Build Gold layer aggregations
