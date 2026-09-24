# Databricks notebook source
# MAGIC %md
# MAGIC # Gold Layer: Security Analytics
# MAGIC
# MAGIC This notebook creates business-ready aggregation tables for the security dashboard.
# MAGIC
# MAGIC **Output Tables:**
# MAGIC - `daily_security_summary` - Daily security health metrics
# MAGIC - `package_risk_scores` - Package risk assessment
# MAGIC - `suspicious_packages` - Flagged packages for review

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
# MAGIC ## 1. Daily Security Summary
# MAGIC
# MAGIC Aggregates all security metrics into a single daily snapshot.

# COMMAND ----------

# Get latest GitHub repo metrics
repo_metrics = spark.sql(f"""
    SELECT *
    FROM {SCHEMA}.github_repo_metrics
    ORDER BY snapshot_at DESC
    LIMIT 1
""").collect()[0]

# Get GitHub issues stats
issues_stats = spark.sql(f"""
    SELECT
        COUNT(*) as total_issues,
        SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_issues,
        SUM(CASE WHEN is_security_related THEN 1 ELSE 0 END) as security_issues,
        SUM(CASE WHEN is_security_related AND state = 'open' THEN 1 ELSE 0 END) as open_security_issues
    FROM {SCHEMA}.github_issues
""").collect()[0]

# Get package stats
package_stats = spark.sql(f"""
    SELECT
        COUNT(*) as total_packages,
        SUM(CASE WHEN is_suspicious THEN 1 ELSE 0 END) as suspicious_packages,
        SUM(CASE WHEN created_at >= date_sub(current_date(), 7) THEN 1 ELSE 0 END) as new_packages_7d,
        AVG(risk_score) as avg_risk_score
    FROM {SCHEMA}.packages
""").collect()[0]

# Get CVE stats
cve_stats = spark.sql(f"""
    SELECT
        COUNT(*) as total_cves,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_cves,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_cves,
        SUM(CASE WHEN is_relevant THEN 1 ELSE 0 END) as relevant_cves,
        MAX(cvss_score) as max_cvss_score
    FROM {SCHEMA}.cve_details
""").collect()[0]

# Calculate security health score (0-100, higher is better)
#
# Scoring philosophy: A mature, actively-maintained project will naturally have
# some CVEs and issues. The score reflects overall security posture, not perfection.
#
# Deductions (scaled for large projects):
# - Critical CVEs: -2 points each (capped at -20)
# - High CVEs: -0.5 points each (capped at -15)
# - Suspicious packages: -1 point each (capped at -10)
# - Open security issues: -0.5 points each (capped at -5)

base_score = 100
score = base_score

# Apply deductions with caps to prevent excessive penalties
critical_penalty = min(20, (cve_stats.critical_cves or 0) * 2)
high_penalty = min(15, (cve_stats.high_cves or 0) * 0.5)
suspicious_penalty = min(10, (package_stats.suspicious_packages or 0) * 1)
issues_penalty = min(5, (issues_stats.open_security_issues or 0) * 0.5)

score -= critical_penalty
score -= high_penalty
score -= suspicious_penalty
score -= issues_penalty

security_score = max(0, min(100, int(score)))  # Clamp between 0-100

# Create summary record using explicit schema to avoid type conflicts
summary_schema = StructType([
    StructField("summary_date", DateType(), False),
    StructField("repo_stars", IntegerType(), True),
    StructField("repo_forks", IntegerType(), True),
    StructField("repo_open_issues", IntegerType(), True),
    StructField("total_issues", LongType(), True),
    StructField("open_issues", LongType(), True),
    StructField("security_issues", LongType(), True),
    StructField("open_security_issues", LongType(), True),
    StructField("total_packages", LongType(), True),
    StructField("suspicious_packages", LongType(), True),
    StructField("new_packages_7d", LongType(), True),
    StructField("avg_risk_score", DoubleType(), True),
    StructField("total_cves", LongType(), True),
    StructField("critical_cves", LongType(), True),
    StructField("high_cves", LongType(), True),
    StructField("relevant_cves", LongType(), True),
    StructField("max_cvss_score", DoubleType(), True),
    StructField("security_score", IntegerType(), True),
    StructField("computed_at", TimestampType(), True),
])

from datetime import date
summary_data = [(
    date.today(),  # summary_date as proper date
    int(repo_metrics.stars),
    int(repo_metrics.forks),
    int(repo_metrics.open_issues),
    int(issues_stats.total_issues),
    int(issues_stats.open_issues),
    int(issues_stats.security_issues),
    int(issues_stats.open_security_issues),
    int(package_stats.total_packages),
    int(package_stats.suspicious_packages),
    int(package_stats.new_packages_7d or 0),
    float(package_stats.avg_risk_score or 0),
    int(cve_stats.total_cves),
    int(cve_stats.critical_cves or 0),
    int(cve_stats.high_cves or 0),
    int(cve_stats.relevant_cves or 0),
    float(cve_stats.max_cvss_score or 0),
    int(security_score),
    datetime.now(timezone.utc),
)]

summary_df = spark.createDataFrame(summary_data, schema=summary_schema)

# Use MERGE to handle same-day updates (upsert pattern)
# First, check if table exists and create if not
table_name = f"{SCHEMA}.daily_security_summary"
try:
    spark.sql(f"SELECT 1 FROM {table_name} LIMIT 1")
    table_exists = True
except:
    table_exists = False

if not table_exists:
    # Create table fresh
    (summary_df.write
        .format("delta")
        .mode("overwrite")
        .saveAsTable(table_name))
    print(f"✓ Created {table_name}")
else:
    # Use SQL MERGE for upsert (handles same-day refreshes)
    summary_df.createOrReplaceTempView("new_summary")
    spark.sql(f"""
        MERGE INTO {table_name} AS target
        USING new_summary AS source
        ON target.summary_date = source.summary_date
        WHEN MATCHED THEN UPDATE SET *
        WHEN NOT MATCHED THEN INSERT *
    """)
    print(f"✓ Updated {table_name}")

print(f"\n📊 Security Score: {security_score}/100")

# COMMAND ----------

# Display the summary
display(spark.sql(f"SELECT * FROM {SCHEMA}.daily_security_summary ORDER BY summary_date DESC LIMIT 5"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Package Risk Scores
# MAGIC
# MAGIC Detailed risk assessment for each package.

# COMMAND ----------

package_risk_df = spark.sql(f"""
    SELECT
        p.package_id,
        p.name,
        p.description,
        p.publisher_name,
        p.is_verified,
        p.downloads,
        p.stars,
        p.risk_flags,
        p.risk_score,
        p.is_suspicious,
        p.created_at,
        p.updated_at,

        -- Calculate days since creation
        DATEDIFF(current_date(), p.created_at) as days_since_creation,

        -- Download velocity (downloads per day)
        CASE
            WHEN DATEDIFF(current_date(), p.created_at) > 0
            THEN p.downloads / DATEDIFF(current_date(), p.created_at)
            ELSE p.downloads
        END as downloads_per_day,

        -- Check for SCD changes (description/publisher changed)
        CASE
            WHEN scd_count.version_count > 1 THEN true
            ELSE false
        END as has_history_changes,

        current_timestamp() as scored_at

    FROM {SCHEMA}.packages p
    LEFT JOIN (
        SELECT package_id, COUNT(*) as version_count
        FROM {SCHEMA}.packages_scd
        GROUP BY package_id
    ) scd_count ON p.package_id = scd_count.package_id
""")

# Write to Gold table
(package_risk_df.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.package_risk_scores"))

print(f"✓ Created package_risk_scores with {package_risk_df.count()} packages")

# COMMAND ----------

# Show highest risk packages
print("🚨 Top 10 Highest Risk Packages:")
display(spark.sql(f"""
    SELECT
        name,
        risk_score,
        risk_flags,
        downloads,
        downloads_per_day,
        is_verified,
        days_since_creation
    FROM {SCHEMA}.package_risk_scores
    WHERE risk_score > 0
    ORDER BY risk_score DESC, downloads DESC
    LIMIT 10
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Suspicious Packages (For Review)
# MAGIC
# MAGIC Packages flagged for manual security review.

# COMMAND ----------

suspicious_df = spark.sql(f"""
    SELECT
        package_id,
        name,
        description,
        publisher_name,
        is_verified,
        downloads,
        risk_score,
        risk_flags,
        days_since_creation,
        downloads_per_day,
        created_at,
        'PENDING' as review_status,
        CAST(NULL AS STRING) as reviewer_notes,
        current_timestamp() as flagged_at
    FROM {SCHEMA}.package_risk_scores
    WHERE is_suspicious = true
    ORDER BY risk_score DESC, downloads DESC
""")

# Write to Gold table
(suspicious_df.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.suspicious_packages"))

suspicious_count = suspicious_df.count()
print(f"✓ Created suspicious_packages with {suspicious_count} packages for review")

# COMMAND ----------

# Display suspicious packages
print("🔍 Packages Requiring Security Review:")
display(spark.sql(f"""
    SELECT
        name,
        description,
        risk_score,
        risk_flags,
        downloads,
        is_verified,
        days_since_creation
    FROM {SCHEMA}.suspicious_packages
    ORDER BY risk_score DESC
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. CVE Summary by Severity

# COMMAND ----------

cve_summary_df = spark.sql(f"""
    SELECT
        severity,
        COUNT(*) as cve_count,
        ROUND(AVG(cvss_score), 1) as avg_cvss,
        MAX(cvss_score) as max_cvss,
        SUM(CASE WHEN is_relevant THEN 1 ELSE 0 END) as relevant_count,
        MIN(published_date) as earliest,
        MAX(published_date) as latest
    FROM {SCHEMA}.cve_details
    GROUP BY severity
    ORDER BY avg_cvss DESC
""")

print("📊 CVE Summary by Severity:")
display(cve_summary_df)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Verify All Gold Tables

# COMMAND ----------

print("\n" + "="*60)
print("GOLD LAYER SUMMARY")
print("="*60)

gold_tables = [
    "daily_security_summary",
    "package_risk_scores",
    "suspicious_packages"
]

for table in gold_tables:
    try:
        count = spark.sql(f"SELECT COUNT(*) as cnt FROM {SCHEMA}.{table}").collect()[0].cnt
        print(f"✓ {table}: {count} records")
    except Exception as e:
        print(f"✗ {table}: error - {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Security Dashboard Query Examples
# MAGIC
# MAGIC Use these queries in Databricks SQL to build your dashboard.

# COMMAND ----------

# MAGIC %md
# MAGIC ### Query 1: Security Health Score Over Time
# MAGIC ```sql
# MAGIC SELECT
# MAGIC     summary_date,
# MAGIC     security_score,
# MAGIC     suspicious_packages,
# MAGIC     critical_cves,
# MAGIC     open_security_issues
# MAGIC FROM openclaw_security.daily_security_summary
# MAGIC ORDER BY summary_date
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ### Query 2: Risk Distribution
# MAGIC ```sql
# MAGIC SELECT
# MAGIC     risk_score,
# MAGIC     COUNT(*) as package_count
# MAGIC FROM openclaw_security.package_risk_scores
# MAGIC GROUP BY risk_score
# MAGIC ORDER BY risk_score
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ### Query 3: Top Threats
# MAGIC ```sql
# MAGIC SELECT
# MAGIC     name,
# MAGIC     risk_flags,
# MAGIC     downloads,
# MAGIC     risk_score
# MAGIC FROM openclaw_security.suspicious_packages
# MAGIC ORDER BY risk_score DESC
# MAGIC LIMIT 20
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## ✅ Gold Layer Complete!
# MAGIC
# MAGIC You now have a complete medallion architecture:
# MAGIC
# MAGIC | Layer | Tables |
# MAGIC |-------|--------|
# MAGIC | **Bronze** | github_*_raw, cve_raw, packages_raw |
# MAGIC | **Silver** | packages, packages_scd, cve_details, github_* |
# MAGIC | **Gold** | daily_security_summary, package_risk_scores, suspicious_packages |
# MAGIC
# MAGIC ### Next Steps:
# MAGIC 1. Create a Databricks SQL Dashboard using the Gold tables
# MAGIC 2. Schedule the notebooks to run daily
# MAGIC 3. Add alerting for high-risk packages
