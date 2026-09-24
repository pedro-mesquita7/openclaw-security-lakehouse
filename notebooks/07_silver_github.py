# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer: GitHub Transformations
# MAGIC
# MAGIC This notebook transforms raw GitHub data into structured records.
# MAGIC
# MAGIC **Output Tables:**
# MAGIC - `github_repo_metrics` - Repository statistics over time
# MAGIC - `github_issues` - Structured issue/PR records
# MAGIC - `github_releases` - Release information

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
# MAGIC ## Transform Repository Metrics

# COMMAND ----------

# Read repository snapshots
repo_bronze = spark.sql(f"""
    SELECT raw_data, fetched_at, ingestion_date
    FROM {SCHEMA}.github_repository_raw
    ORDER BY fetched_at
""")

print(f"Repository snapshots: {repo_bronze.count()}")

# Define schema for repository JSON
repo_schema = StructType([
    StructField("id", LongType()),
    StructField("name", StringType()),
    StructField("full_name", StringType()),
    StructField("description", StringType()),
    StructField("stargazers_count", IntegerType()),
    StructField("forks_count", IntegerType()),
    StructField("open_issues_count", IntegerType()),
    StructField("subscribers_count", IntegerType()),
    StructField("watchers_count", IntegerType()),
    StructField("size", IntegerType()),
    StructField("language", StringType()),
    StructField("created_at", StringType()),
    StructField("updated_at", StringType()),
    StructField("pushed_at", StringType()),
])

# Parse and flatten
repo_df = repo_bronze.withColumn(
    "repo",
    F.from_json(F.col("raw_data"), repo_schema)
).select(
    F.col("repo.full_name").alias("repo_name"),
    F.col("repo.stargazers_count").alias("stars"),
    F.col("repo.forks_count").alias("forks"),
    F.col("repo.open_issues_count").alias("open_issues"),
    F.col("repo.subscribers_count").alias("watchers"),
    F.col("repo.size").alias("repo_size_kb"),
    F.col("repo.language").alias("primary_language"),
    F.to_timestamp("repo.created_at").alias("repo_created_at"),
    F.to_timestamp("repo.pushed_at").alias("last_push_at"),
    F.col("fetched_at").alias("snapshot_at"),
    F.col("ingestion_date").alias("snapshot_date"),
)

# Calculate deltas from previous snapshot
window = Window.orderBy("snapshot_at")
repo_with_deltas = repo_df.withColumn(
    "prev_stars", F.lag("stars", 1).over(window)
).withColumn(
    "stars_delta", F.col("stars") - F.coalesce(F.col("prev_stars"), F.col("stars"))
).withColumn(
    "prev_forks", F.lag("forks", 1).over(window)
).withColumn(
    "forks_delta", F.col("forks") - F.coalesce(F.col("prev_forks"), F.col("forks"))
).drop("prev_stars", "prev_forks")

# Write to Silver
(repo_with_deltas.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.github_repo_metrics"))

print(f"✓ Wrote {repo_with_deltas.count()} snapshots to {SCHEMA}.github_repo_metrics")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Transform Issues

# COMMAND ----------

# Read issues from Bronze
issues_bronze = spark.sql(f"""
    SELECT raw_data, fetched_at
    FROM {SCHEMA}.github_issues_raw
    ORDER BY fetched_at DESC
    LIMIT 1
""")

# Define schema for issues array
issue_schema = ArrayType(StructType([
    StructField("id", LongType()),
    StructField("number", IntegerType()),
    StructField("title", StringType()),
    StructField("state", StringType()),
    StructField("created_at", StringType()),
    StructField("updated_at", StringType()),
    StructField("closed_at", StringType()),
    StructField("body", StringType()),
    StructField("user", StructType([
        StructField("login", StringType()),
        StructField("id", LongType()),
    ])),
    StructField("labels", ArrayType(StructType([
        StructField("name", StringType()),
        StructField("color", StringType()),
    ]))),
    StructField("pull_request", StructType([
        StructField("url", StringType()),
    ])),
    StructField("comments", IntegerType()),
]))

# Parse
parsed_issues = issues_bronze.withColumn(
    "issues",
    F.from_json(F.col("raw_data"), issue_schema)
).select(
    F.explode("issues").alias("issue"),
    "fetched_at"
)

# Flatten and enrich
issues_df = parsed_issues.select(
    F.col("issue.id").alias("issue_id"),
    F.col("issue.number").alias("issue_number"),
    F.col("issue.title").alias("title"),
    F.col("issue.state").alias("state"),
    F.col("issue.body").alias("body"),
    F.col("issue.user.login").alias("author"),
    F.col("issue.comments").alias("comment_count"),
    F.to_timestamp("issue.created_at").alias("created_at"),
    F.to_timestamp("issue.updated_at").alias("updated_at"),
    F.to_timestamp("issue.closed_at").alias("closed_at"),

    # Extract label names
    F.expr("transform(issue.labels, x -> x.name)").alias("labels"),

    # Is this a PR?
    F.col("issue.pull_request.url").isNotNull().alias("is_pull_request"),

    F.col("fetched_at").alias("_ingested_at"),
).withColumn(
    # Check for security-related labels
    "is_security_related",
    F.arrays_overlap(
        F.col("labels"),
        F.array(
            F.lit("security"),
            F.lit("vulnerability"),
            F.lit("cve"),
            F.lit("bug"),
            F.lit("critical")
        )
    )
).withColumn(
    # Days to close (if closed)
    "days_to_close",
    F.when(
        F.col("closed_at").isNotNull(),
        F.datediff(F.col("closed_at"), F.col("created_at"))
    )
).withColumn(
    # Days open (if still open)
    "days_open",
    F.when(
        F.col("state") == "open",
        F.datediff(F.current_date(), F.col("created_at"))
    )
)

# Write to Silver
(issues_df.write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable(f"{SCHEMA}.github_issues"))

print(f"✓ Wrote {issues_df.count()} issues to {SCHEMA}.github_issues")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Transform Releases

# COMMAND ----------

# Check if releases table exists
try:
    releases_bronze = spark.sql(f"""
        SELECT raw_data, fetched_at
        FROM {SCHEMA}.github_releases_raw
        ORDER BY fetched_at DESC
        LIMIT 1
    """)

    # Define schema for releases
    release_schema = ArrayType(StructType([
        StructField("id", LongType()),
        StructField("tag_name", StringType()),
        StructField("name", StringType()),
        StructField("body", StringType()),
        StructField("draft", BooleanType()),
        StructField("prerelease", BooleanType()),
        StructField("created_at", StringType()),
        StructField("published_at", StringType()),
        StructField("author", StructType([
            StructField("login", StringType()),
        ])),
    ]))

    # Parse
    parsed_releases = releases_bronze.withColumn(
        "releases",
        F.from_json(F.col("raw_data"), release_schema)
    ).select(
        F.explode("releases").alias("release"),
        "fetched_at"
    )

    # Flatten
    releases_df = parsed_releases.select(
        F.col("release.id").alias("release_id"),
        F.col("release.tag_name").alias("tag"),
        F.col("release.name").alias("name"),
        F.col("release.body").alias("release_notes"),
        F.col("release.draft").alias("is_draft"),
        F.col("release.prerelease").alias("is_prerelease"),
        F.col("release.author.login").alias("author"),
        F.to_timestamp("release.created_at").alias("created_at"),
        F.to_timestamp("release.published_at").alias("published_at"),
        F.col("fetched_at").alias("_ingested_at"),
    ).withColumn(
        # Check if security-related release
        "is_security_release",
        F.lower(F.col("release_notes")).contains("security") |
        F.lower(F.col("release_notes")).contains("cve") |
        F.lower(F.col("release_notes")).contains("vulnerability")
    )

    # Write to Silver
    (releases_df.write
        .format("delta")
        .mode("overwrite")
        .option("overwriteSchema", "true")
        .saveAsTable(f"{SCHEMA}.github_releases"))

    print(f"✓ Wrote {releases_df.count()} releases to {SCHEMA}.github_releases")

except Exception as e:
    print(f"⚠ Releases table not available: {e}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Silver Tables

# COMMAND ----------

print("\n" + "="*60)
print("SILVER GITHUB SUMMARY")
print("="*60)

# Repo metrics
print(f"\n✓ {SCHEMA}.github_repo_metrics")
display(spark.sql(f"""
    SELECT
        repo_name,
        stars,
        forks,
        open_issues,
        snapshot_date
    FROM {SCHEMA}.github_repo_metrics
    ORDER BY snapshot_at DESC
    LIMIT 5
"""))

# COMMAND ----------

# Issues summary
print(f"\n✓ {SCHEMA}.github_issues")
display(spark.sql(f"""
    SELECT
        state,
        is_pull_request,
        COUNT(*) as count,
        SUM(CASE WHEN is_security_related THEN 1 ELSE 0 END) as security_related
    FROM {SCHEMA}.github_issues
    GROUP BY state, is_pull_request
    ORDER BY state, is_pull_request
"""))

# COMMAND ----------

# Security-related issues
print("\n🔒 Security-related issues:")
display(spark.sql(f"""
    SELECT
        issue_number,
        title,
        state,
        labels,
        days_open
    FROM {SCHEMA}.github_issues
    WHERE is_security_related = true
    ORDER BY created_at DESC
    LIMIT 10
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## All Silver Tables Complete!
# MAGIC
# MAGIC You now have:
# MAGIC - `packages` - Current package state with risk flags
# MAGIC - `packages_scd` - SCD Type 2 history
# MAGIC - `cve_details` - Structured vulnerability data
# MAGIC - `github_repo_metrics` - Repository stats over time
# MAGIC - `github_issues` - Issue/PR records
# MAGIC - `github_releases` - Release information
# MAGIC
# MAGIC ## Next Steps
# MAGIC
# MAGIC Build Gold layer aggregations:
# MAGIC - `daily_security_summary`
# MAGIC - `package_risk_scores`
# MAGIC - Dashboard queries
