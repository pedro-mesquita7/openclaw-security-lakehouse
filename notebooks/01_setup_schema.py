# Databricks notebook source
# MAGIC %md
# MAGIC # Setup: Create Schema and Tables
# MAGIC
# MAGIC Run this notebook first to set up the database schema.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration
# MAGIC
# MAGIC Adjust these values based on your Databricks edition:
# MAGIC - **Community Edition**: Use `hive_metastore` as catalog
# MAGIC - **Free Trial / Paid**: Use `main` as catalog (Unity Catalog)

# COMMAND ----------

# For Community Edition, use hive_metastore
# For Unity Catalog, use main
CATALOG = "hive_metastore"  # Change to "main" if you have Unity Catalog
SCHEMA = "openclaw_security"

print(f"Setting up: {CATALOG}.{SCHEMA}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Create Schema

# COMMAND ----------

# Create the schema
spark.sql(f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
print(f"Schema '{SCHEMA}' created or already exists")

# COMMAND ----------

# List existing tables (should be empty initially)
tables = spark.sql(f"SHOW TABLES IN {SCHEMA}").collect()
print(f"Existing tables in {SCHEMA}:")
for table in tables:
    print(f"  - {table.tableName}")

if not tables:
    print("  (none - ready for ingestion)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Setup

# COMMAND ----------

# Verify we can write to the schema
test_df = spark.createDataFrame([("test",)], ["value"])
test_df.write.mode("overwrite").saveAsTable(f"{SCHEMA}._setup_test")
spark.sql(f"DROP TABLE {SCHEMA}._setup_test")
print("✓ Write permissions verified")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC Schema is ready! Now run the ingestion notebooks:
# MAGIC 1. `02_ingest_github` - GitHub repository data
# MAGIC 2. `03_ingest_cve` - CVE vulnerability data
# MAGIC 3. `04_ingest_packages` - Package registry data
