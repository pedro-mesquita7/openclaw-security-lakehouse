# Architecture Documentation

This document explains the design decisions and architecture of the OpenClaw Security Intelligence Lakehouse.

## Overview

The project follows a **medallion architecture** (Bronze → Silver → Gold) built on **Delta Lake** within **Databricks**. This architecture provides:

- Clear data lineage and quality progression
- Ability to reprocess data from any layer
- Separation of concerns between ingestion and transformation

## Medallion Architecture

### Why Medallion?

1. **Auditability**: Raw data in Bronze enables debugging and reprocessing
2. **Flexibility**: Silver transformations can be refined without re-ingesting
3. **Performance**: Gold tables are optimized for specific queries
4. **Governance**: Clear boundaries for data quality and access control

### Layer Responsibilities

```
┌─────────────────────────────────────────────────────────────┐
│                        BRONZE                                │
├─────────────────────────────────────────────────────────────┤
│ • Raw JSON from APIs (as strings)                           │
│ • Minimal transformation (only add metadata)                │
│ • Append-only (historical record)                           │
│ • Partitioned by ingestion_date                             │
│ • Schema: raw_data, source, fetched_at, ingestion_date      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                        SILVER                                │
├─────────────────────────────────────────────────────────────┤
│ • Parsed, typed columns                                      │
│ • Deduplicated records                                       │
│ • Data quality validated                                     │
│ • SCD Type 2 for tracking changes                           │
│ • MERGE operations for upserts                              │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                         GOLD                                 │
├─────────────────────────────────────────────────────────────┤
│ • Business-ready aggregations                                │
│ • Pre-computed metrics                                       │
│ • Optimized for dashboard queries                           │
│ • Daily/weekly snapshots                                    │
└─────────────────────────────────────────────────────────────┘
```

## Delta Lake Features

### Time Travel

Delta Lake maintains a transaction log that enables querying historical states:

```sql
-- Query package counts before CVE disclosure
SELECT COUNT(*) FROM silver.packages
VERSION AS OF 42

-- Or by timestamp
SELECT * FROM silver.packages
TIMESTAMP AS OF '2026-01-27 00:00:00'
```

**Use Cases:**
- Compare ecosystem state before/after security events
- Audit data changes for compliance
- Debug data quality issues

### Schema Evolution

APIs change over time. Delta Lake handles this gracefully:

```python
# Bronze tables use mergeSchema=true
df.write.option("mergeSchema", "true").saveAsTable(...)
```

**Approach:**
- Bronze: Accept any new fields (raw JSON is flexible)
- Silver: Explicitly handle new columns in transformation logic
- Gold: Aggregate schemas are controlled

### ACID Transactions

All writes are transactional:

```python
# MERGE operation for SCD Type 2
deltaTable.merge(
    updates,
    condition="target.id = source.id AND target.is_current = true"
).whenMatchedUpdate(
    condition="target.hash != source.hash",
    set={"is_current": "false", "valid_to": "current_timestamp()"}
).whenNotMatchedInsert(
    values={...}
).execute()
```

## API Client Design

### Principles

1. **Rate Limit Aware**: Built-in throttling to respect API limits
2. **Retry Logic**: Exponential backoff for transient failures
3. **Raw Preservation**: Return full API responses for Bronze storage
4. **Typed Responses**: Use dataclasses for structure

### Client Hierarchy

```
BaseAPIClient (abstract)
├── GitHubClient
└── NVDClient
```

### Rate Limiting Strategy

| API | Limit | Strategy |
|-----|-------|----------|
| GitHub | 5,000/hour | Track X-RateLimit headers, wait if exhausted |
| NVD | 5 req/30s | Fixed delay between requests (6s) |

## Data Quality Framework

### Check Types

1. **Schema Validation**: Required columns present
2. **Null Checks**: Critical fields not null
3. **Uniqueness**: Primary key constraints
4. **Freshness**: Data not stale
5. **Range Checks**: Values within expected bounds

### Implementation

```python
class DataQualityChecker:
    def __init__(self, spark, raise_on_failure=True):
        self.raise_on_failure = raise_on_failure
        self.results = []

    def assert_not_null(self, df, columns, threshold=0.0):
        # Returns DQResult, optionally raises DataQualityError
        ...
```

### Quality Progression

| Layer | Checks |
|-------|--------|
| Bronze | Schema present, record_count > 0 |
| Silver | Not null, unique keys, valid ranges, freshness |
| Gold | Row count assertions, trend checks |

## SCD Type 2 Implementation

### Why SCD Type 2?

Package metadata can change (descriptions edited, ownership transferred). We need to:
- Track all historical states
- Identify when changes occurred
- Flag suspicious changes (potential malicious takeover)

### Schema

```sql
CREATE TABLE silver.packages_scd (
    -- Business key
    package_id STRING,

    -- Attributes
    name STRING,
    description STRING,
    publisher_id STRING,
    downloads BIGINT,

    -- SCD columns
    valid_from TIMESTAMP,
    valid_to TIMESTAMP,
    is_current BOOLEAN,
    record_hash STRING,

    -- Audit
    _ingested_at TIMESTAMP
)
```

### Merge Logic

```python
# Pseudocode for SCD Type 2 merge
1. Hash current record attributes
2. Compare with existing current record
3. If different:
   a. Close existing record (is_current=false, valid_to=now)
   b. Insert new record (is_current=true, valid_from=now)
4. If same: No action (idempotent)
```

## Anomaly Detection

### Rule-Based Flags

| Flag | Rule |
|------|------|
| CRYPTO_KEYWORDS | Name/description contains: crypto, wallet, bitcoin, seed, etc. |
| SUSPICIOUS_DESCRIPTION | Description < 20 chars or contains: test, example, placeholder |
| RAPID_DOWNLOADS | > 1000 downloads within 7 days of creation |
| UNVERIFIED_HIGH_DOWNLOADS | Unverified publisher + top 10% downloads |

### Statistical Anomalies

```python
# Z-score based download velocity detection
download_zscore = (current_delta - mean_delta) / std_delta
is_anomaly = abs(download_zscore) > 3.0
```

## Job Orchestration

### Schedule

| Job | Schedule | Dependencies |
|-----|----------|--------------|
| ingest_github | Daily 6 AM UTC | None |
| ingest_cve | Daily 7 AM UTC | None |
| ingest_packages | Daily 8 AM UTC | None |
| transform_silver | Daily 9 AM UTC | All Bronze jobs |
| build_gold | Daily 10 AM UTC | Silver jobs |

### Failure Handling

- Retries: 2 attempts with exponential backoff
- Alerts: Email on failure
- Idempotency: All jobs can be safely re-run

## Security Considerations

### Secrets Management

- API keys stored in Databricks Secrets
- Never committed to version control
- Rotated periodically

### Data Privacy

- Only aggregate statistics in Gold layer
- PII removed in Silver transformations

### Access Control

- Bronze: Data engineers only
- Silver: Data engineers + analysts
- Gold: All stakeholders (read-only)

## Performance Optimization

### Partitioning Strategy

| Table | Partition Column | Rationale |
|-------|------------------|-----------|
| Bronze | ingestion_date | Daily incremental loads |
| Silver | None (small data) | Full table scans acceptable |
| Gold | snapshot_date | Time-series queries |

### Caching

- Frequently accessed Gold tables cached
- API responses cached (15-minute TTL)

## Future Enhancements

1. **Real-time Ingestion**: Structured Streaming for GitHub webhooks
2. **ML-based Detection**: Train model on known malicious packages
3. **Alert System**: PagerDuty integration for critical findings
4. **Multi-region**: Support for multiple package registries
