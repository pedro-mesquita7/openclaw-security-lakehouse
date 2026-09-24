"""
Data quality assertion functions for the OpenClaw Security Lakehouse.

These functions provide:
- Schema validation
- Null/completeness checks
- Anomaly detection for security metrics
- Row count and freshness assertions

Usage in Databricks notebooks:
    from src.utils.data_quality import DataQualityChecker

    dq = DataQualityChecker(spark)
    dq.assert_not_null(df, ["id", "created_at"])
    dq.assert_row_count_range(df, min_rows=1, max_rows=10000)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyspark.sql import DataFrame, SparkSession

logger = logging.getLogger(__name__)


@dataclass
class DQResult:
    """Result of a data quality check."""

    check_name: str
    passed: bool
    message: str
    details: dict[str, Any] | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details or {},
            "timestamp": self.timestamp,
        }


class DataQualityError(Exception):
    """Raised when a data quality check fails."""

    def __init__(self, result: DQResult):
        self.result = result
        super().__init__(result.message)


class DataQualityChecker:
    """
    Data quality checker for PySpark DataFrames.

    Provides assertion methods that can either:
    - Raise exceptions on failure (for pipeline enforcement)
    - Return DQResult objects (for logging/monitoring)
    """

    def __init__(self, spark: "SparkSession", raise_on_failure: bool = True):
        """
        Initialize the checker.

        Args:
            spark: SparkSession instance
            raise_on_failure: If True, failed checks raise DataQualityError
        """
        self.spark = spark
        self.raise_on_failure = raise_on_failure
        self.results: list[DQResult] = []

    def _handle_result(self, result: DQResult) -> DQResult:
        """Handle a check result based on configuration."""
        self.results.append(result)
        if not result.passed:
            logger.warning(f"DQ Check Failed: {result.check_name} - {result.message}")
            if self.raise_on_failure:
                raise DataQualityError(result)
        else:
            logger.info(f"DQ Check Passed: {result.check_name}")
        return result

    def assert_not_null(
        self,
        df: "DataFrame",
        columns: list[str],
        threshold: float = 0.0,
    ) -> DQResult:
        """
        Assert that specified columns have no (or few) null values.

        Args:
            df: DataFrame to check
            columns: Column names to check for nulls
            threshold: Maximum allowed null ratio (0.0 = no nulls, 0.1 = 10% nulls ok)
        """
        total_rows = df.count()
        if total_rows == 0:
            return self._handle_result(
                DQResult(
                    check_name="not_null",
                    passed=True,
                    message="DataFrame is empty, skipping null check",
                    details={"columns": columns},
                )
            )

        null_counts = {}
        failed_columns = []

        for col in columns:
            null_count = df.filter(df[col].isNull()).count()
            null_ratio = null_count / total_rows
            null_counts[col] = {"count": null_count, "ratio": null_ratio}
            if null_ratio > threshold:
                failed_columns.append(col)

        passed = len(failed_columns) == 0
        message = (
            f"All columns pass null check (threshold: {threshold})"
            if passed
            else f"Columns with excessive nulls: {failed_columns}"
        )

        return self._handle_result(
            DQResult(
                check_name="not_null",
                passed=passed,
                message=message,
                details={"null_counts": null_counts, "threshold": threshold},
            )
        )

    def assert_unique(self, df: "DataFrame", columns: list[str]) -> DQResult:
        """Assert that the combination of columns is unique."""
        total_rows = df.count()
        distinct_rows = df.select(columns).distinct().count()

        passed = total_rows == distinct_rows
        duplicate_count = total_rows - distinct_rows

        return self._handle_result(
            DQResult(
                check_name="unique",
                passed=passed,
                message=(
                    f"All rows unique on {columns}"
                    if passed
                    else f"Found {duplicate_count} duplicate rows on {columns}"
                ),
                details={
                    "columns": columns,
                    "total_rows": total_rows,
                    "distinct_rows": distinct_rows,
                    "duplicates": duplicate_count,
                },
            )
        )

    def assert_row_count_range(
        self,
        df: "DataFrame",
        min_rows: int = 0,
        max_rows: int | None = None,
    ) -> DQResult:
        """Assert row count is within expected range."""
        row_count = df.count()
        passed = row_count >= min_rows and (max_rows is None or row_count <= max_rows)

        return self._handle_result(
            DQResult(
                check_name="row_count_range",
                passed=passed,
                message=(
                    f"Row count {row_count} within range [{min_rows}, {max_rows or 'inf'}]"
                    if passed
                    else f"Row count {row_count} outside range [{min_rows}, {max_rows or 'inf'}]"
                ),
                details={
                    "row_count": row_count,
                    "min_rows": min_rows,
                    "max_rows": max_rows,
                },
            )
        )

    def assert_values_in_set(
        self,
        df: "DataFrame",
        column: str,
        allowed_values: set[Any],
    ) -> DQResult:
        """Assert all values in a column are from an allowed set."""
        distinct_values = {row[column] for row in df.select(column).distinct().collect()}
        invalid_values = distinct_values - allowed_values

        passed = len(invalid_values) == 0

        return self._handle_result(
            DQResult(
                check_name="values_in_set",
                passed=passed,
                message=(
                    f"All values in '{column}' are valid"
                    if passed
                    else f"Invalid values in '{column}': {invalid_values}"
                ),
                details={
                    "column": column,
                    "allowed_values": list(allowed_values),
                    "invalid_values": list(invalid_values),
                },
            )
        )

    def assert_freshness(
        self,
        df: "DataFrame",
        timestamp_column: str,
        max_age_hours: int = 24,
    ) -> DQResult:
        """Assert that data is not stale (most recent record within max_age)."""
        from pyspark.sql import functions as F

        max_timestamp = df.agg(F.max(timestamp_column)).collect()[0][0]

        if max_timestamp is None:
            return self._handle_result(
                DQResult(
                    check_name="freshness",
                    passed=False,
                    message=f"No timestamp values found in '{timestamp_column}'",
                    details={"column": timestamp_column},
                )
            )

        # Handle different timestamp types
        if isinstance(max_timestamp, str):
            max_timestamp = datetime.fromisoformat(max_timestamp.replace("Z", "+00:00"))
        elif not isinstance(max_timestamp, datetime):
            max_timestamp = datetime.fromtimestamp(float(max_timestamp), tz=timezone.utc)

        if max_timestamp.tzinfo is None:
            max_timestamp = max_timestamp.replace(tzinfo=timezone.utc)

        age = datetime.now(timezone.utc) - max_timestamp
        age_hours = age.total_seconds() / 3600
        passed = age_hours <= max_age_hours

        return self._handle_result(
            DQResult(
                check_name="freshness",
                passed=passed,
                message=(
                    f"Data is fresh (age: {age_hours:.1f}h)"
                    if passed
                    else f"Data is stale (age: {age_hours:.1f}h, max: {max_age_hours}h)"
                ),
                details={
                    "column": timestamp_column,
                    "max_timestamp": max_timestamp.isoformat(),
                    "age_hours": age_hours,
                    "max_age_hours": max_age_hours,
                },
            )
        )

    def assert_schema_matches(
        self,
        df: "DataFrame",
        expected_columns: list[str],
        allow_extra: bool = True,
    ) -> DQResult:
        """Assert DataFrame has expected columns."""
        actual_columns = set(df.columns)
        expected_set = set(expected_columns)

        missing = expected_set - actual_columns
        extra = actual_columns - expected_set if not allow_extra else set()

        passed = len(missing) == 0 and len(extra) == 0

        return self._handle_result(
            DQResult(
                check_name="schema_matches",
                passed=passed,
                message=(
                    "Schema matches expected columns"
                    if passed
                    else f"Schema mismatch - Missing: {missing}, Extra: {extra}"
                ),
                details={
                    "expected_columns": expected_columns,
                    "actual_columns": list(actual_columns),
                    "missing": list(missing),
                    "extra": list(extra),
                },
            )
        )

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all checks run."""
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        return {
            "total_checks": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / len(self.results) if self.results else 0,
            "results": [r.to_dict() for r in self.results],
        }


# Security-specific anomaly detection functions
def detect_suspicious_package_patterns(
    df: "DataFrame",
    name_col: str = "name",
    description_col: str = "description",
    downloads_col: str = "downloads",
    created_col: str = "created_at",
) -> "DataFrame":
    """
    Flag packages with suspicious patterns commonly seen in malicious packages.

    Patterns detected:
    - Crypto/wallet-related keywords in new packages
    - Typosquatting (similar names to popular packages)
    - Suspiciously high downloads for new packages
    - Generic/placeholder descriptions

    Returns DataFrame with added 'risk_flags' column.
    """
    from pyspark.sql import functions as F

    # Suspicious keywords often found in malicious packages
    crypto_keywords = [
        "crypto",
        "wallet",
        "bitcoin",
        "ethereum",
        "seed",
        "private.?key",
        "mnemonic",
    ]
    crypto_pattern = "|".join(crypto_keywords)

    suspicious_desc_patterns = [
        "test",
        "example",
        "placeholder",
        "todo",
        "lorem ipsum",
    ]
    suspicious_desc_pattern = "|".join(suspicious_desc_patterns)

    result = df.withColumn(
        "risk_flags",
        F.array(
            # Flag 1: Crypto keywords in name or description
            F.when(
                F.lower(F.col(name_col)).rlike(crypto_pattern)
                | F.lower(F.col(description_col)).rlike(crypto_pattern),
                F.lit("CRYPTO_KEYWORDS"),
            ),
            # Flag 2: Generic/placeholder description
            F.when(
                F.lower(F.col(description_col)).rlike(suspicious_desc_pattern)
                | (F.length(F.col(description_col)) < 20),
                F.lit("SUSPICIOUS_DESCRIPTION"),
            ),
            # Flag 3: High downloads on recent package (possible inflation)
            F.when(
                (F.col(downloads_col) > 1000)
                & (F.datediff(F.current_date(), F.col(created_col)) < 7),
                F.lit("RAPID_DOWNLOADS"),
            ),
        ),
    )

    # Remove nulls from array
    result = result.withColumn(
        "risk_flags",
        F.array_except(F.col("risk_flags"), F.array(F.lit(None))),
    )

    # Add overall risk score
    result = result.withColumn("risk_score", F.size("risk_flags"))

    return result


def detect_download_velocity_anomalies(
    df: "DataFrame",
    package_col: str = "package_id",
    downloads_col: str = "downloads",
    date_col: str = "snapshot_date",
    std_threshold: float = 3.0,
) -> "DataFrame":
    """
    Detect anomalous download velocity using z-score method.

    Flags packages where daily download increase exceeds std_threshold
    standard deviations from the mean.
    """
    from pyspark.sql import functions as F
    from pyspark.sql.window import Window

    # Calculate daily download delta
    window = Window.partitionBy(package_col).orderBy(date_col)
    df_with_delta = df.withColumn(
        "download_delta",
        F.col(downloads_col) - F.lag(downloads_col, 1).over(window),
    )

    # Calculate statistics per package
    stats_window = Window.partitionBy(package_col)
    df_with_stats = df_with_delta.withColumn(
        "mean_delta", F.avg("download_delta").over(stats_window)
    ).withColumn("std_delta", F.stddev("download_delta").over(stats_window))

    # Calculate z-score and flag anomalies
    result = df_with_stats.withColumn(
        "download_zscore",
        F.when(
            F.col("std_delta") > 0,
            (F.col("download_delta") - F.col("mean_delta")) / F.col("std_delta"),
        ).otherwise(0),
    ).withColumn(
        "is_download_anomaly",
        F.abs(F.col("download_zscore")) > std_threshold,
    )

    return result
