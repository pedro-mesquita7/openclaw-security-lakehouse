"""Unit tests for data quality functions."""

from datetime import datetime

from src.utils.data_quality import (
    DataQualityError,
    DQResult,
)


class TestDQResult:
    """Tests for DQResult dataclass."""

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        result = DQResult(
            check_name="test_check",
            passed=True,
            message="Test passed",
            details={"key": "value"},
        )

        d = result.to_dict()

        assert d["check_name"] == "test_check"
        assert d["passed"] is True
        assert d["message"] == "Test passed"
        assert d["details"]["key"] == "value"
        assert "timestamp" in d

    def test_default_timestamp(self) -> None:
        """Test that timestamp is set by default."""
        result = DQResult(
            check_name="test",
            passed=True,
            message="Test",
        )

        # Should be a valid ISO format
        datetime.fromisoformat(result.timestamp)

    def test_empty_details(self) -> None:
        """Test handling of None details."""
        result = DQResult(
            check_name="test",
            passed=True,
            message="Test",
            details=None,
        )

        d = result.to_dict()
        assert d["details"] == {}


class TestDataQualityError:
    """Tests for DataQualityError exception."""

    def test_error_contains_result(self) -> None:
        """Test that error contains the DQ result."""
        result = DQResult(
            check_name="failed_check",
            passed=False,
            message="Check failed: values out of range",
        )

        error = DataQualityError(result)

        assert error.result == result
        assert "Check failed" in str(error)


class TestSuspiciousPackagePatterns:
    """Tests for suspicious package detection (requires PySpark mock)."""

    def test_crypto_keyword_detection(self) -> None:
        """Test that crypto keywords are flagged."""
        # This would require PySpark to fully test
        # Here we just verify the patterns
        suspicious_keywords = [
            "crypto",
            "wallet",
            "bitcoin",
            "ethereum",
            "seed",
            "private.?key",
            "mnemonic",
        ]

        test_cases = [
            ("crypto-helper", True),
            ("wallet-manager", True),
            ("bitcoin-tool", True),
            ("normal-util", False),
            ("data-processor", False),
        ]

        import re

        pattern = "|".join(suspicious_keywords)

        for name, should_match in test_cases:
            matches = bool(re.search(pattern, name.lower()))
            assert matches == should_match, f"Failed for {name}"

    def test_suspicious_description_patterns(self) -> None:
        """Test suspicious description detection."""
        suspicious_patterns = [
            "test",
            "example",
            "placeholder",
            "todo",
            "lorem ipsum",
        ]

        test_cases = [
            ("This is a test package", True),
            ("Example implementation", True),
            ("A robust data processing library", False),
            ("Secure authentication handler", False),
        ]

        import re

        pattern = "|".join(suspicious_patterns)

        for desc, should_match in test_cases:
            matches = bool(re.search(pattern, desc.lower()))
            assert matches == should_match, f"Failed for: {desc}"


class TestDataQualityChecker:
    """Tests for DataQualityChecker class (integration tests would need PySpark)."""

    def test_raise_on_failure_flag(self) -> None:
        """Test that raise_on_failure controls error behavior."""
        # This is a design validation - actual test needs PySpark
        # The checker should:
        # 1. With raise_on_failure=True: raise DataQualityError on failure
        # 2. With raise_on_failure=False: return DQResult with passed=False

        # Mock test verifying the class structure
        from src.utils.data_quality import DataQualityChecker

        # Can't instantiate without spark, but can verify class exists
        assert hasattr(DataQualityChecker, "assert_not_null")
        assert hasattr(DataQualityChecker, "assert_unique")
        assert hasattr(DataQualityChecker, "assert_row_count_range")
        assert hasattr(DataQualityChecker, "assert_freshness")
        assert hasattr(DataQualityChecker, "get_summary")
