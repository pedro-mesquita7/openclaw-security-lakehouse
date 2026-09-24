"""
Silver layer transformation modules.

The Silver layer contains cleaned, validated, and enriched data:
- packages: Current state with risk flags
- packages_scd: SCD Type 2 history for audit trail
- cve_details: Structured CVE records with CVSS scores
- github_repo_metrics: Repository statistics
- github_issues: Issues with security tags

Transformations are handled by notebooks in the notebooks/ directory:
- 05_silver_packages.py (with SCD Type 2 and DQ checks)
- 06_silver_cve.py
- 07_silver_github.py

These notebooks use shared utilities from utils/data_quality.py.
"""
