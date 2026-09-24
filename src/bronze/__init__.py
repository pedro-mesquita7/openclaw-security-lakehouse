"""
Bronze layer ingestion modules.

The Bronze layer stores raw data from external APIs in Delta format:
- github_repository_raw: GitHub repo metadata snapshots
- github_issues_raw: Issues and PRs
- github_releases_raw: Release information
- github_contributors_raw: Contributor data
- cve_raw: NVD vulnerability records
- packages_raw: Package registry snapshots

Ingestion is handled by notebooks in the notebooks/ directory:
- 02_ingest_github.py
- 03_ingest_cve.py
- 04_ingest_packages.py

These notebooks use shared API clients from utils/api_clients.py.
"""
