# Setup Guide

This guide walks through setting up the OpenClaw Security Intelligence Lakehouse from scratch.

## Prerequisites

- Python 3.10 or higher
- Git
- A Databricks account (Free Edition works)
- GitHub account (for CI/CD)

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/pedro-mesquita7/openclaw-security-lakehouse.git
cd openclaw-security-lakehouse
```

### 2. Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Pre-commit Hooks (Optional)

```bash
pip install pre-commit
pre-commit install
```

### 5. Create Environment File

Create a `.env` file for local testing (never commit this):

```bash
# .env
GITHUB_TOKEN=your_github_personal_access_token
NVD_API_KEY=your_nvd_api_key  # Optional
```

### 6. Run Tests

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=src --cov-report=html
```

### 7. Run Linting

```bash
# Check code style
ruff check src/ tests/

# Format code
ruff format src/ tests/

# Type checking
mypy src/
```

## Databricks Setup

### 1. Create Databricks Account

1. Go to [databricks.com/try-databricks](https://databricks.com/try-databricks)
2. Sign up for the Community Edition (free) or a trial
3. Note your workspace URL (e.g., `https://dbc-xxxxx.cloud.databricks.com`)

### 2. Install Databricks CLI

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/databricks/setup-cli/main/install.ps1 -OutFile install.ps1
.\install.ps1
```

**macOS/Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/databricks/setup-cli/main/install.sh | sh
```

### 3. Configure Authentication

```bash
databricks configure
```

Enter:
- Host: Your workspace URL
- Token: Personal access token (generate in User Settings > Developer)

Verify connection:
```bash
databricks workspace list /
```

### 4. Create Secret Scope

Secrets store API keys securely:

```bash
# Create the scope
databricks secrets create-scope openclaw

# Add GitHub token (for higher API rate limits)
databricks secrets put-secret openclaw github_token
# Enter your GitHub personal access token when prompted

# Add NVD API key (optional, increases rate limits)
databricks secrets put-secret openclaw nvd_api_key
```

Verify secrets:
```bash
databricks secrets list-secrets openclaw
```

### 5. Deploy with Databricks Asset Bundles

```bash
# Validate the bundle configuration
databricks bundle validate

# Deploy to development target
databricks bundle deploy --target dev

# View deployed resources
databricks bundle summary
```

### 6. Run Jobs Manually

Since Databricks Free Edition has compute quotas, jobs are paused by default. Run them manually:

```bash
# List deployed jobs
databricks jobs list

# Run a specific job
databricks jobs run-now --job-id <JOB_ID>

# Or trigger via bundle
databricks bundle run ingest_github --target dev
```

### 7. View Results

1. Open Databricks workspace in browser
2. Navigate to **Catalog** > **main** > **openclaw_security_dev**
3. Browse tables to see ingested data

## GitHub Actions Setup

### 1. Add Repository Secrets

Go to your GitHub repo > Settings > Secrets and variables > Actions

Add these secrets:
- `DATABRICKS_HOST`: Your workspace URL (e.g., `https://dbc-xxxxx.cloud.databricks.com`)
- `DATABRICKS_TOKEN`: Personal access token

### 2. Enable Deployment

Add repository variable:
- `DATABRICKS_CONFIGURED`: Set to `true`

### 3. Test CI Pipeline

1. Create a new branch
2. Make a small change
3. Open a Pull Request
4. Watch the CI workflow run

### 4. Deploy via CD

Merging to `main` triggers deployment automatically (if secrets are configured).

## API Keys

### GitHub Personal Access Token

1. Go to GitHub > Settings > Developer settings > Personal access tokens
2. Generate new token (classic)
3. Select scopes: `public_repo` (read-only access to public repos)
4. Copy the token

**Why needed:** Without a token, GitHub API limits you to 60 requests/hour. With a token, you get 5,000/hour.

### NVD API Key (Optional)

1. Request key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)
2. Key is emailed to you

**Why optional:** NVD works without a key, just with lower rate limits (5 req/30s vs 50 req/30s).

## Troubleshooting

### "Rate limit exceeded" errors

- Ensure API tokens are configured in Databricks secrets
- Check if running multiple jobs simultaneously
- Wait for rate limit reset (check API response headers)

### "Table not found" errors

- Run Bronze ingestion jobs first
- Check catalog/schema names match configuration
- Verify workspace has Unity Catalog enabled

### CI failing on "bundle validate"

- Bundle validation requires workspace connection
- The CI job gracefully handles this by outputting a warning
- Full validation runs during deployment

### Compute quota exceeded (Free Edition)

- Free Edition has daily compute limits
- Space out job runs
- Use smaller datasets during development
- Consider upgrading for production use

## Next Steps

After setup:

1. **Run Bronze ingestion** to populate raw data
2. **Explore data** in Databricks SQL Editor
3. **Build Silver transformations** (Phase 2)
4. **Create Gold aggregations** (Phase 3)
5. **Build dashboard** (Phase 4)

See [architecture.md](architecture.md) for design details.
