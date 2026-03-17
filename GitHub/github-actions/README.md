# GitHub Actions Integration with Prisma AIRS Model Security

This integration adds Palo Alto Networks Prisma AIRS Model Security scanning to a GitHub Actions CI/CD pipeline. It scans AI model files (weights and binaries) against security policies before deployment, blocking models that fail the security assessment.

> **Note:** This integration uses **Prisma AIRS Model Security** (pre-deployment model file scanning), which is different from AI Runtime Security (prompt/response scanning). It uses the [Model Security SDK](https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security) rather than the AIRS Runtime API.

---

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

This integration scans **AI model files** before deployment. It does not scan prompts or responses at inference time — that is handled by the AI Runtime Security integrations elsewhere in this repository.

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Model file scan | ✅ | Scans model weights/binaries for security risks before deployment |
| Prompt | N/A | Use an AI Runtime Security integration for prompt scanning |
| Response | N/A | Use an AI Runtime Security integration for response scanning |
| Streaming | N/A | Not applicable to model file scanning |
| Pre-tool call | N/A | Not applicable to model file scanning |
| Post-tool call | N/A | Not applicable to model file scanning |

### What Gets Scanned

Prisma AIRS Model Security evaluates AI models for:

- **Model provenance and supply chain risks** — Verifying the model source and integrity
- **Known vulnerabilities** — Checking against known CVEs and security advisories
- **Malicious payloads** — Detecting embedded malicious code or backdoors
- **Compliance violations** — Ensuring models meet organizational security policies
- **Training data risks** — Identifying potential data poisoning indicators

---

## Prerequisites

* A GitHub repository with Actions enabled
* A Palo Alto Networks Prisma AIRS subscription with Model Security enabled
* Access to Strata Cloud Manager for credentials and security profile configuration
* (For the included example deployment) A Google Cloud project with the [Vertex AI API](https://console.cloud.google.com/apis/library/aiplatform.googleapis.com) enabled

---

## Configuration Steps

### Step 1: Obtain Prisma AIRS Model Security Credentials

1. Log in to the **Strata Cloud Manager**
2. Create a **Service Account** under Settings > Access Control
3. Note the **Client ID**, **Client Secret**, and **TSG ID**
4. Configure a **Security Profile** (Model Security) and note the profile UUID
5. Note your **API Endpoint** URL (e.g., `https://api.sase.paloaltonetworks.com/aims`)

### Step 2: Configure GitHub Secrets

Add the following secrets in your GitHub repository under **Settings > Secrets and variables > Actions**:

| Secret | Description |
|--------|-------------|
| `MODEL_SECURITY_CLIENT_ID` | Prisma AIRS OAuth client ID (service account) |
| `MODEL_SECURITY_CLIENT_SECRET` | Prisma AIRS OAuth client secret |
| `MODEL_SECURITY_PROFILE_ID` | Security profile UUID |
| `MODEL_SECURITY_API_ENDPOINT` | API endpoint URL |
| `TSG_ID` | Tenant Service Group ID |

For the included Vertex AI deployment example, also configure:

| Secret | Description |
|--------|-------------|
| `GCP_PROJECT_ID` | Google Cloud project ID |
| `GCP_REGION` | GCP region (e.g., `us-central1`) |
| `GCP_SA_KEY` | GCP service account JSON key (with Vertex AI Admin role) |
| `HF_TOKEN` | HuggingFace access token (for gated models) |

> **Note:** These env vars differ from the standard `PRISMA_AIRS_API_KEY` / `PRISMA_AIRS_PROFILE_NAME` / `PRISMA_AIRS_URL` used by AI Runtime Security integrations. Model Security uses OAuth2 client credentials via the `model-security-client` SDK.

### Step 3: Add the Security Scan Job to Your Workflow

The core integration is the `security-scan` job in `.github/workflows/model-security-scan.yml`. It:

1. Authenticates with Prisma AIRS to get a private PyPI URL (`scripts/get_pypi_url.sh`)
2. Installs the `model-security-client` SDK from the private PyPI
3. Runs `scripts/scan_model.py` which scans the model and exits non-zero if BLOCKED

To add this to your own pipeline, copy the `security-scan` job and the supporting files (`scripts/scan_model.py`, `scripts/get_pypi_url.sh`), then configure the required secrets.

### Step 4: Configure the Model

Edit `config/model-config.yaml` to specify the model to scan:

```yaml
model:
  huggingface_id: "google/gemma-3-1b-it"
  display_name: "gemma-3-1b-it"
  version: "1.0"

security:
  scan_enabled: true
```

---

## Architecture

```
Developer changes config/model-config.yaml
                    |
                    v
        GitHub Actions Triggered
                    |
                    v
       +----------------------------+
       | Prisma AIRS Model Security |
       |           Scan             |
       +----------------------------+
                    |
              +-----+-----+
              |           |
           ALLOWED     BLOCKED
              |           |
              v           v
      Deploy model    Pipeline fails.
      to target       Model is NOT
      infrastructure  deployed.
```

**On Pull Requests:** The security scan runs and reports pass/fail status, but the model is not deployed. This allows developers to verify model compliance before merging.

**On Push to Main:** If the security scan passes, the model is automatically deployed and validated.

---

## Validation

### Trigger a Scan

Commit a change to `config/model-config.yaml` and push to the repository. The GitHub Actions workflow will run the security scan automatically.

### Verify in CI Logs

The scan output in the GitHub Actions logs will show:

- The model being scanned and its URI
- The scan UUID for tracking
- The outcome: `ALLOWED` or `BLOCKED`
- Any rule violations with severity and description

### Verify in Strata Cloud Manager

All scan results are visible in the Strata Cloud Manager dashboard under Model Security activity logs.

### Example Output

```
================================================================
  PRISMA AIRS MODEL SECURITY SCAN RESULTS
================================================================
  Model:        google/gemma-3-1b-it
  Scan UUID:    a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Outcome:      EvalOutcome.ALLOWED
  Summary:      Model passed all security checks
  ...
================================================================

ALLOWED: Model approved by Prisma AIRS security policy.
The model is cleared for deployment.
```

---

## Technical Requirements

1. This integration uses the **Model Security SDK** (`model-security-client`), not the AIRS Runtime API. Authentication is via OAuth2 client credentials (not API key).

2. The SDK is installed from a **private PyPI** repository. The `scripts/get_pypi_url.sh` script handles authentication and URL retrieval.

3. The scan script (`scripts/scan_model.py`) sets labels including `pipeline: github-actions` for tracking scan origin in Strata Cloud Manager.

---

## Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── model-security-scan.yml    # CI/CD pipeline definition
├── config/
│   └── model-config.yaml             # Model configuration (trigger file)
├── scripts/
│   ├── scan_model.py                 # Prisma AIRS Model Security scan
│   ├── get_pypi_url.sh               # Private PyPI authentication
│   ├── deploy_model.sh               # Example: Vertex AI deployment
│   ├── test_model.py                 # Example: Endpoint validation
│   └── undeploy_model.sh             # Example: Cost cleanup
├── .env.example                      # Environment variable reference
├── requirements.txt                  # Python dependencies
└── README.md
```

> **Note:** `deploy_model.sh`, `test_model.py`, and `undeploy_model.sh` are example scripts for Google Cloud Vertex AI deployment. Replace these with your own deployment target (e.g., AWS SageMaker, Azure ML, on-prem).

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `get_pypi_url.sh` fails with auth error | Verify `MODEL_SECURITY_CLIENT_ID`, `MODEL_SECURITY_CLIENT_SECRET`, and `TSG_ID` are correct |
| Scan returns unexpected outcome | Check that `MODEL_SECURITY_PROFILE_ID` points to a valid, active security profile |
| SDK install fails | Ensure the private PyPI URL was retrieved successfully in the previous step |

---

## Links

- [Source repository](https://github.com/bartpmika/model-security-scan-via-github-actions)
- [Prisma AIRS Model Security documentation](https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security)
- [Model Security SDK installation guide](https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security/model-security-to-secure-your-ai-models/get-started-with-ai-model-security/install-ai-model-security)
- [Prisma AIRS API documentation](https://pan.dev/airs/)
