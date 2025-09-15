# LiteLLM Integration with Prisma AIRS

This document provides instructions for configuring Prisma AIRS as a security guardrail within the LiteLLM Proxy (LLM Gateway). This integration enables real-time scanning of prompts and responses to protect against threats like prompt injection, malicious content, and data loss.

---

## Prerequisites

* A running instance of the LiteLLM Proxy.
* An active Prisma AIRS license and access to the [Strata Cloud Manager](https://www.strata.paloaltonetworks.com/).
* A configured **Security Profile** within Strata Cloud Manager.
* A Prisma AIRS **API Key**.

---

## Configuration Steps

### Step 1: Obtain Prisma AIRS Credentials

1.  Log in to the **Strata Cloud Manager**.
2.  Activate your Prisma AIRS license if you have not already done so.
3.  Create a **deployment profile** and a **security profile**. Note the exact **Security Profile Name**.
4.  Generate your **API Key** from the deployment profile and store it securely.

### Step 2: Define the Guardrail in `config.yaml`

1.  Open your LiteLLM Proxy `config.yaml` file.
2.  Under the `model_list` section, add the `guardrails` configuration to the desired model.
3.  Define the Prisma AIRS guardrail as follows:

```yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: os.environ/OPENAI_API_KEY
    guardrails:
      - guardrail_name: "panw-prisma-airs-guardrail"
        litellm_params:
          guardrail: panw_prisma_airs
          mode: "pre_call"  # Or "post_call"
          api_key: os.environ/AIRS_API_KEY
          profile_name: os.environ/AIRS_API_PROFILE_NAME
          # api_base: "[https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request](https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request)" # Optional override
```

**Configuration Details:**
* **`guardrail`**: Must be set to `panw_prisma_airs`.
* **`mode`**: Determines when the scan occurs.
    * `pre_call`: Scans the user input *before* the LLM call.
    * `post_call`: Scans both the input and the LLM output *after* the call.
* **`api_key`**: Your Prisma AIRS API key. It's best practice to load this from an environment variable.
* **`profile_name`**: The name of your Security Profile from Strata Cloud Manager.

### Step 3: Set Environment Variables and Start the Gateway

1.  Export the required environment variables in your terminal:
    ```bash
    export AIRS_API_KEY="your-panw-api-key"
    export AIRS_API_PROFILE_NAME="your-security-profile-name"
    export OPENAI_API_KEY="your-openai-api-key"
    ```
2.  Start the LiteLLM Proxy with your configuration file:
    ```bash
    litellm --config config.yaml
    ```

---

## Verification

Send a request to the LiteLLM model you configured. The request will be intercepted and scanned by Prisma AIRS according to the `mode` you set. Blocked requests will receive an error response. You can monitor all scan activity and threat logs in the Strata Cloud Manager dashboard.
