# Kong API Gateway Integration: Prisma AIRS Custom Plugin

This document provides instructions for deploying and configuring the custom Prisma AIRS plugin for Kong API Gateway. This plugin intercepts API requests and responses, sending their content to Prisma AIRS for real-time security scanning. It can block malicious or non-compliant traffic based on your configured security profiles.

---

## Prerequisites

* A running Kong API Gateway instance (version 3.0 or newer).
* Access to the Kong control plane (Admin API, Konnect, or declarative `kong.yml`).
* Administrative access to [Strata Cloud Manager](https://www.strata.paloaltonetworks.com/) for Prisma AIRS.
* A configured **Security Profile** within Strata Cloud Manager. You will need the exact **Profile Name**.
* A Prisma AIRS **API Key**.
* The custom Prisma AIRS Kong plugin source files (`handler.lua`, `schema.lua`), which are located in this repository.

---

## Configuration Steps

### Step 1: Deploy the Custom Plugin Files to Kong


1.  **Locate Plugin Source:** The plugin files (`handler.lua`, `schema.lua`) are located in `kong/plugins/prisma-airs/`.

2.  **Copy Files to Kong Node:** Copy this directory to each node in your Kong cluster. The destination path should follow Kong's plugin structure. For a standard installation, this might be:
    ```bash
    # Example path on a Linux system
    /usr/local/share/lua/5.1/kong/plugins/prisma-airs/
    ```

3.  **Update Kong Configuration:** Add the custom plugin's name (`prisma-airs`) to your Kong configuration to load it at startup.
    * **Using `kong.conf` or environment variables:**
        ```
        KONG_PLUGINS=bundled,prisma-airs
        ```
    * **Using declarative `kong.yml`:**
        ```yaml
        plugins:
          - bundled
          - prisma-airs
        ```

4.  **Restart Kong:** A restart is required for Kong to discover and load the new plugin files.
    ```bash
    kong restart
    ```

### Step 2: Obtain Prisma AIRS Credentials

1.  Log in to the **Strata Cloud Manager**.
2.  Navigate to the Prisma AIRS section.
3.  Identify the **Security Profile** you wish to use. Note the **Profile Name** exactly.
4.  Navigate to the API Key management section and generate a new **API Key**. Store this key securely.

### Step 3: Enable and Configure the Plugin

The plugin can be applied to a specific Service, Route, or enabled globally. Applying it to a Service is a common and recommended approach.

#### **Option A: Enable via Kong Admin API**

Execute the following `curl` command to apply the plugin to a service. Replace the placeholders with your actual values.

```bash
curl -X POST http://localhost:8001/services/{your-service-name-or-id}/plugins \
    --header "Content-Type: application/json" \
    --data '{
        "name": "prisma-airs",
        "config": {
            "api_key": "YOUR_PRISMA_AIRS_API_KEY",
            "profile_name": "YOUR_PRISMA_AIRS_PROFILE_NAME",
            "scan_mode": "pre_and_post_call",
            "block_on_threat": true,
            "timeout": 1000
        }
    }'
```

#### **Option B: Enable via Declarative `kong.yml`**

Add the plugin configuration directly to a service definition in your `kong.yml` file.

```yaml
services:
- name: my-llm-service
  url: [http://my-upstream-api.internal](http://my-upstream-api.internal)
  plugins:
  - name: prisma-airs
    config:
      api_key: "YOUR_PRISMA_AIRS_API_KEY"
      profile_name: "YOUR_PRISMA_AIRS_PROFILE_NAME"
      scan_mode: "pre_and_post_call" # Scan both request and response
      block_on_threat: true
      timeout: 1000 # Timeout in milliseconds
  routes:
  - name: my-llm-route
    paths:
    - /chat
```

---

## Plugin Configuration Parameters

The following parameters are available in the plugin's `config` block:

| Parameter           | Required | Type      | Default                                                     | Description                                                                                             |
| ------------------- | :------: | --------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `api_key`           | **Yes** | String    | `null`                                                      | Your Prisma AIRS API Key (`x-pan-token`).                                                                 |
| `profile_name`      | **Yes** | String    | `null`                                                      | The exact name of the Security Profile to use for scanning.                                             |
| `scan_mode`         |    No    | String    | `pre_call`                                                  | Determines when to scan. Options: `pre_call` (request), `post_call` (response), `pre_and_post_call`.  |
| `block_on_threat`   |    No    | Boolean   | `true`                                                      | If `true`, the plugin will terminate the request with a `403 Forbidden` response if a threat is found.    |
| `timeout`           |    No    | Integer   | `2000`                                                      | Timeout in milliseconds for the HTTP call to the Prisma AIRS API.                                       |
| `airs_api_endpoint` |    No    | String    | `https://service.api.aisecurity.paloaltonetworks.com/v1/scan` | The base URL for the Prisma AIRS scanning API. Only change this if instructed by Palo Alto Networks. |

---

## Verification

1.  **Send a Benign Request:** Make a valid API call through Kong to the endpoint protected by the plugin. The request should pass and receive a `200 OK` response from your upstream service.

2.  **Send a Malicious Request:** Send a request containing a known threat pattern (e.g., a prompt injection attempt like "Ignore previous instructions"). If `block_on_threat` is `true`, Kong should return a `403 Forbidden` status code.

3.  **Check Kong Logs:** Monitor Kong's error logs (`/usr/local/kong/logs/error.log`) for any messages from the `prisma-airs` in case of connection issues or other errors.

4.  **Check Strata Cloud Manager:** Log in to your Strata Cloud Manager dashboard and navigate to the Prisma AIRS monitoring section. You should see scan events corresponding to your test requests, along with their verdicts (`allow` or `block`).
