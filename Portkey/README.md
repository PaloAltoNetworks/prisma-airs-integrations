# Portkey Integration with Prisma AIRS

This document describes how to integrate Prisma AIRS as a security guardrail within the Portkey AI Gateway. This setup allows for the automatic scanning of LLM inputs and outputs to detect and block threats in real-time.

---

## Prerequisites

* Administrative access to your Portkey account.
* An active Prisma AIRS license and access to the [Strata Cloud Manager](https://www.strata.paloaltonetworks.com/).
* A configured **Security Profile** within Strata Cloud Manager. Note the **Profile Name**.
* A Prisma AIRS **API Key**.

---

## Configuration Steps

### Step 1: Add Prisma AIRS Credentials to Portkey

1.  Log in to your Portkey dashboard.
2.  Navigate to **Settings > Integrations**.
3.  Find the **Palo Alto Networks Prisma AIRS** integration and click the **Edit** button.
4.  Add your Prisma AIRS **API Key** as a new credential. Portkey will manage this secret securely.

### Step 2: Create a Prisma AIRS Guardrail

1.  Navigate to the **Guardrails** page in the Portkey dashboard.
2.  Click the **Create** button to add a new guardrail.
3.  Search for and select **"PANW Prisma AIRS Guardrail"**.
4.  Configure the guardrail parameters:
    * **Profile Name:** Enter the exact name of the Security Profile you configured in Strata Cloud Manager. This field is required.
5.  Save the guardrail. Portkey will assign it a unique **Guardrail ID**.

### Step 3: Apply the Guardrail to a Portkey Config

1.  A Portkey **Config** is a reusable configuration that can be attached to your API requests. You can create or edit a Config in the Portkey UI.
2.  In your chosen Config, add the **Guardrail ID** from the previous step to one of the following parameters:
    * **`input_guardrails`**: To scan the prompt before it is sent to the LLM.
    * **`output_guardrails`**: To scan the response from the LLM before it is sent to the user.
3.  Save the Config. You will get a **Config ID** (or you can use a named config).

---

## Verification

Make an API request through the Portkey Gateway, attaching your configured Config ID.

```json
{
  "messages": [...],
  "config": "your-config-id"
}
```

Portkey will automatically invoke the Prisma AIRS guardrail to scan the request and/or response. If a threat is detected and the action is `block`, the request will be denied. All security events can be monitored and analyzed in the Strata Cloud Manager.
