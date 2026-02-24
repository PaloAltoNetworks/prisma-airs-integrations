# TrueFoundry Integration with Prisma AIRS

This document provides instructions for integrating Prisma AIRS with the TrueFoundry AI Gateway. This integration allows you to use Prisma AIRS as a security guardrail, scanning AI requests and responses for threats directly from the gateway.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Gateway scans AI requests before forwarding to LLM |
| Response | ✅ | Gateway validates responses with block/allow actions |
| Streaming | ⚠️ | Supported for `v1/messages` API signature only |
| Pre-tool call | ❌ | Request and response scanning only |
| Post-tool call | ❌ | Tool result scanning not documented |
| MCP | ❌ | No MCP integration |

---

## Prerequisites

* Administrative access to your TrueFoundry platform.
* An active Prisma AIRS license and access to the [Strata Cloud Manager](https://www.strata.paloaltonetworks.com/).
* A configured **Security Profile** within Strata Cloud Manager.
* A Prisma AIRS **API Key**.

---

## Configuration Steps

### Step 1: Obtain Prisma AIRS Credentials

1.  Log in to the **Strata Cloud Manager**.
2.  Navigate to the Prisma AIRS section.
3.  Create or identify the **Security Profile** you wish to use. Note the **Profile Name** exactly.
4.  Navigate to the API Key management section and generate a new **API Key**. Securely store this key.

### Step 2: Configure the Guardrail in TrueFoundry

1.  In the TrueFoundry UI, navigate to the section for creating a new **Guardrails Group**.
2.  Fill in the form:
    * **Name:** Enter a descriptive name for your guardrails group (e.g., `Prisma-AIRS-Security`).
    * **Collaborators:** Add any team members who should have access to this group.
3.  Under the **Palo Alto Prisma AIRS Config** section, provide the following:
    * **Name:** A name for this specific Prisma AIRS configuration.
    * **Profile Name:** The exact name of the Security Profile you noted from Strata Cloud Manager.
4.  Under the **Palo Alto Prisma AIRS Authentication Data** section:
    * **API Key:** Enter the API key you generated from Strata Cloud Manager. TrueFoundry will store this as a secure secret.
5.  Save the Guardrails Group.

---

## Verification

The TrueFoundry Gateway will now route requests through Prisma AIRS for scanning based on your configuration. The validation logic is as follows:

* If the Prisma AIRS API response includes `action: "block"`, the request will be blocked, and a `400` error will be returned to the client.
* If the Prisma AIRS API response includes `action: "allow"`, the request will be allowed to proceed to the language model.

You can monitor scan logs and verdicts within the Strata Cloud Manager to verify that the integration is active and enforcing your security policies.

## Links

Docs: https://docs.truefoundry.com/ai-gateway/palo-alto-airs#palo-alto-prisma-airs-integration
