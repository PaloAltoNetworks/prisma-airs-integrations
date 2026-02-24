# n8n Integration with Prisma AIRS

This document provides instructions for using the Prisma AIRS community node within n8n to add a layer of security to your automation workflows. This node allows you to scan prompts and responses for threats directly within a workflow.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | "Prompt Scan" operation scans user input for threats |
| Response | ✅ | "Response Scan" operation scans AI-generated responses |
| Streaming | ❌ | Node processes complete responses after generation |
| Pre-tool call | ❌ | Workflow-based - not automatic tool interception |
| Post-tool call | ❌ | Tool result scanning not implemented |
| MCP | ❌ | MCP tools in workflows are not scanned by this node |

---

## Prerequisites

* An active n8n instance (Cloud or self-hosted) [Setup Docs](https://docs.n8n.io/hosting/installation/docker/).
* Instance owner permissions to install community nodes.
* An active Prisma AIRS license and access to the [Strata Cloud Manager](https://www.strata.paloaltonetworks.com/).
* A configured **AI Profile Name** within Strata Cloud Manager.
* A Prisma AIRS **API Key**.

---

## Configuration Steps

### Step 1: Install the Community Node

1.  Open your n8n instance.
2.  Navigate to **Settings → Community Nodes**.
3.  Search for `@paloaltonetworks/n8n-nodes-prisma-airs` or visit the [npm package page](https://www.npmjs.com/package/@paloaltonetworks/n8n-nodes-prisma-airs).
4.  Click **Install**.
5.  Restart your n8n instance if prompted for the installation to take effect.

### Step 2: Create Prisma AIRS Credentials

1.  In your n8n instance, go to the **Credentials** section from the left-hand menu.
2.  Click **Add Credential**.
3.  Search for and select **"Prisma AIRS API"**.
4.  Fill in the credential details:
    * **API Key:** Your Prisma AIRS API key (this is the `x-pan-token`).
    * **AI Profile Name:** The exact name of your configured AI security profile from Strata Cloud Manager.

### Step 3: Use the Prisma AIRS Node in a Workflow

1.  Create a new workflow or open an existing one.
2.  Click the `+` icon to add a new node.
3.  Search for **"Prisma AIRS"** and add it to your canvas.
4.  In the node's properties panel, select the credential you created in Step 2.
5.  Choose an **Operation** from the dropdown menu:
    * **Prompt Scan:** Scans user input/prompts for security threats.
    * **Response Scan:** Scans AI-generated responses for policy violations.
    * **Dual Scan:** Scans both a prompt and a response sequentially.
    * **Batch Scan:** Scans multiple items (up to 5) in a single operation.
    * **Mask Data:** Scans content and masks sensitive data found within it.
6.  Connect the input fields of the node (e.g., `Content`) to the output of previous nodes in your workflow using expressions.

---

## Verification

Run your workflow. The Prisma AIRS node will send the specified content to the AIRS API for scanning. The output of the node will contain the verdict from the API (`allow` or `block`), which you can use in subsequent nodes (e.g., an IF node) to control the workflow's logic.

You can monitor detailed logs of all scans and security events in your Strata Cloud Manager dashboard.

## Example Workflows
 
Find workflow templates in the `workflows` directory. Have a useful template to share? We welcome contributions via pull request!

## Links
 
Additional Information: https://n8n.io/integrations/prisma-airs/