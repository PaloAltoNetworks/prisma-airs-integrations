# Prisma AIRS Integrations

Welcome to the central documentation repository for all integrations with Palo Alto Networks Prisma AIRS (AI Runtime Security).

## Overview

Prisma AIRS is a comprehensive AI security platform designed to protect the entire AI application lifecycle. It secures AI and traditional applications, agents, models, and datasets against a wide range of threats.

This repository contains step-by-step setup guides for integrating Prisma AIRS with various third-party MLOps, AI Gateway, and automation platforms. These integrations allow you to embed security directly into your AI workflows, enforcing policies and scanning for threats in real-time.

## Available Integrations

Below is a list of documented integrations. Each guide provides detailed prerequisites and configuration steps.

| Partner | Category | Documentation Link |
| :--- | :--- | :--- |
| **TrueFoundry** | AI Gateway | [./truefoundry/README.md](./TrueFoundry/README.md) |
| **LiteLLM** | LLM Gateway | [./litellm/README.md](./LiteLLM/README.md) |
| **Portkey** | AI Gateway & Observability | [./Portkey/README.md](./portkey/README.md) |
| **n8n** | Workflow Automation | [./n8n/README.md](./n8n/README.md) |

---

## Key Concepts

* **AI Runtime Security (AIRS):** A platform that provides inline, real-time security for AI applications, protecting against threats like prompt injection, malicious code, and sensitive data leakage.
* **Strata Cloud Manager:** The central management interface for configuring Prisma AIRS, including creating security profiles and generating API keys.
* **Security Profile:** A named configuration within Strata Cloud Manager that defines the specific threat detection rules and policies to be applied during a scan.
* **Guardrail:** A security control or policy implemented within a partner platform (like an AI Gateway) that leverages the Prisma AIRS API to scan and validate requests and responses.

## External Resources

* [Prisma AIRS Developer Documenation](https://pan.dev/airs)
* [Prisma AIRS Adminstrator Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
