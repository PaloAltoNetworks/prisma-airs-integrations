# Apigee X + Vertex AI + Prisma AIRS Architecture

## Network Architecture

**Deployment Model**: Non-VPC Peering + Private Service Connect (PSC)

This deployment uses Apigee's **modern, recommended pattern** where:
- ✅ **PSC is required** for all northbound traffic (clients → Apigee)
- ✅ **Test VMs can be in any VPC** - PSC enables cross-VPC/cross-project connectivity
- ✅ **No IP range allocation** needed during Apigee provisioning
- ✅ **Clean separation** between Apigee VPC and client VPCs

**Key Components:**
- **PSC Forwarding Rule**: `<PSC_IP_ADDRESS>` (client access point)
- **Service Attachment**: `<APIGEE_SERVICE_ATTACHMENT>` (Apigee side)
- **Apigee Runtime**: `<APIGEE_RUNTIME_IP>` in `<APIGEE_VPC>`
- **Test VM**: Any VPC (e.g., `default` VPC) with internal-only IP

**Reference**: [Apigee Networking Options](https://cloud.google.com/apigee/docs/api-platform/get-started/networking-options)

---

## Quick Reference: ASCII Flow Diagram

```
┌──────────┐
│  Client  │
└────┬─────┘
     │ POST /vertex
     │ {"contents":[{"role":"user","parts":[{"text":"..."}]}]}
     ▼
┌─────────────────────────────────────────────────────────────────┐
│                         APIGEE PROXY                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PREFLOW (Request Pipeline)                              │    │
│  │                                                         │    │
│  │ 1. [KVM-GetConfig]                                       │  │
│  │    ├─ private.airs.token                                 │  │
│  │    ├─ private.airs.profile                               │  │
│  │    ├─ private.vertex.project                             │  │
│  │    └─ private.vertex.model                               │  │
│  │                                                          │  │
│  │ 2. [JS-ScanPrompt] ─────────────────────────────────┐    │  │
│  │    Extract prompt & build AIRS payload              │    │  │
│  │                                                     │    │  │
│  │ 3. [AM-AIRSRequest]                                 │    │  │
│  │    Set X-Pan-Token: {private.airs.token}            │    │  │
│  │                                                     │    │  │
│  │ 4. [SC-AIRSScan] ────────────────────────┐          │    │  │
│  │    POST /v1/scan/sync/request            │          │    │  │
│  │    Timeout: 5000ms                       │          │    │  │
│  │                                          ▼          │    │  │
│  │                                    ┌──────────────┐ │    │  │
│  │                                    │ Prisma AIRS  │ │    │  │
│  │                                    │   (Prompt)   │ │    │  │
│  │                                    └──────┬───────┘ |    │  │
│  │ 5. [EV-AIRSVerdict] ◄──────────────────┘            │    │  │
│  │    Extract: action, category, redacted              │    │  │
│  │                                                     │    │  │
│  │ 6. [JS-ApplyPromptMasking]? (if redacted)           │    │  │
│  │    Replace prompt with masked version               │    │  │
│  │                                                     │    │  │
│  │ 7. Decision: action = "block"?                      │    │  │
│  │    ├─ YES → [RF-Block] → HTTP 400                   │    │  │
│  │    │         "Prompt blocked by Prisma AIRS"        │    │  │
│  │    └─ NO  → Continue to Target                      │    │  │
│  └────────────────────────────────────────┼────────────┘    │  |
│                                              ▼                 │
│  ┌───────────────────────────────────────────────────── ──┐   │
│  │ TARGET ENDPOINT                                        │   │
│  │                                                        │   │
│  │ [GoogleAccessToken] ──────────────────────┐            │   │
│  │  Auto-generate OAuth token                │            │   │
│  │  Scope: cloud-platform                    │            │   │
│  │  SA: ai-sec-jr@project.iam...             ▼            │   │
│  │                                    ┌──────────────┐    │   │
│  │                                    │  Vertex AI   │    │   │
│  │                                    │(Model Garden)│    │   │
│  │                                    └──────┬───────┘    │   │
│  │                                           │            │   │
│  └───────────────────────────────────────────┼────────────┘   │
│                                              ▼                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ POSTFLOW (Response Pipeline)                            │  │
│  │                                                         │  │
│  │ 8. [JS-ScanResponse] ────────────────────────────────┐  │  │
│  │    Extract response & build AIRS payload             │  │  │
│  │                                                      │  │  │
│  │ 9. [AM-AIRSResponseRequest]                          │  │  │
│  │    Set X-Pan-Token: {private.airs.token              │  │  │
│  │                                                      │  │  │
│  │ 10. [SC-AIRSResponseScan] ──────────────┐            │  │  │
│  │     POST /v1/scan/sync/request          │            │  │  │
│  │     Timeout: 5000ms                     │            │  │  │
│  │                                         ▼            │  │  │
│  │                                     ┌──────────────┐ │  │  │
│  │                                     │ Prisma AIRS  │ │  │  │
│  │                                     │  (Response)  │ │  │  │
│  │                                     └──────┬───────┘ │  │  │
│  │ 11. [EV-AIRSResponseVerdict] ◄─────────────┘         │  │  │
│  │     Extract: action, category, redacted              │  │  │
│  │                                                      │  │  │
│  │ 12. [JS-ApplyMasking]? (if redacted)                 │  │  │
│  │     Replace response with masked version             │  │  │
│  │                                                      │  │  │
│  │ 13. Decision: action = "block"?                      │  │  │
│  │     ├─ YES → [RF-BlockResponse] → HTTP 400           │  │  │
│  │     │         "Response blocked by Prisma AIRS"      │  │  │
│  │     └─ NO  → Continue to Client                      │  │  │
│  └──────────────────────────────────────────┼────────────────┘│
│                                             ▼                 │
└───────────────────────────────────────────────────────────────┘
     │ HTTP 200 OK
     │ {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
     ▼
┌──────────┐
│  Client  │
└──────────┘

LEGEND:
  [Policy]     = Apigee Policy Execution
  ────────►    = Data Flow
  {variable}   = Context Variable
  ?            = Conditional Execution
```

## Network Connectivity 

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Google Cloud VPC                             │
│                                                                     │
│  ┌──────────────────┐                                              │
│  │   Test VM        │                                              │
│  │  (Internal IP)   │                                              │
│  │                  │                                              │
│  │ <INTERNAL_IP>    │                                              │
│  └────────┬─────────┘                                              │
│           │                                                         │
│           │ curl -H "Host: <YOUR_HOSTNAME>"                        │
│           │      https://<PSC_IP_ADDRESS>/vertex                   │
│           │                                                         │
│           ▼                                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Private Service Connect (PSC) Endpoint                      │  │
│  │                                                               │  │
│  │  IP: <PSC_IP_ADDRESS>                                        │  │
│  │  Purpose: GCE_ENDPOINT                                       │  │
│  │  Target: Apigee X Runtime (Managed Tenant Project)          │  │
│  └────────┬─────────────────────────────────────────────────────┘  │
│           │                                                         │
│           │ Private connection (no internet egress)                │
│           │                                                         │
└───────────┼─────────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────────┐
│              Apigee X Runtime (Tenant Project)                    │
│              Managed by Google, Peered to Customer VPC            │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Apigee Proxy: vertex-simple                                │ │
│  │  BasePath: /vertex                                          │ │
│  │  Environment: eval                                          │ │
│  └────────┬────────────────────────────────────────────────────┘ │
│           │                                                       │
│           ├─────────────────────────────────────────────────┐   │
│           │                                                  │   │
│           ▼                                                  ▼   │
│  ┌──────────────────┐                           ┌──────────────┐ │
│  │  Encrypted KVM   │                           │ Google Auth  │ │
│  │  (private)       │                           │ (OAuth 2.0)  │ │
│  │                  │                           │              │ │
│  │ • airs.token     │                           │ Auto-gen     │ │
│  │ • airs.profile   │                           │ token for    │ │
│  │ • vertex.project │                           │ Vertex AI    │ │
│  │ • vertex.model   │                           │              │ │
│  └──────────────────┘                           └──────────────┘ │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
            │                                      │
            │ HTTPS (public internet)              │ HTTPS (Google internal)
            │                                      │
            ▼                                      ▼
┌─────────────────────────┐          ┌──────────────────────────────┐
│   Prisma AIRS API       │          │   Vertex AI API              │
│   (External Service)    │          │   (Google Cloud Service)     │
│                         │          │                              │
│ service.api.            │          │ us-central1-aiplatform.      │
│ aisecurity.             │          │ googleapis.com               │
│ paloaltonetworks.com    │          │                              │
│                         │          │ Project: Your GCP Project    │
│ • /v1/scan/sync/request │          │ Model: Enabled VertexAI Model Garden Model     
│                         │          │                              │
│ Auth: X-Pan-Token       │          │ Auth: OAuth 2.0 Bearer       │
│       (from KVM)        │          │       (auto-generated)       │
└─────────────────────────┘          └──────────────────────────────┘

NETWORK FLOW SUMMARY:
═══════════════════════════════════════════════════════════════════════

1. Test VM → PSC Endpoint (<PSC_IP_ADDRESS>)
   • Private VPC traffic, no internet egress
   • Uses Host header for routing: "<YOUR_HOSTNAME>"
   • TLS/HTTPS on port 443

2. PSC Endpoint → Apigee Runtime (Tenant Project)
   • Private Service Connect peering
   • Managed by Google, transparent to customer
   • No NAT, no public IPs

3. Apigee → Prisma AIRS (External)
   • HTTPS over public internet
   • Apigee NAT IP provisioning for egress
   • X-Pan-Token authentication (from KVM)
   • Efficient Security Profiles: Optimizing security profiles to focus on relevant threats can reduce unnecessary scanning and processing time.

4. Apigee → Vertex AI (Google Internal)
   • HTTPS over Google's internal network
   • OAuth 2.0 token auto-generated per request
   • Service account: <SERVICE_ACCOUNT>@<PROJECT>.iam.gserviceaccount.com
   • variable latency (LLM processing)

KEY POINTS:
───────────────────────────────────────────────────────────────────────
• Test VM has NO external IP (internal-only)
• All client traffic stays within VPC (PSC)
• Apigee handles external API calls (AIRS, Vertex)
• No hardcoded credentials anywhere in the flow
• KVM values encrypted at rest in Apigee
```

## Detailed Flow Diagram

```
┌────────┐      ┌────────┐      ┌─────┐      ┌──────┐      ┌────────┐
│ Client │      │ Apigee │      │ KVM │      │ AIRS │      │ Vertex │
└───┬────┘      └───┬────┘      └──┬──┘      └──┬───┘      └───┬────┘
    │               │              │            │              │
    │ POST /vertex  │              │            │              │
    │──────────────>│              │            │              │
    │               │              │            │              │
    │               │ Get config   │            │              │
    │               │─────────────>│            │              │
    │               │              │            │              │
    │               │ Config values│            │              │
    │               │<─────────────│            │              │
    │               │              │            │              │
    │               │ JS-ScanPrompt (extract)   │              │
    │               │──────┐       │            │              │
    │               │      │       │            │              │
    │               │<─────┘       │            │              │
    │               │              │            │              │
    │               │ Scan prompt  │            │              │
    │               │─────────────────────────>│              │
    │               │              │            │              │
    │               │ Verdict (allow/block)    │              │
    │               │<─────────────────────────│              │
    │               │              │            │              │
    │               │ [If blocked: HTTP 400]   │              │
    │               │              │            │              │
    │               │ Generate content (OAuth) │              │
    │               │────────────────────────────────────────>│
    │               │              │            │              │
    │               │ Response     │            │              │
    │               │<────────────────────────────────────────│
    │               │              │            │              │
    │               │ JS-ScanResponse (extract)│              │
    │               │──────┐       │            │              │
    │               │      │       │            │              │
    │               │<─────┘       │            │              │
    │               │              │            │              │
    │               │ Scan response│            │              │
    │               │─────────────────────────>│              │
    │               │              │            │              │
    │               │ Verdict (allow/block)    │              │
    │               │<─────────────────────────│              │
    │               │              │            │              │
    │ HTTP 200/400  │              │            │              │
    │<──────────────│              │            │              │
    │               │              │            │              │
```

## Authentication & Security Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CREDENTIAL SOURCES                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐                      ┌──────────────────┐        │
│  │  Encrypted KVM   │                      │  Service Account │        │
│  │                  │                      │                  │        │
│  │  ├─ airs.token ──┼──┐                   │  SA with IAM     │        │
│  │  ├─ airs.profile │  │                   │  aiplatform.user │        │
│  │  ├─ vertex.project  │                   │                  │        │
│  │  └─ vertex.model │  │                   └────────┬─────────┘        │
│  └──────────────────┘  │                            │                  │
│                        │                            │                  │
│                        ▼                            ▼                  │
│              ┌─────────────────┐          ┌─────────────────┐          │
│              │  X-Pan-Token    │          │  OAuth 2.0      │          │
│              │  Header         │          │  Bearer Token   │          │
│              └────────┬────────┘          └────────┬────────┘          │
│                       │                            │                   │
│         ┌─────────────┴─────────────┐              │                   │
│         │                           │              │                   │
│         ▼                           ▼              ▼                   │
│  ┌─────────────┐            ┌─────────────┐  ┌─────────────┐           │
│  │ Prompt Scan │            │Response Scan│  │  Vertex AI  │           │
│  │ (AIRS)      │            │ (AIRS)      │  │  API Call   │           │
│  └─────────────┘            └─────────────┘  └─────────────┘           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Policy Execution Order

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        REQUEST FLOW                                      │
└─────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐
  │ Request │
  └────┬────┘
       │
       ▼
  ┌─────────────────┐
  │ 1. KVM-GetConfig│
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ 2. JS-ScanPrompt│
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ 3. AM-AIRSRequest│
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ 4. SC-AIRSScan  │
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ 5. EV-AIRSVerdict│
  └────────┬────────┘
           │
           ▼
      ┌────────┐
      │ Block? │
      └───┬────┘
          │
    ┌─────┴─────┐
    │           │
   YES          NO
    │           │
    ▼           ▼
┌────────┐  ┌───────────────────┐
│HTTP 400│  │ GoogleAccessToken │
└────────┘  └─────────┬─────────┘
                      │
                      ▼
            ┌─────────────────┐
            │ Call Vertex AI  │
            └────────┬────────┘
                     │
┌────────────────────┴────────────────────────────────────────────────────┐
│                        RESPONSE FLOW                                     │
└─────────────────────────────────────────────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ 6. JS-ScanResponse   │
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ 7. AM-AIRSRespRequest│
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ 8. SC-AIRSRespScan   │
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ 9. EV-AIRSRespVerdict│
          └──────────┬───────────┘
                     │
                     ▼
                ┌────────┐
                │ Block? │
                └───┬────┘
                    │
              ┌─────┴─────┐
              │           │
             YES          NO
              │           │
              ▼           ▼
          ┌────────┐  ┌────────┐
          │HTTP 400│  │HTTP 200│
          └────────┘  └────────┘
```

## Security Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 1: NETWORK                                                        │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Private Service Connect (PSC) - No public internet exposure         │ │
│ └───────────────────────────────────┬─────────────────────────────────┘ │
│                                     │                                   │
│                                     ▼                                   │
│ Layer 2: API GATEWAY                                                    │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Apigee X - Policy enforcement, rate limiting, auth                  │ │
│ └───────────────────────────────────┬─────────────────────────────────┘ │
│                                     │                                   │
│                                     ▼                                   │
│ Layer 3: SECRETS                                                        │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Encrypted KVM - No hardcoded credentials                            │ │
│ └───────────────────────────────────┬─────────────────────────────────┘ │
│                                     │                                   │
│                                     ▼                                   │
│ Layer 4: AI SECURITY                                                    │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Prisma AIRS - Prompt injection, DLP, toxic content detection        │ │
│ └───────────────────────────────────┬─────────────────────────────────┘ │
│                                     │                                   │
│                                     ▼                                   │
│ Layer 5: LLM                                                            │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Vertex AI - OAuth 2.0 authenticated, Google-managed                 │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Points

### Authentication Mechanisms
1. **Apigee → Vertex AI**: GoogleAccessToken policy (OAuth 2.0)
   - Runtime SA: `sa-with-correct-role@<project>.iam.gserviceaccount.com`
   - IAM Role: `roles/aiplatform.user`
   - Token auto-generated per request

2. **Apigee → Prisma AIRS**: X-Pan-Token header
   - Stored in encrypted KVM: `airs.token`
   - Retrieved once per request in PreFlow
   - Used for both prompt and response scans

### Correlation ID (tr_id)
- **Priority 1**: `X-Session-ID` header (client-provided)
- **Priority 2**: Apigee `messageid` (auto-generated)
- **Same tr_id** used for both prompt and response scans
- Enables log correlation in Prisma AIRS console

### Blocking Logic
- **Prompt Scan**: Blocks BEFORE calling Vertex AI
- **Response Scan**: Blocks AFTER Vertex AI generates content
- Both return HTTP 400 with descriptive error message
- Fail-closed design: Blocks if AIRS is unreachable

