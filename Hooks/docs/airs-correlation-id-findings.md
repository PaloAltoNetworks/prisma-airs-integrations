# Prisma AIRS correlation-id behaviour — live test findings

**Date:** 2026-08-10 · **Tenant:** live (`service.api.aisecurity.paloaltonetworks.com`) ·
**Endpoint:** `POST /v1/scan/sync/request` · **Profile:** `apigee-delay-optimization` ·
**Method:** 8-variation matrix, sentinel-prefixed ids, each verified against the
`GET /v1/scan/results?scan_ids=…` store. Reproducible: `airs-corr-matrix.py`.

**Why this matters for Cursor:** Cursor hands the hook a **`conversation_id`** (a stable
per-conversation id) and **no per-turn id**. In Palo terms `conversation_id ≈ session_id`.
This test settles exactly how AIRS treats `session_id` vs `transaction_id` vs the legacy
`tr_id`, so we wire Cursor (and everyone else) to the right field.

---

## The raw matrix (what we sent → what AIRS echoed)

Sentinel prefixes: `SID-*` = our `session_id`, `TXNID-*` = our `transaction_id`,
`TRID-*` = our `tr_id`, `pan_*` = server-minted (ours ignored).

| # | sent session_id | sent transaction_id | sent tr_id | **resp.transaction_id** | **resp.session_id** | **resp.tr_id** |
|---|:--:|:--:|:--:|:--|:--|:--|
| V0 | — | — | — | `pan_…` (minted) | `pan_…` (minted) | = session_id |
| V1 | ✓ | — | — | `pan_…` (minted) | **ours** (SID) | = session_id |
| V2 | — | ✓ | — | **ours** (TXNID) | `pan_…` (minted) | = session_id |
| V3 | — | — | ✓ | `pan_…` (minted) | **our tr_id** (TRID) | = session_id |
| V4 | ✓ | ✓ | — | **ours** (TXNID) | **ours** (SID) | = session_id |
| V5 | ✓ | — | ✓ | `pan_…` (minted) | **session_id wins** (SID) | = session_id |
| V6 | — | ✓ | ✓ | **ours** (TXNID) | **tr_id → session** (TRID) | = session_id |
| V7 | ✓ | ✓ | ✓ | **ours** (TXNID) | **session_id wins** (SID) | = session_id |

Every response field is also **persisted** and returned verbatim by the Scan-Results-by-ID
API (keys: `scan_id, report_id, session_id, transaction_id, tr_id, source, action, category,
prompt_detected, response_detected, tool_detected, …`).

---

## The model: AIRS has **two** correlation slots under **three** field names

**Slot 1 — Transaction (per-request/per-turn)** → response/stored `transaction_id`
- Filled **only** by the request's `transaction_id`.
- The request's `tr_id` does **not** feed it (V3, V5 → minted `pan_…`).
- Omitted → server mints a `pan_…` value.

**Slot 2 — Session (per-conversation)** → response/stored `session_id` **and** `tr_id`
- `resp.tr_id` is **always identical to `resp.session_id`** — 8/8 rows. `tr_id` is a **legacy
  mirror of the session slot**, not a transaction field.
- Fill precedence: **request `session_id` › request `tr_id` › minted `pan_…`**
  (V5 & V7 prove `session_id` beats `tr_id`; V3 & V6 prove `tr_id` fills it when `session_id`
  is absent; V0 & V2 mint it when neither is sent).

### Extracted rules

```text
resp.transaction_id = req.transaction_id            else  pan_…      (req.tr_id NEVER feeds this)
resp.session_id     = req.session_id  else req.tr_id else  pan_…
resp.tr_id          = resp.session_id               (always — legacy alias)
```

---

## Correction to prior belief

The earlier note "**`tr_id` is the stale field the live API ignores — send `transaction_id`**"
was directionally right about the *transaction* slot but **incomplete**: `tr_id` is **not
ignored**. On the deployed API `tr_id` is a **legacy alias of `session_id`** — as a request
field it's a *fallback source for the session slot*, and as a response field it always mirrors
`session_id`. It has nothing to do with `transaction_id`.

**Consequence for `tr_id`-only integrations** (repo's old `Cursor/.cursor/hooks/prisma-airs.sh`
and PR #59): their per-request `tr_id` lands in the **session slot**, so `transaction_id` is
minted random **and** — if that `tr_id` is unique per turn — every turn becomes its own
singleton "session," breaking conversation grouping. Wrong for *both* purposes, not just the
transaction one.

---

## What to wire (recommendations)

1. **Cursor `conversation_id` → AIRS `session_id`.** ✅ Correct — it's the session slot, it's
   stored, and it groups the conversation. This is already what our engines do: each agent's
   own session field maps to `session_id` (Cursor `conversation_id`, Cline `taskId`, Claude
   Code / Codex `session_id`, Gemini CLI `conversationId`), falling back to a working-directory
   hash. (The bash/PowerShell engines resolve this via one union chain; the Node.js engine maps
   it per-adapter — same result.)
2. **`transaction_id` is a separate per-turn slot.** Cursor exposes no per-turn id, so it will
   be **minted (`pan_…`)** unless we synthesize one. *Improvement to consider:* for Cursor,
   synthesize a per-call UUID for `transaction_id` instead of the current fallback
   `transaction_id = session_id` — otherwise `transaction_id` is constant across a
   conversation and can't distinguish turns. (Minting is acceptable; synthesizing gives us a
   client-side handle.)
3. **Never send `tr_id` for per-turn correlation.** It's the session mirror. Anyone still on
   `tr_id`-only (PR #59, old repo hook) should switch to explicit `session_id` + `transaction_id`.
4. All AIRS-owned ids (`scan_id`, `report_id`) are server-generated regardless of what we send.

---

## Reproduce

```bash
export PRISMA_AIRS_API_KEY=…  PRISMA_AIRS_PROFILE_NAME=…   # your tenant + profile
python3 docs/airs-corr-matrix.py            # prints the matrix + Scan-Results store, writes JSONL
```
Raw per-variation request/response/stored records: `airs-corr-results.jsonl`.
