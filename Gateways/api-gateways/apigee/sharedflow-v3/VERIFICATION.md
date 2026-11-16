# Verification record: PANW-AIRS v3, phases 1 to 3, and v3.1

This page records each phase 1, 2 and 3 claim about v3's behavior, and each v3.1 claim (OAuth 2.0 tokens toward Prisma AIRS), the result, and where it was measured. A claim that no real client or Prisma AIRS tenant can produce on demand is proven by unit tests only, and is marked so below. No mock stood in for Prisma AIRS in any live row.

## Environments

- **Apigee:**
  - an Apigee X evaluation organization, runtime 1-18-0-apigee-8, in an environment of its own, 9 to 15 November 2026; v3.1 on 16 November, on runtime 1-18-0-apigee-9, two runtime instances;
  - the SharedFlow deployed as `PANW-AIRS-v3`, with a service account, since its log step writes to Cloud Logging;
  - reached over Private Service Connect from a VM in the same Google Cloud project.
- **Lab proxies:**
  - the main lab proxy calls v3's request leg from each TargetEndpoint's PreFlow and its reply leg from the proxy's response flow;
  - a second is the same with `applyDlpMasking=true`;
  - a third is the same with the setting `failOpen=maybe`, for the strict-settings rows;
  - a fourth is the same with `truncationFailClosed=false`, as a proxy for Claude Code sets it;
  - a fifth is the same with `allowOpenStreams=true`, for phase 2's open-stream rows;
  - for the review of phase 2: one whose MCP target counts 4xx and 5xx as success (`success.codes`); one with `failOpen=true` whose request leg's scan goes to a host that doesn't resolve while its reply leg's goes to Prisma AIRS; and one that calls v3 on its reply leg only, with `type=both` and `maxScanChars=800`;
  - for MCP error replies: one that calls v3 on its reply leg only, with its MCP target counting 4xx and 5xx as success;
  - for phase 3: one proxy per operations setting (monitor mode, a retry, a circuit breaker, a verdict cache), the retry's and breaker's request-leg scan sent to a regional host name that doesn't resolve; v3's two flow-hook SharedFlows; and small probes for the platform facts L18 to L21;
  - a proxy with no target measures what the flow sees around ServiceCallouts (L10, L14, L15);
  - for v3.1: one in bearer mode (`prismaAirsAuthMode=bearer`); one with an unknown mode and `failOpen=true`; one in bearer mode that sets the token's variable itself; and a copy of the SharedFlow that reads a second config map (the real key and a made-up token), called by four proxies: three in bearer mode (one with the shipped defaults otherwise, one with `failOpen=true`, one in monitor mode) and one in API-key mode on the request leg and bearer mode on the reply leg.
- **Models and servers:**
  - Vertex AI with Gemini 3.8 Flash, through its native `generateContent` and `streamGenerateContent` endpoints and its OpenAI-compatible Chat Completions endpoint;
  - Claude on Vertex, Claude Haiku 5.5 (`claude-haiku-5-5`), through `rawPredict` and `streamRawPredict` on the global endpoint;
  - an MCP server built with the MCP Python SDK 1.30.0 on Cloud Run, with JSON and event-stream routes.
- **Prisma AIRS:** US region. The lab security profile blocks prompt injection and sensitive data, and returns a masked copy. v3.1's OAuth 2.0 token was made by hand in Strata Cloud Manager from the lab's API key, with a lifetime of one day.
- **Clients:** Python 3.11 with httpx 0.28.1, the OpenAI SDK 3.48.0, the Google Gen AI SDK 3.0.0 and the Anthropic SDK 2.7.0, and Claude Code 2.1.321, on the VM.
  - Claude Code can't trust the lab endpoint's certificate, because the endpoint sends only its leaf certificate. It reached Apigee through a bridge on the VM, listening on 127.0.0.1 only, which checks that certificate and passes each request through unchanged.
- **Unit:**
  - **v3:** `node test/run.js --v3`, 950 cases with v3.1's (911 before it), on an offline emulator that runs the SharedFlow's own XML and JavaScript. Each case names a Prisma AIRS reply recorded from the lab's tenant. The emulator gives a new response message status 200 and no body, as Apigee does (L14), and empties the variable of a config map entry that isn't there (L26). `--auth=bearer` runs the same cases in bearer mode: 910 pass, and the 40 about the key or the mode itself are left out.
  - **V2:** `node test/run.js` runs V2's bundle, which shows all 48 defects that have a V2 case.

**When it ran:**
- **Before the fixes** (00:55 to 01:55 UTC): rows G3, G4, G6, G9 and G12, and SDK2.
- **After them, on revisions 4 to 6** (04:32 to 05:02 UTC): every other row.
- **On revision 10,** with the leg check and the empty-reply rule: LEGL0 to LEGL2, and again M1 to M4, G10, G11, U1, every row of the A*v3 set, GL1 to GL6 and EX1 to EX3, each with the result it had before.
- **On revision 10, with Claude on Vertex** (17:20 to 17:37 UTC): C1, C2, C5, C6, C8, C9, A02v3c, SDK3 to SDK5, and the Claude Code session.
- **On 14 November, revision 12** (23:42 to 23:44 UTC): SZ2 and SZ3; again LEGL0 to LEGL2 and every row of the A*v3 set, each with the result it had before; and the long Claude Code session, through the proxy with `truncationFailClosed=false`.
- **On 15 November, revision 14,** with phase 2 (00:20 to 00:25 UTC): the P2 rows; again M1 to M4, G10, G11, U1, every row of the A*v3 set, LEGL0 to LEGL2, GL1 to GL6 and SZ3, each with the result it had before.
- **On 15 November, revisions 15 and 16,** with the fixes from the review of phase 2 (02:05 to 02:08 UTC, and 02:50 to 02:55 UTC): the P2F rows; again the P2 rows, M1 to M4, G10, G11, U1, every row of the A*v3 set, LEGL0 to LEGL2, GL1 to GL6 and SZ3: 44 rows, each with the HTTP status, JSON-RPC code and refusal it had on revision 14. On revision 16, P2O1's first run got no response headers from the MCP server within its 10 s window (the server's GET stream did the same through the plain proxy, P2G1); run again, it matched.
- **On 15 November, revision 17,** with MCP error replies scanned (09:10 to 09:12 UTC): the P2N rows; again P2F1 to P2F11, the P2 rows, M1 to M4, G10, every row of the A*v3 set, LEGL0 to LEGL2 and GL1 to GL5, each with the result it had before but P2F5, whose reply leg now scans (P2N3). The rows that reach a model (GL6, G11, U1, SZ3) were not rerun: the change can't reach LLM traffic.
- **On 15 November, revision 18,** with the fixes from the review of that change (09:36 UTC): P2N0 to P2N6, and again P2F1 to P2F11, the P2 rows, M1 to M4, G10, every row of the A*v3 set, LEGL0 to LEGL2 and GL1 to GL5: each with its revision 17 result but P2N6, the fix (on revision 17, at 09:35 UTC: HTTP 200 with id 0).
- **On 15 November, revision 19,** with phase 3 (11:12 to 11:21 UTC): the operations rows (MON, RT, BK, VC) and the hook-mode rows (HM); again P2N0 to P2N6, P2F1 to P2F11, the P2 rows, M1 to M4, G10, every row of the A*v3 set, LEGL0 to LEGL2 and GL1 to GL5: all 60 as on revision 18.
- **On 15 November, revision 20,** with the fixes from the review of phase 3, and the hook SharedFlows passing one parameter (12:59 to 13:11 UTC): BK5, HM7 and HM8; again the operations rows, HM1 to HM6, P2N0 to P2N6, P2F1 to P2F11, the P2 rows, M1 to M4, G10, every row of the A*v3 set, LEGL0 to LEGL2 and GL1 to GL5: all as on revision 19.
- **On 15 November, revision 21,** with the fixes from the second review (13:44 to 14:12 UTC): HM9; again HM1 to HM8, BK5 and the operations rows, and the 60 regression rows: all as on revision 20. Two first attempts at the operations rows met the lab's own text, not v3: a timestamp the profile masks as a data pattern, then one spelled in letters that it flags as toxic (Test inputs); their results were set aside.
- **On 16 November, revision 22,** v3.1 (08:11 to 08:39 UTC): the 60 regression rows with the config map as it was, each as on revision 21; OO1, OA6 and OB1 to OB4, which need no token; with the key in the map made up, OA1 to OA5 and a Debug session of them; the renewal on a second map; the 60 rows again in bearer mode with no key in the map; then `deploy.sh` in bearer mode, and EX1 to EX3 through its example proxy.
- **On 16 November, revision 23,** with the fixes from the review of v3.1 (09:26 to 09:36 UTC): the 60 regression rows in API-key mode, each as on revision 22; OA1 to OA3 and OA6, each as on revision 22; then `deploy.sh`'s wait for a replaced token, and EX2.

## Test inputs

| Input | Text |
|---|---|
| Benign prompt | "What is the capital of France? Answer in one word." |
| Sensitive data | the standard Visa test card number, 4111 1111 1111 1111 |
| A reply carrying sensitive data | a prompt asking the model to write the digits 4111 followed by three groups of 1111 |
| Marker | `AIRSV3-MARKER` |
| A unique MCP text per run (the operations and hook rows, from revision 21) | "hello" and the run's timestamp as number words. A 10-digit timestamp can match a data pattern the lab profile masks ("Tax Id - UK - UTR": "hello 1794750001" came back allowed with a masked copy, so v3 refused it on MCP, as A24 says), and the timestamp spelled in letters was flagged `toxic_content` for three values in four (K5) |

## Requests: what gets read

Each row places the test card where v3 must read it. A block means Prisma AIRS judged the text, and the model was not called.

| Claim | Result |
|---|---|
| **Every user turn is scanned** | The card in an earlier user turn of a Gemini request: blocked on the request leg (G10). |
| **A conversation may end with anyone's message** | Chat Completions with the card in the user turn and an assistant prefill last: blocked (A02v3). The same in Anthropic Messages on Claude: blocked before Claude (A02v3c). Through V2, the same request reached Claude Haiku 4.5, and only V2's reply scan blocked the answer that repeated the card; Claude Haiku 5.5 refuses a prefill with HTTP 400 (A02-claude). |
| **The Responses API's string input** | The card in a plain-string `input`: blocked (A03v3). The allowed case needs a Responses endpoint, which the lab project lacks. |
| **No caller header turns scanning off** | `x-app: cli` with the card in the prompt: blocked (A04v3). |
| **Anthropic documents and search results** | The card in a text document, and in a `search_result` block, on Claude on Vertex's `rawPredict` path: blocked (A05v3a, A05v3b). Only the block was measured. |
| **Keys inside tool arguments** | The card as a key in MCP `tools/call` arguments: JSON-RPC `-32001` with the request id (A11v3). |
| **Inline text payloads are decoded** | A Gemini `inlineData` part, `text/plain`, base64, carrying the card: blocked (A28v3). |
| **The size limit** | A 200,000-character prompt: refused before any scan, in Gemini's format (G11). With the 100,000-character default: a Claude prompt of 100,001 characters of natural prose was refused before any scan, in Anthropic's format, in 266 ms (SZ3); one of exactly 100,000 was scanned whole in 1.6 s, allowed and forwarded to Claude (SZ2). Unit cases: 100,000 scanned, 100,001 refused (SIZE-1, SIZE-2). |

## What can't be read is not let through

| Claim | Result |
|---|---|
| **Unknown endpoints and trailing slashes** | An embeddings call: HTTP 403, refused (U1). A Chat Completions path with a trailing slash: refused (A12v3). |
| **Bodies that aren't JSON** | A form-encoded body at Gemini's path: refused (A13v3a). A deflate-compressed body carrying the card: Apigee decompressed it, v3 scanned it, and it was blocked (A13v3b). |
| **Duplicate keys** | Two `messages` keys in a streamed Chat Completions request: refused, as an event stream (GL5). |
| **A body the flow can't see** | An empty POST to Gemini's path: refused (GL4a). An empty chunked POST: refused, because `Transfer-Encoding` reaches the flow (GL4b). |
| **A path detail never picks the reader** | A model name containing "count-tokens", with the card in the prompt: scanned and blocked (GL1). Dot segments, plain and percent-encoded: the front end normalised them before the flow saw the path (GL2a, GL2b). |
| **A WebSocket upgrade is refused** | On the MCP route: JSON-RPC error with id null, HTTP 403 (GL3). The `Upgrade` header reaches the flow. |
| **Settings are read strictly** | With `failOpen=maybe`, every request was refused, with a message naming `failOpen` and never its value: in Gemini's format (A39v3a), and as JSON-RPC `-32003` with the request id (A39v3b). |
| **`type` must match the leg** | A reply-leg FlowCallout set to `user-prompt`: the request was scanned and forwarded, and the reply refused, `-32003` with "Check the setting: type (this step runs on the reply leg)" (LEGL1). A request-leg FlowCallout set to `both`: refused before the server, naming the request leg (LEGL2). A correctly placed pair: scanned on both legs and allowed (LEGL0), so the reply's status reads empty on the request leg and set on the reply leg. |

## Replies

| Claim | Result |
|---|---|
| **The reply is scanned** | A Gemini reply carrying the card: blocked on the reply leg (G5). A Claude reply carrying the card: blocked, answered as an Anthropic message (C5). A harmless Claude reply passed (C1). |
| **A stream is recognised by its Content-Type, never by "data:" in the text** | A reply starting with "data: " and carrying the card: blocked (G12). |
| **Streamed calls are scanned** | Streaming was turned off on the way to the model, the whole reply scanned, then sent back as one burst of the client's own stream: Gemini with `alt=sse` (G2), Chat Completions with `stream: true` (G4) and Claude's `streamRawPredict` (C2). A streamed reply carrying the card was blocked in the client's own stream format: Gemini events (G6), Chat Completions chunks (G7) and Anthropic events (C6). |
| **Real streaming SDKs read the one-burst reply** | The OpenAI SDK's `chat.completions.create(stream=True)`: 3 chunks, "Paris", before and after the fixes (SDK1). The Google Gen AI SDK's `generate_content_stream`: 1 chunk, "Paris" (SDK2). The Anthropic SDK's `messages.create(stream=True)` on Vertex: the whole event sequence, `message_start` to `message_stop`, "Paris" (SDK3). It read v3's blocks too: streamed, as the same event sequence carrying the block message (SDK4), and not streamed, as an ordinary assistant message (SDK5). |
| **Masking writes back exactly** | With `applyDlpMasking=true`, a reply carrying the card reached the client with the card masked as 19 X's (G8). The same for a streamed call, sent back as one event-stream burst (G9). The same on Claude, 19 X's (C8), and streamed (C9). |
| **Blocks to streaming clients are in their own format** | Gemini events (G6), Chat Completions chunks (G7), Anthropic events (C6, SDK4), and a JSON array for `streamGenerateContent` without `alt=sse` (GL6). The Responses API half needs a Responses endpoint. |
| **An LLM body that adds JSON-RPC members gets no skip** | Vertex answered such a body. v3 read the reply as text and scanned it. Prisma AIRS returned a masked copy with no detection flag, and v3 never rewrites MCP text, so the reply was withheld (GL7). |

## Claude Code

| Claim | Result |
|---|---|
| **A Claude Code session works through v3** | Claude Code 2.1.321 on Claude Haiku 5.5, a task that reads five short files and runs two commands: 8 turns by Claude Code's count, no error. Each of its 7 streamed calls was turned off toward Vertex, scanned on both legs, allowed, and sent back as one burst, which Claude Code read (v3's 14 log lines). It took 15.0 s, against 8.2 to 10.7 s in four runs through the lab's proxy that doesn't scan. |
| **Its `<system-reminder>` text is scanned as sent, and passes** | Through v3, all 14 scans of the session were allowed. In a run of the same task through the lab's proxy that doesn't scan, the one distinct reminder block, 580 characters, was allowed on its own, and so were each request's user turns and tool results (L9). Other reminders weren't measured. |
| **Each request carries the whole conversation** | v3's scan text grew from 9,999 to 32,647 characters over the 7 calls, about 4,400 per file read of 41 lines. Each request's scan text includes a 9,203-character message with role `system` that Claude Code sends inside `messages`, which v3 reads like a user turn. |
| **A long session, through a proxy that scans the newest part** | Through the proxy with `truncationFailClosed=false`, the same kind of task reading 12 files of natural prose (consecutive parts of a public-domain novel), about 10,000 characters each: 14 turns by Claude Code's count, no error, 53.9 s. v3's scan text grew from 10,085 to 96,108 characters over the first 9 of 14 calls, about 10,750 per file read. Each of the last 5 was scanned by its newest 100,000 characters, logged "scanned the newest 100000 characters", and allowed, and so were all 14 replies. The whole text reached about 140,000 characters by the last call, estimated from the request sizes. Request scans took 0.43 to 1.81 s. With the default, `truncationFailClosed=true`, the 10th call would have been refused before any scan, as too large, and the session would have stopped there. |

## MCP

| Claim | Result |
|---|---|
| **A clean tool call passes, both legs scanned** | `tools/call` with harmless arguments: allowed (M1). |
| **Arguments carrying sensitive data are refused, with the request id** | JSON-RPC `-32001`, id 22, HTTP 200 (M2). |
| **Every method is read** | A `tools/list` JSON reply with the card in a tool description: withheld (M3). |
| **Tool results are read in full** | A JSON `tools/call` result carrying the card: withheld (A19v3). |
| **Event-stream replies are withheld** | A `tools/call` answered as an event stream: JSON-RPC `-32001` with the id, because the flow can't see the stream's body (M4). |

## MCP, phase 2

| Claim | Result |
|---|---|
| **A `tools/list` answer is a tool event, and still catches a poisoned description** | The harmless catalogue: one tool event, its output the bare tools array, allowed (P2L1). The catalogue whose tool description carries the card: blocked as `tool_output.dlp`, `-32001` with id 42 (P2L2; M3 the same on revision 14). |
| **A batch is read member by member** | `[ping, tools/call with the card]`: one scan, blocked, and the whole batch refused before the server, `-32001` for ids 1 and 2 (P2B1). Three harmless calls: three scans, allowed and forwarded (P2B3). |
| **The first refusal stops the scans after it** | `[hello, card, hello]`: two scans, the second blocked; the third member was never scanned (v3's log: 2 scans); errors for ids 1, 2 and 3 (P2B4). |
| **A batch over `mcpBatchLimit` is refused before any scan** | 9 pings: 9 errors, "could not inspect this batch (more than 8 messages)", no scan, 17 to 38 ms (P2B5). |
| **`allowOpenStreams=true` passes open streams, unscanned and logged** | On the lab proxy with the setting: an MCP GET for an event stream got HTTP 200 and an event stream, logged on both legs as "an open stream passes unscanned (allowOpenStreams)" (P2O1); a `tools/call` answered as an event stream reached the client, logged "an MCP event-stream reply passes unscanned (allowOpenStreams)" (P2O2). Without it: 405 (P2O1g) and `-32001` (P2O2g). The setting opens no request: a call with the card was still blocked (P2O3). |
| **The key never shows in Debug, in any slot** | A Debug session of a three-member batch showed slots 1 to 3 running (revision 13), and one of an eight-member batch all 8, `SC-Airs3Scan` to `SC-Airs3Scan8` (P2F3, revision 15). The key's value appeared 0 times in either, and no entry was named `private.airs3_token` or `x-pan-token`. The Debug data was deleted on Apigee and locally. |
| **All 8 slots run, one after another** | Eight harmless `tools/call`: 8 scans, allowed and forwarded; the request leg took 2,083 ms, and the slots' callouts started 251 to 273 ms apart (P2F3). |
| **MCP text goes to Prisma AIRS as a prompt** | `resources/read` and `prompts/get` of the lab server's marked resource and prompt: withheld, `-32001`, and v3's reply-leg line says `prompt.dlp`: the server's text went as a prompt, where Prisma AIRS's injection detector reads (P2F1, P2F2). |
| **A member named `__proto__` is scanned on Rhino** | A `tools/call` whose arguments hold the card under `__proto__`: blocked as `tool_input.dlp` (P2F4). So Rhino's `JSON.parse` keeps such a member as an own member (L17). |
| **A failed scan on the request leg doesn't hide the reply's verdict** | `failOpen=true`, the request leg's scan sent to a host that doesn't resolve, the reply leg's to Prisma AIRS: the request passed, failed open, and a tool result carrying the card was still withheld, `tool_output.dlp` (P2F6; L15). |
| **An MCP error reply is scanned, when the proxy counts it as success** | The lab server answers a message it can't validate with HTTP 400 and a JSON-RPC error that quotes the refused value. Through a proxy that calls v3 on its reply leg only, with `success.codes` counting 4xx and 5xx: a 400 quoting the card was withheld, `-32001` with id 71, and v3's line says `prompt.dlp` (P2N1); a harmless one was scanned once, allowed, and reached the client unchanged (P2N2). The batch 400 that revision 16 logged as "a non-2xx reply is not scanned" (P2F5) is scanned and allowed on revision 17 (P2N3). With Apigee's default `success.codes`, v3's reply leg didn't run (P2N4, as P2F5g) (L16). |
| **A refused client reply has no id to answer** | The client's own JSON-RPC reply (id 0, no method) carrying the card: on revision 17, refused in HTTP 200 with id 0, the server's own id; on revision 18, `-32001` with id null in HTTP 403, as MuleSoft answers and as v3 answers a batch of client replies (P2N6). |
| **`type=both` on MCP judges the request with the reply** | On a proxy that calls v3 on its reply leg only: a harmless `tools/call` was judged once, by the reply's tool event, which carries the same arguments: 1 scan, allowed (P2F8). With `maxScanChars=800` and the card in an argument the tool ignores, the reply's tool event, about 1,000 characters, would go as the text of its result alone, so the request's own tool event was scanned too: blocked, `tool_input.dlp`, `-32001` (P2F9). |
| **`allowOpenStreams` on any MCP path** | On the lab proxy with the setting, `tools/call` answered as an event stream at `/mcp-marked`, a path that doesn't end in `/mcp`, passed unscanned, logged (P2F10). |
| **A large body is refused within the steps' time limits** | A 3.8 MB `tools/call` holding 150,000 small objects: refused as too large to inspect, `-32001`, after 4.4 s of v3's own work, not as a step that ran out of time (P2F11). A step that doesn't finish refuses the leg whatever `failOpen` says. |
| **A refusal before any scan says why in the log** | 9 pings: the line's note is the client's message, "could not inspect this batch (more than 8 messages)" (P2B5 on revision 15; on revision 14 the note was empty). |
| **The lab's MCP server refuses batches** | The MCP Python SDK 1.30.0 server answered a batch with HTTP 400, `-32602` "Validation error", on its JSON and event-stream routes alike (MCP 2025-06-18 has no batches). So a batch v3 forwards comes back as that 400 (P2B2, P2B3), and the reply-leg batch rules are unit only. |

## Phase 3: operations and flow hooks

| Claim | Result |
|---|---|
| **Monitor mode changes nothing the client receives** | `enforcementMode=monitor`: a `tools/call` with the card was forwarded and its echo returned; both legs logged `monitored_block`, with their detections. An MCP GET stream was not answered 405, and passed, logged `gap_unenforced` (MON1, MON2). |
| **A retry is one more call after no answer** | `scanRetries=1`, the scan sent to a host that doesn't resolve: the log line says `retries` 1, then the leg failed open (RT1). The same ServiceCallout ran twice in one leg (L15). |
| **The circuit breaker opens, skips Prisma AIRS, and reopens on a failed trial** | `breakerFailures=2`, `breakerCooldownS=30`: the second failure opened it; the next request made no call and failed open, logged "the circuit breaker is open"; 31 s later one trial call was made, failed, and opened it again (BK1 to BK4). |
| **The verdict cache answers a repeated scan** | `verdictCacheTtlS=60`: the same `tools/call` twice; the second was answered from the cache on both legs, `cached` 1, with the first call's scan ids, in 59 ms against 583 ms (VC1, VC2). |
| **Hook mode scans only the listed proxies, and refuses from inside the hook** | v3's hook SharedFlows on the pre-target and post-target hooks, airs_hook listing two base paths: on a proxy with no FlowCallout, the card was refused on the request leg and a tool result with the card withheld on the reply leg; a proxy not listed was untouched, with no log line (HM1 to HM4). |
| **Never twice** | On a listed proxy with its own FlowCallouts, each leg was scanned once: the hook passed the request leg the FlowCallout had scanned, and the FlowCallout passed the reply leg the hook had scanned (HM5). |
| **Streaming is turned off from the pre-target hook** | A Gemini `streamGenerateContent` through the hooks: destreamed, the reply scanned by the post-target hook, and the client's event stream sent back (HM6, L21). |
| **An open breaker with failOpen turns streaming off and back on** | A Gemini `streamGenerateContent?alt=sse` through the breaker's proxy while it was open: the request passed with no call ("failed open: the circuit breaker is open") and went out with streaming off; the reply was scanned and came back as the client's event stream, with the marker (BK5, revisions 20 and 21). |
| **The hook SharedFlows pass one parameter** | With `hookMode=request` and `hookMode=response` and no `type`, HM1 to HM6 gave the results they had on revision 19 (revisions 20 and 21). |
| **Never twice marks only a leg a run enforced a verdict on** | airs_hook in monitor mode, `resources/read` of the marked resource through a listed proxy with its own FlowCallouts: the post-target hook logged `monitored_block` and passed the reply, and the proxy's reply-leg FlowCallout scanned it itself and withheld it, -32001 (HM7). Through a proxy with no FlowCallout, the card passed, logged `monitored_block` by the hooks (HM8). |
| **A later run on a reply an earlier run put back into the stream reads the JSON it kept** | The same, a Gemini stream through the listed proxy: the post-target hook scanned the reply and put it back into the client's stream; the proxy's reply-leg FlowCallout found the hash of what the hook had sent, read the JSON (its line says `stream` none, not `event-stream-reply`), scanned it and put it back again; the client got its event stream (HM9, L22). |
| **LLM replies outside 2xx carry no model text (A31)** | The error replies the lab met from Vertex's OpenAI-compatible endpoint, the Responses path and Claude on Vertex hold the platform's own message, never text the model wrote; so they pass unscanned, logged, as in MuleSoft. |

## The key and the call to Prisma AIRS

| Claim | Result |
|---|---|
| **The key never shows in Debug** | With the scan request held in a message with a plain name (revision 5), Debug showed the key's value where the AssignMessage set the `x-pan-token` header: 3 times in 2 transactions. With the message named `private.airs3_scan` (revision 6), the key appeared nowhere, and the scans worked as before. Checked by searching the Debug session's data for the key's value, printing only where it appeared; the Debug data was deleted afterwards. |
| **Strict certificate checks** | Every live scan ran with `SSLInfo` `Enforce=true`. With it, a self-signed certificate was refused; without `SSLInfo`, as V2 has it, the same certificate was accepted (L5). |

## v3.1: OAuth 2.0 tokens

| Claim | Result |
|---|---|
| **An upgrade with no OAuth entries changes nothing** | Revision 22 with the config map as it was, with no `airs_bearer` and no `airs_auth_mode`: the 60 regression rows gave the HTTP status, `x-airs-*` headers and body they had on revision 21, row for row. |
| **The token alone authenticates** | With the key in the map replaced by a made-up value, a proxy in API-key mode got HTTP 403 from Prisma AIRS (six calls). Through a proxy in bearer mode at the same time, a harmless `tools/call` was scanned on both legs and allowed (OA1), a batch of 8 got 8 scans and was forwarded (OA3), and a Gemini prompt with the marker was allowed on both legs (OA4). Each log line says `auth` `bearer`, with Prisma AIRS status 200. Prisma AIRS refuses a token sent beside a wrong key (K6), so the key wasn't sent. |
| **Blocks are the same in bearer mode** | The card in a `tools/call`: blocked on the request leg, never forwarded (OA2). A Gemini reply carrying the card: blocked on the reply leg (OA5). |
| **Each scan carries the token and nothing else** | In a Debug session of OA1 to OA5, by each step's condition result, the token's step ran before each of the 15 calls, in slots 1 to 8 for the batch, and the key's step never ran. |
| **The token never shows in Debug** | In the same 5 transactions, the token appeared nowhere, whole or in any 16-character piece, raw or JSON-escaped, and neither did the key. Debug showed no `Authorization` header and no variable holding the token (see also L23). The session's data was deleted afterwards. |
| **A rejected token is a scanner failure** | Through a copy that reads a second map holding a made-up token, Prisma AIRS answered 403. The request was refused, "could not scan this request", logged `failure` with "Prisma AIRS rejected the OAuth token (HTTP 403): it is wrong or expired, or its API key expired" (OB1). With `failOpen=true`, the call passed, and both legs logged that note after "failed open:" (OB2). In monitor mode it passed, logged `failed_open` (OB4). |
| **The mode can differ by leg** | A proxy whose request leg uses API-key mode and whose reply leg uses bearer mode, on the second map: the request leg was allowed with the key and forwarded; the reply leg's scan was refused for the made-up token, and the reply was withheld (OB3). |
| **A configuration problem refuses before any scan, even with failOpen** | `prismaAirsAuthMode=oauth` with `failOpen=true`: refused, naming the setting (OA6). Bearer mode with no `airs_bearer` in the map: refused, naming the entry, and not forwarded, though the proxy had set the token's variable itself; v3 empties it, and only the config map fills it (OO1, without `failOpen`; the same with `failOpen=true` is a unit case). |
| **Renewal by hand needs no redeploy** | `deploy.sh --bearer-only` replaced the second map's made-up token with the real one. One runtime instance used the new token at once. The other kept sending the old one until 300 s after its own last read of the map (L24), so calls were mixed for 80 s. From then on, every call was allowed. |
| **OAuth alone** | With `airs_auth_mode=bearer` in the config map and `airs_token` deleted from it more than five minutes before: the 60 regression rows gave the results they had in API-key mode, row for row, but one that goes to a lab probe outside v3, which reads the key itself. v3's log lines were the same in number and outcome, each saying `auth` `bearer`. |
| **`deploy.sh` installs bearer mode from scratch** | With `AIRS_AUTH_MODE=bearer`, a token and no key in its env file, the packaged `deploy.sh` created the config map, wrote the token before the mode, and deployed the SharedFlow and the LLM example proxy, each READY. Through that example, the smoke test's harmless prompt was allowed, its card prompt was blocked before the model, and a harmless `alt=sse` stream was turned off, scanned and sent back as an event stream (EX1 to EX3), each logged `auth` `bearer`. Run again, with the fix from the review of v3.1, over that map with its mode entry removed and its token kept: it wrote the token, deployed the SharedFlow and the example, and wrote the mode last, 313 s after the token. The card prompt was then blocked, logged `auth` `bearer` (EX2). Offline, against stand-ins for gcloud, curl and sleep, it waited whenever the map held a token, or answered unclearly, and the run switched the map's mode or flow hooks' settings to bearer; and not for a first token, a mode already bearer, or none given. |

**Compared with APIM's v2.2.0 fragment,** which v3.1 follows for the mode setting, the single credential header and the token's rule:
- v3.1 refuses every request on a configuration problem, even one with nothing to scan, where APIM fails only the requests it would scan;
- v3.1 checks the token as it is stored, where APIM trims it first, so `deploy.sh` drops the whitespace around a token before it stores it;
- v3.1 has a monitor mode, which passes a request with a configuration problem and logs it (`config_unenforced`).

## Deployment and the example proxy

| Claim | Result |
|---|---|
| **`deploy.sh` deploys everything it names** | The config map, the SharedFlow and the LLM example proxy, with the SharedFlow's and the map's names overridden as its options allow. Each deployment was reported READY. |
| **The key and the token never reach a command line** | `deploy.sh` refuses `--airs-token` and v3.1's `--airs-bearer`, and reads the key and the token only from its env file or the environment. It hands each to jq through jq's environment and to curl on standard input, so no process's command line holds it. That version wrote the config map live (revision 10's run), and v3.1's wrote the token the same way (16 November). With no valid gcloud session, it stops at once and says to sign in again. |
| **The LLM example proxy works as shipped** | The smoke test's harmless prompt was allowed (EX1). Its prompt with the test card was blocked before the model (EX2). A harmless `alt=sse` stream was turned off, scanned, and sent back as one event-stream burst (EX3). The example sets `target.url` only through its TargetEndpoint's URL, the form most proxies use. |

## Logging

| Claim | Result |
|---|---|
| **One line per leg, never content or keys** | v3's own lines, written from inside the SharedFlow, landed in Cloud Logging (log `panw-airs`), blocks included. Each line has the ids, the outcome, the detections, the scan id and a note, and no scanned text. |

## Unit tests only

These can't be produced on demand by a real client or tenant, or can't be produced on this runtime:
- **every choice of a reply,** when only one choice carries the text: a model can't be made to put it in one choice only;
- **event streams rebuilt event by event:** this runtime never shows the flow an event stream's body, so v3 turns streaming off instead;
- **Gemini's grounding, citation and URL-context sources:** they can't be made to carry a flagged item on demand;
- **an allow that reports a detector error or a time-out, and any other unclean verdict:** the tenant can't be made to send one;
- **each scan starts clean:** no state from the request leg decides the reply. Apigee's side of it is measured: a new response message has status 200 and no body (L14), and a callout's failed flag is reset when it runs again and gets an answer (L15);
- **reply arrays (phase 2):** each answer matched to its request member by its id as a JSON value, the messages that answer no member scanned together after the answers, a block on a later answer, and a reply that would need more than 8 scans: no current MCP server sends a batch reply;
- **a retry after HTTP 429 or a 5xx:** the tenant can't be made to answer either; the retry after no answer ran live (RT1), and the same rule decides all three;
- **hook mode's settings from `airs_hook`:** the live rows used an empty settings object and `enforcementMode=monitor`; the other settings are read by the same strict code as a proxy's;
- **a step cut by its time limit:** `JS-Airs3Init` or `JS-Airs3CacheKeys` cut mid-way (the reset that makes a cut run refuse, and the cache that then reads and writes nothing) can't be produced on demand; the suite stands in for the cut;
- **monitor mode's passes decided after the verdict steps:** a refusal before any verdict, on a call v3 turns streaming off for, then de-streamed and re-streamed after `JS-Airs3Respond`; and an MCP batch whose every member is over the size limit, logged `gap_unenforced`;
- **never twice, the other cases:** a run that scanned only part of the text (`truncationFailClosed=false`) or let a gap pass leaves the leg to the other run; a reply the proxy changed after the hook's re-stream is read as the event stream it is and passed as it is; a request-leg refusal after an earlier run turned streaming off goes back in the client's stream format;
- **a de-streamed reply v3 can't read, under `onScanError=allow`:** it passes as the model sent it, not re-streamed;
- **an empty HTTP 200 reply with `Content-Length: 0` passes:** the lab's MCP server keeps no sessions, so it answers a `DELETE` with 405. A server that keeps sessions answers it with 200 and no body (the Python MCP SDK 1.30.0 does).
- **v3.1, a token v3 can't send** (empty, over 4,096 characters, or with a space or a control character), **and a mistyped `airs_auth_mode` in the map:** each refused, naming the entry. These weren't run live, because the config map's 300 s cache would refuse every proxy in the environment for up to five minutes. `deploy.sh` refuses both before it writes anything; the unknown mode set by a proxy ran live (OA6);
- **v3.1, a config map that can't be read:** refused before any scan, even when the proxy had set the credential's variable itself. The message names the token's entry when the proxy sets bearer mode, and else the key's, since the map's own mode can't be read either; the suite stands in for the failure;
- **v3.1, the verdict cache and the circuit breaker in bearer mode:** both are keyed by the token where API-key mode uses the key. A verdict cached under the key isn't used in bearer mode, and a breaker opened in bearer mode is the token's. So a renewed token starts with no cached verdicts and a closed breaker; API-key mode's keys are unchanged;
- **MCP error replies to a request with no body:** with `type=both`, a `GET` or `DELETE` has nothing to judge, so its reply is scanned alone; and an event stream outside 2xx to such a request on an MCP route is withheld unless `allowOpenStreams` opens it. The lab's server sends neither an error reply that `type=both` at an `apiFormat=mcp` route would meet nor an event stream outside 2xx.

## Not yet measured live

- **The Responses API:** the lab project has no Responses endpoint. That leaves the allowed case, streamed tool-call arguments and the Responses block format.
- **v3.1, an expired token, a token whose API key has expired or been deleted, and a token sent to a Prisma AIRS host in another region:** Prisma AIRS's answer to an expired token hasn't been observed yet; v3.1 reads any HTTP 401 or 403 in bearer mode as a rejected token.

## Platform facts measured on Apigee

The code's comments cite these by id. L1 to L22 were measured on runtime 1-18-0-apigee-8, L23, L24 and L26 on 1-18-0-apigee-9.

| Id | What was measured |
|---|---|
| **L1** | **Event-stream replies:** the response flow sees the reply's headers, but `response.content` is empty, while the client still gets the whole stream. That held for Gemini with `alt=sse` and for an MCP server's event-stream replies. A `streamGenerateContent` reply without `alt=sse` arrives as one JSON array, which the flow reads whole. A RaiseFault in the response flow still stops an event-stream reply, and the client gets the refusal. **Turning streaming off:** from the TargetEndpoint's request flow, a SharedFlow can change the path and the body; from the ProxyEndpoint's, setting `target.url` has no effect. Claude's `streamRawPredict` replies behave the same: the flow saw no body (L1g), and with streaming turned off from the TargetEndpoint it read Claude's whole reply (L1f). |
| **L2** | **JavaScript time:** there is no fixed 200 ms cap. `timeLimit` is enforced when set. With `continueOnError=true`, a cut step ends silently, and only its unset done flag shows it; with `continueOnError=false`, Apigee answers HTTP 500. **Body size:** a 10.5 MB request got HTTP 413 before any step ran; 9.99 MB passed. |
| **L3** | **Compression:** the flow sees gzip bodies decompressed, on both legs, and a deflate request body decompressed too. |
| **L4** | **Duplicate keys:** with two top-level `contents` keys, Gemini answered from the second copy, the one `JSON.parse` keeps. |
| **L5** | **The call to Prisma AIRS:** with `SSLInfo` `Enforce=true` and no truststore of one's own, the scan works and a self-signed certificate is refused. With no `SSLInfo`, a self-signed certificate is accepted. |
| **L6** | **Flow variables** last the whole exchange: a 100,000-character value set on the request leg is read whole on the reply leg. Once a variable `x` holds a value, setting `x.y` is silently dropped. |
| **L9** | **A Claude Code session** (2.1.321, 7 model calls): its one distinct `<system-reminder>` block, 580 characters, and each request's user turns and tool results, 794 to 23,142 characters, were allowed by the lab's profile. L9 read role `user` messages only, so it left out the 9,203-character message with role `system` that Claude Code sends inside `messages`; v3's scans of the same task, which include it, were allowed (see Claude Code above). Apigee's Debug keeps only about the first 5 KB of a message body (each of these was cut at 5,124 bytes), so the bodies were read at the lab's bridge instead. |
| **L10** | **A failed ServiceCallout** with `continueOnError=true`: `servicecallout.<name>.failed` is `true`. When Prisma AIRS answered, its status and body stay readable: 400 for a prompt over 2,097,152 characters, 403 for a wrong key. With no answer (a time-out or a refused connection) there is no status at all, and `error.message` is empty. |
| **L11** | **Long harmless prompts:** with the lab's profile, natural prose (the opening of a public-domain novel) was allowed at 50,000, 87,500 and 100,000 characters. Text built from a few sentences used over and over was blocked as prompt injection and agent manipulation: sentences built from short word lists were allowed at 25,000, 50,000, 75,000 and 81,250 to 81,950 characters and blocked at 87,500 and 100,000; six sentences repeated in turn were allowed at 10,000 and blocked at 100,000; one sentence repeated was blocked at 50,000, with or without an instruction after it. Scans of 100,000 characters took 0.97 to 1.57 s. |
| **L12** | **Ids:** Prisma AIRS refuses a `transaction_id` or `session_id` over 100 characters with HTTP 400, so v3 skips such an id and uses the next source. |
| **L13** | **Logging:** a MessageLogging step writes one line per request to Cloud Logging, blocks included, when it runs as a service account that can write logs. From inside a SharedFlow, the SharedFlow must be deployed with that service account. |
| **L14** | **AssignMessage `createNew`** on a response message that held Prisma AIRS's HTTP 400: the new message has status 200 and an empty body. A ServiceCallout with a 1 ms timeout into it then leaves it at 200 with no body, with `servicecallout.<name>.failed` `true`. So a slot that gets no answer reads 200 and an empty body, never the other leg's answer, and v3 reads a failed call that shows a 2xx as no answer. |
| **L15** | **The failed flag across runs:** the same ServiceCallout policy run twice in one exchange, first to a host that doesn't resolve, then to Prisma AIRS: `servicecallout.<name>.failed` went from `true` to `false`. So the reply leg's scan is judged by its own call, whatever the request leg's did. |
| **L16** | **Non-2xx target replies:** with the default `success.codes`, the lab MCP server's HTTP 400 ran the error flow, and the ProxyEndpoint's response flow, where v3's reply leg runs, didn't run. With `success.codes` set to `1xx,2xx,3xx,4xx,5xx` on the TargetEndpoint, it ran. |
| **L17** | **Rhino and `__proto__`:** `JSON.parse` keeps a member named `__proto__` as an own member of the parsed object: v3's check for objects with another prototype didn't fire, and the member's text reached the scan. |
| **L18** | **Hashing in a SharedFlow:** `crypto.getSHA256()` is there; `digest()` gives hex and `digest64()` base64, both equal to a local SHA-256, non-ASCII text hashed as UTF-8. 100,000 characters took under 1 ms (phase 3, 15 Nov). |
| **L19** | **The cache in a SharedFlow:** LookupCache and PopulateCache work with the key and the expiry from variables (an expiry takes a value or a variable, not both). An entry written by one proxy through the SharedFlow is read by another with scope Exclusive as well as Global: a SharedFlow's cache is shared by every proxy that calls it. Expiry held (phase 3, 15 Nov). |
| **L20** | **The target flow hooks (a change reaches the runtime's instances one by one, so for some seconds requests may or may not see it):** the pre-target hook runs after the TargetEndpoint's request PreFlow, just before the call; the post-target hook just after the reply, before the TargetEndpoint's response flow. Neither gets a parameter; both see variables the proxy set; only the post-target hook sees a reply status. A RaiseFault inside either ends the request with its response, with the hook's `continueOnError` true or false; from the pre-target hook the server is never called. A proxy with no target runs neither. A hook change reaches the runtime 40 to 50 s after the API call (phase 3, 15 Nov). |
| **L21** | **Changing the call from the pre-target hook:** a change to `request.content` there reaches the server. `target.url` reads as the TargetEndpoint's URL without the request's path, and a URL set there is used as it is, the path suffix no longer added (setting the bare base gave HTTP 500, "Request path cannot be empty"). v3's de-stream step already writes the whole URL, path included (phase 3, 15 Nov). |
| **L22** | **A reply set in one SharedFlow run reads back unchanged in the next on the same leg:** after the post-target hook put a Gemini reply back into the client's stream, the proxy's own reply-leg FlowCallout found exactly what the hook had set: the SHA-256 v3 kept matched, so it read the JSON the hook kept (HM9, revision 21). |
| **L23** | **A bearer token in Debug (16 Nov, before v3.1 was built):** a made-up value read from a config map into a `private.` variable and sent as `Authorization: Bearer` on a `private.` message reached Prisma AIRS (HTTP 403) and showed nowhere in a Debug session of 7 calls, whole or in any 16-character piece, raw or JSON-escaped; Debug showed no `Authorization` header at all. |
| **L24** | **The config map's cache:** each runtime instance keeps an entry it has read for 300 s from its own last read. A changed entry was first read 175 and 205 s after the change on the two instances, a deleted one 185 and 226 s after; an entry added where none existed was read at once (4 s); a new revision, ready 94 s after a change, still read the old value until the same 300 s were up. |
| **L26** | **An absent config map entry:** a KVM Get of an entry that isn't there empties the variable it assigns: one that held a value reads `null` afterwards, `private.` or not, and the Gets after it still run. An AssignVariable with an empty `<Value>` leaves `""`. |
| **K3** | **Prisma AIRS judges only the last entry of `contents`:** with the test card in the first of two prompt entries, the scan was allowed; with the same text in one entry, it was blocked. |
| **K4** | **A prompt sent as a separate entry before the reply is ignored:** v3 sends the prompt and the reply in one entry. |
| **K5** | **A data pattern can mask text DLP doesn't flag (15 Nov):** "hello 1794750001" came back `allow`, `masked` true, with a masked copy ("hello" and ten X's) and the pattern "Tax Id - UK - UTR", while its `dlp` flag was false; "hello 1794750003" (no valid checksum) came back with no masked copy. On MCP, v3 refuses an allow that carries a masked copy (A24). The same timestamps spelled in letters were flagged `toxic_content` three times in four. |
| **K6** | **Prisma AIRS and an OAuth 2.0 token (15 Nov, direct calls to the US scan API):** a token made by hand in Strata Cloud Manager was taken as it is, as `Authorization: Bearer`, with or without `x-payload-hash`. A made-up token got HTTP 403, "Invalid API Key or OAuth Token". A valid token sent beside a wrong `x-pan-token` got 403, so v3.1 sends one credential only. |
