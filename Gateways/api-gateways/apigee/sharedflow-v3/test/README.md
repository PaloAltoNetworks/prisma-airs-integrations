# Unit tests for the PANW-AIRS SharedFlow

This suite runs the SharedFlow's own XML and JavaScript in an offline emulator of Apigee, with no network. Each case checks one of two things:

- which text of a request or a reply reaches the Prisma AIRS scan;
- what the flow does with a Prisma AIRS reply recorded from a real tenant.

---

## Running

From the `sharedflow-v3` folder:

```bash
node test/run.js --v3
```

| Command | What it runs |
|---|---|
| `node test/run.js --v3` | Every case's v3 expectation, against this folder's bundle, `PANW-AIRS/sharedflowbundle/` |
| `node test/run.js` | Every case's V2 expectation, against V2's bundle in `../sharedflow/PANW-AIRS/sharedflowbundle/` |
| `node test/run.js --v3 --only A01` | Only the cases whose label is exactly `A01` (any label works, such as `MS-batch`) |
| `node test/run.js --v3 --file 30-verdict-and-config.js` | Only the cases in one file of `cases/` |
| `node test/debug.js "<part of a title>" v3` | One case, by part of its title, with what each leg scanned, its route, its refusal message and any script error (`v2` for V2's bundle) |

The suite needs Node.js only: no packages, no cloud account and no Prisma AIRS key.

It prints one line per case, `PASS` or `FAIL`, with the case's label and title, and under a `FAIL` what went wrong. The last line counts the passes, the failures, and the cases with no expectation for that bundle:

```text
v3: <n> pass, 0 fail, <n> with no v3 expectation
```

The exit code is 0 when every case passes, 1 when a case fails, and 2 when the bundle isn't found.

**On V2,** a case passes when V2 shows the defect the case describes. A clean run on V2 therefore shows that the suite can see each defect it tests, and the same cases passing on v3 show the defects fixed.

**On v3,** two more rules apply:

- **Variable names:** the harness throws on any flow variable whose name extends another, in either order. Apigee silently drops such a variable (L6), so v3 must never set one. V2 runs under Apigee's own rule instead, where the variable is dropped.
- **No silent leg:** each leg, and each run of `setup.runs`, must end with a scan, a refusal, or a pass on an explicit route. One that ends with none of them fails its case, unless the verdict cache answered every scan it made (phase 3), judged by its own counts, read when it ends.

---

## The harness

`harness/apigee.js` is an offline Apigee for SharedFlow bundles. It runs:

- the steps of `sharedflows/default.xml`, in order, with their conditions;
- each policy from its own XML: JavaScript (`IncludeURL`, `ResourceURL`, `Properties`, `timeLimit`, `continueOnError`), KeyValueMapOperations, AssignMessage, ServiceCallout, ExtractVariables, RaiseFault, MessageLogging, LookupCache and PopulateCache;
- one cache store per case, which `setup.cache` can fill first, shared by every leg and run of the case, as the environment's cache is shared by every proxy (L19);
- flow variables, with the rules measured on Apigee;
- messages, with headers, content, status, verb and path;
- a ServiceCallout that records each request it is sent and answers from the case's responder, never from the network.

`harness/xml.js` reads the bundle's XML. Anything it doesn't understand stops the run, so a bundle never runs half-read. `harness/replies.js` loads the recorded replies.

Each case runs the legs it names on one flow: the request leg with `type=user-prompt`, then, unless the request leg stopped, the reply leg with `type=response-prompt`. A case with `setup.runs` runs the SharedFlow once per entry instead, in order, each with its own leg and parameters, as a flow hook's run and a proxy's FlowCallout share one exchange. The config map holds a test key and the profile name `PROFILE_NAME`.

The harness runs the JavaScript in Node.js, not in Apigee's Rhino engine, and doesn't model everything a runtime does. [VERIFICATION.md](../VERIFICATION.md) records what a live Apigee did.

---

## Recorded replies

`fixtures/airs/` holds Prisma AIRS replies recorded from a tenant, one per file. Each file has:

- `what` the scan was, and `recorded_utc`, when it ran;
- the HTTP `status`, the time in `ms`, and the shape of the `contents` sent (`request_contents_shape`);
- the `body` as Prisma AIRS sent it, with the profile id and name, the scan id, the report id, and the transaction, session and `tr_id` values replaced by placeholders.

The recordings cover:

- allows for a harmless prompt, a harmless prompt and reply, and a harmless MCP tool call;
- blocks for the standard Visa test card number, 4111 1111 1111 1111, in a prompt, a reply, an MCP tool's input and its output, and in the second of two prompt entries (K3);
- a block of 100,000 characters of harmless text (L11);
- blocks that carry a masked copy, recorded for the exact scan text each masking case sends, V2's and v3's;
- error answers: HTTP 400 for a prompt over 2,097,152 characters (L10) and for a 101-character `transaction_id` (L12), and HTTP 403 for a wrong key.

Every prompt is harmless: plain questions, filler text and the test card number.

**Each case names the reply its scan gets:**

- `R.answers('allow-prompt', 'block-dlp-response-masked')` answers the first scan with the first recording and the next scan with the second; the last one repeats.
- `R.noAnswer()` gives no answer at all, as a time-out or a refused connection does (L10).
- `R.status(code, body)` gives a bare status and body, such as an HTTP 500 or an HTML page.
- `R.asAllow(name)` gives a recorded block with its action set to allow, standing in for a profile whose sensitive-data action is allow. It is marked synthetic.
- A few cases build an answer that no tenant gives on demand, such as an allow that reports a detector error, often by changing one field of a recorded reply. The cases call such answers synthetic.

The harness never decides a verdict. The SharedFlow's own verdict step reads whatever reply the case names.

---

## Case labels

Each case has a label (`finding`) and a title. The label says where the case comes from.

| Label | Meaning |
|---|---|
| `A01` to `A39` | A finding about V2, defined in [MIGRATION.md](../MIGRATION.md#the-findings-a01-to-a39). The case's V2 expectation shows the defect on V2's bundle; its v3 expectation shows it fixed. |
| `MS-*` | A behaviour ported from the tests of this repository's MuleSoft policy. Many titles name the MuleSoft test or source line they port. Where v3 differs from MuleSoft on purpose, the case holds v3's rule and its title says so |
| `GATE-*`, `FIX-*` | Written by reviews of v3, each for a finding of the review. The case failed until the fix and passes now |
| `GUARD-*`, and labels with a `G` number such as `GATE-COV-G01` or `FIX-C-G01` | Guards from the same reviews: they passed when written, and pin behaviour that must not change |
| `GATE-OWN-*` | Guards for the parts of the reviews' fixes that no other case pinned |
| `LEG-*`, `EMPTY-*` | `type` checked against the leg the step runs on, and a 2xx reply that says it has no body. `LEG-1` to `LEG-3` show the V2 defect on V2's bundle; the `G` cases are guards |
| `SIZE-*` | The size limit's default, 100,000 characters, and the newest-part scan a proxy for Claude Code uses |
| `P2-*` | Phase 2, MCP completely: batches member by member, the scan slots, reply arrays, `mcpBatchLimit`, `allowOpenStreams`, and a `tools/list` tool event past the size limit. Cases ending in `g` are guards |
| `P2GATE-*` | Written by the review of phase 2, each for a finding of the review. The case failed until the fix and passes now. Titles that start with "Guard" passed when written and pin behaviour that must not change. `P2GATE-NON2XX` was first deferred with A31; the owner moved A31's MCP half into phase 2, and its cases now hold MuleSoft's rule |
| `P2FIX-*` | Written while fixing the phase 2 review's findings: defects found on the way, and guards for parts of the fixes that a mutation check showed no other case pinned |
| `P2FR-*` | Written by a review of those fixes, for closure and new holes (`P2FR-C-*`) and for Apigee's behaviour and regressions (`P2FR-R-*`). The case failed until its fix and passes now; titles that start with "Guard" pin the fixes |
| `P2NON2XX` | MCP replies outside 2xx, moved into phase 2 by the owner: a body that can be read is scanned whatever its status, and one that is empty or not JSON passes, logged. Each case failed until the fix; titles that start with "Guard" pin what must not change, such as an LLM reply outside 2xx still passing (A31, phase 3) |
| `P2NR-*` | Written by a review of that change, each for a finding of the review. The case failed until its fix and passes now; titles that start with "Guard" were written with the fixes and pin their other side |
| `P3-MON`, `P3-RETRY`, `P3-BRK`, `P3-VC`, `P3-HOOK` | Phase 3: monitor mode, the retry, the circuit breaker, the verdict cache and flow hooks, each from MuleSoft's rule and tests where it has them. Each case failed until its code; titles that start with "Guard" pin what must not change |
| `P3GATE-COV-*`, `P3GATE-APIGEE-*`, `P3GATE-CONF-*`, `P3GATE-CRIT-*`, `P3GATE-FIX-*` | Written by the review of phase 3, each for a finding of the review, and by its fixes. A case failed until its fix and passes now; titles that start with "Guard" pin behaviour that must not change |

A title that cites a measurement id, such as L1 or K3, refers to a measurement on a live Apigee or Prisma AIRS tenant, defined in [VERIFICATION.md](../VERIFICATION.md).

---

## Case files

| File | Cases |
|---|---|
| `10-request-text.js` | Which text of a request reaches the scan (A01 to A05) |
| `20-reply-and-mcp.js` | Which text of a reply or an MCP message reaches the scan, and the MCP refusal's id (A06, A07, A10, A17, A19, A29) |
| `30-verdict-and-config.js` | What the flow does with a recorded reply or a setting (A13 to A15, A25 to A27, A39) |
| `31-size-default.js` | The size limit's default, 100,000 characters, and a long conversation scanned by its newest 100,000 when `truncationFailClosed=false` (SIZE-1 to SIZE-3) |
| `40-masking-streams-misc.js` | Masking (A22 to A24), event streams (A08, A09, A18, A21, A30), and A11, A12, A16, A28 and A31 |
| `51-ms-request.js` to `58-ms-fixture-cases.js` | The MuleSoft ports: requests, replies, MCP requests and replies, verdicts, settings, integration cases, and cases that needed a reply recorded for v3's exact scan text |
| `91-*.js` to `98-*.js` | The reviews of v3: coverage, failing closed, Apigee's behaviour, conformance, completeness, two reviews of the fixes, and guards for the fixes |
| `60-p2-mcp.js` | Phase 2: batches, the scan slots, reply arrays, the two MCP settings, and a `tools/list` tool event past the size limit (P2-*) |
| `61-*.js` to `67-*.js` | The review of phase 2: coverage and failing closed, Apigee's behaviour, conformance to MuleSoft's rules, completeness (P2GATE-*), the cases written while fixing it (P2FIX-*), and the review of the fixes (P2FR-*) |
| `68-p2-non2xx.js` | MCP replies outside 2xx (P2NON2XX) |
| `69-non2xx-review.js` | The review of that change: `type=both` with a request with no body, an event stream to such a request, and the id of a refused client reply (P2NR-*) |
| `75-p3gate-coverage.js` to `79-p3gate-fixes.js` | The review of phase 3: four reviewers' cases (coverage, Apigee realism, MuleSoft conformance, completeness), and the cases for what their fixes changed (P3GATE-*) |
| `70-p3-monitor.js` to `74-p3-hooks.js` | Phase 3: monitor mode, the retry, the circuit breaker, the verdict cache and flow hooks. The cache and breaker cases fill the cache first and read it back; the hook cases run v3 several times on one flow |
| `99-leg-and-empty-reply.js` | A `type` that doesn't match the leg, and a reply with no body that says so |
| `_shapes.js` | Request and reply builders the cases share. Files that start with `_` are not case files |

---

## Writing a case

A case is an object in a file under `cases/`:

- `finding` and `title`: its label and what it checks;
- `setup`: the path suffix (`path`), the `request`, the `legs` to run, the settings (`vars`, or `varsFor` per bundle), the reply its scan gets (`airs`, or `airsFor` per bundle) and, for the reply leg, the model's `response`. `params` changes a leg's FlowCallout parameters, as in `params: { response: { type: 'both' } }`; `null` leaves a parameter unset. By default the request leg runs with `type=user-prompt` and the reply leg with `type=response-prompt`. Phase 3 adds `runs` (a list of `{ leg, params }`, run in order on one flow, each optionally with `before`, a function run on the flow just before it; the result is `r.runs`, each with its own log `lines`), `kvm` (more config map entries, such as `airs_hook`), `cache` (the cache store's entries before the case) and `beforeResponse` (a function run on the flow between the legs);
- `v2` and `v3`: functions that take the result and return `true`, or a sentence that says what went wrong. A case without one of them is skipped on that bundle.

Use harmless content only: plain sentences, the marker `AIRSV3-MARKER`, and the test card number.
