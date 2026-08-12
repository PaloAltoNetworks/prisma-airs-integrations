<div align="center">

# 🛡️ Gemini CLI × Prisma AIRS

**Scan every checkpoint of Gemini CLI — prompt, tool call, tool output, and final answer — through [Prisma AIRS](https://pan.dev/prisma-airs/).**

![Runtimes](https://img.shields.io/badge/runtimes-node%20%C2%B7%20bash%20%C2%B7%20powershell-3fb950)
&nbsp;<a href="../README.md">↩ all agents</a>

</div>

## Quick start

**1 · Copy the `.gemini/` folder into your Gemini CLI project** — pick the runtime you have:
```bash
cp -r nodejs/.gemini  /path/to/your/project/      # or  bash/.gemini  ·  powershell/.gemini
```

**2 · Set your Prisma AIRS credentials**
```bash
export PRISMA_AIRS_API_KEY="your-api-key"
export PRISMA_AIRS_PROFILE_NAME="your-profile"
```

> [!IMPORTANT]
> **Configure before you rely on it.** With **no `PRISMA_AIRS_API_KEY`** set, a fresh install **passes traffic through unscanned** and prints a loud `NOT CONFIGURED` warning on every call — so copying the folder in won't brick Gemini CLI, but you are **not protected** until credentials land. Once a key **is** set, any AIRS error (or a half-config with a key but no profile) fails **closed** on the input side.

> [!WARNING]
> **In production, set `AIRS_REQUIRE_CONFIG=1`.** Gemini CLI is an env-writer (it has file/shell tools), so an injected instruction could delete this install's `.env` — a benign-looking file op AIRS won't flag — to *force* the unconfigured state and silently bypass scanning. `AIRS_REQUIRE_CONFIG=1` makes that fail **closed** (a loud DoS, not a bypass). Also deny the agent write access to the hooks dir. See [SECURITY.md](../SECURITY.md).

**3 · Start Gemini CLI — done.** Every checkpoint below is now scanned.

## Choose your runtime

| Runtime | Requires | Best for |
|:--|:--|:--|
| [`nodejs/`](nodejs/) | Node 18+ · zero deps | Full engine — DLP mask-in-place + chunking |
| [`bash/`](bash/) | `jq` + `curl` | macOS / Linux |
| [`powershell/`](powershell/) | PowerShell 5.1+ / 7 · no `jq`/`curl` | Windows-native |

Each folder is self-contained (engine + wiring + `.gemini/`). Shared `example.env` documents every variable; `tests/` runs the same fixtures against all three runtimes.

## Coverage

| Prompt | Response | Streaming | Pre-tool | Post-tool |
|:--:|:--:|:--:|:--:|:--:|
| ✅ | ⚠️ | ❌ | ✅ | ✅ |

<div align="center"><sub>✅ hard-block &nbsp;·&nbsp; ⚠️ scan + alert / redact &nbsp;·&nbsp; ❌ no usable surface in the hook contract</sub></div>


```mermaid
flowchart LR
    P["Prompt<br/>🛡️ block"] --> T["Tool call<br/>🛡️ block"]
    T --> O["Tool output<br/>🛡️ block"]
    O --> A["Model answer<br/>⚠️ scan+alert"]
```

<details>
<summary><b>How enforcement works in Gemini CLI</b></summary>

<br>

Gemini CLI reads hooks from `.gemini/settings.json` and blocks via **exit code 2** (stderr = reason). All four checkpoints are real events: `BeforeAgent` (prompt), `BeforeTool` (pre-tool), `AfterTool` (post-tool, receives `tool_response`), and `AfterAgent` (response, receives `prompt_response`). **Prompt and Pre-tool are verified end-to-end on a live Gemini CLI** (Vertex + ADC); **Post-tool** uses the same exit-2 block on `AfterTool`; **Response** (`AfterAgent`) is **advisory** — exit 2 there triggers a model retry (loop risk), so the answer is scanned and alerted, not hard-blocked. Tool input/output is sent as a `tool_event` (`tools/call`) to catch **indirect prompt injection**.
</details>

<div align="center">
<br>
<sub>MIT © 2026 Palo Alto Networks &nbsp;·&nbsp; <a href="../README.md">all agents</a> &nbsp;·&nbsp; <a href="https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/">detection categories</a></sub>
</div>
