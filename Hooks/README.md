# Prisma AIRS Security Hooks — agent × runtime matrix

![License](https://img.shields.io/badge/license-MIT-blue) ![Runtimes](https://img.shields.io/badge/runtimes-node%20%7C%20bash%20%7C%20powershell-brightgreen)

Drop-in AI-runtime-security hooks that scan **every** checkpoint of a coding
agent's loop — prompt, tool input, tool output, and final answer — through
**Prisma AIRS**. One folder per **agent**; inside each, one folder per **runtime**
(`nodejs`, `bash`, `powershell`). Each cell ships the agent's real config directory
(`.cursor/`, `.claude/`, …) so install is *copy the folder into your project root*.

## Agents

| Integration | Category | Prompt | Response | Streaming | Pre-tool | Post-tool |
|---|---|:---:|:---:|:---:|:---:|:---:|
| [ClaudeCode](ClaudeCode/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |
| [Codex](Codex/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |
| [Cursor](Cursor/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |
| [Cline](Cline/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |
| [Windsurf](Windsurf/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |
| [Antigravity](Antigravity/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ |

> Detection categories & use cases: <https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/>

## Runtimes
- **nodejs** — the full engine (DLP mask-in-place + chunking); Node 18+, zero deps.
- **bash** — core parity; needs `jq` + `curl` (macOS / Linux).
- **powershell** — core parity, Windows-native; PowerShell 5.1+ or 7, no `jq`/`curl`.

**Core parity** (bash + powershell): all four checkpoints, correct AIRS
content-types incl. `tool_event` (`tools/call`) for indirect-injection, fail-closed
input / fail-open output, no silent truncation. **nodejs-only:** DLP mask-in-place
and multi-chunk scanning.

## Validation
Every agent has `tests/run-tests.sh` — runs shared fixtures through all three
runtimes. Offline (no key) it exercises each runtime's block rendering; set
`PRISMA_AIRS_API_KEY` + `PRISMA_AIRS_PROFILE_NAME` for a live detection run.

## Install
Open your agent's folder, pick a runtime, follow its `README.md`. All runtimes read
the same environment — see any `example.env`.

## License
[MIT](LICENSE) © 2026 Palo Alto Networks.
