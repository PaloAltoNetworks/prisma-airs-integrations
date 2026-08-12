# Security Policy

These hooks are a security control for AI coding agents: they inspect every
checkpoint (prompt, tool input, tool output, final answer) and delegate the
verdict to **Prisma AIRS**.

## Design guarantees
- **No secrets in the repo.** Credentials come from the environment
  (`PRISMA_AIRS_API_KEY`, `PRISMA_AIRS_PROFILE_NAME` / `PRISMA_AIRS_PROFILE_ID`).
  Never commit a real `.env` — only `example.env` (placeholders) is tracked.
- **Fail-closed on input for scan failures.** With a key configured, any AIRS error,
  an unknown/partial verdict, unparseable/over-nested input, or a key-set-but-no-profile
  half-config blocks prompts and tool calls rather than letting unverified content through.
- **Unconfigured (no key) passes through by default** — see the accepted risk below.
- **Fail-open on output.** If AIRS is unreachable, post-execution and Stop
  checkpoints degrade to a warning instead of breaking the agent; `Stop` never loops.
- **No telemetry.** The hooks talk only to your configured AIRS endpoint. The only
  local write is the scan log (`SECURITY_LOG_PATH`).

## Accepted risk — the unconfigured pass-through (self-tamper bypass)
By default, an install with **no `PRISMA_AIRS_API_KEY` at all** passes traffic through
with a loud `NOT CONFIGURED` warning instead of blocking, so copying the folder in before
`.env` exists doesn't brick the agent on first run. This is a deliberate UX trade with a
**known bypass** you must account for:

> A coding agent has file and shell tools, so it is itself an env-writer. An **injected
> instruction** can make the agent run a benign-looking file op — e.g. `rm .cursor/hooks/.env`
> — that AIRS has no reason to flag. Every subsequent scan then reads "unconfigured" and
> **passes through**. The default converts self-tamper from a *loud denial-of-service* (the
> old strict behavior bricks the agent visibly) into a **silent bypass** (an advisory the
> attacker ignores).

**Mitigations (recommended for production / enterprise):**
- **Set `AIRS_REQUIRE_CONFIG=1`.** The unconfigured state then fails **closed** on the input
  side — deleting the key becomes a loud DoS again, not a bypass. Recommended for any
  non-experimental deployment.
- **Protect the hooks directory.** Deny the agent write/delete access to the install's hooks
  dir and `.env` via the agent's own permission config (e.g. a `deny` rule on
  `.cursor/hooks/**` / `Write`/`Bash(rm *)` against that path) so the tamper op never runs.
- **Prefer a centralized key** the agent process can't reach (e.g. injected by the launcher /
  a managed-settings deployment) over a file the agent can delete.

## Reporting a vulnerability
If you find a way to bypass these hooks, or a defect that could leak data or disable
enforcement, report it privately to the maintainers rather than opening a public
issue. Include the agent, runtime, checkpoint, and a minimal reproducing payload.

## Scope note
These hooks reduce risk; they do not eliminate it. Detection quality depends on your
AIRS **security profile**. Treat them as one layer of defense-in-depth, not a sole
control.
