# Security Policy

These hooks are a security control for AI coding agents: they inspect every
checkpoint (prompt, tool input, tool output, final answer) and delegate the
verdict to **Prisma AIRS**.

## Design guarantees
- **No secrets in the repo.** Credentials come from the environment
  (`PRISMA_AIRS_API_KEY`, `PRISMA_AIRS_PROFILE_NAME` / `PRISMA_AIRS_PROFILE_ID`).
  Never commit a real `.env` — only `example.env` (placeholders) is tracked.
- **Fail-closed on input.** A missing key/profile blocks prompts and tool calls
  rather than letting unverified content through.
- **Fail-open on output.** If AIRS is unreachable, post-execution and Stop
  checkpoints degrade to a warning instead of breaking the agent; `Stop` never loops.
- **No telemetry.** The hooks talk only to your configured AIRS endpoint. The only
  local write is the scan log (`SECURITY_LOG_PATH`).

## Reporting a vulnerability
If you find a way to bypass these hooks, or a defect that could leak data or disable
enforcement, report it privately to the maintainers rather than opening a public
issue. Include the agent, runtime, checkpoint, and a minimal reproducing payload.

## Scope note
These hooks reduce risk; they do not eliminate it. Detection quality depends on your
AIRS **security profile**. Treat them as one layer of defense-in-depth, not a sole
control.
