# Cursor Security Hooks — PowerShell runtime (Windows)

Install and verify steps for the PowerShell implementation of the Cursor security hooks, for Windows endpoints without `bash`, `jq`, or `curl`. For the overview, coverage matrix, hook contracts, configuration, and limitations, see the [Cursor README](../README.md).

## Prerequisites

- Cursor IDE (with hooks support)
- Prisma AIRS API access with a valid API key
- **Windows PowerShell 5.1** (ships with Windows 10/11) or **PowerShell 7+** (`pwsh`). No `jq`/`curl` needed.
- Outbound HTTPS to the Prisma AIRS API (the scripts force TLS 1.2 for older hosts).

## Install

**1. Copy the hooks into your project**

Copy this folder's `.cursor` directory into your project root. Cursor runs hook commands from the project root, which is why the `-File` paths in `hooks.json` are relative (`.cursor/hooks/...`).

**2. Configure credentials**

Copy [`example.env`](../example.env) to `.env` in your project root and fill it in, or set process environment variables:

```powershell
$env:PRISMA_AIRS_API_KEY     = "your-prisma-airs-api-key"
$env:PRISMA_AIRS_PROFILE_NAME = "your-security-profile-name"
```

The scripts load `.env` from the project root identically to the bash version. See [Configuration](../README.md#configuration) for all variables.

**3. Restart Cursor**

`.cursor/hooks.json` is pre-wired to `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .cursor/hooks/*.ps1` with a 10000 ms timeout. Cursor detects it on restart.

## Verify

```powershell
'{"prompt": "Hello world"}' | powershell.exe -NoProfile -File .cursor\hooks\pre_submit_prompt.ps1   # -> {"continue":true}
Get-Content .cursor\hooks\prisma-airs.log -Wait
```

### Automated harness: `test-hooks.ps1`

`test-hooks.ps1` runs the shared fixtures' scenarios against all four hooks and checks stdout + exit codes. With no credentials it runs offline contract tests only (allow/skip and fail-closed paths, no network). When `PRISMA_AIRS_API_KEY` and a profile are configured, it also runs live detection tests (a benign prompt that should pass, plus prompt-injection and EICAR payloads that should block). Pass `-NoLive` to force offline-only.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File test-hooks.ps1
# PowerShell 7:
pwsh -NoProfile -File test-hooks.ps1
# offline only, even with credentials set:
pwsh -NoProfile -File test-hooks.ps1 -NoLive
```

Live detection depends on your AIRS profile: a malicious payload that returns "allow" usually means the profile does not block that category, not a hook bug. The verdict is printed for each live case.

## Windows notes

- **Execution policy:** `hooks.json` passes `-ExecutionPolicy Bypass` so the scripts run under a `Restricted` *user* policy. If your fleet enforces `AllSigned` via Group Policy, code-sign the `.ps1` files with a trusted certificate.
- **PowerShell 7:** if `pwsh` is deployed to your endpoints, swap `powershell.exe` for `pwsh` in `hooks.json` for a faster cold start.
- **Timeout:** the config uses a `10000` ms hook timeout (vs `5000` for bash) to absorb PowerShell process startup on top of the 3 s API timeout. Hooks still fail open on timeout (`failClosed: false`); only a missing API key/profile fails closed.
- **TLS:** the scripts force TLS 1.2 for older Windows hosts.
