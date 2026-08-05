#Requires -Version 5.1
<#
.SYNOPSIS
  Offline contract smoke test for the PowerShell Cursor hooks.

.DESCRIPTION
  Pipes representative JSON into each hook and asserts the stdout JSON + exit
  code match Cursor's contract. Exercises only the no-network paths: the early
  allow/skip branches and the fail-closed-on-missing-credentials branches. It
  does NOT call the Prisma AIRS API, so it needs no key or profile.

  Run from anywhere (paths resolve relative to this script):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Cursor\test-hooks.ps1
  or, if PowerShell 7 is installed:
    pwsh -NoProfile -File Cursor/test-hooks.ps1

  The fail-closed checks are skipped automatically when credentials are present
  (a .env in the project root or PRISMA_AIRS_API_KEY set), because with
  credentials those paths would call the live API.

  For live detection tests (EICAR, prompt injection) with a real API key and
  profile, see the "Testing" section of README.md.
#>

$hooksDir = Join-Path (Join-Path $PSScriptRoot '.cursor') 'hooks'
$psExe    = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell.exe' }

# -ExecutionPolicy is a Windows-only switch; omit it on macOS/Linux pwsh.
# ($IsWindows is undefined on Windows PowerShell 5.1, so treat that as Windows.)
$policyArgs = if ($IsWindows -eq $false) { @() } else { @('-ExecutionPolicy', 'Bypass') }

$script:pass = 0
$script:fail = 0

# Pipe $Json to a hook via a fresh PowerShell process; capture stdout + exit code.
function Invoke-Hook([string]$Script, [string]$Json) {
    $path = Join-Path $hooksDir $Script
    $out  = $Json | & $psExe -NoProfile @policyArgs -File $path 2>$null
    return [pscustomobject]@{
        StdOut = ($out | Out-String).Trim()
        Exit   = $LASTEXITCODE
    }
}

function Test-Case([string]$Name, [scriptblock]$Check) {
    try {
        if (& $Check) {
            $script:pass++
            Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        } else {
            $script:fail++
            Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
        }
    } catch {
        $script:fail++
        Write-Host ("  FAIL  {0}  ({1})" -f $Name, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host "`nContract smoke tests (no network, no credentials)`n"

# --- Allow / skip paths (no credentials required) ---
Test-Case 'pre_submit_prompt: empty prompt -> allow' {
    $r = Invoke-Hook 'pre_submit_prompt.ps1' '{}'
    $r.Exit -eq 0 -and $r.StdOut -eq '{"continue":true}'
}
Test-Case 'pre_mcp_execution: no tool_name -> allow' {
    $r = Invoke-Hook 'pre_mcp_execution.ps1' '{}'
    $r.Exit -eq 0 -and $r.StdOut -eq '{"permission":"allow"}'
}
Test-Case 'pre_mcp_execution: empty tool_input -> allow' {
    $r = Invoke-Hook 'pre_mcp_execution.ps1' '{"tool_name":"MCP:demo:list"}'
    $r.Exit -eq 0 -and $r.StdOut -eq '{"permission":"allow"}'
}
Test-Case 'scan_response: built-in tool -> skip/allow' {
    $r = Invoke-Hook 'scan_response.ps1' '{"tool_name":"Read","tool_output":"local file text"}'
    $r.Exit -eq 0 -and $r.StdOut -eq '{}'
}
Test-Case 'scan_response: empty output -> skip/allow' {
    $r = Invoke-Hook 'scan_response.ps1' '{"tool_name":"MCP:demo:get","tool_output":""}'
    $r.Exit -eq 0 -and $r.StdOut -eq '{}'
}
Test-Case 'scan_response: oversized output (>50KB) -> skip/allow' {
    $big = 'x' * 60000
    $r = Invoke-Hook 'scan_response.ps1' (@{ tool_name = 'MCP:demo:get'; tool_output = $big } | ConvertTo-Json -Compress)
    $r.Exit -eq 0 -and $r.StdOut -eq '{}'
}
Test-Case 'agent_response_scan: empty response -> allow (no stdout)' {
    $r = Invoke-Hook 'agent_response_scan.ps1' '{}'
    $r.Exit -eq 0 -and $r.StdOut -eq ''
}

# --- Fail-closed paths (only meaningful when no credentials are present) ---
$hasEnvFile = Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env')
$hasKey     = -not [string]::IsNullOrEmpty($env:PRISMA_AIRS_API_KEY)

if ($hasEnvFile -or $hasKey) {
    Write-Host "`n  SKIP  fail-closed tests (credentials present via .env or env var; would call the API)`n" -ForegroundColor Yellow
} else {
    Write-Host "`nFail-closed tests (no credentials configured)`n"

    Test-Case 'pre_submit_prompt: prompt + no creds -> deny, exit 2' {
        $r = Invoke-Hook 'pre_submit_prompt.ps1' '{"prompt":"hello"}'
        $o = $r.StdOut | ConvertFrom-Json
        $r.Exit -eq 2 -and $o.continue -eq $false
    }
    Test-Case 'pre_mcp_execution: tool + no creds -> deny, exit 2' {
        $r = Invoke-Hook 'pre_mcp_execution.ps1' '{"tool_name":"MCP:demo:get","tool_input":{"path":"x"}}'
        $o = $r.StdOut | ConvertFrom-Json
        $r.Exit -eq 2 -and $o.permission -eq 'deny'
    }
    Test-Case 'scan_response: output + no creds -> block, exit 0 (never exit 2)' {
        $r = Invoke-Hook 'scan_response.ps1' '{"tool_name":"MCP:demo:get","tool_output":"external data"}'
        $o = $r.StdOut | ConvertFrom-Json
        $r.Exit -eq 0 -and $null -ne $o.updated_mcp_tool_output
    }
    Test-Case 'agent_response_scan: response + no creds -> block, exit 2 (no stdout)' {
        $r = Invoke-Hook 'agent_response_scan.ps1' '{"text":"hello"}'
        $r.Exit -eq 2 -and $r.StdOut -eq ''
    }
}

Write-Host ("`nResults: {0} passed, {1} failed`n" -f $script:pass, $script:fail)
exit ([int]($script:fail -gt 0))
