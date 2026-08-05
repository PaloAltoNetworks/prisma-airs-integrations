# Shared Prisma AIRS configuration for Cursor IDE hooks (Windows / PowerShell)
#
# Dot-source this from each hook script:
#     . "$PSScriptRoot\prisma-airs.ps1"
#
# PowerShell port of prisma-airs.sh. Requires Windows PowerShell 5.1+ (ships with
# Windows 10/11) or PowerShell 7+ (pwsh). No external tools (no bash/jq/curl).

# --- Make HTTPS + output behave predictably on Windows PowerShell 5.1 ---
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# --- Resolve paths relative to this script (equivalent of BASH_SOURCE/dirname) ---
$Script:HooksDir   = $PSScriptRoot
$Script:ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# --- Load .env from project root if present (KEY=VALUE -> process env) ---
$envFile = Join-Path $Script:ProjectDir '.env'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed.StartsWith('export ')) { $trimmed = $trimmed.Substring(7).Trim() }
        $eq = $trimmed.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $trimmed.Substring(0, $eq).Trim()
        $val = $trimmed.Substring($eq + 1).Trim()
        if (($val.StartsWith('"') -and $val.EndsWith('"')) -or
            ($val.StartsWith("'") -and $val.EndsWith("'"))) {
            if ($val.Length -ge 2) { $val = $val.Substring(1, $val.Length - 2) }
        }
        [Environment]::SetEnvironmentVariable($key, $val, 'Process')
    }
}

# --- Configuration (env var wins, else default) ---
function Get-EnvOrDefault([string]$Name, [string]$Default = '') {
    $v = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrEmpty($v)) { return $Default } else { return $v }
}

$Script:PrismaAirsApiUrl      = Get-EnvOrDefault 'PRISMA_AIRS_API_URL' 'https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request'
$Script:PrismaAirsApiKey      = Get-EnvOrDefault 'PRISMA_AIRS_API_KEY'
$Script:PrismaAirsProfileName = Get-EnvOrDefault 'PRISMA_AIRS_PROFILE_NAME'
$Script:PrismaAirsProfileId   = Get-EnvOrDefault 'PRISMA_AIRS_PROFILE_ID'
$Script:TimeoutSeconds        = 3
$Script:AppName               = 'cursor-hooks'

# --- Logging ---
$Script:LogFile = Join-Path $Script:HooksDir 'prisma-airs.log'
if (-not (Test-Path -LiteralPath $Script:LogFile)) {
    New-Item -ItemType File -Path $Script:LogFile -Force | Out-Null
}
function Write-Log([string]$Message) {
    $stamp = (Get-Date).ToString('ddd MMM d HH:mm:ss yyyy')
    Add-Content -LiteralPath $Script:LogFile -Value ("[{0}] {1}" -f $stamp, $Message)
}

# --- Hook stdout/stderr: emit EXACTLY the bytes we intend, nothing else.
#     (Equivalent of the bash FD3 hardening: keep stdout clean for Cursor.) ---
function Write-HookJson([string]$Json)  { [Console]::Out.WriteLine($Json) }
function Write-HookError([string]$Text) { [Console]::Error.WriteLine($Text) }

# --- Profile helpers: prefer profile_id over profile_name ---
function Build-AiProfile {
    if (-not [string]::IsNullOrEmpty($Script:PrismaAirsProfileId)) {
        return @{ profile_id = $Script:PrismaAirsProfileId }
    } elseif (-not [string]::IsNullOrEmpty($Script:PrismaAirsProfileName)) {
        return @{ profile_name = $Script:PrismaAirsProfileName }
    } else {
        return $null
    }
}
function Test-HasProfile {
    return (-not [string]::IsNullOrEmpty($Script:PrismaAirsProfileId)) -or
           (-not [string]::IsNullOrEmpty($Script:PrismaAirsProfileName))
}

# --- New session id when Cursor does not supply conversation_id ---
function New-SessionId([string]$Prefix) {
    return ("{0}-{1}-{2}" -f $Prefix, [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $PID)
}

# --- Parse Cursor tool_name into server + tool.
#     MCP:<server>:<tool...> -> Server=<server>, Tool=<server:tool...>
#     non-MCP                 -> Server=cursor,   Tool=<raw>           ---
function Get-ToolParts([string]$Raw) {
    if ($Raw -like 'MCP:*') {
        $withoutPrefix = $Raw.Substring(4)          # strip "MCP:"
        $server = $withoutPrefix.Split(':')[0]
        return [pscustomobject]@{ Server = $server; Tool = $withoutPrefix }
    }
    return [pscustomobject]@{ Server = 'cursor'; Tool = $Raw }
}

# --- Low-level POST to AIRS. Returns the parsed response object, or $null on
#     any transport/HTTP error (callers treat $null as "scan failed"). ---
function Invoke-AirsRequest([hashtable]$Payload) {
    $json  = $Payload | ConvertTo-Json -Depth 12 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $headers = @{
        'Accept'      = 'application/json'
        'x-pan-token' = $Script:PrismaAirsApiKey
    }
    try {
        return Invoke-RestMethod -Uri $Script:PrismaAirsApiUrl -Method Post `
            -Headers $headers -ContentType 'application/json' `
            -Body $bytes -TimeoutSec $Script:TimeoutSeconds
    } catch {
        Write-Log ("AIRS request failed: {0}" -f $_.Exception.Message)
        return $null
    }
}

# --- Scan a prompt or response.  Usage: Invoke-AirsScan "content" "prompt|response" "session" ---
function Invoke-AirsScan([string]$Content, [string]$ContentType = 'prompt', [string]$SessionId) {
    if ([string]::IsNullOrEmpty($SessionId)) { $SessionId = New-SessionId 'cursor' }
    $contentItem = if ($ContentType -eq 'response') { @{ response = $Content } } else { @{ prompt = $Content } }
    $payload = @{
        tr_id      = $SessionId
        ai_profile = (Build-AiProfile)
        metadata   = @{ app_user = 'cursor-user'; app_name = $Script:AppName }
        contents   = @($contentItem)
    }
    return Invoke-AirsRequest $payload
}

# --- Scan a tool_event (MCP tool interaction).
#     Usage: Invoke-AirsScanToolEvent "server" "tool" "input" "output" "session" ---
function Invoke-AirsScanToolEvent([string]$Server, [string]$Tool, [string]$InputText, [string]$OutputText, [string]$SessionId) {
    if ([string]::IsNullOrEmpty($SessionId)) { $SessionId = New-SessionId 'cursor' }
    if ([string]::IsNullOrEmpty($Server)) { $Server = 'unknown' }
    if ([string]::IsNullOrEmpty($Tool))   { $Tool   = 'unknown' }
    $payload = @{
        tr_id      = $SessionId
        ai_profile = (Build-AiProfile)
        metadata   = @{ app_user = 'cursor-user'; app_name = $Script:AppName }
        contents   = @(@{
            tool_event = @{
                metadata = @{
                    ecosystem    = 'mcp'
                    method       = 'tools/call'
                    server_name  = $Server
                    tool_invoked = $Tool
                }
                input  = $InputText
                output = $OutputText
            }
        })
    }
    return Invoke-AirsRequest $payload
}

# --- Collect all triggered detection categories -> comma-separated string ---
function Get-Detections($ScanResult) {
    if (-not $ScanResult) { return '' }
    $dets = New-Object System.Collections.Generic.List[string]
    foreach ($field in 'prompt_detected', 'response_detected') {
        $obj = $ScanResult.$field
        if ($obj) {
            foreach ($p in $obj.PSObject.Properties) {
                if ($p.Value -eq $true) { [void]$dets.Add($p.Name) }
            }
        }
    }
    return (($dets | Select-Object -Unique) -join ',')
}
