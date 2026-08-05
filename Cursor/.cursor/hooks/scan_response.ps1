# Prisma AIRS postToolUse hook for Cursor (Windows / PowerShell)
#
# Scans MCP and Shell tool outputs. Skips Cursor built-ins (Grep, Read, Write, etc.)
# which operate on local files and don't introduce external content.
#
#   MCP tools  -> scan as tool_event (structured input + output)
#   Shell      -> scan as response   (command output is external content)
#   Built-ins  -> skip (Grep, Read, Write, Delete, Task, Glob, Edit, NotebookEdit)
#
# Cursor contract:
#   stdin  -> JSON { tool_name, tool_input, tool_output, conversation_id, ... }
#   stdout -> {} (allow)  or  {"updated_mcp_tool_output":"..."} (block)
#   NEVER emit: permission, additional_context.  NEVER exit 2.

. (Join-Path $PSScriptRoot 'prisma-airs.ps1')

function Send-Allow { Write-HookJson '{}' }
function Send-Block([string]$Message) {
    Write-HookJson ((@{ updated_mcp_tool_output = $Message } | ConvertTo-Json -Compress))
}

# Normalize a tool_input/tool_output value (string or object) to a string
function ConvertTo-Str($Value) {
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    return ($Value | ConvertTo-Json -Depth 12 -Compress)
}

# === READ + PARSE STDIN ===
$InputJson = [Console]::In.ReadToEnd()
try { $data = $InputJson | ConvertFrom-Json } catch {
    Write-Log 'SCAN-RESPONSE: Failed to parse stdin JSON, passing through'
    Send-Allow; exit 0
}
if (-not $data) { Write-Log 'SCAN-RESPONSE: empty stdin, passing through'; Send-Allow; exit 0 }

$toolName = if ($data.tool_name) { [string]$data.tool_name } else { 'unknown' }

# === SKIP CURSOR BUILT-INS: local operations, no external content ===
if ($toolName -in 'Grep', 'Read', 'Write', 'Delete', 'Task', 'Glob', 'Edit', 'NotebookEdit') {
    Write-Log ("SCAN-RESPONSE: Skipping built-in tool={0}" -f $toolName)
    Send-Allow; exit 0
}

$toolInput  = ConvertTo-Str $data.tool_input
$toolOutput = ConvertTo-Str $data.tool_output

Write-Log ("SCAN-RESPONSE: tool={0} output_size={1}" -f $toolName, $toolOutput.Length)

# === GUARDRAIL: empty output ===
if ([string]::IsNullOrWhiteSpace($toolOutput)) {
    Write-Log 'SCAN-RESPONSE: tool_output is empty, skipping scan'
    Send-Allow; exit 0
}

# === GUARDRAIL: output size limit (50KB) ===
if ($toolOutput.Length -gt 51200) {
    Write-Log ("SCAN-RESPONSE: tool_output too large ({0} bytes), skipping scan" -f $toolOutput.Length)
    Send-Allow; exit 0
}

# === GUARDRAIL: API key and profile (fail-closed) ===
if ([string]::IsNullOrEmpty($Script:PrismaAirsApiKey)) {
    Write-Log 'SCAN-RESPONSE: ERROR: PRISMA_AIRS_API_KEY not set - blocking (fail-closed)'
    Send-Block 'Prisma AIRS: API key not configured - blocking response (fail-closed)'
    exit 0
}
if (-not (Test-HasProfile)) {
    Write-Log 'SCAN-RESPONSE: ERROR: no profile configured - blocking (fail-closed)'
    Send-Block 'Prisma AIRS: profile not configured - blocking response (fail-closed)'
    exit 0
}

# === PARSE TOOL NAME ===
$parts = Get-ToolParts $toolName

# === EXTRACT AND LOG URLS (audit trail) ===
$urlMatches = [regex]::Matches($toolOutput, 'https?://[^\s<>"'']+')
if ($urlMatches.Count -gt 0) {
    $urls    = @($urlMatches | ForEach-Object { $_.Value } | Select-Object -Unique)
    $preview = ($urls | Select-Object -First 3) -join ' '
    Write-Log ("SCAN-RESPONSE: Found {0} URL(s): {1}" -f $urls.Count, $preview)
}

# === TRUNCATE CONTENT BEFORE SCANNING ===
$truncOut = if ($toolOutput.Length -gt 20000) { $toolOutput.Substring(0, 20000) } else { $toolOutput }
$truncIn  = if ($toolInput.Length  -gt 20000) { $toolInput.Substring(0, 20000) }  else { $toolInput }

# === SESSION ID: group all scans in one session via conversation_id ===
$trId = if ($data.conversation_id) { [string]$data.conversation_id } else { New-SessionId 'cursor-posttool' }

# === SCAN WITH AIRS ===
# MCP tools -> tool_event (structured input + output with server/tool metadata)
# Shell     -> response   (plain text output from command execution)
if ($toolName -like 'MCP:*') {
    Write-Log ("SCAN-RESPONSE: Scanning MCP tool={0} server={1} as tool_event" -f $toolName, $parts.Server)
    $scan = Invoke-AirsScanToolEvent -Server $parts.Server -Tool $parts.Tool -InputText $truncIn -OutputText $truncOut -SessionId $trId
} else {
    Write-Log ("SCAN-RESPONSE: Scanning tool={0} as response" -f $toolName)
    $scan = Invoke-AirsScan -Content $truncOut -ContentType 'response' -SessionId $trId
}

# === FAIL-OPEN on transport error ===
if (-not $scan) {
    Write-Log 'SCAN-RESPONSE: WARNING: request failed, allowing by default'
    Send-Allow; exit 0
}

$action   = if ($scan.action)   { [string]$scan.action }   else { 'unknown' }
$category = if ($scan.category)  { [string]$scan.category }  else { 'unknown' }
$scanId   = if ($scan.scan_id)   { [string]$scan.scan_id }   else { 'unknown' }

# Fail-open on bad API response
if ([string]::IsNullOrEmpty($action) -or $action -eq 'unknown' -or $action -eq 'null') {
    Write-Log 'SCAN-RESPONSE: WARNING: AIRS returned invalid/no action, allowing by default'
    Send-Allow; exit 0
}

$detections = Get-Detections $scan

# === HANDLE VERDICT ===
if ($action -eq 'block') {
    if ($detections) {
        Write-Log ("SCAN-RESPONSE: BLOCKED tool={0} category={1} detections=[{2}] scan_id={3}" -f $toolName, $category, $detections, $scanId)
        $blockMsg = "BLOCKED by Prisma AIRS: $category (detected: $detections) [scan:$scanId]"
    } else {
        Write-Log ("SCAN-RESPONSE: BLOCKED tool={0} category={1} scan_id={2}" -f $toolName, $category, $scanId)
        $blockMsg = "BLOCKED by Prisma AIRS: $category [scan:$scanId]"
    }
    Send-Block $blockMsg
    exit 0
} elseif ($action -eq 'allow') {
    if ($detections) {
        Write-Log ("SCAN-RESPONSE: ALLOWED tool={0} category={1} detections=[{2}] scan_id={3}" -f $toolName, $category, $detections, $scanId)
    } else {
        Write-Log ("SCAN-RESPONSE: ALLOWED tool={0} scan_id={1}" -f $toolName, $scanId)
    }
} else {
    Write-Log ("SCAN-RESPONSE: WARNING tool={0} action={1} category={2} detections=[{3}] scan_id={4}" -f $toolName, $action, $category, $detections, $scanId)
}
Send-Allow
exit 0
