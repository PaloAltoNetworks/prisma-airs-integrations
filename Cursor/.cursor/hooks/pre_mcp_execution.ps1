# Prisma AIRS beforeMCPExecution hook for Cursor (Windows / PowerShell)
# Scans MCP tool input via Prisma AIRS before execution (tool_event content type).
#
# Cursor contract:
#   stdin  -> JSON { tool_name, tool_input, conversation_id, ... }
#   stdout -> {"permission":"allow"}  or  {"permission":"deny","user_message":...,"agent_message":...}
#   exit 0 = allow, exit 2 = deny

. "$PSScriptRoot\prisma-airs.ps1"

function Send-Allow { Write-HookJson '{"permission":"allow"}' }
function Send-Deny([string]$UserMsg, [string]$AgentMsg) {
    Write-HookJson ((@{ permission = 'deny'; user_message = $UserMsg; agent_message = $AgentMsg } | ConvertTo-Json -Compress))
}

$InputJson = [Console]::In.ReadToEnd()
try { $data = $InputJson | ConvertFrom-Json } catch { $data = $null }

# --- Extract tool_name ---
$toolName = if ($data -and $data.tool_name) { [string]$data.tool_name } else { '' }
if ([string]::IsNullOrEmpty($toolName)) {
    Write-Log 'PRE-MCP: No tool_name in input; allowing through'
    Send-Allow; exit 0
}

# --- Normalize tool_input (string or object) to a string for the API ---
$toolInputStr = ''
if ($data -and $null -ne $data.tool_input) {
    if ($data.tool_input -is [string]) {
        $toolInputStr = $data.tool_input
    } else {
        $toolInputStr = ($data.tool_input | ConvertTo-Json -Depth 12 -Compress)
    }
}
if ([string]::IsNullOrEmpty($toolInputStr)) {
    Write-Log ("PRE-MCP: tool_name={0} - empty tool_input; allowing through" -f $toolName)
    Send-Allow; exit 0
}

# --- Validate required configuration (fail-closed) ---
if ([string]::IsNullOrEmpty($Script:PrismaAirsApiKey)) {
    Write-Log ("PRE-MCP: ERROR - PRISMA_AIRS_API_KEY is not set; blocking tool={0} (fail-closed)" -f $toolName)
    Send-Deny 'Prisma AIRS: API key not configured - blocking MCP request (fail-closed)' `
              'AIRS security scan could not run: API key not configured. Do not retry.'
    exit 2
}
if (-not (Test-HasProfile)) {
    Write-Log ("PRE-MCP: ERROR - no profile configured; blocking tool={0} (fail-closed)" -f $toolName)
    Send-Deny 'Prisma AIRS: profile not configured - blocking MCP request (fail-closed)' `
              'AIRS security scan could not run: profile not configured. Do not retry.'
    exit 2
}

# --- Parse tool name + session id ---
$parts = Get-ToolParts $toolName
$trId  = if ($data.conversation_id) { [string]$data.conversation_id } else { New-SessionId 'cursor-mcp' }

Write-Log ("PRE-MCP: Scanning tool={0} server={1} tr_id={2}" -f $toolName, $parts.Server, $trId)

# --- Scan with AIRS tool_event ---
$scan = Invoke-AirsScanToolEvent -Server $parts.Server -Tool $parts.Tool -InputText $toolInputStr -OutputText '' -SessionId $trId

# Fail-open on transport error
if (-not $scan) {
    Write-Log ("PRE-MCP: request error scanning tool={0}; failing open" -f $toolName)
    Send-Allow; exit 0
}

$action   = if ($scan.action)   { [string]$scan.action }   else { '' }
$category = if ($scan.category)  { [string]$scan.category }  else { 'unknown' }
$scanId   = if ($scan.scan_id)   { [string]$scan.scan_id }   else { 'unknown' }

# Fail-open on empty/unparseable verdict
if ([string]::IsNullOrEmpty($action) -or $action -eq 'null') {
    Write-Log ("PRE-MCP: Empty or unparseable AIRS response for tool={0}; failing open" -f $toolName)
    Send-Allow; exit 0
}

$detections = Get-Detections $scan

# --- Enforce ---
if ($action -eq 'block') {
    if ($detections) {
        Write-Log ("PRE-MCP: BLOCKED tool={0} category={1} detections=[{2}] scan_id={3}" -f $toolName, $category, $detections, $scanId)
    } else {
        Write-Log ("PRE-MCP: BLOCKED tool={0} category={1} scan_id={2}" -f $toolName, $category, $scanId)
    }

    $detLine = if ($detections) { "`nDetections: $detections" } else { '' }
    $userMsg = "Prisma AIRS blocked this MCP tool call.`n`n" +
               "Tool: $toolName`n" +
               "Scan ID: $scanId`n" +
               "Category: $category$detLine`n`n" +
               "The tool input was flagged for potential security issues."
    $agentMsg = "AIRS security scan blocked the $toolName tool call (scan_id: $scanId, category: $category). " +
                "Do not retry this tool call. Inform the user that the tool input was flagged by security scanning."

    Send-Deny $userMsg $agentMsg
    exit 2
}

# --- Allow ---
if ($detections) {
    Write-Log ("PRE-MCP: ALLOWED tool={0} action={1} category={2} detections=[{3}] scan_id={4}" -f $toolName, $action, $category, $detections, $scanId)
} else {
    Write-Log ("PRE-MCP: ALLOWED tool={0} action={1} scan_id={2}" -f $toolName, $action, $scanId)
}
Send-Allow
exit 0
