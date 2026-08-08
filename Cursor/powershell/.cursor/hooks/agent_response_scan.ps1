# Prisma AIRS Agent Response Security Scanner Hook for Cursor (Windows / PowerShell)
# afterAgentResponse: scans assistant responses AFTER generation to catch sensitive
# or malicious output.
#
# Output contract: exit 0 = allow (no JSON), exit 2 = block

. (Join-Path $PSScriptRoot 'prisma-airs.ps1')

$InputJson = [Console]::In.ReadToEnd()
try { $data = $InputJson | ConvertFrom-Json } catch { $data = $null }

# Try common response-bearing field names (.text first, then others)
$responseText = ''
if ($data) {
    foreach ($f in 'text', 'response', 'message', 'content', 'output') {
        if (($data.PSObject.Properties.Name -contains $f) -and -not [string]::IsNullOrEmpty([string]$data.$f)) {
            $responseText = [string]$data.$f
            break
        }
    }
}

# Nothing to scan - allow silently
if ([string]::IsNullOrEmpty($responseText)) { exit 0 }

# Truncate before scanning
$truncated = if ($responseText.Length -gt 20000) { $responseText.Substring(0, 20000) } else { $responseText }
Write-Log ("AGENT-RESPONSE: Scanning assistant response ({0} chars)" -f $truncated.Length)

# Fail-closed: block if credentials missing
if ([string]::IsNullOrEmpty($Script:PrismaAirsApiKey) -or -not (Test-HasProfile)) {
    Write-Log 'ERROR: PRISMA_AIRS_API_KEY or profile not set - blocking response (fail-closed)'
    Write-HookError 'Prisma AIRS: API key or profile not configured - blocking response (fail-closed)'
    exit 2
}

# Use Cursor's conversation_id to group all scans in one session
$trId = if ($data.conversation_id) { [string]$data.conversation_id } else { New-SessionId 'cursor-response' }

$scan = Invoke-AirsScan -Content $truncated -ContentType 'response' -SessionId $trId

$action     = if ($scan -and $scan.action)   { [string]$scan.action }   else { 'unknown' }
$category   = if ($scan -and $scan.category)  { [string]$scan.category }  else { 'unknown' }
$scanId     = if ($scan -and $scan.scan_id)   { [string]$scan.scan_id }   else { 'unknown' }
$detections = Get-Detections $scan

if ($action -eq 'block') {
    if ($detections) {
        Write-Log ("BLOCKED AGENT RESPONSE: {0} - detected: [{1}] (scan_id: {2})" -f $category, $detections, $scanId)
        $blockMsg = "Blocked by Prisma AIRS: Agent response contained $category content (detected: $detections)"
    } else {
        Write-Log ("BLOCKED AGENT RESPONSE: {0} (scan_id: {1})" -f $category, $scanId)
        $blockMsg = "Blocked by Prisma AIRS: Agent response contained $category content"
    }

    Write-HookError ''
    Write-HookError $blockMsg
    Write-HookError ''

    exit 2
}

# Log allow - no stdout JSON for this hook
if ($detections) {
    Write-Log ("ALLOWED AGENT RESPONSE: {0} - detected: [{1}] (scan_id: {2})" -f $category, $detections, $scanId)
} else {
    Write-Log ("ALLOWED AGENT RESPONSE: {0} (scan_id: {1})" -f $category, $scanId)
}
exit 0
