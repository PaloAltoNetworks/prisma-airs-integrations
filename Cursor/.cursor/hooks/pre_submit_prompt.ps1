# Prisma AIRS Prompt Security Scanner Hook for Cursor (Windows / PowerShell)
# beforeSubmitPrompt: scans user prompts BEFORE submission to detect prompt injection.
#
# Cursor contract:
#   stdin  -> JSON { prompt, conversation_id, ... }
#   stdout -> {"continue":true}  or  {"continue":false,"user_message":"..."}
#   exit 0 = allow, exit 2 = block

. "$PSScriptRoot\prisma-airs.ps1"

function Send-Allow { Write-HookJson '{"continue":true}' }
function Send-Deny([string]$Message) {
    Write-HookJson ((@{ continue = $false; user_message = $Message } | ConvertTo-Json -Compress))
}

$InputJson = [Console]::In.ReadToEnd()
try { $data = $InputJson | ConvertFrom-Json } catch { $data = $null }

$prompt = if ($data) { [string]$data.prompt } else { '' }

# Nothing to scan
if ([string]::IsNullOrEmpty($prompt)) { Send-Allow; exit 0 }

# Truncate before scanning
$truncated = if ($prompt.Length -gt 20000) { $prompt.Substring(0, 20000) } else { $prompt }
Write-Log ("PRE-PROMPT: Scanning user prompt ({0} chars)" -f $truncated.Length)

# Fail-closed: block if credentials missing
if ([string]::IsNullOrEmpty($Script:PrismaAirsApiKey) -or -not (Test-HasProfile)) {
    Write-Log 'ERROR: PRISMA_AIRS_API_KEY or profile not set - blocking prompt (fail-closed)'
    Write-HookError 'Prisma AIRS: API key or profile not configured - blocking prompt (fail-closed)'
    Send-Deny 'Prisma AIRS: API key or profile not configured - blocking prompt (fail-closed)'
    exit 2
}

# Use Cursor's conversation_id to group all scans in one session
$trId = if ($data.conversation_id) { [string]$data.conversation_id } else { New-SessionId 'cursor-prompt' }

$scan = Invoke-AirsScan -Content $truncated -ContentType 'prompt' -SessionId $trId

$action     = if ($scan -and $scan.action)   { [string]$scan.action }   else { 'unknown' }
$category   = if ($scan -and $scan.category)  { [string]$scan.category }  else { 'unknown' }
$scanId     = if ($scan -and $scan.scan_id)   { [string]$scan.scan_id }   else { 'unknown' }
$detections = Get-Detections $scan

if ($action -eq 'block') {
    if ($detections) {
        Write-Log ("BLOCKED USER PROMPT: {0} - detected: [{1}] (scan_id: {2})" -f $category, $detections, $scanId)
        $blockMsg = "Blocked by Prisma AIRS: Prompt contained $category content (detected: $detections)"
    } else {
        Write-Log ("BLOCKED USER PROMPT: {0} (scan_id: {1})" -f $category, $scanId)
        $blockMsg = "Blocked by Prisma AIRS: Prompt contained $category content"
    }

    Write-HookError ''
    Write-HookError $blockMsg
    Write-HookError 'This prompt may contain prompt injection, jailbreaking, or malicious instructions.'
    Write-HookError ''

    Send-Deny $blockMsg
    exit 2
}

# Log allow and proceed
if ($detections) {
    Write-Log ("ALLOWED USER PROMPT: {0} - detected: [{1}] (scan_id: {2})" -f $category, $detections, $scanId)
} else {
    Write-Log ("ALLOWED USER PROMPT: {0} (scan_id: {1})" -f $category, $scanId)
}
Send-Allow
exit 0
