#!/usr/bin/env pwsh
# =============================================================================
# Prisma AIRS security hook — PowerShell core engine (core-parity port).
#
# Windows-native: uses Invoke-RestMethod + ConvertTo/From-Json — NO jq, NO curl.
# One script, all six vendors (-Vendor), all four checkpoints (-EventName).
# Core parity with the Node.js / bash engines:
#   • 4 checkpoints, correct AIRS content-types incl. tool_event (tools/call)
#   • per-tool input mapping, recursive string capture on tool output
#   • fail-closed on input / fail-open on output, Stop loop-guard
#   • no silent truncation
# NOT ported (nodejs only): DLP mask-in-place, multi-chunk scanning.
#
# NOTE: uses PowerShell-native flags (-Vendor / -EventName), since PowerShell
# does not pass through POSIX-style "--vendor". Works on Windows PowerShell 5.1+ / PowerShell 7+.
# =============================================================================
param(
  # $Vendor starts EMPTY (not 'claude') so an OMITTED -Vendor is distinguishable from an explicit one.
  [string]$Vendor = '',
  [string]$EventName = ''
)
$ErrorActionPreference = 'Stop'
# Suppress the WARNING stream: ConvertTo-Json emits a depth-truncation warning that, on this host,
# can surface on STDOUT and corrupt the deny-JSON decision channel (clients parse stdout as JSON).
$WarningPreference = 'SilentlyContinue'
$Vendor = $Vendor.ToLower()
# Vendor dispatch is a config-time contract (in the install's wiring), not attacker-controlled. But an
# UNKNOWN -Vendor must never silently alias to Claude: on a stdout-reading client (Cursor/Cline) a
# Claude-shaped block renders in the wrong channel and fails OPEN. Fail closed loudly on unknown; on an
# OMITTED vendor keep the historical Claude default but say so. (ASCII only — PS 5.1 console safety.)
$KnownVendors = @('claude','codex','cursor','cline','devin','antigravity','gemini')
if ($Vendor -eq '') {
  [Console]::Error.Write("[airs-hooks] no -Vendor given; defaulting to claude`n"); $Vendor = 'claude'
} elseif ($Vendor -notin $KnownVendors) {
  [Console]::Error.Write("`n[BLOCK] Prisma AIRS: unknown -Vendor '$Vendor' - blocking (fail-closed). Known: $($KnownVendors -join ', ').`n`n")
  exit 2
}
# Windows PowerShell 5.1 defaults to old TLS — force 1.2 so the AIRS HTTPS call works.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# Parse a non-negative integer env var WITHOUT throwing. A bad value (e.g. AIRS_TIMEOUT_MS=abc)
# must never crash config parsing into a bare `exit 1` — which every client reads as a
# non-blocking hook error (fail-OPEN). Mirrors the bash `case ''|*[!0-9]*` guard.
function IntEnv([string]$v, [int]$d) { $n = 0; if ([int]::TryParse($v, [ref]$n) -and $n -ge 0) { $n } else { $d } }

# ---- config -----------------------------------------------------------------
$BaseUrl     = if ($env:PRISMA_AIRS_URL) { $env:PRISMA_AIRS_URL.TrimEnd('/') } else { 'https://service.api.aisecurity.paloaltonetworks.com' }
$ApiUrl      = "$BaseUrl/v1/scan/sync/request"
$ApiKey      = $env:PRISMA_AIRS_API_KEY
$ProfileId   = $env:PRISMA_AIRS_PROFILE_ID
$ProfileName = $env:PRISMA_AIRS_PROFILE_NAME
$LogFile     = if ($env:SECURITY_LOG_PATH) { $env:SECURITY_LOG_PATH } else { '' }   # per-agent default set below
$TimeoutMs   = IntEnv $env:AIRS_TIMEOUT_MS 10000
$Retries     = IntEnv $env:AIRS_RETRIES 1
# normalize case/whitespace so "CLOSED" / "Closed" / " closed " all mean closed; only a clean "open" opts out.
$FailMode    = if ($env:AIRS_FAIL_MODE) { $env:AIRS_FAIL_MODE.Trim().ToLower() } else { 'closed' }
if ($FailMode -ne 'open') { $FailMode = 'closed' }
# A brand-new install with NO API key is "unconfigured" (first run), NOT an attack: by default pass
# such traffic through with a loud warning rather than brick the agent. AIRS_REQUIRE_CONFIG=1 restores
# hard fail-closed. Separate from FailMode (which governs SCAN failures, where a key IS set).
$RequireConfig = ($env:AIRS_REQUIRE_CONFIG -in @('1','true','yes'))
$Suffix      = if ($env:AIRS_APP_SUFFIX) { $env:AIRS_APP_SUFFIX } elseif ($env:CLAUDE_CODE_APP_SUFFIX) { $env:CLAUDE_CODE_APP_SUFFIX } else { '' }
$Debug       = ($env:AIRS_DEBUG -in @('1','true','yes'))
$CodeAware   = ($null -eq $env:AIRS_CODE_AWARE) -or ($env:AIRS_CODE_AWARE -in @('1','true','yes'))
$TimeoutSec  = [int][math]::Ceiling($TimeoutMs / 1000.0); if ($TimeoutSec -lt 1) { $TimeoutSec = 1 }
# PowerShell has no chunking: content past this budget can't be scanned -> fail-mode.
$MaxChars    = IntEnv $env:AIRS_MAX_CONTENT_CHARS 20000; if ($MaxChars -lt 1) { $MaxChars = 20000 }
$MaxChunks   = IntEnv $env:AIRS_MAX_CHUNKS 6; if ($MaxChunks -lt 1) { $MaxChunks = 6 }
$MaxBudget   = $MaxChars * $MaxChunks

$AppName = switch ($Vendor) {
  'claude'      { 'Claude Code' }
  'codex'       { 'Codex CLI' }
  'cursor'      { 'Cursor' }
  'cline'       { 'Cline' }
  'devin'       { 'Devin CLI' }
  'antigravity' { 'Antigravity' }
  'gemini'      { 'Gemini CLI' }
  default       { 'Claude Code' }
}
$CfgDir = switch ($Vendor) {
  'claude' { '.claude' } 'codex' { '.codex' } 'cursor' { '.cursor' } 'cline' { '.clinerules' }
  'devin' { '.devin' } 'antigravity' { '.agents' } 'gemini' { '.gemini' } default { '.claude' }
}
if ($Suffix) { $AppName = "$AppName-$Suffix" }
# app_user now reflects the actual agent (was hardcoded 'claude-code-user'); env-overridable.
$AppUser = if ($env:AIRS_APP_USER) { $env:AIRS_APP_USER } else { "$Vendor-user" }
if (-not $LogFile) { $LogFile = "$CfgDir/hooks/prisma-airs.log" }

function Dbg($m) { if ($Debug) { [Console]::Error.WriteLine("[airs-hooks] $m") } }

# ---- read stdin once --------------------------------------------------------
$Raw = ''; try { $Raw = [Console]::In.ReadToEnd() } catch { $Raw = '' }
$In  = $null
if ($Raw -and $Raw.Trim().Length -gt 0) { try { $In = $Raw | ConvertFrom-Json } catch { $In = $null } }
function Field($obj, [string]$name) { if ($null -eq $obj) { return $null } $p = $obj.PSObject.Properties[$name]; if ($p) { $p.Value } else { $null } }

# ---- event mapping ----------------------------------------------------------
$RawEvent = if ($EventName) { $EventName } else { [string](Field $In 'hook_event_name') }
$IEvent = switch ($Vendor) {
  'cursor' { switch ($RawEvent) { 'beforeSubmitPrompt'{'UserPromptSubmit'} 'beforeShellExecution'{'PreToolUse'} 'beforeMCPExecution'{'PreToolUse'} 'postToolUse'{'PostToolUse'} 'afterAgentResponse'{'Stop'} default{''} } }
  'cline' { switch ($RawEvent) { 'UserPromptSubmit'{'UserPromptSubmit'} 'PreToolUse'{'PreToolUse'} 'PostToolUse'{'PostToolUse'} 'TaskComplete'{'Stop'} default{''} } }
  { $_ -in @('antigravity','gemini') } { switch ($RawEvent) { {$_ -in @('BeforeAgent','UserPromptSubmit','PreInvocation')}{'UserPromptSubmit'} {$_ -in @('BeforeTool','PreToolUse')}{'PreToolUse'} {$_ -in @('AfterTool','PostToolUse')}{'PostToolUse'} {$_ -in @('AfterAgent','Stop','SubagentStop','PostInvocation')}{'Stop'} default{''} } }
  default { switch ($RawEvent) { 'UserPromptSubmit'{'UserPromptSubmit'} 'PreToolUse'{'PreToolUse'} 'PostToolUse'{'PostToolUse'} {$_ -in @('Stop','SubagentStop')}{'Stop'} default{''} } }
}
$Side = if ($IEvent -in @('UserPromptSubmit','PreToolUse')) { 'input' } else { 'output' }

# ---- render (vendor wire format) then EXIT ----------------------------------
function Render([string]$kind, [string]$text) {
  $out = ''; $code = 0
  switch ($Vendor) {
    'claude' {
      if ($kind -eq 'block') {
        switch ($IEvent) {
          'PreToolUse'       { $out = @{ hookSpecificOutput = @{ hookEventName='PreToolUse'; permissionDecision='deny'; permissionDecisionReason=$text } } | ConvertTo-Json -Compress -Depth 6 }
          'UserPromptSubmit' { $out = @{ decision='block'; reason=$text; hookSpecificOutput=@{ hookEventName='UserPromptSubmit' } } | ConvertTo-Json -Compress -Depth 6 }
          'PostToolUse'      { $out = @{ decision='block'; reason=$text; hookSpecificOutput=@{ hookEventName='PostToolUse' } } | ConvertTo-Json -Compress -Depth 6 }
          'Stop'             { $out = @{ decision='block'; reason=$text } | ConvertTo-Json -Compress -Depth 6 }
        }
      }
    }
    'codex' {
      if ($kind -eq 'block') {
        switch ($IEvent) {
          { $_ -in @('UserPromptSubmit','PreToolUse') } { $code = 2 }
          'PostToolUse' { $out = @{ decision='block'; reason=$text; hookSpecificOutput=@{ hookEventName='PostToolUse' } } | ConvertTo-Json -Compress -Depth 6 }
          'Stop'        { $out = @{ continue=$false; stopReason=$text } | ConvertTo-Json -Compress -Depth 6 }
        }
      } elseif ($IEvent -eq 'Stop') { $out = '{"continue":true}' }
    }
    'cursor' {
      # Cursor reads decisions from STDOUT. Pre-tool hard-blocks via permission=deny.
      # postToolUse can't hard-block — MCP output is redacted (updated_mcp_tool_output)
      # + warned (additional_context); non-MCP only warned. beforeSubmitPrompt advisory;
      # afterAgentResponse can't block.
      if ($kind -eq 'block') {
        switch ($IEvent) {
          'UserPromptSubmit' { $out = @{ continue=$false; user_message=$text } | ConvertTo-Json -Compress -Depth 6 }
          'PreToolUse'       { $out = @{ permission='deny'; user_message=$text; agent_message=$text } | ConvertTo-Json -Compress -Depth 6 }
          'PostToolUse'      { $out = @{ updated_mcp_tool_output=("[Prisma AIRS blocked this tool output: " + $text + "]"); additional_context=("⚠️ Prisma AIRS flagged this tool output: " + $text) } | ConvertTo-Json -Compress -Depth 6 }
          default            { $code = 0 }
        }
      } else {
        switch ($IEvent) {
          'UserPromptSubmit' { $out = '{"continue":true}' }
          'PreToolUse'       { $out = '{"permission":"allow"}' }
          'PostToolUse'      { $out = '{}' }
        }
      }
    }
    'cline' {
      if ($kind -eq 'block') {
        if ($IEvent -eq 'Stop') { $out = @{ cancel=$false; contextModification=$text } | ConvertTo-Json -Compress -Depth 6 }
        else { $out = @{ cancel=$true; errorMessage=$text } | ConvertTo-Json -Compress -Depth 6 }
      } elseif ($kind -eq 'warn') { $out = @{ cancel=$false; contextModification=("Prisma AIRS: " + $text) } | ConvertTo-Json -Compress -Depth 6 }
      else { $out = '{"cancel":false}' }
    }
    'devin' {
      # Devin CLI: PreToolUse is the only hard block (exit 2). UserPromptSubmit can
      # only inject additionalContext (advisory); PostToolUse/Stop are advisory too.
      if ($kind -eq 'block') {
        switch ($IEvent) {
          'PreToolUse'       { $code = 2 }
          'UserPromptSubmit' { $out = @{ hookSpecificOutput = @{ hookEventName='UserPromptSubmit'; additionalContext=("⚠️ Prisma AIRS flagged this prompt: " + $text) } } | ConvertTo-Json -Compress -Depth 6 }
          default            { $code = 0 }
        }
      }
    }
    { $_ -in @('antigravity','gemini') } {
      # Gemini CLI blocks via exit 2 on BeforeAgent/BeforeTool/AfterTool.
      # AfterAgent(Stop) is advisory (exit 2 there triggers a retry loop).
      if ($kind -eq 'block') {
        switch ($IEvent) {
          { $_ -in @('UserPromptSubmit','PreToolUse','PostToolUse') } { $code = 2 }
          default { $code = 0 }
        }
      }
    }
  }
  if ($out) { [Console]::Out.Write($out) }
  if ($kind -eq 'warn') { [Console]::Error.Write("[Prisma AIRS] $text`n") }
  elseif ($kind -eq 'block') {
    if ($Vendor -eq 'devin' -and $IEvent -in @('UserPromptSubmit','PostToolUse','Stop')) { [Console]::Error.Write("`n[ALERT] Devin $IEvent is advisory (not a hard block) - $text`n`n") }
    elseif ($Vendor -eq 'cursor' -and $IEvent -eq 'Stop') { [Console]::Error.Write("`n[ALERT] Cursor cannot block the model answer - $text`n`n") }
    elseif ($Vendor -in @('gemini','antigravity') -and $IEvent -eq 'Stop') { [Console]::Error.Write("`n[ALERT] Gemini response scanned; not hard-blocked (avoids retry loop) - $text`n`n") }
    else { [Console]::Error.Write("`n[BLOCKED] $text`n`n") }
  }
  exit $code
}

# Top-level safety net: any unexpected terminating error honors the fail mode instead of
# bubbling up as a bare exit 1 (which every client reads as non-blocking). Render calls exit.
trap {
  try { [Console]::Error.Write("[airs-hooks] internal error - $($_.Exception.Message)`n") } catch { }
  # Fail-closed on the input side unless fail-open was explicitly requested — default to block
  # even when $FailMode was never assigned (an error before config parsing).
  if ($Side -eq 'input' -and $FailMode -ne 'open') { Render 'block' "Prisma AIRS internal error - blocking (fail-closed)" }
  Render 'allow' ''
}

function Log([string]$label, [string]$tag) {
  try {
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    $dir = Split-Path -Parent $LogFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Add-Content -Path $LogFile -Value "[$ts] $IEvent $label`: $tag"
  } catch { }
}

# malformed / non-object stdin — non-empty raw that ConvertFrom-Json rejected, or a JSON
# primitive/array/null (top-level hook input is always an object). Runs BEFORE the unhandled-event
# allow so a malformed body with NO resolvable event fails CLOSED (as bash/node do). The leading-'['
# check catches a single-element array [{...}] that `$Raw | ConvertFrom-Json` unwraps to an object.
if ($Raw.Trim().Length -gt 0 -and ($Raw.Trim()[0] -eq '[' -or -not ($In -is [System.Management.Automation.PSCustomObject]))) {
  Log 'input' "unscannable (hook input is not a JSON object)"
  if (-not $IEvent) { [Console]::Error.Write("`n[BLOCKED] Prisma AIRS could not scan (hook input is not a JSON object) - fail-closed`n`n"); exit 2 }
  if ($Side -eq 'input') { Render 'block' "Prisma AIRS could not scan (hook input is not a JSON object) - blocking (fail-closed)" }
  else { Render 'warn' "Prisma AIRS could not scan (hook input is not a JSON object) - content NOT scanned" }
}

if (-not $IEvent) { Dbg "unhandled event '$RawEvent' for vendor '$Vendor'"; Render 'allow' '' }

# ---- helpers ----------------------------------------------------------------
# For a non-string value, collect all strings/keys recursively (depth-gated via $script:OverDepth)
# rather than ConvertTo-Json -Depth 10, which truncated a deep structured field value to a lossy
# stub and dropped the injection -> input-side fail-open. Get-AllStrings is defined below.
function JStr($v) { if ($v -is [string]) { $v } elseif ($null -eq $v) { '' } else { (Get-AllStrings $v) -join "`n" } }
function JoinF([object[]]$parts) { ($parts | ForEach-Object { if ($null -eq $_) { } elseif ($_ -is [string]) { if ($_ -ne '') { $_ } } else { (Get-AllStrings $_) -join "`n" } }) -join "`n" }
function Flatten([string]$s) { if ($null -eq $s) { '' } else { $s -replace "[\r\n]", ' ' } }

function Get-AllStrings($o) {
  # Collect every string VALUE and every object KEY, recursively. Depth cap is 64 (well beyond
  # any real MCP/tool payload) — content nested deeper is flagged via $script:OverDepth so the
  # caller can fail-closed on the input side instead of silently dropping an unscanned payload.
  $acc = New-Object System.Collections.Generic.List[string]
  function _walk($x, $d) {
    if ($null -eq $x) { return }
    if ($d -gt 199) { $script:OverDepth = $true; return }   # align with bash's <200 depth gate; avoid over-blocking realistic deep-but-benign input
    if ($x -is [string]) { if ($x.Length -gt 0) { $acc.Add($x) } }
    elseif ($x -is [System.Collections.IEnumerable] -and -not ($x -is [string])) { foreach ($e in $x) { _walk $e ($d+1) } }
    elseif ($x -is [System.Management.Automation.PSCustomObject]) { foreach ($p in $x.PSObject.Properties) { if ($p.Name) { $acc.Add([string]$p.Name) }; _walk $p.Value ($d+1) } }
  }
  _walk $o 0
  $acc
}
function Get-TrueKeys($o) {
  $acc = New-Object System.Collections.Generic.List[string]
  function _walk($x) {
    if ($null -eq $x) { return }
    if ($x -is [System.Management.Automation.PSCustomObject]) {
      foreach ($p in $x.PSObject.Properties) {
        if ($p.Value -is [bool] -and $p.Value) { $acc.Add($p.Name) }
        elseif ($p.Value -is [System.Management.Automation.PSCustomObject] -or ($p.Value -is [System.Collections.IEnumerable] -and -not ($p.Value -is [string]))) { _walk $p.Value }
      }
    } elseif ($x -is [System.Collections.IEnumerable] -and -not ($x -is [string])) { foreach ($e in $x) { _walk $e } }
  }
  _walk $o
  $acc
}

function ToolIdentity([string]$name, $ti) {
  if ($name -like 'mcp__*') {
    $parts = $name -split '__'
    $script:Server = if ($parts.Count -ge 2 -and $parts[1]) { $parts[1] } else { 'unknown' }
    $script:Tool   = if ($parts.Count -ge 3) { ($parts[2..($parts.Count-1)] -join '__') } elseif ($parts.Count -ge 2) { $parts[1] } else { $name }
  } elseif ($name -in @('ReadMcpResourceTool','ReadMcpResourceDirTool','ListMcpResourcesTool')) {
    $s = Field $ti 'server'; $script:Server = if ($s) { $s } else { 'unknown' }
    $u = Field $ti 'uri'; $p = Field $ti 'path'
    $script:Tool = if ($u) { $u } elseif ($p) { $p } else { $name }
  } else {
    $nm = if ([string]::IsNullOrEmpty($name)) { 'unknown' } else { $name }
    $script:Server = "claude-code/$nm"
    $script:Tool   = $nm
  }
}

function ToolInputText([string]$name, $ti) {
  # non-object tool_input (array/primitive) can't be field-indexed; collect it wholesale so a
  # primitive/array injection for a KNOWN built-in tool isn't dropped to empty (input-side fail-open).
  if ($null -ne $ti -and -not ($ti -is [System.Management.Automation.PSCustomObject])) { return (Get-AllStrings $ti) -join "`n" }
  switch ($name) {
    'Bash'         { JoinF @((Field $ti 'command'), (Field $ti 'description')) }
    'WebFetch'     { JoinF @((Field $ti 'url'), (Field $ti 'prompt')) }
    'WebSearch'    { JStr (Field $ti 'query') }
    'Write'        { JoinF @((Field $ti 'file_path'), (Field $ti 'content')) }
    'Edit'         { JoinF @((Field $ti 'file_path'), (Field $ti 'old_string'), (Field $ti 'new_string')) }
    'Read'         { JStr (Field $ti 'file_path') }
    'Glob'         { JoinF @((Field $ti 'pattern'), (Field $ti 'path')) }
    'Grep'         { JoinF @((Field $ti 'pattern'), (Field $ti 'path')) }
    'Task'         { JoinF @((Field $ti 'description'), (Field $ti 'subagent_type'), (Field $ti 'prompt')) }
    'NotebookEdit' { JoinF @((Field $ti 'notebook_path'), (Field $ti 'new_source')) }
    'TodoWrite'    { (Get-AllStrings (Field $ti 'todos')) -join "`n" }
    'ExitPlanMode' { JStr (Field $ti 'plan') }
    { $_ -in @('ReadMcpResourceTool','ReadMcpResourceDirTool') } { JoinF @((Field $ti 'server'), (Field $ti 'uri'), (Field $ti 'path')) }
    'ListMcpResourcesTool' { JStr (Field $ti 'server') }
    default { if ($null -eq $ti) { '' } else { (Get-AllStrings $ti) -join "`n" } }  # recurse (no Depth-10 truncation); over-depth is flagged for fail-closed
  }
}
function NormToolName([string]$n) { if ($n -like 'MCP:*') { 'mcp__' + (($n.Substring(4)) -replace ':', '__') } else { $n } }

# ---- normalize + ScanPlan ---------------------------------------------------
$Kind=''; $Text=''; $Server=''; $Tool=''; $InText=''; $ToolName=''; $StopActive=$false; $Label=''
$script:OverDepth = $false   # set by Get-AllStrings when content nests past the scan-depth cap
switch ($IEvent) {
  'UserPromptSubmit' {
    $Label='user prompt'; $Kind='prompt'
    # Get-AllStrings (not JStr): a non-string prompt (array/object) is collected recursively — depth
    # gated by $script:OverDepth — instead of JStr's ConvertTo-Json -Depth 10, which would truncate a
    # deep injection to a lossy stub and fail open. For a plain string it returns the string as-is.
    $Text = switch ($Vendor) {
      'cline'    { (Get-AllStrings (Field (Field $In 'userPromptSubmit') 'prompt')) -join "`n" }
      default    { (Get-AllStrings (Field $In 'prompt')) -join "`n" }
    }
  }
  'PreToolUse' {
    $Kind='toolInput'; $ti=$null
    switch ($Vendor) {
      'cline'    { $ToolName=[string](Field (Field $In 'preToolUse') 'toolName'); $ti=Field (Field $In 'preToolUse') 'parameters' }
      'cursor'   {
        if ($RawEvent -eq 'beforeShellExecution') { $ToolName='Shell'; $ti=[pscustomobject]@{ command=(Field $In 'command') } }  # keep raw (no [string] cast) so a non-string command is collected, not collapsed to a lossy stub
        else { $ToolName=NormToolName([string](Field $In 'tool_name')); $ti=Field $In 'tool_input' }
      }
      { $_ -in @('antigravity','gemini') } { $tn=Field $In 'tool_name'; if (-not $tn) { $tn=Field (Field $In 'toolCall') 'name' }; $ToolName=[string]$tn; $ti=Field $In 'tool_input'; if ($null -eq $ti) { $ti=Field (Field $In 'toolCall') 'args' } }
      default    { $ToolName=[string](Field $In 'tool_name'); $ti=Field $In 'tool_input' }
    }
    $Label="$(if ($ToolName) { $ToolName } else { 'tool' }) input"
    $Text = ToolInputText $ToolName $ti
    ToolIdentity $ToolName $ti
  }
  'PostToolUse' {
    $Kind='toolOutput'; $ti=$null; $tr=$null
    switch ($Vendor) {
      'cline'    { $ptu=Field $In 'postToolUse'; $ToolName=[string](Field $ptu 'toolName'); $ti=Field $ptu 'parameters'; $tr=Field $ptu 'result' }
      'cursor'   { $ToolName=NormToolName([string](Field $In 'tool_name')); $ti=Field $In 'tool_input'; $tr=Field $In 'tool_response'; if ($null -eq $tr) { $tr=Field $In 'tool_output' } }
      { $_ -in @('antigravity','gemini') } { $tn=Field $In 'tool_name'; if (-not $tn) { $tn=Field (Field $In 'toolCall') 'name' }; $ToolName=[string]$tn; $ti=Field $In 'tool_input'; $tr=Field $In 'tool_response'; if ($null -eq $tr) { $tr=Field $In 'tool_result' } }
      default    { $ToolName=[string](Field $In 'tool_name'); $ti=Field $In 'tool_input'; $tr=Field $In 'tool_response'; if ($null -eq $tr) { $tr=Field $In 'tool_result' } }
    }
    $Label="$(if ($ToolName) { $ToolName } else { 'tool' }) output"
    $Text = (Get-AllStrings $tr) -join "`n"
    $InText = ToolInputText $ToolName $ti
    ToolIdentity $ToolName $ti
  }
  'Stop' {
    $Label='model answer'; $Kind='response'
    switch ($Vendor) {
      'cline'    { $Text=[string](Field (Field $In 'taskComplete') 'task') }
      'cursor'   { $t=Field $In 'text'; foreach ($k in @('response','message','content','output')) { if (-not $t) { $t=Field $In $k } }; $Text=[string]$t }
      { $_ -in @('antigravity','gemini') } { $t=Field $In 'last_assistant_message'; foreach ($k in @('prompt_response','response','agent_response')) { if (-not $t) { $t=Field $In $k } }; $Text=[string]$t; $StopActive=[bool](Field $In 'stop_hook_active') }
      default    { $Text=[string](Field $In 'last_assistant_message'); $StopActive=[bool](Field $In 'stop_hook_active') }
    }
  }
}

if ($IEvent -eq 'Stop' -and $StopActive) { Dbg 'stop_hook_active set - allowing (loop guard)'; Render 'allow' '' }

# Do NOT flatten newlines before scanning — ConvertTo-Json escapes them, and the verdict
# must be made on the real multi-line text (what actually executes).

# ---- config error -----------------------------------------------------------
$CfgErr = ''; $Unconfigured = $false
if (-not $ApiKey) { $CfgErr = 'PRISMA_AIRS_API_KEY not set'; $Unconfigured = $true }
elseif (-not $ProfileId -and -not $ProfileName) { $CfgErr = 'PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set' }
if ($CfgErr) {
  Log $Label "config_error ($CfgErr)"
  # Genuinely UNCONFIGURED (no key) + not strict -> pass through with a LOUD per-call warning so a
  # copy-the-folder install before .env exists doesn't brick the agent. A key set but half-configured
  # (no profile) is a real misconfig -> fall through to fail-closed on input.
  if ($Unconfigured -and -not $RequireConfig) {
    [Console]::Error.Write("`n[WARN] Prisma AIRS NOT CONFIGURED - traffic passing UNSCANNED. Set PRISMA_AIRS_API_KEY (+ profile) in $CfgDir\hooks\.env, then reload. (AIRS_REQUIRE_CONFIG=1 to block instead.)`n`n")
    Render 'allow' ''
  }
  if ($Side -eq 'input') { Render 'block' "Prisma AIRS not configured ($CfgErr) - set it in $CfgDir\hooks\.env - blocking (fail-closed)" }
  else { Render 'warn' "Prisma AIRS not configured ($CfgErr) - content NOT scanned" }
}

# over-depth is checked BEFORE the empty-content allow: a payload nested past the depth cap
# (e.g. a pure deep ARRAY with no collectable keys/strings) collects to empty $Text, which would
# otherwise hit the empty-content allow and fail OPEN. Block on input, warn on output.
if ($script:OverDepth) {
  Log $Label "content_over_depth (nesting exceeds scan depth)"
  if ($Side -eq 'input') { Render 'block' "Content nesting exceeds the AIRS scan depth - blocking unscanned (fail-closed)" }
  else { Render 'warn' "Content nesting exceeds the AIRS scan depth - NOT fully scanned" }
}
if ([string]::IsNullOrWhiteSpace($Text)) { Dbg "no scannable content for $Label - allowing"; Render 'allow' '' }

# oversized content -> PowerShell can't chunk, so the tail is UNSCANNABLE. Block on input
# (regardless of fail-mode), warn on output. Never silently allowed.
if ($Text.Length -gt $MaxBudget) {
  Log $Label "content_overflow ($($Text.Length) chars > $MaxBudget budget)"
  if ($Side -eq 'input') { Render 'block' "Content exceeds the AIRS scan budget ($($Text.Length) chars) - blocking unscanned" }
  else { Render 'warn' "Content exceeds the AIRS scan budget ($($Text.Length) chars) - NOT fully scanned" }
}

# ---- build AIRS request -----------------------------------------------------
$AiProfile = if ($ProfileId) { @{ profile_id = $ProfileId } } else { @{ profile_name = $ProfileName } }
$Session = ''
foreach ($k in @('session_id','taskId','trajectory_id','conversation_id','conversationId')) { if (-not $Session) { $v = Field $In $k; if ($v) { $Session = [string]$v } } }
if (-not $Session) {
  $cwd = [string](Field $In 'cwd'); if (-not $cwd) { $cwd = (Get-Location).Path }
  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($cwd))
  $Session = -join ($sha | ForEach-Object { $_.ToString('x2') }); $Session = $Session.Substring(0, [math]::Min(32, $Session.Length))
}
$Txn = ''
foreach ($k in @('tool_use_id','prompt_id','turn_id')) { if (-not $Txn) { $v = Field $In $k; if ($v) { $Txn = [string]$v } } }
# per-event id: synthesize a GUID rather than reusing the session id, so AIRS can distinguish
# turns even when the client gives no per-turn id.
if (-not $Txn) { $Txn = [guid]::NewGuid().ToString() }

$Content = switch ($Kind) {
  'prompt'   { $c = @{ prompt = $Text };   if ($CodeAware) { $c['code_prompt'] = $Text };   $c }
  'response' { $c = @{ response = $Text }; if ($CodeAware) { $c['code_response'] = $Text }; $c }
  'toolInput' {
    $te = @{ metadata = @{ ecosystem='mcp'; method='tools/call'; server_name=$Server; tool_invoked=$Tool } }
    if ($Text.Length -gt 0) { $te['input'] = $Text }
    $c = @{ tool_event = $te }; if ($CodeAware) { $c['code_prompt'] = $Text }; $c
  }
  'toolOutput' {
    $te = @{ metadata = @{ ecosystem='mcp'; method='tools/call'; server_name=$Server; tool_invoked=$Tool } }
    if ($InText.Length -gt 0) { $te['input'] = $InText }
    $te['output'] = $Text
    $c = @{ tool_event = $te }
    if ($CodeAware) { $c['code_response'] = $Text; if ($InText.Length -gt 0) { $c['code_prompt'] = $InText } }
    $c
  }
}
$Meta = @{ app_user=$AppUser; app_name=$AppName; source=$IEvent }
if ($ToolName) { $Meta['tool_name'] = $ToolName }
$Body = @{ transaction_id=$Txn; session_id=$Session; ai_profile=$AiProfile; metadata=$Meta; contents=,$Content }
$BodyJson = $Body | ConvertTo-Json -Depth 12 -Compress

# ---- call AIRS --------------------------------------------------------------
$Scan = $null; $ScanErr = ''
$headers = @{ 'x-pan-token' = $ApiKey; 'Accept' = 'application/json' }
for ($attempt = 0; $attempt -le $Retries; $attempt++) {
  try {
    $Scan = Invoke-RestMethod -Uri $ApiUrl -Method Post -ContentType 'application/json' -Headers $headers -Body $BodyJson -TimeoutSec $TimeoutSec
    $ScanErr = ''; break
  } catch {
    $ScanErr = $_.Exception.Message; $Scan = $null
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $ScanErr += ": " + $_.ErrorDetails.Message }   # response body (PS7)
    $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
    # 4xx (except 429) won't change on retry — stop retrying a bad key/profile.
    if ($code -ge 400 -and $code -lt 500 -and $code -ne 429) { break }
  }
}

if ($ScanErr -or $null -eq $Scan) {
  if (-not $ScanErr) { $ScanErr = 'empty response' }
  Log $Label "error($ScanErr)"
  if ($IEvent -eq 'Stop') { Render 'warn' "AIRS scan error at Stop ($ScanErr) - allowing" }
  elseif ($FailMode -eq 'closed' -and $Side -eq 'input') { Render 'block' "Prisma AIRS scan failed ($ScanErr) - blocking (fail-closed)" }
  else { Render 'warn' "AIRS scan error ($ScanErr) - allowing (fail-open)" }
}

# ---- parse verdict ----------------------------------------------------------
$Action   = if (Field $Scan 'action')   { [string](Field $Scan 'action') }   else { 'unknown' }
$Category = if (Field $Scan 'category') { [string](Field $Scan 'category') } else { 'unknown' }
$ScanId   = if (Field $Scan 'scan_id')  { [string](Field $Scan 'scan_id') }  else { 'unknown' }
$Dets = @()
$Dets += Get-TrueKeys (Field $Scan 'prompt_detected')
$Dets += Get-TrueKeys (Field $Scan 'response_detected')
$Dets += Get-TrueKeys (Field $Scan 'tool_detected')
$DetStr = ($Dets | Select-Object -Unique | Sort-Object) -join ', '

if ($Action -eq 'block') {
  $reason = "Blocked by Prisma AIRS: $Category"
  if ($DetStr) { $reason += " [$DetStr]" }
  $reason += " (scan_id: $ScanId)"
  Log $Label "BLOCK $reason"
  Render 'block' $reason
} elseif ($Action -eq 'allow') {
  $tag = if ($DetStr) { "allow [$DetStr]" } else { 'allow' }
  $tag += " [scan:$ScanId]"
  Log $Label $tag
  Render 'allow' ''
} else {
  # Unrecognized action (partial response / API contract drift) is NOT clean -> fail-mode.
  Log $Label "unexpected action '$Action' - fail-mode ($FailMode)"
  if ($FailMode -eq 'closed' -and $Side -eq 'input') { Render 'block' "Prisma AIRS returned an unexpected action ('$Action') - blocking (fail-closed)" }
  else { Render 'warn' "Prisma AIRS returned an unexpected action ('$Action') - allowing (fail-open)" }
}
