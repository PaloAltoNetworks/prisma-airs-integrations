#!/usr/bin/env node

// src/config.ts
var DEFAULT_BASE_URL = "https://service.api.aisecurity.paloaltonetworks.com";
var SCAN_PATH = "/v1/scan/sync/request";
function loadConfig(env = process.env) {
  const base = (env.PRISMA_AIRS_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const profileId = str(env.PRISMA_AIRS_PROFILE_ID);
  const profileName = str(env.PRISMA_AIRS_PROFILE_NAME);
  const profile = profileId ? { profile_id: profileId } : profileName ? { profile_name: profileName } : null;
  const suffix = str(env.AIRS_APP_SUFFIX) || str(env.CLAUDE_CODE_APP_SUFFIX);
  return {
    apiUrl: base + SCAN_PATH,
    apiKey: str(env.PRISMA_AIRS_API_KEY),
    profile,
    // Default base; the entrypoint overrides with the active adapter's appName.
    appName: suffix ? `Claude Code-${suffix}` : "Claude Code",
    appSuffix: suffix,
    logPath: str(env.SECURITY_LOG_PATH) || ".claude/hooks/prisma-airs.log",
    timeoutMs: intEnv(env.AIRS_TIMEOUT_MS, 1e4),
    retries: intEnv(env.AIRS_RETRIES, 1),
    failMode: env.AIRS_FAIL_MODE === "closed" ? "closed" : "open",
    maxContentChars: Math.max(1, intEnv(env.AIRS_MAX_CONTENT_CHARS, 2e4)),
    maxChunks: Math.max(1, intEnv(env.AIRS_MAX_CHUNKS, 6)),
    enableMasking: bool(env.AIRS_ENABLE_MASKING),
    codeAware: env.AIRS_CODE_AWARE === void 0 ? true : bool(env.AIRS_CODE_AWARE),
    debug: bool(env.AIRS_DEBUG)
  };
}
function configError(cfg) {
  if (!cfg.apiKey) return "PRISMA_AIRS_API_KEY not set";
  if (!cfg.profile) return "PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set";
  return null;
}
function str(v) {
  return (v ?? "").trim();
}
function bool(v) {
  return v === "1" || v === "true" || v === "yes";
}
function intEnv(v, dflt) {
  if (!v) return dflt;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}

// src/log.ts
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
function makeLogger(logPath, cwd, debug) {
  const absPath = isAbsolute(logPath) ? logPath : resolve(cwd || process.cwd(), logPath);
  let dirReady = false;
  const ensureDir = () => {
    if (dirReady) return;
    try {
      mkdirSync(dirname(absPath), { recursive: true });
      dirReady = true;
    } catch {
    }
  };
  const write = (line) => {
    ensureDir();
    try {
      appendFileSync(absPath, line + "\n");
    } catch {
    }
  };
  return {
    log(msg) {
      write(`[${(/* @__PURE__ */ new Date()).toISOString()}] ${msg}`);
    },
    debug(msg) {
      if (!debug) return;
      write(`[${(/* @__PURE__ */ new Date()).toISOString()}] DEBUG ${msg}`);
      try {
        process.stderr.write(`[airs-hook] ${msg}
`);
      } catch {
      }
    }
  };
}

// src/router.ts
import { createHash } from "node:crypto";

// src/airs.ts
var CHUNK_OVERLAP = 256;
async function scanPlan(cfg, plan, meta) {
  const { pieces, overflow } = splitChunks(plan.text, cfg.maxContentChars, cfg.maxChunks, CHUNK_OVERLAP);
  let firstError = null;
  let lastVerdict = null;
  for (let i = 0; i < pieces.length; i++) {
    const content = buildContent(plan, pieces[i], cfg.codeAware);
    const partMeta = pieces.length > 1 ? { ...meta, transactionId: `${meta.transactionId}#${i + 1}`, extra: { ...meta.extra ?? {}, chunk: `${i + 1}/${pieces.length}` } } : meta;
    const verdict = await scan(cfg, content, partMeta);
    lastVerdict = verdict;
    if (verdict.action === "block") return verdict;
    if (verdict.error && !firstError) firstError = verdict;
  }
  if (overflow) {
    return firstError ?? {
      action: "unknown",
      category: "content_overflow",
      scanId: "unknown",
      detections: [],
      error: `content exceeded scan budget (${cfg.maxChunks} x ${cfg.maxContentChars} chars) \u2014 tail unscanned`
    };
  }
  if (firstError) return firstError;
  return lastVerdict ?? { action: "allow", category: "benign", scanId: "unknown", detections: [] };
}
function splitChunks(text, maxChars, maxChunks, overlap) {
  if (text.length <= maxChars) return { pieces: [text], overflow: false };
  const eff = Math.min(overlap, Math.floor(maxChars / 4));
  const step = Math.max(1, maxChars - eff);
  const pieces = [];
  let start = 0;
  let end = 0;
  while (start < text.length && pieces.length < maxChunks) {
    end = Math.min(start + maxChars, text.length);
    pieces.push(text.slice(start, end));
    if (end >= text.length) break;
    start += step;
  }
  return { pieces, overflow: end < text.length };
}
function buildContent(plan, chunkText, codeAware) {
  switch (plan.kind) {
    case "prompt": {
      const c = { prompt: chunkText };
      if (codeAware) c.code_prompt = chunkText;
      return c;
    }
    case "response": {
      const c = { response: chunkText };
      if (codeAware) c.code_response = chunkText;
      return c;
    }
    case "toolInput": {
      const c = { tool_event: toolEvent(plan.server, plan.tool, chunkText, void 0) };
      if (codeAware) c.code_prompt = chunkText;
      return c;
    }
    case "toolOutput": {
      const c = { tool_event: toolEvent(plan.server, plan.tool, plan.inputText || void 0, chunkText) };
      if (codeAware) {
        c.code_response = chunkText;
        if (plan.inputText) c.code_prompt = plan.inputText;
      }
      return c;
    }
  }
}
function toolEvent(serverName, toolInvoked, input, output) {
  const te = {
    metadata: { ecosystem: "mcp", method: "tools/call", server_name: serverName, tool_invoked: toolInvoked }
  };
  if (input !== void 0 && input.length > 0) te.input = input;
  if (output !== void 0 && output.length > 0) te.output = output;
  return te;
}
async function scan(cfg, content, meta) {
  const body = {
    transaction_id: meta.transactionId,
    session_id: meta.sessionId,
    ai_profile: cfg.profile,
    metadata: {
      app_user: "claude-code-user",
      app_name: cfg.appName,
      ...meta.extra ?? {}
    },
    contents: [content]
  };
  let lastError = "";
  for (let attempt = 0; attempt <= cfg.retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
    try {
      const res = await fetch(cfg.apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "x-pan-token": cfg.apiKey
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      const text = await res.text();
      if (!res.ok) {
        lastError = `HTTP ${res.status}: ${text.slice(0, 200)}`;
        continue;
      }
      return parseVerdict(text);
    } catch (err) {
      const e = err;
      lastError = e?.name === "AbortError" ? `timeout after ${cfg.timeoutMs}ms` : String(e?.message ?? err);
    } finally {
      clearTimeout(timer);
    }
  }
  return { action: "unknown", category: "scan_error", scanId: "unknown", detections: [], error: lastError };
}
function parseVerdict(text) {
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    return { action: "unknown", category: "parse_error", scanId: "unknown", detections: [], error: "non-JSON response" };
  }
  const action = normalizeAction(json.action);
  return {
    action,
    category: asString(json.category, "unknown"),
    scanId: asString(json.scan_id, "unknown"),
    detections: collectDetections(json),
    maskedPrompt: extractMasked(json.prompt_masked_data),
    maskedResponse: extractMasked(json.response_masked_data),
    raw: json
  };
}
function extractMasked(v) {
  if (!v || typeof v !== "object") return void 0;
  const data = v.data;
  return typeof data === "string" && data.length > 0 ? data : void 0;
}
function normalizeAction(v) {
  if (v === "block") return "block";
  if (v === "allow") return "allow";
  return "unknown";
}
function collectDetections(json) {
  const found = /* @__PURE__ */ new Set();
  const harvest = (obj2) => {
    if (!obj2 || typeof obj2 !== "object") return;
    for (const [key, val] of Object.entries(obj2)) {
      if (val === true) found.add(key);
    }
  };
  harvest(json.prompt_detected);
  harvest(json.response_detected);
  const tool = json.tool_detected;
  if (tool && typeof tool === "object") {
    harvest(tool.summary?.detections);
    for (const side of ["input_detected", "output_detected"]) {
      const entries = tool[side]?.detection_entries;
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          harvest(entry?.detections);
        }
      }
    }
  }
  return [...found].sort();
}
function asString(v, dflt) {
  return typeof v === "string" && v.length > 0 ? v : dflt;
}

// src/content.ts
function promptContent(input) {
  const text = flatten(str2(input.prompt));
  return text.trim().length > 0 ? { kind: "prompt", text } : null;
}
function answerContent(input) {
  const text = flatten(str2(input.last_assistant_message));
  return text.trim().length > 0 ? { kind: "response", text } : null;
}
function preToolContent(input) {
  const toolName = str2(input.tool_name);
  const ti = asObject(input.tool_input);
  const text = flatten(toolInputText(toolName, ti));
  if (text.trim().length === 0) return null;
  const { server, tool } = toolIdentity(toolName, ti);
  return { kind: "toolInput", server, tool, text };
}
function postToolContent(input, maxInputChars) {
  const toolName = str2(input.tool_name);
  const ti = asObject(input.tool_input);
  const text = flatten(toolOutputText(input.tool_response ?? input.tool_result));
  if (text.trim().length === 0) return null;
  const { server, tool } = toolIdentity(toolName, ti);
  const inputText = clip(flatten(toolInputText(toolName, ti)), maxInputChars);
  return { kind: "toolOutput", server, tool, inputText, text };
}
function toolInputText(toolName, ti) {
  switch (toolName) {
    case "Bash":
      return join([s(ti.command), s(ti.description)]);
    case "WebFetch":
      return join([s(ti.url), s(ti.prompt)]);
    case "WebSearch":
      return s(ti.query);
    case "Write":
      return join([s(ti.file_path), s(ti.content)]);
    case "Edit":
      return join([s(ti.file_path), s(ti.old_string), s(ti.new_string)]);
    case "Read":
      return s(ti.file_path);
    case "Glob":
      return join([s(ti.pattern), s(ti.path)]);
    case "Grep":
      return join([s(ti.pattern), s(ti.path)]);
    case "Task":
      return join([s(ti.description), s(ti.subagent_type), s(ti.prompt)]);
    case "NotebookEdit":
      return join([s(ti.notebook_path), s(ti.new_source)]);
    case "TodoWrite":
      return s(ti.todos);
    case "ExitPlanMode":
      return s(ti.plan);
    case "ReadMcpResourceTool":
    case "ReadMcpResourceDirTool":
      return join([s(ti.server), s(ti.uri), s(ti.path)]);
    case "ListMcpResourcesTool":
      return s(ti.server);
    default:
      return safeJson(ti);
  }
}
var MCP_RESOURCE_TOOLS = /* @__PURE__ */ new Set(["ReadMcpResourceTool", "ReadMcpResourceDirTool", "ListMcpResourcesTool"]);
function toolIdentity(toolName, ti) {
  if (toolName.startsWith("mcp__")) {
    return names(toolName);
  }
  if (MCP_RESOURCE_TOOLS.has(toolName)) {
    const server = str2(ti.server) || "unknown";
    const tool = str2(ti.uri) || str2(ti.path) || toolName;
    return { server, tool };
  }
  return names(toolName);
}
function primaryInputField(toolName, ti) {
  const pick = (field) => {
    const v = ti[field];
    return typeof v === "string" && v.length > 0 ? { field, value: v } : null;
  };
  switch (toolName) {
    case "Bash":
      return pick("command");
    case "Write":
      return pick("content");
    case "Edit":
      return pick("new_string");
    case "WebSearch":
      return pick("query");
    case "Task":
      return pick("prompt");
    case "NotebookEdit":
      return pick("new_source");
    case "ExitPlanMode":
      return pick("plan");
    default:
      return null;
  }
}
function toolOutputText(resp) {
  if (resp == null) return "";
  if (typeof resp === "string") return resp;
  if (typeof resp !== "object") return String(resp);
  const strings = collectStrings(resp);
  if (strings.length === 0) return safeJson(resp);
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const v of strings) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out.join("\n");
}
function names(toolName) {
  if (toolName.startsWith("mcp__")) {
    const parts = toolName.split("__");
    return { server: parts[1] || "unknown", tool: parts.slice(2).join("__") || parts[1] || toolName };
  }
  return { server: `claude-code/${toolName || "unknown"}`, tool: toolName || "unknown" };
}
function collectStrings(value, out = [], depth = 0) {
  if (depth > 6) return out;
  if (typeof value === "string") {
    if (value.length > 0) out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) collectStrings(v, out, depth + 1);
  }
  return out;
}
function flatten(s2) {
  return s2.replace(/\r/g, "").replace(/\n/g, " ");
}
function clip(s2, maxChars) {
  return s2.length > maxChars ? s2.slice(0, maxChars) : s2;
}
function asObject(v) {
  return v && typeof v === "object" ? v : {};
}
function s(v) {
  return typeof v === "string" ? v : v == null ? "" : safeJson(v);
}
function join(parts) {
  return parts.filter((p) => p && p.length > 0).join("\n");
}
function str2(v) {
  return typeof v === "string" ? v : "";
}
function safeJson(v) {
  try {
    return JSON.stringify(v) ?? "";
  } catch {
    return String(v);
  }
}

// src/decide.ts
function decide(verdict, ctx) {
  if (ctx.configError) {
    if (ctx.side === "input") {
      return { kind: "block", reason: `Prisma AIRS not configured (${ctx.configError}) \u2014 blocking (fail-closed)` };
    }
    return { kind: "warn", message: `Prisma AIRS not configured (${ctx.configError}) \u2014 content NOT scanned` };
  }
  if (verdict.error) {
    if (ctx.event === "Stop") return { kind: "warn", message: `AIRS scan error at Stop (${verdict.error}) \u2014 allowing` };
    if (ctx.cfg.failMode === "closed" && ctx.side === "input") {
      return { kind: "block", reason: `Prisma AIRS scan failed (${verdict.error}) \u2014 blocking (fail-closed)` };
    }
    return { kind: "warn", message: `AIRS scan error (${verdict.error}) \u2014 allowing (fail-open)` };
  }
  if (verdict.action === "block") return { kind: "block", reason: reasonText(verdict) };
  return { kind: "allow" };
}
function reasonText(v) {
  const det = v.detections.length > 0 ? ` [${v.detections.join(", ")}]` : "";
  return `Blocked by Prisma AIRS: ${v.category}${det} (scan_id: ${v.scanId})`;
}

// src/router.ts
var ALLOW = { kind: "allow" };
async function route(input, cfg, log, caps) {
  const event = String(input.hook_event_name ?? "").trim();
  const cfgErr = configError(cfg);
  switch (event) {
    case "UserPromptSubmit":
      return { event, decision: await handle(input, cfg, log, caps, "UserPromptSubmit", "input", cfgErr, promptContent(input), "user prompt") };
    case "PreToolUse":
      return { event, decision: await handle(input, cfg, log, caps, "PreToolUse", "input", cfgErr, preToolContent(input), `${input.tool_name ?? "tool"} input`) };
    case "PostToolUse":
      return {
        event,
        decision: await handle(input, cfg, log, caps, "PostToolUse", "output", cfgErr, postToolContent(input, cfg.maxContentChars), `${input.tool_name ?? "tool"} output`)
      };
    case "Stop":
      if (input.stop_hook_active) {
        log.debug("Stop: stop_hook_active set \u2014 allowing (loop guard)");
        return { event: "Stop", decision: ALLOW };
      }
      return { event: "Stop", decision: await handle(input, cfg, log, caps, "Stop", "output", cfgErr, answerContent(input), "model answer") };
    default:
      log.debug(`unhandled event: ${event || "(none)"}`);
      return { event: "PostToolUse", decision: ALLOW };
  }
}
async function handle(input, cfg, log, caps, event, side, cfgErr, plan, label) {
  const ctx = { event, side, cfg, configError: cfgErr };
  if (cfgErr) {
    log.log(`${event} ${label}: config_error (${cfgErr})`);
    return decide({ action: "unknown", category: "config_error", scanId: "unknown", detections: [] }, ctx);
  }
  if (!plan) {
    log.debug(`${event}: no scannable content for ${label} \u2014 allowing`);
    return ALLOW;
  }
  const meta = buildMeta(input);
  const scanMeta = { ...meta, extra: { tool_name: String(input.tool_name ?? ""), source: event } };
  const verdict = await scanPlan(cfg, plan, scanMeta);
  const tag = verdict.error ? `error(${verdict.error})` : verdict.action === "block" ? `BLOCK ${reasonText(verdict)}` : `allow${verdict.detections.length ? " [" + verdict.detections.join(",") + "]" : ""} [scan:${verdict.scanId}]`;
  log.log(`${event} ${label}: ${tag}`);
  const canRewrite = event === "PreToolUse" && caps.rewriteInput || event === "PostToolUse" && caps.rewriteOutput;
  if (cfg.enableMasking && canRewrite && verdict.action === "allow" && plan.text.length <= cfg.maxContentChars) {
    const masked = await tryMask(input, plan, cfg, scanMeta, event);
    if (masked) {
      log.log(`${event} ${label}: MASKED (DLP redacted in place)`);
      return masked;
    }
  }
  return decide(verdict, ctx);
}
async function tryMask(input, plan, cfg, scanMeta, event) {
  if (event === "PreToolUse" && plan.kind === "toolInput") {
    const field = primaryInputField(String(input.tool_name ?? ""), input.tool_input ?? {});
    if (!field || field.value.length > cfg.maxContentChars) return null;
    const v = await scan(cfg, { prompt: field.value }, scanMeta);
    const masked = v.maskedPrompt;
    if (isPureDlpMask(v, masked, field.value)) {
      const updatedInput = { ...input.tool_input, [field.field]: masked };
      return { kind: "maskInput", updatedInput, note: `Prisma AIRS masked sensitive data in ${input.tool_name} ${field.field} (scan_id: ${v.scanId})` };
    }
    return null;
  }
  if (event === "PostToolUse" && plan.kind === "toolOutput") {
    const v = await scan(cfg, { response: plan.text }, scanMeta);
    const masked = v.maskedResponse;
    if (isPureDlpMask(v, masked, plan.text)) {
      return { kind: "maskOutput", updatedOutput: masked, note: `Prisma AIRS masked sensitive data in ${input.tool_name} output (scan_id: ${v.scanId})` };
    }
    return null;
  }
  return null;
}
function isPureDlpMask(v, masked, original) {
  return v.action === "block" && typeof masked === "string" && masked.length > 0 && masked !== original && v.detections.length > 0 && v.detections.every((d) => d === "dlp");
}
function buildMeta(input) {
  const sessionId = typeof input.session_id === "string" && input.session_id || sha256(String(input.cwd ?? process.cwd())).slice(0, 32);
  const perEvent = typeof input.tool_use_id === "string" && input.tool_use_id || typeof input.prompt_id === "string" && input.prompt_id || sessionId;
  return { sessionId, transactionId: perEvent };
}
function sha256(s2) {
  return createHash("sha256").update(s2).digest("hex");
}

// src/adapters/claude.ts
function mapEvent(name) {
  switch (name) {
    case "UserPromptSubmit":
    case "PreToolUse":
    case "PostToolUse":
      return name;
    case "Stop":
    case "SubagentStop":
      return "Stop";
    default:
      return "";
  }
}
var claudeAdapter = {
  name: "claude",
  appName: "Claude Code",
  capabilities: { rewriteInput: true, rewriteOutput: true, postCanBlock: true },
  normalize(raw, eventName) {
    const input = { ...raw };
    input.hook_event_name = mapEvent(eventName ?? raw.hook_event_name);
    return input;
  },
  render(event, decision) {
    switch (decision.kind) {
      case "allow":
        return { exitCode: 0 };
      case "warn":
        return { exitCode: 0, stderr: `[Prisma AIRS] ${decision.message}
` };
      case "block":
        return blockOutcome(event, decision.reason);
      case "maskInput":
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput: decision.updatedInput, additionalContext: decision.note }
          }),
          stderr: `
\u{1F6E1}\uFE0F  ${decision.note}

`
        };
      case "maskOutput":
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: decision.updatedOutput, additionalContext: decision.note }
          }),
          stderr: `
\u{1F6E1}\uFE0F  ${decision.note}

`
        };
    }
  }
};
function blockOutcome(event, reason) {
  const stderr = `
\u{1F6AB} ${reason}

`;
  let obj2;
  switch (event) {
    case "PreToolUse":
      obj2 = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } };
      break;
    case "UserPromptSubmit":
      obj2 = { decision: "block", reason, hookSpecificOutput: { hookEventName: "UserPromptSubmit" } };
      break;
    case "PostToolUse":
      obj2 = { decision: "block", reason, hookSpecificOutput: { hookEventName: "PostToolUse" } };
      break;
    case "Stop":
      obj2 = { decision: "block", reason };
      break;
  }
  return { exitCode: 0, stdout: JSON.stringify(obj2), stderr };
}

// src/adapters/codex.ts
function mapEvent2(name) {
  switch (name) {
    case "UserPromptSubmit":
    case "PreToolUse":
    case "PostToolUse":
      return name;
    case "Stop":
    case "SubagentStop":
      return "Stop";
    default:
      return "";
  }
}
var codexAdapter = {
  name: "codex",
  appName: "Codex CLI",
  capabilities: { rewriteInput: false, rewriteOutput: false, postCanBlock: true },
  normalize(raw, eventName) {
    const input = { ...raw };
    input.hook_event_name = mapEvent2(eventName ?? raw.hook_event_name);
    if (typeof raw.turn_id === "string" && !input.prompt_id) input.prompt_id = raw.turn_id;
    return input;
  },
  render(event, decision) {
    switch (decision.kind) {
      case "allow":
        return event === "Stop" ? { exitCode: 0, stdout: '{"continue": true}' } : { exitCode: 0 };
      case "warn":
        return event === "Stop" ? { exitCode: 0, stdout: '{"continue": true}', stderr: `[Prisma AIRS] ${decision.message}
` } : { exitCode: 0, stderr: `[Prisma AIRS] ${decision.message}
` };
      case "block": {
        const stderr = `
\u{1F6AB} ${decision.reason}

`;
        if (event === "UserPromptSubmit" || event === "PreToolUse") {
          return { exitCode: 2, stderr };
        }
        if (event === "PostToolUse") {
          return { exitCode: 0, stdout: JSON.stringify({ decision: "block", reason: decision.reason, hookSpecificOutput: { hookEventName: "PostToolUse" } }), stderr };
        }
        return { exitCode: 0, stdout: JSON.stringify({ continue: false, stopReason: decision.reason }), stderr };
      }
      // Codex can't rewrite; masking is gated off for it, so these are unreachable.
      // Defensive: the content was a primary-allowed pure-DLP surface — allow.
      case "maskInput":
      case "maskOutput":
        return event === "Stop" ? { exitCode: 0, stdout: '{"continue": true}' } : { exitCode: 0 };
    }
  }
};

// src/adapters/cursor.ts
function mapEvent3(name) {
  switch (name) {
    case "beforeSubmitPrompt":
      return "UserPromptSubmit";
    case "beforeShellExecution":
      return "PreToolUse";
    case "beforeMCPExecution":
      return "PreToolUse";
    case "postToolUse":
      return "PostToolUse";
    case "afterAgentResponse":
      return "Stop";
    default:
      return "";
  }
}
function normalizeToolName(name) {
  if (typeof name !== "string") return "";
  if (name.startsWith("MCP:")) return "mcp__" + name.slice(4).split(":").join("__");
  return name;
}
var cursorAdapter = {
  name: "cursor",
  appName: "Cursor",
  // Pre-tool is the hard block. postToolUse can redact MCP output / inject context (no hard block).
  capabilities: { rewriteInput: false, rewriteOutput: false, postCanBlock: true },
  normalize(raw, eventName) {
    const input = { ...raw };
    input.hook_event_name = mapEvent3(eventName);
    if (eventName === "beforeShellExecution") {
      input.tool_name = "Shell";
      input.tool_input = { command: typeof raw.command === "string" ? raw.command : "" };
    } else if (raw.tool_name !== void 0) {
      input.tool_name = normalizeToolName(raw.tool_name);
    }
    if (input.tool_response === void 0 && raw.tool_output !== void 0) input.tool_response = raw.tool_output;
    if (input.last_assistant_message === void 0) {
      const t = raw.text ?? raw.response ?? raw.message ?? raw.content ?? raw.output;
      if (typeof t === "string") input.last_assistant_message = t;
    }
    if (typeof raw.conversation_id === "string" && !input.session_id) input.session_id = raw.conversation_id;
    return input;
  },
  render(event, decision) {
    switch (decision.kind) {
      case "allow":
        return allowOutcome(event);
      case "warn":
        return { ...allowOutcome(event), stderr: `[Prisma AIRS] ${decision.message}
` };
      case "block": {
        const stderr = `
\u{1F6AB} ${decision.reason}

`;
        switch (event) {
          case "UserPromptSubmit":
            return { exitCode: 0, stdout: JSON.stringify({ continue: false, user_message: decision.reason }), stderr };
          case "PreToolUse":
            return { exitCode: 0, stdout: JSON.stringify({ permission: "deny", user_message: decision.reason, agent_message: decision.reason }), stderr };
          case "PostToolUse":
            return { exitCode: 0, stdout: JSON.stringify({ updated_mcp_tool_output: `[Prisma AIRS blocked this tool output: ${decision.reason}]`, additional_context: `\u26A0\uFE0F Prisma AIRS flagged this tool output: ${decision.reason}` }), stderr };
          case "Stop":
          default:
            return { exitCode: 0, stderr: `
\u26A0\uFE0F  ALERT (Cursor cannot block at ${event}) \u2014 ${decision.reason}

` };
        }
      }
      // No input/output masking on Cursor.
      case "maskInput":
      case "maskOutput":
        return allowOutcome(event);
    }
  }
};
function allowOutcome(event) {
  switch (event) {
    case "UserPromptSubmit":
      return { exitCode: 0, stdout: JSON.stringify({ continue: true }) };
    case "PreToolUse":
      return { exitCode: 0, stdout: JSON.stringify({ permission: "allow" }) };
    default:
      return { exitCode: 0 };
  }
}

// src/adapters/cline.ts
function obj(v) {
  return v && typeof v === "object" ? v : {};
}
function str3(v) {
  return typeof v === "string" ? v : void 0;
}
var clineAdapter = {
  name: "cline",
  appName: "Cline",
  capabilities: { rewriteInput: false, rewriteOutput: false, postCanBlock: true },
  normalize(raw, eventName) {
    const input = {};
    if (typeof raw.taskId === "string") input.session_id = raw.taskId;
    switch (eventName) {
      case "UserPromptSubmit": {
        input.hook_event_name = "UserPromptSubmit";
        input.prompt = str3(obj(raw.userPromptSubmit).prompt);
        break;
      }
      case "PreToolUse": {
        input.hook_event_name = "PreToolUse";
        const p = obj(raw.preToolUse);
        input.tool_name = str3(p.toolName);
        input.tool_input = obj(p.parameters);
        break;
      }
      case "PostToolUse": {
        input.hook_event_name = "PostToolUse";
        const p = obj(raw.postToolUse);
        input.tool_name = str3(p.toolName);
        input.tool_input = obj(p.parameters);
        input.tool_response = p.result;
        break;
      }
      case "TaskComplete": {
        input.hook_event_name = "Stop";
        input.last_assistant_message = str3(obj(raw.taskComplete).task);
        break;
      }
      default:
        input.hook_event_name = "";
    }
    return input;
  },
  render(event, decision) {
    const emit = (o, stderr) => ({ exitCode: 0, stdout: JSON.stringify(o), stderr });
    switch (decision.kind) {
      case "allow":
        return emit({ cancel: false });
      case "warn":
        return emit({ cancel: false, contextModification: `Prisma AIRS: ${decision.message}` }, `[Prisma AIRS] ${decision.message}
`);
      case "block":
        if (event === "Stop") return emit({ cancel: false, contextModification: decision.reason }, `
\u{1F6AB} ${decision.reason}

`);
        return emit({ cancel: true, errorMessage: decision.reason }, `
\u{1F6AB} ${decision.reason}

`);
      // Cline can't rewrite; masking is gated off for it.
      case "maskInput":
      case "maskOutput":
        return emit({ cancel: false });
    }
  }
};

// src/adapters/devin.ts
var devinAdapter = {
  name: "devin",
  appName: "Devin CLI",
  capabilities: { rewriteInput: false, rewriteOutput: false, postCanBlock: false },
  normalize(raw, eventName) {
    const input = { ...raw };
    input.hook_event_name = eventName ?? (typeof raw.hook_event_name === "string" ? raw.hook_event_name : "");
    if (input.hook_event_name === "Stop") input.last_assistant_message = void 0;
    return input;
  },
  render(event, decision) {
    switch (decision.kind) {
      case "allow":
        return { exitCode: 0 };
      case "warn":
        return { exitCode: 0, stderr: `[Prisma AIRS] ${decision.message}
` };
      case "block":
        switch (event) {
          case "PreToolUse":
            return { exitCode: 2, stderr: `
\u{1F6AB} ${decision.reason}

` };
          case "UserPromptSubmit":
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                hookSpecificOutput: {
                  hookEventName: "UserPromptSubmit",
                  additionalContext: `\u26A0\uFE0F Prisma AIRS flagged this prompt: ${decision.reason}`
                }
              }),
              stderr: `
\u26A0\uFE0F  ALERT (Devin UserPromptSubmit cannot block; enforcement is at the tool gate) \u2014 ${decision.reason}

`
            };
          default:
            return { exitCode: 0, stderr: `
\u26A0\uFE0F  ALERT (Devin ${event} is advisory) \u2014 ${decision.reason}

` };
        }
      // Devin doesn't rewrite output here; masking stays gated off.
      case "maskInput":
      case "maskOutput":
        return { exitCode: 0 };
    }
  }
};

// src/adapters/gemini.ts
function mapEvent4(name) {
  switch (name) {
    case "BeforeAgent":
    case "UserPromptSubmit":
      return "UserPromptSubmit";
    case "BeforeTool":
    case "PreToolUse":
      return "PreToolUse";
    case "AfterTool":
    case "PostToolUse":
      return "PostToolUse";
    case "AfterAgent":
    case "Stop":
    case "SubagentStop":
    case "PostInvocation":
      return "Stop";
    // Antigravity IDE turn-start event (provisional). Maps to prompt-in.
    case "PreInvocation":
      return "UserPromptSubmit";
    default:
      return "";
  }
}
function makeGeminiAdapter(name, appName) {
  return {
    name,
    appName,
    // Gemini CLI can block a prompt, block a pre-tool call, block/withhold a tool
    // result, and REWRITE tool input (hookSpecificOutput.tool_input). No documented
    // clean tool-OUTPUT rewrite, so output masking stays off.
    capabilities: { rewriteInput: true, rewriteOutput: false, postCanBlock: true },
    normalize(raw, eventName) {
      const input = { ...raw };
      input.hook_event_name = mapEvent4(eventName ?? raw.hook_event_name);
      if (input.last_assistant_message === void 0) {
        const ans = raw.prompt_response ?? raw.response ?? raw.agent_response;
        if (typeof ans === "string") input.last_assistant_message = ans;
      }
      if (input.tool_name === void 0 && raw.toolCall && typeof raw.toolCall === "object") {
        const tc = raw.toolCall;
        if (typeof tc.name === "string") input.tool_name = tc.name;
        if (tc.args && typeof tc.args === "object") input.tool_input = tc.args;
      }
      if (input.session_id === void 0 && typeof raw.conversationId === "string") input.session_id = raw.conversationId;
      return input;
    },
    render(event, decision) {
      switch (decision.kind) {
        case "allow":
          return { exitCode: 0 };
        case "warn":
          return { exitCode: 0, stderr: `[Prisma AIRS] ${decision.message}
` };
        case "block":
          return blockOutcome2(event, decision.reason);
        case "maskInput":
          return {
            exitCode: 0,
            stdout: JSON.stringify({
              hookSpecificOutput: { hookEventName: "BeforeTool", tool_input: decision.updatedInput, additionalContext: decision.note }
            }),
            stderr: `
\u{1F6E1}\uFE0F  ${decision.note}

`
          };
        case "maskOutput":
          return { exitCode: 0 };
      }
    }
  };
}
function blockOutcome2(event, reason) {
  const stderr = `
\u{1F6AB} ${reason}

`;
  switch (event) {
    case "UserPromptSubmit":
    case "PreToolUse":
      return { exitCode: 2, stderr };
    case "PostToolUse":
      return { exitCode: 2, stderr };
    case "Stop":
    default:
      return { exitCode: 0, stderr: `
\u26A0\uFE0F  ALERT (Gemini response scanned; not hard-blocked to avoid retry loop) \u2014 ${reason}

` };
  }
}
var antigravityAdapter = makeGeminiAdapter("antigravity", "Antigravity");
var geminiAdapter = makeGeminiAdapter("gemini", "Gemini CLI");

// src/adapters/registry.ts
var ADAPTERS = {
  claude: claudeAdapter,
  codex: codexAdapter,
  cursor: cursorAdapter,
  cline: clineAdapter,
  devin: devinAdapter,
  // Antigravity reuses Gemini CLI's verified hook contract; `gemini` is the same
  // adapter with Gemini-CLI attribution.
  antigravity: antigravityAdapter,
  gemini: geminiAdapter
};
function getAdapter(name) {
  return ADAPTERS[(name || "claude").toLowerCase()] ?? claudeAdapter;
}
var adapterNames = Object.keys(ADAPTERS);

// src/index.ts
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--vendor") out.vendor = argv[++i];
    else if (a.startsWith("--vendor=")) out.vendor = a.slice("--vendor=".length);
    else if (a === "--event") out.event = argv[++i];
    else if (a.startsWith("--event=")) out.event = a.slice("--event=".length);
  }
  return out;
}
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const raw = await readStdin();
  let parsed = {};
  try {
    parsed = raw.trim() ? JSON.parse(raw) : {};
  } catch {
    process.stderr.write("[airs-hook] could not parse hook input JSON \u2014 allowing\n");
    process.exit(0);
  }
  const cfg = loadConfig();
  const adapter = getAdapter(args.vendor);
  cfg.appName = cfg.appSuffix ? `${adapter.appName}-${cfg.appSuffix}` : adapter.appName;
  const input = adapter.normalize(parsed, args.event);
  const cwd = String(input.cwd ?? parsed.cwd ?? process.cwd());
  const log = makeLogger(cfg.logPath, cwd, cfg.debug);
  try {
    const { event, decision } = await route(input, cfg, log, adapter.capabilities);
    const outcome = adapter.render(event, decision);
    if (outcome.stderr) process.stderr.write(outcome.stderr);
    if (outcome.stdout) process.stdout.write(outcome.stdout);
    process.exit(outcome.exitCode ?? 0);
  } catch (err) {
    const event = String(input.hook_event_name ?? "");
    const isStop = event === "Stop";
    log.log(`internal error (${event || "?"}): ${String(err?.stack ?? err)}`);
    if (cfg.failMode === "closed" && !isStop) {
      process.stderr.write("[airs-hook] internal error \u2014 blocking (fail-closed)\n");
      process.exit(2);
    }
    process.stderr.write("[airs-hook] internal error \u2014 allowing (fail-open)\n");
    process.exit(0);
  }
}
function readStdin() {
  return new Promise((resolve2) => {
    if (process.stdin.isTTY) {
      resolve2("");
      return;
    }
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => data += chunk);
    process.stdin.on("end", () => resolve2(data));
    process.stdin.on("error", () => resolve2(data));
  });
}
void main();
