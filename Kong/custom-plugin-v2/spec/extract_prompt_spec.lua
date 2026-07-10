-- Unit test for extract_prompt in handler.lua (._sse.extract_prompt).
-- Loads the REAL handler with its two Kong deps stubbed, so it exercises the
-- shipped code, not a copy. Runnable with plain Lua:
--   cd Kong/custom-plugin-v2 && lua spec/extract_prompt_spec.lua
-- Focus: the multi-turn fix -- in a conversation the client resends the full
-- history, so the plugin must scan the LATEST user turn, not the first.

-- ---- minimal JSON encoder for the cjson stub (Bedrock serialize fallback) ----
local function json_encode(v)
  if type(v) ~= "table" then return tostring(v) end
  local parts = {}
  for _, item in ipairs(v) do
    if type(item) == "table" and item.text then
      parts[#parts + 1] = '{"text":"' .. tostring(item.text) .. '"}'
    end
  end
  return "[" .. table.concat(parts, ",") .. "]"
end

-- ---- stub the handler's require()d deps, then load the REAL handler ----
package.loaded["resty.http"] = {}
package.loaded["cjson"] = { decode = function() return nil end, encode = json_encode }
_G.ngx = { encode_base64 = function(s) return s end, decode_base64 = function(s) return s end }
_G.kong = { ctx = { shared = {} }, request = {}, service = { request = {} } }

local handler = dofile("handler.lua")
local extract_prompt = handler._sse.extract_prompt
assert(type(extract_prompt) == "function", "handler._sse.extract_prompt missing")

local cases = {
  {
    "multi-turn returns LAST user turn",
    { messages = {
        { role = "user", content = "first prompt" },
        { role = "assistant", content = "an answer" },
        { role = "user", content = "second prompt" },
    } },
    "second prompt",
  },
  {
    "single user turn (string content)",
    { messages = { { role = "user", content = "hello" } } },
    "hello",
  },
  {
    "system + user -> user content",
    { messages = {
        { role = "system", content = "be helpful" },
        { role = "user", content = "the question" },
    } },
    "the question",
  },
  {
    "Bedrock Converse content array -> text",
    { messages = { { role = "user", content = { { text = "bedrock prompt" } } } } },
    "bedrock prompt",
  },
  {
    "OpenAI Responses top-level input (string)",
    { input = "responses api prompt" },
    "responses api prompt",
  },
  {
    "no user message -> nil",
    { messages = { { role = "system", content = "only system" } } },
    nil,
  },
  {
    "nil body -> nil",
    nil,
    nil,
  },
}

local pass, fail = 0, 0
print("=========== handler._sse.extract_prompt (real handler.lua) ===========")
for _, c in ipairs(cases) do
  local got = extract_prompt(c[2])
  local ok = got == c[3]
  print(string.format("[%s] %-38s want=%-22s got=%s",
    ok and "PASS" or "FAIL", c[1], tostring(c[3]), tostring(got)))
  if ok then pass = pass + 1 else fail = fail + 1 end
end
print("----------------------------------------------------------------------")
print(string.format("RESULTS: %d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
