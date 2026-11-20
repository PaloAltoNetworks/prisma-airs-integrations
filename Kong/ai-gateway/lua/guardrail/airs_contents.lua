-- ai-custom-guardrail function: contents
--
-- Builds the AIRS contents[] for whichever leg is running. `$(source)` is
-- "INPUT" while the request is inspected and "OUTPUT" while the response is,
-- and AIRS keys the two differently: contents[].prompt versus
-- contents[].response. Sending a model answer under `prompt` does not merely
-- mislabel it -- AIRS runs a different detector set per direction, so the scan
-- would be wrong, not just untidy.
--
-- ============================================================================
-- ONE ELEMENT. ALWAYS. This is the single most dangerous thing to "fix".
--
-- DOCUMENTED, and it is literal: the scan endpoint describes contents[] as "a
-- list of prompt or response or prompt/response pairs. The last element is the
-- one that needs to be scanned, and the previous elements are the context for
-- the scan". MEASURED (2026-09-14) against a live tenant, five probes: an
-- injection sent alone blocks; the same injection as the FIRST of two elements
-- comes back allow/benign; as the first of three, allow/benign; as the LAST
-- element, blocks. Earlier elements are context and are NOT judged.
--
-- So splitting a conversation into one element per message -- which is what a
-- natural reading of the schema invites, and which reviews as tidier -- stops
-- scanning every turn but the newest, with no error and no log line. Whatever
-- must be scanned goes inside the one element this function returns.
-- ============================================================================
--
-- WHY THE TEXT IS REBUILT RATHER THAN TAKEN AS GIVEN. `text_source` joins
-- message CONTENT only, with no indication of who said what. MEASURED
-- (2026-09-14) on a live tenant, and it is a live false positive rather than a
-- theoretical one: the ordinary exchange "And Italy? / The capital of France is
-- Paris. / What is the capital of France?" was blocked 3 times out of 3 as
-- agent + prompt injection, and the threat report's `pi_snippets` contained
-- that exact string. The assistant's own previous answer, unattributed, reads
-- as an assertion somebody planted in the prompt. The matrix, each cell run 3
-- times: reverse order + unlabelled, blocked; chronological + unlabelled,
-- blocked -- so the order is not the cause; chronological + labelled, clean;
-- reverse + labelled, clean. Labelling does not blunt detection: a real
-- injection alone, as the newest turn, and as an earlier turn all still block
-- 3/3.
--
-- Rebuilding needs the structured messages, which MEASURED (2026-09-14)
-- kong.request.get_body() returns in BOTH phases, chronological, roles intact.
-- Every call to it is pcall-guarded: on the OUTPUT leg of a STREAMED response
-- there is no request context and an unguarded raise there does not fail the
-- request, it silently skips the guardrail call for that segment -- a
-- fail-OPEN. On any shape this function does not understand it returns `flat`,
-- the text `text_source` produced, so an unrecognised body narrows nothing.
--
-- NEVER WRITE "system:". MEASURED (2026-09-14): `system: You are a helpful
-- assistant.` in front of otherwise labelled turns is blocked 3/3 as agent +
-- injection, and capitalised `System:` blocks too, while the same system
-- content with no label is clean and `Instructions:` as a label is clean. That
-- is AIRS being right: a prompt that claims to carry a system message is the
-- shape of a system-prompt spoof. The system message, tool results and any
-- role this function does not recognise go in UNLABELLED.
--
-- The type guard and the empty guard below are unchanged and stay first. A
-- fallback such as `content or ""` would JSON-encode whatever arrived --
-- potentially the whole `conf` table -- into contents[].prompt and ship it to
-- AIRS and the SCM scan log; and AIRS returns `allow` on an empty string, so a
-- silent extraction gap would record as a clean scan of nothing. Raising is
-- the safe failure: MEASURED 2026-09-08, a guardrail function that raises
-- refuses the request with HTTP 500 before the model is called. The error text
-- reaches the client verbatim, so these messages carry no configuration value
-- and no credential.
return function(source, content, conf)
    if type(content) ~= "string" then
        error("airs_contents: scanned content was not a string; refusing to build a scan payload")
    end
    if content == "" then
        error("airs_contents: no text was extracted to scan")
    end
    if source == "OUTPUT" then
        return { { response = content } }
    end
    if source ~= "INPUT" then
        error("airs_contents: unrecognised scan phase")
    end

    -- The answer to every shape below that cannot be understood.
    local flat = { { prompt = content } }

    local ok, body = pcall(function() return kong.request.get_body() end)
    if not ok or type(body) ~= "table" or type(body.messages) ~= "table" then
        return flat
    end

    local params = (conf and conf.params) or {}
    local mode = params.tool_scan
    local want_tools = (mode == "calls" or mode == "catalogue")
    local loaded, cjson = pcall(require, "cjson.safe")
    local encode = (loaded and type(cjson) == "table") and cjson.encode or nil

    local parts, count = {}, 0
    local function push(text)
        if type(text) == "string" and text ~= "" then
            count = count + 1
            parts[count] = text
        end
    end

    -- TOOL SCANNING, opt-in, default off. It addresses the coverage gap that
    -- tools[].function.description and tool_calls[].function.arguments are not
    -- message content and never enter $(content) under any text_source -- so a
    -- tool call is scanned on its way back in as a tool RESULT and never on its
    -- way out. The raw body carries both, so the text can be put in front of
    -- the detectors after all. It goes INSIDE the scanned prompt element rather
    -- than as a contents[].tool_event, even though AIRS supports tool_event and
    -- detects it well: a tool_event is judged only as the LAST element, which
    -- would displace the prompt, and a guardrail function gets one scan per leg.
    -- MEASURED (2026-09-14) with guarding_mode INPUT to isolate the prompt leg,
    -- on a conversation whose injection sits only in a tool call's arguments:
    -- off, 200 five times out of five; "calls", 400 five times out of five.
    --
    -- "catalogue" additionally prepends tools[], which is the tool-poisoning
    -- surface. It is its own opt-in because a JSON parameter schema reads as
    -- source code to a profile with that detector enabled (MEASURED
    -- 2026-09-14). Try it against your own profile before enabling it.
    if mode == "catalogue" and encode and type(body.tools) == "table" then
        push(encode(body.tools))
    end

    for _, message in ipairs(body.messages) do
        if type(message) ~= "table" then
            return flat
        end
        local role, text = message.role, message.content

        -- Content is a string on the common path and an ARRAY OF PARTS as soon
        -- as the client attaches an image or a file -- what most SDKs and chat
        -- front-ends send. An earlier version of this logic skipped such a turn
        -- entirely; because the other turns still made count > 0, the flat
        -- fallback never fired and an injection hidden in an array part was
        -- never judged. Assemble the text parts instead.
        if type(text) == "table" then
            local chunks, seen = {}, 0
            for _, part in ipairs(text) do
                if type(part) ~= "table" then
                    return flat
                end
                seen = seen + 1
                local kind = part.type
                if kind == "text" then
                    if type(part.text) ~= "string" then
                        return flat
                    end
                    chunks[#chunks + 1] = part.text
                elseif kind ~= "image_url" and kind ~= "input_audio" and kind ~= "file" then
                    -- Any other part type, or none at all, is a shape this
                    -- function does not understand. Fall back rather than
                    -- silently narrow the scan.
                    return flat
                end
            end
            -- image_url, input_audio and file parts carry no text, so a turn
            -- made only of those contributes nothing -- an image with no
            -- caption is ordinary multimodal use, not a reason to bail out.
            -- Walking ZERO parts is different: an empty array, or a map-shaped
            -- content table that ipairs does not enumerate, is the unknown
            -- shape again, and is only expected on a tool call.
            if seen == 0 and type(message.tool_calls) ~= "table" then
                return flat
            end
            text = table.concat(chunks, "\n")
        end

        if type(text) == "string" and text ~= "" then
            if role == "user" or role == "assistant" then
                push(role .. ": " .. text)
            else
                -- system, tool, and anything unrecognised. Unlabelled on
                -- purpose: see the "system:" note in the header.
                push(text)
            end
        end

        if want_tools and type(message.tool_calls) == "table" then
            for _, call in ipairs(message.tool_calls) do
                -- `call.function` is a syntax error: `function` is a Lua
                -- keyword, and the OpenAI body is full of the key.
                local fn = (type(call) == "table" and type(call["function"]) == "table")
                    and call["function"] or nil
                if fn then
                    local arguments = fn.arguments
                    if type(arguments) ~= "string" and encode then
                        arguments = encode(arguments)
                    end
                    if type(arguments) == "string" then
                        push((type(fn.name) == "string" and fn.name or "tool") .. " " .. arguments)
                    end
                end
            end
        end
    end

    if count == 0 then
        return flat
    end
    return { { prompt = table.concat(parts, "\n\n") } }
end
