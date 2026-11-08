-- ai-custom-guardrail function: contents
--
-- Picks the AIRS content key from the phase. `$(source)` is "INPUT" while the
-- request is being inspected and "OUTPUT" while the response is, and AIRS keys
-- the two differently: contents[].prompt versus contents[].response. Sending a
-- model answer under `prompt` does not merely mislabel it -- AIRS runs a
-- different detector set per direction, so the scan would be wrong, not just
-- untidy.
--
-- The type guard is mandatory and the reason is specific. Built-ins are matched
-- by PARAMETER NAME, so a rename in Kong, or a typo here, hands this function
-- something that is not the scanned text. A permissive fallback such as
-- `content or ""` would then JSON-encode whatever arrived -- potentially the
-- whole `conf` table -- into contents[].prompt and ship it to AIRS and into the
-- SCM scan log. Raising is the safe failure: a guardrail function that errors
-- refuses the request with HTTP 500 before the model is called.
--
-- Note the error text reaches the client verbatim, so these messages carry no
-- configuration values and no credential.
return function(source, content)
    if type(content) ~= "string" then
        error("airs_contents: scanned content was not a string; refusing to build a scan payload")
    end
    if content == "" then
        -- An empty extraction is not a clean scan. AIRS would return `allow` on
        -- an empty string and the gateway would record a successful inspection
        -- of nothing, which is how a content-extraction gap silently becomes a
        -- pass. Refuse instead, and let the operator see it.
        error("airs_contents: no text was extracted to scan")
    end
    if source == "INPUT" then
        return { { prompt = content } }
    end
    if source == "OUTPUT" then
        return { { response = content } }
    end
    error("airs_contents: unrecognised scan phase")
end
