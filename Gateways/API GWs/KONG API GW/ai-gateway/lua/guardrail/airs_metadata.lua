-- ai-custom-guardrail function: metadata
--
-- Everything here comes from static policy config, and that is a CONSTRAINT,
-- not a choice. Only `source`, `content`, `conf` and `resp` are injectable into
-- a guardrail function; `consumer`, `model`, `route`, `service`, `request`,
-- `headers` and `kong` are all rejected outright with
--   argument '<name>' is not allowed in guardrail functions
-- so there is no way to reach the calling consumer's identity, the model name,
-- or a request id from this phase. Per-request correlation is therefore NOT
-- available on the LLM path in configuration alone -- see docs/DESIGN.md.
--
-- The consequence to be honest about: every scan from one policy lands in SCM
-- under the same app_name and app_user, so an SCM operator can tell which
-- gateway a detection came from and cannot tell which caller. The
-- configuration-native way to get coarse attribution back is one copy of the
-- policy per AI Consumer Group, each with its own params.app_user, attached to
-- that group only.
return function(conf)
    local md = { app_name = conf.params.app_name }
    -- app_user and ai_model are optional in the AIRS schema. They are sent only
    -- when an operator has set them, rather than defaulted to something
    -- plausible: a fabricated user in a security log is worse than no user.
    if type(conf.params.app_user) == "string" and conf.params.app_user ~= "" then
        md.app_user = conf.params.app_user
    end
    if type(conf.params.ai_model) == "string" and conf.params.ai_model ~= "" then
        md.ai_model = conf.params.ai_model
    end
    return md
end
