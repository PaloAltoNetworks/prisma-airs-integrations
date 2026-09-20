-- ai-custom-guardrail function: metadata
--
-- Labels the scan in the Prisma AIRS log: which gateway, which model, which
-- caller, from which address.
--
-- THIS FILE USED TO SAY THE OPPOSITE. It read static policy config only, and
-- explained that the calling consumer and the model name were unreachable
-- because the injectable parameter allowlist is `source`, `content`, `conf`,
-- `resp`. The allowlist is real; the conclusion drawn from it was not. It
-- describes what Kong hands the function as an ARGUMENT, and says nothing
-- about the sandbox the body runs in. MEASURED (2026-09-14, AI Gateway 2.0.3):
-- in the body `kong` and `ngx` are tables and `require` is a function.
-- Reachable and used here: ngx.ctx.ai_model (the AI Model entity, with `name`),
-- kong.request.get_body(), kong.client.get_forwarded_ip(), kong.client.get_ip()
-- and kong.client.get_consumer(). Reachable and not used: get_credential(),
-- kong.request.get_path(), ngx.var.request_id (airs_correlation uses that one).
-- Not reachable: kong.router.* is nil and kong.log.serialize() refuses with
-- "function cannot be called in access phase". See docs/CREDITS.md.
--
-- The visible consequence is the one the README used to record as a limit:
-- Strata Cloud Manager showed `model_name: None` and `user_id: None` on every
-- scan. It now shows the model and the caller.
--
-- EVERY LOOKUP IS pcall-GUARDED, and that is load-bearing rather than tidy.
-- MEASURED (2026-09-14): on the OUTPUT leg of a STREAMED response the function
-- runs with no request context and these calls raise. A raise there does not
-- fail the request; it silently skips the guardrail call for that segment --
-- a fail-OPEN, invisible to the client, measured as 7 segment scans becoming
-- 0. `first` swallows each failure and moves on, and a field nothing could
-- build is left nil.
--
-- NIL, NEVER "". MEASURED (2026-09-14): a request.body field that is nil is
-- omitted from the scan payload, while a field that is an empty string is
-- rendered as JSON `false`. An identifier that cannot be built must therefore
-- be absent, not blank.
--
-- DEPLOYMENT CAVEAT ON user_ip. get_forwarded_ip() returns the X-Forwarded-For
-- address only when the immediate peer is listed in the data plane's
-- `trusted_ips`; otherwise it returns the peer's own address, which behind a
-- load balancer is the load balancer. That is correct Kong behaviour and it is
-- visible to whoever reads the scan log, so set trusted_ips on the data plane
-- if the recorded client address has to be the real one.
return function(conf)
    local params = (conf and conf.params) or {}

    -- Returns the first getter that yields a usable string. A getter that
    -- raises, returns nil, returns a non-string, or returns something absurdly
    -- long is skipped rather than fatal.
    local function first(...)
        for _, get in ipairs({ ... }) do
            local ok, value = pcall(get)
            if ok and type(value) == "string" and #value > 0 and #value <= 256 then
                return value
            end
        end
        return nil
    end

    return {
        app_name = params.app_name,

        -- The AI Model entity first, because that is the name an operator
        -- configured and reads back in Konnect. MEASURED: on the INPUT leg
        -- body.model is the model the CALLER asked for and on the OUTPUT leg
        -- it is the resolved target, so it is the fallback and not the source.
        -- params.ai_model remains the last resort for an operator who prefers
        -- a fixed label.
        ai_model = first(function() return ngx.ctx.ai_model.name end,
                         function() return kong.request.get_body().model end,
                         function() return params.ai_model end),

        user_ip = first(function() return kong.client.get_forwarded_ip() end,
                        function() return kong.client.get_ip() end),

        -- The authenticated consumer first: that is an identity Kong
        -- established. The header after it is for a gateway fronting an
        -- application that knows its own end user -- it is caller-controlled,
        -- so it labels a scan and must never be read as an authenticated
        -- identity. params.app_user stays last, unchanged in meaning: a fixed
        -- label for a policy attached to one consumer group.
        app_user = first(function()
                             local consumer = kong.client.get_consumer()
                             return consumer and (consumer.username or consumer.id) or nil
                         end,
                         function() return kong.request.get_header(params.user_header) end,
                         function() return params.app_user end),
    }
end
