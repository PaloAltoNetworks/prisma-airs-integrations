-- ai-custom-guardrail function: ai_profile
--
-- Referenced from the policy as a BARE expression, `$(airs_profile)`. The
-- explicit-argument form `$(airs_profile(conf))` is not valid: the data plane
-- answers HTTP 500 "failed to render by function: invalid expression syntax"
-- and no request reaches the model. Built-ins are injected BY PARAMETER NAME,
-- so this function is handed `conf` because it is named `conf`.
--
-- AIRS accepts either profile_name or profile_id. Name is used here because it
-- is what an operator reads in Strata Cloud Manager; profile_id is the stable
-- identifier and is the better choice if profiles are renamed in place.
return function(conf)
    return { profile_name = conf.params.profile }
end
