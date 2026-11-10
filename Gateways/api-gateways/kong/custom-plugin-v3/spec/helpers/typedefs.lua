-- Stand-in for kong.db.schema.typedefs, so schema.lua can be loaded as a real
-- Lua table and its structure asserted directly. Regex over the source cannot
-- see entity_checks at all, and quietly passes when a field moves.
--
-- These mirror the SHAPE of the real typedefs, not their validators: nothing
-- here executes Kong's validation, so a spec must assert on declarations rather
-- than on accept/reject behaviour.
return {
  protocols_http = {
    type = "set",
    required = true,
    default = { "http", "https" },
    elements = { type = "string", one_of = { "http", "https" } },
  },
  no_consumer = { type = "foreign", reference = "consumers", eq = ngx and ngx.null or nil },
  url = { type = "string", required = true },
}
