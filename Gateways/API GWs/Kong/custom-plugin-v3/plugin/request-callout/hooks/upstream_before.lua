-- upstream.before — restore the client's original body.
--
-- The request hook replaced the callout's body, not the upstream's, but the
-- plugin re-serialises the request either way, so the original bytes are put
-- back explicitly. Unchanged in substance; kept here so all three hooks live
-- together and are generated from the same place.

if kong.ctx.shared.airs_blocked then return end

local body = kong.ctx.shared.original_request_body
if body then
    kong.service.request.set_raw_body(body)
    kong.service.request.set_header('content-length', tostring(#body))
end
