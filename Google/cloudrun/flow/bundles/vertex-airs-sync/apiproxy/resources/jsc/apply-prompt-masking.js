// Apply the masked prompt AIRS returned (when the profile enables masking)
// before the request reaches Vertex. The PANW-AIRS SharedFlow stays payload-
// agnostic — it only exposes airs.prompt.redacted as a string. This policy,
// which lives in the Vertex proxy, is the one that knows the Vertex request
// shape (contents[].parts[].text) and writes the redacted text back in.
var action = context.getVariable('airs.action');
var redactedPrompt = context.getVariable('airs.prompt.redacted');

// Only on an allow verdict that carried masked content. A block verdict is
// handled by the SharedFlow's RF-* policies and never reaches the target.
if (action === 'allow' && redactedPrompt) {
  try {
    var requestObj = JSON.parse(context.getVariable('request.content'));
    if (requestObj.contents && Array.isArray(requestObj.contents)) {
      for (var i = 0; i < requestObj.contents.length; i++) {
        var parts = requestObj.contents[i].parts;
        if (parts && Array.isArray(parts)) {
          for (var j = 0; j < parts.length; j++) {
            if (parts[j].text) {
              parts[j].text = redactedPrompt;
            }
          }
        }
      }
    }
    context.setVariable('request.content', JSON.stringify(requestObj));
    context.setVariable('airs.prompt.masking.applied', 'true');
  } catch (e) {
    // Don't fail the request on a masking error — send the original prompt.
    print('Error applying prompt masking: ' + e);
  }
}
