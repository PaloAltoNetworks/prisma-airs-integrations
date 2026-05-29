// Apply the masked model output AIRS returned (when the profile enables
// masking) before the response goes back to the client. Mirror of
// apply-prompt-masking.js for the response side: the SharedFlow exposes
// airs.response.redacted as a string; this policy knows the Vertex response
// shape (candidates[].content.parts[].text) and writes the redacted text in.
var action = context.getVariable('airs.action');
var redactedResponse = context.getVariable('airs.response.redacted');

if (action === 'allow' && redactedResponse) {
  try {
    var responseObj = JSON.parse(context.getVariable('response.content'));
    if (responseObj.candidates && Array.isArray(responseObj.candidates)) {
      for (var i = 0; i < responseObj.candidates.length; i++) {
        var content = responseObj.candidates[i].content;
        if (content && content.parts && Array.isArray(content.parts)) {
          for (var j = 0; j < content.parts.length; j++) {
            if (content.parts[j].text) {
              content.parts[j].text = redactedResponse;
            }
          }
        }
      }
    }
    context.setVariable('response.content', JSON.stringify(responseObj));
    context.setVariable('airs.response.masking.applied', 'true');
  } catch (e) {
    // Don't fail the response on a masking error — return the original output.
    print('Error applying response masking: ' + e);
  }
}
