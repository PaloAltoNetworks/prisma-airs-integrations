// Apply masked prompt from AIRS before sending to Vertex AI
// This prevents PII from reaching the LLM when masking is enabled in AIRS profile
var action = context.getVariable('airs.action');
var redactedPrompt = context.getVariable('airs.prompt.redacted');

// If AIRS provided masked prompt content (regardless of category)
// This respects the AIRS profile configuration in SCM
if (action === 'allow' && redactedPrompt) {
  try {
    // Get the original request
    var originalRequest = context.getVariable('request.content');
    var requestObj = JSON.parse(originalRequest);
    
    // Replace the prompt text with masked content from AIRS
    if (requestObj.contents && Array.isArray(requestObj.contents)) {
      for (var i = 0; i < requestObj.contents.length; i++) {
        if (requestObj.contents[i].parts && Array.isArray(requestObj.contents[i].parts)) {
          for (var j = 0; j < requestObj.contents[i].parts.length; j++) {
            if (requestObj.contents[i].parts[j].text) {
              // Replace with masked prompt from AIRS
              requestObj.contents[i].parts[j].text = redactedPrompt;
            }
          }
        }
      }
    }
    
    // Set the modified request that will go to Vertex AI
    context.setVariable('request.content', JSON.stringify(requestObj));
    context.setVariable('airs.prompt.masking.applied', 'true');
    
  } catch (e) {
    // If error, log but don't fail - original request will be sent
    print('Error applying prompt masking: ' + e);
  }
}



