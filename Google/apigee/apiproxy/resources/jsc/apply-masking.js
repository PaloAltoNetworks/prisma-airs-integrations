// Apply masked content from AIRS when provided
// AIRS returns masked content in contents[0].response when masking is enabled in the profile
var action = context.getVariable('airs.scan.response.action');
var redactedContent = context.getVariable('airs.scan.response.redacted');

// If AIRS provided masked content (regardless of category)
// This respects the AIRS profile configuration in SCM
if (action === 'allow' && redactedContent) {
  try {
    // Get the original Vertex AI response
    var originalResponse = context.getVariable('response.content');
    var responseObj = JSON.parse(originalResponse);
    
    // Replace the text with masked content from AIRS
    if (responseObj.candidates && Array.isArray(responseObj.candidates)) {
      for (var i = 0; i < responseObj.candidates.length; i++) {
        if (responseObj.candidates[i].content && 
            responseObj.candidates[i].content.parts && 
            Array.isArray(responseObj.candidates[i].content.parts)) {
          for (var j = 0; j < responseObj.candidates[i].content.parts.length; j++) {
            if (responseObj.candidates[i].content.parts[j].text) {
              // Replace with masked content from AIRS
              responseObj.candidates[i].content.parts[j].text = redactedContent;
            }
          }
        }
      }
    }
    
    // Set the modified response back
    context.setVariable('response.content', JSON.stringify(responseObj));
    context.setVariable('airs.masking.applied', 'true');
    
  } catch (e) {
    // If error, log but don't fail - original response will be returned
    print('Error applying masking: ' + e);
  }
}

