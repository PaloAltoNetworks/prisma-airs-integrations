// Extract response from Vertex AI (mirrors scan-prompt.js pattern)
var body = context.getVariable('response.content') || '';
var response_text = '';

try {
  var obj = JSON.parse(body);
  if (obj.candidates && Array.isArray(obj.candidates)) {
    for (var i = 0; i < obj.candidates.length; i++) {
      var candidate = obj.candidates[i];
      if (candidate.content && candidate.content.parts && Array.isArray(candidate.content.parts)) {
        for (var j = 0; j < candidate.content.parts.length; j++) {
          if (candidate.content.parts[j].text) {
            response_text += candidate.content.parts[j].text;
          }
        }
      }
    }
  }
} catch (e) {
  response_text = body;
}

// Build AIRS scan payload
var sessionId = context.getVariable('request.header.X-Session-ID') || context.getVariable('messageid');
var airsProfile = context.getVariable('request.header.X-Pan-Profile') || context.getVariable('private.prisma.airs.profile') || 'default';
var vertexModel = context.getVariable('private.vertex.model') || 'gemini-2.5-flash';

var payload = {
  tr_id: sessionId,
  ai_profile: {profile_name: airsProfile},
  metadata: {
    ai_model: vertexModel,
    app_user: 'apigee-user',
    app_name: 'vertex-simple'
  },
  contents: [{response: response_text}]
};

context.setVariable('airs.scan.response.payload', JSON.stringify(payload));
