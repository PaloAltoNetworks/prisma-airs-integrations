// Extract prompt from Vertex AI request
var body = context.getVariable('request.content') || '';
var prompt = '';

try {
  var obj = JSON.parse(body);
  if (obj.contents && Array.isArray(obj.contents)) {
    for (var i = 0; i < obj.contents.length; i++) {
      var content = obj.contents[i];
      if (content.parts && Array.isArray(content.parts)) {
        for (var j = 0; j < content.parts.length; j++) {
          if (content.parts[j].text) {
            prompt += content.parts[j].text;
          }
        }
      }
    }
  }
} catch (e) {
  prompt = body;
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
  contents: [{prompt: prompt}]
};

context.setVariable('airs.request.payload', JSON.stringify(payload));
context.setVariable('ai.prompt', prompt);
