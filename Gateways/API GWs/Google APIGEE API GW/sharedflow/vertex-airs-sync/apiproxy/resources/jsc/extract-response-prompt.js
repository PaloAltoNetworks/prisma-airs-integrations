// Parse the Vertex generateContent response body and flatten all model-emitted
// text into response_prompt_value (single string). Joined with newlines so the
// AIRS output scan sees the full model response, properly escaped downstream.

var raw = context.getVariable('response.content');
var text = '';

try {
    if (raw) {
        var body = JSON.parse(raw);
        if (body && body.candidates && body.candidates.length > 0) {
            var content = body.candidates[0].content;
            if (content && content.parts) {
                var parts = [];
                for (var i = 0; i < content.parts.length; i++) {
                    if (content.parts[i] && typeof content.parts[i].text === 'string') {
                        parts.push(content.parts[i].text);
                    }
                }
                text = parts.join('\n');
            }
        }
    }
} catch (e) {
    text = '';
}

context.setVariable('response_prompt_value', text);
