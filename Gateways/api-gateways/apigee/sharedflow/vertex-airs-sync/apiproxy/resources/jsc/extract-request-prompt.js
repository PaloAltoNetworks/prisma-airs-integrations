// Parse the Vertex generateContent request body and flatten all user-supplied
// text into request_prompt_value (single string). Multi-turn / multi-part
// messages are joined with newlines so AIRS scans the whole conversation.

var raw = context.getVariable('request.content');
var text = '';

try {
    if (raw) {
        var body = JSON.parse(raw);
        var parts = [];
        if (body && body.contents) {
            for (var i = 0; i < body.contents.length; i++) {
                var entry = body.contents[i];
                if (entry && entry.parts) {
                    for (var j = 0; j < entry.parts.length; j++) {
                        if (entry.parts[j] && typeof entry.parts[j].text === 'string') {
                            parts.push(entry.parts[j].text);
                        }
                    }
                }
            }
        }
        text = parts.join('\n');
    }
} catch (e) {
    text = '';
}

context.setVariable('request_prompt_value', text);
