// Build the AIRS sync/request JSON body safely.
// Branches on FlowCallout parameter "type":
//   "user-prompt"     -> uses request_prompt_value, content.prompt
//   "response-prompt" -> uses response_prompt_value, content.response
// JSON.stringify handles quotes, newlines, backslashes, unicode etc.

var type = context.getVariable('type');
var profile = context.getVariable('airs.profile');
// Apigee's messageid is unique per request — a transaction identifier.
var transactionId = context.getVariable('messageid');
var model = context.getVariable('model');

var content = {};
if (type === 'response-prompt') {
    content.response = context.getVariable('response_prompt_value') || '';
} else {
    content.prompt = context.getVariable('request_prompt_value') || '';
}

var body = {
    transaction_id: transactionId || '',
    ai_profile: { profile_name: profile || '' },
    metadata: {
        ai_model: model || 'unknown',
        app_user: 'apigee-shared-flow',
        app_name: 'Apigee-SharedFlow'
    },
    contents: [content]
};

context.setVariable('airsScanRequestBody', JSON.stringify(body));
