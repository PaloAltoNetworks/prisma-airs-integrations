mod common;

use common::{encode64, pcm};
use prisma_airs_core::extract::response::{from_value, scan_text, ResponseParts, ToolCall};
use prisma_airs_core::extract::{ExtractError, Slot};
use prisma_airs_core::format::Format;
use prisma_airs_core::sse;
use serde_json::{json, Value};

fn raw(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/response/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn json_parts(format: Format, name: &str) -> ResponseParts {
    let value: Value = serde_json::from_slice(&raw(name)).unwrap();
    from_value(format, &value).unwrap()
}

fn sse_parts_of(format: Format, body: &[u8]) -> ResponseParts {
    let events = sse::events(body);
    from_value(format, &sse::to_final_json(format, &events).unwrap()).unwrap()
}

fn sse_parts(format: Format, name: &str) -> ResponseParts {
    sse_parts_of(format, &raw(name))
}

fn scanned(parts: &ResponseParts) -> String {
    scan_text(parts, 20000).text
}

fn weather_call(parts: &ResponseParts) {
    assert_eq!(parts.tool_calls.len(), 1, "{:?}", parts.tool_calls);
    let call = &parts.tool_calls[0];
    assert_eq!(call.name, "get_weather");
    let args: Value = serde_json::from_str(&call.arguments).unwrap_or_else(|_| panic!("arguments not JSON: {}", call.arguments));
    assert_eq!(args, json!({"city": "Paris"}));
    let text = scanned(parts);
    assert!(text.contains("tool get_weather:") && text.contains("Paris"), "{text:?}");
}

// ---- recorded replies, JSON and SSE through the same extractor ---------------------------------------------------

#[test]
fn json_anthropic_plain() {
    let p = json_parts(Format::AnthropicMessages, "anthropic/plain.json");
    assert_eq!(p.texts, vec!["ready".to_string()]);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Single("/content/0/text".into()));
}

#[test]
fn sse_anthropic_plain() {
    assert_eq!(scanned(&sse_parts(Format::AnthropicMessages, "anthropic/plain.sse")), "ready");
}

#[test]
fn json_anthropic_tool() {
    let p = json_parts(Format::AnthropicMessages, "anthropic/tool.json");
    weather_call(&p);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Multi);
}

#[test]
fn sse_anthropic_tool() {
    weather_call(&sse_parts(Format::AnthropicMessages, "anthropic/tool.sse"));
}

#[test]
fn json_anthropic_thinking() {
    let p = json_parts(Format::AnthropicMessages, "anthropic/thinking.json");
    assert_eq!(p.texts, vec!["391".to_string()]);
    assert_eq!(p.thinking.len(), 1);
    assert!(p.thinking[0].contains("17"), "{:?}", p.thinking);
    let text = scanned(&p);
    assert!(text.starts_with("391\n\n") && text.contains("17"), "text first, thinking after: {text:?}");
}

#[test]
fn sse_anthropic_thinking() {
    let p = sse_parts(Format::AnthropicMessages, "anthropic/thinking.sse");
    assert_eq!(p.texts, vec!["391".to_string()]);
    assert!(p.thinking.len() == 1 && p.thinking[0].contains("17"), "{:?}", p.thinking);
}

#[test]
fn json_openai_plain() {
    let p = json_parts(Format::OpenAiChat, "openai/plain.json");
    assert_eq!(p.texts, vec!["ready".to_string()]);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Single("/choices/0/message/content".into()));
}

#[test]
fn sse_openai_plain() {
    assert_eq!(scanned(&sse_parts(Format::OpenAiChat, "openai/plain.sse")), "ready");
}

#[test]
fn json_openai_n2() {
    let p = json_parts(Format::OpenAiChat, "openai/n2.json");
    assert_eq!(p.texts.len(), 2, "{:?}", p.texts);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Multi);
}

#[test]
fn json_openai_tool() {
    weather_call(&json_parts(Format::OpenAiChat, "openai/tool.json"));
}

#[test]
fn sse_openai_tool() {
    weather_call(&sse_parts(Format::OpenAiChat, "openai/tool.sse"));
}

#[test]
fn json_responses_plain() {
    let p = json_parts(Format::OpenAiResponses, "responses/plain.json");
    assert_eq!(p.texts, vec!["ready".to_string()]);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Single("/output/0/content/0/text".into()));
}

#[test]
fn sse_responses_plain() {
    assert_eq!(scanned(&sse_parts(Format::OpenAiResponses, "responses/plain.sse")), "ready");
}

#[test]
fn json_responses_tool() {
    weather_call(&json_parts(Format::OpenAiResponses, "responses/tool.json"));
}

#[test]
fn sse_responses_tool() {
    weather_call(&sse_parts(Format::OpenAiResponses, "responses/tool.sse"));
}

#[test]
fn json_gemini_plain() {
    let p = json_parts(Format::Gemini, "gemini/plain.json");
    assert_eq!(p.texts, vec!["ready".to_string()]);
    assert_eq!(scan_text(&p, 20000).slot, Slot::Single("/candidates/0/content/parts/0/text".into()));
}

#[test]
fn sse_gemini_plain() {
    assert_eq!(scanned(&sse_parts(Format::Gemini, "gemini/plain.sse")), "ready");
}

#[test]
fn json_gemini_tool() {
    weather_call(&json_parts(Format::Gemini, "gemini/tool.json"));
}

#[test]
fn sse_gemini_tool() {
    // The recorded Gemini stream uses CRLF line endings.
    assert!(raw("gemini/tool.sse").windows(2).any(|w| w == b"\r\n"));
    weather_call(&sse_parts(Format::Gemini, "gemini/tool.sse"));
}

// ---- SSE edge cases -----------------------------------------------------------------------------------------------

#[test]
fn sse_azure_empty_choices_first() {
    let body = raw("openai/plain.sse");
    let first = sse::events(&body).into_iter().next().unwrap();
    assert!(first.data.contains("\"choices\":[]"), "the recording starts with Azure's prompt-filter event");
    let p = sse_parts_of(Format::OpenAiChat, &body);
    assert!(!p.is_empty());
}

#[test]
fn sse_keepalive_and_crlf() {
    let body = b": keep-alive\r\n\r\ndata:{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\r\n\r\n: ping\r\n\
data: {\"choices\":[{\"index\":0,\r\ndata: \"delta\":{\"content\":\"lo\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n";
    let events = sse::events(body);
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(events[1].data, "{\"choices\":[{\"index\":0,\n\"delta\":{\"content\":\"lo\"}}]}");
    assert_eq!(scanned(&sse_parts_of(Format::OpenAiChat, body)), "hello");
}

#[test]
fn sse_event_names_and_lone_cr() {
    let body = b"event: message_start\rdata: {\"type\":\"message_start\",\"message\":{\"content\":[]}}\r\r";
    let events = sse::events(body);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.as_deref(), Some("message_start"));
}

#[test]
fn sse_last_event_without_blank_line_counts() {
    let body = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"tail\"}]}}]}";
    assert_eq!(scanned(&sse_parts_of(Format::Gemini, body)), "tail");
}

#[test]
fn sse_anthropic_ping_and_error_event_keeps_prior_text() {
    let body = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"content\":[]}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: ping\ndata: {\"type\":\"ping\"}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"BLOCKME half\"}}\n\n",
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n",
    );
    let p = sse_parts_of(Format::AnthropicMessages, body.as_bytes());
    assert_eq!(scanned(&p), "BLOCKME half");
}

#[test]
fn sse_garbage_frame_is_unreadable() {
    let events = sse::events(b"data: {\"choices\":[]}\n\ndata: not json\n\n");
    assert!(matches!(sse::to_final_json(Format::OpenAiChat, &events), Err(ExtractError::Unreadable(_))));
}

#[test]
fn sse_anthropic_partial_tool_json_is_kept_as_text() {
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"content\":[]}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"run\",\"input\":{}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\": \\\"rm -\"}}\n\n",
    );
    let p = sse_parts_of(Format::AnthropicMessages, body.as_bytes());
    assert_eq!(p.tool_calls, vec![ToolCall { name: "run".into(), arguments: "{\"cmd\": \"rm -".into() }]);
}

// ---- what a reply must not hide ---------------------------------------------------------------------------------

#[test]
fn tool_call_only_openai() {
    let v = json!({"choices":[{"index":0,"message":{"role":"assistant","content":null,
        "tool_calls":[{"id":"c1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"x@example.com\"}"}}]}}]});
    let p = from_value(Format::OpenAiChat, &v).unwrap();
    assert!(!p.is_empty());
    let text = scanned(&p);
    assert!(text.contains("tool send_email:") && text.contains("x@example.com"), "{text:?}");
}

#[test]
fn tool_call_only_anthropic() {
    let v = json!({"content":[{"type":"tool_use","id":"t","name":"send_email","input":{"to":"x@example.com"}}]});
    let p = from_value(Format::AnthropicMessages, &v).unwrap();
    assert!(!p.is_empty());
    assert!(scanned(&p).contains("tool send_email:"));
}

#[test]
fn n2_scans_both_choices() {
    let v = json!({"choices":[{"index":0,"message":{"content":"fine"}},{"index":1,"message":{"content":"BLOCKME"}}]});
    let text = scanned(&from_value(Format::OpenAiChat, &v).unwrap());
    assert!(text.contains("fine") && text.contains("BLOCKME"), "{text:?}");
}

#[test]
fn n2_streamed_scans_both_choices() {
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"fine\"}},{\"index\":1,\"delta\":{\"content\":\"BLOCK\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":1,\"delta\":{\"content\":\"ME\"}}]}\n\n",
        "data: [DONE]\n\n",
    );
    let text = scanned(&sse_parts_of(Format::OpenAiChat, body.as_bytes()));
    assert!(text.contains("fine") && text.contains("BLOCKME"), "{text:?}");
}

#[test]
fn gemini_function_call_and_thought_parts() {
    let v = json!({"candidates":[{"index":0,"content":{"role":"model","parts":[
        {"text":"thinking about it","thought":true},
        {"functionCall":{"name":"lookup","args":{"q":"BLOCKME"}}},
        {"text":"done"}]}}]});
    let p = from_value(Format::Gemini, &v).unwrap();
    assert_eq!(p.texts, vec!["done".to_string()]);
    assert_eq!(p.thinking, vec!["thinking about it".to_string()]);
    assert_eq!(p.tool_calls[0].name, "lookup");
    assert!(scanned(&p).contains("BLOCKME"));
}

#[test]
fn gemini_two_candidates_are_two_texts() {
    let v = json!({"candidates":[{"index":0,"content":{"parts":[{"text":"a"}]}},{"index":1,"content":{"parts":[{"text":"b"}]}}]});
    assert_eq!(from_value(Format::Gemini, &v).unwrap().texts, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn responses_completed_event_preferred() {
    let body = concat!(
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"partial\"}\n\n",
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"the final text\"}]}]}}\n\n",
    );
    assert_eq!(scanned(&sse_parts_of(Format::OpenAiResponses, body.as_bytes())), "the final text");
}

#[test]
fn responses_rebuilt_without_completed() {
    for (name, expect) in [("responses/plain.sse", "ready"), ("responses/tool.sse", "get_weather")] {
        let body = String::from_utf8(raw(name)).unwrap();
        let kept: Vec<&str> = body.split("\n\n").filter(|block| !block.contains("response.completed")).collect();
        let stripped = kept.join("\n\n");
        assert!(!stripped.contains("response.completed"));
        let text = scanned(&sse_parts_of(Format::OpenAiResponses, stripped.as_bytes()));
        assert!(text.contains(expect), "{name}: {text:?}");
    }
}

#[test]
fn unknown_anthropic_blocks_are_scanned_not_dropped() {
    let v = json!({"content":[{"type":"web_search_tool_result","content":[{"type":"web_search_result","title":"BLOCKME"}]}]});
    assert!(scanned(&from_value(Format::AnthropicMessages, &v).unwrap()).contains("BLOCKME"));
}

// ---- empty and unreadable -----------------------------------------------------------------------------------------

#[test]
fn empty_reply_is_empty() {
    let p = from_value(Format::OpenAiChat, &json!({"choices":[{"message":{"content":""}}]})).unwrap();
    assert!(p.is_empty());
}

#[test]
fn stream_with_no_content_is_empty() {
    let body = b"data: {\"choices\":[],\"prompt_filter_results\":[]}\n\ndata: [DONE]\n\n";
    assert!(sse_parts_of(Format::OpenAiChat, body).is_empty());
}

#[test]
fn missing_container_is_unreadable() {
    assert!(matches!(from_value(Format::OpenAiChat, &json!({"id":"x"})), Err(ExtractError::Unreadable(_))));
    assert!(matches!(from_value(Format::AnthropicMessages, &json!({"id":"x"})), Err(ExtractError::Unreadable(_))));
    assert!(matches!(from_value(Format::OpenAiResponses, &json!({"id":"x"})), Err(ExtractError::Unreadable(_))));
    assert!(matches!(from_value(Format::Gemini, &json!({"id":"x"})), Err(ExtractError::Unreadable(_))));
    assert!(matches!(from_value(Format::Gemini, &json!("x")), Err(ExtractError::Unreadable(_))));
}

#[test]
fn gemini_blocked_prompt_reply_is_empty() {
    let v = json!({"promptFeedback": {"blockReason": "SAFETY"}});
    assert!(from_value(Format::Gemini, &v).unwrap().is_empty());
}

#[test]
fn scan_text_truncates_by_chars_and_drops_the_slot() {
    let p = from_value(Format::OpenAiChat, &json!({"choices":[{"message":{"content":"é".repeat(30)}}]})).unwrap();
    let e = scan_text(&p, 10);
    assert!(e.truncated);
    assert_eq!(e.text.chars().count(), 10);
    assert_eq!(e.slot, Slot::Multi);
}

// ---- Gemini parts and candidate metadata --------------------------------------------------------------------------

#[test]
fn gemini_unknown_parts_and_metadata_are_scanned() {
    let v = json!({"candidates":[{"index":0,
        "content":{"role":"model","parts":[{"inlineData":{"mimeType":"image/png","data":"iVBORw0KGgo"}}]},
        "groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://BLOCKME.example/a","title":"t"}}]},
        "citationMetadata":{"citationSources":[{"uri":"https://cite.example/b"}]},
        "urlContextMetadata":{"urlMetadata":[{"retrievedUrl":"https://ctx.example/c"}]}}]});
    let p = from_value(Format::Gemini, &v).unwrap();
    assert!(!p.is_empty(), "a reply of non-text parts and metadata is not empty");
    let t = scanned(&p);
    for s in ["BLOCKME", "cite.example", "ctx.example", "image/png"] {
        assert!(t.contains(s), "{s} missing: {t:?}");
    }
}

#[test]
fn gemini_text_with_grounding_is_scanned_with_its_sources() {
    let v = json!({"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"See the source."}]},
        "groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://BLOCKME.example/a"}}],
        "searchEntryPoint":{"renderedContent":"<a href=\"https://BLOCKME.example/b\">x</a>"}}}]});
    let t = scanned(&from_value(Format::Gemini, &v).unwrap());
    assert!(t.contains("See the source.") && t.contains("https://BLOCKME.example/a") && t.contains("https://BLOCKME.example/b"), "{t:?}");
}

#[test]
fn gemini_stream_keeps_candidate_metadata() {
    let body = concat!(
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]}}]}\r\n\r\n",
        "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\" world\"}]},",
        "\"groundingMetadata\":{\"groundingChunks\":[{\"web\":{\"uri\":\"https://BLOCKME.example/a\"}}]}}]}\r\n\r\n",
    );
    let t = scanned(&sse_parts_of(Format::Gemini, body.as_bytes()));
    assert!(t.contains("Hello world") && t.contains("BLOCKME"), "{t:?}");
}

// ---- a provider's inline payload is read as the bytes it declares -------------------------------------------------

/// A Gemini speech part: `samples` samples of audio with no file header, as Gemini's speech generation streams it.
fn speech_part(samples: usize) -> Value {
    json!({"inlineData": {"mimeType": "audio/L16;codec=pcm;rate=24000", "data": encode64(&pcm(samples))}})
}

fn head(text: &str) -> String {
    text.chars().take(300).collect()
}

#[test]
fn a_gemini_speech_reply_is_scanned_without_its_bytes() {
    let part = speech_part(48_000);
    let data = part["inlineData"]["data"].as_str().unwrap().to_string();
    let v = json!({"candidates": [{"index": 0, "content": {"role": "model", "parts": [part]}}]});
    let e = scan_text(&from_value(Format::Gemini, &v).unwrap(), 100_000);
    assert!(!e.truncated, "two seconds of speech fit the limit once its bytes are left out: {}", head(&e.text));
    assert!(e.text.contains("audio/L16") && !e.text.contains(&data[..48]), "{}", head(&e.text));
}

#[test]
fn a_streamed_gemini_speech_reply_is_scanned_without_its_bytes() {
    let frames: String = (0..4)
        .map(|_| {
            let frame = json!({"candidates": [{"index": 0, "content": {"role": "model", "parts": [speech_part(12_000)]}}]});
            format!("data: {frame}\r\n\r\n")
        })
        .collect();
    let e = scan_text(&sse_parts_of(Format::Gemini, frames.as_bytes()), 100_000);
    assert!(!e.truncated, "each streamed chunk is left out: {}", head(&e.text));
    assert!(e.text.contains("audio/L16") && e.text.contains("<binary,"), "{}", head(&e.text));
}
