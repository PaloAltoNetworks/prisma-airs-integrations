mod common;

use common::{encode64, pcm};
use prisma_airs_core::extract::request::prompt_text;
use prisma_airs_core::extract::{write_back, ExtractError, Field, Slot};
use prisma_airs_core::format::{is_streamed, requested_model, Format};
use prisma_airs_core::settings::{Role, RoleSet};
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/request/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn all_roles() -> RoleSet {
    RoleSet::user_only().with(Role::System).with(Role::Assistant).with(Role::Tool)
}

fn text(format: Format, body: &Value, roles: &RoleSet) -> String {
    prompt_text(format, body, roles, 20000).unwrap().text
}

fn field(pointer: &str, chars: usize) -> Field {
    Field { pointer: pointer.into(), chars }
}

fn assert_in_order(text: &str, pieces: &[&str]) {
    let mut at = 0;
    for piece in pieces {
        let found = text[at..].find(piece).unwrap_or_else(|| panic!("{piece:?} missing or out of order in {text:?}"));
        at += found + piece.len();
    }
}

// ---- detection -------------------------------------------------------------------------------------------------

#[test]
fn detect_header_beats_body() {
    assert_eq!(Format::detect(Some("openai"), "/openai/responses", &json!({"input":"x"})), Some(Format::OpenAiResponses));
}

#[test]
fn detect_header_wins_over_body_shape() {
    let gemini_shaped = json!({"contents": [{"parts": [{"text": "x"}]}]});
    assert_eq!(Format::detect(Some("anthropic"), "/claude/v1/messages", &gemini_shaped), Some(Format::AnthropicMessages));
    assert_eq!(Format::detect(Some("openai"), "/openai/chat/completions", &gemini_shaped), Some(Format::OpenAiChat));
    assert_eq!(Format::detect(Some("gemini"), "/gemini/models/m:generateContent", &json!({})), Some(Format::Gemini));
}

#[test]
fn detect_by_path_without_header() {
    let b = json!({});
    assert_eq!(Format::detect(None, "/v1/chat/completions", &b), Some(Format::OpenAiChat));
    assert_eq!(Format::detect(None, "/openai/responses", &b), Some(Format::OpenAiResponses));
    assert_eq!(Format::detect(None, "/claude/v1/messages", &b), Some(Format::AnthropicMessages));
    assert_eq!(Format::detect(None, "/gemini/models/gemini-3.6-flash:generateContent", &b), Some(Format::Gemini));
    assert_eq!(Format::detect(None, "/gemini/models/gemini-3.6-flash:streamGenerateContent?alt=sse", &b), Some(Format::Gemini));
}

#[test]
fn detect_unknown_header_value_falls_back_to_path() {
    assert_eq!(Format::detect(Some("cohere"), "/x/v1/chat/completions", &json!({})), Some(Format::OpenAiChat));
    assert_eq!(Format::detect(Some("cohere"), "/x/v2/chat", &json!({"messages": []})), None);
}

#[test]
fn detect_falls_back_to_unambiguous_body_shape() {
    assert_eq!(Format::detect(None, "/x/y", &json!({"contents":[]})), Some(Format::Gemini));
    assert_eq!(Format::detect(None, "/x/y", &json!({"input":"x"})), Some(Format::OpenAiResponses));
}

#[test]
fn detect_ambiguous_body_is_none() {
    assert_eq!(Format::detect(None, "/x/y", &json!({"messages":[]})), None);
    assert_eq!(Format::detect(None, "/x/y", &json!({"input":"x","messages":[]})), None);
    assert_eq!(Format::detect(None, "/x/embeddings", &json!({"model":"m"})), None);
}

#[test]
fn format_names_are_stable() {
    assert_eq!(Format::OpenAiChat.name(), "openai_chat");
    assert_eq!(Format::OpenAiResponses.name(), "openai_responses");
    assert_eq!(Format::AnthropicMessages.name(), "anthropic_messages");
    assert_eq!(Format::Gemini.name(), "gemini");
}

// ---- streaming flag and model ----------------------------------------------------------------------------------

#[test]
fn streamed_flags() {
    let on = json!({"stream": true});
    let off = json!({"stream": false});
    assert!(is_streamed(Format::OpenAiChat, "/openai/chat/completions", &on));
    assert!(!is_streamed(Format::OpenAiChat, "/openai/chat/completions", &off));
    assert!(is_streamed(Format::OpenAiResponses, "/openai/responses", &on));
    assert!(is_streamed(Format::AnthropicMessages, "/claude/v1/messages", &on));
    assert!(!is_streamed(Format::AnthropicMessages, "/claude/v1/messages", &json!({})));
    assert!(is_streamed(Format::Gemini, "/gemini/models/m:streamGenerateContent?alt=sse", &json!({})));
    assert!(!is_streamed(Format::Gemini, "/gemini/models/m:generateContent", &on));
}

#[test]
fn gemini_model_from_path() {
    let path = "/gemini/models/gemini-3.6-flash:generateContent";
    assert_eq!(requested_model(Format::Gemini, path, &json!({})).as_deref(), Some("gemini-3.6-flash"));
    let streamed = "/gemini/models/gemini-3.6-flash:streamGenerateContent?alt=sse";
    assert_eq!(requested_model(Format::Gemini, streamed, &json!({})).as_deref(), Some("gemini-3.6-flash"));
}

#[test]
fn model_from_body() {
    let b = fixture("s02_openai_chat.json");
    assert_eq!(requested_model(Format::OpenAiChat, "/openai/chat/completions", &b).as_deref(), Some("openai/gpt-6-luna"));
    assert_eq!(requested_model(Format::AnthropicMessages, "/x", &json!({})), None);
}

// ---- OpenAI Chat Completions ----------------------------------------------------------------------------------

#[test]
fn openai_every_user_turn_by_default() {
    // s03 Task 12: the caller writes the whole history, so an earlier user turn is no more trusted than the newest.
    let b = json!({"messages":[{"role":"user","content":"first"},
        {"role":"assistant","content":"a"},{"role":"user","content":"second"}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "first\n\nsecond");
    assert_eq!(e.slot, Slot::Fields(vec![field("/messages/0/content", 5), field("/messages/2/content", 6)]));
    assert!(!e.truncated);
}

#[test]
fn every_user_turn_in_every_format() {
    let roles = RoleSet::user_only();
    let responses = json!({"input":[{"role":"user","content":"first"},{"role":"assistant","content":"a"},
        {"role":"user","content":"second"}]});
    assert_eq!(text(Format::OpenAiResponses, &responses, &roles), "first\n\nsecond");
    let anthropic = json!({"messages":[{"role":"user","content":"first"},{"role":"assistant","content":"a"},
        {"role":"user","content":"second"}]});
    assert_eq!(text(Format::AnthropicMessages, &anthropic, &roles), "first\n\nsecond");
    let gemini = json!({"contents":[{"role":"user","parts":[{"text":"first"}]},{"role":"model","parts":[{"text":"a"}]},
        {"role":"user","parts":[{"text":"second"}]}]});
    assert_eq!(text(Format::Gemini, &gemini, &roles), "first\n\nsecond");
}

#[test]
fn openai_every_text_part() {
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"text","text":"a"},
        {"type":"image_url","image_url":{"url":"https://example.com/cat.png"}},
        {"type":"text","text":"b"}]}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_in_order(&e.text, &["a", "https://example.com/cat.png", "b"]);
    assert_eq!(e.slot, Slot::Multi, "a serialized part has no field to write masked text back to");
}

#[test]
fn openai_single_text_part_has_its_own_slot() {
    let b = json!({"messages":[{"role":"user","content":[{"type":"text","text":"only"}]}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.slot, Slot::Single("/messages/0/content/0/text".into()));
}

#[test]
fn openai_no_text_turn_is_serialized() {
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}]}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert!(e.text.contains("image_url"), "{}", e.text);
    assert_eq!(e.slot, Slot::Multi);
}

#[test]
fn openai_tool_role_added_when_configured() {
    let b = fixture("openai_agent_loop.json");
    assert_eq!(text(Format::OpenAiChat, &b, &RoleSet::user_only()), "What is the weather in Paris?\n\nAnd tomorrow?");
    let with_tool = text(Format::OpenAiChat, &b, &RoleSet::user_only().with(Role::Tool));
    assert_eq!(with_tool, "What is the weather in Paris?\n\nSunny, 21C\n\nAnd tomorrow?");
}

#[test]
fn openai_all_roles_in_conversation_order() {
    let b = fixture("openai_agent_loop.json");
    let t = text(Format::OpenAiChat, &b, &all_roles());
    assert_in_order(&t, &["You are a weather bot.", "What is the weather in Paris?", "get_weather", "{\"city\":\"Paris\"}",
        "Sunny, 21C", "And tomorrow?"]);
}

#[test]
fn openai_developer_counts_as_system() {
    let b = json!({"messages":[{"role":"developer","content":"Be terse."},{"role":"user","content":"hi"}]});
    assert_eq!(text(Format::OpenAiChat, &b, &RoleSet::user_only().with(Role::System)), "Be terse.\n\nhi");
}

// ---- OpenAI Responses -------------------------------------------------------------------------------------------

#[test]
fn responses_input_string() {
    let b = fixture("s02_openai_responses.json");
    let e = prompt_text(Format::OpenAiResponses, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "Reply with the single word: ready");
    assert_eq!(e.slot, Slot::Single("/input".into()));
}

#[test]
fn responses_input_items() {
    let b = fixture("responses_agent_loop.json");
    let e = prompt_text(Format::OpenAiResponses, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "What is the weather in Paris?");
    assert_eq!(e.slot, Slot::Single("/input/0/content/0/text".into()));
    let with_tool = text(Format::OpenAiResponses, &b, &RoleSet::user_only().with(Role::Tool));
    assert_eq!(with_tool, "What is the weather in Paris?\n\nSunny, 21C");
    let all = text(Format::OpenAiResponses, &b, &all_roles());
    assert!(all.starts_with("You are a weather bot."), "instructions come first: {all:?}");
    assert!(all.contains("get_weather") && all.contains("Sunny, 21C"), "{all:?}");
}

// ---- Anthropic Messages -----------------------------------------------------------------------------------------

#[test]
fn anthropic_system_blocks_with_system_role() {
    let b = fixture("anthropic_agent_loop.json");
    let t = text(Format::AnthropicMessages, &b, &RoleSet::user_only().with(Role::System));
    assert_eq!(t, "You are a weather bot.\n\nWhat is the weather in Paris?");
    let plain = json!({"system": "Be terse.", "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(text(Format::AnthropicMessages, &plain, &RoleSet::user_only().with(Role::System)), "Be terse.\n\nhi");
}

#[test]
fn anthropic_tool_result_only_message_is_a_tool_turn() {
    let b = fixture("anthropic_agent_loop.json");
    let e = prompt_text(Format::AnthropicMessages, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "What is the weather in Paris?");
    assert_eq!(e.slot, Slot::Single("/messages/0/content".into()));
    let with_tool = text(Format::AnthropicMessages, &b, &RoleSet::user_only().with(Role::Tool));
    assert_eq!(with_tool, "What is the weather in Paris?\n\nSunny, 21C");
}

#[test]
fn anthropic_assistant_tool_use_input_is_scanned_with_assistant_role() {
    let b = fixture("anthropic_agent_loop.json");
    let t = text(Format::AnthropicMessages, &b, &RoleSet::user_only().with(Role::Assistant));
    assert!(t.contains("Let me check.") && t.contains("get_weather") && t.contains("Paris"), "{t:?}");
}

#[test]
fn anthropic_tool_result_blocks_inside_content() {
    let b = json!({"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t",
        "content":[{"type":"text","text":"from the tool"}]}, {"type":"text","text":"now summarise"}]}]});
    assert_eq!(text(Format::AnthropicMessages, &b, &RoleSet::user_only()), "now summarise");
    assert_eq!(text(Format::AnthropicMessages, &b, &RoleSet::user_only().with(Role::Tool)), "from the tool\n\nnow summarise");
}

// ---- Gemini -----------------------------------------------------------------------------------------------------

#[test]
fn gemini_contents_and_system_instruction() {
    let b = fixture("gemini_agent_loop.json");
    let e = prompt_text(Format::Gemini, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "What is the weather in Paris?");
    assert_eq!(e.slot, Slot::Single("/contents/0/parts/0/text".into()));
    let t = text(Format::Gemini, &b, &all_roles());
    assert!(t.starts_with("You are a weather bot."), "{t:?}");
    assert!(t.contains("get_weather") && t.contains("Sunny, 21C"), "{t:?}");
    let snake = json!({"system_instruction": {"parts": [{"text": "Be terse."}]},
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    assert_eq!(text(Format::Gemini, &snake, &RoleSet::user_only().with(Role::System)), "Be terse.\n\nhi");
}

#[test]
fn gemini_function_response_only_content_is_a_tool_turn() {
    let b = fixture("gemini_agent_loop.json");
    assert_eq!(text(Format::Gemini, &b, &RoleSet::user_only().with(Role::Tool)), "What is the weather in Paris?\n\n{\"result\":\"Sunny, 21C\"}");
}

#[test]
fn gemini_content_without_role_is_user() {
    let b = json!({"contents": [{"parts": [{"text": "hello"}]}]});
    assert_eq!(text(Format::Gemini, &b, &RoleSet::user_only()), "hello");
}

// ---- the s02 request bodies -------------------------------------------------------------------------------------

#[test]
fn s02_bodies_extract_the_prompt() {
    let cases = [
        (Format::AnthropicMessages, "s02_anthropic.json"),
        (Format::OpenAiChat, "s02_openai_chat.json"),
        (Format::OpenAiResponses, "s02_openai_responses.json"),
        (Format::Gemini, "s02_gemini.json"),
    ];
    for (format, name) in cases {
        assert_eq!(text(format, &fixture(name), &RoleSet::user_only()), "Reply with the single word: ready", "{name}");
    }
}

// ---- limits and errors ------------------------------------------------------------------------------------------

#[test]
fn truncation_counts_chars() {
    let long: String = "é".repeat(25_000);
    let b = json!({"messages":[{"role":"user","content": long}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20_000).unwrap();
    assert!(e.truncated);
    assert_eq!(e.text.chars().count(), 20_000);
    assert_eq!(e.slot, Slot::Multi, "masked text of a truncated scan must never overwrite the whole field");
}

#[test]
fn exactly_the_cap_is_not_truncated() {
    let b = json!({"messages":[{"role":"user","content": "a".repeat(100)}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 100).unwrap();
    assert!(!e.truncated);
}

#[test]
fn no_messages_is_no_content() {
    assert_eq!(prompt_text(Format::OpenAiChat, &json!({"model":"m"}), &RoleSet::user_only(), 20000).unwrap_err(), ExtractError::NoContent);
    assert_eq!(prompt_text(Format::Gemini, &json!({"contents": []}), &RoleSet::user_only(), 20000).unwrap_err(), ExtractError::NoContent);
}

#[test]
fn empty_user_text_is_no_content() {
    let b = json!({"messages":[{"role":"user","content":""}]});
    assert_eq!(prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap_err(), ExtractError::NoContent);
}

#[test]
fn wrong_shapes_are_unreadable() {
    let roles = RoleSet::user_only();
    assert!(matches!(prompt_text(Format::OpenAiChat, &json!({"messages": "hi"}), &roles, 20000), Err(ExtractError::Unreadable(_))));
    assert!(matches!(prompt_text(Format::AnthropicMessages, &json!({"messages": [{"role": "user", "content": 5}]}), &roles, 20000), Err(ExtractError::Unreadable(_))));
    assert!(matches!(prompt_text(Format::Gemini, &json!({"contents": {"parts": []}}), &roles, 20000), Err(ExtractError::Unreadable(_))));
    assert!(matches!(prompt_text(Format::OpenAiChat, &json!([1, 2]), &roles, 20000), Err(ExtractError::Unreadable(_))));
}

// ---- s03 Task 12: non-text parts, the newest text first to go, masked text written back --------------------------

#[test]
fn anthropic_text_document_next_to_text_is_scanned() {
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"document","source":{"type":"text","media_type":"text/plain","data":"DOCTEXT"},"title":"TITLE","context":"CTX"},
        {"type":"text","text":"ask"}]}]});
    let t = text(Format::AnthropicMessages, &b, &RoleSet::user_only());
    for s in ["DOCTEXT", "TITLE", "CTX", "ask"] {
        assert!(t.contains(s), "{s} missing: {t:?}");
    }
}

#[test]
fn anthropic_content_document_and_search_result_are_scanned() {
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"document","source":{"type":"content","content":[{"type":"text","text":"PART1"},{"type":"text","text":"PART2"}]}},
        {"type":"search_result","source":"https://example.com/r","title":"RT","content":[{"type":"text","text":"RESULT"}]},
        {"type":"text","text":"ask"}]}]});
    let t = text(Format::AnthropicMessages, &b, &RoleSet::user_only());
    for s in ["PART1", "PART2", "https://example.com/r", "RT", "RESULT", "ask"] {
        assert!(t.contains(s), "{s} missing: {t:?}");
    }
}

#[test]
fn gemini_inline_text_data_is_decoded_and_scanned() {
    // "RE9DVEVYVA==" is base64 for DOCTEXT.
    let b = json!({"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"text/plain","data":"RE9DVEVYVA=="}},{"text":"ask"}]}]});
    let t = text(Format::Gemini, &b, &RoleSet::user_only());
    assert!(t.contains("DOCTEXT") && t.contains("ask"), "{t:?}");
}

#[test]
fn non_text_parts_are_scanned_without_their_bytes() {
    let png = "iVBORw0KGgoAAAANSUhEUgAA".repeat(20);
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"text","text":"ask"},
        {"type":"image_url","image_url":{"url":"https://example.com/cat.png"}},
        {"type":"image_url","image_url":{"url": format!("data:image/png;base64,{png}")}},
        {"type":"future_part","note":"FUTURE"}]}]});
    let t = text(Format::OpenAiChat, &b, &RoleSet::user_only());
    assert!(t.contains("ask") && t.contains("https://example.com/cat.png") && t.contains("FUTURE"), "{t:?}");
    assert!(!t.contains(&png[..48]), "binary payloads are not scanned: {t:?}");
    let image = json!({"messages":[{"role":"user","content":[{"type":"text","text":"ask"},
        {"type":"image","source":{"type":"base64","media_type":"image/png","data": png.clone()}}]}]});
    let t = text(Format::AnthropicMessages, &image, &RoleSet::user_only());
    assert!(t.contains("ask") && t.contains("image/png") && !t.contains(&png[..48]), "{t:?}");
}

#[test]
fn prompt_over_the_limit_keeps_the_newest_text() {
    let b = json!({"messages":[{"role":"user","content":"a".repeat(30)},{"role":"user","content":"NEWEST"}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 10).unwrap();
    assert!(e.truncated);
    assert!(e.text.ends_with("NEWEST"), "{:?}", e.text);
    assert_eq!(e.text.chars().count(), 10);
    assert_eq!(e.slot, Slot::Multi);
}

#[test]
fn masked_text_is_written_back_to_every_field() {
    let body = json!({"messages":[{"role":"user","content":"card 1234"},{"role":"assistant","content":"ok"},
        {"role":"user","content":"and 5678"}]});
    let e = prompt_text(Format::OpenAiChat, &body, &RoleSet::user_only(), 20000).unwrap();
    let bytes = serde_json::to_vec(&body).unwrap();
    let out = write_back(&bytes, &e.slot, "card XXXX\n\nand XXXX").expect("same length: written back");
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["messages"][0]["content"], "card XXXX");
    assert_eq!(v["messages"][1]["content"], "ok");
    assert_eq!(v["messages"][2]["content"], "and XXXX");
}

#[test]
fn masked_text_that_does_not_line_up_is_not_written_back() {
    let body = json!({"messages":[{"role":"user","content":"card 1234"},{"role":"user","content":"and 5678"}]});
    let e = prompt_text(Format::OpenAiChat, &body, &RoleSet::user_only(), 20000).unwrap();
    let bytes = serde_json::to_vec(&body).unwrap();
    assert_eq!(write_back(&bytes, &e.slot, "card [MASKED]\n\nand XXXX"), None, "another length");
    assert_eq!(write_back(&bytes, &e.slot, "card XXXX  and XXXX"), None, "the separator was changed");
    assert_eq!(write_back(&bytes, &Slot::Multi, "card XXXX\n\nand XXXX"), None);
}

#[test]
fn single_field_masked_text_is_written_back() {
    let body = json!({"messages":[{"role":"user","content":"card 1234"}]});
    let e = prompt_text(Format::OpenAiChat, &body, &RoleSet::user_only(), 20000).unwrap();
    let out = write_back(&serde_json::to_vec(&body).unwrap(), &e.slot, "card XXXX").unwrap();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["messages"][0]["content"], "card XXXX");
}

#[test]
fn a_data_uri_part_is_scanned_as_the_text_it_carries() {
    let notes = encode64(format!("BLOCKME notes {}", "pad ".repeat(70)).as_bytes());
    let b = json!({"messages":[{"role":"user","content":[{"type":"text","text":"ask"},
        {"type":"file","file":{"filename":"notes.txt","file_data": format!("data:text/plain;base64,{notes}")}},
        {"type":"image_url","image_url":{"url": format!("data:text/plain,{}BLOCKME cleartext", "pad ".repeat(70))}}]}]});
    let t = text(Format::OpenAiChat, &b, &RoleSet::user_only());
    assert!(t.contains("BLOCKME notes") && t.contains("BLOCKME cleartext"), "{t:?}");
}

// ---- the phase-2 gate: a provider's inline payload is read as the bytes it declares -------------------------------

#[test]
fn a_gemini_audio_part_with_no_file_header_is_left_out() {
    let data = encode64(&pcm(48_000));
    let b = json!({"contents": [{"role": "user", "parts": [{"text": "transcribe this"},
        {"inlineData": {"mimeType": "audio/L16;codec=pcm;rate=24000", "data": data.clone()}}]}]});
    let e = prompt_text(Format::Gemini, &b, &RoleSet::user_only(), 100_000).unwrap();
    assert!(!e.truncated, "the audio's bytes are not counted");
    assert!(e.text.contains("transcribe this") && e.text.contains("audio/L16") && !e.text.contains(&data[..48]));
}

#[test]
fn a_gemini_inline_code_file_is_scanned_as_its_text() {
    let script = format!("// BLOCKME notes\n{}", "console.log('pad');\n".repeat(20));
    for mime in ["application/x-javascript", "application/x-sh"] {
        let b = json!({"contents": [{"role": "user", "parts": [{"text": "review this file"},
            {"inlineData": {"mimeType": mime, "data": encode64(script.as_bytes())}}]}]});
        let t = text(Format::Gemini, &b, &RoleSet::user_only());
        assert!(t.contains("BLOCKME notes"), "{mime}: {t:?}");
    }
}

#[test]
fn an_inline_text_file_that_is_not_utf8_is_scanned() {
    // Latin-1: the é of "café" is the single byte 0xe9, so the bytes are not UTF-8.
    let mut latin1 = b"name,note\ncaf\xe9,BLOCKME notes\n".to_vec();
    latin1.extend(b"row,pad\n".repeat(40));
    let data = encode64(&latin1);
    let gemini = json!({"contents": [{"role": "user", "parts": [{"text": "read this"},
        {"inlineData": {"mimeType": "text/csv", "data": data.clone()}}]}]});
    let t = text(Format::Gemini, &gemini, &RoleSet::user_only());
    assert!(t.contains("BLOCKME notes"), "Gemini: {t:?}");
    let anthropic = json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "read this"},
        {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": data}}]}]});
    let t = text(Format::AnthropicMessages, &anthropic, &RoleSet::user_only());
    assert!(t.contains("BLOCKME notes"), "Anthropic: {t:?}");
}
