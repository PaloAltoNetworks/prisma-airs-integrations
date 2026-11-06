use prisma_airs_core::extract::request::prompt_text;
use prisma_airs_core::extract::{ExtractError, Slot};
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
fn openai_newest_user_turn_only_by_default() {
    let b = json!({"messages":[{"role":"user","content":"first"},
        {"role":"assistant","content":"a"},{"role":"user","content":"second"}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "second");
    assert_eq!(e.slot, Slot::Single("/messages/2/content".into()));
    assert!(!e.truncated);
}

#[test]
fn openai_every_text_part() {
    let b = json!({"messages":[{"role":"user","content":[
        {"type":"text","text":"a"},
        {"type":"image_url","image_url":{"url":"https://example.com/cat.png"}},
        {"type":"text","text":"b"}]}]});
    let e = prompt_text(Format::OpenAiChat, &b, &RoleSet::user_only(), 20000).unwrap();
    assert_eq!(e.text, "a\n\nb");
    assert_eq!(e.slot, Slot::Multi);
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
    assert_eq!(text(Format::OpenAiChat, &b, &RoleSet::user_only()), "And tomorrow?");
    let with_tool = text(Format::OpenAiChat, &b, &RoleSet::user_only().with(Role::Tool));
    assert_eq!(with_tool, "Sunny, 21C\n\nAnd tomorrow?");
}

#[test]
fn openai_all_roles_in_conversation_order() {
    let b = fixture("openai_agent_loop.json");
    let t = text(Format::OpenAiChat, &b, &all_roles());
    let order = ["You are a weather bot.", "get_weather", "{\"city\":\"Paris\"}", "Sunny, 21C", "And tomorrow?"];
    let mut at = 0;
    for piece in order {
        let found = t[at..].find(piece).unwrap_or_else(|| panic!("{piece:?} missing or out of order in {t:?}"));
        at += found + piece.len();
    }
    assert!(!t.contains("What is the weather in Paris?"), "an older user turn is not the newest one: {t:?}");
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
