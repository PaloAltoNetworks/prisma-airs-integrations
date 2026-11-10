use prisma_airs_core::airs::Leg;
use prisma_airs_core::decision::BlockKind;
use prisma_airs_core::errors::{client_error, mcp_refusal, stream_refusal};
use prisma_airs_core::format::Format;
use serde_json::{json, Value};

fn body(format: Option<Format>, leg: Leg, status: u16, kind: BlockKind, scan_id: Option<&str>, cats: Option<&[String]>) -> Value {
    let (content_type, bytes) = client_error(format, leg, status, kind, scan_id, cats);
    assert_eq!(content_type, "application/json");
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn error_bodies_exact_per_format() {
    assert_eq!(
        body(Some(Format::OpenAiChat), Leg::Prompt, 403, BlockKind::Policy, Some("abc"), None),
        json!({"error":{"message":"Request blocked by Prisma AIRS security policy. Scan ID: abc.",
            "type":"prisma_airs_blocked","param":null,"code":"prisma_airs_blocked"}})
    );
    assert_eq!(
        body(Some(Format::AnthropicMessages), Leg::Response, 503, BlockKind::Scanner, None, None),
        json!({"type":"error","error":{"type":"api_error",
            "message":"Prisma AIRS could not scan this response, so it was withheld."}})
    );
    assert_eq!(
        body(Some(Format::Gemini), Leg::Prompt, 403, BlockKind::Gap, None, None),
        json!({"error":{"code":403,"status":"PERMISSION_DENIED",
            "message":"Prisma AIRS could not inspect this request, so it was not forwarded."}})
    );
}

#[test]
fn other_formats_and_legs() {
    let r = body(Some(Format::OpenAiResponses), Leg::Response, 403, BlockKind::Policy, Some("s1"), None);
    assert_eq!(r["error"]["message"], "Response blocked by Prisma AIRS security policy. Scan ID: s1.");
    let a = body(Some(Format::AnthropicMessages), Leg::Prompt, 403, BlockKind::Policy, None, None);
    assert_eq!(a["error"]["type"], "permission_error");
    assert_eq!(a["error"]["message"], "Request blocked by Prisma AIRS security policy.");
    let g = body(Some(Format::Gemini), Leg::Response, 503, BlockKind::Scanner, None, None);
    assert_eq!(g["error"]["status"], "UNAVAILABLE");
    assert_eq!(g["error"]["code"], 503);
    let gap = body(Some(Format::OpenAiChat), Leg::Response, 403, BlockKind::Gap, None, None);
    assert_eq!(gap["error"]["message"], "Prisma AIRS could not inspect this response, so it was withheld.");
    let unavailable = body(Some(Format::OpenAiChat), Leg::Prompt, 503, BlockKind::Scanner, None, None);
    assert_eq!(unavailable["error"]["message"], "Prisma AIRS could not scan this request, so it was not forwarded.");
    assert_eq!(unavailable["error"]["type"], "prisma_airs_unavailable");
}

#[test]
fn unknown_format_gets_the_openai_shape() {
    let v = body(None, Leg::Prompt, 403, BlockKind::Gap, None, None);
    assert_eq!(v["error"]["type"], "prisma_airs_blocked");
}

#[test]
fn dlp_on_stream_reads_as_a_policy_block() {
    let v = body(Some(Format::OpenAiChat), Leg::Response, 403, BlockKind::DlpOnStream, Some("s2"), None);
    assert_eq!(v["error"]["message"], "Response blocked by Prisma AIRS security policy. Scan ID: s2.");
}

#[test]
fn categories_hidden_by_default() {
    let hidden = body(Some(Format::OpenAiChat), Leg::Prompt, 403, BlockKind::Policy, Some("abc"), None);
    assert!(!hidden.to_string().contains("injection"));
    let cats = vec!["injection".to_string(), "agent".to_string()];
    let shown = body(Some(Format::OpenAiChat), Leg::Prompt, 403, BlockKind::Policy, Some("abc"), Some(&cats));
    assert_eq!(shown["error"]["message"], "Request blocked by Prisma AIRS security policy. Scan ID: abc. Detected: injection, agent.");
}

#[test]
fn bodies_never_contain_the_key() {
    // The error builder never receives the key; every body is checked anyway.
    for format in [None, Some(Format::OpenAiChat), Some(Format::OpenAiResponses), Some(Format::AnthropicMessages), Some(Format::Gemini)] {
        for leg in [Leg::Prompt, Leg::Response] {
            for (status, kind) in [(403, BlockKind::Policy), (403, BlockKind::Gap), (403, BlockKind::DlpOnStream), (503, BlockKind::Scanner)] {
                let (_, bytes) = client_error(format, leg, status, kind, Some("id"), None);
                assert!(!String::from_utf8(bytes).unwrap().contains("SECRET-123"));
            }
        }
    }
}

#[test]
fn rejected_configuration_has_its_own_message() {
    // On a managed gateway the policy's error line is not visible, so the reply says what is wrong.
    for format in [None, Some(Format::OpenAiChat), Some(Format::AnthropicMessages), Some(Format::Gemini)] {
        let (_, body) = client_error(format, Leg::Prompt, 503, BlockKind::Config, None, None);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("Prisma AIRS Guardrails is not configured correctly"), "{format:?}: {text}");
        assert!(!text.contains("could not scan"), "{format:?}: {text}");
    }
}

// ---- MCP: JSON-RPC refusals --------------------------------------------------------------------------------------

fn parsed(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn mcp_refusal_answers_each_id() {
    let (status, content_type, b) = mcp_refusal(&[json!(7)], false, Leg::Prompt, BlockKind::Policy, Some("scan-1"), None);
    assert_eq!(status, 200);
    assert_eq!(content_type, "application/json");
    let v = parsed(&b);
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32001);
    assert_eq!(v["error"]["message"], "Request blocked by Prisma AIRS security policy. Scan ID: scan-1.");

    let (_, _, b) = mcp_refusal(&[json!("abc")], false, Leg::Response, BlockKind::Policy, None, None);
    let v = parsed(&b);
    assert_eq!(v["id"], "abc", "a string id stays a string");
    assert_eq!(v["error"]["message"], "Response blocked by Prisma AIRS security policy.");
}

#[test]
fn mcp_refusal_for_a_batch_is_an_array() {
    let (status, _, b) = mcp_refusal(&[json!(1), json!(2)], true, Leg::Prompt, BlockKind::Gap, None, None);
    assert_eq!(status, 200);
    let v = parsed(&b);
    let items = v.as_array().expect("a batch gets an array of errors");
    assert_eq!(items.len(), 2);
    assert_eq!((items[0]["id"].clone(), items[1]["id"].clone()), (json!(1), json!(2)));
    for e in items {
        assert_eq!(e["error"]["code"], -32001);
        assert_eq!(e["error"]["message"], "Prisma AIRS could not inspect this request, so it was not forwarded.");
    }
}

#[test]
fn mcp_refusal_without_an_id_uses_null() {
    let (status, _, b) = mcp_refusal(&[], false, Leg::Prompt, BlockKind::Policy, None, None);
    assert_eq!(status, 403);
    let v = parsed(&b);
    assert!(v.as_object().unwrap().contains_key("id") && v["id"].is_null(), "JSON-RPC needs the id member, null when unknown");
    let (status, _, b) = mcp_refusal(&[], true, Leg::Prompt, BlockKind::Policy, None, None);
    assert_eq!(status, 403);
    assert!(parsed(&b).is_object(), "nothing to answer member by member: one error object");
}

#[test]
fn scanner_failure_is_minus_32003() {
    let (status, _, b) = mcp_refusal(&[json!(1)], false, Leg::Prompt, BlockKind::Scanner, None, None);
    assert_eq!(status, 200);
    let v = parsed(&b);
    assert_eq!(v["error"]["code"], -32003);
    assert_eq!(v["error"]["message"], "Prisma AIRS could not scan this request, so it was not forwarded.");
    let (_, _, c) = mcp_refusal(&[json!(1)], false, Leg::Prompt, BlockKind::Config, None, None);
    assert_eq!(parsed(&c)["error"]["code"], -32003, "a rejected configuration is unavailable, not a block");
}

#[test]
fn the_refusal_status_follows_r2() {
    for kind in [BlockKind::Policy, BlockKind::Gap, BlockKind::Scanner, BlockKind::DlpOnStream, BlockKind::Config] {
        assert_eq!(mcp_refusal(&[json!(1)], false, Leg::Prompt, kind, None, None).0, 200, "{kind:?}");
        assert_eq!(mcp_refusal(&[json!(1), json!(2)], true, Leg::Response, kind, None, None).0, 200, "{kind:?}");
    }
    assert_eq!(mcp_refusal(&[], false, Leg::Prompt, BlockKind::Policy, None, None).0, 403);
    assert_eq!(mcp_refusal(&[], false, Leg::Prompt, BlockKind::Gap, None, None).0, 403);
    assert_eq!(mcp_refusal(&[], false, Leg::Prompt, BlockKind::Scanner, None, None).0, 503);
}

#[test]
fn mcp_refusal_shows_categories_only_when_asked() {
    let cats = vec!["tool_input.injection".to_string()];
    let (_, _, b) = mcp_refusal(&[json!(1)], false, Leg::Prompt, BlockKind::Policy, Some("s-1"), Some(&cats));
    let message = parsed(&b)["error"]["message"].as_str().unwrap().to_string();
    assert!(message.ends_with("Scan ID: s-1. Detected: tool_input.injection."), "{message}");
    let (_, _, b) = mcp_refusal(&[json!(1)], false, Leg::Prompt, BlockKind::Policy, Some("s-1"), None);
    assert!(!parsed(&b)["error"]["message"].as_str().unwrap().contains("Detected"));
}

#[test]
fn stream_refusal_says_what_to_do() {
    let (status, content_type, b) = stream_refusal();
    assert_eq!(status, 405);
    assert_eq!(content_type, "application/json");
    let v = parsed(&b);
    assert!(v["id"].is_null());
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("event stream") && message.contains("POST"), "{message}");
}
