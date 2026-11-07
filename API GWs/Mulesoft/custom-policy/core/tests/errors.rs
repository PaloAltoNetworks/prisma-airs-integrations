use prisma_airs_core::airs::Leg;
use prisma_airs_core::decision::BlockKind;
use prisma_airs_core::errors::client_error;
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
    // s03 Task 12: on a managed gateway the policy's error line is not visible, so the reply says what is wrong.
    for format in [None, Some(Format::OpenAiChat), Some(Format::AnthropicMessages), Some(Format::Gemini)] {
        let (_, body) = client_error(format, Leg::Prompt, 503, BlockKind::Config, None, None);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("Prisma AIRS Guardrails is not configured correctly"), "{format:?}: {text}");
        assert!(!text.contains("could not scan"), "{format:?}: {text}");
    }
}
