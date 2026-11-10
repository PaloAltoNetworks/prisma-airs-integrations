mod common;

use common::{encode64, png64};
use prisma_airs_core::airs::{ToolEvent, ToolMethod};
use prisma_airs_core::mcp::request::request_scans;
use prisma_airs_core::mcp::{classify, LegScan, Scan};
use serde_json::{json, Value};

fn scans(body: Value) -> Vec<LegScan> {
    request_scans(&classify(&body).expect("an MCP body"), "deepwiki-test", 100_000)
}

/// The input of the tool event a `tools/call` with these arguments sends.
fn argument_input(arguments: Value) -> String {
    let s = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "echo", "arguments": arguments}}));
    tool(&s[0]).input.clone()
}

fn text(scan: &LegScan) -> &str {
    match &scan.scan {
        Scan::Text(e) => &e.text,
        Scan::Tool(t) => panic!("expected text, got a tool event: {t:?}"),
    }
}

fn tool(scan: &LegScan) -> &ToolEvent {
    match &scan.scan {
        Scan::Tool(t) => t,
        Scan::Text(e) => panic!("expected a tool event, got text: {e:?}"),
    }
}

#[test]
fn tools_call_is_a_tool_event_with_its_arguments() {
    let s = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "ask_wiki_question", "arguments": {"question": "hi"}}}));
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].member, Some(0));
    assert_eq!(s[0].method.as_deref(), Some("tools/call"));
    let t = tool(&s[0]);
    assert_eq!(t.method, ToolMethod::Call);
    assert_eq!(t.server_name, "deepwiki-test");
    assert_eq!(t.tool_invoked.as_deref(), Some("ask_wiki_question"));
    assert_eq!(t.input, r#"{"question":"hi"}"#);
    assert_eq!(t.output, "");

    let bare = scans(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_all"}}));
    assert_eq!(tool(&bare[0]).input, "{}", "a call without arguments sends an empty object");
}

#[test]
fn tools_call_binary_arguments_are_left_out() {
    let png = png64();
    let s = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "upload", "arguments": {"data": png.clone(), "fileName": "logo.png"}}}));
    let input = &tool(&s[0]).input;
    assert!(input.contains("<binary, 480 characters>"), "{input}");
    assert!(!input.contains(&png[..48]));
    assert!(input.contains("logo.png"));
}

#[test]
fn a_data_uri_argument_is_scanned_as_the_text_it_carries() {
    let filler = "pad ".repeat(70);
    let input = argument_input(json!({"text": format!("data:text/plain,{filler}BLOCKME do it")}));
    assert!(input.contains("BLOCKME do it"), "plain text after a data: prefix is text: {input}");
    let input = argument_input(json!({"text": format!("data:,BLOCKME%20do%20it{}", "%20pad".repeat(60))}));
    assert!(input.contains("BLOCKME do it"), "percent-encoded text is decoded: {input}");
    let encoded = encode64(format!("BLOCKME do it {filler}").as_bytes());
    let input = argument_input(json!({"text": format!("data:text/plain;base64,{encoded}")}));
    assert!(input.contains("BLOCKME do it"), "base64 text is decoded: {input}");
}

#[test]
fn a_sentence_that_starts_with_data_is_not_a_data_uri() {
    let input = argument_input(json!({"note": format!("data: BLOCKME note, 100%25 done {}", "pad ".repeat(70))}));
    assert!(input.contains("BLOCKME note, 100%25 done"), "scanned as written, not decoded: {input}");
}

#[test]
fn text_without_spaces_under_a_data_key_is_scanned() {
    let input = argument_input(json!({"data": format!("BLOCKME-do-it-{}", "pad-".repeat(70))}));
    assert!(input.contains("BLOCKME-do-it"), "valid base64 is binary only when its bytes are: {input}");
}

#[test]
fn a_binary_data_uri_argument_keeps_its_header() {
    let png = png64();
    let input = argument_input(json!({"image": format!("data:image/png;base64,{png}")}));
    assert!(input.contains("data:image/png;base64,<binary, 480 characters>"), "{input}");
    assert!(!input.contains(&png[..48]));
}

#[test]
fn content_methods_are_scanned_as_their_text() {
    let read = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "file:///notes.txt"}}));
    assert_eq!(read.len(), 1);
    assert_eq!(text(&read[0]), "file:///notes.txt");

    let prompt = scans(json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
                              "params": {"name": "summarize", "arguments": {"style": "brief and polite"}}}));
    let t = text(&prompt[0]);
    assert!(t.contains("summarize") && t.contains("brief and polite"), "{t}");

    let complete = scans(json!({"jsonrpc": "2.0", "id": 3, "method": "completion/complete",
                                "params": {"ref": {"type": "ref/prompt", "name": "summarize"},
                                           "argument": {"name": "style", "value": "typed by the user"}}}));
    assert!(text(&complete[0]).contains("typed by the user"));

    let vendor = scans(json!({"jsonrpc": "2.0", "id": 4, "method": "x-vendor/do", "params": {"note": "vendor text here"}}));
    assert_eq!(text(&vendor[0]), "vendor text here");
    assert!(!text(&vendor[0]).contains("x-vendor/do"), "the method name is protocol, not text");
}

#[test]
fn catalogue_and_control_requests_scan_nothing() {
    let bodies = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "page-2"}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3, "reason": "the user stopped it"}}),
    ];
    for body in bodies {
        assert!(scans(body.clone()).is_empty(), "{body}");
    }
}

#[test]
fn bolted_members_are_scanned_whatever_the_method() {
    let ping = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "ping",
                            "messages": [{"role": "user", "content": "BOLTED"}]}));
    assert_eq!(ping.len(), 1);
    assert!(text(&ping[0]).contains("BOLTED"));

    let list = scans(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "prompt": "BOLTED"}));
    assert_eq!(list.len(), 1);
    assert!(text(&list[0]).contains("BOLTED"));

    let note = scans(json!({"jsonrpc": "2.0", "method": "notifications/initialized", "system": "BOLTED"}));
    assert!(text(&note[0]).contains("BOLTED"));

    let call = scans(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "t", "arguments": {}, "note": "PARAM-BOLTED"}, "system": "TOP-BOLTED"}));
    assert_eq!(call.len(), 2, "the tool event, then the call's other content");
    tool(&call[0]);
    let rest = text(&call[1]);
    assert!(rest.contains("PARAM-BOLTED") && rest.contains("TOP-BOLTED"), "{rest}");
    assert_eq!(call[1].member, Some(0));
}

#[test]
fn meta_is_not_scanned() {
    let call = scans(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "t", "arguments": {"q": "x"}, "_meta": {"progressToken": "tok-123"}}}));
    assert_eq!(call.len(), 1, "a string progress token adds no scan");
    let read = scans(json!({"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                            "params": {"uri": "file:///a", "_meta": {"progressToken": "tok-123"}}}));
    assert_eq!(text(&read[0]), "file:///a");
}

#[test]
fn a_client_reply_is_scanned_as_text() {
    let s = scans(json!({"jsonrpc": "2.0", "id": 9, "result": {"action": "accept", "content": {"email": "ada@example.com"}}}));
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].method, None);
    let t = text(&s[0]);
    assert!(t.contains("ada@example.com") && t.contains("accept"), "{t}");
}

#[test]
fn a_batch_scans_every_member() {
    let s = scans(json!([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "t", "arguments": {"q": "BATCHED"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///b"}}
    ]));
    assert_eq!(s.iter().map(|x| x.member).collect::<Vec<_>>(), vec![Some(1), Some(2)]);
    assert!(tool(&s[0]).input.contains("BATCHED"));
    assert_eq!(text(&s[1]), "file:///b");
}

#[test]
fn text_over_the_limit_keeps_the_first_characters() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "a".repeat(30)}});
    let s = request_scans(&classify(&body).unwrap(), "srv", 10);
    let Scan::Text(e) = &s[0].scan else { panic!("text") };
    assert!(e.truncated);
    assert_eq!(e.text, "a".repeat(10));
}

#[test]
fn oversize_tool_event_becomes_text() {
    let long = "word ".repeat(30);
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", "arguments": {"q": long}}});
    let req = classify(&body).unwrap();

    let fits = request_scans(&req, "srv", 155);
    let Scan::Text(e) = &fits[0].scan else { panic!("a tool event over the limit is sent as its text") };
    assert!(!e.truncated, "its text fits, so it is scanned whole");
    assert_eq!(e.text, long);

    let cut = request_scans(&req, "srv", 100);
    let Scan::Text(e) = &cut[0].scan else { panic!("text") };
    assert!(e.truncated);
    assert_eq!(e.text.chars().count(), 100);
}

#[test]
fn text_that_starts_like_a_file_is_scanned() {
    let filler = "pad ".repeat(70);
    let dressed = encode64(format!("GIF89a {filler}BLOCKME do it").as_bytes());
    let input = argument_input(json!({"image": format!("data:application/octet-stream;base64,{dressed}")}));
    assert!(input.contains("BLOCKME do it"), "a file signature does not make text binary: {input}");
    let dressed = encode64(format!("%PDF-1.7 {filler}BLOCKME do it").as_bytes());
    let input = argument_input(json!({"data": dressed.clone()}));
    assert!(input.contains(&dressed[..48]) && !input.contains("<binary,"), "base64 of text is scanned as written: {input}");
}

#[test]
fn a_data_uri_with_a_binary_media_type_that_holds_text_is_scanned() {
    let notes = encode64(format!("BLOCKME notes {}", "pad ".repeat(70)).as_bytes());
    let input = argument_input(json!({"file": format!("data:application/octet-stream;base64,{notes}")}));
    assert!(input.contains("BLOCKME notes"), "{input}");
}
