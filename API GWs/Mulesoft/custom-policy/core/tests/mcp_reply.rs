use prisma_airs_core::airs::ToolMethod;
use prisma_airs_core::extract::ExtractError;
use prisma_airs_core::mcp::reply::{messages, reply_scans};
use prisma_airs_core::mcp::{classify, Request, Scan};
use serde_json::{json, Value};

fn req(body: Value) -> Request {
    classify(&body).expect("an MCP body")
}

fn sse(msgs: &[Value]) -> Vec<u8> {
    msgs.iter().map(|m| format!("event: message\ndata: {m}\n\n")).collect::<String>().into_bytes()
}

fn call_req() -> Request {
    req(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "read_wiki_structure", "arguments": {"repoName": "modelcontextprotocol/servers"}}}))
}

#[test]
fn json_and_event_stream_replies_give_the_same_messages() {
    let m = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
    assert_eq!(messages(m.to_string().as_bytes(), false).unwrap(), vec![m.clone()]);
    assert_eq!(messages(&sse(&[m.clone()]), true).unwrap(), vec![m]);

    let batch = json!([{"jsonrpc": "2.0", "id": 1, "result": {}}, {"jsonrpc": "2.0", "id": 2, "result": {}}]);
    assert_eq!(messages(batch.to_string().as_bytes(), false).unwrap().len(), 2, "a batch reply is split");

    let primed = b"id: 1\ndata:\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
    assert_eq!(messages(primed, true).unwrap().len(), 1, "an event without data is not a message");
}

#[test]
fn tools_call_reply_is_a_tool_event_with_input_and_output() {
    let result = json!({"content": [{"type": "text", "text": "Available pages"}], "isError": false});
    let scans = reply_scans(Some(&call_req()), &[json!({"jsonrpc": "2.0", "id": 3, "result": result})], "deepwiki-test", 100_000);
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].member, Some(0));
    assert_eq!(scans[0].method.as_deref(), Some("tools/call"));
    let Scan::Tool(t) = &scans[0].scan else { panic!("expected a tool event") };
    assert_eq!(t.method, ToolMethod::Call);
    assert_eq!(t.server_name, "deepwiki-test");
    assert_eq!(t.tool_invoked.as_deref(), Some("read_wiki_structure"));
    assert_eq!(t.input, r#"{"repoName":"modelcontextprotocol/servers"}"#);
    assert_eq!(serde_json::from_str::<Value>(&t.output).unwrap(), result);
}

#[test]
fn tools_list_reply_output_is_the_bare_tools_array() {
    let r = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}));
    let tools = json!([{"name": "read_wiki_structure", "description": "Get topics", "inputSchema": {"type": "object"}}]);
    let reply = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools, "nextCursor": "page-2"}});
    let scans = reply_scans(Some(&r), &[reply], "deepwiki-test", 100_000);
    assert_eq!(scans.len(), 1, "nextCursor adds no scan");
    let Scan::Tool(t) = &scans[0].scan else { panic!("expected a tool event") };
    assert_eq!(t.method, ToolMethod::List);
    assert_eq!(t.tool_invoked, None);
    let output: Value = serde_json::from_str(&t.output).unwrap();
    assert!(output.is_array(), "AIRS refuses the {{\"tools\":[..]}} object");
    assert_eq!(output, tools);
    assert_eq!(t.input, "{}");
}

#[test]
fn tools_list_extra_result_members_are_scanned() {
    let r = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let reply = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [], "notice": "EXTRA TEXT"}});
    let scans = reply_scans(Some(&r), &[reply], "s", 100_000);
    assert_eq!(scans.len(), 2);
    assert!(matches!(scans[0].scan, Scan::Tool(_)));
    assert!(matches!(&scans[1].scan, Scan::Text(e) if e.text.contains("EXTRA TEXT")));
}

#[test]
fn tools_list_reply_without_tools_is_scanned_as_text() {
    let r = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let reply = json!({"jsonrpc": "2.0", "id": 2, "result": {"tool": "not a list, injected text"}});
    let scans = reply_scans(Some(&r), &[reply], "s", 100_000);
    assert_eq!(scans.len(), 1);
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("injected text")));
}

#[test]
fn catalogue_replies_are_scanned_as_text() {
    let init = req(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}));
    let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18",
                       "serverInfo": {"name": "DeepWiki", "version": "4.0.2"}, "instructions": "Use the tools politely."}});
    let scans = reply_scans(Some(&init), &[reply], "s", 100_000);
    assert_eq!(scans.len(), 1);
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("Use the tools politely.") && e.text.contains("DeepWiki")));

    let list = req(json!({"jsonrpc": "2.0", "id": 5, "method": "resources/list"}));
    let reply = json!({"jsonrpc": "2.0", "id": 5, "result": {"resources": [{"uri": "file:///a", "name": "a", "description": "Resource description text"}]}});
    let scans = reply_scans(Some(&list), &[reply], "s", 100_000);
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("Resource description text")));
}

#[test]
fn error_replies_are_scanned_as_text() {
    let reply = json!({"jsonrpc": "2.0", "id": 3, "error": {"code": -32000, "message": "Tool failed: ERROR TEXT"}});
    let scans = reply_scans(Some(&call_req()), &[reply], "s", 100_000);
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].member, Some(0));
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("Tool failed: ERROR TEXT")), "not a tool event");
}

#[test]
fn every_other_message_in_the_reply_is_scanned() {
    let body = sse(&[
        json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "LOG TEXT"}}),
        json!({"jsonrpc": "2.0", "id": "srv-1", "method": "elicitation/create",
               "params": {"message": "ELICIT TEXT", "requestedSchema": {"type": "object"}}}),
        json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "ok"}]}}),
    ]);
    let scans = reply_scans(Some(&call_req()), &messages(&body, true).unwrap(), "s", 100_000);
    assert_eq!(scans.len(), 2);
    assert!(matches!(scans[0].scan, Scan::Tool(_)));
    assert_eq!(scans[1].member, None);
    let Scan::Text(e) = &scans[1].scan else { panic!("text") };
    assert!(e.text.contains("LOG TEXT") && e.text.contains("ELICIT TEXT"), "{}", e.text);
    assert!(!e.text.contains("notifications/message"), "method names are protocol, not text");
}

#[test]
fn ids_match_by_value() {
    let r = req(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", "arguments": {}}}));
    let reply = json!({"jsonrpc": "2.0", "id": "1", "result": {"content": [{"type": "text", "text": "STRING ID REPLY"}]}});
    let scans = reply_scans(Some(&r), &[reply], "s", 100_000);
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].member, None, "\"1\" does not answer request 1");
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("STRING ID REPLY")));
}

#[test]
fn an_unreadable_event_is_unreadable() {
    assert!(matches!(messages(b"event: message\ndata: {not json\n\n", true), Err(ExtractError::Unreadable(_))));
    assert!(matches!(messages(b"<html>oops</html>", false), Err(ExtractError::Unreadable(_))));
}

#[test]
fn an_empty_reply_has_no_messages() {
    assert_eq!(messages(b"", false).unwrap(), Vec::<Value>::new());
    assert_eq!(messages(b"  \n", true).unwrap(), Vec::<Value>::new());
    assert!(reply_scans(Some(&call_req()), &[], "s", 100_000).is_empty());
}

#[test]
fn a_ping_reply_scans_nothing() {
    let r = req(json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}));
    assert!(reply_scans(Some(&r), &[json!({"jsonrpc": "2.0", "id": 4, "result": {}})], "s", 100_000).is_empty());
}

#[test]
fn a_bodiless_request_reply_is_scanned_as_text() {
    let msg = json!({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage",
                     "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "SAMPLE TEXT"}}],
                                "systemPrompt": "SYSTEM TEXT"}});
    let scans = reply_scans(None, &[msg], "s", 100_000);
    assert_eq!(scans.len(), 1);
    assert!(matches!(&scans[0].scan, Scan::Text(e) if e.text.contains("SAMPLE TEXT") && e.text.contains("SYSTEM TEXT")));
}

#[test]
fn oversize_reply_tool_event_becomes_text() {
    let result = json!({"content": [{"type": "text", "text": "x".repeat(200)}]});
    let scans = reply_scans(Some(&call_req()), &[json!({"jsonrpc": "2.0", "id": 3, "result": result})], "s", 150);
    let Scan::Text(e) = &scans[0].scan else { panic!("text") };
    assert!(e.truncated);
    assert_eq!(e.text.chars().count(), 150);
}
