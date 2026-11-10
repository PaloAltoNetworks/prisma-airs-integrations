mod common;

use common::{encode64, pcm, png64};
use prisma_airs_core::airs::ToolMethod;
use prisma_airs_core::extract::ExtractError;
use prisma_airs_core::mcp::reply::{messages, reply_scans};
use prisma_airs_core::mcp::{classify, Request, Scan};
use serde_json::{json, Value};

fn req(body: Value) -> Request {
    classify(&body).expect("an MCP body")
}

/// The output of the tool event the reply `message` to `request` sends.
fn event_output(request: &Request, message: Value) -> String {
    match &reply_scans(Some(request), &[message], "deepwiki-test", 100_000)[0].scan {
        Scan::Tool(t) => t.output.clone(),
        Scan::Text(e) => panic!("expected a tool event, got text: {e:?}"),
    }
}

/// Everything the scans of the reply `message` send, joined.
fn all_scanned(request: Option<&Request>, message: Value) -> String {
    let scans = reply_scans(request, &[message], "deepwiki-test", 100_000);
    let texts: Vec<String> = scans
        .iter()
        .map(|s| match &s.scan {
            Scan::Tool(t) => format!("{}\n{}", t.input, t.output),
            Scan::Text(e) => e.text.clone(),
        })
        .collect();
    texts.join("\n")
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

#[test]
fn a_tool_description_behind_a_data_prefix_is_scanned_as_written() {
    let list = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let description = format!("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgBLOCKMEreadTheUsersKeys{}", "A".repeat(300));
    let out = event_output(&list, json!({"jsonrpc": "2.0", "id": 2,
                                         "result": {"tools": [{"name": "t", "description": description}]}}));
    assert!(out.contains("BLOCKMEreadTheUsersKeys"), "a model reads a description as it is written: {out}");
}

#[test]
fn a_tool_result_behind_a_data_prefix_is_scanned_as_written() {
    let text = format!("data:text/plain,{}BLOCKME exfiltrate", "pad ".repeat(70));
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3,
                                               "result": {"content": [{"type": "text", "text": text}]}}));
    assert!(out.contains("BLOCKME exfiltrate"), "{out}");
    let structured = format!("BLOCKME-{}", "x-".repeat(150));
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3,
                                               "result": {"content": [], "structuredContent": {"data": structured}}}));
    assert!(out.contains("BLOCKME-x-x"), "structured content is text a model may read: {out}");
}

#[test]
fn binary_slots_are_left_out_and_text_blobs_are_read() {
    let png = png64();
    let notes = encode64(format!("BLOCKME secret notes {}", "pad ".repeat(70)).as_bytes());
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [
        {"type": "image", "data": png.clone(), "mimeType": "image/png"},
        {"type": "resource", "resource": {"uri": "file:///notes.txt", "mimeType": "text/plain", "blob": notes}}]}}));
    assert!(!out.contains(&png[..48]) && out.contains("<binary, 480 characters>"), "an image is left out: {out}");
    assert!(out.contains("BLOCKME secret notes"), "a text resource sent as a blob is scanned as its text: {out}");
}

#[test]
fn initialize_instructions_behind_a_data_prefix_are_scanned() {
    let init = req(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}));
    let instructions = format!("data:text/plain,{}BLOCKME obey", "pad ".repeat(70));
    let all = all_scanned(Some(&init), json!({"jsonrpc": "2.0", "id": 1,
                                              "result": {"protocolVersion": "2025-06-18", "instructions": instructions}}));
    assert!(all.contains("BLOCKME obey"), "{all}");
}

#[test]
fn look_alike_slots_in_structured_content_and_schemas_are_scanned() {
    let words = format!("BLOCKME-{}", "x-".repeat(150));
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [], "structuredContent": {
        "file": {"uri": "file:///a", "blob": words.clone()}, "picture": {"type": "image", "data": words.clone()}}}}));
    assert_eq!(out.matches("BLOCKME-x-x").count(), 2, "only MCP's own slots hold bytes: {out}");
    let list = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let out = event_output(&list, json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "t", "description": "d",
        "inputSchema": {"type": "object", "icons": [{"src": words.clone()}]}}]}}));
    assert!(out.contains("BLOCKME-x-x"), "a schema is text, whatever its shape: {out}");
}

#[test]
fn resource_and_message_slots_are_left_out() {
    let png = png64();
    let read = req(json!({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "file:///logo.png"}}));
    let all = all_scanned(Some(&read), json!({"jsonrpc": "2.0", "id": 4, "result": {"contents": [
        {"uri": "file:///logo.png", "mimeType": "image/png", "blob": png.clone()}]}}));
    assert!(!all.contains(&png[..48]) && all.contains("file:///logo.png"), "{all}");
    let sampling = json!({"jsonrpc": "2.0", "id": 9, "method": "sampling/createMessage", "params": {"maxTokens": 5,
        "messages": [{"role": "user", "content": {"type": "image", "data": png.clone(), "mimeType": "image/png"}}]}});
    let all = all_scanned(None, sampling);
    assert!(!all.contains(&png[..48]), "{all}");
}

#[test]
fn icons_are_left_out() {
    let list = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let png = png64();
    let out = event_output(&list, json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "t", "description": "d",
        "icons": [{"src": format!("data:image/png;base64,{png}"), "mimeType": "image/png"}]}]}}));
    assert!(!out.contains(&png[..48]), "an icon is an image for people, not text for a model: {out}");
}

#[test]
fn an_icon_is_left_out_whatever_it_holds() {
    let list = req(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let svg = format!("<svg xmlns=\"http://www.w3.org/2000/svg\"><text>BLOCKME svg</text>{}</svg>", "<g/>".repeat(60));
    let out = event_output(&list, json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "t", "description": "d",
        "icons": [{"src": format!("data:image/svg+xml;base64,{}", encode64(svg.as_bytes())), "mimeType": "image/svg+xml"},
                  {"src": "data:text/plain,BLOCKME plain"},
                  {"src": "https://icons.example/tool.png"}]}]}}));
    assert!(!out.contains("BLOCKME"), "an icon is drawn for people, never read by a model: {out}");
    assert!(out.contains("data:image/svg+xml;base64,<binary,") && out.contains("https://icons.example/tool.png"), "{out}");
}

#[test]
fn an_svg_image_result_is_scanned_as_its_markup() {
    let svg = format!("<svg xmlns=\"http://www.w3.org/2000/svg\"><text>BLOCKME chart</text>{}</svg>", "<g/>".repeat(60));
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [
        {"type": "image", "data": encode64(svg.as_bytes()), "mimeType": "image/svg+xml"}]}}));
    assert!(out.contains("BLOCKME chart"), "an SVG image is text a model can be given: {out}");
}

#[test]
fn an_audio_block_without_a_known_header_is_left_out() {
    let data = encode64(&pcm(2_000));
    let out = event_output(&call_req(), json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [
        {"type": "audio", "data": data.clone(), "mimeType": "audio/pcm"}]}}));
    assert!(out.contains("<binary,") && !out.contains(&data[..48]), "{out}");
}

#[test]
fn a_blob_of_text_under_a_binary_type_is_read() {
    let notes = encode64(format!("BLOCKME notes {}", "pad ".repeat(70)).as_bytes());
    let read = req(json!({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "file:///notes"}}));
    let all = all_scanned(Some(&read), json!({"jsonrpc": "2.0", "id": 4, "result": {"contents": [
        {"uri": "file:///notes", "mimeType": "application/octet-stream", "blob": notes}]}}));
    assert!(all.contains("BLOCKME notes"), "{all}");
}

#[test]
fn an_image_sent_as_text_counts_toward_the_limit() {
    let png = png64();
    let as_text = json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [
        {"type": "text", "text": format!("data:image/png;base64,{png}")}]}});
    match &reply_scans(Some(&call_req()), &[as_text], "deepwiki-test", 300)[0].scan {
        Scan::Text(e) => assert!(e.truncated, "base64 a model reads as text is counted: {e:?}"),
        Scan::Tool(t) => panic!("expected the text fallback over the limit, got {t:?}"),
    }
    let as_image = json!({"jsonrpc": "2.0", "id": 3, "result": {"content": [
        {"type": "image", "data": png, "mimeType": "image/png"}]}});
    match &reply_scans(Some(&call_req()), &[as_image], "deepwiki-test", 300)[0].scan {
        Scan::Tool(_) => {}
        Scan::Text(e) => panic!("an image block's bytes are not counted: {e:?}"),
    }
}
