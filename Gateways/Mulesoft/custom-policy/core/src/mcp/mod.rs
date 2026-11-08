//! MCP traffic: which bodies are MCP JSON-RPC messages, what each method carries, and the text of a message.
//!
//! The body decides, not a header: on an MCP server instance `x-input-format` is only a client header, so a client
//! could set it. A message is an object whose `jsonrpc` is exactly `"2.0"` and that has either a non-empty string
//! `method`, or an `id` with a `result` or an `error` (a client's reply to a server request). A batch is a non-empty
//! array whose every element is a message. Anything else is not MCP: it takes the LLM path, where its content is
//! scanned or the request fails closed.
//!
//! A batch is never classified by one member: `[ping, tools/call]` is two members, each with its own kind (Kong v3's
//! lesson: classifying by the first member let a `ping` carry an unscanned `tools/call`).

pub mod reply;
pub mod request;

use serde_json::{Map, Value};

use crate::airs::ToolEvent;
use crate::extract::{declared_type, picture, reading, truncate, Extracted, Reading, Slot};

/// The members of a JSON-RPC message. Anything else at a message's top level is extra content, and is scanned.
pub const ENVELOPE: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// What a method carries, which decides what each leg scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nothing to scan on either leg: `ping`, `logging/setLevel`, `initialized` and every `notifications/` method.
    Control,
    /// Nothing on the request leg; the reply is a catalogue the client hands to a model: `initialize`,
    /// `resources/list`, `resources/templates/list`, `prompts/list`, `roots/list`.
    Catalogue,
    /// `tools/list`: the reply is the tool catalogue, scanned as a tool event.
    ToolList,
    /// `tools/call`: a tool event on both legs.
    ToolCall,
    /// Every other method, under any other spelling: its text, on both legs.
    Content,
    /// A client's reply to a server request (no method): its text, on the request leg.
    ClientReply,
}

/// One message of a request body.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// Its position in a batch; 0 for a single message.
    pub index: usize,
    /// Its id as sent (a number stays a number, a string a string); `None` for a notification.
    pub id: Option<Value>,
    /// `None` for a client reply.
    pub method: Option<String>,
    pub kind: Kind,
    pub message: Value,
}

/// An MCP request body.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub members: Vec<Member>,
    /// The body was an array (a JSON-RPC batch), so a refusal is an array too.
    pub batch: bool,
}

/// What one scan sends to Prisma AIRS: a tool event, or text, which is sent as a prompt on both legs (MCP text reaches
/// a model as input).
#[derive(Debug, Clone, PartialEq)]
pub enum Scan {
    Tool(ToolEvent),
    Text(Extracted),
}

/// One scan of a leg.
#[derive(Debug, Clone, PartialEq)]
pub struct LegScan {
    /// The request member it belongs to; `None` for the messages of a reply that answer no member.
    pub member: Option<usize>,
    pub method: Option<String>,
    pub scan: Scan,
}

/// The MCP reading of a request body, or `None` when it is not MCP.
pub fn classify(body: &Value) -> Option<Request> {
    match body {
        Value::Object(_) => member(0, body).map(|m| Request { members: vec![m], batch: false }),
        Value::Array(items) if !items.is_empty() => {
            let members: Option<Vec<Member>> = items.iter().enumerate().map(|(i, v)| member(i, v)).collect();
            members.map(|members| Request { members, batch: true })
        }
        _ => None,
    }
}

fn member(index: usize, value: &Value) -> Option<Member> {
    let obj = value.as_object()?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let id = obj.get("id").cloned();
    let (method, kind) = match obj.get("method") {
        Some(Value::String(m)) if !m.is_empty() => (Some(m.clone()), kind_of(m)),
        Some(_) => return None,
        None if id.is_some() && (obj.contains_key("result") || obj.contains_key("error")) => (None, Kind::ClientReply),
        None => return None,
    };
    Some(Member { index, id, method, kind, message: value.clone() })
}

/// The kind of a method. Method names are case-sensitive in MCP; any other spelling is `Content`, so it is scanned.
pub fn kind_of(method: &str) -> Kind {
    match method {
        "ping" | "logging/setLevel" | "initialized" => Kind::Control,
        m if m.starts_with("notifications/") => Kind::Control,
        "initialize" | "resources/list" | "resources/templates/list" | "prompts/list" | "roots/list" => Kind::Catalogue,
        "tools/list" => Kind::ToolList,
        "tools/call" => Kind::ToolCall,
        _ => Kind::Content,
    }
}

/// Who wrote a value, which decides how its strings are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// The client, writing for the server, which takes what it is given as data: a data URI is read as the text it
    /// carries, and a known binary format is left out (see `extract::reading`).
    Client,
    /// The server, writing for the client, which hands its text to a model as it is. Only a binary slot is read for
    /// its bytes, and an icon is left out; every other string is scanned as written, whatever it looks like, because a
    /// model reads it that way.
    Server,
}

/// Where a value sits in an MCP message, as far as bytes go. MCP carries bytes in three places only: an image or
/// audio content block's `data` and a resource's `blob`, the binary slots, which are read for their bytes; and an
/// icon's `src`, which a client only draws for people, so a data URI there is left out whatever it holds. A look-alike
/// anywhere else (inside `structuredContent`, a schema, `_meta`, the arguments) is text a model may read, so it is
/// never a binary slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Place {
    /// A JSON-RPC message.
    Message,
    /// A message's `params` or `result`, or one message of a prompt or a sampling request.
    Body,
    /// A `content`: a list of content blocks, or a single one.
    Blocks,
    /// A content block.
    Block,
    /// A `contents` list of resources.
    Resources,
    /// A resource: an element of `contents`, or a content block's `resource`.
    Resource,
    /// A list of tools, prompts, resources or resource templates.
    Definitions,
    /// One of those, or a `serverInfo` or `clientInfo`.
    Definition,
    /// An `icons` list.
    Icons,
    /// An icon.
    Icon,
    /// The `messages` of a prompt or a sampling request.
    Messages,
    /// Anything else: arguments, `structuredContent`, schemas, `_meta`, members MCP does not define.
    Opaque,
}

impl Place {
    /// The place of the member `key` of an object here.
    fn member(self, key: &str) -> Place {
        match (self.object(), key) {
            (Place::Message, "params" | "result") => Place::Body,
            (Place::Body, "content") => Place::Blocks,
            (Place::Body, "contents") => Place::Resources,
            (Place::Body, "messages") => Place::Messages,
            (Place::Body, "tools" | "prompts" | "resources" | "resourceTemplates") => Place::Definitions,
            (Place::Body, "serverInfo" | "clientInfo") => Place::Definition,
            (Place::Block, "resource") => Place::Resource,
            (Place::Block | Place::Resource | Place::Definition, "icons") => Place::Icons,
            _ => Place::Opaque,
        }
    }

    /// The place of an element of a list here.
    fn element(self) -> Place {
        match self {
            Place::Blocks => Place::Block,
            Place::Resources => Place::Resource,
            Place::Definitions => Place::Definition,
            Place::Icons => Place::Icon,
            Place::Messages => Place::Body,
            _ => Place::Opaque,
        }
    }

    /// The place of an object here: a `content` may be one block rather than a list of them.
    fn object(self) -> Place {
        if self == Place::Blocks {
            Place::Block
        } else {
            self
        }
    }
}

/// Where a string sits: its key, and the object and place that hold it.
#[derive(Clone, Copy)]
struct At<'a> {
    key: Option<&'a str>,
    parent: Option<&'a Map<String, Value>>,
    /// The place of the object that holds the value.
    holder: Place,
    /// The value's own place.
    place: Place,
}

/// The top of a value at `place`.
fn root(place: Place) -> At<'static> {
    At { key: None, parent: None, holder: Place::Opaque, place }
}

impl<'a> At<'a> {
    /// The member `key` of `parent`, an object at `holder`.
    fn member(parent: &'a Map<String, Value>, holder: Place, key: &'a str) -> Self {
        At { key: Some(key), parent: Some(parent), holder, place: holder.member(key) }
    }

    /// An element of the list here.
    fn element(self) -> At<'static> {
        root(self.place.element())
    }

    /// Whether a string here sits in one of MCP's binary slots: an image or audio block's `data`, a resource's `blob`.
    fn slot(self) -> bool {
        match (self.key, self.holder.object()) {
            (Some("data"), Place::Block) => {
                self.parent.is_some_and(|p| matches!(p.get("type").and_then(Value::as_str), Some("image" | "audio")))
            }
            (Some("blob"), Place::Resource) => true,
            _ => false,
        }
    }

    /// Whether a string here is an icon's `src`: a client draws an icon for people and never gives it to a model.
    fn icon(self) -> bool {
        self.key == Some("src") && self.holder.object() == Place::Icon
    }

    /// How a string here, written by `sender`, is scanned.
    fn read(self, s: &str, sender: Sender) -> Reading {
        if self.icon() {
            return picture(s);
        }
        let slot = self.slot();
        if sender == Sender::Server && !slot {
            return Reading::Plain;
        }
        reading(self.key, s, self.parent.and_then(declared_type), slot)
    }
}

/// The text of a message the server sent, in a stable order (an array's items in order, an object's members by key):
/// every non-blank string, and every object key that is not a plain identifier (an injection can sit in a schema's
/// property name). At the top level of the message, `jsonrpc`, `id` and `method` are protocol and are skipped; deeper
/// down they are content. Only the bytes in MCP's binary slots and its icons are left out (see [`Place`]).
pub fn text_values(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect(value, root(Place::Message), true, Sender::Server, &mut out);
    out
}

/// The member `key` of `parent`, an object at `holder`: its key when it is not a plain identifier, then its value's
/// text, nothing skipped.
pub(crate) fn entry_text(
    key: &str,
    value: &Value,
    parent: &Map<String, Value>,
    holder: Place,
    sender: Sender,
    out: &mut Vec<String>,
) {
    if !plain_identifier(key) && !key.trim().is_empty() {
        out.push(key.to_string());
    }
    collect(value, At::member(parent, holder, key), false, sender, out);
}

/// The text of a value at `place`, nothing skipped.
pub(crate) fn value_text(value: &Value, place: Place, sender: Sender, out: &mut Vec<String>) {
    collect(value, root(place), false, sender, out);
}

fn collect(value: &Value, at: At<'_>, top: bool, sender: Sender, out: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.trim().is_empty() => match at.read(s, sender) {
            Reading::Plain => out.push(s.clone()),
            Reading::Decoded(text) | Reading::Binary(text) => {
                if !text.trim().is_empty() {
                    out.push(text);
                }
            }
        },
        Value::Array(items) => items.iter().for_each(|v| collect(v, at.element(), false, sender, out)),
        Value::Object(map) => {
            for (k, v) in map {
                if top && matches!(k.as_str(), "jsonrpc" | "id" | "method") {
                    continue;
                }
                if !plain_identifier(k) && !k.trim().is_empty() {
                    out.push(k.to_string());
                }
                collect(v, At::member(map, at.place, k), false, sender, out);
            }
        }
        _ => {}
    }
}

/// A value at `place` as the JSON of a tool event, each string read as for [`text_values`], by `sender`: a binary
/// payload becomes a placeholder, and an encoded text becomes that text.
pub(crate) fn json_text(value: &Value, place: Place, sender: Sender) -> String {
    serde_json::to_string(&rewrite(value, root(place), sender)).unwrap_or_default()
}

fn rewrite(value: &Value, at: At<'_>, sender: Sender) -> Value {
    match value {
        Value::String(s) => match at.read(s, sender) {
            Reading::Plain => value.clone(),
            Reading::Decoded(text) | Reading::Binary(text) => Value::String(text),
        },
        Value::Array(items) => Value::Array(items.iter().map(|v| rewrite(v, at.element(), sender)).collect()),
        Value::Object(map) => Value::Object(
            map.iter().map(|(k, v)| (k.clone(), rewrite(v, At::member(map, at.place, k), sender))).collect(),
        ),
        other => other.clone(),
    }
}

/// Texts joined one per line for one scan, keeping the first characters over the limit; `None` when there is none.
pub(crate) fn text_scan(texts: Vec<String>, max_chars: usize) -> Option<Extracted> {
    if texts.is_empty() {
        return None;
    }
    let (text, truncated) = truncate(texts.join("\n"), max_chars);
    Some(Extracted { text, truncated, slot: Slot::Multi })
}

/// A tool event, or, when its input and output together exceed the limit, the text of `sources` (the values the event
/// was built from, each with its place and sender): AIRS cannot take a cut JSON string, so the content is scanned as
/// text, cut only if its text is too.
pub(crate) fn tool_or_text(event: ToolEvent, sources: &[(&Value, Place, Sender)], max_chars: usize) -> Scan {
    if event.input.chars().count() + event.output.chars().count() <= max_chars {
        return Scan::Tool(event);
    }
    let mut texts = Vec::new();
    sources.iter().for_each(|(v, place, sender)| value_text(v, *place, *sender, &mut texts));
    let empty = Extracted { text: String::new(), truncated: true, slot: Slot::Multi };
    Scan::Text(text_scan(texts, max_chars).unwrap_or(empty))
}

/// Letters, digits and `_ - . $ / :`, 1 to 64 characters: a key that cannot carry a sentence.
fn plain_identifier(key: &str) -> bool {
    (1..=64).contains(&key.chars().count())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$' | '/' | ':'))
}
