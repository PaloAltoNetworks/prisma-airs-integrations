//! Turning request and response bodies into the text Prisma AIRS scans.

pub mod request;
pub mod response;

use std::fmt;

use serde_json::{Map, Value};

/// Where the scanned text came from, for writing masked text back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Exactly one string field contributed, at this JSON pointer, and nothing was cut.
    Single(String),
    /// Several whole string fields contributed, in this order, joined with a blank line, and nothing was cut.
    Fields(Vec<Field>),
    /// Text was synthesized or truncated: masked text cannot be written back.
    Multi,
}

/// One string field of a [`Slot::Fields`]: its JSON pointer and its length in characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub pointer: String,
    pub chars: usize,
}

impl Slot {
    /// Whether masked text can be written back to the body.
    pub fn maskable(&self) -> bool {
        !matches!(self, Slot::Multi)
    }
}

/// The body with `masked` written back into the fields the scanned text came from; `None` when it cannot be done
/// exactly, so the caller blocks rather than forward the original. Several fields need masked text of the same
/// length as the scanned text, with every separator still in place: then each field gets its own stretch of it.
pub fn write_back(body: &[u8], slot: &Slot, masked: &str) -> Option<Vec<u8>> {
    let writes: Vec<(&str, String)> = match slot {
        Slot::Multi => return None,
        Slot::Single(pointer) => vec![(pointer.as_str(), masked.to_string())],
        Slot::Fields(fields) => {
            let chars: Vec<char> = masked.chars().collect();
            let expected = fields.iter().map(|f| f.chars).sum::<usize>() + SEPARATOR.chars().count() * (fields.len().saturating_sub(1));
            if fields.is_empty() || chars.len() != expected {
                return None;
            }
            let mut at = 0;
            let mut writes = Vec::with_capacity(fields.len());
            for (i, field) in fields.iter().enumerate() {
                if i > 0 {
                    let sep: String = chars[at..at + SEPARATOR.chars().count()].iter().collect();
                    if sep != SEPARATOR {
                        return None;
                    }
                    at += SEPARATOR.chars().count();
                }
                writes.push((field.pointer.as_str(), chars[at..at + field.chars].iter().collect()));
                at += field.chars;
            }
            writes
        }
    };
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    for (pointer, text) in writes {
        let target = value.pointer_mut(pointer)?;
        if !target.is_string() {
            return None;
        }
        *target = serde_json::Value::String(text);
    }
    serde_json::to_vec(&value).ok()
}

/// What joins the pieces of scanned text.
const SEPARATOR: &str = "\n\n";

/// The text to scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub text: String,
    /// The text was cut at the scan limit.
    pub truncated: bool,
    pub slot: Slot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The body is well-formed but holds nothing to scan.
    NoContent,
    /// The body does not have the shape its format requires.
    Unreadable(String),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractError::NoContent => write!(f, "nothing to scan"),
            ExtractError::Unreadable(why) => write!(f, "unreadable body: {why}"),
        }
    }
}

impl std::error::Error for ExtractError {}

/// One piece of text, and the JSON pointer of the string field it is exactly equal to, if any.
#[derive(Debug, Clone)]
pub(crate) struct Piece {
    pub text: String,
    pub pointer: Option<String>,
}

/// Joins the pieces with a blank line and applies the character limit, keeping the first characters. Blank pieces
/// are dropped.
pub(crate) fn assemble(pieces: Vec<Piece>, max_chars: usize) -> Result<Extracted, ExtractError> {
    assemble_keeping(pieces, max_chars, Keep::First)
}

/// The same, keeping the last characters: a prompt's newest text is the part that must not be cut.
pub(crate) fn assemble_newest(pieces: Vec<Piece>, max_chars: usize) -> Result<Extracted, ExtractError> {
    assemble_keeping(pieces, max_chars, Keep::Last)
}

#[derive(Clone, Copy)]
enum Keep {
    First,
    Last,
}

fn assemble_keeping(pieces: Vec<Piece>, max_chars: usize, keep: Keep) -> Result<Extracted, ExtractError> {
    let pieces: Vec<Piece> = pieces.into_iter().filter(|p| !p.text.trim().is_empty()).collect();
    if pieces.is_empty() {
        return Err(ExtractError::NoContent);
    }
    let joined = pieces.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(SEPARATOR);
    let (text, truncated) = match keep {
        Keep::First => truncate(joined, max_chars),
        Keep::Last => truncate_keeping_last(joined, max_chars),
    };
    let slot = if truncated {
        Slot::Multi
    } else if let [only] = pieces.as_slice() {
        only.pointer.clone().map(Slot::Single).unwrap_or(Slot::Multi)
    } else if pieces.iter().all(|p| p.pointer.is_some()) {
        Slot::Fields(
            pieces
                .iter()
                .map(|p| Field { pointer: p.pointer.clone().unwrap_or_default(), chars: p.text.chars().count() })
                .collect(),
        )
    } else {
        Slot::Multi
    };
    Ok(Extracted { text, truncated, slot })
}

/// The first `max_chars` characters (not bytes), and whether anything was cut.
pub(crate) fn truncate(text: String, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        None => (text, false),
        Some((byte, _)) => (text[..byte].to_string(), true),
    }
}

/// The last `max_chars` characters, and whether anything was cut.
fn truncate_keeping_last(text: String, max_chars: usize) -> (String, bool) {
    let total = text.chars().count();
    if total <= max_chars {
        return (text, false);
    }
    let start = text.char_indices().nth(total - max_chars).map(|(byte, _)| byte).unwrap_or(0);
    (text[start..].to_string(), true)
}

/// A non-text part as text to scan: its JSON, each string read by [`reading`], so URLs, names and unknown fields are
/// scanned, an encoded text is scanned as that text, and the bytes of an image are not.
pub(crate) fn without_binary(value: &Value) -> String {
    serde_json::to_string(&strings(value, None, None, false)).unwrap_or_default()
}

/// A provider's content part as text to scan, read as [`without_binary`] reads it, except that the `data` of its
/// inline payload (Gemini's `inlineData`, an Anthropic `source` of type `base64`) is a binary slot, read against the
/// media type beside it: the provider decodes those bytes as that type and never gives the model the string as
/// written. So a file that is text is scanned as that text, and audio with no file header is left out.
pub(crate) fn without_payload(part: &Value) -> String {
    let read = match part {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let value = match v {
                        Value::Object(inner) if is_payload(k, inner) => members(inner, true),
                        _ => strings(v, Some(k.as_str()), Some(map), false),
                    };
                    (k.clone(), value)
                })
                .collect(),
        ),
        other => strings(other, None, None, false),
    };
    serde_json::to_string(&read).unwrap_or_default()
}

/// Whether `inner`, the member `key` of a provider's content part, is that provider's inline payload.
fn is_payload(key: &str, inner: &Map<String, Value>) -> bool {
    match key {
        "inlineData" | "inline_data" => true,
        "source" => inner.get("type").and_then(Value::as_str) == Some("base64"),
        _ => false,
    }
}

/// `value` with each string read by [`reading`]; `slot` says that `value`, if it is a string, sits in a binary slot.
fn strings(value: &Value, key: Option<&str>, parent: Option<&Map<String, Value>>, slot: bool) -> Value {
    match value {
        Value::Object(map) => members(map, false),
        Value::Array(items) => Value::Array(items.iter().map(|v| strings(v, None, None, false)).collect()),
        Value::String(s) => match reading(key, s, parent.and_then(declared_type), slot) {
            Reading::Plain => value.clone(),
            Reading::Decoded(text) | Reading::Binary(text) => Value::String(text),
        },
        other => other.clone(),
    }
}

/// An object's members, read by [`strings`]; in an inline payload (`payload`), its `data` is a binary slot.
fn members(map: &Map<String, Value>, payload: bool) -> Value {
    Value::Object(
        map.iter().map(|(k, v)| (k.clone(), strings(v, Some(k.as_str()), Some(map), payload && k == "data"))).collect(),
    )
}

/// How a string is scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    /// As it is.
    Plain,
    /// As this text instead: what a data URI or a binary slot carries, a data URI's header kept.
    Decoded(String),
    /// Left out: this placeholder is scanned in its place.
    Binary(String),
}

/// The shortest base64 string under a data-like key, or in a binary slot, that is read as a payload.
const LONG: usize = 256;

/// How a string under `key` is scanned. Nothing is left out on its looks alone: a prefix, an alphabet or a file
/// signature proves nothing, because a model reads a string as it is written, and text can start with anything.
///
/// - A data URI (`data:`, a media type, `;base64` or not, a comma, the data) is scanned as the text it carries, its
///   header kept. When its bytes are not text (not UTF-8, and its media type is not text) and start with a known
///   binary signature, a placeholder is scanned instead. A string that merely starts with "data:" (a sentence, say)
///   is not a data URI.
/// - A long base64 string in a binary slot (`slot`: where the receiver decodes it as bytes and never reads it as
///   written) is read the same way, against `declared`, the media type beside it; there, bytes that are not text are
///   left out whatever their format.
/// - A long base64 string under a data-like key anywhere else is left out only when its bytes are not UTF-8 and start
///   with a known binary signature. Anything else may be text itself (a sentence without spaces is valid base64), so
///   it is scanned as it is.
/// - Every other string is scanned as it is.
pub(crate) fn reading(key: Option<&str>, s: &str, declared: Option<&str>, slot: bool) -> Reading {
    if let Some(uri) = DataUri::parse(s) {
        let Some(bytes) = uri.bytes() else { return Reading::Plain };
        return match judge(bytes, uri.text(), slot) {
            Judged::Text(text) => Reading::Decoded(format!("data:{},{text}", uri.header)),
            Judged::Binary => Reading::Binary(format!("data:{},<binary, {} characters>", uri.header, uri.data.len())),
            Judged::Raw => Reading::Plain,
        };
    }
    if s.len() < LONG || !(slot || is_data_key(key)) {
        return Reading::Plain;
    }
    let Some(bytes) = base64_bytes(s) else { return Reading::Plain };
    let placeholder = || Reading::Binary(format!("<binary, {} characters>", s.len()));
    if !slot {
        return match judge(bytes, false, false) {
            Judged::Binary => placeholder(),
            Judged::Text(_) | Judged::Raw => Reading::Plain,
        };
    }
    match judge(bytes, declared.is_some_and(is_text_mime), true) {
        Judged::Text(text) => Reading::Decoded(text),
        Judged::Binary => placeholder(),
        Judged::Raw => Reading::Plain,
    }
}

/// What decoded bytes are.
enum Judged {
    /// Text, scanned in place of the string that carried it.
    Text(String),
    /// A binary payload, left out.
    Binary,
    /// Neither: the string that carried them is scanned as it is.
    Raw,
}

/// Valid UTF-8 is text, whatever it starts with, and so are bytes whose media type is text (decoded with replacement
/// characters). Other bytes are binary when they start with a known binary signature or sit in a binary slot, and
/// are scanned as written anywhere else.
fn judge(bytes: Vec<u8>, text: bool, slot: bool) -> Judged {
    match String::from_utf8(bytes) {
        Ok(decoded) => Judged::Text(decoded),
        Err(e) if text => Judged::Text(String::from_utf8_lossy(e.as_bytes()).into_owned()),
        Err(e) if slot || known_binary(e.as_bytes()) => Judged::Binary,
        Err(_) => Judged::Raw,
    }
}

/// How a string that a client only draws for people and never gives a model (an MCP icon's `src`) is scanned: a data
/// URI is left out whatever it holds, its header kept; anything else, a link, is scanned as it is.
pub(crate) fn picture(s: &str) -> Reading {
    match DataUri::parse(s) {
        Some(uri) => Reading::Binary(format!("data:{},<binary, {} characters>", uri.header, uri.data.len())),
        None => Reading::Plain,
    }
}

/// A data URI (RFC 2397).
struct DataUri<'a> {
    /// Everything between `data:` and the first comma.
    header: &'a str,
    /// The media type without its parameters, lowercased; empty means text (RFC 2397's default).
    media: String,
    base64: bool,
    data: &'a str,
}

impl<'a> DataUri<'a> {
    /// `s` as a data URI: `data:` in any case, a media type that may be empty and may carry parameters, `;base64` or
    /// not, a comma, the data. `None` when the header is not a media type, so a sentence that starts with "data:" is
    /// not one.
    fn parse(s: &'a str) -> Option<Self> {
        if !s.get(..5)?.eq_ignore_ascii_case("data:") {
            return None;
        }
        let (header, data) = s[5..].split_once(',')?;
        if header.len() > 255 {
            return None;
        }
        let (params, base64) = match header.len().checked_sub(7).and_then(|at| Some(at).zip(header.get(at..))) {
            Some((at, tail)) if tail.eq_ignore_ascii_case(";base64") => (&header[..at], true),
            _ => (header, false),
        };
        let mut parts = params.split(';');
        let media = parts.next().unwrap_or_default();
        let media_ok = media.is_empty() || media.split_once('/').is_some_and(|(t, sub)| is_token(t) && is_token(sub));
        let params_ok = parts.all(|p| p.split_once('=').is_some_and(|(name, value)| is_token(name) && is_token(value)));
        (media_ok && params_ok).then(|| DataUri { header, media: media.to_ascii_lowercase(), base64, data })
    }

    /// Whether its media type says its bytes are text.
    fn text(&self) -> bool {
        self.media.is_empty() || is_text_mime(&self.media)
    }

    /// Its bytes: base64 decoded, or `%` escapes decoded; `None` when it says base64 and is not.
    fn bytes(&self) -> Option<Vec<u8>> {
        if self.base64 {
            base64_bytes(self.data)
        } else {
            Some(percent_decode(self.data))
        }
    }
}

/// A media type token (RFC 6838): letters, digits and `! # $ & - ^ _ . +`, 1 to 127 characters.
fn is_token(s: &str) -> bool {
    (1..=127).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

/// A key whose long base64 value is commonly a binary payload.
fn is_data_key(key: Option<&str>) -> bool {
    matches!(key, Some("data" | "file_data" | "b64_json" | "bytes" | "image_data" | "audio_data" | "blob"))
}

/// A media type whose bytes are text a model reads.
pub(crate) fn is_text_mime(mime: &str) -> bool {
    let mime = mime.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    mime.starts_with("text/")
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
        || matches!(
            mime.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-javascript"
                | "application/x-python"
                | "application/x-ndjson"
                | "application/yaml"
                | "application/x-yaml"
        )
}

/// The media type an object declares for its payload (`mimeType`, `media_type` and their other spellings).
pub(crate) fn declared_type(map: &Map<String, Value>) -> Option<&str> {
    ["mimeType", "mime_type", "mediaType", "media_type"].iter().find_map(|k| map.get(*k)).and_then(Value::as_str)
}

/// Whether bytes begin with the signature of a format that is handed on as bytes, never as text: an image, audio,
/// video, a PDF, an archive or an office document, a font, a database or a program.
pub(crate) fn known_binary(b: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"\x1f\x8b",
        b"\xfd7zXZ\x00",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x28\xb5\x2f\xfd",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"OggS",
        b"fLaC",
        b"ID3",
        b"\x1a\x45\xdf\xa3",
        b"\x30\x26\xb2\x75\x8e\x66\xcf\x11",
        b"FLV\x01",
        b"\x00\x00\x01\xba",
        b"\x00\x00\x01\xb3",
        b"II*\x00",
        b"MM\x00*",
        b"\x00\x00\x01\x00",
        b"\x00\x01\x00\x00\x00",
        b"OTTO",
        b"wOFF",
        b"wOF2",
        b"\x00asm",
        b"\x7fELF",
        b"SQLite format 3\x00",
    ];
    let at = |range: std::ops::Range<usize>, tag: &[u8]| b.get(range) == Some(tag);
    SIGNATURES.iter().any(|sig| b.starts_with(sig))
        || (at(0..4, b"RIFF") && [b"WEBP", b"WAVE", b"AVI "].iter().any(|f| at(8..12, *f)))
        || (at(0..4, b"FORM") && [b"AIFF", b"AIFC"].iter().any(|f| at(8..12, *f)))
        || at(4..8, b"ftyp")
        || matches!(b, [0xff, second, ..] if *second & 0xe0 == 0xe0)
}

/// Standard or URL-safe base64, padding optional, line breaks allowed; `None` for anything else, a space included.
pub(crate) fn base64_bytes(data: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut padded = false;
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    for b in data.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'\r' | b'\n' => continue,
            b'=' => {
                padded = true;
                continue;
            }
            _ => return None,
        };
        if padded {
            return None;
        }
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

/// `%XX` escapes decoded, everything else kept.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let hex = |i: usize| b.get(i).and_then(|c| char::from(*c).to_digit(16));
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Standard or URL-safe base64, padding optional; `None` if it is not base64 or not UTF-8 text.
pub(crate) fn base64_text(data: &str) -> Option<String> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    for b in data.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_uri_boundaries_never_panic() {
        assert!(DataUri::parse("dataé:x,y").is_none(), "a multibyte character where the colon belongs");
        assert!(DataUri::parse("data:éééé,x").is_none(), "a header that is not a media type");
        assert!(DataUri::parse(&format!("data:{},x", "a".repeat(256))).is_none(), "a header over 255 bytes");
        assert!(DataUri::parse("data:text/plain;charset=\"utf-8\",x").is_none(), "a quoted value: scanned as written");
        let upper = DataUri::parse("DATA:TEXT/PLAIN;BASE64,QUJD").expect("case does not matter");
        assert!(upper.base64 && upper.media == "text/plain" && upper.bytes() == Some(b"ABC".to_vec()));
        let spaced = DataUri::parse("data:;base64,QU JD").and_then(|u| u.bytes());
        assert_eq!(spaced, None, "base64 with a space is not base64");
        let plain = DataUri::parse("data:,hello").expect("an empty media type");
        assert!(plain.text() && !plain.base64, "an empty media type means text");
    }

    #[test]
    fn percent_decode_keeps_what_is_not_an_escape() {
        assert_eq!(percent_decode("%"), b"%");
        assert_eq!(percent_decode("%4"), b"%4");
        assert_eq!(percent_decode("%zz"), b"%zz");
        assert_eq!(percent_decode("a%20b%2"), b"a b%2");
    }
}
