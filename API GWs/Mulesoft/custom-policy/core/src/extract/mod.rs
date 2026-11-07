//! Turning request and response bodies into the text Prisma AIRS scans.

pub mod request;
pub mod response;

use std::fmt;

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

/// A non-text part as text to scan: its JSON, with binary payloads (data URIs, long base64 data fields) replaced, so
/// URLs, names and unknown fields are scanned and the bytes of an image are not.
pub(crate) fn without_binary(value: &serde_json::Value) -> String {
    fn strip(value: &serde_json::Value, key: Option<&str>) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), strip(v, Some(k)))).collect()),
            Value::Array(items) => Value::Array(items.iter().map(|v| strip(v, None)).collect()),
            Value::String(s) if is_binary(key, s) => Value::String(format!("<binary, {} characters>", s.len())),
            other => other.clone(),
        }
    }
    serde_json::to_string(&strip(value, None)).unwrap_or_default()
}

fn is_binary(key: Option<&str>, s: &str) -> bool {
    const LONG: usize = 256;
    if s.len() < LONG {
        return false;
    }
    if s.starts_with("data:") {
        return true;
    }
    let data_key = matches!(key, Some("data" | "file_data" | "b64_json" | "bytes" | "image_data" | "audio_data"));
    data_key && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_' | b'\n' | b'\r'))
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
