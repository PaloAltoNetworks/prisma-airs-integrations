//! Turning request and response bodies into the text Prisma AIRS scans.

pub mod request;
pub mod response;

use std::fmt;

/// Where the scanned text came from, for writing masked text back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Exactly one string field contributed, at this JSON pointer, and nothing was cut.
    Single(String),
    /// Several fields contributed, or text was synthesized or truncated: masked text cannot be written back.
    Multi,
}

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

/// Joins the pieces with a blank line and applies the character limit. Blank pieces are dropped.
pub(crate) fn assemble(pieces: Vec<Piece>, max_chars: usize) -> Result<Extracted, ExtractError> {
    let pieces: Vec<Piece> = pieces.into_iter().filter(|p| !p.text.trim().is_empty()).collect();
    if pieces.is_empty() {
        return Err(ExtractError::NoContent);
    }
    let single = match pieces.as_slice() {
        [only] => only.pointer.clone(),
        _ => None,
    };
    let joined = pieces.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join("\n\n");
    let (text, truncated) = truncate(joined, max_chars);
    let slot = match single {
        Some(pointer) if !truncated => Slot::Single(pointer),
        _ => Slot::Multi,
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
