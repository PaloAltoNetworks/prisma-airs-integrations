//! Helpers shared by the test files.
#![allow(dead_code)]

/// Standard base64, padded.
pub fn encode64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// The base64 of a PNG: its signature, then the start of its first chunk, again and again (480 characters).
pub fn png64() -> String {
    "iVBORw0KGgoAAAANSUhEUgAA".repeat(20)
}

/// Audio with no file header, as a speech model streams it: `samples` 16-bit little-endian samples of a 440 Hz tone
/// at 24 kHz. Its bytes are not UTF-8 and start with no known signature.
pub fn pcm(samples: usize) -> Vec<u8> {
    (0..samples)
        .flat_map(|i| (((i as f64 * 440.0 * std::f64::consts::TAU / 24_000.0).sin() * 8_000.0) as i16).to_le_bytes())
        .collect()
}
