//! Prisma AIRS Guardrails, the part that does not depend on the gateway.
//!
//! Everything here is plain Rust: it compiles to `wasm32-wasip1` inside the MuleSoft policy and runs its tests on the
//! build machine's own target. The policy crate only wires these functions to the PDK.

pub mod airs;
pub mod breaker;
pub mod cache;
pub mod decision;
pub mod errors;
pub mod evidence;
pub mod extract;
pub mod format;
pub mod identity;
pub mod mcp;
pub mod settings;
pub mod sse;
