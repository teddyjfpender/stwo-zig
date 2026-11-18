//! Compatibility module; the implementation is shared by RV64 guests.
#[path = "keccak_sponge_service.rs"]
mod shared;
pub use shared::*;
