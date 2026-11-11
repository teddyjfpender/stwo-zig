//! Compatibility module; the implementation is shared by RV64 guests.
#[path = "../../../../guests/ethereum/rv64/src/keccak_sponge_service.rs"]
mod shared;
pub use shared::*;
