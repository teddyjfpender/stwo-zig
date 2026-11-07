//! Bounded OP execution using pinned Kona. This does not establish L1 derivation.
#![no_std]
extern crate alloc;
#[cfg(not(feature = "sha-service"))]
pub(crate) use sha2 as statement_sha2;
#[cfg(feature = "sha-service")]
pub(crate) use sha2_rv64 as statement_sha2;
#[cfg(feature = "derivation")]
mod anchored_chain;
#[cfg(feature = "derivation")]
pub mod anchored_l1;
#[cfg(feature = "derivation")]
pub mod anchored_l2;
pub mod execution;
pub mod metadata;
#[cfg(feature = "precompile-services")]
pub mod precompiles;
pub mod witness;
