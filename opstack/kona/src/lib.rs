//! Bounded OP execution using pinned Kona. This does not establish L1 derivation.
#![no_std]
extern crate alloc;
#[cfg(not(feature = "sha-service"))]
pub(crate) use sha2 as statement_sha2;
#[cfg(feature = "sha-service")]
pub(crate) use sha2_rv64 as statement_sha2;
#[cfg(feature = "blob-derivation")]
pub mod anchored_blobs;
#[cfg(feature = "derivation")]
mod anchored_chain;
#[cfg(feature = "derivation")]
pub mod anchored_l1;
#[cfg(feature = "derivation")]
pub mod anchored_l2;
#[cfg(feature = "blob-derivation")]
mod blob_roots;
pub mod execution;
pub mod metadata;
#[cfg(feature = "precompile-services")]
pub mod precompiles;
#[cfg(feature = "derivation")]
pub mod transition;
#[cfg(feature = "transition-program")]
pub mod transition_input;
#[cfg(all(feature = "host", feature = "transition-program"))]
pub mod transition_trace;
pub mod witness;

#[cfg(feature = "host-phase-census")]
pub mod phase_census;

#[cfg(all(feature="host-phase-census",feature="canonical-fr"))]
compile_error!("Montgomery branch census requires the control field representation");

#[cfg(all(test, feature="canonical-fr"))]
mod canonical_fr_tests;

#[cfg(all(test,feature="lazy-brotli"))]
#[path="../vendor/kona-protocol/src/brotli_alloc.rs"]
mod brotli_allocator_qualification;

#[cfg(all(test, feature="derivation"))]
mod brotli_qualification;
