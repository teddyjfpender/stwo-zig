//! Metal GPU proving backend for STWO, targeting Apple Silicon unified memory.
//!
//! `MetalBackend` implements the full stwo backend trait surface over GPU-resident column
//! buffers with zero-copy host views (unified memory). The kernels and runtime originate from
//! the `stwo-metal` companion project and were ported against the current trait surface;
//! the Cairo-specific witness lane, the bytecode-JIT constraint lane, and the staged-migration
//! scaffolding of that project were intentionally left behind.
//!
//! Conformance is enforced by `stwo-backend-testkit`: the backend must produce proofs
//! **byte-identical** to the CPU reference backend's.
//!
//! On machines without a Metal device (or non-macOS hosts), constructing GPU resources fails
//! at runtime; the crate always compiles.

mod backend;
mod columns;

pub use backend::MetalBackend;
pub use columns::{BaseFieldVec, Blake2sHashVec, SecureFieldVec};
