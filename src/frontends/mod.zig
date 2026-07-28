//! Domain-specific proof system frontends for stwo-zig.
//!
//! A frontend defines:
//! - AIR component constraints (via the constraint framework)
//! - Trace generation logic
//! - A prove/verify orchestration function
//!
//! Frontends dispatch explicit backend implementations behind authenticated
//! program inputs and backend-independent proof acceptance contracts.
//!
//! ## Available frontends
//!
//! - `examples` — Reference implementations (blake, poseidon, plonk, state_machine, etc.)
//! - `cairo` — (future) Full stwo-cairo prover in Zig
//! - `riscv` — release-gated RV32IM frontend backed by the pinned Sail model

pub const examples = @import("stwo_native_examples");
pub const cairo = @import("stwo_cairo_frontend");
pub const riscv = @import("stwo_riscv_frontend");
