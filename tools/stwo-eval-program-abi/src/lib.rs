//! The backend-neutral evaluation-program ABI shared by the AIR recorders of stwo-zig.
//!
//! This directory is the single source of the `STP1` evaluation program (`program`), its byte
//! encoding (`encoding`), the `EvalAtRow` recorder that lowers a `FrameworkEval` into it
//! (`recording`), the differential check of a recording against the framework's own point
//! evaluation (`semantic`), the lookup-parameter classifier (`parameters`) and the `STWZEVA`
//! bundle container (`bundle`), the two-recording capture of one component (`capture`) and the
//! ABI byte-compare fixture both consumers check (`abi_fixture`). Two tools compile it into their own crate with
//!
//! ```ignore
//! #[path = "../../stwo-eval-program-abi/src/lib.rs"]
//! mod eval_program_abi;
//! ```
//!
//! - `tools/stwo-cairo-air-compiler` (Stwo-Cairo `82f2125`, Stwo `7b211ed`);
//! - `tools/stwo-circuit-oracle-rs` (`proving@5a7c5ed`).
//!
//! The recorder is generic over `stwo` and `stwo_constraint_framework`, and each consumer pins a
//! different revision of both, so the sources resolve those crates in the including crate rather
//! than through a manifest of their own: the directory has no `Cargo.toml`, no lock and no
//! dependencies, and neither consumer needs a path dependency or a patch. The `EvalAtRow` trait is
//! identical in both pins (`constraint-framework/src` differs only in `prover/logup.rs`).
//!
//! Every byte this code emits is part of the contract with the Zig readers
//! (`src/frontends/cairo/witness/{composition_bundle,eval_program}.zig`); the Cairo compiler's
//! committed bundles must stay byte-identical.

// Parts of the ABI surface are used by one consumer only.
#![allow(dead_code)]

pub mod abi_fixture;
pub mod bundle;
pub mod capture;
pub mod encoding;
pub mod parameters;
pub mod program;
pub mod recording;
pub mod semantic;
