//! Test support shared by the fixture-backed rungs of this package and of
//! the circuit integrations: the oracle fixture reader, the gate-list
//! digests, the `prover_test.rs` circuits and the R4 multiverifier.
//! Test-only; built as the `circuit_testing` module.
pub const fixture_json = @import("fixture_json.zig");
pub const circuit_summary = @import("circuit_summary.zig");
pub const contexts = @import("contexts.zig");
pub const verifier_stages = @import("verifier_stages.zig");
pub const fold_registry = @import("fold_registry.zig");
/// `crates/stark_verifier/src/test_utils.rs::TestComponentData`.
pub const component_data = @import("component_data.zig");
