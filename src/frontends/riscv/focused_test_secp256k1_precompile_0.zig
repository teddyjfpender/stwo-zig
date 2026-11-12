//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("air/guest_precompile/tests/ethereum_statement_test.zig");
    _ = @import("air/guest_precompile/ethereum_lookup_registration.zig");
    _ = @import("prover/guest_precompile/ethereum_witness.zig");
    _ = @import("prover/guest_precompile/ethereum_types.zig");
    _ = @import("prover/guest_precompile/ethereum_transcript.zig");
    _ = @import("prover/guest_precompile/ethereum_preprocessed.zig");
    _ = @import("prover/guest_precompile/ethereum_main.zig");
    _ = @import("prover/guest_precompile/ethereum_interaction.zig");
    _ = @import("prover/guest_precompile/ethereum_assembly.zig");
    _ = @import("prover/guest_precompile/ethereum_cancellation.zig");
    _ = @import("prover/guest_precompile/ethereum_orchestration.zig");
    _ = @import("prover/guest_precompile/ethereum_verifier.zig");
}
