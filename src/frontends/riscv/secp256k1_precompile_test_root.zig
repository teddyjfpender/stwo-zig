//! Fast edit-loop root for the secp256k1 precompile authority.

test {
    _ = @import("air/guest_precompile/secp256k1_field_test.zig");
    _ = @import("air/guest_precompile/secp256k1_mul_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_linear_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_affine_test.zig");
    _ = @import("air/guest_precompile/secp256k1_point_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_split_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_scalar_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_table_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_ecdsa_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_recovery_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_recovery_caller_test.zig");
    _ = @import("air/guest_precompile/secp256k1_component_test.zig");
    _ = @import("air/guest_precompile/secp256k1_adaptive_profile_test.zig");
    _ = @import("air/guest_precompile/ethereum_statement_test.zig");
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
