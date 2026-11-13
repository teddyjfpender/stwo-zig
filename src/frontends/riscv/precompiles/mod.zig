//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const air = struct {
    pub const bulk_memcpy_caller_candidate = @import("air/bulk_memcpy_caller_candidate.zig");
    pub const bulk_memcpy_word_candidate = @import("air/bulk_memcpy_word_candidate.zig");
    pub const caller_component_mask = @import("air/caller_component_mask.zig");
    pub const identity_hash = @import("air/identity_hash.zig");
    pub const keccakf_authority = @import("air/keccakf_authority.zig");
    pub const keccakf_lookup_tuples = @import("air/keccakf_lookup_tuples.zig");
    pub const keccakf_multiplicities = @import("air/keccakf_multiplicities.zig");
    pub const keccakf_relations = @import("air/keccakf_relations.zig");
    pub const keccakf_table_component = @import("air/keccakf_table_component.zig");
    pub const keccakf_table_interaction = @import("air/keccakf_table_interaction.zig");
    pub const keccakf_tables = @import("air/keccakf_tables.zig");
    pub const keccakf_throughput_tables = @import("air/keccakf_throughput_tables.zig");
    pub const keccakf_witness = @import("air/keccakf_witness.zig");
    pub const mask_layout = @import("air/mask_layout.zig");
    pub const relation_challenges = @import("air/relation_challenges.zig");
    pub const relation_event = @import("air/relation_event.zig");
    pub const relation_registry = @import("air/relation_registry.zig");
    pub const secp256k1_affine = @import("air/secp256k1_affine.zig");
    pub const secp256k1_component = @import("air/secp256k1_component.zig");
    pub const secp256k1_component_interaction = @import("air/secp256k1_component_interaction.zig");
    pub const secp256k1_component_trace = @import("air/secp256k1_component_trace.zig");
    pub const secp256k1_ecdsa = @import("air/secp256k1_ecdsa.zig");
    pub const secp256k1_ecdsa_direct = @import("air/secp256k1_ecdsa_direct.zig");
    pub const secp256k1_field = @import("air/secp256k1_field.zig");
    pub const secp256k1_linear_direct = @import("air/secp256k1_linear_direct.zig");
    pub const secp256k1_mul_direct = @import("air/secp256k1_mul_direct.zig");
    pub const secp256k1_point_direct = @import("air/secp256k1_point_direct.zig");
    pub const secp256k1_recovery = @import("air/secp256k1_recovery.zig");
    pub const secp256k1_recovery_direct = @import("air/secp256k1_recovery_direct.zig");
    pub const secp256k1_relations = @import("air/secp256k1_relations.zig");
    pub const secp256k1_scalar_direct = @import("air/secp256k1_scalar_direct.zig");
    pub const secp256k1_split_direct = @import("air/secp256k1_split_direct.zig");
    pub const secp256k1_table_direct = @import("air/secp256k1_table_direct.zig");
    pub const sha256_compression = @import("air/sha256_compression.zig");
    pub const sha256_compression_graph = @import("air/sha256_compression_graph.zig");
    pub const sha256_compression_rows = @import("air/sha256_compression_rows.zig");
    pub const sha256_memory_record = @import("air/sha256_memory_record.zig");
    pub const sha256_packed_arithmetic = @import("air/sha256_packed_arithmetic.zig");
    pub const sha256_packed_call = @import("air/sha256_packed_call.zig");
    pub const sha256_packed_source = @import("air/sha256_packed_source.zig");
    pub const sha256_relations = @import("air/sha256_relations.zig");
    pub const sha256_word_program = @import("air/sha256_word_program.zig");
    pub const stack_swap_caller_candidate = @import("air/stack_swap_caller_candidate.zig");
    pub const stack_swap_word_candidate = @import("air/stack_swap_word_candidate.zig");
};
pub const primitives = struct {
    pub const arith256 = @import("rv64_services/arith256.zig");
    pub const secp256k1 = @import("rv64_services/secp256k1.zig");
    pub const sha256 = @import("rv64_services/sha256.zig");
};
pub const recovery_abi = @import("recovery_abi.zig");
pub const runner = struct {
    pub const bulk_memcpy_call_buffer = @import("runner/bulk_memcpy_call_buffer.zig");
    pub const bulk_memcpy_session_tape = @import("runner/bulk_memcpy_session_tape.zig");
    pub const call_buffer = @import("runner/call_buffer.zig");
    pub const keccakf_call_buffer = @import("runner/keccakf_call_buffer.zig");
    pub const secp256k1_recover_call_buffer = @import("runner/secp256k1_recover_call_buffer.zig");
    pub const stack_swap_session_tape = @import("runner/stack_swap_session_tape.zig");
};
pub const testing = struct {
    pub const air = struct {
        pub const tests = struct {
            pub const secp256k1_affine_test = @import("air/tests/secp256k1_affine_test.zig");
        };
    };
    pub const inventory_source = @embedFile("tests/root.zig");
    pub const runner = struct {
        pub const c011_elf_test_support = @import("runner/c011_elf_test_support.zig");
        pub const c011_scalar_reference_test_support = @import("runner/c011_scalar_reference_test_support.zig");
    };
};

test {
    _ = @import("tests/root.zig");
}
