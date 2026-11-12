//! Complete literal discovery for this owner; original focused exclusions are retained.
test {
    _ = @import("../air/sha256_compression.zig");
    _ = @import("../air/sha256_compression_rows.zig");
    _ = @import("../air/sha256_relations.zig");
    _ = @import("../air/tests/bulk_memcpy_caller_candidate_test.zig");
    _ = @import("../air/tests/keccakf_authority_test.zig");
    _ = @import("../air/tests/keccakf_relations_test.zig");
    _ = @import("../air/tests/keccakf_witness_test.zig");
    _ = @import("../air/tests/secp256k1_affine_test.zig");
    _ = @import("../air/tests/secp256k1_ecdsa_direct_test.zig");
    _ = @import("../air/tests/secp256k1_field_test.zig");
    _ = @import("../air/tests/secp256k1_linear_direct_test.zig");
    _ = @import("../air/tests/secp256k1_mul_direct_test.zig");
    _ = @import("../air/tests/secp256k1_point_direct_test.zig");
    _ = @import("../air/tests/secp256k1_recovery_direct_test.zig");
    _ = @import("../air/tests/secp256k1_scalar_direct_test.zig");
    _ = @import("../air/tests/secp256k1_split_direct_test.zig");
    _ = @import("../air/tests/secp256k1_table_direct_test.zig");
    _ = @import("../recovery_abi.zig");
    _ = @import("../runner/call_buffer.zig");
    _ = @import("../runner/secp256k1_recover_call_buffer.zig");
    _ = @import("../rv64_services/arith256.zig");
    _ = @import("../rv64_services/secp256k1.zig");
    _ = @import("../rv64_services/sha256.zig");
    _ = @import("contracts.zig");
}
