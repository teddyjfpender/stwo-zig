//! Backend-inclusive test root for the canonical zig_protocol_test.py runner.
//! The ordinary frontend frontier root retains its backend-free dependency set.
test {
    _ = @import("air/memory_commitment/poseidon2_narrow_degree3_v1_test.zig");
    _ = @import("air/memory_commitment/poseidon2_narrow_proof_v1_test.zig");
    _ = @import("air/memory_commitment/poseidon2_narrow_backend_v1_test.zig");
}
