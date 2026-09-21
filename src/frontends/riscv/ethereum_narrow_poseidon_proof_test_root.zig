//! Backend-neutral narrow Poseidon semantic and export tests.
//! The ordinary frontend frontier root retains its backend-free dependency set.
test {
    _ = @import("air/memory_commitment/poseidon2_narrow_degree3_v1_test.zig");
    _ = @import("air/memory_commitment/poseidon2_narrow_backend_v1_test.zig");
}
