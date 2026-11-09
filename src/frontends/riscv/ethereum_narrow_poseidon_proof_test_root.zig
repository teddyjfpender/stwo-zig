//! Backend-neutral narrow Poseidon semantic and export tests.
//! The ordinary frontend frontier root retains its backend-free dependency set.
test {
    _ = @import("stwo_riscv_testing").modules.cases_air_memory_commitment_poseidon2_narrow_degree3_test;
    _ = @import("stwo_riscv_testing").modules.cases_air_memory_commitment_poseidon2_narrow_backend_test;
}
