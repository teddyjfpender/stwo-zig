//! Opt-in direct-original verifier qualification with canonical package identity.
test {
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/admission_test.zig");
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/saved_metadata_test.zig");
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/retained_qualification.zig");
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/qualification.zig");
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/native_qualification.zig");
    _ = @import("integrations/circuit_cpu/riscv_originals_v1/block_pipeline_test.zig");
}
