test {
    _ = @import("stwo_riscv_isa").modules.authority;
    _ = @import("stwo_riscv_isa").modules.custom0;
    _ = @import("stwo_riscv_isa").modules.decode;
    _ = @import("stwo_riscv_isa").modules.execution_profile;
    _ = @import("stwo_riscv_frontend").modules.isa_ethereum_signer_recovery;
    _ = @import("stwo_riscv_isa").modules.implementation;
    _ = @import("stwo_riscv_isa").modules.profile;
}
