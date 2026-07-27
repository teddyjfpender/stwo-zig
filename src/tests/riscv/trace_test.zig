//! Exhaustive RISC-V release tests, consumed by `test-riscv-prover` and CP-13.

const test_options = @import("test_options");

test {
    _ = @import("unit_test.zig");
    // The row oracle and the committed-layout map are consumed by
    // `witness_rigidity_test.zig` as well as by the mutation suites, so their
    // self-checks run unconditionally. A file's tests are only collected when
    // something names it inside a `test` block; a file-scope `@import` of it is
    // not enough.
    _ = @import("committed_row_layout.zig");
    _ = @import("row_admissibility.zig");
    if (test_options.riscv_committed_mutations) {
        // The forgery harness, the guest wrapper and the DIVU guest each carry
        // the self-checks that make the suites below trustworthy: a broken
        // fixture would satisfy "the forgery is rejected" vacuously.
        _ = @import("committed_forgery_harness.zig");
        _ = @import("guest_elf_fixture.zig");
        _ = @import("divu_elf_fixture.zig");
        _ = @import("auipc_alias_soundness_test.zig");
        _ = @import("bitwise_result_soundness_test.zig");
        _ = @import("divisor_byte_range_soundness_test.zig");
        _ = @import("jalr_target_soundness_test.zig");
        _ = @import("load_sign_soundness_test.zig");
        _ = @import("malicious_witness_test.zig");
        _ = @import("main_witness_rejection_test.zig");
        _ = @import("mulh_soundness_test.zig");
        _ = @import("partial_store_soundness_test.zig");
        _ = @import("read_only_access_soundness_test.zig");
        _ = @import("shift_sign_soundness_test.zig");
    }
    _ = @import("proof_admission_test.zig");
    _ = @import("prover_test.zig");
    _ = @import("public_relation_binding_test.zig");
    _ = @import("transcript_path_test.zig");
    _ = @import("witness_rigidity_test.zig");
}
