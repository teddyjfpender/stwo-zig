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
        // Produces `zig-out/committed-trace/*.json` for the independent Python
        // row checker; it is a mutation suite because two of its three exports
        // are forgeries and it asserts the pipeline's verdict on each.
        _ = @import("committed_trace_export_test.zig");
        _ = @import("divisor_byte_range_soundness_test.zig");
        _ = @import("jalr_target_soundness_test.zig");
        _ = @import("load_sign_soundness_test.zig");
        _ = @import("malicious_witness_test.zig");
        _ = @import("main_witness_rejection_test.zig");
        // The production-path malicious-prover suite: the shared transaction
        // harness and its four attack classes (issue #131).
        _ = @import("malicious_prover_harness.zig");
        _ = @import("malicious_prover_completion_test.zig");
        _ = @import("malicious_prover_forged_output_test.zig");
        _ = @import("malicious_prover_skipped_test.zig");
        _ = @import("malicious_prover_stale_read_test.zig");
        _ = @import("mulh_soundness_test.zig");
        _ = @import("opcode_family_committed_soundness_test.zig");
        _ = @import("partial_store_soundness_test.zig");
        _ = @import("read_only_access_soundness_test.zig");
        _ = @import("shift_sign_soundness_test.zig");
    }
    // The Sail-derived operand-class corpus and its honest sweep: the
    // corpus's structural self-checks are imported by the sweep module.
    _ = @import("operand_class_sweep_test.zig");
    _ = @import("proof_admission_test.zig");
    _ = @import("prover_test.zig");
    _ = @import("public_relation_binding_test.zig");
    _ = @import("transcript_path_test.zig");
    _ = @import("typed_poseidon2_proof_equivalence_test.zig");
    // The extraction differential guards every uniqueness verdict: if the IR
    // stops matching `Semantics(QM31)`, the solver is answering about a system
    // we no longer ship. Unregistered it never ran, so the guard was nominal.
    _ = @import("uniqueness_ir_test.zig");
    _ = @import("uniqueness_counterexample_test.zig");
    _ = @import("witness_rigidity_test.zig");
    _ = @import("typed_lui_witness_corpus_test.zig");
    _ = @import("typed_jalr_witness_corpus_test.zig");
    _ = @import("typed_jal_witness_corpus_test.zig");
    _ = @import("typed_branch_eq_witness_corpus_test.zig");
    _ = @import("typed_branch_lt_witness_corpus_test.zig");
    _ = @import("typed_lui_witness_authority_test.zig");
    _ = @import("typed_base_alu_imm_witness_authority_test.zig");
    _ = @import("typed_base_alu_reg_witness_authority_test.zig");
    _ = @import("typed_div_witness_authority_test.zig");
    _ = @import("typed_fence_witness_authority_test.zig");
    _ = @import("typed_auipc_witness_authority_test.zig");
    _ = @import("typed_jalr_witness_authority_test.zig");
    _ = @import("typed_jal_witness_authority_test.zig");
    _ = @import("typed_branch_eq_witness_authority_test.zig");
    _ = @import("typed_branch_lt_witness_authority_test.zig");
    _ = @import("main_trace_planned_proof_test.zig");
    _ = @import("recursion_poseidon_leaf_test.zig");
    _ = @import("recursion_control_typed_proof_test.zig");
    _ = @import("typed_load_store_witness_authority_test.zig");
    _ = @import("typed_lt_imm_witness_corpus_test.zig");
    _ = @import("typed_lt_imm_witness_authority_test.zig");
    _ = @import("typed_lt_reg_witness_corpus_test.zig");
    _ = @import("typed_lt_reg_witness_authority_test.zig");
    _ = @import("typed_mul_witness_authority_test.zig");
    _ = @import("typed_mulh_witness_corpus_test.zig");
    _ = @import("typed_mulh_witness_authority_test.zig");
    _ = @import("typed_shifts_imm_witness_corpus_test.zig");
    _ = @import("typed_shifts_imm_witness_authority_test.zig");
    _ = @import("typed_shifts_reg_witness_corpus_test.zig");
    _ = @import("typed_shifts_reg_witness_authority_test.zig");
}
