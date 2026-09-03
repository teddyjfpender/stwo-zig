//! CPU instantiation of the nonproduction bulk-memcpy proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
const harness = frontend.testing.bulk_memcpy_proof_harness_v1;
const lifted_composition = frontend.testing.bulk_memcpy_lifted_composition_diagnostic_v1;

test "bulk memcpy heterogeneous composition matches canonical lift, PCS masks, and split two" {
    const result = try lifted_composition.run(std.testing.allocator);
    if (result.caller_direct_first_mismatch) |mismatch| {
        std.debug.print(
            "bulk memcpy caller direct mismatch: index={d} class={s}\n",
            .{ mismatch.index, @tagName(mismatch.classification) },
        );
    }
    try std.testing.expectEqual(lifted_composition.Mismatch.none, result.firstMismatch());
    try result.validate();
}

test "bulk memcpy candidate proves, decodes, and cold fresh-verifies" {
    const receipt = try harness.exerciseTiny(Engine, std.testing.allocator);
    try receipt.validate();
    try std.testing.expect(receipt.call_relation_closed);
    try std.testing.expect(receipt.external_base_tables_required);
    try std.testing.expect(!receipt.production_eligible);
}
