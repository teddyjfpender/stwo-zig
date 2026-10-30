const Owner = @import("integrations/riscv_cuda/hybrid_framework_composition_v1.zig");
test "CUDA framework composition full lifecycle semantic" {
    _ = &Owner.Owner.open;
    _ = &Owner.Owner.deinit;
    _ = &Owner.Owner.executor;
    _ = &force;
}
fn force(o: *Owner.Owner, original: []const @import("stwo_prover_engine").air.component_prover.ComponentProver, normalized: []const @import("stwo_prover_engine").air.component_prover.ComponentProver) !void {
    const e = o.executor();
    const stage = try e.bind(e.context, original, normalized);
    defer e.release(e.context);
    var output: @import("stwo_prover_engine").secure_column.SecureColumnByCoords = undefined;
    _ = try stage.evaluate(stage.context, @import("std").heap.page_allocator, @import("stwo_core").fields.qm31.QM31.one(), 3, 1, undefined, &output);
}
