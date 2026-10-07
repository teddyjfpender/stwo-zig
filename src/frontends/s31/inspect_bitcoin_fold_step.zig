//! Witness-free gate and AIR-row inspection for the direct Bitcoin fold step.
//! This measures only the header transition kernel, not the recursive verifier.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const s31 = @import("stwo_s31_prototype");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var ctx = try circuit.builder.Context(circuit.builder.NoValue).init(allocator, 8);
    defer ctx.deinit();
    var prior_root: [8]circuit.builder.Var = undefined;
    for (&prior_root) |*wire| wire.* = try ctx.guessM31(.{});
    const output = try s31.bitcoin_fold_step.constrainMainnetPowLinkStep(
        circuit.builder.NoValue,
        &ctx,
        [_]circuit.builder.NoValue{.{}} ** 16,
        [_]circuit.builder.NoValue{.{}} ** 40,
        prior_root,
    );
    try ctx.setOutputs(&output);
    try ctx.finalize(false);
    const raw = circuit.common.finalize.rawComponentSizes(circuit.common.preprocessed.CircuitView.fromBuilder(&ctx.circuit));
    const padded = raw.map(circuit.common.finalize.paddedSize);
    std.debug.print(
        "{{\"schema\":\"s31-bitcoin-fold-step-inspection-v1\",\"raw_vars\":{d},\"raw\":{{\"eq\":{d},\"qm31_ops\":{d},\"m31_to_u32\":{d},\"triple_xor\":{d},\"blake_g\":{d}}},\"padded\":{{\"eq\":{d},\"qm31_ops\":{d},\"m31_to_u32\":{d},\"triple_xor\":{d},\"blake_g\":{d}}}}}\n",
        .{ ctx.circuit.n_vars, raw.eq, raw.qm31_ops, raw.m31_to_u32, raw.triple_xor, raw.blake_g_gate, padded.eq, padded.qm31_ops, padded.m31_to_u32, padded.triple_xor, padded.blake_g_gate },
    );
}
