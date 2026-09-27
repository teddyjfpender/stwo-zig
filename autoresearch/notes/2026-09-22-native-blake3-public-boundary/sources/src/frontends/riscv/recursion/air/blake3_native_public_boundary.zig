//! Existing public-sum arithmetic evaluated from a verified native BLAKE3 capture.
const std = @import("std");
const core = @import("stwo_core");
const verifier = @import("../../prover/verifier.zig");
const authority = @import("../segment_public_native_sum_authority_v2.zig");
const arithmetic = @import("../arithmetic_circuit.zig");
const bytes = @import("../segment_register_byte_layout_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    circuit: arithmetic.Circuit,
    graph: authority.NativeOwnedGraph,
    evaluation: arithmetic.Evaluation,
    inputs: []Q,
    bindings: []authority.InputSourceV2,
    pub fn deinit(self: *Prepared) void {
        self.evaluation.deinit();
        self.graph.deinit();
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn evaluate(self: *const Prepared, a: std.mem.Allocator, inputs: []const Q) !arithmetic.Evaluation {
        return evaluateChecked(a, &self.circuit, inputs);
    }
};
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine)) !Prepared {
    comptime {
        if (Engine.Hasher != @import("../blake3_engine_protocol.zig").Hasher) @compileError("native boundary adapter requires BLAKE3 capture");
    }
    try capture.validate();
    const view = try capture.public_data.data.authenticatedView();
    const layout = try bytes.MemoryLayout.init(&view);
    var authored = try authority.buildNativeGraph(a, &view);
    errdefer authored.circuit.deinit();
    var graph = try authority.NativeOwnedGraph.init(a, &authored.circuit);
    errdefer graph.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const input_count = authored.circuit.inputNodes().len;
    const inputs = try temp.alloc(Q, input_count);
    const bindings = try temp.alloc(authority.InputSourceV2, input_count);
    const sums = capture.native_public_sums.sums;
    const domain_sums = [_]Q{ sums.registers_state, sums.memory_access, sums.program_access, sums.merkle };
    const words = capture.public_data.data.words();
    for (inputs, bindings, 0..) |*input, *source, i| {
        source.* = try authority.nativeInputSource(@intCast(words.len), @intCast(layout.memoryByteCount()), i);
        const value: M = switch (source.*) {
            .wire_word => |index| words[index],
            .published_sum_word => |c| domain_sums[@intFromEnum(c.domain)].toM31Array()[c.limb],
            .published_total_word => |c| capture.native_public_sums.total.toM31Array()[c.limb],
            .native_challenge_word => |c| capture.vm_air.relation_draws[@as(usize, @intFromEnum(c.relation)) * 2 + c.limb / 4].toM31Array()[c.limb % 4],
            .register_byte => |index| bytes.value(words, index),
            .memory_byte => |index| layout.value(words, bytes.BYTE_COUNT + index),
            .memory_selector => |index| M.fromCanonical(@intFromBool(layout.value(words, bytes.BYTE_COUNT + index).v != 0)),
        };
        input.* = Q.fromBase(value);
    }
    const evaluation = try evaluateChecked(a, &authored.circuit, inputs);
    return .{ .arena = arena, .circuit = authored.circuit, .graph = graph, .evaluation = evaluation, .inputs = inputs, .bindings = bindings };
}
fn evaluateChecked(a: std.mem.Allocator, circuit: *const arithmetic.Circuit, inputs: []const Q) !arithmetic.Evaluation {
    try circuit.validate();
    var evaluation = try circuit.evaluate(a, inputs);
    errdefer evaluation.deinit();
    if (!try circuit.outputsAreZero(evaluation.values)) return error.InvalidNativePublicBoundary;
    return evaluation;
}
