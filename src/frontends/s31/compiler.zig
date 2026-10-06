//! Lower the normalized S31 DAG into the existing Stwo circuit builder.
//! Topology and value builds run the same code; witness values cannot alter
//! gate selection or order.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const program_mod = @import("program.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const N_RESERVED = circuit.common.component_list.N_RESERVED;

pub fn compile(comptime V: type, allocator: std.mem.Allocator, source: program_mod.Program, input: []const u16) !circuit.builder.Context(V) {
    try source.validate(allocator);
    if (input.len != source.lanes) return error.InputLengthMismatch;
    var ctx = try circuit.builder.Context(V).init(allocator, N_RESERVED);
    errdefer ctx.deinit();
    const scratch = ctx.scratch();
    var values = std.StringHashMapUnmanaged([]Var){};
    defer values.deinit(scratch);

    const n_packed: usize = input.len / 4;
    const packed_input = try scratch.alloc(Var, n_packed);
    var input_lanes: [4]Var = undefined;
    for (packed_input, 0..) |*packed_wire, group| {
        var lanes: [4]Var = undefined;
        for (&lanes, 0..) |*lane, offset| {
            const word = input[4 * group + offset];
            const value = circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(word)));
            const guessed = try circuit.builder.wrappers.guessU16(V, &ctx, circuit.builder.wrappers.U16Wrapper(V).newUnsafe(value));
            lane.* = guessed.get();
            input_lanes[4 * group + offset] = lane.*;
        }
        packed_wire.* = try circuit.builder.ops.fromPartialEvals(V, &ctx, lanes);
    }
    try values.put(scratch, source.input, packed_input);

    for (source.nodes) |node| {
        const lhs = values.get(node.lhs) orelse return error.UnknownOperand;
        const rhs = if (node.rhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const out = try scratch.alloc(Var, n_packed);
        const scalar = if (node.constant) |c| try ctx.constant(QM31.fromM31(M31.fromCanonical(c), M31.fromCanonical(c), M31.fromCanonical(c), M31.fromCanonical(c))) else null;
        for (out, lhs, 0..) |*slot, a, index| slot.* = switch (node.op) {
            .add => try ctx.add(a, rhs.?[index]),
            .mul => try ctx.pointwiseMul(a, rhs.?[index]),
            .add_const => try ctx.add(a, scalar.?),
            .mul_const => try ctx.pointwiseMul(a, scalar.?),
            .repeat_square_add => blk: {
                var value = a;
                for (0..node.rounds.?) |_| {
                    value = try ctx.pointwiseMul(value, value);
                    value = try ctx.add(value, scalar.?);
                }
                break :blk value;
            },
        };
        try values.put(scratch, node.name, out);
    }

    const result = values.get(source.result) orelse return error.UnknownResult;
    var outputs: [N_RESERVED]Var = undefined;
    comptime std.debug.assert(N_RESERVED == 8);
    @memcpy(outputs[0..4], &input_lanes);
    for (0..4) |lane| {
        const one = circuit.builder.simd.Simd.fromPacked(result[0..1], 4);
        const unpacked = try circuit.builder.simd.unpackIdx(V, &ctx, one, lane);
        outputs[4 + lane] = (try circuit.builder.blake.m31ToU32(V, &ctx, unpacked)).get();
    }
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    return ctx;
}

test "S31 source compiles to identical value and topology gate counts" {
    const source =
        \\{"version":0,"name":"affine4","lanes":4,"input":"x","nodes":[{"name":"scaled","op":"mul_const","lhs":"x","constant":7},{"name":"y","op":"add_const","lhs":"scaled","constant":11}],"result":"y","public_abi":"u32x8_input_result"}
    ;
    var parsed = try program_mod.parse(std.testing.allocator, source);
    defer parsed.deinit();
    var with_values = try compile(QM31, std.testing.allocator, parsed.value, &.{ 1, 2, 3, 65535 });
    defer with_values.deinit();
    var topology = try compile(circuit.builder.NoValue, std.testing.allocator, parsed.value, &.{ 0, 0, 0, 0 });
    defer topology.deinit();
    try std.testing.expect(std.meta.eql(with_values.gate_counts, topology.gate_counts));
    try std.testing.expectEqual(with_values.circuit.nQm31OpsRows(), topology.circuit.nQm31OpsRows());
    try std.testing.expect(try with_values.isCircuitValid());
}
