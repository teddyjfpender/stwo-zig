//! Reader of the oracle's `STWZCIRC/1` circuit-prover inputs
//! (`tools/stwo-circuit-oracle-rs/src/multiverifier_inputs.rs`): a finalized
//! circuit's gate lists and its value table.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const QM31 = core.fields.qm31.QM31;
const preprocessed = circuit.common.preprocessed;

pub const magic = "STWZCIRC";
pub const version: u32 = 1;

/// The decoded inputs; every slice lives in `arena`.
pub const Inputs = struct {
    arena: std.heap.ArenaAllocator,
    view: preprocessed.CircuitView,
    values: []QM31,

    pub fn deinit(self: *Inputs) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn int(self: *Reader) !u32 {
        if (self.bytes.len - self.at < 4) return error.TruncatedInputs;
        const value = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
        self.at += 4;
        return value;
    }

    fn ints(self: *Reader, out: []u32) !void {
        for (out) |*value| value.* = try self.int();
    }
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Inputs {
    if (bytes.len < magic.len or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.InvalidInputsMagic;
    var reader = Reader{ .bytes = bytes, .at = magic.len };
    if (try reader.int() != version) return error.UnsupportedInputsVersion;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const n_vars = try reader.int();
    var counts: [10]u32 = undefined;
    try reader.ints(&counts);

    var binary: [4][]preprocessed.BinaryGate = undefined;
    for (&binary, counts[0..4]) |*gates, count| {
        gates.* = try a.alloc(preprocessed.BinaryGate, count);
        for (gates.*) |*gate| gate.* = .{ .in0 = try reader.int(), .in1 = try reader.int(), .out = try reader.int() };
    }
    const eq = try a.alloc(preprocessed.EqGate, counts[4]);
    for (eq) |*gate| gate.* = .{ .in0 = try reader.int(), .in1 = try reader.int() };
    const triple_xor = try a.alloc(preprocessed.TripleXorGate, counts[5]);
    for (triple_xor) |*gate| gate.* = .{
        .input_a = try reader.int(),
        .input_b = try reader.int(),
        .input_c = try reader.int(),
        .out = try reader.int(),
    };
    const m31_to_u32 = try a.alloc(preprocessed.M31ToU32Gate, counts[6]);
    for (m31_to_u32) |*gate| gate.* = .{ .input = try reader.int(), .out = try reader.int() };
    const blake_g_gate = try a.alloc(preprocessed.BlakeGGate, counts[7]);
    for (blake_g_gate) |*gate| {
        var fields: [10]u32 = undefined;
        try reader.ints(&fields);
        gate.* = .{
            .input_a = fields[0],
            .input_b = fields[1],
            .input_c = fields[2],
            .input_d = fields[3],
            .input_f0 = fields[4],
            .input_f1 = fields[5],
            .out_base = fields[6],
        };
        // The builder allocates the four outputs consecutively.
        if (!std.mem.eql(u32, fields[6..10], &gate.outputs())) return error.InvalidBlakeGGate;
    }
    var ends: std.ArrayListUnmanaged(u32) = .empty;
    var inputs: std.ArrayListUnmanaged(u32) = .empty;
    var outputs: std.ArrayListUnmanaged(u32) = .empty;
    for (0..counts[8]) |_| {
        const n_inputs = try reader.int();
        for (0..n_inputs) |_| try inputs.append(a, try reader.int());
        const n_outputs = try reader.int();
        if (n_outputs != n_inputs) return error.InvalidPermutation;
        for (0..n_outputs) |_| try outputs.append(a, try reader.int());
        try ends.append(a, @intCast(inputs.items.len));
    }
    const output = try a.alloc(u32, counts[9]);
    try reader.ints(output);

    const values = try a.alloc(QM31, try reader.int());
    for (values) |*value| {
        var limbs: [4]u32 = undefined;
        try reader.ints(&limbs);
        for (limbs) |limb| if (limb >= core.fields.m31.Modulus) return error.NonCanonicalValue;
        value.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    if (reader.at != bytes.len) return error.TrailingInputBytes;
    return .{
        .arena = arena,
        .view = .{
            .n_vars = n_vars,
            .add = binary[0],
            .sub = binary[1],
            .mul = binary[2],
            .pointwise_mul = binary[3],
            .eq = eq,
            .triple_xor = triple_xor,
            .m31_to_u32 = m31_to_u32,
            .blake_g_gate = blake_g_gate,
            .permutation_ends = ends.items,
            .permutation_inputs = inputs.items,
            .permutation_outputs = outputs.items,
            .output = output,
        },
        .values = values,
    };
}
