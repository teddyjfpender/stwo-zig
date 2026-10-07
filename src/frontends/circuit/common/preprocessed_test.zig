//! Port of `crates/circuit_common/src/preprocessed_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), plus preprocessed roots of the
//! same circuits computed by upstream `PreprocessedCircuit::preprocessed_root`.

const std = @import("std");
const core = @import("stwo_core");
const preprocessed = @import("preprocessed.zig");
const finalize = @import("finalize.zig");

const BinaryGate = preprocessed.BinaryGate;
const CircuitView = preprocessed.CircuitView;

/// Preprocessed roots from upstream `PreprocessedCircuit::preprocessed_root`
/// (release build of `crates/circuit_common` with feature `prover` at the
/// pinned commit), for `sample_circuit` and for `permutation_circuit`:
/// `sample_circuit` with its add and sub gates replaced by one permutation
/// gate `[2, 5] -> [30, 31]` and output gates `[0, 30, 2]`.
const UpstreamRoot = struct { circuit: enum { sample, permutation }, log_blowup: u32, root: []const u8 };
const upstream_roots = [_]UpstreamRoot{
    .{ .circuit = .sample, .log_blowup = 1, .root = "e12c23a2b831b5fdf1c70778dd50d6cfbd7aa80c4e417ef09a7191d70ea39900" },
    .{ .circuit = .sample, .log_blowup = 3, .root = "9263afc78200837c467f40b9813d6d2c68d601fdd234a09b9dd0d3b4279fe8c1" },
    .{ .circuit = .permutation, .log_blowup = 1, .root = "7f89ad03784d339ab3b6a78005bc19418013cad37bfcc09ed9f3836871ede800" },
    .{ .circuit = .permutation, .log_blowup = 3, .root = "dd576538329b069ee68694fae5edaa0324eadf42ad1517b96b581fe6a7c79051" },
};

/// Storage for `sample_circuit`: 2 eq, 8 qm31_ops (binary only), and 16
/// each of triple_xor, m31_to_u32 and blake_g_gate.
const SampleCircuit = struct {
    add: [2]BinaryGate = .{ .{ .in0 = 0, .in1 = 1, .out = 2 }, .{ .in0 = 3, .in1 = 4, .out = 5 } },
    sub: [2]BinaryGate = .{ .{ .in0 = 6, .in1 = 7, .out = 8 }, .{ .in0 = 9, .in1 = 10, .out = 11 } },
    mul: [2]BinaryGate = .{ .{ .in0 = 12, .in1 = 13, .out = 14 }, .{ .in0 = 15, .in1 = 16, .out = 17 } },
    pointwise_mul: [2]BinaryGate = .{ .{ .in0 = 18, .in1 = 19, .out = 20 }, .{ .in0 = 21, .in1 = 22, .out = 23 } },
    eq: [2]preprocessed.EqGate = .{ .{ .in0 = 0, .in1 = 1 }, .{ .in0 = 0, .in1 = 2 } },
    triple_xor: [16]preprocessed.TripleXorGate = undefined,
    m31_to_u32: [16]preprocessed.M31ToU32Gate = undefined,
    blake_g_gate: [16]preprocessed.BlakeGGate = undefined,
    output: [1]u32 = .{0},

    fn init() SampleCircuit {
        var self: SampleCircuit = .{};
        for (&self.triple_xor, 0..) |*gate, i| gate.* = .{ .input_a = 0, .input_b = 1, .input_c = 2, .out = @intCast(56 + i) };
        for (&self.blake_g_gate, 0..) |*gate, i| {
            gate.* = .{
                .input_a = 0,
                .input_b = 1,
                .input_c = 2,
                .input_d = 3,
                .input_f0 = 4,
                .input_f1 = 5,
                .out_base = @intCast(88 + 4 * i),
            };
        }
        for (&self.m31_to_u32, 0..) |*gate, i| gate.* = .{ .input = 0, .out = @intCast(72 + i) };
        return self;
    }

    fn view(self: *const SampleCircuit) CircuitView {
        return .{
            .n_vars = 152,
            .add = &self.add,
            .sub = &self.sub,
            .mul = &self.mul,
            .pointwise_mul = &self.pointwise_mul,
            .eq = &self.eq,
            .triple_xor = &self.triple_xor,
            .m31_to_u32 = &self.m31_to_u32,
            .blake_g_gate = &self.blake_g_gate,
            .output = &self.output,
        };
    }
};

test "preprocessed: test_preprocess_circuit column lengths" {
    const sample = SampleCircuit.init();
    var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, sample.view());
    defer circuit.deinit(std.testing.allocator);

    const expected = [_]usize{
        2,      2,      8,       8,       8,       8,     8,     8,     8,     8,
        16,     16,     16,      16,      16,      16,    16,    16,    16,    16,
        16,     16,     16,      16,      16,      16,    16,    16,    16,    256,
        256,    256,    16384,   16384,   16384,   65536, 65536, 65536, 65536, 262144,
        262144, 262144, 1048576, 1048576, 1048576,
    };
    try std.testing.expectEqual(expected.len, circuit.columns.len);
    for (expected, circuit.columns) |want, column| try std.testing.expectEqual(want, column.values.len);
    try std.testing.expectEqual(@as(usize, 8), circuit.first_permutation_row);
    try std.testing.expectEqual(@as(usize, 0), circuit.n_outputs);
}

test "preprocessed: layout_from_component_sizes matches the preprocessed trace" {
    const sample = SampleCircuit.init();
    const view = sample.view();
    var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, view);
    defer circuit.deinit(std.testing.allocator);
    const from_sizes = try preprocessed.ColumnLayout.fromComponentSizes(finalize.rawComponentSizes(view));
    const real = circuit.layout();
    try std.testing.expect(real.eql(&from_sizes));
}

test "preprocessed: fixed column values match the fixed layout" {
    const sample = SampleCircuit.init();
    var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, sample.view());
    defer circuit.deinit(std.testing.allocator);
    for (preprocessed.FIXED_COLUMNS) |fixed| {
        const values = circuit.columnValues(fixed.id) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 1) << @intCast(fixed.log_size), values.len);
    }
    const xor_8_2 = circuit.columnValues("bitwise_xor_8_2").?;
    const row: usize = (0xa5 << 8) | 0x3c;
    try std.testing.expectEqual(@as(u32, 0xa5 ^ 0x3c), xor_8_2[row].toU32());
    try std.testing.expectEqual(@as(u32, 0xa5), circuit.columnValues("bitwise_xor_8_0").?[row].toU32());
    try std.testing.expectEqual(@as(u32, 0x3c), circuit.columnValues("bitwise_xor_8_1").?[row].toU32());
    try std.testing.expectEqual(@as(u32, 40000), circuit.columnValues("seq_16").?[40000].toU32());
}

test "preprocessed: multiplicities count uses and blake_g outputs must agree" {
    var sample = SampleCircuit.init();
    var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, sample.view());
    defer circuit.deinit(std.testing.allocator);
    // Var 2 is the output of add #0: used by eq #1 and every triple_xor and
    // blake_g gate (input_c), 1 + 16 + 16 = 33 times.
    try std.testing.expectEqual(@as(u32, 33), circuit.columnValues("qm31_ops_mults").?[0].toU32());
    try std.testing.expectEqual(@as(u32, 1), circuit.columnValues("qm31_ops_add_flag").?[1].toU32());
    try std.testing.expectEqual(@as(u32, 1), circuit.columnValues("qm31_ops_sub_flag").?[2].toU32());
    try std.testing.expectEqual(@as(u32, 0), circuit.columnValues("qm31_ops_add_flag").?[2].toU32());

    // A lone use of out_b makes the four multiplicities disagree.
    sample.output[0] = 89;
    try std.testing.expectError(
        error.MultiplicityMismatch,
        preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, sample.view()),
    );
}

test "preprocessed: permutations lower to add rows through fresh wires" {
    var sample = SampleCircuit.init();
    const ends = [_]u32{2};
    const inputs = [_]u32{ 2, 5 };
    const outputs = [_]u32{ 30, 31 };
    const output_gates = [_]u32{ 0, 30, 2 };
    var view = sample.view();
    view.add = &.{};
    view.sub = &.{};
    view.permutation_ends = &ends;
    view.permutation_inputs = &inputs;
    view.permutation_outputs = &outputs;
    view.output = &output_gates;
    var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(std.testing.allocator, view);
    defer circuit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 4), circuit.first_permutation_row);
    try std.testing.expectEqual(@as(usize, 2), circuit.n_outputs);
    const in0 = circuit.columnValues("qm31_ops_in0_address").?;
    const in1 = circuit.columnValues("qm31_ops_in1_address").?;
    const out = circuit.columnValues("qm31_ops_out_address").?;
    const mults = circuit.columnValues("qm31_ops_mults").?;
    const add_flag = circuit.columnValues("qm31_ops_add_flag").?;
    // Rows 4..8: every pair of one gate goes through the gate's single fresh
    // wire `n_vars + g` (upstream output: in1 [2, 152, 5, 152], out
    // [152, 30, 152, 31], mults [1, 1, 1, 0]).
    const expected_rows = [_][4]u32{ .{ 2, 152, 1, 1 }, .{ 152, 30, 1, 1 }, .{ 5, 152, 1, 1 }, .{ 152, 31, 0, 1 } };
    for (expected_rows, 4..) |want, row| {
        try std.testing.expectEqual(@as(u32, 0), in0[row].toU32());
        try std.testing.expectEqual(want[0], in1[row].toU32());
        try std.testing.expectEqual(want[1], out[row].toU32());
        try std.testing.expectEqual(want[2], mults[row].toU32());
        try std.testing.expectEqual(want[3], add_flag[row].toU32());
    }
}

const permutation_ends = [_]u32{2};
const permutation_inputs = [_]u32{ 2, 5 };
const permutation_outputs = [_]u32{ 30, 31 };
const permutation_output_gates = [_]u32{ 0, 30, 2 };

fn permutationView(sample: *const SampleCircuit) CircuitView {
    var view = sample.view();
    view.add = &.{};
    view.sub = &.{};
    view.permutation_ends = &permutation_ends;
    view.permutation_inputs = &permutation_inputs;
    view.permutation_outputs = &permutation_outputs;
    view.output = &permutation_output_gates;
    return view;
}

test "preprocessed: preprocessed_root matches upstream at blowup 1 and 3" {
    const allocator = std.testing.allocator;
    const sample = SampleCircuit.init();
    for (upstream_roots) |case| {
        const view = switch (case.circuit) {
            .sample => sample.view(),
            .permutation => permutationView(&sample),
        };
        var circuit = try preprocessed.PreprocessedCircuit.fromCircuit(allocator, view);
        defer circuit.deinit(allocator);
        const root = try circuit.preprocessedRoot(allocator, case.log_blowup);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.root);
        try std.testing.expectEqualSlices(u8, &expected, &root);
    }
}

test "preprocessed: malformed circuit views fail closed" {
    const allocator = std.testing.allocator;
    var sample = SampleCircuit.init();
    const n_vars = sample.view().n_vars;

    // A gate output past `n_vars`.
    const bad_add = [_]BinaryGate{.{ .in0 = 0, .in1 = 1, .out = @intCast(n_vars) }};
    var view = sample.view();
    view.add = &bad_add;
    try std.testing.expectError(error.VariableOutOfRange, preprocessed.PreprocessedCircuit.fromCircuit(allocator, view));

    // A blake_g gate whose last output (`out_base + 3`) is past `n_vars`.
    sample.blake_g_gate[3].out_base = @intCast(n_vars - 3);
    try std.testing.expectError(error.VariableOutOfRange, preprocessed.PreprocessedCircuit.fromCircuit(allocator, sample.view()));
    sample = SampleCircuit.init();

    // Permutation CSR layouts: decreasing ends, a short final end, unpaired
    // outputs, and an out-of-range output.
    const decreasing = [_]u32{ 2, 1, 2 };
    const short = [_]u32{1};
    const unpaired = [_]u32{30};
    const out_of_range = [_]u32{ 30, @intCast(n_vars) };
    inline for (.{
        .{ &decreasing, &permutation_outputs },
        .{ &short, &permutation_outputs },
        .{ &permutation_ends, &unpaired },
        .{ &permutation_ends, &out_of_range },
    }) |case| {
        var malformed = permutationView(&sample);
        malformed.permutation_ends = case[0];
        malformed.permutation_outputs = case[1];
        try std.testing.expectError(error.VariableOutOfRange, preprocessed.PreprocessedCircuit.fromCircuit(allocator, malformed));
    }
}

test "preprocessed: private SHA boundary adds one canonical Gate yield per limb" {
    const allocator = std.testing.allocator;
    const sample = SampleCircuit.init();
    var add: [58]BinaryGate = undefined;
    var boundary = preprocessed.ShaBoundary{ .addresses = undefined };
    for (&add, 0..) |*gate, index| {
        gate.* = .{ .in0 = 0, .in1 = 1, .out = @intCast(152 + index) };
        if (index < boundary.addresses.len) boundary.addresses[index] = gate.out;
    }
    var view = sample.view();
    view.add = &add;
    view.n_vars = 210;
    var ordinary = try preprocessed.PreprocessedCircuit.fromCircuit(allocator, view);
    defer ordinary.deinit(allocator);
    var joined = try preprocessed.PreprocessedCircuit.fromCircuitWithShaBoundary(allocator, view, boundary);
    defer joined.deinit(allocator);
    try std.testing.expect(joined.sha_boundary != null);
    try std.testing.expectEqualDeep(boundary, joined.sha_boundary.?);
    const output_addresses = joined.columnValues("qm31_ops_out_address").?;
    const old_mult = ordinary.columnValues("qm31_ops_mults").?;
    const new_mult = joined.columnValues("qm31_ops_mults").?;
    for (output_addresses, old_mult, new_mult) |address, before, after| {
        const consumed = std.mem.indexOfScalar(u32, &boundary.addresses, address.toU32()) != null;
        try std.testing.expectEqual(before.toU32() + @as(u32, @intFromBool(consumed)), after.toU32());
    }
    for (ordinary.columns, joined.columns) |left, right| {
        if (std.mem.eql(u8, left.id, "qm31_ops_mults")) continue;
        try std.testing.expectEqualSlices(core.fields.m31.M31, left.values, right.values);
    }

    var duplicate = boundary;
    duplicate.addresses[1] = duplicate.addresses[0];
    try std.testing.expectError(error.DuplicateShaPrivateBoundary, preprocessed.PreprocessedCircuit.fromCircuitWithShaBoundary(allocator, view, duplicate));
    const public_output = [_]u32{boundary.addresses[0]};
    var public_view = view;
    public_view.output = &public_output;
    try std.testing.expectError(error.PublicShaPrivateBoundary, preprocessed.PreprocessedCircuit.fromCircuitWithShaBoundary(allocator, public_view, boundary));
    var missing = boundary;
    missing.addresses[0] = 3;
    try std.testing.expectError(error.InvalidShaBoundaryProducer, preprocessed.PreprocessedCircuit.fromCircuitWithShaBoundary(allocator, view, missing));
}
