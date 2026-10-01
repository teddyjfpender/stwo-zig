//! Byte parity of the CUDA paired-fraction producer with the circuit CPU
//! lookup definitions for all eleven components.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const SecureField = cuda.abi.field.SecureField;
const K = circuit.witness.components;
const Lookup = K.Lookup;
const trace = circuit.witness.trace;
const interaction = cuda.runtime.stages.circuit_interaction;

extern "c" fn stwo_circuit_interaction_fractions_emulate(
    component: u32,
    rows: u32,
    pp_host: [*]const [*]const u32,
    pp_count: u32,
    base_host: [*]const [*]const u32,
    base_count: u32,
    out_host: [*]const [*]u32,
    out_count: u32,
    powers: [*]const SecureField,
    power_count: u32,
    z: *const SecureField,
    denominators: [*]SecureField,
    denominator_count: u32,
    error_flag: *u32,
) c_int;

extern "c" fn stwo_circuit_lookup_sum_emulate(
    claims: [*]const SecureField,
    outputs: ?[*]const SecureField,
    output_count: u32,
    powers: [*]const SecureField,
    power_count: u32,
    z: *const SecureField,
    error_flag: *u32,
) c_int;

fn secure(value: QM31) SecureField {
    const parts = value.toM31Array();
    return .{ .a = parts[0].toU32(), .b = parts[1].toU32(), .c = parts[2].toU32(), .d = parts[3].toU32() };
}

fn expectSecure(expected: QM31, actual: SecureField) !void {
    const want = secure(expected);
    try std.testing.expectEqual(want.a, actual.a);
    try std.testing.expectEqual(want.b, actual.b);
    try std.testing.expectEqual(want.c, actual.c);
    try std.testing.expectEqual(want.d, actual.d);
}

fn verifyPairs(
    elements: *const trace.LookupElements,
    lookups: []const Lookup,
    row: usize,
    output: *const [52][16]u32,
    denominators: []const SecureField,
) !void {
    for (0..(lookups.len + 1) / 2) |column| {
        const first = &lookups[2 * column];
        const d0 = elements.combine(first.values());
        const numerator, const denominator = if (2 * column + 1 < lookups.len) blk: {
            const second = &lookups[2 * column + 1];
            const d1 = elements.combine(second.values());
            break :blk .{
                d1.mulM31(first.numerator).add(d0.mulM31(second.numerator)),
                d0.mul(d1),
            };
        } else .{ QM31.fromBase(first.numerator), d0 };
        const parts = numerator.toM31Array();
        for (parts, 0..) |part, limb|
            try std.testing.expectEqual(part.toU32(), output[4 * column + limb][row]);
        try expectSecure(denominator, denominators[column * 16 + row]);
    }
}

fn runOracle(
    component: usize,
    row: usize,
    pp: *const [11][16]u32,
    base: *const [52][16]u32,
    elements: *const trace.LookupElements,
    output: *const [52][16]u32,
    denominators: []const SecureField,
) !void {
    var p: [11]M31 = undefined;
    var c: [52]M31 = undefined;
    for (&p, 0..) |*entry, index| entry.* = M31.fromCanonical(pp[index][row]);
    for (&c, 0..) |*entry, index| entry.* = M31.fromCanonical(base[index][row]);
    switch (component) {
        0 => try verifyPairs(elements, &K.eq.lookups(&c[0..4].*, .{ .in0 = p[0], .in1 = p[1] }), row, output, denominators),
        1 => try verifyPairs(elements, &K.qm31_ops.lookups(&c[0..12].*, .{ .in0 = p[4], .in1 = p[5], .out = p[6], .mults = p[7] }), row, output, denominators),
        2 => try verifyPairs(elements, &K.triple_xor.lookups(&c[0..20].*, .{ .in0 = p[0], .in1 = p[1], .in2 = p[2], .out = p[3], .mults = p[4] }), row, output, denominators),
        3 => try verifyPairs(elements, &K.m31_to_u32.lookups(&c[0..4].*, .{ .input = p[0], .output = p[1], .mults = p[2] }), row, output, denominators),
        4 => try verifyPairs(elements, &K.blake_g_gate.lookups(&c[0..52].*, .{
            .inputs = p[0..6].*,
            .outputs = p[6..10].*,
            .mults = p[10],
        }), row, output, denominators),
        5, 7, 8, 9 => {
            const table = switch (component) {
                5 => K.xor_8,
                7 => K.xor_4,
                8 => K.xor_7,
                else => K.xor_9,
            };
            var lookups: [2]Lookup = undefined;
            K.xorTableLookups(table, p[0..3].*, c[0..table.relations.len], lookups[0..table.relations.len]);
            try verifyPairs(elements, lookups[0..table.relations.len], row, output, denominators);
        },
        6 => {
            var lookups: [16]Lookup = undefined;
            for (&lookups, 0..) |*lookup, index| {
                lookup.* = .{ .numerator = c[index].neg(), .len = 4 };
                lookup.tuple[0..4].* = K.xor_12.tupleAt(index, row);
            }
            try verifyPairs(elements, &lookups, row, output, denominators);
        },
        10 => {
            var lookup = Lookup{ .numerator = c[0].neg(), .len = 2 };
            lookup.tuple[0..2].* = .{ M31.fromCanonical(circuit.common.component_list.RANGE_CHECK_16_RELATION_ID), p[0] };
            try verifyPairs(elements, (&lookup)[0..1], row, output, denominators);
        },
        else => unreachable,
    }
}

test "circuit CUDA paired fractions equal CPU lookups for every component" {
    const z = QM31.fromU32Unchecked(123456, 789, 456, 101);
    const alpha = QM31.fromU32Unchecked(4567, 321, 17, 5);
    const elements = trace.LookupElements.init(z, alpha);
    var powers: [6]SecureField = undefined;
    for (elements.alpha_powers, &powers) |power, *out| out.* = secure(power);
    const z_words = secure(z);
    for (0..interaction.component_count) |component| {
        var pp: [11][16]u32 = undefined;
        var base: [52][16]u32 = undefined;
        var output: [52][16]u32 = @splat(@splat(0));
        var denominators: [13 * 16]SecureField = undefined;
        var pp_ptrs: [11][*]const u32 = undefined;
        var base_ptrs: [52][*]const u32 = undefined;
        var output_ptrs: [52][*]u32 = undefined;
        for (&pp, &pp_ptrs, 0..) |*column, *pointer, index| {
            for (column, 0..) |*value, row| value.* = @intCast(31 + index * 71 + row * 5);
            pointer.* = column;
        }
        for (&base, &base_ptrs, 0..) |*column, *pointer, index| {
            for (column, 0..) |*value, row| value.* = @intCast(13 + index * 101 + row * 7);
            pointer.* = column;
        }
        for (&output, &output_ptrs) |*column, *pointer| pointer.* = column;
        var error_flag: u32 = 0;
        const secure_count = interaction.secure_widths[component];
        try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_interaction_fractions_emulate(
            @intCast(component),
            16,
            &pp_ptrs,
            @intCast(interaction.pp_widths[component]),
            &base_ptrs,
            @intCast(interaction.base_widths[component]),
            &output_ptrs,
            @intCast(4 * secure_count),
            &powers,
            6,
            &z_words,
            &denominators,
            @intCast(16 * secure_count),
            &error_flag,
        ));
        try std.testing.expectEqual(@as(u32, 0), error_flag);
        for (0..16) |row| try runOracle(component, row, &pp, &base, &elements, &output, &denominators);
    }
}

test "circuit CUDA global lookup sum matches CPU admission and rejects tampering" {
    const z = QM31.fromU32Unchecked(123456, 789, 456, 101);
    const alpha = QM31.fromU32Unchecked(4567, 321, 17, 5);
    const elements = trace.LookupElements.init(z, alpha);
    var powers: [6]SecureField = undefined;
    for (elements.alpha_powers, &powers) |power, *out| out.* = secure(power);
    const z_words = secure(z);
    const outputs = [_]QM31{
        QM31.fromU32Unchecked(23, 49, 0, 0),
        QM31.fromU32Unchecked(61, 91, 0, 0),
    };
    const device_outputs = [_]SecureField{ secure(outputs[0]), secure(outputs[1]) };
    var sums: [11]QM31 = @splat(QM31.zero());
    const public_sum = try trace.lookupSum(&outputs, circuit.common.component_list.PerComponent(QM31).fromArray(sums), z, alpha);
    sums[0] = public_sum.neg();
    try std.testing.expect((try trace.lookupSum(&outputs, circuit.common.component_list.PerComponent(QM31).fromArray(sums), z, alpha)).isZero());
    var claims: [11]SecureField = undefined;
    for (sums, &claims) |sum, *out| out.* = secure(sum);
    var error_flag: u32 = 0;
    try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_lookup_sum_emulate(
        &claims,
        &device_outputs,
        2,
        &powers,
        6,
        &z_words,
        &error_flag,
    ));
    try std.testing.expectEqual(@as(u32, 0), error_flag);
    claims[0].a = (claims[0].a + 1) % core.fields.m31.Modulus;
    try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_lookup_sum_emulate(
        &claims,
        &device_outputs,
        2,
        &powers,
        6,
        &z_words,
        &error_flag,
    ));
    try std.testing.expectEqual(@as(u32, 4), error_flag);
}
