//! CPU emulation executes the exact new CUDA O8 fraction body against the
//! original native RawLookupRows authority for all eleven real components.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const engine = @import("stwo_prover_engine");
const P = @import("protocol.zig");
const W = @import("witness.zig");
const Air = @import("../air.zig");
const Job = extern struct {
    fixed: ?[*]const u32,
    main: [*]const u32,
    parameters: [*]const u32,
    numerators: [*]u32,
    denominators: [*]u32,
    status: *u32,
    fixed_words: u64,
    main_words: u64,
    numerator_words: u64,
    denominator_words: u64,
    component: u32,
    row_log: u32,
    reserved: [2]u32 = .{ 0, 0 },
};
extern "c" fn stwo_circuit_om31_fractions_emulate(*const Job) c_int;
test "native octic circuit CUDA fractions share tuple authority all components" {
    const a = std.testing.allocator;
    var ctx = try circuit.builder.Context(P.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(P.Q.fromU32Unchecked(3, 4, 5, 6));
    const out = try ctx.mul(x, x);
    try ctx.setOutputs(&.{out});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(P.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var base = try circuit.witness.trace.writeTrace(a, ctx.values(), &pp);
    defer base.deinit();
    const raw = try circuit.witness.trace.RawLookupRows.init(base.columns, &pp);
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var template = try Air.parse(a, bytes);
    defer template.deinit();
    const layout = pp.layout();
    var bundle = try Air.bind(a, &template, base.log_sizes, &layout);
    defer bundle.deinit();
    const z = P.O.fromM31Array(.{ P.M.fromU64(17), P.M.fromU64(19), P.M.fromU64(23), P.M.fromU64(29), P.M.fromU64(31), P.M.fromU64(37), P.M.fromU64(41), P.M.fromU64(43) });
    const alpha = z.add(P.O.basis());
    const elements = W.Elements.init(z, alpha);
    var parameters: [56]u32 = undefined;
    for (z.toM31Array(), 0..) |m, i| parameters[i] = m.v;
    for (elements.powers, 0..) |power, i| for (power.toM31Array(), 0..) |m, j| {
        parameters[8 + 8 * i + j] = m.v;
    };
    var at: usize = 0;
    for (std.enums.values(circuit.common.component_list.ComponentList), circuit.witness.trace.traceWidths(), bundle.components, 0..) |kind, width, component, ci| {
        const pp_width: usize = if (ci == 6) 0 else component.preprocessed_indices.len;
        const fixed = try a.alloc(u32, 16 * pp_width);
        defer a.free(fixed);
        for (0..pp_width) |i| {
            const column = if (ci < 5) raw.gather_pp[ci][i] else if (ci == 5) raw.table_pp[0][i] else if (ci == 7) raw.table_pp[1][i] else if (ci == 8) raw.table_pp[2][i] else if (ci == 9) raw.table_pp[3][i] else raw.seq;
            for (0..16) |r| fixed[16 * i + r] = column[r].v;
        }
        const main = try a.alloc(u32, 16 * width);
        defer a.free(main);
        for (base.columns[at..][0..width], 0..) |column, i| for (0..16) |r| {
            main[16 * i + r] = column.values[r].v;
        };
        at += width;
        const pairs = (circuit.witness.trace.RawLookupRows.count(kind) + 1) / 2;
        const numerators = try a.alloc(u32, 8 * pairs * 16);
        defer a.free(numerators);
        const denominators = try a.alloc(u32, numerators.len);
        defer a.free(denominators);
        var status: u32 = 0;
        var job = Job{ .fixed = fixed.ptr, .main = main.ptr, .parameters = &parameters, .numerators = numerators.ptr, .denominators = denominators.ptr, .status = &status, .fixed_words = fixed.len, .main_words = main.len, .numerator_words = numerators.len, .denominator_words = denominators.len, .component = @intCast(ci), .row_log = 4 };
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(Job));
        try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_om31_fractions_emulate(&job));
        try std.testing.expectEqual(@as(u32, 0), status);
        for (0..16) |r| {
            var storage: [circuit.witness.trace.RawLookupRows.MAX_LOOKUPS]circuit.witness.components.Lookup = undefined;
            var fractions: [13]engine.air.logup_columns.ForField(P.O).Fraction = undefined;
            try W.pairFractions(&elements, try raw.fill(kind, r, &storage), fractions[0..pairs]);
            for (fractions[0..pairs], 0..) |fraction, i| {
                for (fraction.numerator.toM31Array(), 0..) |m, j| {
                    if (m.v != numerators[(8 * i + j) * 16 + r]) std.debug.print("NUM row={} pair={} coord={}\n", .{ r, i, j });
                    try std.testing.expectEqual(m.v, numerators[(8 * i + j) * 16 + r]);
                }
                for (fraction.denominator.toM31Array(), 0..) |m, j| {
                    if (m.v != denominators[(8 * i + j) * 16 + r]) std.debug.print("DEN row={} pair={} coord={}\n", .{ r, i, j });
                    try std.testing.expectEqual(m.v, denominators[(8 * i + j) * 16 + r]);
                }
            }
        }
        job.denominator_words -= 1;
        try std.testing.expectEqual(@as(c_int, 1), stwo_circuit_om31_fractions_emulate(&job));
        job.denominator_words += 1;
        job.reserved[1] = 1;
        try std.testing.expectEqual(@as(c_int, 1), stwo_circuit_om31_fractions_emulate(&job));
        job.reserved[1] = 0;
        job.denominators = job.numerators;
        try std.testing.expectEqual(@as(c_int, 1), stwo_circuit_om31_fractions_emulate(&job));
        job.denominators = denominators.ptr;
        job.component = 11;
        try std.testing.expectEqual(@as(c_int, 1), stwo_circuit_om31_fractions_emulate(&job));
        job.component = @intCast(ci);
        var zero_parameters: [56]u32 = @splat(0);
        job.parameters = &zero_parameters;
        status = 0;
        try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_om31_fractions_emulate(&job));
        try std.testing.expect(status & 4 != 0);
    }
    std.debug.print("OM31_CUDA_FRACTIONS components=11 physical_rows=16 native_tuple_parity=true geometry_overlap_mutants=44 zero_denominator_cases=11\n", .{});
}
