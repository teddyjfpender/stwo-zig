//! CPU-only typed equation/interaction and ownership admission fixtures.
//! No GPU session, STARK proof, or execution-segment replay is performed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const gpu = @import("frontends/riscv/prover/block_v5_ram_lanes_gpu_program_v1.zig");
const Component = @import("frontends/riscv/prover/block_v5_ram_lanes_component_v1.zig");
const Protocol = @import("frontends/riscv/prover/block_v5_ram_lanes_protocol_v1.zig");
const Trace = @import("frontends/riscv/air/block/word_memory_lanes_trace_v1.zig");
const Interaction = @import("frontends/riscv/prover/block_v5_ram_lanes_interaction_v1.zig");
const Transition = @import("frontends/riscv/air/block/memory_transition.zig").Transition;
const Placement = @import("frontends/riscv/air/block/memory_component_trace.zig");
const capability = engine.air.secure_polynomial_capability_v1;
const ingress = @import("backends/metal/runtime/secure_coefficient_ingress_v1.zig");
const metal = @import("backends/metal/runtime/secure_polynomial_codegen_v1.zig");
const cuda = @import("backends/cuda/secure_polynomial_resident_codegen_v1.zig");
const events = [_]Transition{
    .{ .space = 1, .address = 0x2000, .clock = 0x1_0000_0001, .before = 7, .after = 8 },
    .{ .space = 1, .address = 0x2000, .clock = 0x1_0000_0002, .before = 8, .after = 9 },
    .{ .space = 1, .address = 0x2004, .clock = 1, .before = 11, .after = 12 },
    .{ .space = 1, .address = 0x2004, .clock = std.math.maxInt(u64) - 1, .before = 12, .after = 13 },
    .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 0xeeee_ffff },
};
fn challenges() Protocol.Challenges {
    return .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
}
fn claim(start: usize, count: u32) Protocol.Claim {
    return .{ .first_event = start, .total_events = events.len, .events = count, .row_log = 3, .first = events[start], .last = events[start + count - 1], .preceding = if (start == 0) null else events[start - 1] };
}
fn fill(comptime n: usize, offset: usize) [n]Q {
    var result: [n]Q = undefined;
    for (&result, 0..) |*out, i| out.* = Q.fromU32Unchecked(@intCast(offset + i + 1), @intCast(offset + 3 * i + 2), @intCast(offset + 7 * i + 3), @intCast(offset + 11 * i + 4));
    return result;
}
fn resolve(a: std.mem.Allocator, program: *const gpu.ir.Program, fixed: [24]Q, main: [54]Q, previous: [54]Q, current: [92]Q, before: [92]Q) ![]Q {
    const values = try a.alloc(Q, program.inputs.len);
    for (values, program.inputs) |*out, input| out.* = switch (input.tree) {
        0 => fixed[input.column],
        1 => if (input.previous) previous[input.column] else main[input.column],
        2 => if (input.previous) before[input.column] else current[input.column],
        else => unreachable,
    };
    return values;
}
test "RAM GPU typed all117 OOD equations and271 inputs retain exact canonical mask order" {
    const a = std.testing.allocator;
    const ch = challenges();
    var trace = try Trace.Trace.init(a, claim(0, events.len), .{ .max_row_log = 3, .max_events = events.len, .max_owned_bytes = 1 << 20 });
    defer trace.deinit();
    for (events) |event| try trace.append(event);
    try trace.seal();
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var counter = try @import("frontends/riscv/prover/block_v5_range16_v1.zig").Counter.init(a);
    defer counter.deinit();
    var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
    defer generated.deinit(a);
    const spec = Component.Spec{ .claim = trace.claim, .interaction_claim = generated.claim, .challenges = &ch };
    const c = try Component.Component.init(spec.claim.row_log, spec);
    const cap = c.asProverComponent().secure_polynomial_capability_v1.?;
    var equations = try cap.export_program(cap.context, a);
    defer equations.deinit();
    try std.testing.expectEqual(gpu.ir.Kind.ram_lanes_equations_v1, cap.kind);
    try std.testing.expectEqual(@as(usize, 271), equations.inputs.len);
    try std.testing.expectEqual(@as(usize, 117), equations.roots.len);
    const fixed = fill(24, 1);
    const main = fill(54, 40);
    const previous = fill(54, 100);
    const current = fill(92, 160);
    const before = fill(92, 300);
    const values = try resolve(a, &equations, fixed, main, previous, current, before);
    defer a.free(values);
    const actual = try equations.evaluate(a, values);
    defer a.free(actual);
    const expected = try spec.evaluate(fixed, main, previous, current, before, 8);
    for (actual, expected) |left, right| try std.testing.expect(left.eql(right));
    const original = equations.inputs[24 + 54];
    equations.inputs[24 + 54].column = 2; // Forbidden previous lane0 cell.
    try std.testing.expectError(error.InvalidSecurePolynomialSchema, equations.validate());
    equations.inputs[24 + 54] = original;
    try std.testing.expectError(error.InvalidSecureRamLanesGeometry, gpu.equations(a, spec, 16));
    const source = try metal.generateLibrary(a, &.{&equations});
    defer a.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "[[buffer(10)]]") != null);
    const device_source = try cuda.generateLibrary(a, &.{&equations});
    defer a.free(device_source);
    try std.testing.expect(std.mem.indexOf(u8, device_source, "extern \"C\" __global__ void") != null);
}
test "RAM GPU23 fraction planes match actual centered CPU prefixes including odd padding" {
    const a = std.testing.allocator;
    const ch = challenges();
    var table = try Interaction.RangeInverses.init(a, ch.range16);
    defer table.deinit();
    var first_identity: ?[32]u8 = null;
    // Includes first, interior and final shards with an odd last event.
    for ([_]Protocol.Claim{ claim(0, 1), claim(1, 2), claim(3, 2) }) |geometry| {
        var trace = try Trace.Trace.init(a, geometry, .{ .max_row_log = 3, .max_events = events.len, .max_owned_bytes = 1 << 20 });
        defer trace.deinit();
        for (events[geometry.first_event..][0..geometry.events]) |event| try trace.append(event);
        try trace.seal();
        var counter = try @import("frontends/riscv/prover/block_v5_range16_v1.zig").Counter.init(a);
        defer counter.deinit();
        var generated = try Interaction.generatePrepared(a, &trace, &ch, &counter, &table, 8 << 20);
        defer generated.deinit(a);
        const spec = Component.Spec{ .claim = geometry, .interaction_claim = generated.claim, .challenges = &ch };
        var program = try gpu.fractions(a, spec, 8);
        defer program.deinit();
        if (first_identity) |identity| try std.testing.expectEqualSlices(u8, &identity, &program.identity) else first_identity = program.identity;
        var range_nodes: usize = 0;
        for (program.nodes) |node| range_nodes += @intFromBool(node.op == .range_fraction);
        try std.testing.expectEqual(@as(usize, 34), range_nodes);
        try std.testing.expect((try program.rangeChallenge()).?.eql(ch.range16.z));
        const means = try Interaction.normalize(generated.claim, geometry);
        for (0..8) |logical| {
            const physical = Placement.committedRow(logical, 3);
            const before = Placement.committedRow((logical + 7) % 8, 3);
            var fixed: [24]Q = undefined;
            for (&fixed, 0..) |*out, column| out.* = Q.fromBase(trace.fixedColumn(column)[physical]);
            const main = trace.rowAt(logical);
            const prior = trace.rowAt((logical + 7) % 8);
            const values = try resolve(a, &program, fixed, main[0] ++ main[1], prior[0] ++ prior[1], @splat(Q.zero()), @splat(Q.zero()));
            defer a.free(values);
            const fractions = try program.evaluate(a, values);
            defer a.free(fractions);
            for (fractions, means, 0..) |fraction, mean, bus| {
                var current: [4]M = undefined;
                var previous: [4]M = undefined;
                for (0..4) |coordinate| {
                    current[coordinate] = generated.columns[bus * 4 + coordinate][physical];
                    previous[coordinate] = generated.columns[bus * 4 + coordinate][before];
                }
                try std.testing.expect(fraction.eql(Q.fromM31Array(current).sub(Q.fromM31Array(previous)).add(mean)));
            }
        }
    }
}
test "RAM GPU ingress caps and no-copy alignment fail closed and protocol powers partition exactly" {
    const g = try ingress.geometry(170, 12, 14, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 170 * 4096 * 4), g.source_bytes);
    try std.testing.expectEqual(@as(usize, 170 * 16384 * 4), g.output_bytes);
    try std.testing.expectError(error.SecureCoefficientResidentCap, ingress.geometry(170, 12, 14, g.charged_bytes - 1));
    try std.testing.expectError(error.InvalidSecureCoefficientGeometry, ingress.geometry(170, 12, 12, std.math.maxInt(usize)));
    try ingress.requireNoCopySpan(0x10000, 0x4000, 0x4000);
    try std.testing.expectError(error.SecureCoefficientNoCopyUnavailable, ingress.requireNoCopySpan(0x10004, 0x4000, 0x4000));
    try std.testing.expectError(error.SecureCoefficientNoCopyUnavailable, ingress.requireNoCopySpan(0x10000, 8, 0x4000));
    try std.testing.expectError(error.SecureCoefficientNoCopyUnavailable, ingress.requireNoCopySpan(std.math.maxInt(usize) - 0x3fff, 0x4000, 0x4000));
    var cursor: usize = 119;
    try std.testing.expectEqual(@as(usize, 2), try capability.powerStart(119, &cursor, 117));
    try std.testing.expectEqual(@as(usize, 0), try capability.powerStart(119, &cursor, 2));
    try std.testing.expectError(error.InvalidSecurePowerPartition, capability.powerStart(119, &cursor, 1));
    try std.testing.expect(gpu.ir.layout(.ram_lanes_equations_v1).interaction != gpu.ir.layout(.word_equations_v4).interaction);
}
test "RAM GPU borrowed PCS source rejects changed coefficient extent or evaluation identity" {
    const a = std.testing.allocator;
    const coeff = [_]M{ M.one(), M.zero(), M.zero(), M.zero() };
    const other = [_]M{ M.zero(), M.one(), M.zero(), M.zero() };
    var polys = [_]engine.air.component_prover.Poly{.{ .log_size = 2, .values = &coeff, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coeff) }};
    var trees = [_][]const engine.air.component_prover.Poly{ &polys, &.{}, &.{} };
    // Runtime-owned addresses are distinct even in ReleaseFast. Zig may
    // coalesce equal const local values; a const copy is not an owner identity
    // test and can legitimately have the same address as the original.
    const trace = try a.create(engine.air.component_prover.Trace);
    defer a.destroy(trace);
    trace.* = .{ .polys = .{ .items = &trees } };
    var descriptor = [_]ingress.Descriptor{.{ .coefficients = &coeff, .evaluations = &coeff, .coefficient_words = 4, .evaluation_words = 4, .tree_index = 0, .column_index = 0, .trace_log = 2, .evaluation_log = 2 }};
    // This owner validates bindings only: no resident operation/deinit occurs.
    const owner = ingress.Owned{ .a = a, .source = trace, .descriptors = &descriptor, .columns = &.{}, .offsets = .{ &.{}, &.{}, &.{} }, .resident = undefined, .gpu_milliseconds = 0, .ingress_bytes = 16 };
    try owner.requireSource(trace);
    polys[0].values = &other;
    try std.testing.expect(trace.polys.items[0][0].values.ptr != descriptor[0].evaluations);
    try std.testing.expectError(error.InvalidSecureCoefficientOwner, owner.requireSource(trace));
    polys[0].values = &coeff;
    polys[0].coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(coeff[0..2]);
    try std.testing.expect(trace.polys.items[0][0].coefficients.?.coefficients().len != descriptor[0].coefficient_words);
    try std.testing.expectError(error.InvalidSecureCoefficientOwner, owner.requireSource(trace));
    polys[0].coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&other);
    try std.testing.expect(trace.polys.items[0][0].coefficients.?.coefficients().ptr != descriptor[0].coefficients);
    try std.testing.expectError(error.InvalidSecureCoefficientOwner, owner.requireSource(trace));
    polys[0].coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(&coeff);
    try owner.requireSource(trace);
    const copy = try a.create(engine.air.component_prover.Trace);
    defer a.destroy(copy);
    copy.* = trace.*;
    try std.testing.expect(copy != owner.source);
    try std.testing.expectError(error.InvalidSecureCoefficientOwner, owner.requireSource(copy));
}
