//! Non-proving CPU qualification of the authenticated device schema. Device
//! execution/AOT compilation is explicitly a different qualification gate.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const gpu_program = @import("../block_v5_word_gpu_program_v1.zig");
const protocol = @import("../block_v5_word_memory_protocol_v1.zig");
const Word = @import("../block_v5_word_memory_component_v1.zig").Spec;
const Range = @import("../block_v5_range16_component_v1.zig");
const inter = @import("../block_v5_word_memory_interaction_v1.zig");
const Trace = @import("../../air/block/word_memory_trace_v5.zig").Trace;
const rows = @import("../../air/block/memory_component_trace.zig");
const range = @import("../block_v5_range16_v1.zig");
const Transition = @import("../../air/block/memory_transition.zig").Transition;
fn value(i: usize) Q {
    return Q.fromU32Unchecked(@intCast(i * 7 + 3), @intCast(i * 11 + 5), @intCast(i * 13 + 7), @intCast(i * 17 + 11));
}
fn challenges() protocol.Challenges {
    return .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() };
}
fn spec(c: *const protocol.Challenges) Word {
    const event: Transition = .{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 7 };
    return .{ .claim = .{ .first_row = 0, .total_rows = 1, .rows = 1, .log_size = 3, .first = event, .last = event, .preceding = null }, .interaction_claim = .{ .transition_sum = value(1), .link_sum = value(2), .initial_sum = value(3), .endpoint_sum = value(4), .endpoint_count = 1, .register_endpoint_sum = value(5), .register_endpoint_count = 0, .range_count = 10, .range_sums = @splat(value(6)) }, .challenges = c };
}
fn fill(comptime n: usize, start: usize) [n]Q {
    var out: [n]Q = undefined;
    for (&out, 0..) |*cell, i| cell.* = value(start + i);
    return out;
}
test "word device DAG equals all 63 typed secure OOD equations and dynamic instance identity" {
    const a = std.testing.allocator;
    var c = challenges();
    const s = spec(&c);
    var program = try gpu_program.wordEquations(a, s, 8);
    defer program.deinit();
    const fixed = fill(12, 10);
    const main = fill(27, 30);
    const prior = fill(27, 60);
    const current = fill(68, 90);
    const previous = fill(68, 160);
    const supplied = try gpu_program.wordValues(a, &program, fixed, main, prior, current, previous);
    defer a.free(supplied);
    const actual = try program.evaluate(a, supplied);
    defer a.free(actual);
    const wanted = try s.evaluate(fixed, main, prior, current, previous, 8);
    for (actual, wanted) |left, right| try std.testing.expect(left.eql(right));
    var changed = s;
    changed.claim.first.before ^= 0x1111;
    changed.claim.last = changed.claim.first;
    var second = try gpu_program.wordEquations(a, changed, 8);
    defer second.deinit();
    try std.testing.expectEqualSlices(u8, &program.identity, &second.identity);
    try std.testing.expect(!std.mem.eql(u8, &program.invocationDigest(3), &second.invocationDigest(3)));
    try std.testing.expectEqual(@as(usize, 184), program.inputs.len);
    const saved = program.inputs[0];
    program.inputs[0].previous = true;
    try std.testing.expectError(error.InvalidSecurePolynomialSchema, program.validate());
    program.inputs[0] = saved;
    program.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSecurePolynomialIdentity, program.validate());
    program.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidWordDeviceGeometry, gpu_program.wordEquations(a, s, 16));
}
test "word device fractions recover exact 17 CPU prefix buses including padding and high clocks" {
    const a = std.testing.allocator;
    var c = challenges();
    const events = [_]Transition{
        .{ .space = 0, .address = 1, .clock = 0xffff_ffff_0000_0001, .before = 7, .after = 7 },
        .{ .space = 1, .address = 0x2000, .clock = 0xffff_ffff_0000_0002, .before = 9, .after = 10 },
        .{ .space = 1, .address = 0x2000, .clock = 0xffff_ffff_0000_0003, .before = 10, .after = 11 },
        .{ .space = 1, .address = 0x2004, .clock = 0xffff_ffff_0000_0004, .before = 0, .after = 1 },
        .{ .space = 1, .address = 0xffff_ffff, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 3 },
    };
    var t = try Trace.init(a, .{ .first_row = 0, .total_rows = events.len, .rows = events.len, .log_size = 3, .first = events[0], .last = events[events.len - 1], .preceding = null });
    defer t.deinit();
    for (events) |event| try t.append(event);
    try t.seal();
    var counter = try range.Counter.init(a);
    defer counter.deinit();
    var generated = try inter.generate(a, &t, &c, &counter);
    defer generated.deinit(a);
    const s = Word{ .claim = t.claim, .interaction_claim = generated.claim, .challenges = &c };
    const means = try inter.normalize(generated.claim, 8);
    var program = try gpu_program.wordFractions(a, s, 8);
    defer program.deinit();
    var cached_terms: usize = 0;
    var ordinary_terms: usize = 0;
    for (program.nodes) |node| {
        if (node.op == .range_fraction) cached_terms += 1;
        if (node.op == .fraction) ordinary_terms += 1;
    }
    try std.testing.expectEqual(@as(usize, 17), cached_terms);
    try std.testing.expectEqual(@as(usize, 8), ordinary_terms);
    try std.testing.expect((try program.rangeChallenge()).?.eql(c.range16.z));
    var totals: [17]Q = @splat(Q.zero());
    for (0..8) |logical| {
        const physical = rows.committedRow(logical, 3);
        const before = rows.committedRow((logical + 7) % 8, 3);
        var fixed: [12]Q = undefined;
        for (&fixed, 0..) |*cell, column| cell.* = Q.fromBase(t.fixedColumn(column)[physical]);
        const supplied = try gpu_program.wordValues(a, &program, fixed, t.rowAt(logical), t.rowAt((logical + 7) % 8), @splat(Q.zero()), @splat(Q.zero()));
        defer a.free(supplied);
        const actual = try program.evaluate(a, supplied);
        defer a.free(actual);
        for (actual, means, &totals, 0..) |fraction, mean, *total, bus| {
            var current: [4]M = undefined;
            var previous: [4]M = undefined;
            for (0..4) |coordinate| {
                current[coordinate] = generated.columns[bus * 4 + coordinate][physical];
                previous[coordinate] = generated.columns[bus * 4 + coordinate][before];
            }
            const wanted = Q.fromM31Array(current).sub(Q.fromM31Array(previous)).add(mean);
            try std.testing.expect(fraction.eql(wanted));
            total.* = total.add(fraction);
        }
    }
    for (totals, means) |total, mean| try std.testing.expect(total.eql(mean.mulM31(M.fromCanonical(8))));
}
test "range16 device DAG equals typed secure equations and preserves zero-weight poles" {
    const a = std.testing.allocator;
    var c = challenges();
    const s = Range.Spec{ .claim = .{ .sum = value(2), .count = 13 }, .challenges = &c };
    var program = try gpu_program.rangeEquations(a, s);
    defer program.deinit();
    const fixed = fill(1, 1);
    const main = fill(1, 2);
    const current = fill(8, 3);
    const prior = fill(8, 11);
    const inputs = try a.alloc(Q, program.inputs.len);
    defer a.free(inputs);
    for (program.inputs, inputs) |input, *out| out.* = switch (input.tree) {
        0 => fixed[0],
        1 => main[0],
        2 => if (input.previous) prior[input.column] else current[input.column],
        else => unreachable,
    };
    const actual = try program.evaluate(a, inputs);
    defer a.free(actual);
    const wanted = try s.evaluate(fixed, main, @splat(Q.zero()), current, prior, 65536);
    for (actual, wanted) |left, right| try std.testing.expect(left.eql(right));
    c.range16 = .init(Q.fromBase(M.fromCanonical(42)), Q.one());
    var fraction = try gpu_program.rangeFractions(a, s);
    defer fraction.deinit();
    var table = try @import("../block_v5_range16_inverse_table_v1.zig").Table.init(a, c.range16);
    defer table.deinit();
    const zero = try fraction.evaluate(a, &.{ Q.fromBase(M.fromCanonical(42)), Q.zero() });
    defer a.free(zero);
    try std.testing.expect(zero[0].isZero() and zero[1].isZero());
    try std.testing.expect((try table.fraction(Q.fromBase(M.fromCanonical(42)), Q.zero())).isZero());
    try std.testing.expectError(error.DivisionByZero, fraction.evaluate(a, &.{ Q.fromBase(M.fromCanonical(42)), Q.one() }));
    try std.testing.expectError(error.DivisionByZero, table.fraction(Q.fromBase(M.fromCanonical(42)), Q.one()));
    const request = [_]Q{ Q.fromBase(M.fromCanonical(65535)), Q.fromBase(M.fromCanonical(7)) };
    const supplied = try fraction.evaluate(a, &request);
    defer a.free(supplied);
    try std.testing.expect(supplied[0].eql(try table.fraction(request[0], request[1])));
    try std.testing.expect(supplied[1].eql(request[1]));
    try std.testing.expectError(error.InvalidSecureRangeValue, fraction.evaluate(a, &.{ Q.fromBase(M.fromCanonical(65536)), Q.one() }));
    c.range16.alpha_powers[0] = Q.fromU32Unchecked(2, 0, 0, 0);
    try std.testing.expectError(error.InvalidSecureRangeChallenge, gpu_program.rangeFractions(a, s));
}
test "word device claim metadata retains exact wide public boundaries" {
    const witness = @import("../block_v5_word_gpu_witness_v1.zig");
    var c = challenges();
    const s = spec(&c);
    const encoded = try witness.claimWords(s.claim);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), encoded[16]);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), encoded[15]);
    try std.testing.expectEqualSlices(u32, &witness.recordWords(s.claim.first), encoded[13..19]);
    var invalid = s.claim;
    invalid.rows = 0;
    try std.testing.expectError(error.InvalidMemoryComponentClaim, witness.claimWords(invalid));
}

test "word device offline executable covers interior shards and changing capacity" {
    const a = std.testing.allocator;
    var c = challenges();
    var first = spec(&c);
    // Match the offline export's smallest allowed capacity and no predecessor.
    first.claim.log_size = 1;
    var base = try gpu_program.wordEquations(a, first, 2);
    defer base.deinit();
    var fractions = try gpu_program.wordFractions(a, first, 2);
    defer fractions.deinit();
    var interior = first;
    interior.claim.log_size = 7;
    interior.claim.first_row = (@as(u64, 1) << 40) + 17;
    interior.claim.total_rows = interior.claim.first_row + 3;
    interior.claim.preceding = interior.claim.first;
    interior.claim.preceding.?.clock -= 1;
    interior.claim.preceding.?.after = interior.claim.first.before;
    var other = try gpu_program.wordEquations(a, interior, 128);
    defer other.deinit();
    var other_fractions = try gpu_program.wordFractions(a, interior, 128);
    defer other_fractions.deinit();
    try std.testing.expectEqualSlices(u8, &base.identity, &other.identity);
    try std.testing.expectEqualSlices(u8, &fractions.identity, &other_fractions.identity);
    try std.testing.expect(!std.mem.eql(u8, &base.invocationDigest(1), &other.invocationDigest(7)));
    // Retain the register/RAM space selector in the reusable schema as well.
    first.claim.first.space = 0;
    first.claim.first.address = 31;
    first.claim.last = first.claim.first;
    var registers = try gpu_program.wordEquations(a, first, 2);
    defer registers.deinit();
    try std.testing.expectEqualSlices(u8, &base.identity, &registers.identity);
    // Compare each public-boundary policy at arbitrary secure OOD values. The
    // reusable schema may not erase either enabled or disabled selectors.
    const fixed = fill(12, 10);
    const main = fill(27, 30);
    const prior = fill(27, 60);
    const current = fill(68, 90);
    const previous = fill(68, 160);
    const cases = [_]struct { program: *const gpu_program.ir.Program, source: Word, size: u32 }{
        .{ .program = &other, .source = interior, .size = 128 },
        .{ .program = &registers, .source = first, .size = 2 },
    };
    for (cases) |case| {
        const inputs = try gpu_program.wordValues(a, case.program, fixed, main, prior, current, previous);
        defer a.free(inputs);
        const actual = try case.program.evaluate(a, inputs);
        defer a.free(actual);
        const wanted = try case.source.evaluate(fixed, main, prior, current, previous, case.size);
        for (actual, wanted) |left, right| try std.testing.expect(left.eql(right));
    }
}
