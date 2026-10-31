const std = @import("std");
const core = @import("stwo_core");
const rom = @import("../setup.zig");
const provider = @import("../provider.zig");
const compact = @import("../compact.zig");
const L = @import("../../layout.zig");
const E = @import("../../evaluation.zig");
const a = std.testing.allocator;
const Q = E.Q;
const M = core.fields.m31.M31;
const words = [_]u32{ 0x00108093, 0x001080b3, 0xffffffff };

test "rv64 program ROM: identity owns canonical program only and preserves upper PC bits" {
    var mutable = words;
    var setup = try rom.Setup.init(a, .{ .base = 0x100001000, .words = &mutable });
    defer setup.deinit();
    var sparse = try rom.Setup.init(a, .{ .base = 0x100001000, .words = &words, .addresses = &.{ 0x100001000, 0x100001004, 0x100001008 } });
    defer sparse.deinit();
    try std.testing.expectEqualSlices(u8, &setup.identity, &sparse.identity);
    try std.testing.expect(setup.contiguous and sparse.contiguous);
    mutable[0] = 0;
    try std.testing.expectEqual(words[0], setup.decoded[0].raw);
    for (setup.rows, setup.decoded, 0..) |row, entry, i| {
        try std.testing.expectEqualDeep(rom.deriveRow(0x100001000 + 4 * i, words[i]), row);
        if (row[rom.field.valid].isZero()) continue;
        try std.testing.expectEqualDeep(try @import("../../../decode.zig").Instruction.decode(words[i]), entry.instruction);
        for (entry.enabled, 0..) |enabled, slot| try std.testing.expectEqual(!row[rom.field.slots + slot].isZero(), enabled);
    }
    try std.testing.expectEqual(@as(usize, 0), try setup.lookup(0x100001000));
    try std.testing.expectError(error.InvalidRv64RomExecution, setup.lookup(0x1000));
    try std.testing.expectError(error.InvalidRv64RomExecution, setup.lookup(0x100001008));
    try std.testing.expectError(error.InvalidRv64RomExecution, setup.lookup(0x100001001));
    var low = try rom.Setup.init(a, .{ .base = 0x1000, .words = &words });
    defer low.deinit();
    try std.testing.expect(!std.mem.eql(u8, &setup.identity, &low.identity));
    const high_row = setup.row(0);
    try std.testing.expectEqual(@as(u32, 1), high_row[rom.field.pc + 4].toU32());
}

test "rv64 program ROM: canonical address admission and wraparound decode" {
    try std.testing.expectError(error.InvalidRv64RomAddress, rom.Setup.init(a, .{ .base = 0x1001, .words = &words }));
    try std.testing.expectError(error.InvalidRv64RomAddress, rom.Setup.init(a, .{ .base = 0x1000, .words = &words, .addresses = &.{ 0x1000, 0x1004, 0x1004 } }));
    try std.testing.expectError(error.InvalidRv64RomAddress, rom.Setup.init(a, .{ .base = 0xfffffffffffffffc, .words = &words }));
    var top = try rom.Setup.init(a, .{ .base = 0xfffffffffffffffc, .words = words[0..1] });
    defer top.deinit();
    const row = top.row(0);
    for (row[rom.field.increment..][0..8]) |byte| try std.testing.expect(byte.isZero());
    try std.testing.expectEqual(@as(usize, 0), try top.lookup(0xfffffffffffffffc));
    try std.testing.expectError(error.InvalidRv64RomExecution, top.lookup(0));
    var sparse = try rom.Setup.init(a, .{ .base = 0x1000, .words = words[0..2], .addresses = &.{ 0x1000, 0xfffffffffffffffc } });
    defer sparse.deinit();
    try std.testing.expect(!sparse.contiguous);
    try std.testing.expectEqual(@as(usize, 1), try sparse.lookup(0xfffffffffffffffc));
    try std.testing.expectError(error.InvalidRv64RomExecution, sparse.lookup(0x1004));
}

test "rv64 program provider: fresh multiplicities and exact execution closure with adversarial mutations" {
    var setup = try rom.Setup.init(a, .{ .base = 0x100001000, .words = &words });
    defer setup.deinit();
    const pcs = [_]u64{ 0x100001000, 0x100001004, 0x100001000 };
    var request = try provider.Request.init(a, &setup, &pcs);
    defer request.deinit();
    var other = try provider.Request.init(a, &setup, pcs[1..2]);
    defer other.deinit();
    try std.testing.expectEqual(@as(u32, 0), other.multiplicities[provider.physical(0, setup.log_size)].toU32());
    try std.testing.expectEqual(@as(u32, 2), request.multiplicities[provider.physical(0, setup.log_size)].toU32());
    var channel = @import("../../protocol.zig").Channel{};
    const challenges = provider.Challenges.draw(&channel);
    const claim = try request.generateInteraction(&setup, challenges);
    var execution_sum = Q.zero();
    for (pcs) |pc| {
        const entry = rom.tuple(&setup.rows[try setup.lookup(pc)]);
        execution_sum = execution_sum.add(try challenges.denominator(&entry).inv());
    }
    try std.testing.expect(execution_sum.add(claim).isZero());
    const n = setup.domainSize();
    for (0..n) |logical| {
        const index = provider.physical(logical, setup.log_size);
        const prior_index = provider.physical((logical + n - 1) % n, setup.log_size);
        var current: [provider.INTERACTION]Q = undefined;
        var previous: [provider.INTERACTION]Q = undefined;
        for (&current, &previous, 0..) |*cur, *prev, c| {
            cur.* = Q.fromBase(request.interaction[c * n + index]);
            prev.* = Q.fromBase(request.interaction[c * n + prior_index]);
        }
        const row = setup.row(logical);
        const entry = rom.tuple(&row);
        var output: [provider.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &output };
        const first = E.q(@intFromBool(logical == 0));
        const last = E.q(@intFromBool(logical + 1 == n));
        provider.evaluate(first, last, &entry, Q.fromBase(request.multiplicities[index]), &current, &previous, challenges, claim, &sink);
        for (output) |value| try std.testing.expect(value.isZero());
        for (0..provider.INTERACTION) |c| {
            var mutated = current;
            mutated[c] = mutated[c].add(Q.one());
            sink.count = 0;
            provider.evaluate(first, last, &entry, Q.fromBase(request.multiplicities[index]), &mutated, &previous, challenges, claim, &sink);
            try std.testing.expect(nonzero(&output));
        }
        sink.count = 0;
        provider.evaluate(first, last, &entry, Q.fromBase(request.multiplicities[index]).add(Q.one()), &current, &previous, challenges, claim, &sink);
        try std.testing.expect(nonzero(&output));
        if (logical + 1 == n) {
            sink.count = 0;
            provider.evaluate(first, last, &entry, Q.fromBase(request.multiplicities[index]), &current, &previous, challenges, claim.add(Q.one()), &sink);
            try std.testing.expect(nonzero(&output));
        }
    }
    const old = request.interaction.ptr;
    try std.testing.expectError(error.DivisionByZero, request.generateInteraction(&setup, .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }));
    try std.testing.expectEqual(old, request.interaction.ptr);
    try std.testing.expectError(error.InvalidRv64RomExecution, provider.Request.init(a, &setup, &.{0x1000}));
}
fn nonzero(values: []const Q) bool {
    for (values) |value| if (!value.isZero()) return true;
    return false;
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var setup = try rom.Setup.init(allocator, .{ .base = 0x1000, .words = &words });
    defer setup.deinit();
    var request = try provider.Request.init(allocator, &setup, &.{0x1000});
    defer request.deinit();
    var channel = @import("../../protocol.zig").Channel{};
    _ = try request.generateInteraction(&setup, provider.Challenges.draw(&channel));
}
test "rv64 program ROM: allocation failures release setup and request storage" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}

test "rv64 compact41: exhaustive decoded opcode enables match full ROM and selector mutations fail" {
    var seen: [L.fixed.OPCODES]bool = @splat(false);
    for ([_]u32{ 0x33, 0x3b, 0x13, 0x1b, 0x03, 0x23, 0x63, 0x6f, 0x67, 0x37, 0x17, 0x0f }) |major| {
        for (0..128) |f7| for (0..8) |f3| for ([_]u32{ 0, 1 }) |register| {
            const raw = major | (register << 7) | (@as(u32, @intCast(f3)) << 12) | (register << 15) | (register << 20) | (@as(u32, @intCast(f7)) << 25);
            const full_row = rom.deriveRow(0x8765432100001000, raw);
            if (full_row[rom.field.valid].isZero()) continue;
            const op = full_row[rom.field.opcode].toU32();
            seen[op] = true;
            const entry = compact.fromRow(&full_row);
            var selectors: [L.fixed.OPCODES]Q = @splat(Q.zero());
            selectors[op] = Q.one();
            const inflated = compact.inflateFixed(&entry, &selectors);
            for (0..L.WORDS) |i| try std.testing.expect(inflated[L.fixed.word_start + i].eql(Q.fromBase(full_row[rom.field.words + i])));
            for (0..L.CARRIES) |i| try std.testing.expect(inflated[L.fixed.carry_start + i].eql(Q.fromBase(full_row[rom.field.carries + i])));
        };
    }
    for (seen[0..63]) |covered| try std.testing.expect(covered);
    const row = rom.deriveRow(0x1000, words[0]);
    const entry = compact.fromRow(&row);
    var selectors: [L.fixed.OPCODES]Q = @splat(Q.zero());
    selectors[row[rom.field.opcode].toU32()] = Q.one();
    var residuals: [compact.SELECTOR_CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    compact.evaluateSelectors(&entry, &selectors, &sink);
    try std.testing.expect(!nonzero(&residuals));
    selectors[0] = Q.one();
    sink.count = 0;
    compact.evaluateSelectors(&entry, &selectors, &sink);
    try std.testing.expect(nonzero(&residuals));
}

test "rv64 compact41: enable inflation is linear over arbitrary extension-field points" {
    var x: compact.Tuple = undefined;
    var y: compact.Tuple = undefined;
    var sum: compact.Tuple = undefined;
    var sx: [L.fixed.OPCODES]Q = undefined;
    var sy: [L.fixed.OPCODES]Q = undefined;
    var ss: [L.fixed.OPCODES]Q = undefined;
    for (&x, &y, &sum, 0..) |*xx, *yy, *s, i| {
        xx.* = Q.fromU32Unchecked(@intCast(i), 2, 3, 4);
        yy.* = Q.fromU32Unchecked(5, @intCast(i), 7, 8);
        s.* = xx.add(yy.*);
    }
    for (&sx, &sy, &ss, 0..) |*xx, *yy, *s, i| {
        xx.* = Q.fromU32Unchecked(@intCast(i), 11, 12, 13);
        yy.* = Q.fromU32Unchecked(14, @intCast(i), 16, 17);
        s.* = xx.add(yy.*);
    }
    const fx = compact.inflateFixed(&x, &sx);
    const fy = compact.inflateFixed(&y, &sy);
    const fs = compact.inflateFixed(&sum, &ss);
    for (fx, fy, fs) |xx, yy, actual| try std.testing.expect(actual.eql(xx.add(yy)));
    var challenges: provider.Challenges = .{ .offset = Q.fromU32Unchecked(19, 23, 29, 31), .coefficients = undefined };
    for (&challenges.coefficients, 0..) |*coefficient, i| coefficient.* = Q.fromU32Unchecked(@intCast(i), 37, 41, 43);
    var expanded = compact.expand(&x);
    try std.testing.expect(compact.denominator(challenges, &x).eql(challenges.denominator(&expanded)));
    expanded[rom.field.valid] = Q.one();
    try std.testing.expect(compact.executionDenominator(challenges, &x).eql(challenges.denominator(&expanded)));
}
