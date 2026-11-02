//! Compact execution decode linkage. Word/carry enables are linear expressions
//! in the authenticated one-hot opcode and four authenticated slot enables.
//! PC+4 and PC+imm remain in ROM, preserving existing full-u64 arithmetic.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const E = @import("../evaluation.zig");
const L = E.L;
const ops = @import("../operations.zig");
const rom = @import("setup.zig");
const provider = @import("provider.zig");
pub const COUNT = 41;
pub const Tuple = [COUNT]Q;
pub const SELECTOR_CONSTRAINTS = L.fixed.OPCODES + 2;
pub const fields = blk: {
    var result: [COUNT]usize = undefined;
    var n: usize = 0;
    for (0..rom.field.raw) |i| {
        result[n] = i;
        n += 1;
    }
    for (rom.field.opcode..rom.field.words) |i| {
        result[n] = i;
        n += 1;
    }
    if (n != COUNT) @compileError("compact ROM tuple width changed");
    break :blk result;
};

pub fn fromRow(row: *const rom.Row) Tuple {
    var result: Tuple = undefined;
    for (&result, fields) |*value, source| value.* = Q.fromBase(row[source]);
    return result;
}
/// Draw under a distinct schema. Zero coefficients for dropped fields permit
/// the full reference provider to share this exact compact execution relation.
pub fn draw(channel: *@import("../protocol.zig").Channel) provider.Challenges {
    channel.mixU32s(&.{ 0x52563634, 0x524f4d43, 1, COUNT });
    var result = provider.Challenges{ .offset = channel.drawSecureFelt(), .coefficients = @splat(Q.zero()) };
    for (fields) |index| result.coefficients[index] = channel.drawSecureFelt();
    return result;
}
pub fn expand(entry: *const Tuple) rom.Tuple {
    return expandFor(Q, entry);
}
pub fn expandFor(comptime F: type, entry: *const [COUNT]F) [rom.field.COUNT]F {
    var result: [rom.field.COUNT]F = @splat(F.zero());
    for (entry, fields) |value, destination| result[destination] = value;
    return result;
}
/// Same polynomial as denominator(expand(entry)), including arbitrary OODS
/// values and challenge coefficients. Omitted tuple coordinates are zero.
pub fn denominator(challenges: provider.Challenges, entry: *const Tuple) Q {
    return denominatorFor(Q, challenges, entry);
}
pub fn denominatorFor(comptime F: type, challenges: provider.ChallengesFor(E.ConstFor(F)), entry: *const [COUNT]F) E.SecureFor(F) {
    var result = E.splatFor(F, challenges.offset);
    for (entry, fields) |value, source| result = result.add(E.mulBaseFor(F, E.splatFor(F, challenges.coefficients[source]), value));
    return result;
}
/// The CPU requests valid ROM membership even on disabled rows; its inverse is
/// separately zero-gated. This preserves the original constant-validity term.
pub fn executionDenominator(challenges: provider.Challenges, entry: *const Tuple) Q {
    return executionDenominatorFor(Q, challenges, entry);
}
pub fn executionDenominatorFor(comptime F: type, challenges: provider.ChallengesFor(E.ConstFor(F)), entry: *const [COUNT]F) E.SecureFor(F) {
    var result = E.splatFor(F, challenges.offset.add(challenges.coefficients[rom.field.valid]));
    for (entry[1..], fields[1..]) |value, source| result = result.add(E.mulBaseFor(F, E.splatFor(F, challenges.coefficients[source]), value));
    return result;
}
/// Padding must use valid=0 and all selectors=0. Exactly one Boolean selector
/// is enabled on active rows; weighted opcode equality links it to the ROM.
pub fn evaluateSelectors(entry: *const Tuple, selectors: *const [L.fixed.OPCODES]Q, sink: *E.Sink) void {
    return evaluateSelectorsFor(Q, entry, selectors, sink);
}
pub fn evaluateSelectorsFor(comptime F: type, entry: *const [COUNT]F, selectors: *const [L.fixed.OPCODES]F, sink: *E.SinkFor(F)) void {
    const full = expandFor(F, entry);
    var sum = F.zero();
    var opcode = F.zero();
    for (selectors, 0..) |selector, i| {
        E.booleanFor(F, sink, selector);
        sum = sum.add(selector);
        opcode = opcode.add(selector.mul(E.qFor(F, @intCast(i))));
    }
    sink.emit(sum.sub(full[rom.field.valid]));
    sink.emit(opcode.sub(full[rom.field.opcode]));
}
/// first/last, ticks and next-PC are request geometry/state, filled by caller.
/// All fields derived here cost expressions, not committed CPU columns.
pub const DecodedView = DecodedViewFor(Q);
pub fn DecodedViewFor(comptime F: type) type {
    return struct {
        valid: F,
        rs1: F,
        rs2: F,
        rd: F,
        immediate: *const [8]F,
        slots: *const [4]F,
        pc: *const [8]F,
        increment: *const [8]F,
        target: *const [8]F,
    };
}
fn fieldIndex(comptime full: usize) usize {
    inline for (fields, 0..) |source, i| if (source == full) return i;
    @compileError("field omitted from compact ROM");
}
pub fn decodedView(entry: *const Tuple) DecodedView {
    return decodedViewFor(Q, entry);
}
pub fn decodedViewFor(comptime F: type, entry: *const [COUNT]F) DecodedViewFor(F) {
    return .{ .valid = entry[0], .rs1 = entry[fieldIndex(rom.field.rs1)], .rs2 = entry[fieldIndex(rom.field.rs2)], .rd = entry[fieldIndex(rom.field.rd)], .immediate = entry[fieldIndex(rom.field.immediate)..][0..8], .slots = entry[fieldIndex(rom.field.slots)..][0..4], .pc = entry[fieldIndex(rom.field.pc)..][0..8], .increment = entry[fieldIndex(rom.field.increment)..][0..8], .target = entry[fieldIndex(rom.field.target)..][0..8] };
}
pub fn inflateFixed(entry: *const Tuple, selectors: *const [L.fixed.OPCODES]Q) E.Fixed {
    return inflateFixedFor(Q, entry, selectors);
}
pub fn inflateFixedFor(comptime F: type, entry: *const [COUNT]F, selectors: *const [L.fixed.OPCODES]F) E.FixedFor(F) {
    return inflateDecodedFor(F, decodedViewFor(F, entry), selectors);
}
pub fn inflateDecoded(decoded: DecodedView, selectors: *const [L.fixed.OPCODES]Q) E.Fixed {
    return inflateDecodedFor(Q, decoded, selectors);
}
pub fn inflateDecodedFor(comptime F: type, decoded: DecodedViewFor(F), selectors: *const [L.fixed.OPCODES]F) E.FixedFor(F) {
    @setEvalBranchQuota(100_000);
    var result: E.FixedFor(F) = @splat(F.zero());
    result[L.fixed.active] = decoded.valid;
    @memcpy(result[L.fixed.opcode_start..][0..L.fixed.OPCODES], selectors);
    result[L.fixed.rs1] = decoded.rs1;
    result[L.fixed.rs2] = decoded.rs2;
    result[L.fixed.rd] = decoded.rd;
    @memcpy(result[L.fixed.slot_start..][0..4], decoded.slots);
    @memcpy(result[L.fixed.immediate..][0..8], decoded.immediate);
    @memcpy(result[L.fixed.pc..][0..8], decoded.pc);
    @memcpy(result[L.fixed.increment..][0..8], decoded.increment);
    @memcpy(result[L.fixed.target..][0..8], decoded.target);
    var sums: [enable_plan.count]F = @splat(F.zero());
    inline for (enable_plan.masks[0..enable_plan.count], 0..) |mask, i| {
        inline for (0..L.fixed.OPCODES) |opcode| {
            if (comptime mask & (@as(u128, 1) << opcode) != 0) sums[i] = sums[i].add(selectors[opcode]);
        }
    }
    for (enable_plan.sources, 0..) |source, i| {
        const value = if (source >= 128) decoded.slots[source - 128] else sums[source];
        result[if (i < L.WORDS) L.fixed.word_start + i else L.fixed.carry_start + i - L.WORDS] = value;
    }
    return result;
}

// Derive and deduplicate the exact linear forms once at compile time. Evaluation
// adds only their nonzero opcode coefficients; 110 enables do not repeat 65-way
// classification or allocate/commit 110 CPU columns per row.
const enable_plan = blk: {
    @setEvalBranchQuota(100_000);
    var plan: struct {
        masks: [L.WORDS + L.CARRIES]u128 = @splat(0),
        sources: [L.WORDS + L.CARRIES]u8 = undefined,
        count: usize = 0,
    } = .{};
    for (0..L.WORDS + L.CARRIES) |i| {
        const slot: ?u8 = if (i < L.WORDS) switch (@as(L.Word, @enumFromInt(i))) {
            .a => 0,
            .b => 1,
            .previous_rd => 2,
            .memory_before, .memory_after => 3,
            else => null,
        } else null;
        if (slot) |value| {
            plan.sources[i] = 128 + value;
            continue;
        }
        var mask: u128 = 0;
        for (0..L.fixed.OPCODES) |opcode| {
            const enabled = if (i < L.WORDS)
                ops.wordActive(@enumFromInt(i), @enumFromInt(opcode), @splat(false))
            else
                ops.carryActive(@enumFromInt((i - L.WORDS) / 8), (i - L.WORDS) % 8, @enumFromInt(opcode));
            if (enabled) mask |= @as(u128, 1) << @intCast(opcode);
        }
        var source: usize = 0;
        while (source < plan.count and plan.masks[source] != mask) : (source += 1) {}
        if (source == plan.count) {
            plan.masks[source] = mask;
            plan.count += 1;
        }
        plan.sources[i] = @intCast(source);
    }
    break :blk plan;
};
