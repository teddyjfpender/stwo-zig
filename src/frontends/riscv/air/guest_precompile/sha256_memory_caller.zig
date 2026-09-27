//! Typed CPU/memory boundary for the general SHA compression contract.
//! The combined execution profile must admit this roster before activation.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const relation = @import("../lang/relation.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const graph = @import("sha256_compression_graph.zig");
const contract = @import("../../isa/sha256_compression_v1.zig");
const record_mod = @import("sha256_memory_record.zig");
const clocks = @import("../../access_clock.zig");
const M = core.fields.m31.M31;
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const production_active = false;
pub const PROGRAM_BOUND_PC_INPUTS: []const usize = &.{Layout.pc};
pub const Layout = struct {
    pub const clock = 0;
    pub const pc = 1;
    pub const register_clock = 2;
    pub const memory_clock = 3;
    pub const registers = 4;
    pub const pointers = 6;
    pub const register_previous = 14;
    pub const register_gap = 16;
    pub const pointer_words = 18;
    pub const end_words = 20;
    pub const before = 28;
    pub const output = 124;
    pub const addresses = 156;
    pub const previous = 180;
    pub const gaps = 204;
    pub const state_first = 228;
    pub const span_gap = 229;
    pub const scaled_pointer_high = 233;
    pub const scaled_register = 235;
    pub const register_difference_inverse = 237;
};
pub const PHYSICAL_MAIN_COLUMN_COUNT = 238;
pub const PREPROCESSED_COLUMN_COUNT = 1;
pub const LOGICAL_INPUT_COUNT = 239;
pub const DIRECT_CONSTRAINT_COUNT = 63;
pub const RELATION_EVENT_COUNT = 189;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 95;
pub const INTERACTION_COLUMN_COUNT = 380;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, "e6a6504bd77f318065725524cd55e3378c71bced21c6bf1fc3c4260d8a067ed9") catch unreachable;
    break :blk result;
};
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const @This()) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidShaCallerGeometry;
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidShaCallerIdentity;
    }
};
fn columnType(i: usize) lang.types.Type {
    if (i == PHYSICAL_MAIN_COLUMN_COUNT) return .selector;
    if (i == Layout.pc) return .pc;
    if (i == Layout.clock or (i >= Layout.register_clock and i <= Layout.memory_clock) or
        (i >= Layout.register_previous and i < Layout.register_gap) or (i >= Layout.previous and i < Layout.gaps)) return .clock;
    if (i >= Layout.registers and i < Layout.pointers) return .register_index;
    if ((i >= Layout.register_gap and i < Layout.pointer_words) or (i >= Layout.gaps and i < Layout.state_first)) return .uint20;
    if (i >= Layout.addresses and i < Layout.previous) return lang.types.Type.boundedField(28) catch unreachable;
    if (i == Layout.state_first) return .bit;
    if (i == Layout.end_words + 3 or i == Layout.end_words + 7 or i == Layout.span_gap + 3) return lang.types.Type.boundedField(4) catch unreachable;
    if ((i >= Layout.pointers and i < Layout.register_previous) or (i >= Layout.end_words and i < Layout.addresses) or (i >= Layout.span_gap and i < Layout.register_difference_inverse)) return .byte;
    return .felt;
}
const Author = struct {
    arena: lang.ir.Arena,
    ids: [LOGICAL_INPUT_COUNT + 4]Id,
    active_index: usize = PHYSICAL_MAIN_COLUMN_COUNT,
    fn c(self: *Author, value: u32) !Id {
        return self.arena.constantField(value, span);
    }
    fn add(self: *Author, a: Id, b: Id) !Id {
        return self.arena.add(a, b, span);
    }
    fn sub(self: *Author, a: Id, b: Id) !Id {
        return self.arena.sub(a, b, span);
    }
    fn mul(self: *Author, a: Id, b: Id) !Id {
        return self.arena.mul(a, b, span);
    }
    fn eq(self: *Author, a: Id, b: Id) !void {
        var name: [48]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&name, "sha.caller.eq_{d}", .{self.arena.constraintsView().len}), try self.sub(a, b), null, .semantic, span);
    }
    fn event(self: *Author, domain: relation.Domain, role: relation.Role, values: []const Id) !void {
        try self.eventWeighted(domain, role, values, self.ids[self.active_index]);
    }
    fn eventWeighted(self: *Author, domain: relation.Domain, role: relation.Role, values: []const Id, weight: Id) !void {
        _ = try effects.appendGroup(1, &self.arena, .{.{ .domain = domain, .role = role, .values = values, .weight = weight }}, span);
    }
    fn localZeroPointer(self: *Author, pointer: []const Id, register: Id, previous: Id, nonzero: Id, inverse: Id) !void {
        const active = self.ids[self.active_index];
        const one = try self.c(1);
        const zero = try self.c(0);
        const live_zero = try self.mul(active, try self.sub(one, nonzero));
        const inactive = try self.sub(one, active);
        try self.eq(try self.mul(active, inactive), zero);
        try self.eq(zero, zero); // Static register space0 boolean equation.
        try self.eq(try self.mul(active, try self.mul(nonzero, try self.sub(one, nonzero))), zero);
        try self.eq(try self.mul(live_zero, register), zero);
        try self.eq(try self.mul(active, try self.sub(try self.mul(register, inverse), nonzero)), zero);
        try self.eq(try self.mul(inactive, nonzero), zero);
        try self.eq(try self.mul(inactive, inverse), zero);
        for (pointer) |byte| try self.eq(try self.mul(live_zero, byte), zero);
        for (pointer) |byte| try self.eq(try self.mul(live_zero, byte), zero);
        try self.eq(try self.mul(live_zero, previous), zero);
        try self.eq(try self.mul(live_zero, inverse), zero);
    }
    fn compose(self: *Author, limbs: []const Id) !Id {
        var result = try self.c(0);
        for (limbs, 0..) |byte, i| result = try self.add(result, try self.mul(byte, try self.c(@as(u32, 1) << @as(u5, @intCast(i * 8)))));
        return result;
    }
    fn bytes(self: *Author, values: []const Id) !void {
        try self.event(.range_check_8_8, .request, values[0..2]);
        try self.event(.range_check_8_8, .request, values[2..4]);
    }
    fn limbs28(self: *Author, values: []const Id) !void {
        try self.event(.range_check_8_8, .request, values[0..2]);
        // The middle byte is repeated to keep the exact shared-table ABI.
        try self.event(.range_check_8_8_4, .request, &.{ values[2], values[2], values[3] });
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var result = try buildForRecipe(a, false);
    errdefer result.deinit();
    try result.validate();
    return result;
}
/// Source-authoring candidate only. Its new typed identity must be independently
/// pinned by the containing profile; this function does not grant admission.
pub const LocalZeroCandidate = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
    pub fn identity(self: *const @This()) ![32]u8 {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT + 34 or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidShaCallerGeometry;
        return (try lang.digest.computeIdentity(&self.arena)).bytes;
    }
};
pub fn buildLocalZeroCandidate(a: std.mem.Allocator) !LocalZeroCandidate {
    const result = try buildForRecipe(a, true);
    return .{ .arena = result.arena, .events = result.events };
}
fn buildForRecipe(a: std.mem.Allocator, local_zero: bool) !Definition {
    var o = Author{ .arena = lang.ir.Arena.init(a), .ids = undefined, .active_index = PHYSICAL_MAIN_COLUMN_COUNT + (if (local_zero) @as(usize, 4) else 0) };
    errdefer o.arena.deinit();
    for (o.ids[0 .. o.active_index + 1], 0..) |*id, i| {
        var name: [48]u8 = undefined;
        const ty: lang.types.Type = if (i == o.active_index) .selector else if (local_zero and i >= PHYSICAL_MAIN_COLUMN_COUNT) (if ((i - PHYSICAL_MAIN_COLUMN_COUNT) % 2 == 0) .bit else .felt) else columnType(i);
        id.* = try o.arena.input(try std.fmt.bufPrint(&name, "sha.caller.value_{d}", .{i}), ty, span);
    }
    const ids = o.ids;
    const active = ids[o.active_index];
    const one = try o.c(1);
    const four = try o.c(4);
    try o.eq(ids[Layout.register_clock], try o.sub(try o.mul(four, ids[Layout.clock]), try o.mul(try o.c(3), active)));
    try o.eq(ids[Layout.memory_clock], try o.sub(try o.mul(four, ids[Layout.clock]), try o.mul(try o.c(2), active)));
    try o.event(.program_access, .request, &.{ ids[Layout.pc], try o.c(contract.proof_opcode_id), try o.c(0), ids[Layout.registers], ids[Layout.registers + 1] });
    _ = try @import("../lang/effects.zig").retire(&o.arena, .{ .pc = ids[Layout.pc], .clock = ids[Layout.clock] }, .{ .pc = try o.arena.instructionNextPc(ids[Layout.pc], span), .clock = try o.arena.instructionNextClock(ids[Layout.clock], span) }, active, span);
    for (0..2) |i| {
        const pointer = ids[Layout.pointers + 4 * i ..][0..4];
        const end = ids[Layout.end_words + 4 * i ..][0..4];
        try o.bytes(pointer);
        try o.limbs28(end);
        try o.eq(try o.compose(pointer), try o.mul(four, ids[Layout.pointer_words + i]));
        try o.eq(try o.compose(end), try o.add(ids[Layout.pointer_words + i], try o.mul(try o.c(if (i == 0) 7 else 15), active)));
        try o.eq(ids[Layout.scaled_pointer_high + i], try o.mul(pointer[3], four));
        try o.eq(ids[Layout.scaled_register + i], try o.mul(ids[Layout.registers + i], try o.c(8)));
        try o.event(.range_check_8_8, .request, &.{ ids[Layout.scaled_pointer_high + i], ids[Layout.scaled_register + i] });
        const address = try o.arena.registerAddress(ids[Layout.registers + i], span);
        const custody = if (local_zero) try o.mul(active, ids[PHYSICAL_MAIN_COLUMN_COUNT + 2 * i]) else active;
        try o.eventWeighted(.memory_access, .consume, &(.{ try o.c(0), address, ids[Layout.register_previous + i] } ++ pointer.*), custody);
        try o.eventWeighted(.memory_access, .emit, &(.{ try o.c(0), address, ids[Layout.register_clock] } ++ pointer.*), custody);
        try o.eq(ids[Layout.register_gap + i], try o.sub(try o.sub(ids[Layout.register_clock], ids[Layout.register_previous + i]), active));
        try o.eventWeighted(.range_check_20, .request, &.{ids[Layout.register_gap + i]}, custody);
        if (local_zero) try o.localZeroPointer(pointer, ids[Layout.registers + i], ids[Layout.register_previous + i], ids[PHYSICAL_MAIN_COLUMN_COUNT + 2 * i], ids[PHYSICAL_MAIN_COLUMN_COUNT + 2 * i + 1]);
    }
    try o.eq(try o.mul(try o.sub(ids[Layout.registers], ids[Layout.registers + 1]), ids[Layout.register_difference_inverse]), active);
    const first = ids[Layout.state_first];
    try o.eq(try o.mul(first, try o.sub(one, first)), try o.c(0));
    try o.limbs28(ids[Layout.span_gap..][0..4]);
    const left = try o.sub(try o.sub(ids[Layout.pointer_words + 1], ids[Layout.pointer_words]), try o.mul(try o.c(8), active));
    const right = try o.sub(try o.sub(ids[Layout.pointer_words], ids[Layout.pointer_words + 1]), try o.mul(try o.c(16), active));
    try o.eq(try o.compose(ids[Layout.span_gap..][0..4]), try o.add(try o.mul(first, left), try o.mul(try o.sub(one, first), right)));
    const topology = graph.build();
    for (0..24) |word| {
        const before = ids[Layout.before + 4 * word ..][0..4];
        const after = if (word < 8) ids[Layout.output + 4 * word ..][0..4] else before;
        try o.bytes(before);
        if (word < 8) try o.bytes(after);
        try o.eq(ids[Layout.addresses + word], try o.add(ids[Layout.pointer_words + @as(usize, @intFromBool(word >= 8))], try o.mul(try o.c(@intCast(if (word < 8) word else word - 8)), active)));
        try o.eq(ids[Layout.gaps + word], try o.sub(try o.sub(ids[Layout.memory_clock], ids[Layout.previous + word]), active));
        try o.event(.memory_access, .consume, &(.{ try o.c(1), try o.arena.alignedWordAddress(ids[Layout.addresses + word], span), ids[Layout.previous + word] } ++ before.*));
        try o.event(.memory_access, .emit, &(.{ try o.c(1), try o.arena.alignedWordAddress(ids[Layout.addresses + word], span), ids[Layout.memory_clock] } ++ after.*));
        try o.event(.range_check_20, .request, &.{ids[Layout.gaps + word]});
        const sha_bytes = if (word < 8) before.* else .{ before[3], before[2], before[1], before[0] };
        try o.event(.recursion_wire, .emit, &(.{ ids[Layout.clock], try o.c(@intCast(graph.input_boundary_offset + word)) } ++ sha_bytes));
        if (word < 8) try o.event(.recursion_wire, .consume, &(.{ ids[Layout.clock], try o.c(topology.output[word]) } ++ after.*));
    }
    try lang.validate.validate(&o.arena);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    const result = Definition{ .arena = o.arena, .events = events };
    if (local_zero and o.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT + 2 * @import("../x0_local_custody_v1.zig").CONSTRAINT_COUNT) return error.InvalidShaCallerGeometry;
    return result;
}
fn writeBytes(result: *Row, at: usize, value: u32) void {
    for (0..4) |i| result[at + i] = M.fromCanonical((value >> @as(u5, @intCast(8 * i))) & 255);
}
pub fn row(record: record_mod.Record) !Row {
    try record.validate();
    var result: Row = @splat(M.zero());
    result[PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    result[Layout.clock] = M.fromCanonical(record.execution_clock);
    result[Layout.pc] = M.fromCanonical(record.pc);
    const reg_clock = clocks.encode(record.execution_clock, .first);
    const mem_clock = clocks.encode(record.execution_clock, .second);
    result[Layout.register_clock] = M.fromCanonical(reg_clock);
    result[Layout.memory_clock] = M.fromCanonical(mem_clock);
    const pointers = [2]u32{ record.state_ptr, record.block_ptr };
    const regs = [2]u5{ record.state_register, record.block_register };
    for (pointers, regs, 0..) |pointer, register, i| {
        result[Layout.registers + i] = M.fromCanonical(register);
        writeBytes(&result, Layout.pointers + 4 * i, pointer);
        result[Layout.pointer_words + i] = M.fromCanonical(pointer / 4);
        writeBytes(&result, Layout.end_words + 4 * i, pointer / 4 + @as(u32, if (i == 0) 7 else 15));
        result[Layout.register_previous + i] = M.fromCanonical(record.pointer_previous_clocks[i]);
        result[Layout.register_gap + i] = M.fromCanonical(reg_clock - record.pointer_previous_clocks[i] - 1);
        result[Layout.scaled_pointer_high + i] = M.fromCanonical((pointer >> 24) * 4);
        result[Layout.scaled_register + i] = M.fromCanonical(@as(u32, register) * 8);
    }
    result[Layout.register_difference_inverse] = try result[Layout.registers].sub(result[Layout.registers + 1]).inv();
    const first = record.state_ptr < record.block_ptr;
    result[Layout.state_first] = M.fromCanonical(@intFromBool(first));
    writeBytes(&result, Layout.span_gap, if (first) (record.block_ptr - record.state_ptr - 32) / 4 else (record.state_ptr - record.block_ptr - 64) / 4);
    for (0..24) |word| {
        writeBytes(&result, Layout.before + 4 * word, record.before(word));
        if (word < 8) writeBytes(&result, Layout.output + 4 * word, record.output[word]);
        result[Layout.addresses + word] = M.fromCanonical(record.address(word) / 4);
        result[Layout.previous + word] = M.fromCanonical(record.memory_previous_clocks[word]);
        result[Layout.gaps + word] = M.fromCanonical(mem_clock - record.memory_previous_clocks[word] - 1);
    }
    return result;
}
