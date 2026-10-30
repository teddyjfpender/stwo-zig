//! Per-access first-halt policy. The address is derived from the admitted ELF.
//! A later zero endpoint cannot erase an earlier nonzero halt write/read.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const COLUMN_COUNT = 2;
pub const CONSTRAINT_COUNT = 10;
pub const DEGREE = 4;
pub const Policy = struct {
    halt_address: u32,
    permitted_final_instruction_cycle: ?u32 = null,
    pub fn validate(self: Policy) !void {
        // Native aligned addresses have an independently proved 28-bit quarter.
        if (self.halt_address % 4 != 0 or self.halt_address >= 1 << 30) return error.InvalidNativeHaltPolicy;
        if (self.permitted_final_instruction_cycle) |cycle| if (cycle == 0 or cycle >= 1 << 25) return error.InvalidNativeHaltPolicy;
    }
};
fn c(comptime S: type, value: u32) S {
    if (S == M) return M.fromCanonical(value);
    return @import("block_v7_memory_relations_v1.zig").lift(S, Q.fromBase(M.fromCanonical(value)));
}
/// Also applies to caller memory rows once their byte address, instruction
/// cycle and after bytes are authenticated. No final-endpoint shortcut.
pub fn constraints(comptime S: type, policy: Policy, active: S, byte_address: S, cycle: S, after: [4]S, aux: [2]S) [CONSTRAINT_COUNT]S {
    const delta = byte_address.sub(c(S, policy.halt_address));
    const hit = aux[0];
    const inv = aux[1];
    const inactive = S.one().sub(active);
    const gate = if (policy.permitted_final_instruction_cycle) |last| hit.mul(cycle.sub(c(S, last))) else hit;
    var out: [CONSTRAINT_COUNT]S = undefined;
    out[0] = hit.mul(hit.sub(active));
    out[1] = delta.mul(hit);
    out[2] = delta.mul(inv).sub(active).add(hit);
    out[3] = inactive.mul(hit);
    out[4] = inactive.mul(inv);
    out[5] = hit.mul(inv);
    for (after, 0..) |byte, i| out[6 + i] = gate.mul(byte);
    return out;
}
/// Reviewed physical identities, pinned to the typed AIR rather than a second
/// manually maintained load/store interpretation. The read after-word is src;
/// the write after-word is dst.next (including byte/halfword merged stores).
pub const NativeColumns = struct {
    pub const clock = 0;
    pub const store_after = [4]usize{ 8, 9, 10, 11 };
    pub const load_after = [4]usize{ 19, 20, 21, 22 };
    pub const store_flags = [3]usize{ 39, 40, 41 };
    pub const quarter = 48;
    pub const width = 50;
    pub const used = [13]usize{ clock, quarter, store_flags[0], store_flags[1], store_flags[2], load_after[0], load_after[1], load_after[2], load_after[3], store_after[0], store_after[1], store_after[2], store_after[3] };
};
const Typed = @import("../air/lang/typed_load_store.zig");
const ValueId = @import("../air/lang/types.zig").ValueId;
fn numbered(comptime T: type, next: *u32) T {
    if (T == ValueId) {
        const value: ValueId = @enumFromInt(next.*);
        next.* += 1;
        return value;
    }
    var result: T = undefined;
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.fields) |field| {
            @field(result, field.name) = numbered(field.type, next);
        },
        .array => |info| for (0..info.len) |i| {
            result[i] = numbered(info.child, next);
        },
        else => @compileError("unsupported typed load/store physical manifest type"),
    }
    return result;
}
comptime {
    // Updating typed semantics requires an explicit review of the guard's
    // physical binding, even when the total column count stays unchanged.
    if (!std.mem.eql(u8, Typed.SEMANTIC_DIGEST_HEX, "3257ffcf1f911056a0724255043536e7820607159c4ea8b7e490b65dc16b7316")) @compileError("review native halt binding after typed load/store semantic change");
    var next: u32 = 0;
    const columns = numbered(Typed.Columns, &next);
    const physical = columns.physical();
    const expected = [_]ValueId{ columns.clock, columns.aligned_addr_quarter, columns.is_sb, columns.is_sh, columns.is_sw, columns.src.value[0], columns.src.value[1], columns.src.value[2], columns.src.value[3], columns.dst.next[0], columns.dst.next[1], columns.dst.next[2], columns.dst.next[3] };
    if (physical.len != NativeColumns.width or Typed.MAIN_COLUMN_COUNT != NativeColumns.width) @compileError("native halt physical manifest width changed");
    for (NativeColumns.used, expected) |index, value| if (physical[index] != value) @compileError("native halt physical manifest binding changed");
}
pub const INPUT_COUNT = NativeColumns.used.len;
pub fn constraintsSparse(comptime S: type, policy: Policy, active: S, input: [INPUT_COUNT]S, aux: [2]S) [CONSTRAINT_COUNT]S {
    const store = input[2].add(input[3]).add(input[4]);
    var after: [4]S = undefined;
    for (&after, 0..) |*byte, i| byte.* = input[5 + i].add(store.mul(input[9 + i].sub(input[5 + i])));
    return constraints(S, policy, active, input[1].mul(c(S, 4)), input[0], after, aux);
}
pub fn constraintsNative(comptime S: type, policy: Policy, active: S, main: []const S, aux: [2]S) ![CONSTRAINT_COUNT]S {
    if (main.len != NativeColumns.width) return error.InvalidNativeHaltRow;
    var input: [INPUT_COUNT]S = undefined;
    for (&input, NativeColumns.used) |*value, index| value.* = main[index];
    return constraintsSparse(S, policy, active, input, aux);
}
/// Base-field row lanes keep all ten polynomial residuals in M31. Secure
/// arithmetic is used only for their shared random linear combination.
pub const PackedBase = struct {
    value: core.fields.m31.PackedM31,
    pub inline fn zero() @This() {
        return .{ .value = @splat(0) };
    }
    pub inline fn one() @This() {
        return .{ .value = @splat(1) };
    }
    pub inline fn splat(value: Q) @This() {
        return .{ .value = core.fields.m31.splatPacked(value.tryIntoM31() catch unreachable) };
    }
    pub inline fn add(a: @This(), b: @This()) @This() {
        return .{ .value = core.fields.m31.addPacked(a.value, b.value) };
    }
    pub inline fn sub(a: @This(), b: @This()) @This() {
        return .{ .value = core.fields.m31.subPacked(a.value, b.value) };
    }
    pub inline fn mul(a: @This(), b: @This()) @This() {
        return .{ .value = core.fields.m31.mulPacked(a.value, b.value) };
    }
};
pub const PackedQ = core.fields.packed_qm31.PackedQM31;
pub fn foldPacked(checks: [CONSTRAINT_COUNT]PackedBase, weights: [CONSTRAINT_COUNT]PackedQ) PackedQ {
    var result = PackedQ.zero();
    inline for (checks, weights) |check, weight| result = result.add(weight.mulBase(check.value));
    return result;
}
pub fn witness(active: bool, byte_address: M, policy: Policy) ![2]M {
    try policy.validate();
    if (!active) return .{ M.zero(), M.zero() };
    const delta = byte_address.sub(M.fromCanonical(policy.halt_address));
    return if (delta.isZero()) .{ M.one(), M.zero() } else .{ M.zero(), try delta.inv() };
}
pub fn count(shape: *const Shape) usize {
    var n: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        n += 1;
    };
    return n;
}
pub fn mainLogs(a: std.mem.Allocator, shape: *const Shape) ![]u32 {
    return mainLogsWithExternal(a, shape, 0);
}
pub fn mainLogsWithExternal(a: std.mem.Allocator, shape: *const Shape, external: u32) ![]u32 {
    const original = try Template.columnLogs(a, shape, external, .main);
    defer a.free(original);
    const logs = try a.alloc(u32, original.len + 2 * count(shape));
    @memcpy(logs[0..original.len], original);
    var i = original.len;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        @memset(logs[i..][0..2], desc.log_size);
        i += 2;
    };
    return logs;
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    original_count: usize,
    columns: []Column,
    pub fn deinit(self: *Owned) void {
        for (self.columns[self.original_count..]) |column| self.allocator.free(column.values);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, shape: *const Shape, original: []const Column, policy: Policy) !Owned {
    return prepareWithExternal(a, shape, original, policy, 0);
}
pub fn prepareWithExternal(a: std.mem.Allocator, shape: *const Shape, original: []const Column, policy: Policy, external: u32) !Owned {
    try policy.validate();
    const logs = try Template.columnLogs(a, shape, external, .main);
    defer a.free(logs);
    if (original.len != logs.len) return error.InvalidNativeHaltColumns;
    for (original, logs) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidNativeHaltColumns;
    const columns = try a.alloc(Column, original.len + 2 * count(shape));
    errdefer a.free(columns);
    @memcpy(columns[0..original.len], original);
    var ready = original.len;
    errdefer for (columns[original.len..ready]) |column| a.free(column.values);
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        defer offset += desc.n_columns;
        if (desc.family != .load_store) continue;
        if (desc.n_columns != NativeColumns.width) return error.InvalidNativeHaltColumns;
        const rows = @as(usize, 1) << @intCast(desc.log_size);
        for (0..2) |_| {
            columns[ready] = .{ .log_size = desc.log_size, .values = try a.alloc(M, rows) };
            ready += 1;
        }
        for (0..rows) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, desc.log_size), desc.log_size);
            const aux = try witness(logical < desc.n_rows, original[offset + NativeColumns.quarter].values[physical].mul(M.fromCanonical(4)), policy);
            @constCast(columns[ready - 2].values)[physical] = aux[0];
            @constCast(columns[ready - 1].values)[physical] = aux[1];
        }
    }
    return .{ .allocator = a, .original_count = original.len, .columns = columns };
}
