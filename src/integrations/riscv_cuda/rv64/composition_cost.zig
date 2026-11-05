//! Allocation/lifetime ledger of resident_composition.Job.run. Source owners
//! remain external. Direct-source eligibility and cold FIXED misses are inputs
//! that must be frozen and validated by the production adapter before admission.
const std = @import("std");
const A = @import("global_admission.zig");
pub const Auxiliary = enum { none, last, hc };
pub const Column = struct { log: u32, direct: bool };
pub const Role = struct {
    trace_log: u32,
    eval_log: u32,
    columns: []const Column,
    auxiliary: Auxiliary = .none,
    masks: usize,
    parameters: usize,
    constraints: usize,
};
pub const Format = enum { legacy_blake32_m31, poseidon2_w24_v1 };
pub const Input = struct {
    format: Format = .legacy_blake32_m31,
    roles: []const Role,
    shared_role_arena: bool = false,
    log: u32,
    split: u32,
    beta: u32,
    separate_coefficients: bool,
    constraints: usize,
    /// Whole cold immutable FIXED forest, one allocation. Zero only for an
    /// audited cache hit/device-only forest. Cache aliases cost no new bytes.
    fixed_cold_words: u64 = 0,
};
pub const Kind = enum { fixed_forest, role_arena, auxiliary_inverse, hc, direct_logs, parameters, powers, masks, denominators, bucket, output, commit_scratch, accumulator, composition_inverse, tree };
pub const Allocation = struct { kind: Kind, role: ?u32, bytes: u64, rounded: A.Footprint, live_until_end: bool };
pub const Plan = struct {
    format: Format = .legacy_blake32_m31,
    events: std.ArrayList(Allocation) = .empty,
    additional_peak: A.Footprint = .{},
    workspace_words: u64 = 0,
    retained_after: A.Footprint = .{},
    live: A.Footprint = .{},
    host_cost_known: bool = false,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        self.events.deinit(a);
        self.* = undefined;
    }
    fn allocate(self: *Plan, a: std.mem.Allocator, kind: Kind, role: ?u32, words: u64, until_end: bool) !A.Footprint {
        const bytes = try std.math.mul(u64, @max(words, 1), 4);
        const rounded = try A.Footprint.allocation(bytes);
        try self.events.append(a, .{ .kind = kind, .role = role, .bytes = bytes, .rounded = rounded, .live_until_end = until_end });
        self.live = try self.live.add(rounded);
        self.additional_peak = self.additional_peak.max(self.live);
        return rounded;
    }
};
fn rows(log: u32) !u64 {
    if (log > 28) return error.InvalidCompositionGeometry;
    return @as(u64, 1) << @intCast(log);
}
fn mul(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
fn add(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b);
}
pub fn arenaWords(role: Role) !u64 {
    const rl = role.trace_log;
    const el = role.eval_log;
    if (rl < 4 or rl > 27 or el < rl + 1 or el > rl + 2 or el > 28) return error.InvalidCompositionGeometry;
    const n = try rows(el);
    const aux: u64 = switch (role.auxiliary) {
        .none => 0,
        .last => 1,
        .hc => 10,
    };
    const columns = try add(role.columns.len, aux);
    var staging = try mul(aux, try rows(rl));
    for (role.columns) |column| {
        if (column.log >= el) return error.InvalidCompositionGeometry;
        if (column.direct) {
            if (column.log + 1 != el and column.log + 2 != el) return error.InvalidCompositionDirectSource;
        } else staging = try add(staging, try rows(column.log));
    }
    const tw_base = try add(staging, try mul(columns, n));
    const desc_base = std.mem.alignForward(u64, try add(tw_base, n / 2), 2);
    return try add(desc_base, try mul(columns, 6));
}
pub fn init(a: std.mem.Allocator, input: Input) !Plan {
    if (input.format != .legacy_blake32_m31) return error.AllocationCostFormatUnavailable;
    if (input.roles.len == 0 or input.log < 5 or input.log > 28 or input.split < 1 or input.split > 2 or input.beta < 1 or input.beta > 4 or (input.separate_coefficients and input.beta != 1)) return error.InvalidCompositionGeometry;
    var p: Plan = .{};
    errdefer p.deinit(a);
    if (input.fixed_cold_words != 0) p.retained_after = try p.allocate(a, .fixed_forest, null, input.fixed_cold_words, true);
    var buckets: [29]bool = @splat(false);
    var constraints: u64 = 0;
    var shared: A.Footprint = .{};
    if (input.shared_role_arena) {
        for (input.roles) |role| p.workspace_words = @max(p.workspace_words, try arenaWords(role));
        shared = try p.allocate(a, .role_arena, null, p.workspace_words, false);
    }
    for (input.roles, 0..) |role, ordinal| {
        const rl = role.trace_log;
        const el = role.eval_log;
        if (rl < 4 or rl > 27 or el < rl + 1 or el > rl + 2 or el > input.log or role.constraints == 0) return error.InvalidCompositionGeometry;
        const id: u32 = @intCast(ordinal);
        constraints = try add(constraints, role.constraints);
        const n = try rows(el);
        const aux: u64 = switch (role.auxiliary) {
            .none => 0,
            .last => 1,
            .hc => 10,
        };
        const columns = try add(role.columns.len, aux);
        const arena = if (input.shared_role_arena) A.Footprint{} else try p.allocate(a, .role_arena, id, try arenaWords(role), false);
        if (aux != 0) {
            _ = try p.allocate(a, .auxiliary_inverse, id, (try rows(rl)) / 2, true);
            if (role.auxiliary == .hc) _ = try p.allocate(a, .hc, id, 16 * @as(u64, rl), true);
        }
        _ = try p.allocate(a, .direct_logs, id, columns, true);
        _ = try p.allocate(a, .parameters, id, try mul(role.parameters, 8), true);
        _ = try p.allocate(a, .powers, id, try mul(role.constraints, 8), true);
        _ = try p.allocate(a, .masks, id, try mul(role.masks, 2), true);
        _ = try p.allocate(a, .denominators, id, try rows(el - rl), true);
        if (!buckets[el]) {
            _ = try p.allocate(a, .bucket, id, try mul(n, 8), true);
            buckets[el] = true;
        }
        // The role's arena is released at loop end; uploaded metadata, inverse
        // planes and quotient buckets remain live until the final joined defer.
        p.live.large -= arena.large;
        p.live.small -= arena.small;
    }
    if (constraints != input.constraints) return error.WrongCompositionConstraintCount;
    p.live.large -= shared.large;
    p.live.small -= shared.small;
    const n = try rows(input.log);
    const coefficient_words = try mul(n, 8);
    const chunk_log = input.log - input.split;
    const count = @as(u64, 8) << @intCast(input.split);
    const commit_rows = try rows(chunk_log + input.beta);
    const eval_base = if (input.separate_coefficients) 0 else coefficient_words;
    const output_tw = try add(eval_base, try mul(count, commit_rows));
    const output_desc = std.mem.alignForward(u64, try add(output_tw, commit_rows / 2), 2);
    const scratch_words = try add(output_desc, try mul(count, if (input.separate_coefficients) 1 else 6));
    const output = try p.allocate(a, .output, null, if (input.separate_coefficients) coefficient_words else scratch_words, true);
    p.retained_after = try p.retained_after.add(output);
    if (input.separate_coefficients) _ = try p.allocate(a, .commit_scratch, null, scratch_words, true);
    _ = try p.allocate(a, .accumulator, null, coefficient_words, true);
    _ = try p.allocate(a, .composition_inverse, null, n / 2, true);
    _ = try p.allocate(a, .tree, null, try mul(2 * commit_rows - 1, 8), true);
    return p;
}

test "composition lifetime plan retains metadata but releases each role arena" {
    const cols = [_]Column{.{ .log = 4, .direct = true }} ** 3;
    const role = Role{ .trace_log = 4, .eval_log = 6, .columns = &cols, .auxiliary = .last, .masks = 3, .parameters = 2, .constraints = 1 };
    var p = try init(std.testing.allocator, .{ .roles = &.{ role, role }, .log = 6, .split = 1, .beta = 1, .separate_coefficients = true, .constraints = 2 });
    defer p.deinit(std.testing.allocator);
    var arenas: usize = 0;
    var bucket_count: usize = 0;
    for (p.events.items) |event| switch (event.kind) {
        .role_arena => {
            arenas += 1;
            try std.testing.expectEqual(@as(u64, (16 + 4 * 64 + 32 + 4 * 6) * 4), event.bytes);
            try std.testing.expect(!event.live_until_end);
        },
        .bucket => bucket_count += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), arenas);
    try std.testing.expectEqual(@as(usize, 1), bucket_count);
    try std.testing.expectEqual(try A.Footprint.allocation(8 * 64 * 4), p.retained_after);
    try std.testing.expect(!p.host_cost_known);
}

test "classic Keccak role exposes its actual arena multiplier before mutation" {
    const cols = [_]Column{.{ .log = 18, .direct = true }} ** (32 + 1923 + 1560);
    const role = Role{ .trace_log = 18, .eval_log = 20, .columns = &cols, .auxiliary = .last, .masks = 1, .parameters = 1, .constraints = 1 };
    var p = try init(std.testing.allocator, .{ .roles = &.{role}, .log = 20, .split = 1, .beta = 1, .separate_coefficients = true, .constraints = 1 });
    defer p.deinit(std.testing.allocator);
    const expected_words: u64 = (1 << 18) + @as(u64, 3516) * (1 << 20) + (1 << 19) + 3516 * 6;
    try std.testing.expectEqual(expected_words * 4, p.events.items[0].bytes);
    try std.testing.expect(p.additional_peak.large > 14_747_000_000);
}

test "new hash ABI cannot reuse legacy composition allocation costs" {
    try std.testing.expectError(error.AllocationCostFormatUnavailable, init(std.testing.allocator, .{ .format = .poseidon2_w24_v1, .roles = &.{}, .log = 5, .split = 1, .beta = 1, .separate_coefficients = true, .constraints = 0 }));
}

test "max-role workspace includes later accumulated buckets before release" {
    const tall = [_]Column{.{ .log = 19, .direct = true }} ** 64;
    const short = [_]Column{.{ .log = 18, .direct = true }};
    const roles = [_]Role{
        .{ .trace_log = 19, .eval_log = 20, .columns = &tall, .masks = 1, .parameters = 1, .constraints = 1 },
        .{ .trace_log = 18, .eval_log = 19, .columns = &short, .masks = 1, .parameters = 1, .constraints = 1 },
    };
    const input = Input{ .roles = &roles, .log = 20, .split = 1, .beta = 1, .separate_coefficients = true, .constraints = 2 };
    var old = try init(std.testing.allocator, input);
    defer old.deinit(std.testing.allocator);
    var reuse_input = input;
    reuse_input.shared_role_arena = true;
    var shared_plan = try init(std.testing.allocator, reuse_input);
    defer shared_plan.deinit(std.testing.allocator);
    try std.testing.expectEqual(try arenaWords(roles[0]), shared_plan.workspace_words);
    try std.testing.expectEqual(old.additional_peak.large + A.chunk_bytes, shared_plan.additional_peak.large);
    try std.testing.expectEqual(old.retained_after, shared_plan.retained_after);
    try std.testing.expect(!shared_plan.host_cost_known);
}
