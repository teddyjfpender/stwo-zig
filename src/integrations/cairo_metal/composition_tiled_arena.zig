//! Bounded row tiles for large AIR components, including exact mask reads.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_cairo_frontend");
const eval_arena = @import("composition_eval_arena.zig");
const pool_split = frontend.witness.pool_split;
const Component = frontend.witness.composition_bundle.Component;

pub const Read = struct { global: u32, mask: i32, slab: u32 = 0 };
pub const Plan = struct {
    layout: eval_arena.Plan,
    reads: []Read,
    descriptors: []u32,
    tile_rows: u32,
    base_params: u32,
    eval_log: u32,

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.reads);
        allocator.free(self.descriptors);
        self.layout.deinit(allocator);
        self.* = undefined;
    }
};

fn less(_: void, a: Read, b: Read) bool {
    return a.global < b.global or (a.global == b.global and a.mask < b.mask);
}

pub fn plan(allocator: std.mem.Allocator, component: Component, byte_cap: u64) !Plan {
    var layout = try eval_arena.nativeGeometry(allocator, component);
    errdefer layout.deinit(allocator);
    var reads: std.ArrayList(Read) = .empty;
    defer reads.deinit(allocator);
    var seen = std.AutoHashMap(struct { global: u32, mask: i32 }, void).init(allocator);
    defer seen.deinit();
    for (component.parts) |part| for (part.program.base_insts) |inst| {
        if (inst.op != .trace_col and inst.op != .preprocessed_col) continue;
        if (inst.interaction >= layout.bases.len) return error.InvalidTraceShape;
        const begin = layout.bases[inst.interaction];
        const end = if (inst.interaction + 1 < layout.bases.len) layout.bases[inst.interaction + 1] else layout.columns;
        if (inst.a >= end - begin) return error.InvalidTraceShape;
        const global = begin + inst.a;
        const entry = try seen.getOrPut(.{ .global = global, .mask = inst.imm });
        if (!entry.found_existing) try reads.append(allocator, .{ .global = global, .mask = inst.imm });
    };
    std.mem.sort(Read, reads.items, {}, less);
    const metadata_words = try std.math.add(u64, 1 + 6 * @as(u64, layout.columns) + layout.interactions, try std.math.add(u64, 2 * @as(u64, reads.items.len), 4 * @as(u64, layout.ext_param_count) +
        4 * @as(u64, layout.coefficient_count) + layout.denominator_count));
    var tile_rows: u32 = @min(layout.eval_rows, 1 << 20);
    while (tile_rows != 0) : (tile_rows >>= 1) {
        const words = try std.math.add(u64, metadata_words, try std.math.mul(u64, reads.items.len + 4, tile_rows));
        if (words <= std.math.maxInt(u32) and words <= byte_cap / @sizeOf(u32)) break;
    }
    if (tile_rows < 2) return error.EvalArenaTooLarge;
    const descriptors = try allocator.alloc(u32, 5 * @as(usize, layout.columns) + 2 * reads.items.len);
    errdefer allocator.free(descriptors);
    var next: u64 = 0;
    for (reads.items) |*read| read.slab = try take(&next, tile_rows);
    layout.trace_offsets = try take(&next, 1 + layout.columns);
    const descriptor_base = try take(&next, descriptors.len);
    @memset(descriptors, 0);
    var read_cursor: usize = 0;
    var descriptor_cursor: usize = 0;
    for (0..layout.columns) |global| {
        const count_slot = descriptor_cursor;
        descriptor_cursor += 5;
        const first = read_cursor;
        while (read_cursor < reads.items.len and reads.items[read_cursor].global == global) : (read_cursor += 1) {
            const read = reads.items[read_cursor];
            if (read.mask == 0) descriptors[count_slot] = read.slab;
            if (read.mask == -1) descriptors[count_slot + 1] = read.slab;
            if (read.mask == 1) descriptors[count_slot + 2] = read.slab;
            descriptors[descriptor_cursor] = @bitCast(read.mask);
            descriptors[descriptor_cursor + 1] = read.slab;
            descriptor_cursor += 2;
        }
        descriptors[count_slot + 4] = @intCast(read_cursor - first);
    }
    std.debug.assert(descriptor_cursor == descriptors.len and read_cursor == reads.items.len);
    layout.column_base = descriptor_base; // Typed metadata, never a full column arena.
    layout.interaction_offsets = try take(&next, layout.interactions);
    const base_params = try take(&next, 0); // Expressible programs have no base parameters.
    layout.ext_params = try take(&next, 4 * @as(u64, layout.ext_param_count));
    layout.random_coeffs = try take(&next, 4 * @as(u64, layout.coefficient_count));
    layout.denom_inv = try take(&next, layout.denominator_count);
    for (&layout.coordinates) |*offset| offset.* = try take(&next, tile_rows);
    if (next > std.math.maxInt(u32) or next * @sizeOf(u32) > byte_cap) return error.EvalArenaTooLarge;
    layout.words = next;
    return .{ .layout = layout, .reads = try reads.toOwnedSlice(allocator), .descriptors = descriptors, .tile_rows = tile_rows, .base_params = base_params, .eval_log = component.evaluation_log_size };
}

fn take(next: *u64, count: u64) !u32 {
    const offset = std.math.cast(u32, next.*) orelse return error.EvalArenaTooLarge;
    next.* = try std.math.add(u64, next.*, count);
    return offset;
}

/// Copies one row tile and all required shifted reads. Mask mapping is the
/// core host evaluator's own function; stored lifting is applied afterward.
pub fn stage(words: []u32, planned: Plan, resolved: []const eval_arena.ResolvedScratch, row_base: u32, rows: u32) !u64 {
    if (words.len < planned.layout.words or resolved.len != planned.layout.columns or rows == 0 or
        rows > planned.tile_rows or row_base > planned.layout.eval_rows or rows > planned.layout.eval_rows - row_base or row_base & 1 != 0)
        return error.EvalArenaColumnShape;
    for (resolved) |column| {
        if (column.values.len == 0) continue;
        if (column.values.len < 2 or !std.math.isPowerOfTwo(column.values.len) or column.values.len > planned.layout.eval_rows or
            column.shift_amt != planned.eval_log - @as(u32, @intCast(@ctz(column.values.len))) + 1)
            return error.EvalArenaColumnShape;
    }
    words[planned.layout.trace_offsets] = row_base;
    @memcpy(words[planned.layout.column_base..][0..planned.descriptors.len], planned.descriptors);
    var descriptor_cursor: u32 = planned.layout.column_base;
    for (0..planned.layout.columns) |global| {
        words[planned.layout.trace_offsets + 1 + global] = descriptor_cursor;
        words[descriptor_cursor + 3] = if (resolved[global].values.len == 0) 1 else resolved[global].shift_amt;
        descriptor_cursor += 5 + 2 * words[descriptor_cursor + 4];
    }
    var staged_words: u64 = 0;
    for (planned.reads) |read| {
        const shift = words[words[planned.layout.trace_offsets + 1 + read.global] + 3];
        staged_words += nativePairWords(row_base, rows, shift);
    }
    const workers = @min(planned.reads.len, pool_split.workerCount(.{
        .rows = @as(usize, planned.reads.len) * rows,
        .min_rows_per_worker = 1 << 18,
    }));
    if (workers <= 1) {
        var work: Work = .{ .words = words, .plan = planned, .resolved = resolved, .row_base = row_base, .rows = rows, .worker = 0, .workers = 1 };
        work.run();
    } else {
        var storage: [pool_split.work_pool.MAX_WORKERS]Work = undefined;
        const jobs = storage[0..workers];
        for (jobs, 0..) |*work, worker| work.* = .{ .words = words, .plan = planned, .resolved = resolved, .row_base = row_base, .rows = rows, .worker = worker, .workers = workers };
        try pool_split.dispatch(Work, jobs);
    }
    return staged_words * @sizeOf(u32);
}

fn nativePairWords(row_base: u32, rows: u32, shift: u32) u32 {
    return (((row_base + rows - 1) >> @intCast(shift)) - (row_base >> @intCast(shift)) + 1) * 2;
}

const Work = struct {
    words: []u32,
    plan: Plan,
    resolved: []const eval_arena.ResolvedScratch,
    row_base: u32,
    rows: u32,
    failure: ?anyerror = null,
    worker: usize,
    workers: usize,
    pub fn run(self: *Work) void {
        var index = self.worker;
        while (index < self.plan.reads.len) : (index += self.workers) {
            const read = self.plan.reads[index];
            const column = self.resolved[read.global];
            const shift: u32 = if (column.values.len == 0) 1 else column.shift_amt;
            const native_words = nativePairWords(self.row_base, self.rows, shift);
            const destination = self.words[read.slab..][0..native_words];
            if (column.values.len == 0) {
                @memset(destination, 0);
                continue;
            }
            if (read.mask == 0) {
                const source_index = (self.row_base >> @intCast(shift)) * 2;
                @memcpy(destination, column.values[source_index..][0..native_words]);
                continue;
            }
            const first_group = self.row_base >> @intCast(shift);
            for (0..native_words / 2) |group| {
                const representative = (first_group + group) << @intCast(shift);
                inline for (0..2) |parity| {
                    const target = core.utils.offsetBitReversedCircleDomainIndex(representative + parity, self.plan.layout.trace_log_size, self.plan.eval_log, read.mask);
                    destination[2 * group + parity] = column.values[eval_arena.liftedIndex(target, @intCast(shift))];
                }
            }
        }
    }
};

const test_reads = [_]frontend.witness.eval_program.BaseInst{
    .{ .op = .preprocessed_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
    .{ .op = .trace_col, .interaction = 1, .dst = 1, .a = 0, .b = 0, .imm = -1 },
    .{ .op = .trace_col, .interaction = 1, .dst = 2, .a = 0, .b = 0, .imm = 1 },
    .{ .op = .trace_col, .interaction = 1, .dst = 3, .a = 0, .b = 0, .imm = -1 },
};
const test_denominators = [_]u32{ 1, 3, 5, 7 };
const test_spans = [_]frontend.witness.composition_bundle.TraceSpan{.{ .tree = 1, .start = 0, .end = 1 }};
const test_preprocessed = [_]u32{0};
const test_parts = [_]frontend.witness.composition_bundle.Part{.{
    .rc_base = 0,
    .semantic_hash = 0,
    .program = .{ .allocator = std.testing.allocator, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 2, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 4, .max_ext_regs = 0, .domain_log_size = 2 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = @constCast(&test_reads), .ext_insts = &.{}, .constraint_roots = &.{} },
}};
fn testComponent() Component {
    return .{ .label = @constCast("tiled-test"), .instance = 0, .trace_log_size = 2, .evaluation_log_size = 4, .n_constraints = 1, .random_coefficient_offset = 0, .trace_spans = @constCast(&test_spans), .preprocessed_indices = @constCast(&test_preprocessed), .denominator_inverses = @constCast(&test_denominators), .ext_sources = &.{}, .parts = @constCast(&test_parts) };
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var tiled = try plan(allocator, testComponent(), 232);
    defer tiled.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 4), tiled.tile_rows);
    try std.testing.expectEqual(@as(usize, 3), tiled.reads.len);
    try std.testing.expect(tiled.layout.words * 4 <= 232);
}
test "tiled composition owns no leaked allocation on any planning failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    try std.testing.expectError(error.EvalArenaTooLarge, plan(std.testing.allocator, testComponent(), 4));
}
test "tiled composition masks match full host columns across boundaries and short tails" {
    var tiled = try plan(std.testing.allocator, testComponent(), 232);
    defer tiled.deinit(std.testing.allocator);
    const words = try std.testing.allocator.alloc(u32, @intCast(tiled.layout.words));
    defer std.testing.allocator.free(words);
    const short = [_]u32{ 3, 11, 19, 29 };
    const long = [_]u32{ 7, 13, 23, 31, 43, 53, 61, 71 };
    var resolved = [_]eval_arena.ResolvedScratch{ .{ .values = &short, .shift_amt = 3 }, .{ .values = &long, .shift_amt = 2 } };
    var full: [2][16]u32 = undefined;
    for (resolved, &full) |column, *lifted| try eval_arena.liftColumn(lifted, column.values, @intCast(column.shift_amt));
    for ([_]u32{ 0, 4, 8, 12, 14 }) |base| {
        const rows = @min(tiled.tile_rows, 16 - base);
        @memset(words, 0xdeadbeef);
        try std.testing.expectEqual(@as(u64, 24), try stage(words, tiled, &resolved, base, rows));
        try std.testing.expectEqual(base, words[tiled.layout.trace_offsets]);
        for (tiled.reads) |read| {
            const descriptor = words[tiled.layout.trace_offsets + 1 + read.global];
            const fast: ?usize = switch (read.mask) {
                0 => 0,
                -1 => 1,
                1 => 2,
                else => null,
            };
            if (fast) |slot| try std.testing.expectEqual(read.slab, words[descriptor + slot]);
            var found = false;
            const shift = words[descriptor + 3];
            for (0..words[descriptor + 4]) |i| {
                if (words[descriptor + 5 + 2 * i] == @as(u32, @bitCast(read.mask))) {
                    found = true;
                    try std.testing.expectEqual(read.slab, words[descriptor + 6 + 2 * i]);
                }
            }
            try std.testing.expect(found);
            for (0..rows) |local| {
                const global = base + local;
                const target = if (read.mask == 0) global else core.utils.offsetBitReversedCircleDomainIndex(global, 2, 4, read.mask);
                const native_index = (((global >> @intCast(shift)) - (base >> @intCast(shift))) << 1) + (global & 1);
                try std.testing.expectEqual(full[read.global][target], words[read.slab + native_index]);
            }
            const used = nativePairWords(base, rows, shift);
            if (used < tiled.tile_rows) try std.testing.expectEqual(@as(u32, 0xdeadbeef), words[read.slab + used]);
        }
    }
    resolved[1].shift_amt = 1;
    try std.testing.expectError(error.EvalArenaColumnShape, stage(words, tiled, &resolved, 0, 4));
    resolved[1] = .{ .values = &.{}, .shift_amt = 0 };
    _ = try stage(words, tiled, &resolved, 12, 4);
    for (tiled.reads) |read| if (read.global == 1) try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0, 0 }, words[read.slab..][0..4]);
    try std.testing.expectError(error.EvalArenaColumnShape, stage(words, tiled, &resolved, 15, 2));
}

test "tiled composition retains arbitrary AIR masks beside common direct slots" {
    var component = testComponent();
    var reads = test_reads;
    reads[3].imm = 7;
    var parts = test_parts;
    parts[0].program.base_insts = &reads;
    component.parts = &parts;
    var tiled = try plan(std.testing.allocator, component, 256);
    defer tiled.deinit(std.testing.allocator);
    const words = try std.testing.allocator.alloc(u32, @intCast(tiled.layout.words));
    defer std.testing.allocator.free(words);
    const source = [_]u32{ 3, 11, 19, 29, 43, 53, 61, 71 };
    const resolved = [_]eval_arena.ResolvedScratch{ .{ .values = source[0..4], .shift_amt = 3 }, .{ .values = &source, .shift_amt = 2 } };
    _ = try stage(words, tiled, &resolved, 12, tiled.tile_rows);
    var unusual: ?Read = null;
    for (tiled.reads) |read| if (read.mask == 7) {
        unusual = read;
    };
    const read = unusual orelse return error.TestExpectedUnusualMask;
    for (0..tiled.tile_rows) |row| {
        const target = core.utils.offsetBitReversedCircleDomainIndex(12 + row, 2, 4, 7);
        const native_index = (((12 + row) >> 2) - (12 >> 2)) * 2 + ((12 + row) & 1);
        try std.testing.expectEqual(source[eval_arena.liftedIndex(target, 2)], words[read.slab + native_index]);
    }
}

test "circle mask reads are constant over lifted native pairs" {
    for (3..11) |eval_log_usize| {
        const eval_log: u32 = @intCast(eval_log_usize);
        const rows: usize = @as(usize, 1) << @intCast(eval_log);
        for (0..eval_log) |trace_log_usize| {
            const trace_log: u32 = @intCast(trace_log_usize);
            for (1..eval_log + 1) |source_log_usize| {
                const source_log: u32 = @intCast(source_log_usize);
                const shift = eval_log - source_log + 1;
                for ([_]i32{ -7, -3, -1, 0, 1, 3, 7 }) |mask| {
                    for (0..rows) |row| {
                        const representative = ((row >> @intCast(shift)) << @intCast(shift)) | (row & 1);
                        const target = if (mask == 0) row else core.utils.offsetBitReversedCircleDomainIndex(row, trace_log, eval_log, mask);
                        const representative_target = if (mask == 0) representative else core.utils.offsetBitReversedCircleDomainIndex(representative, trace_log, eval_log, mask);
                        try std.testing.expectEqual(eval_arena.liftedIndex(target, @intCast(shift)), eval_arena.liftedIndex(representative_target, @intCast(shift)));
                    }
                }
            }
        }
    }
}
