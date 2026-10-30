//! Producer-only row fusion: construct ordered typed entries once per row,
//! then emit every physical projection. Claims, columns and prefix order are
//! unchanged. No cross-proof cache, changed AIR, or claimed verification token.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Pool = engine.work_pool;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Opcode = @import("../runner/trace.zig");
const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const Row = @import("../recursion/air/framework_interaction.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const Generated = struct { columns: [4][]M, sum: Q };
pub const Owned = struct {
    a: std.mem.Allocator,
    values: []Generated,
    pub fn deinit(self: *Owned) void {
        for (self.values) |value| for (value.columns) |column| self.a.free(column);
        self.a.free(self.values);
        self.* = undefined;
    }
};
const TILE: usize = 256;
const Group = struct { indices: []usize };
fn sourceId(slot: Source.Slot) usize {
    return switch (slot.kind) {
        .program => |family| @intFromEnum(family),
        .lookup => |lookup| switch (lookup.source) {
            .opcode => |family| @intFromEnum(family),
            .clock => Opcode.N_FAMILIES,
        },
    };
}
pub fn sameSource(left: Source.Slot, right: Source.Slot) bool {
    return left.main_offset == right.main_offset and left.width == right.width and left.log_size == right.log_size and sourceId(left) == sourceId(right);
}
pub fn generate(a: std.mem.Allocator, main: []const Column, slots: []const Source.Slot, relations: *const Universal) !Owned {
    if (slots.len > 4096) return error.ProjectionBatchResourceLimit;
    var out = Owned{ .a = a, .values = try a.alloc(Generated, slots.len) };
    var ready: usize = 0;
    errdefer {
        for (out.values[0..ready]) |value| for (value.columns) |column| a.free(column);
        a.free(out.values);
    }
    for (slots, out.values) |slot, *value| {
        if (slot.log_size < 1 or slot.log_size > 24 or slot.width == 0 or slot.width > Opcode.MAX_FAMILY_COLUMNS or slot.main_offset > main.len or slot.width > main.len - slot.main_offset) return error.InvalidProjectionBatchGeometry;
        if (slot.register_custody_mode > 1) return error.InvalidProjectionBatchGeometry;
        if (slot.kind == .lookup) {
            const lookup = slot.kind.lookup;
            if (lookup.width != slot.width or lookup.main_offset != slot.main_offset or lookup.log_size != slot.log_size or lookup.n_rows != slot.n_rows or lookup.register_custody_mode != slot.register_custody_mode) return error.InvalidProjectionBatchGeometry;
        }
        const size = @as(usize, 1) << @intCast(slot.log_size);
        if (slot.n_rows > size) return error.InvalidProjectionBatchGeometry;
        for (main[slot.main_offset..][0..slot.width]) |column| if (column.log_size != slot.log_size or column.values.len != size) return error.InvalidProjectionBatchGeometry;
        var allocated: usize = 0;
        errdefer for (value.columns[0..allocated]) |column| a.free(column);
        for (&value.columns) |*column| {
            column.* = try a.alloc(M, size);
            allocated += 1;
        }
        value.sum = Q.zero();
        ready += 1;
    }
    if (slots.len == 0) return out;
    const seen = try a.alloc(bool, slots.len);
    defer a.free(seen);
    @memset(seen, false);
    var groups: std.ArrayList(Group) = .empty;
    defer {
        for (groups.items) |group| a.free(group.indices);
        groups.deinit(a);
    }
    var maximum: usize = 0;
    for (slots, 0..) |slot, index| {
        if (seen[index]) continue;
        var ids: std.ArrayList(usize) = .empty;
        defer ids.deinit(a);
        for (slots[index..], index..) |other, other_index| if (!seen[other_index] and sameSource(slot, other)) {
            try ids.append(a, other_index);
            seen[other_index] = true;
        };
        maximum = @max(maximum, ids.items.len);
        const owned = try ids.toOwnedSlice(a);
        groups.append(a, .{ .indices = owned }) catch |err| {
            a.free(owned);
            return err;
        };
    }
    var lease: ?Pool.WorkLease = null;
    if (groups.items.len > 1) if (Pool.currentScopedPool()) |pool| {
        const workers = @min(pool.workerCount(), groups.items.len);
        if (workers > 1) lease = pool.acquire(try Pool.WorkerBudget.init(workers)) catch |err| switch (err) {
            error.WorkerBudgetUnavailable => null,
            else => return err,
        };
    };
    defer if (lease) |*held| held.deinit();
    const workers = if (lease) |*held| held.workerCount() else 1;
    const scratch = try a.alloc(Q, 2 * workers * maximum * TILE);
    defer a.free(scratch);
    var jobs: [Pool.MAX_WORKERS]Job = undefined;
    var wait = std.Thread.WaitGroup{};
    {
        defer {
            wait.wait();
            if (lease) |*held| held.completeWave();
        }
        for (jobs[0..workers], 0..) |*job, index| {
            job.* = .{ .groups = groups.items, .worker = index, .workers = workers, .main = main, .slots = slots, .values = out.values, .relations = relations, .scratch = scratch[2 * index * maximum * TILE ..][0 .. 2 * maximum * TILE] };
            if (index + 1 < workers) try lease.?.spawnWg(&wait, Job.run, .{job}) else job.run();
        }
    }
    for (jobs[0..workers]) |job| if (job.failure) |err| return err;
    return out;
}
fn store(value: *Generated, row: usize, q: Q) void {
    for (value.columns, q.toM31Array()) |column, limb| column[row] = limb;
}
fn load(value: *const Generated, row: usize) Q {
    return Q.fromM31Array(.{ value.columns[0][row], value.columns[1][row], value.columns[2][row], value.columns[3][row] });
}
const Job = struct {
    groups: []const Group,
    worker: usize,
    workers: usize,
    main: []const Column,
    slots: []const Source.Slot,
    values: []Generated,
    relations: *const Universal,
    scratch: []Q,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.fill() catch |err| {
            self.failure = err;
        };
    }
    fn fill(self: *Job) !void {
        var group_index = self.worker;
        while (group_index < self.groups.len) : (group_index += self.workers) {
            const ids = self.groups[group_index].indices;
            const first = self.slots[ids[0]];
            const size = @as(usize, 1) << @intCast(first.log_size);
            var begin: usize = 0;
            while (begin < size) {
                const end = @min(size, begin + TILE);
                const count = (end - begin) * ids.len;
                const denominators = self.scratch[0..count];
                const inverses = self.scratch[self.scratch.len / 2 ..][0..count];
                for (begin..end) |logical| {
                    const physical = Row.committedRow(logical, first.log_size);
                    var row: [Opcode.MAX_FAMILY_COLUMNS]M = undefined;
                    for (row[0..first.width], self.main[first.main_offset..][0..first.width]) |*value, column| value.* = column.values[physical];
                    const entries = try Source.baseEntries(first, row[0..first.width]);
                    for (ids, 0..) |id, offset| {
                        const request = try Source.fromBaseEntries(self.slots[id], &entries, self.relations);
                        denominators[(logical - begin) * ids.len + offset] = request.denominator();
                        store(&self.values[id], physical, request.numerator());
                    }
                }
                try core.fields.batchInverseInPlace(Q, denominators, inverses);
                for (begin..end) |logical| {
                    const physical = Row.committedRow(logical, first.log_size);
                    for (ids, 0..) |id, offset| {
                        const value = &self.values[id];
                        const term = load(value, physical).mul(inverses[(logical - begin) * ids.len + offset]);
                        value.sum = value.sum.add(term);
                        store(value, physical, term);
                    }
                }
                begin = end;
            }
            for (ids) |id| {
                const value = &self.values[id];
                const mean = try value.sum.divM31(M.fromCanonical(@intCast(size)));
                var prefix = Q.zero();
                for (0..size) |logical| {
                    const physical = Row.committedRow(logical, first.log_size);
                    prefix = prefix.add(load(value, physical)).sub(mean);
                    store(value, physical, prefix);
                }
                if (!prefix.isZero()) return error.InvalidProjectionBatchPrefix;
            }
        }
    }
};
