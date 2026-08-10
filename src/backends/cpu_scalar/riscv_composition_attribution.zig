//! Exact semantic contribution plans for profiled fused RISC-V composition.
//!
//! This coordinator-only module adds no unprofiled allocation or worker-loop
//! work. It converts the already-admitted tile plan into immutable per-task
//! slices before launch; workers never synchronize on or mutate attribution.

const std = @import("std");
const prover = @import("stwo_prover_engine");
const admission = @import("riscv_composition_admission.zig");
const lanes = @import("riscv_composition_lanes.zig");

const BaseProgramEntry = admission.BaseProgramEntry;
const LookupProgramEntry = admission.LookupProgramEntry;
const PairJob = admission.PairJob;
const Tile = lanes.Tile;

const Range = struct {
    start: usize,
    len: usize,
};

const PairWork = struct {
    rows: u64 = 0,
    tiles: u64 = 0,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    contributions: []prover.task_graph.TaskContributionPlan,
    task_ranges: []Range,

    pub fn init(
        allocator: std.mem.Allocator,
        host_workers: anytype,
        pairs: []const PairJob,
        base_programs: []const BaseProgramEntry,
        lookup_programs: []const LookupProgramEntry,
        tiles: []const Tile,
        lane_count: usize,
    ) !Plan {
        if (lane_count == 0 or pairs.len == 0) {
            return error.InvalidCompositionAttributionPlan;
        }
        const cell_count = std.math.mul(usize, lane_count, pairs.len) catch
            return error.WorkEstimateOverflow;
        const pair_work = try allocator.alloc(PairWork, cell_count);
        defer allocator.free(pair_work);
        @memset(pair_work, .{});

        for (0..lane_count) |lane_index| {
            var tile_index = lane_index;
            while (tile_index < tiles.len) : (tile_index += lane_count) {
                const tile = tiles[tile_index];
                const rows = std.math.cast(u64, tile.row_end - tile.row_start) orelse
                    return error.WorkEstimateOverflow;
                for (tile.bucket.pair_indices) |pair_index| {
                    if (pair_index >= pairs.len) {
                        return error.InvalidCompositionAttributionPlan;
                    }
                    const cell = &pair_work[lane_index * pairs.len + pair_index];
                    cell.rows = std.math.add(u64, cell.rows, rows) catch
                        return error.WorkEstimateOverflow;
                    cell.tiles = std.math.add(u64, cell.tiles, 1) catch
                        return error.WorkEstimateOverflow;
                }
            }
        }

        var contribution_count = host_workers.len;
        for (pair_work) |work| {
            if (work.tiles == 0) continue;
            contribution_count = std.math.add(usize, contribution_count, 2) catch
                return error.WorkEstimateOverflow;
        }
        if (contribution_count > std.math.maxInt(u32)) {
            return error.TaskProfileContributionCountOverflow;
        }
        const contributions = try allocator.alloc(
            prover.task_graph.TaskContributionPlan,
            contribution_count,
        );
        errdefer allocator.free(contributions);
        const task_count = std.math.add(usize, host_workers.len, lane_count) catch
            return error.WorkEstimateOverflow;
        const task_ranges = try allocator.alloc(Range, task_count);
        errdefer allocator.free(task_ranges);

        var cursor: usize = 0;
        for (host_workers, 0..) |worker, task_index| {
            const rows = try componentRows(worker.component);
            task_ranges[task_index] = .{ .start = cursor, .len = 1 };
            contributions[cursor] = .{
                .component_registry_index = worker.component_registry_index,
                .component_kind = "riscv_fallback_component",
                .role = .exclusive,
                .work_estimate = try componentWorkEstimate(worker.component, rows),
                .planned_rows = rows,
            };
            cursor += 1;
        }
        for (0..lane_count) |lane_index| {
            const range_start = cursor;
            for (pairs, 0..) |pair, pair_index| {
                const work = pair_work[lane_index * pairs.len + pair_index];
                if (work.tiles == 0) continue;
                const base = base_programs[pair.base_program_index].program;
                const lookup = lookup_programs[pair.lookup_program_index].program;
                contributions[cursor] = .{
                    .component_registry_index = pair.semantic_registry_index,
                    .component_kind = "riscv_semantic_component",
                    .role = .semantic_constraints,
                    .work_estimate = try checkedWork(work.rows, base.roots.len),
                    .planned_rows = work.rows,
                    .planned_tiles = work.tiles,
                };
                cursor += 1;
                contributions[cursor] = .{
                    .component_registry_index = pair.lookup_registry_index,
                    .component_kind = "riscv_lookup_component",
                    .role = .lookup_constraints,
                    .work_estimate = try checkedWork(work.rows, lookup.batchCount()),
                    .planned_rows = work.rows,
                    .planned_tiles = work.tiles,
                };
                cursor += 1;
            }
            task_ranges[host_workers.len + lane_index] = .{
                .start = range_start,
                .len = cursor - range_start,
            };
        }
        std.debug.assert(cursor == contributions.len);
        return .{
            .allocator = allocator,
            .contributions = contributions,
            .task_ranges = task_ranges,
        };
    }

    pub fn deinit(self: *Plan) void {
        const allocator = self.allocator;
        allocator.free(self.task_ranges);
        allocator.free(self.contributions);
        self.* = undefined;
    }

    pub fn forTask(
        self: *const Plan,
        task_index: usize,
    ) []const prover.task_graph.TaskContributionPlan {
        const range = self.task_ranges[task_index];
        return self.contributions[range.start..][0..range.len];
    }
};

fn componentRows(component: anytype) !u64 {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn componentWorkEstimate(component: anytype, rows: u64) !u64 {
    return checkedWork(rows, component.nConstraints());
}

fn checkedWork(rows: u64, constraint_count: usize) !u64 {
    return prover.task_graph.checkedWorkEstimate(&.{
        rows,
        std.math.cast(u64, constraint_count) orelse
            return error.WorkEstimateOverflow,
    });
}
