//! Ethereum wrapper telemetry. Estimates are PCS lower bounds, not admission
//! guarantees: Merkle nodes, witness owners and composition scratch are excluded.
const std = @import("std");
const prover = @import("stwo_prover_engine");
const residency = prover.pcs.residency_estimate;
const usage = prover.measurement.process_usage;

pub const RetainedColumns = prover.mmap_alloc.FileBackedAllocator;

/// Execution-only opt-in. Scratch storage never selects an AIR or circuit key.
/// Callers must destroy all PCS trees and quotient value buffers before
/// destroying this owner.
pub fn openRetainedColumns(allocator: std.mem.Allocator) !?RetainedColumns {
    const path = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PCS_SCRATCH_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer allocator.free(path);
    if (path.len == 0) return error.EmptyEthereumPcsScratchDirectory;
    return try RetainedColumns.init(path);
}

pub fn closeRetainedColumns(owner: *RetainedColumns) void {
    progress("ETHEREUM_WRAPPER_PCS_STORAGE backing=file total_mapped_bytes={d} remaining_mapped_bytes={d}\n", .{
        owner.total_bytes.load(.monotonic), owner.live_bytes.load(.monotonic),
    });
    owner.deinit();
}

/// Zig's test server buffers stderr until a test ends. An optional append log
/// makes long proof phases visible while retaining the ordinary test output.
/// Logging cannot change proof acceptance or allocator ownership.
pub fn progress(comptime format: []const u8, args: anytype) void {
    std.debug.print(format, args);
    const allocator = std.heap.page_allocator;
    const path = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_PROGRESS") catch return;
    defer allocator.free(path);
    var buffer: [4096]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, format, args) catch return;
    const file = std.fs.cwd().createFile(path, .{ .truncate = false }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch return;
    file.writeAll(line) catch return;
}

pub const TreeEstimate = struct {
    columns: u64 = 0,
    source_bytes: u64 = 0,
    minimum_resident_bytes: u64 = 0,

    pub fn add(self: *TreeEstimate, columns: u64, log_size: u32, blowup: u32, retention: residency.RetentionPolicy) !void {
        const item = try residency.estimateUniform(columns, log_size, blowup, retention);
        const next: TreeEstimate = .{
            .columns = try std.math.add(u64, self.columns, columns),
            .source_bytes = try std.math.add(u64, self.source_bytes, item.source_bytes),
            .minimum_resident_bytes = try std.math.add(u64, self.minimum_resident_bytes, item.minimum_resident_bytes),
        };
        self.* = next;
    }
};

/// Walk admitted geometry without allocating or reading witness columns.
pub fn reportPlan(comptime Contract: type, manifest: *const Contract.Manifest, blowup: u32, retention: residency.RetentionPolicy) !void {
    var trees = [_]TreeEstimate{.{}} ** 3;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const counts = [_]usize{
            geometry.preprocessed_columns,
            geometry.main_columns,
            geometry.interaction_columns,
        };
        var component: TreeEstimate = .{};
        for (&trees, counts) |*tree, count| {
            try tree.add(@intCast(count), geometry.log_size, blowup, retention);
            try component.add(@intCast(count), geometry.log_size, blowup, retention);
        }
        progress(
            "ETHEREUM_WRAPPER_COMPONENT_PLAN row={d} log_size={d} preprocessed_columns={d} main_columns={d} interaction_columns={d} source_bytes={d} pcs_minimum_resident_bytes={d}\n",
            .{ row, geometry.log_size, counts[0], counts[1], counts[2], component.source_bytes, component.minimum_resident_bytes },
        );
    }
    var total: u64 = 0;
    for (trees, 0..) |tree, index| {
        total = try std.math.add(u64, total, tree.minimum_resident_bytes);
        progress(
            "ETHEREUM_WRAPPER_MEMORY_PLAN tree={d} columns={d} source_bytes={d} pcs_minimum_resident_bytes={d} blowup_log={d} coefficient_retention={s}\n",
            .{ index, tree.columns, tree.source_bytes, tree.minimum_resident_bytes, blowup, @tagName(retention) },
        );
    }
    progress("ETHEREUM_WRAPPER_MEMORY_PLAN total_pcs_minimum_resident_bytes={d} excludes_merkle_witness_composition=true\n", .{total});
}

pub const Measurements = struct {
    timer: ?std.time.Timer,

    pub fn init() Measurements {
        return .{ .timer = std.time.Timer.start() catch null };
    }

    pub fn mark(self: *Measurements, comptime phase: []const u8) void {
        const elapsed: ?u64 = if (self.timer) |*timer| timer.lap() else null;
        const sample = usage.sample() catch null;
        progress(
            "ETHEREUM_WRAPPER_RESOURCES phase={s} wall_ns={?d} lifetime_peak_footprint_bytes={?d} current_footprint_bytes={?d} source={s}\n",
            .{
                phase,
                elapsed,
                if (sample) |value| value.lifetime_peak_physical_footprint_bytes else null,
                if (sample) |value| value.current_physical_footprint_bytes else null,
                if (sample) |value| @tagName(value.source) else "unavailable",
            },
        );
    }
};

test "Ethereum wrapper memory estimate handles mixed logs and overflow without allocation" {
    var estimate: TreeEstimate = .{};
    try estimate.add(2, 3, 1, .never);
    try estimate.add(3, 4, 1, .never);
    try std.testing.expectEqual(@as(u64, 5), estimate.columns);
    try std.testing.expectEqual(@as(u64, 256), estimate.source_bytes);
    try std.testing.expectEqual(@as(u64, 512), estimate.minimum_resident_bytes);
    var retained: TreeEstimate = .{};
    try retained.add(2, 3, 1, .always);
    try std.testing.expectEqual(@as(u64, 192), retained.minimum_resident_bytes);
    const saved = estimate;
    try std.testing.expectError(error.InvalidColumnLogSize, estimate.add(1, 64, 1, .never));
    try std.testing.expectEqualDeep(saved, estimate);
    try std.testing.expectError(error.ResidencyEstimateOverflow, estimate.add(std.math.maxInt(u64), 2, 1, .never));
    try std.testing.expectEqualDeep(saved, estimate);
}
