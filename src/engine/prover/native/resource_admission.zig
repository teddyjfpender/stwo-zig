//! Checked workload geometry and bounded Native proving resource profiles.

const std = @import("std");

pub const MAX_LOG_ROWS: u32 = 22;
// Admission reserves one base-field trace (4 bytes), its current 2x LDE
// representation (8 bytes), and one trace-width scratch allowance (4 bytes).
// This is a deterministic preflight reservation, not a replacement for peak
// RSS measurement; changes to the storage plan must review this factor.
pub const ACCOUNTED_BYTES_PER_COMMITTED_CELL: u64 = 16;

// These decimal constants are the Zig-owned source authority consumed by the
// Native matrix source-contract parser. Keep their declarations literal.
pub const STANDARD_MAX_COMMITTED_CELLS: u64 = 33_554_432;
pub const STANDARD_MAX_ACCOUNTED_BYTES: u64 = 536_870_912;
pub const LARGE_MAX_COMMITTED_CELLS: u64 = 134_217_728;
pub const LARGE_MAX_ACCOUNTED_BYTES: u64 = 2_147_483_648;
pub const EXTREME_MAX_COMMITTED_CELLS: u64 = 419_430_400;
pub const EXTREME_MAX_ACCOUNTED_BYTES: u64 = 6_710_886_400;

pub const Profile = enum {
    standard,
    large,
    extreme,

    pub fn limits(self: Profile) Limits {
        return switch (self) {
            .standard => .{
                .max_committed_cells = STANDARD_MAX_COMMITTED_CELLS,
                .max_accounted_bytes = STANDARD_MAX_ACCOUNTED_BYTES,
            },
            .large => .{
                .max_committed_cells = LARGE_MAX_COMMITTED_CELLS,
                .max_accounted_bytes = LARGE_MAX_ACCOUNTED_BYTES,
            },
            .extreme => .{
                .max_committed_cells = EXTREME_MAX_COMMITTED_CELLS,
                .max_accounted_bytes = EXTREME_MAX_ACCOUNTED_BYTES,
            },
        };
    }
};

pub const Limits = struct {
    max_committed_cells: u64,
    max_accounted_bytes: u64,
};

pub const Geometry = struct {
    log_rows: u32,
    rows: u64,
    committed_columns: u64,
    committed_cells: u64,
    accounted_bytes: u64,
};

pub const Admission = struct {
    profile: Profile,
    geometry: Geometry,
    limits: Limits,
    accounted_bytes_per_committed_cell: u64 = ACCOUNTED_BYTES_PER_COMMITTED_CELL,
};

pub const Error = error{
    InvalidLogRows,
    InvalidCommittedColumnCount,
    InvalidCommittedCellCount,
    CommittedCellCountOverflow,
    CommittedCellCountExceedsLogicalGeometry,
    AccountedByteCountOverflow,
    CommittedCellBudgetExceeded,
    AccountedMemoryBudgetExceeded,
};

pub fn admit(profile: Profile, log_rows: u32, committed_columns: u64) Error!Admission {
    return admitWithLimits(profile, log_rows, committed_columns, profile.limits());
}

pub fn admitWithLimits(
    profile: Profile,
    log_rows: u32,
    committed_columns: u64,
    limits: Limits,
) Error!Admission {
    const geometry = try measure(log_rows, committed_columns);
    if (geometry.committed_cells > limits.max_committed_cells)
        return error.CommittedCellBudgetExceeded;
    if (geometry.accounted_bytes > limits.max_accounted_bytes)
        return error.AccountedMemoryBudgetExceeded;
    return .{ .profile = profile, .geometry = geometry, .limits = limits };
}

pub fn admitExact(
    profile: Profile,
    log_rows: u32,
    committed_columns: u64,
    committed_cells: u64,
) Error!Admission {
    return admitExactWithLimits(
        profile,
        log_rows,
        committed_columns,
        committed_cells,
        profile.limits(),
    );
}

pub fn admitExactWithLimits(
    profile: Profile,
    log_rows: u32,
    committed_columns: u64,
    committed_cells: u64,
    limits: Limits,
) Error!Admission {
    const geometry = try measureExact(
        log_rows,
        committed_columns,
        committed_cells,
    );
    if (geometry.committed_cells > limits.max_committed_cells)
        return error.CommittedCellBudgetExceeded;
    if (geometry.accounted_bytes > limits.max_accounted_bytes)
        return error.AccountedMemoryBudgetExceeded;
    return .{ .profile = profile, .geometry = geometry, .limits = limits };
}

/// Admits a trace whose committed columns may use component domains taller
/// than the statement's logical row domain.
pub fn admitMixedHeight(
    profile: Profile,
    log_rows: u32,
    committed_columns: u64,
    committed_cells: u64,
) Error!Admission {
    const geometry = try measureMixedHeight(
        log_rows,
        committed_columns,
        committed_cells,
    );
    const limits = profile.limits();
    if (geometry.committed_cells > limits.max_committed_cells)
        return error.CommittedCellBudgetExceeded;
    if (geometry.accounted_bytes > limits.max_accounted_bytes)
        return error.AccountedMemoryBudgetExceeded;
    return .{ .profile = profile, .geometry = geometry, .limits = limits };
}

pub fn measure(log_rows: u32, committed_columns: u64) Error!Geometry {
    if (log_rows == 0 or log_rows > MAX_LOG_ROWS) return error.InvalidLogRows;
    if (committed_columns == 0) return error.InvalidCommittedColumnCount;
    const rows = @as(u64, 1) << @intCast(log_rows);
    const committed_cells = std.math.mul(u64, rows, committed_columns) catch
        return error.CommittedCellCountOverflow;
    return measureExact(log_rows, committed_columns, committed_cells);
}

pub fn measureExact(
    log_rows: u32,
    committed_columns: u64,
    committed_cells: u64,
) Error!Geometry {
    const geometry = try measureMixedHeight(
        log_rows,
        committed_columns,
        committed_cells,
    );
    const maximum_cells = std.math.mul(
        u64,
        geometry.rows,
        committed_columns,
    ) catch return error.CommittedCellCountOverflow;
    if (committed_cells > maximum_cells)
        return error.CommittedCellCountExceedsLogicalGeometry;
    return geometry;
}

pub fn measureMixedHeight(
    log_rows: u32,
    committed_columns: u64,
    committed_cells: u64,
) Error!Geometry {
    if (log_rows == 0 or log_rows > MAX_LOG_ROWS) return error.InvalidLogRows;
    if (committed_columns == 0) return error.InvalidCommittedColumnCount;
    if (committed_cells == 0) return error.InvalidCommittedCellCount;
    const rows = @as(u64, 1) << @intCast(log_rows);
    const accounted_bytes = std.math.mul(
        u64,
        committed_cells,
        ACCOUNTED_BYTES_PER_COMMITTED_CELL,
    ) catch return error.AccountedByteCountOverflow;
    return .{
        .log_rows = log_rows,
        .rows = rows,
        .committed_columns = committed_columns,
        .committed_cells = committed_cells,
        .accounted_bytes = accounted_bytes,
    };
}

test "resource admission: mixed-height geometry retains logical width" {
    const rows: u64 = 1 << 10;
    const admission = try admitExact(.standard, 10, 12, 9 * rows);
    try std.testing.expectEqual(@as(u64, 12), admission.geometry.committed_columns);
    try std.testing.expectEqual(9 * rows, admission.geometry.committed_cells);
    try std.testing.expectError(
        error.CommittedCellCountExceedsLogicalGeometry,
        admitExact(.standard, 10, 12, 13 * rows),
    );
}

test "resource admission: taller mixed-height components remain bounded" {
    const cells: u64 = 1 << 20;
    const admission = try admitMixedHeight(.standard, 5, 8, cells);
    try std.testing.expectEqual(@as(u64, 32), admission.geometry.rows);
    try std.testing.expectEqual(cells, admission.geometry.committed_cells);
    try std.testing.expectError(
        error.CommittedCellBudgetExceeded,
        admitMixedHeight(.standard, 5, 8, STANDARD_MAX_COMMITTED_CELLS + 1),
    );
}

test "resource admission: standard cell boundary is inclusive and fail closed" {
    const columns_at = STANDARD_MAX_COMMITTED_CELLS / 1024;
    const below = try admit(.standard, 10, columns_at - 1);
    try std.testing.expectEqual(STANDARD_MAX_COMMITTED_CELLS - 1024, below.geometry.committed_cells);
    const at = try admit(.standard, 10, columns_at);
    try std.testing.expectEqual(STANDARD_MAX_COMMITTED_CELLS, at.geometry.committed_cells);
    try std.testing.expectError(
        error.CommittedCellBudgetExceeded,
        admit(.standard, 10, columns_at + 1),
    );
}

test "resource admission: large cell boundary is inclusive and fail closed" {
    const columns_at = LARGE_MAX_COMMITTED_CELLS / 1024;
    const below = try admit(.large, 10, columns_at - 1);
    try std.testing.expectEqual(LARGE_MAX_COMMITTED_CELLS - 1024, below.geometry.committed_cells);
    const at = try admit(.large, 10, columns_at);
    try std.testing.expectEqual(LARGE_MAX_COMMITTED_CELLS, at.geometry.committed_cells);
    try std.testing.expectError(
        error.CommittedCellBudgetExceeded,
        admit(.large, 10, columns_at + 1),
    );
}

test "resource admission: extreme cell boundary is inclusive and fail closed" {
    const columns_at = EXTREME_MAX_COMMITTED_CELLS / 1024;
    const below = try admit(.extreme, 10, columns_at - 1);
    try std.testing.expectEqual(EXTREME_MAX_COMMITTED_CELLS - 1024, below.geometry.committed_cells);
    const at = try admit(.extreme, 10, columns_at);
    try std.testing.expectEqual(EXTREME_MAX_COMMITTED_CELLS, at.geometry.committed_cells);
    try std.testing.expectError(
        error.CommittedCellBudgetExceeded,
        admit(.extreme, 10, columns_at + 1),
    );
}

test "resource admission: reviewed large profile admits log20x100 only" {
    const admitted = try admit(.large, 20, 100);
    try std.testing.expectEqual(@as(u64, 104_857_600), admitted.geometry.committed_cells);
    try std.testing.expectEqual(@as(u64, 1_677_721_600), admitted.geometry.accounted_bytes);
    try std.testing.expectError(error.CommittedCellBudgetExceeded, admit(.large, 22, 100));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, admit(.large, 22, 512));
}

test "resource admission: extreme admits log22x100 without weakening large" {
    const admitted = try admit(.extreme, 22, 100);
    try std.testing.expectEqual(@as(u64, 419_430_400), admitted.geometry.committed_cells);
    try std.testing.expectEqual(@as(u64, 6_710_886_400), admitted.geometry.accounted_bytes);
    try std.testing.expectError(error.CommittedCellBudgetExceeded, admit(.large, 22, 100));
    try std.testing.expectError(error.CommittedCellBudgetExceeded, admit(.extreme, 22, 101));
}

test "resource admission: checked geometry distinguishes arithmetic and memory failures" {
    try std.testing.expectError(error.InvalidLogRows, measure(0, 1));
    try std.testing.expectError(error.InvalidLogRows, measure(MAX_LOG_ROWS + 1, 1));
    try std.testing.expectError(error.InvalidCommittedColumnCount, measure(1, 0));
    try std.testing.expectError(error.CommittedCellCountOverflow, measure(1, std.math.maxInt(u64)));
    try std.testing.expectError(
        error.AccountedByteCountOverflow,
        measure(1, std.math.maxInt(u64) / 2),
    );
    try std.testing.expectError(
        error.AccountedMemoryBudgetExceeded,
        admitWithLimits(.standard, 1, 8, .{
            .max_committed_cells = 16,
            .max_accounted_bytes = 255,
        }),
    );
}

test "resource admission: production policies bind cell and byte accounting" {
    inline for (.{ Profile.standard, Profile.large, Profile.extreme }) |profile| {
        const limits = profile.limits();
        try std.testing.expectEqual(
            limits.max_committed_cells * ACCOUNTED_BYTES_PER_COMMITTED_CELL,
            limits.max_accounted_bytes,
        );
    }
}
