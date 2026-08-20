const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_mod = @import("../air/public_data.zig");
const leaf_owner = @import("segment_leaf_authority.zig");
const claim = @import("vm_public_claim.zig");
const source = @import("segment_statement_outer_source.zig");
const framework = @import("air/framework_interaction.zig");
const manifest_mod = @import("air/universal_adapter_manifest.zig");
const roster = @import("air/universal_roster.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal = @import("air/universal_challenges.zig");
const row10_relation = @import("air/statement_input_relation.zig");
const row10_witness = @import("air/statement_input_witness.zig");
const row11_relation = @import("air/statement_semantics_input_relation.zig");
const row11_witness = @import("air/statement_semantics_input_witness.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");

// Shared fixtures and mutation helpers for this conformance suite.

pub fn authorityFailureCase(
    allocator: std.mem.Allocator,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
) !void {
    var authority = try source.Authority.init(allocator, leaf_preprocessing);
    defer authority.deinit();
}

pub fn workspaceFailureCase(allocator: std.mem.Allocator) !void {
    var workspace = try source.Workspace.init(allocator);
    defer workspace.deinit();
}

pub fn preparedFailureCase(
    allocator: std.mem.Allocator,
    authority: *const source.Authority,
    workspace: *source.Workspace,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    data: *const public_data_mod.PublicData,
    leaf: *const leaf_owner.Prepared,
) !void {
    var prepared = try source.Prepared.init(
        allocator,
        authority,
        workspace,
        leaf_preprocessing,
        data,
        leaf,
    );
    defer prepared.deinit();
}

pub fn OwnedColumns(comptime count: usize) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        storage: []M31,
        columns: [count][]M31,

        fn init(allocator: std.mem.Allocator, size: usize) !Self {
            const storage = try allocator.alloc(M31, count * size);
            errdefer allocator.free(storage);
            @memset(storage, M31.zero());
            var columns: [count][]M31 = undefined;
            for (&columns, 0..) |*column, index|
                column.* = storage[index * size ..][0..size];
            return .{
                .allocator = allocator,
                .storage = storage,
                .columns = columns,
            };
        }

        fn deinit(self: *Self) void {
            self.allocator.free(self.storage);
            self.* = undefined;
        }

        fn fill(self: *Self, value: M31) void {
            @memset(self.storage, value);
        }

        fn expectFilled(self: *const Self, value: M31) !void {
            for (self.storage) |actual|
                try std.testing.expect(actual.eql(value));
        }
    };
}

pub fn expectCommittedColumns(
    comptime count: usize,
    log_size: u32,
    logical: *const [count][]M31,
    committed: *const [count][]M31,
) !void {
    for (logical, committed) |expected_column, actual_column| {
        try std.testing.expectEqual(expected_column.len, actual_column.len);
        for (expected_column, 0..) |expected, logical_row| {
            try std.testing.expectEqual(
                expected,
                actual_column[source.committedRow(logical_row, log_size)],
            );
        }
    }
}

pub fn expectColumnsEqual(
    comptime count: usize,
    expected: *const [count][]M31,
    actual: *const [count][]M31,
) !void {
    for (expected, actual) |expected_column, actual_column|
        try std.testing.expectEqualSlices(M31, expected_column, actual_column);
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    data: public_data_mod.PublicData,
    leaf_preprocessing: leaf_owner.Preprocessing,
    leaf: leaf_owner.Prepared,
    authority: source.Authority,
    workspace: source.Workspace,
    prepared: source.Prepared,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        const data = testPublicData();
        var leaf_preprocessing = try leaf_owner.Preprocessing.init(
            allocator,
            try claim.Shape.init(3, 3),
        );
        errdefer leaf_preprocessing.deinit();
        var leaf = try leaf_owner.Prepared.init(
            allocator,
            &leaf_preprocessing,
            &data,
        );
        errdefer leaf.deinit();
        var authority = try source.Authority.init(allocator, &leaf_preprocessing);
        errdefer authority.deinit();
        var workspace = try source.Workspace.init(allocator);
        errdefer workspace.deinit();
        var prepared = try source.Prepared.init(
            allocator,
            &authority,
            &workspace,
            &leaf_preprocessing,
            &data,
            &leaf,
        );
        errdefer prepared.deinit();
        return .{
            .allocator = allocator,
            .data = data,
            .leaf_preprocessing = leaf_preprocessing,
            .leaf = leaf,
            .authority = authority,
            .workspace = workspace,
            .prepared = prepared,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.workspace.deinit();
        self.authority.deinit();
        self.leaf.deinit();
        self.leaf_preprocessing.deinit();
        self.* = undefined;
    }

    pub fn manifest(self: *const Fixture) !manifest_mod.Manifest {
        var builder = manifest_mod.Builder{};
        _ = try builder.append(self.authority.statementInputGeometry());
        _ = try builder.append(self.authority.statementSemanticsGeometry());
        _ = try builder.append(self.authority.rangeGeometry());
        return builder.seal();
    }
};

pub const TreeKind = enum { preprocessed, main, interaction };

pub const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        kind: TreeKind,
    ) !Tree {
        const count: usize = switch (kind) {
            .preprocessed => manifest.total_preprocessed_columns,
            .main => manifest.total_main_columns,
            .interaction => manifest.total_interaction_columns,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var total: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row_value| {
            const placement = manifest.placements[row_value].?;
            const column_count: usize = switch (kind) {
                .preprocessed => placement.geometry.preprocessed_columns,
                .main => placement.geometry.main_columns,
                .interaction => placement.geometry.interaction_columns,
            };
            total = try std.math.add(
                usize,
                total,
                try std.math.mul(
                    usize,
                    column_count,
                    @as(usize, 1) << @intCast(placement.geometry.log_size),
                ),
            );
        }
        const storage = try allocator.alloc(M31, total);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var column_cursor: usize = 0;
        var storage_cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row_value| {
            const placement = manifest.placements[row_value].?;
            const column_count: usize = switch (kind) {
                .preprocessed => placement.geometry.preprocessed_columns,
                .main => placement.geometry.main_columns,
                .interaction => placement.geometry.interaction_columns,
            };
            const row_count = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            for (0..column_count) |_| {
                columns[column_cursor] = storage[storage_cursor..][0..row_count];
                column_cursor += 1;
                storage_cursor += row_count;
            }
        }
        std.debug.assert(
            column_cursor == columns.len and storage_cursor == storage.len,
        );
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
pub const test_output_words = [_]public_data_mod.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

pub fn testPublicData() public_data_mod.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data_mod.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}
