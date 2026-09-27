//! Append-only Tree 0/1/2 owner for the incremental-memory bridge.
//!
//! The native statement and its ordinary components remain the committed
//! prefix. This module derives one exact appended component, owns its trace
//! columns, and supplies stable prover/verifier handles. It does not select a
//! statement family or activate production; the V3 profile owner must bind
//! this geometry into the transcript before Tree 0.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const core_components = @import("stwo_core").air.components;
const prover_component = @import("stwo_prover_engine").air.component_prover;

const statement_mod = @import("../air/statement.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const bridge = @import("../air/memory_commitment/incremental_bridge_v2.zig");
const bridge_component =
    @import("../air/memory_commitment/incremental_bridge_component_v2.zig");
const opcode_trace = @import("opcode_trace.zig");
const proof_workspace = @import("proof_workspace.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = 1;
pub const PREPROCESSED_COLUMNS: usize = 2;
pub const MAIN_COLUMNS: usize = bridge.N_MAIN_COLUMNS;
pub const INTERACTION_COLUMNS: usize = bridge.N_INTERACTION_COLUMNS;
pub const Digest = [32]u8;

const DOMAIN_WORDS = [4]u32{
    0x5749_5453, // STIW
    0x3347_4442, // BDG3
    FORMAT_VERSION,
    COMPONENT_COUNT,
};
const IDENTITY_DOMAIN =
    "stwo.riscv.incremental-bridge-external.v3\x00";

/// Exact committed prefix immediately before the bridge in Trees 0/1/2.
/// Full Ethereum leaves derive this from the authenticated base plus all
/// fourteen extension descriptors; core-only callers use the legacy wrappers.
pub const PrefixColumnsV3 = struct {
    preprocessed: u32,
    main: u32,
    interaction: u32,

    pub fn validate(self: PrefixColumnsV3) !void {
        if (self.preprocessed == 0 or self.main == 0 or self.interaction == 0)
            return error.InvalidIncrementalBridgePrefix;
    }
};

pub const GeometryV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    n_rows: u32,
    log_size: u32,
    placement: bridge_component.Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    identity_sha256: Digest,

    pub fn canonical(
        core: *const statement_mod.RiscVStatement,
        n_rows: u32,
        base_interaction_columns: u32,
    ) !GeometryV3 {
        return canonicalAfterPrefix(n_rows, .{
            .preprocessed = core.nPreprocessedColumns(),
            .main = core.nMainColumns(),
            .interaction = base_interaction_columns,
        });
    }

    pub fn canonicalAfterPrefix(
        n_rows: u32,
        prefix: PrefixColumnsV3,
    ) !GeometryV3 {
        if (n_rows == 0) return error.EmptyIncrementalBridge;
        try prefix.validate();
        const log_size = logSize(n_rows);
        var result = GeometryV3{
            .n_rows = n_rows,
            .log_size = log_size,
            .placement = .{
                .is_first_col_idx = prefix.preprocessed,
                .is_active_col_idx = try add(prefix.preprocessed, 1),
                .main_col_offset = prefix.main,
                .interaction_col_offset = prefix.interaction,
            },
            .total_preprocessed_columns = try add(
                prefix.preprocessed,
                PREPROCESSED_COLUMNS,
            ),
            .total_main_columns = try add(prefix.main, MAIN_COLUMNS),
            .total_interaction_columns = try add(
                prefix.interaction,
                INTERACTION_COLUMNS,
            ),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAfterPrefix(prefix);
        return result;
    }

    pub fn validate(
        self: *const GeometryV3,
        core: *const statement_mod.RiscVStatement,
        base_interaction_columns: u32,
    ) !void {
        return self.validateAfterPrefix(.{
            .preprocessed = core.nPreprocessedColumns(),
            .main = core.nMainColumns(),
            .interaction = base_interaction_columns,
        });
    }

    pub fn validateAfterPrefix(
        self: *const GeometryV3,
        prefix: PrefixColumnsV3,
    ) !void {
        try prefix.validate();
        if (self.format_version != FORMAT_VERSION or self.n_rows == 0 or
            self.log_size != logSize(self.n_rows))
        {
            return error.InvalidIncrementalBridgeGeometry;
        }
        try self.placement.validate();
        const expected = try canonicalUnchecked(self.n_rows, prefix);
        if (!std.meta.eql(self.placement, expected.placement) or
            self.total_preprocessed_columns !=
                expected.total_preprocessed_columns or
            self.total_main_columns != expected.total_main_columns or
            self.total_interaction_columns !=
                expected.total_interaction_columns or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.InvalidIncrementalBridgeGeometry;
        }
    }

    pub fn mixFieldAuthority(self: *const GeometryV3, channel: anytype) void {
        channel.mixU32s(&DOMAIN_WORDS);
        channel.mixU32s(&.{
            self.format_version,
            self.n_rows,
            self.log_size,
            @intCast(self.placement.is_first_col_idx),
            @intCast(self.placement.is_active_col_idx),
            @intCast(self.placement.main_col_offset),
            @intCast(self.placement.interaction_col_offset),
            self.total_preprocessed_columns,
            self.total_main_columns,
            self.total_interaction_columns,
        });
    }
};

const GeometryUnchecked = struct {
    placement: bridge_component.Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
};

fn canonicalUnchecked(
    n_rows: u32,
    prefix: PrefixColumnsV3,
) !GeometryUnchecked {
    _ = n_rows;
    return .{
        .placement = .{
            .is_first_col_idx = prefix.preprocessed,
            .is_active_col_idx = try add(prefix.preprocessed, 1),
            .main_col_offset = prefix.main,
            .interaction_col_offset = prefix.interaction,
        },
        .total_preprocessed_columns = try add(
            prefix.preprocessed,
            PREPROCESSED_COLUMNS,
        ),
        .total_main_columns = try add(prefix.main, MAIN_COLUMNS),
        .total_interaction_columns = try add(
            prefix.interaction,
            INTERACTION_COLUMNS,
        ),
    };
}

pub const PreprocessedTraceV3 = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: [PREPROCESSED_COLUMNS][]M31,
    views: [PREPROCESSED_COLUMNS][]const M31,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: *const GeometryV3,
    ) !PreprocessedTraceV3 {
        var columns: [PREPROCESSED_COLUMNS][]M31 = undefined;
        columns[0] = try opcode_trace.generateIsFirst(
            allocator,
            geometry.log_size,
        );
        errdefer allocator.free(columns[0]);
        columns[1] = try opcode_trace.generateIsActive(
            allocator,
            geometry.log_size,
            geometry.n_rows,
        );
        return .{
            .allocator = allocator,
            .log_size = geometry.log_size,
            .columns = columns,
            .views = .{ columns[0], columns[1] },
        };
    }

    pub fn deinit(self: *PreprocessedTraceV3) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }

    pub fn block(self: *const PreprocessedTraceV3) external_tree.BorrowedBlock {
        return .{ .log_size = self.log_size, .columns = &self.views };
    }
};

pub const MainTraceV3 = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: bridge.Columns,
    views: [MAIN_COLUMNS][]const M31,

    pub fn init(
        allocator: std.mem.Allocator,
        rows: []const bridge.Row,
        geometry: *const GeometryV3,
    ) !MainTraceV3 {
        if (rows.len != geometry.n_rows)
            return error.InvalidIncrementalBridgeTrace;
        const columns = try bridge.generateMain(
            allocator,
            rows,
            geometry.log_size,
        );
        var views: [MAIN_COLUMNS][]const M31 = undefined;
        for (&views, columns.values) |*view, column| view.* = column;
        return .{
            .allocator = allocator,
            .log_size = geometry.log_size,
            .columns = columns,
            .views = views,
        };
    }

    pub fn deinit(self: *MainTraceV3) void {
        self.columns.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn block(self: *const MainTraceV3) external_tree.BorrowedBlock {
        return .{ .log_size = self.log_size, .columns = &self.views };
    }
};

pub const InteractionTraceV3 = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    interaction: bridge.Interaction,

    pub fn init(
        allocator: std.mem.Allocator,
        rows: []const bridge.Row,
        entry_root: u32,
        exit_root: u32,
        relations: *const relations_mod.Relations,
        geometry: *const GeometryV3,
    ) !InteractionTraceV3 {
        if (rows.len != geometry.n_rows)
            return error.InvalidIncrementalBridgeTrace;
        return .{
            .allocator = allocator,
            .log_size = geometry.log_size,
            .interaction = try bridge.generateInteraction(
                allocator,
                rows,
                geometry.log_size,
                entry_root,
                exit_root,
                relations,
            ),
        };
    }

    pub fn deinit(self: *InteractionTraceV3) void {
        self.interaction.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn claim(self: *const InteractionTraceV3) QM31 {
        return self.interaction.claim;
    }

    pub fn ownedColumns(
        self: *InteractionTraceV3,
    ) [INTERACTION_COLUMNS]external_tree.OwnedColumn {
        var result: [INTERACTION_COLUMNS]external_tree.OwnedColumn = undefined;
        for (&result, &self.interaction.columns) |*output, *column| {
            output.* = .{ .log_size = self.log_size, .values = column };
        }
        return result;
    }
};

pub fn mixClaim(channel: anytype, claim: QM31) void {
    channel.mixFelts(&.{claim});
}

pub fn Assembly(comptime direction: enum { prover, verifier }) type {
    const Handle = if (direction == .prover)
        prover_component.ComponentProver
    else
        core_components.Component;
    return struct {
        const Self = @This();
        const MAX_HANDLES = proof_workspace.MAX_COMPONENT_HANDLES + 1;

        bridge_component_value: bridge_component.IncrementalBridgeComponentV2,
        handles: [MAX_HANDLES]Handle,
        len: usize,

        pub fn create(
            allocator: std.mem.Allocator,
            base: []const Handle,
            geometry: *const GeometryV3,
            entry_root: u32,
            exit_root: u32,
            relations: *const relations_mod.Relations,
            claim: QM31,
        ) !*Self {
            if (base.len + 1 > MAX_HANDLES)
                return error.TooManyComponentHandles;
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.bridge_component_value =
                try bridge_component.IncrementalBridgeComponentV2.init(
                    geometry.log_size,
                    geometry.n_rows,
                    entry_root,
                    exit_root,
                    geometry.placement,
                    relations,
                    claim,
                );
            @memcpy(self.handles[0..base.len], base);
            self.handles[base.len] = if (direction == .prover)
                self.bridge_component_value.asProverComponent()
            else
                self.bridge_component_value.asVerifierComponent();
            self.len = base.len + 1;
            return self;
        }

        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.len];
        }

        pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self);
        }
    };
}

fn identity(value: *const GeometryV3) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashU16(&hash, value.format_version);
    hashU32(&hash, value.n_rows);
    hashU32(&hash, value.log_size);
    hashU32(&hash, @intCast(value.placement.is_first_col_idx));
    hashU32(&hash, @intCast(value.placement.is_active_col_idx));
    hashU32(&hash, @intCast(value.placement.main_col_offset));
    hashU32(&hash, @intCast(value.placement.interaction_col_offset));
    hashU32(&hash, value.total_preprocessed_columns);
    hashU32(&hash, value.total_main_columns);
    hashU32(&hash, value.total_interaction_columns);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn logSize(rows: u32) u32 {
    return @max(@as(u32, 4), std.math.log2_int_ceil(u32, rows));
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        error.IncrementalBridgeGeometryOverflow;
}

fn hashU16(hash: anytype, value: u16) void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .little);
    hash.update(&bytes);
}

fn hashU32(hash: anytype, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

// A real core always commits at least one column per tree, which
// `PrefixColumnsV3.validate` enforces; these owner tests therefore build the
// geometry from an explicit minimal prefix instead of a zero-column statement.
const test_prefix = PrefixColumnsV3{
    .preprocessed = 1,
    .main = 1,
    .interaction = 1,
};

test "incremental bridge external owner pins geometry and all three trees" {
    const allocator = std.testing.allocator;
    const geometry = try GeometryV3.canonicalAfterPrefix(2, test_prefix);
    try geometry.validateAfterPrefix(test_prefix);
    try std.testing.expectEqual(@as(u32, 4), geometry.log_size);
    try std.testing.expectEqual(
        test_prefix.preprocessed + @as(u32, PREPROCESSED_COLUMNS),
        geometry.total_preprocessed_columns,
    );
    try std.testing.expectEqual(
        test_prefix.main + @as(u32, MAIN_COLUMNS),
        geometry.total_main_columns,
    );
    try std.testing.expectEqual(
        test_prefix.interaction + @as(u32, INTERACTION_COLUMNS),
        geometry.total_interaction_columns,
    );

    const rows = [_]bridge.Row{
        .{ .index = 7, .depth = 30, .value = 11, .mode = .external_both },
        .{ .index = 3, .depth = 29, .value = 13, .mode = .reused_subtree },
    };
    var tree0 = try PreprocessedTraceV3.init(allocator, &geometry);
    defer tree0.deinit();
    var tree1 = try MainTraceV3.init(allocator, &rows, &geometry);
    defer tree1.deinit();
    const relations = relations_mod.Relations.dummy();
    var tree2 = try InteractionTraceV3.init(
        allocator,
        &rows,
        17,
        19,
        &relations,
        &geometry,
    );
    defer tree2.deinit();
    try std.testing.expectEqual(PREPROCESSED_COLUMNS, tree0.block().columns.len);
    try std.testing.expectEqual(MAIN_COLUMNS, tree1.block().columns.len);
    try std.testing.expectEqual(INTERACTION_COLUMNS, tree2.ownedColumns().len);

    const assembly = try Assembly(.prover).create(
        allocator,
        &.{},
        &geometry,
        17,
        19,
        &relations,
        tree2.claim(),
    );
    defer assembly.destroy(allocator);
    try std.testing.expectEqual(@as(usize, 1), assembly.active().len);
    try std.testing.expect(!PRODUCTION_ACTIVE);
}

test "incremental bridge external geometry rejects placement and row drift" {
    var geometry = try GeometryV3.canonicalAfterPrefix(1, test_prefix);
    geometry.placement.main_col_offset += 1;
    try std.testing.expectError(
        error.InvalidIncrementalBridgeGeometry,
        geometry.validateAfterPrefix(test_prefix),
    );
    // A degenerate prefix is refused before any geometry check.
    try std.testing.expectError(
        error.InvalidIncrementalBridgePrefix,
        GeometryV3.canonicalAfterPrefix(1, .{
            .preprocessed = 0,
            .main = 1,
            .interaction = 1,
        }),
    );
    const rows = [_]bridge.Row{.{
        .index = 1,
        .depth = 30,
        .value = 1,
        .mode = .external_entry,
    }};
    var canonical = try GeometryV3.canonicalAfterPrefix(2, test_prefix);
    try std.testing.expectError(
        error.InvalidIncrementalBridgeTrace,
        MainTraceV3.init(std.testing.allocator, &rows, &canonical),
    );
}

comptime {
    if (PRODUCTION_ACTIVE or COMPONENT_COUNT != 1 or
        PREPROCESSED_COLUMNS != 2 or MAIN_COLUMNS != 7 or
        INTERACTION_COLUMNS != 4)
    {
        @compileError("incremental bridge external V3 geometry drifted");
    }
}
