//! Fixed-column geometry and independent Tree0 reconstruction.
const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;
const m31 = @import("stwo_core").fields.m31;
const fixed_program_table = @import("stwo_riscv_rv32").air.program.fixed_table;
const program_commitment = @import("stwo_riscv_rv32").air.program.commitment;
const lookup_physical_v2 =
    @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const statement = @import("stwo_riscv_rv32").air.statement;
const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const incremental_bridge = @import("incremental_bridge_external.zig");
const ethereum_preprocessed =
    @import("guest_precompile/ethereum_preprocessed.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");

pub fn prefixColumns(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
    circuit_profile: @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1,
) !incremental_bridge.PrefixColumnsV3 {
    var result = incremental_bridge.PrefixColumnsV3{
        .preprocessed = native.core.nPreprocessedColumns(),
        .main = native.core.nMainColumns(),
        .interaction = @intCast(
            try authenticated.totalInteractionColumns(&native.core, manifest),
        ),
    };
    for (extension.components) |descriptor| {
        result.preprocessed = try add(
            result.preprocessed,
            descriptor.preprocessed_columns,
        );
        result.main = try add(result.main, descriptor.main_columns);
        result.interaction = try add(
            result.interaction,
            descriptor.interaction_columns,
        );
    }
    if (circuit_profile.programPolicy() == .fixed_decoded_table_v1) result.preprocessed = try add(result.preprocessed, fixed_program_table.COLUMN_COUNT);
    try result.validate();
    return result;
}

pub fn deriveExpectedPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    native_core: *const statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    geometry: *const incremental_bridge.GeometryV3,
    pcs_config: pcs_core.PcsConfig,
) !Engine.Hasher.Hash {
    return deriveExpectedPreprocessedRootInternal(Engine, allocator, native_core, extension, geometry, pcs_config, null);
}

pub fn deriveExpectedPreprocessedRootWithFixedProgramV1(comptime Engine: type, allocator: std.mem.Allocator, native_core: *const statement.RiscVStatement, extension: *const ethereum_statement.Statement, geometry: *const incremental_bridge.GeometryV3, pcs_config: pcs_core.PcsConfig, fixed_rows: []const program_commitment.Row) !Engine.Hasher.Hash {
    return deriveExpectedPreprocessedRootInternal(Engine, allocator, native_core, extension, geometry, pcs_config, fixed_rows);
}

pub fn deriveExpectedPreprocessedRootInternal(comptime Engine: type, allocator: std.mem.Allocator, native_core: *const statement.RiscVStatement, extension: *const ethereum_statement.Statement, geometry: *const incremental_bridge.GeometryV3, pcs_config: pcs_core.PcsConfig, fixed_rows: ?[]const program_commitment.Row) !Engine.Hasher.Hash {
    if (native_core.n_components > statement.MAX_COMPONENTS or
        native_core.n_infra > statement.MAX_INFRA_COMPONENTS)
        return error.InvalidIncrementalEthereumProofShape;
    try extension.validateStructure(native_core);
    const manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(native_core, &manifest);
    var prefix = incremental_bridge.PrefixColumnsV3{
        .preprocessed = native_core.nPreprocessedColumns(),
        .main = native_core.nMainColumns(),
        .interaction = std.math.cast(u32, try authenticated.totalInteractionColumns(native_core, &manifest)) orelse return error.InvalidIncrementalEthereumProofShape,
    };
    for (extension.components) |descriptor| {
        prefix.preprocessed = try add(prefix.preprocessed, descriptor.preprocessed_columns);
        prefix.main = try add(prefix.main, descriptor.main_columns);
        prefix.interaction = try add(prefix.interaction, descriptor.interaction_columns);
    }
    if (fixed_rows != null) prefix.preprocessed = try add(prefix.preprocessed, fixed_program_table.COLUMN_COUNT);
    try geometry.validateAfterPrefix(prefix);
    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(allocator, geometry);
    defer bridge_tree0.deinit();
    var fixed_columns: ?fixed_program_table.ColumnsV1 = if (fixed_rows) |rows| try fixed_program_table.ColumnsV1.init(allocator, rows, native_core.infra_descs[0].log_size) else null;
    defer if (fixed_columns) |*columns| columns.deinit(allocator);
    var blocks: [2]external_tree.BorrowedBlock = undefined;
    var count: usize = 0;
    var fixed_views: [fixed_program_table.COLUMN_COUNT][]const m31.M31 = undefined;
    if (fixed_columns) |columns| {
        for (columns.values, &fixed_views) |column, *view| view.* = column;
        blocks[count] = .{ .log_size = columns.log_size, .columns = &fixed_views };
        count += 1;
    }
    blocks[count] = bridge_tree0.block();
    count += 1;
    const columns = try ethereum_preprocessed.generateWithExternalBlocks(
        allocator,
        native_core,
        extension,
        blocks[0..count],
    );
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.InvalidIncrementalEthereumPreprocessedRoot;
    return roots.items[0];
}

pub fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.IncrementalEthereumLeafGeometryOverflow;
}

pub fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
