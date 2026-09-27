//! Internal shard of binary_inactive_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_inactive_outer_source_claims.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const leaf_authority = dependency_0.leaf_authority;
const segment_source = dependency_0.segment_source;
const air = dependency_0.air;
const framework = dependency_0.framework;
const manifest_mod = dependency_0.manifest_mod;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const universal = dependency_0.universal;
const FIRST_ROW = dependency_0.FIRST_ROW;
const LAST_INACTIVE_ROW = dependency_0.LAST_INACTIVE_ROW;
const CONTROL_ROW = dependency_0.CONTROL_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const INACTIVE_ROW_COUNT = dependency_0.INACTIVE_ROW_COUNT;
const Parameters = dependency_0.Parameters;

pub fn appendTupleContributions(
    plan: anytype,
    ledger: ?*relation_interaction.TupleLedger,
    component: roster.Component,
    rows: anytype,
) !void {
    if (ledger) |destination| try plan.appendPreparedTupleContributions(
        destination,
        @intCast(@intFromEnum(component)),
        rows,
        relation_interaction.allDomainMask(),
    );
}

pub fn generateIntoStage(
    comptime Framework: type,
    allocator: std.mem.Allocator,
    plan: *const Framework.Plan,
    rows: []const Framework.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
    stage: *Stage,
    row: roster.Component,
) !QM31 {
    var generated = try Framework.generatePrepared(
        allocator,
        plan,
        rows,
        log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const destination = try stage.columns(
        Framework.INTERACTION_COLUMN_COUNT,
        row,
    );
    for (destination, generated.columns) |target, source| @memcpy(target, source);
    return generated.claimed_sum;
}

pub const Stage = struct {
    allocator: std.mem.Allocator,
    tree: usize,
    offsets: [ROW_COUNT]usize,
    column_counts: [ROW_COUNT]usize,
    row_sizes: [ROW_COUNT]usize,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !Stage {
        var offsets: [ROW_COUNT]usize = undefined;
        var column_counts: [ROW_COUNT]usize = undefined;
        var row_sizes: [ROW_COUNT]usize = undefined;
        var total: usize = 0;
        inline for (0..ROW_COUNT) |index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            const placement = try manifest.placement(row);
            const column_count = geometryColumnCount(placement.geometry, tree);
            const row_size = try traceSize(placement.geometry.log_size);
            offsets[index] = total;
            column_counts[index] = column_count;
            row_sizes[index] = row_size;
            total = std.math.add(
                usize,
                total,
                std.math.mul(usize, column_count, row_size) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
        }
        const storage = try allocator.alloc(M31, total);
        @memset(storage, M31.zero());
        return .{
            .allocator = allocator,
            .tree = tree,
            .offsets = offsets,
            .column_counts = column_counts,
            .row_sizes = row_sizes,
            .storage = storage,
        };
    }

    pub fn deinit(self: *Stage) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn columns(
        self: *Stage,
        comptime count: usize,
        row: roster.Component,
    ) ![count][]M31 {
        const index = rowIndex(row);
        if (self.column_counts[index] != count)
            return error.ManifestGeometryMismatch;
        var result: [count][]M31 = undefined;
        const row_size = self.row_sizes[index];
        var cursor = self.offsets[index];
        for (&result) |*column| {
            column.* = self.storage[cursor..][0..row_size];
            cursor += row_size;
        }
        return result;
    }

    pub fn commit(
        self: *const Stage,
        manifest: *const manifest_mod.Manifest,
        destination: []const []M31,
    ) void {
        inline for (0..ROW_COUNT) |index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            const placement = manifest.placement(row) catch unreachable;
            const tree_offset = placementTreeOffset(placement, self.tree);
            const row_size = self.row_sizes[index];
            var cursor = self.offsets[index];
            for (0..self.column_counts[index]) |column| {
                const source = self.storage[cursor..][0..row_size];
                const target = destination[tree_offset + column];
                if (self.tree == manifest_mod.INTERACTION_TREE_INDEX) {
                    @memcpy(target, source);
                } else {
                    for (source, 0..) |value, logical_row| target[
                        framework.committedRow(
                            logical_row,
                            std.math.log2_int(usize, row_size),
                        )
                    ] = value;
                }
                cursor += row_size;
            }
        }
    }
};

pub fn preflightDestination(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    if (destination.len != manifestTreeColumnCount(manifest, tree))
        return error.DestinationColumnCountMismatch;
    inline for (0..ROW_COUNT) |index| {
        const row: roster.Component = @enumFromInt(FIRST_ROW + index);
        const placement = try manifest.placement(row);
        const offset = placementTreeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        const expected_rows = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationColumnCountMismatch;
        for (destination[offset..][0..count]) |column|
            if (column.len != expected_rows)
                return error.DestinationLogSizeMismatch;
    }
    inline for (0..ROW_COUNT) |left_index| {
        const left_row: roster.Component = @enumFromInt(FIRST_ROW + left_index);
        const left_placement = try manifest.placement(left_row);
        const left_offset = placementTreeOffset(left_placement, tree);
        const left_count = geometryColumnCount(left_placement.geometry, tree);
        for (destination[left_offset..][0..left_count], 0..) |
            left,
            left_column,
        | {
            var right_index: usize = left_index;
            while (right_index < ROW_COUNT) : (right_index += 1) {
                const right_row: roster.Component = @enumFromInt(
                    FIRST_ROW + right_index,
                );
                const right_placement = try manifest.placement(right_row);
                const right_offset = placementTreeOffset(right_placement, tree);
                const right_count = geometryColumnCount(
                    right_placement.geometry,
                    tree,
                );
                const start = if (right_index == left_index)
                    left_column + 1
                else
                    0;
                for (destination[right_offset + start ..][0 .. right_count - start]) |
                    right,
                | if (slicesOverlap(left, right)) return error.DestinationAlias;
            }
        }
    }
}

pub fn rowIndex(row: roster.Component) usize {
    const value = @intFromEnum(row);
    std.debug.assert(value >= FIRST_ROW and value <= CONTROL_ROW);
    return value - FIRST_ROW;
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn manifestTreeColumnCount(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn placementTreeOffset(
    placement: manifest_mod.Placement,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn geometryColumnCount(
    geometry: manifest_mod.Geometry,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

pub fn slicesOverlap(left: []const M31, right: []const M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(
        usize,
        left_start,
        left.len * @sizeOf(M31),
    ) catch return true;
    const right_end = std.math.add(
        usize,
        right_start,
        right.len * @sizeOf(M31),
    ) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn leafPreprocessingDigest(
    preprocessing: *const leaf_authority.Preprocessing,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-inactive-leaf-preprocessing/v1\x00");
    hash.update(&preprocessing.claim_input.authority_digest);
    hash.update(&preprocessing.claim_hash.authority_digest);
    hash.update(&preprocessing.io_hash.authority_digest);
    return hash.finalResult();
}

pub fn hashRows(hash: anytype, rows: anytype) void {
    hashInt(hash, u64, rows.len);
    for (rows) |row| for (row) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (FIRST_ROW != 12 or LAST_INACTIVE_ROW != 16 or CONTROL_ROW != 17 or
        ROW_COUNT != 6 or INACTIVE_ROW_COUNT != 5)
    {
        @compileError("binary inactive outer source roster contract drifted");
    }
    if (@sizeOf(Parameters) != @sizeOf(segment_source.Parameters))
        @compileError("binary inactive parameter geometry drifted");
}
