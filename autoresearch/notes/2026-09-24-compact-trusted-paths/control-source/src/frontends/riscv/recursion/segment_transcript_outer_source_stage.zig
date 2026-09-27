//! Internal shard of segment_transcript_outer_source.zig; use the public facade.

const dependency_0 = @import("segment_transcript_outer_source_executors.zig");

const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const segment_witness = dependency_0.segment_witness;
const framework = dependency_0.framework;
const relation_interaction = dependency_0.relation_interaction;
const manifest_mod = dependency_0.manifest_mod;
const binding = dependency_0.binding;
const roster = dependency_0.roster;
const universal = dependency_0.universal;
const control_air = dependency_0.control_air;
const control_witness = dependency_0.control_witness;
const transcript_air = dependency_0.transcript_air;
const transcript_binding_air = dependency_0.transcript_binding_air;
const transcript_state_air = dependency_0.transcript_state_air;
const transcript_word_air = dependency_0.transcript_word_air;
const transcript_payload_air = dependency_0.transcript_payload_air;
const pow_check_air = dependency_0.pow_check_air;
const pow_frame_air = dependency_0.pow_frame_air;
const relation_challenge_air = dependency_0.relation_challenge_air;
const verifier_randomness_air = dependency_0.verifier_randomness_air;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const LAST_ROW = dependency_0.LAST_ROW;
const ControlFramework = dependency_0.ControlFramework;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowFrameFramework = dependency_0.PowFrameFramework;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const ControlAdapter = dependency_0.ControlAdapter;
const TranscriptAirAdapter = dependency_0.TranscriptAirAdapter;
const TranscriptBindingAdapter = dependency_0.TranscriptBindingAdapter;
const TranscriptStateAdapter = dependency_0.TranscriptStateAdapter;
const TranscriptWordAdapter = dependency_0.TranscriptWordAdapter;
const TranscriptPayloadAdapter = dependency_0.TranscriptPayloadAdapter;
const PowCheckAdapter = dependency_0.PowCheckAdapter;
const PowFrameAdapter = dependency_0.PowFrameAdapter;
const RelationChallengeAdapter = dependency_0.RelationChallengeAdapter;
const VerifierRandomnessAdapter = dependency_0.VerifierRandomnessAdapter;
const LogSizes = dependency_0.LogSizes;
const PowLogSizes = dependency_0.PowLogSizes;

pub fn deriveLogSizes(
    control: *const control_witness.Preprocessed,
    preprocessing: *const segment_witness.Preprocessing,
    prepared: anytype,
    pow_log_sizes: PowLogSizes,
) !LogSizes {
    try pow_log_sizes.validateFor(prepared);
    return .{
        control.log_size,
        prepared.transcript_air.log_size,
        preprocessing.transcript_binding.log_size,
        preprocessing.transcript_state.log_size,
        preprocessing.transcript_word.log_size,
        preprocessing.transcript_payload.log_size,
        pow_log_sizes.check,
        pow_log_sizes.frame,
        preprocessing.relation_challenge.log_size,
        preprocessing.verifier_randomness.log_size,
    };
}

pub fn validateExecutorBinding(
    comptime Witness: type,
    definition: anytype,
    executor: *const Witness.Executor,
) !void {
    const expected = try Witness.Binding.canonical(definition);
    const actual = executor.binding.identityDigest();
    if (!std.meta.eql(expected, executor.binding) or
        !std.mem.eql(u8, &actual, &executor.binding_digest) or
        !std.mem.eql(u8, &actual, &Witness.BINDING_DIGEST))
    {
        return error.PreparedAuthorityMismatch;
    }
}

pub fn rowIndex(row: roster.Component) usize {
    const value = @intFromEnum(row);
    std.debug.assert(value >= FIRST_ROW and value <= LAST_ROW);
    return value - FIRST_ROW;
}

pub fn appendTupleContributions(
    plan: anytype,
    ledger: ?*relation_interaction.TupleLedger,
    component: roster.Component,
    rows: anytype,
) !void {
    if (ledger) |destination| {
        try plan.appendPreparedTupleContributions(
            destination,
            @intCast(@intFromEnum(component)),
            rows,
            relation_interaction.allDomainMask(),
        );
    }
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
    const destination = try stage.columns(Framework.INTERACTION_COLUMN_COUNT, row);
    for (destination, generated.columns) |target, source| @memcpy(target, source);
    return generated.claimed_sum;
}

pub const Stage = struct {
    allocator: std.mem.Allocator,
    tree: usize,
    offsets: [ROW_COUNT]usize,
    tree_offsets: [ROW_COUNT]usize,
    column_counts: [ROW_COUNT]usize,
    row_sizes: [ROW_COUNT]usize,
    destination: []const []M31,
    storage: ?[]M31,
    committed: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
        destination: []const []M31,
    ) !Stage {
        var offsets: [ROW_COUNT]usize = undefined;
        var tree_offsets: [ROW_COUNT]usize = undefined;
        var column_counts: [ROW_COUNT]usize = undefined;
        var row_sizes: [ROW_COUNT]usize = undefined;
        var total: usize = 0;
        inline for (0..ROW_COUNT) |index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            const placement = try manifest.placement(row);
            const column_count = geometryColumnCount(placement.geometry, tree);
            const row_size = try traceSize(placement.geometry.log_size);
            offsets[index] = total;
            tree_offsets[index] = placementTreeOffset(placement, tree);
            column_counts[index] = column_count;
            row_sizes[index] = row_size;
            total = std.math.add(
                usize,
                total,
                std.math.mul(usize, column_count, row_size) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
        }
        const direct = ownedDestinationIsZero(
            destination,
            tree_offsets,
            column_counts,
        );
        const storage = if (direct) null else try allocator.alloc(M31, total);
        if (storage) |values| @memset(values, M31.zero());
        return .{
            .allocator = allocator,
            .tree = tree,
            .offsets = offsets,
            .tree_offsets = tree_offsets,
            .column_counts = column_counts,
            .row_sizes = row_sizes,
            .destination = destination,
            .storage = storage,
            .committed = false,
        };
    }

    pub fn deinit(self: *Stage) void {
        // A direct write is permitted only over an all-zero owned sink. If any
        // later generator fails, restoring that exact prior state is an
        // allocation-free memset over rows 0--9; unrelated roster rows remain
        // untouched. Nonzero sinks retain the old copy-on-success fallback.
        if (self.storage == null and !self.committed)
            self.clearDestination();
        if (self.storage) |storage| self.allocator.free(storage);
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
        if (self.storage) |storage| {
            var cursor = self.offsets[index];
            for (&result) |*column| {
                column.* = storage[cursor..][0..row_size];
                cursor += row_size;
            }
        } else {
            const tree_offset = self.tree_offsets[index];
            for (&result, 0..) |*column, column_index|
                column.* = self.destination[tree_offset + column_index];
        }
        return result;
    }

    /// Infallible finalization after `preflightDestination`. In direct mode,
    /// generators already wrote logical rows into the owned destination and a
    /// failing caller would trigger `deinit` rollback; commit performs only the
    /// in-place commitment-order permutation and disarms that rollback.
    pub fn commit(
        self: *Stage,
        manifest: *const manifest_mod.Manifest,
    ) void {
        if (self.storage == null) {
            if (self.tree != manifest_mod.INTERACTION_TREE_INDEX) {
                inline for (0..ROW_COUNT) |index| {
                    const tree_offset = self.tree_offsets[index];
                    for (self.destination[tree_offset..][0..self.column_counts[index]]) |target|
                        stwo_core.utils.bitReverseCosetToCircleDomainOrder(M31, target);
                }
            }
            self.committed = true;
            return;
        }
        const storage = self.storage.?;
        inline for (0..ROW_COUNT) |index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            const placement = manifest.placement(row) catch unreachable;
            const tree_offset = placementTreeOffset(placement, self.tree);
            const row_size = self.row_sizes[index];
            var cursor = self.offsets[index];
            for (0..self.column_counts[index]) |column| {
                const source = storage[cursor..][0..row_size];
                const target = self.destination[tree_offset + column];
                if (self.tree == manifest_mod.INTERACTION_TREE_INDEX) {
                    // Framework LogUp generation already writes the canonical
                    // circle-domain commitment order.
                    @memcpy(target, source);
                } else {
                    // Typed main/preprocessed writers intentionally operate in
                    // logical row order. Commit exactly once at this boundary;
                    // copying them directly would prove a bit-permuted trace.
                    for (source, 0..) |value, logical_row|
                        target[
                            framework.committedRow(
                                logical_row,
                                std.math.log2_int(usize, row_size),
                            )
                        ] = value;
                }
                cursor += row_size;
            }
        }
        self.committed = true;
    }

    fn clearDestination(self: *Stage) void {
        inline for (0..ROW_COUNT) |index| {
            const tree_offset = self.tree_offsets[index];
            for (self.destination[tree_offset..][0..self.column_counts[index]]) |column|
                @memset(column, M31.zero());
        }
    }
};

pub fn ownedDestinationIsZero(
    destination: []const []M31,
    tree_offsets: [ROW_COUNT]usize,
    column_counts: [ROW_COUNT]usize,
) bool {
    inline for (0..ROW_COUNT) |index| {
        const tree_offset = tree_offsets[index];
        for (destination[tree_offset..][0..column_counts[index]]) |column| {
            for (column) |value| if (!value.isZero()) return false;
        }
    }
    return true;
}

pub fn preflightDestination(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    const expected_columns = manifestTreeColumnCount(manifest, tree);
    if (destination.len != expected_columns)
        return error.DestinationColumnCountMismatch;
    inline for (0..ROW_COUNT) |index| {
        const row: roster.Component = @enumFromInt(FIRST_ROW + index);
        const placement = try manifest.placement(row);
        const offset = placementTreeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        const expected_rows = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationColumnCountMismatch;
        for (destination[offset..][0..count]) |column| {
            if (column.len != expected_rows)
                return error.DestinationLogSizeMismatch;
        }
    }
    // Reject two manifest columns backed by overlapping memory. Without this
    // check a malicious sink could make a later row overwrite an earlier one.
    inline for (0..ROW_COUNT) |left_index| {
        const left_row: roster.Component = @enumFromInt(FIRST_ROW + left_index);
        const left_placement = try manifest.placement(left_row);
        const left_offset = placementTreeOffset(left_placement, tree);
        const left_count = geometryColumnCount(left_placement.geometry, tree);
        for (destination[left_offset..][0..left_count], 0..) |left, column_index| {
            var right_row_index: usize = left_index;
            while (right_row_index < ROW_COUNT) : (right_row_index += 1) {
                const right_row: roster.Component = @enumFromInt(FIRST_ROW + right_row_index);
                const right_placement = try manifest.placement(right_row);
                const right_offset = placementTreeOffset(right_placement, tree);
                const right_count = geometryColumnCount(right_placement.geometry, tree);
                const start = if (right_row_index == left_index) column_index + 1 else 0;
                for (destination[right_offset + start ..][0 .. right_count - start]) |right| {
                    if (slicesOverlap(left, right)) return error.DestinationAlias;
                }
            }
        }
    }
}

pub fn slicesOverlap(left: []M31, right: []M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len * @sizeOf(M31);
    const right_end = right_start + right.len * @sizeOf(M31);
    return left_start < right_end and right_start < left_end;
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn manifestTreeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn placementTreeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn geometryColumnCount(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

pub fn sourceColumnCount(index: usize, tree: usize) ?usize {
    const preprocessed = [ROW_COUNT]usize{
        control_air.PREPROCESSED_COLUMN_COUNT,
        transcript_air.PREPROCESSED_COLUMN_COUNT,
        transcript_binding_air.PREPROCESSED_COLUMN_COUNT,
        transcript_state_air.PREPROCESSED_COLUMN_COUNT,
        transcript_word_air.PREPROCESSED_COLUMN_COUNT,
        transcript_payload_air.PREPROCESSED_COLUMN_COUNT,
        pow_check_air.PREPROCESSED_COLUMN_COUNT,
        pow_frame_air.PREPROCESSED_COLUMN_COUNT,
        relation_challenge_air.PREPROCESSED_COLUMN_COUNT,
        verifier_randomness_air.PREPROCESSED_COLUMN_COUNT,
    };
    const main = [ROW_COUNT]usize{
        control_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_binding_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_state_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_word_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_payload_air.PHYSICAL_MAIN_COLUMN_COUNT,
        pow_check_air.PHYSICAL_MAIN_COLUMN_COUNT,
        pow_frame_air.PHYSICAL_MAIN_COLUMN_COUNT,
        relation_challenge_air.PHYSICAL_MAIN_COLUMN_COUNT,
        verifier_randomness_air.PHYSICAL_MAIN_COLUMN_COUNT,
    };
    const interaction = [ROW_COUNT]usize{
        ControlFramework.INTERACTION_COLUMN_COUNT,
        TranscriptAirFramework.INTERACTION_COLUMN_COUNT,
        TranscriptBindingFramework.INTERACTION_COLUMN_COUNT,
        TranscriptStateFramework.INTERACTION_COLUMN_COUNT,
        TranscriptWordFramework.INTERACTION_COLUMN_COUNT,
        TranscriptPayloadFramework.INTERACTION_COLUMN_COUNT,
        PowCheckFramework.INTERACTION_COLUMN_COUNT,
        PowFrameFramework.INTERACTION_COLUMN_COUNT,
        RelationChallengeFramework.INTERACTION_COLUMN_COUNT,
        VerifierRandomnessFramework.INTERACTION_COLUMN_COUNT,
    };
    if (index >= ROW_COUNT) return null;
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => preprocessed[index],
        manifest_mod.MAIN_TREE_INDEX => main[index],
        manifest_mod.INTERACTION_TREE_INDEX => interaction[index],
        else => null,
    };
}

comptime {
    if (FIRST_ROW != 0 or LAST_ROW != 9)
        @compileError("segment transcript outer source roster range drifted");
    if (ControlAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptAirAdapter.PARAMETER_COLUMN_COUNT != 0 or
        TranscriptBindingAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptStateAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptWordAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptPayloadAdapter.PARAMETER_COLUMN_COUNT != 2 or
        PowCheckAdapter.PARAMETER_COLUMN_COUNT != 0 or
        PowFrameAdapter.PARAMETER_COLUMN_COUNT != 0 or
        RelationChallengeAdapter.PARAMETER_COLUMN_COUNT != 4 or
        VerifierRandomnessAdapter.PARAMETER_COLUMN_COUNT != 2)
    {
        @compileError("segment transcript parameter geometry drifted");
    }
}
