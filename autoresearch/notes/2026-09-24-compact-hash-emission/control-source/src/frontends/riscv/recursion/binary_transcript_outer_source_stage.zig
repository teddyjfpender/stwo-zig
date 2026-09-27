//! Internal shard of binary_transcript_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_transcript_outer_source_executors.zig");
const dependency_3 = @import("binary_transcript_outer_source_source_column_count.zig");

const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const binary_authority = dependency_0.binary_authority;
const framework = dependency_0.framework;
const relation_interaction = dependency_0.relation_interaction;
const manifest_mod = dependency_0.manifest_mod;
const binding = dependency_0.binding;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const control_witness = dependency_0.control_witness;
const transcript_air = dependency_0.transcript_air;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const LAST_ROW = dependency_0.LAST_ROW;
const ControlRelation = dependency_0.ControlRelation;
const TranscriptAirRelation = dependency_0.TranscriptAirRelation;
const TranscriptBindingRelation = dependency_0.TranscriptBindingRelation;
const TranscriptStateRelation = dependency_0.TranscriptStateRelation;
const TranscriptWordRelation = dependency_0.TranscriptWordRelation;
const TranscriptPayloadRelation = dependency_0.TranscriptPayloadRelation;
const PowCheckRelation = dependency_0.PowCheckRelation;
const PowFrameRelation = dependency_0.PowFrameRelation;
const RelationChallengeRelation = dependency_0.RelationChallengeRelation;
const VerifierRandomnessRelation = dependency_0.VerifierRandomnessRelation;
const LogSizes = dependency_0.LogSizes;
const PowLogSizes = dependency_0.PowLogSizes;
const Owners = dependency_0.Owners;
const preflightDestination = dependency_3.preflightDestination;
const traceSize = dependency_3.traceSize;
const placementTreeOffset = dependency_3.placementTreeOffset;
const geometryColumnCount = dependency_3.geometryColumnCount;

pub fn logicalStorageCount(
    source: anytype,
    preprocessing: *const binary_authority.TranscriptPreprocessing,
    prepared: anytype,
) !usize {
    var total: usize = 0;
    total = try addRowStorage(
        ControlRelation.Row,
        total,
        source.control_preprocessing.rows.len,
    );
    total = try addRowStorage(
        TranscriptAirRelation.Row,
        total,
        prepared.transcript_air.rows.len,
    );
    total = try addRowStorage(
        TranscriptBindingRelation.Row,
        total,
        preprocessing.transcript_binding.rows.len,
    );
    total = try addRowStorage(
        TranscriptStateRelation.Row,
        total,
        preprocessing.transcript_state.rows.len,
    );
    total = try addRowStorage(
        TranscriptWordRelation.Row,
        total,
        preprocessing.transcript_word.rows.len,
    );
    total = try addRowStorage(
        TranscriptPayloadRelation.Row,
        total,
        preprocessing.transcript_payload.rows.len,
    );
    total = try addRowStorage(
        PowCheckRelation.Row,
        total,
        prepared.pow_check.invocations.len,
    );
    total = try addRowStorage(
        PowFrameRelation.Row,
        total,
        prepared.pow_frame.invocations.len,
    );
    total = try addRowStorage(
        RelationChallengeRelation.Row,
        total,
        preprocessing.relation_challenge.rows.len,
    );
    return addRowStorage(
        VerifierRandomnessRelation.Row,
        total,
        preprocessing.verifier_randomness.rows.len,
    );
}

pub fn addRowStorage(comptime Row: type, total: usize, count: usize) !usize {
    comptime validatePackedRow(Row);
    const row_cells = @sizeOf(Row) / @sizeOf(M31);
    const cells = std.math.mul(usize, row_cells, count) catch
        return error.ArithmeticOverflow;
    return std.math.add(usize, total, cells) catch
        return error.ArithmeticOverflow;
}

pub fn carveRows(
    comptime Row: type,
    storage: []M31,
    cursor: *usize,
    count: usize,
) ![]Row {
    const end = try addRowStorage(Row, cursor.*, count);
    if (end > storage.len) return error.InteractionWorkspaceGeometryMismatch;
    const result = @as([*]Row, @ptrCast(storage[cursor.*..].ptr))[0..count];
    cursor.* = end;
    return result;
}

pub fn validateCarvedRows(
    comptime Row: type,
    storage: []const M31,
    cursor: *usize,
    actual: []const Row,
    expected_count: usize,
) !void {
    const end = try addRowStorage(Row, cursor.*, expected_count);
    if (end > storage.len or actual.len != expected_count or
        @intFromPtr(actual.ptr) != @intFromPtr(storage[cursor.*..].ptr))
    {
        return error.InteractionWorkspaceGeometryMismatch;
    }
    cursor.* = end;
}

pub fn validatePackedRow(comptime Row: type) void {
    if (@alignOf(Row) > @alignOf(M31) or
        @sizeOf(Row) == 0 or
        @sizeOf(Row) % @sizeOf(M31) != 0)
    {
        @compileError("interaction logical rows must be packed M31 arrays");
    }
}

pub fn deriveLogSizes(
    control: *const control_witness.Preprocessed,
    preprocessing: *const binary_authority.TranscriptPreprocessing,
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

/// Compact, allocation-free integrity seal over the static typed programs,
/// exact preprocessing/schedule authority, and the already-authenticated pair
/// custody record.  It is not a substitute for `Prepared.init`'s Poseidon
/// authentication; it lets hot tree writers detect mutation without repeating
/// that expensive cold protocol walk.
pub fn sourceDigest(
    source: anytype,
    preprocessing: *const binary_authority.TranscriptPreprocessing,
    prepared: anytype,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-riscv-binary-transcript-outer-source-v1");
    hashCanonicalValue(&hash, FORMAT_VERSION);

    // Exact authenticated typed-program identities in roster order. Owners
    // are independently revalidated against their definitions on every use.
    hashCanonicalValue(&hash, source.owners.control.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.transcript_air.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.transcript_binding.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.transcript_state.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.transcript_word.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.transcript_payload.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.pow_check.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.pow_frame.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.relation_challenge.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.verifier_randomness.relation.semantic_digest);
    hashCanonicalValue(&hash, source.owners.control.relation.registry_order_digest);

    hashCanonicalValue(&hash, source.vm_schedule_digest);
    hashCanonicalValue(&hash, source.recursion_schedule_digests);
    hashCanonicalValue(&hash, source.log_sizes);
    hashCanonicalValue(&hash, source.parameters);
    hashPreprocessingAuthority(&hash, &source.control_preprocessing);
    hashPreprocessingAuthority(&hash, &preprocessing.transcript_binding);
    hashPreprocessingAuthority(&hash, &preprocessing.transcript_state);
    hashPreprocessingAuthority(&hash, &preprocessing.transcript_word);
    hashPreprocessingAuthority(&hash, &preprocessing.transcript_payload);
    hashPreprocessingAuthority(&hash, &preprocessing.relation_challenge);
    hashPreprocessingAuthority(&hash, &preprocessing.verifier_randomness);

    // These values were admitted together by `binary_pair_authority.Prepared`.
    // Canonical structural hashing avoids padding and pointer identities.
    hashCanonicalValue(&hash, prepared.plan_digest);
    hashCanonicalValue(&hash, prepared.contract);
    hashCanonicalValue(&hash, prepared.authority);
    hashCanonicalValue(&hash, prepared.record);
    hashCanonicalValue(&hash, prepared.authenticated_root);
    hashCanonicalValue(&hash, prepared.left_statement);
    hashCanonicalValue(&hash, prepared.right_statement);
    hashCanonicalValue(&hash, prepared.parent_statement);
    hashCanonicalValue(&hash, prepared.left_words);
    hashCanonicalValue(&hash, prepared.right_words);
    hashCanonicalValue(&hash, prepared.parent_words);
    return hash.finalResult();
}

pub fn hashPreprocessingAuthority(hash: anytype, value: anytype) void {
    hashCanonicalValue(hash, value.log_size);
    hashCanonicalValue(hash, value.vm_schedule_digest);
    hashCanonicalValue(hash, value.recursion_schedule_digest);
    hashCanonicalValue(hash, @as(u64, @intCast(value.rows.len)));
}

pub fn hashCanonicalValue(hash: anytype, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .bool => hashCanonicalInt(hash, u8, @intFromBool(value)),
        .int => hashCanonicalInt(hash, T, value),
        .@"enum" => |info| hashCanonicalInt(hash, info.tag_type, @intFromEnum(value)),
        .array => for (value) |item| hashCanonicalValue(hash, item),
        .@"struct" => inline for (std.meta.fields(T)) |field|
            hashCanonicalValue(hash, @field(value, field.name)),
        .@"union" => |info| {
            const Tag = info.tag_type orelse
                @compileError("authority seal requires tagged unions");
            const active = std.meta.activeTag(value);
            hashCanonicalValue(hash, active);
            inline for (info.fields) |field| {
                if (active == @field(Tag, field.name))
                    hashCanonicalValue(hash, @field(value, field.name));
            }
        },
        .optional => {
            if (value) |payload| {
                hashCanonicalInt(hash, u8, 1);
                hashCanonicalValue(hash, payload);
            } else {
                hashCanonicalInt(hash, u8, 0);
            }
        },
        .void => {},
        else => @compileError("unsupported canonical authority-seal field: " ++ @typeName(T)),
    }
}

pub fn hashCanonicalInt(hash: anytype, comptime T: type, value: T) void {
    const info = @typeInfo(T).int;
    if (info.bits > 128) @compileError("authority-seal integer exceeds 128 bits");
    const U = std.meta.Int(.unsigned, info.bits);
    const unsigned: U = @bitCast(value);
    var encoded: [19]u8 = undefined;
    std.mem.writeInt(u16, encoded[0..2], info.bits, .little);
    encoded[2] = @intFromBool(info.signedness == .signed);
    std.mem.writeInt(u128, encoded[3..19], @as(u128, unsigned), .little);
    hash.update(&encoded);
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
    workspace: *Framework.Workspace,
    plan: *const Framework.Plan,
    rows: []const Framework.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
    stage: *Stage,
    row: roster.Component,
) !QM31 {
    var destination = try stage.columns(Framework.INTERACTION_COLUMN_COUNT, row);
    return Framework.generatePreparedInto(
        workspace,
        plan,
        rows,
        log_size,
        relations,
        &destination,
    );
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
