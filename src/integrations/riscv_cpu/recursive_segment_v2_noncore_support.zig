const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const contract = @import("recursive_segment_v2_noncore_contract.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const transcript_source = recursion.segment_transcript_outer_source_v2;
const transcript_components = recursion.segment_transcript_outer_components_v2;
const statement_source = recursion.segment_statement_outer_source_v2;
const public_source = recursion.segment_public_outer_source_v2;
const range_authority = recursion.segment_range_authority_v2;
const boundary_authority = recursion.segment_leaf_outer_authority_v2;
const input_provider_authority = recursion.segment_publication_input_provider_authority_v2;
const input_provider_air = recursion.air.segment_publication_input_provider_v2;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;
const native_relations_mod = frontend.air.relation_challenges;
const range_bridge = recursion.air.range_check_8_8_bridge;
const noncore_audits = recursion.segment_outer_noncore_audits_v2;
const OWNED_ROW_INDICES = noncore_audits.NONCORE_ROW_INDICES;
const PreparedNativeV2LeafOuter = leaf_outer.PreparedNativeV2LeafOuter;
const Manifest = manifest_mod.Manifest;
const GeneratedInteractionsV2 = contract.GeneratedInteractionsV2;
const FORMAT_VERSION: u16 = 1;
const SCHEMA_VERSION: u16 = 1;
const AUTHORITY_ID_DOMAIN = contract.OWNER_ID_DOMAIN;
const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4e43_5632;

pub const OwnedStatementDestinations = struct {
    allocator: std.mem.Allocator,
    preprocessed_storage: []M31,
    main_storage: []M31,
    logical_rows: []statement_source.Air.Row,
    events: []statement_source.RelationEventV2,
    ranges: []statement_source.RangeRequestV2,
    preprocessed: [statement_source.Air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: statement_source.ManifestV2,
    ) !OwnedStatementDestinations {
        const rows: usize = manifest.trace_row_count;
        const preprocessed_storage = try allocator.alloc(
            M31,
            try std.math.mul(
                usize,
                rows,
                statement_source.Air.PREPROCESSED_COLUMN_COUNT,
            ),
        );
        errdefer allocator.free(preprocessed_storage);
        const main_storage = try allocator.alloc(
            M31,
            try std.math.mul(
                usize,
                rows,
                statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT,
            ),
        );
        errdefer allocator.free(main_storage);
        const logical_rows = try allocator.alloc(
            statement_source.Air.Row,
            manifest.logical_row_count,
        );
        errdefer allocator.free(logical_rows);
        const events = try allocator.alloc(
            statement_source.RelationEventV2,
            manifest.relation_event_count,
        );
        errdefer allocator.free(events);
        const ranges = try allocator.alloc(
            statement_source.RangeRequestV2,
            manifest.range_request_count,
        );
        errdefer allocator.free(ranges);
        var preprocessed: [statement_source.Air.PREPROCESSED_COLUMN_COUNT][]M31 =
            undefined;
        for (&preprocessed, 0..) |*column, index|
            column.* = preprocessed_storage[index * rows ..][0..rows];
        var main: [statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&main, 0..) |*column, index|
            column.* = main_storage[index * rows ..][0..rows];
        return .{
            .allocator = allocator,
            .preprocessed_storage = preprocessed_storage,
            .main_storage = main_storage,
            .logical_rows = logical_rows,
            .events = events,
            .ranges = ranges,
            .preprocessed = preprocessed,
            .main = main,
        };
    }

    pub fn deinit(self: *OwnedStatementDestinations) void {
        self.allocator.free(self.ranges);
        self.allocator.free(self.events);
        self.allocator.free(self.logical_rows);
        self.allocator.free(self.main_storage);
        self.allocator.free(self.preprocessed_storage);
        self.* = undefined;
    }

    pub fn destinations(self: *OwnedStatementDestinations) statement_source.DestinationsV2 {
        return .{
            .trace = .{ .preprocessed = self.preprocessed, .main = self.main },
            .logical_rows = self.logical_rows,
            .relation_events = self.events,
            .range_requests = self.ranges,
        };
    }
};

pub const OwnedInputProviderTraces = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    preprocessed: [input_provider_air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [input_provider_air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    interaction: [input_provider_air.INTERACTION_COLUMN_COUNT][]M31,

    pub fn init(allocator: std.mem.Allocator) !OwnedInputProviderTraces {
        const row_count = input_provider_authority.TRACE_ROW_COUNT;
        const column_count = input_provider_air.PREPROCESSED_COLUMN_COUNT +
            input_provider_air.PHYSICAL_MAIN_COLUMN_COUNT +
            input_provider_air.INTERACTION_COLUMN_COUNT;
        const storage = try allocator.alloc(M31, try std.math.mul(
            usize,
            row_count,
            column_count,
        ));
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var at: usize = 0;
        var preprocessed: [input_provider_air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed) |*column| {
            column.* = storage[at..][0..row_count];
            at += row_count;
        }
        var main: [input_provider_air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&main) |*column| {
            column.* = storage[at..][0..row_count];
            at += row_count;
        }
        var interaction: [input_provider_air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction) |*column| {
            column.* = storage[at..][0..row_count];
            at += row_count;
        }
        std.debug.assert(at == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        };
    }

    pub fn deinit(self: *OwnedInputProviderTraces) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn view(self: *OwnedInputProviderTraces) input_provider_authority.TraceV2 {
        return .{
            .preprocessed = self.preprocessed,
            .main = self.main,
            .interaction = self.interaction,
        };
    }
};

/// Global-width pointer table backed only for the 22 owned rows. Empty core
/// slices preserve the component writers' whole-tree alias checks without
/// allocating a second copy of the large verifier-core traces.
pub const SparseTree = struct {
    allocator: std.mem.Allocator,
    tree_index: usize,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const Manifest,
        tree_index: usize,
    ) !SparseTree {
        try manifest.validate();
        const column_count: usize = treeColumnCount(manifest, tree_index) orelse
            return error.ManifestMismatch;
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        for (columns) |*column| column.* = @constCast((&[_]M31{})[0..]);
        var words: usize = 0;
        for (OWNED_ROW_INDICES) |row| {
            const placement = manifest.placements[row].?;
            const size = try traceSize(placement.geometry.log_size);
            words = try std.math.add(
                usize,
                words,
                try std.math.mul(
                    usize,
                    size,
                    treeGeometryColumns(placement.geometry, tree_index),
                ),
            );
        }
        const storage = try allocator.alloc(M31, words);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (OWNED_ROW_INDICES) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, tree_index);
            const count = treeGeometryColumns(placement.geometry, tree_index);
            const size = try traceSize(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..size];
                cursor += size;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{
            .allocator = allocator,
            .tree_index = tree_index,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *SparseTree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn clear(self: *SparseTree) void {
        @memset(self.storage, M31.zero());
    }

    pub fn validate(self: *const SparseTree, manifest: *const Manifest) !void {
        if (self.columns.len != (treeColumnCount(manifest, self.tree_index) orelse
            return error.ManifestMismatch)) return error.ManifestMismatch;
        for (OWNED_ROW_INDICES) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, self.tree_index);
            const count = treeGeometryColumns(placement.geometry, self.tree_index);
            const size = try traceSize(placement.geometry.log_size);
            for (self.columns[offset..][0..count]) |column|
                if (column.len != size) return error.ManifestMismatch;
        }
    }
};

pub fn deriveTranscriptPrepared(
    prepared: *const PreparedNativeV2LeafOuter,
) !transcript_source.PreparedV2 {
    return transcript_source.preflight(
        &prepared.transcript_program,
        &prepared.transcript_execution,
        &prepared.transcript_evidence,
        &prepared.vm_plan,
        prepared.pcs_config,
        &prepared.capture.public_data.data,
        prepared.capture.vm_air.component_descs,
        prepared.capture.vm_air.infra_descs,
    );
}

pub fn transcriptNativeInputs(
    prepared: *const PreparedNativeV2LeafOuter,
) transcript_components.NativeInputs {
    return .{
        .program = &prepared.transcript_program,
        .execution = &prepared.transcript_execution,
        .evidence = &prepared.transcript_evidence,
        .plan = &prepared.vm_plan,
        .pcs_config = prepared.pcs_config,
        .data = &prepared.capture.public_data.data,
        .component_descs = prepared.capture.vm_air.component_descs,
        .infra_descs = prepared.capture.vm_air.infra_descs,
    };
}

pub fn nativeRelations(
    prepared: *const PreparedNativeV2LeafOuter,
) native_relations_mod.Relations {
    return native_relations_mod.Relations.fromDrawSequence(
        &prepared.capture.vm_air.relation_draws,
    );
}

pub fn publicInputs(
    prepared: *const PreparedNativeV2LeafOuter,
    relations: *const native_relations_mod.Relations,
) public_source.InputsV2 {
    return .{
        .statement_source = &prepared.authority_prepared.source,
        .owned_public_data = &prepared.capture.public_data,
        .publication = &prepared.authority_prepared.public_logup,
        .native_public_sums = &prepared.capture.native_public_sums,
        .verified_receipt = &prepared.capture.receipt,
        .relations = relations,
        .component_descs = prepared.capture.vm_air.component_descs,
        .infra_descs = prepared.capture.vm_air.infra_descs,
        .vm_plan = &prepared.vm_plan,
    };
}

pub fn admittedBoundaryTraces(
    prepared: *const PreparedNativeV2LeafOuter,
) boundary_authority.TracesV2 {
    return .{
        .statement = .{
            .preprocessed = prepared.authority_traces.statement_preprocessed,
            .main = prepared.authority_traces.statement_main,
            .interaction = prepared.authority_traces.statement_interaction,
        },
        .public_logup = .{
            .preprocessed = prepared.authority_traces.public_logup_preprocessed,
            .main = prepared.authority_traces.public_logup_main,
            .interaction = prepared.authority_traces.public_logup_interaction,
        },
    };
}

pub fn fillRangePreprocessed(owner: anytype) !void {
    const placement = owner.manifest.placements[35].?;
    const offset: usize = placement.preprocessed_offset;
    const is_first = owner.tree0.columns[offset];
    if (is_first.len != range_bridge.TABLE_SIZE)
        return error.ManifestMismatch;
    var tuple_columns = [2][]M31{
        owner.tree0.columns[offset + 1],
        owner.tree0.columns[offset + 2],
    };
    try owner.range_owner.executor.generatePreprocessedInto(
        owner.range_prepared.provider(),
        &tuple_columns,
    );
    is_first[0] = M31.one();
}

pub fn fillRangeMain(owner: anytype) !void {
    const placement = owner.manifest.placements[35].?;
    const offset: usize = placement.main_offset;
    var columns = [1][]M31{owner.tree1.columns[offset]};
    try owner.range_owner.executor.generateMainInto(
        owner.range_prepared.provider(),
        &columns,
    );
}

pub fn copyRangeInteraction(
    tree: *SparseTree,
    manifest: *const Manifest,
    interaction: *const range_authority.ProviderInteractionV2,
) void {
    const placement = manifest.placements[35].?;
    for (interaction.columns(), 0..) |column, index|
        @memcpy(tree.columns[placement.interaction_offset + index], column);
}

pub fn copyBoundaryInteraction(
    tree: *SparseTree,
    manifest: *const Manifest,
    traces: *const leaf_outer.OwnedAuthorityTracesV2,
) void {
    const statement = manifest.placements[36].?;
    for (traces.statement_interaction, 0..) |column, index|
        @memcpy(tree.columns[statement.interaction_offset + index], column);
    const public_logup = manifest.placements[37].?;
    for (traces.public_logup_interaction, 0..) |column, index|
        @memcpy(tree.columns[public_logup.interaction_offset + index], column);
}

pub fn compareBoundaryCommittedColumns(
    rebuilt: *const leaf_outer.OwnedAuthorityTracesV2,
    admitted: *const leaf_outer.OwnedAuthorityTracesV2,
) !void {
    try compareBoundaryColumnSet(
        "statement",
        "preprocessed",
        &rebuilt.statement_preprocessed,
        &admitted.statement_preprocessed,
    );
    try compareBoundaryColumnSet(
        "statement",
        "main",
        &rebuilt.statement_main,
        &admitted.statement_main,
    );
    try compareBoundaryColumnSet(
        "public_logup",
        "preprocessed",
        &rebuilt.public_logup_preprocessed,
        &admitted.public_logup_preprocessed,
    );
    try compareBoundaryColumnSet(
        "public_logup",
        "main",
        &rebuilt.public_logup_main,
        &admitted.public_logup_main,
    );
}

pub fn compareInputProviderCommittedColumns(
    rebuilt: *const OwnedInputProviderTraces,
    admitted: *const OwnedInputProviderTraces,
) !void {
    try compareBoundaryColumnSet(
        "verifier_input_provider",
        "preprocessed",
        &rebuilt.preprocessed,
        &admitted.preprocessed,
    );
    try compareBoundaryColumnSet(
        "verifier_input_provider",
        "main",
        &rebuilt.main,
        &admitted.main,
    );
}

fn compareBoundaryColumnSet(
    component: []const u8,
    tree: []const u8,
    rebuilt: []const []M31,
    admitted: []const []M31,
) !void {
    if (rebuilt.len != admitted.len) {
        reportBoundaryMismatch(component, tree, null, null, rebuilt, admitted);
        return error.BoundaryCommittedTraceMismatch;
    }
    for (rebuilt, admitted, 0..) |left, right, column| {
        if (left.len != right.len) {
            reportBoundaryMismatch(component, tree, column, null, rebuilt, admitted);
            return error.BoundaryCommittedTraceMismatch;
        }
        for (left, right, 0..) |left_word, right_word, row| {
            if (!left_word.eql(right_word)) {
                reportBoundaryMismatch(component, tree, column, row, rebuilt, admitted);
                std.debug.print(
                    "V2_NONCORE_BOUNDARY_WORD rebuilt={d} admitted={d}\n",
                    .{ left_word.toU32(), right_word.toU32() },
                );
                return error.BoundaryCommittedTraceMismatch;
            }
        }
    }
}

fn reportBoundaryMismatch(
    component: []const u8,
    tree: []const u8,
    column: ?usize,
    row: ?usize,
    rebuilt: []const []M31,
    admitted: []const []M31,
) void {
    const rebuilt_hash = boundaryColumnsIdentity(rebuilt);
    const admitted_hash = boundaryColumnsIdentity(admitted);
    const rebuilt_hex = std.fmt.bytesToHex(rebuilt_hash, .lower);
    const admitted_hex = std.fmt.bytesToHex(admitted_hash, .lower);
    std.debug.print(
        "\nV2_NONCORE_BOUNDARY_MISMATCH component={s} tree={s} " ++
            "column={any} row={any} rebuilt_hash={s} admitted_hash={s}\n",
        .{
            component,
            tree,
            column,
            row,
            &rebuilt_hex,
            &admitted_hex,
        },
    );
}

fn boundaryColumnsIdentity(columns: []const []M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/segment-v2-boundary-columns/diagnostic/v1\x00");
    hashInt(&hash, u32, columns.len);
    for (columns) |column| {
        hashInt(&hash, u64, column.len);
        for (column) |word| hashInt(&hash, u32, word.toU32());
    }
    return hash.finalResult();
}

pub fn initStageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nV2_NONCORE_OWNER_INIT_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

pub fn publishSparseTree(
    source: *const SparseTree,
    manifest: *const Manifest,
    destination: []const []M31,
) !void {
    const expected = treeColumnCount(manifest, source.tree_index) orelse
        return error.ManifestMismatch;
    if (destination.len != expected)
        return error.DestinationColumnCountMismatch;
    for (OWNED_ROW_INDICES) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, source.tree_index);
        const count = treeGeometryColumns(placement.geometry, source.tree_index);
        const size = try traceSize(placement.geometry.log_size);
        for (destination[offset..][0..count], offset..) |target, target_index| {
            if (target.len != size) return error.DestinationLogSizeMismatch;
            for (target) |value| if (!value.isZero())
                return error.DestinationNotFresh;
            if (overlap(
                std.mem.sliceAsBytes(target),
                std.mem.sliceAsBytes(source.storage),
            )) return error.AliasedDestination;
            for (destination, 0..) |other, other_index| {
                if (target_index != other_index and overlap(
                    std.mem.sliceAsBytes(target),
                    std.mem.sliceAsBytes(other),
                )) return error.AliasedDestination;
            }
        }
    }
    for (OWNED_ROW_INDICES) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, source.tree_index);
        const count = treeGeometryColumns(placement.geometry, source.tree_index);
        for (
            source.columns[offset..][0..count],
            destination[offset..][0..count],
        ) |from, to| @memcpy(to, from);
    }
}

pub fn ownerIdentity(owner: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&owner.manifest.seal);
    hash.update(&owner.prepared_leaf.identity);
    hash.update(&owner.prepared_leaf.authority_trace_id);
    for (owner.transcript_prepared.source_id) |word| hashInt(&hash, u32, word);
    for (owner.statement_prepared.identity) |word| hashInt(&hash, u32, word);
    for (owner.public_prepared.source_id) |word| hashInt(&hash, u32, word);
    hash.update(&owner.public_native_sum_source.authority_digest);
    hash.update(&owner.range_prepared.source_authority_digest);
    hash.update(&owner.input_provider_owner.source_authority_sha_id);
    return hash.finalResult();
}

pub fn generatedIdentity(value: *const GeneratedInteractionsV2) [32]u8 {
    return contract.generatedIdentity(value);
}

pub fn shaWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}

fn treeColumnCount(manifest: *const Manifest, tree: usize) ?usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => null,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn hashQM31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}

pub fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |index| result |= componentBit(index);
    return result;
}
