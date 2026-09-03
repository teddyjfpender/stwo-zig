//! Internal recursion air composition circuit authority shard; use recursion_air_composition_circuit.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const circle = stwo_core.circle;
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const qm31 = stwo_core.fields.qm31;
pub const verifier_types = stwo_core.verifier_types;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const graph_mod = @import("air/composition_circuit.zig");
pub const recorder = @import("air/composition_graph_recorder.zig");
pub const manifest_mod = @import("air/universal_adapter_manifest.zig");
pub const roster = @import("air/universal_roster.zig");
pub const shared_provider = @import("air/universal_shared_provider.zig");
pub const shared_provider_composition = @import("air/universal_shared_provider_composition.zig");
pub const statement_input = @import("air/statement_input.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
pub const span_statement = @import("span_statement.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const CIRCUIT_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-composition-circuit/v2\x00";
pub const TREE_COUNT: usize = manifest_mod.TREE_COUNT + 1;
pub const COMPOSITION_TREE_INDEX: usize = 3;
pub const ROSTER_CLAIM_COUNT: usize = roster.COMPONENT_COUNT;
pub const POSEIDON_AUX_START: usize = ROSTER_CLAIM_COUNT;
pub const COMPOSITION_CLAIM_INPUT_COUNT: usize =
    ROSTER_CLAIM_COUNT + shared_provider_composition.POSEIDON_AUXILIARY_CLAIM_COUNT;
pub const RELATION_CHALLENGE_COUNT: usize = universal.RELATION_COUNT;
pub const STATEMENT_WORD_COUNT: usize = statement_input.CANONICAL_WORD_COUNT;

comptime {
    if (TREE_COUNT != 4 or COMPOSITION_TREE_INDEX != 3 or
        ROSTER_CLAIM_COUNT != 36 or POSEIDON_AUX_START != 36 or
        COMPOSITION_CLAIM_INPUT_COUNT != 38 or RELATION_CHALLENGE_COUNT != 47 or
        STATEMENT_WORD_COUNT != span_statement.SPAN_STATEMENT_CANONICAL_WORDS)
    {
        @compileError("binary recursion composition protocol geometry drifted");
    }
}

pub const Error = std.mem.Allocator.Error || graph_mod.Error ||
    recorder.Error || manifest_mod.Error || shared_provider.Error ||
    shared_provider_composition.Error || universal.Error || M31.Error || error{
    ArithmeticOverflow,
    BindingCountMismatch,
    CircuitAlreadyFinished,
    CircuitIdentityMismatch,
    CircuitTooLarge,
    ComponentGeometryMismatch,
    ComponentOrderMismatch,
    ComponentProgramSealMismatch,
    IncompleteProofKindProgram,
    InvalidCaptureShape,
    InvalidCompositionGeometry,
    InvalidInputShape,
    InvalidManifest,
    InvalidSampleGeometry,
    InvalidTraceLogGeometry,
    ProviderRequiresExactRecorder,
};

pub const ProgramStatistics = struct {
    constraints_per_kind: [3]usize,
    roster_rows_per_kind: [3]u8,
    sampled_values: usize,
    graph_inputs: usize,
    graph_nodes: usize,
    composition_log_size: u32,
    composition_log_split: u32,
    quotient_max_log_degree_bound: u32,
    fri_log_blowup: u32,
};

/// All concrete values are verifier-owned.  `sampled_values`, randomness, and
/// the OODS seed come from a transactionally published `VerifiedProofCapture`;
/// claims and challenges come from the already successful outer transcript.
pub const Witness = struct {
    parent_binary_selector: bool,
    child_kind: graph_mod.ProofKind,
    statement_words: *const [STATEMENT_WORD_COUNT]M31,
    sampled_values: []const QM31,
    claimed_sums: *const [ROSTER_CLAIM_COUNT]QM31,
    poseidon2_partials: *const [shared_provider_composition.POSEIDON_AUXILIARY_CLAIM_COUNT]QM31,
    relations: *const universal.UniversalRelations,
    composition_randomness: QM31,
    oods_seed: QM31,
};

/// Owned graph product suitable for transactional attachment to a successful
/// outer verification receipt.  Evaluation is allocation-free with two
/// caller-owned scratch slices.
pub const Circuit = struct {
    allocator: std.mem.Allocator,
    recorded: recorder.Circuit,
    bindings: []graph_mod.RecursionInputBinding,
    input_profile: graph_mod.InputProfile,
    manifest_seal: [32]u8,
    statistics: ProgramStatistics,
    identity_digest: [Sha256.digest_length]u8,

    pub fn deinit(self: *Circuit) void {
        self.allocator.free(self.bindings);
        self.recorded.deinit();
        self.* = undefined;
    }

    pub fn graph(self: *const Circuit) graph_mod.CircuitGraph {
        return self.recorded.graph();
    }

    pub fn lane(
        self: *const Circuit,
        verifier_id: u32,
        circuit_id: u32,
        statement_scope: u32,
    ) graph_mod.RecursionLane {
        return .{
            .verifier_id = verifier_id,
            .circuit_id = circuit_id,
            .statement_scope = statement_scope,
            .graph = self.graph(),
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }

    pub fn validate(self: *const Circuit) Error!void {
        try self.recorded.validate();
        if (self.input_profile.claimed_sum_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.input_profile.relation_challenge_count != RELATION_CHALLENGE_COUNT or
            self.input_profile.public_wire_boundary_count != 0 or
            self.bindings.len != self.recorded.input_count or
            self.bindings.len != try graph_mod.recursionInputCount(self.input_profile) or
            self.statistics.graph_inputs != self.recorded.input_count or
            self.statistics.graph_nodes != self.recorded.nodes.len or
            self.statistics.sampled_values != self.input_profile.sampled_value_count)
        {
            return error.CircuitIdentityMismatch;
        }
        for (self.bindings, 0..) |binding, index| {
            const expected = graph_mod.expectedRecursionSource(
                self.input_profile,
                index,
            ) orelse return error.BindingCountMismatch;
            if (binding.node_id != index or !std.meta.eql(binding.source, expected))
                return error.BindingCountMismatch;
        }
        for (self.statistics.roster_rows_per_kind) |count|
            if (count != ROSTER_CLAIM_COUNT)
                return error.IncompleteProofKindProgram;
        for (self.statistics.constraints_per_kind) |count|
            if (count == 0) return error.IncompleteProofKindProgram;
        if (allZero(&self.manifest_seal) or
            !std.mem.eql(u8, &self.identity_digest, &circuitDigest(self)))
        {
            return error.CircuitIdentityMismatch;
        }
    }

    /// Writes graph inputs in the exact authenticated row-18 source order.
    /// Preflight completes before the first destination write.
    pub fn writeInputs(
        self: *const Circuit,
        witness: Witness,
        destination: []QM31,
    ) Error!void {
        try self.validate();
        try witness.relations.validate();
        if (destination.len != self.recorded.input_count or
            witness.sampled_values.len != self.input_profile.sampled_value_count)
        {
            return error.InvalidInputShape;
        }

        for (self.bindings, 0..) |binding, index| {
            const word = switch (binding.source) {
                .parent_binary_selector => M31.fromCanonical(
                    @intFromBool(witness.parent_binary_selector),
                ),
                .child_kind_selector => |kind| M31.fromCanonical(@intFromBool(
                    witness.parent_binary_selector and witness.child_kind == kind,
                )),
                .statement_word => |word_index| witness.statement_words[word_index],
                .sampled_value => |coordinate| try secureWord(
                    witness.sampled_values,
                    coordinate.item_index,
                    coordinate.word_index,
                ),
                .claimed_sum => |coordinate| blk: {
                    if (coordinate.item_index < ROSTER_CLAIM_COUNT) {
                        break :blk try secureWord(
                            witness.claimed_sums,
                            coordinate.item_index,
                            coordinate.word_index,
                        );
                    }
                    const auxiliary_index = coordinate.item_index - POSEIDON_AUX_START;
                    break :blk try secureWord(
                        witness.poseidon2_partials,
                        @intCast(auxiliary_index),
                        coordinate.word_index,
                    );
                },
                .relation_challenge => |coordinate| blk: {
                    if (coordinate.challenge >= RELATION_CHALLENGE_COUNT or
                        coordinate.word_index >= graph_mod.RELATION_CHALLENGE_WORD_COUNT)
                    {
                        return error.InvalidInputShape;
                    }
                    const element = witness.relations.elements[coordinate.challenge];
                    const value = if (coordinate.word_index < 4)
                        element.z
                    else
                        element.alpha;
                    break :blk value.toM31Array()[coordinate.word_index % 4];
                },
                .composition_randomness => |word_index| try secureValueWord(
                    witness.composition_randomness,
                    word_index,
                ),
                .oods_point => |word_index| try secureValueWord(
                    witness.oods_seed,
                    word_index,
                ),
                .public_wire_boundary, .transcript_claimed_sum => return error.InvalidInputShape,
            };
            destination[index] = QM31.fromBase(word);
        }
    }

    pub fn evaluateInto(
        self: *const Circuit,
        witness: Witness,
        input_scratch: []QM31,
        node_scratch: []QM31,
    ) Error!void {
        try self.writeInputs(witness, input_scratch);
        try self.recorded.evaluateInto(input_scratch, node_scratch);
    }
};

pub const KindState = struct {
    next_row: u8 = 0,
    constraint_count: usize = 0,
    accumulation: recorder.Scalar = recorder.Scalar.zero(),
};

pub fn advanceProviderState(state: *KindState, recorded_count: usize) Error!void {
    state.constraint_count = std.math.add(
        usize,
        state.constraint_count,
        recorded_count,
    ) catch return error.CircuitTooLarge;
    state.next_row += 1;
}

pub const CaptureLayout = struct {
    allocator: std.mem.Allocator,
    offsets: [TREE_COUNT][]usize,
    composition_log_size: u32,
    composition_log_split: u32,
    quotient_max_log_degree_bound: u32,
    fri_log_blowup: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        capture: anytype,
    ) Error!CaptureLayout {
        if (capture.sampled_points.len != TREE_COUNT or
            capture.column_log_sizes.len != TREE_COUNT)
        {
            return error.InvalidCaptureShape;
        }
        const composition_columns = capture.sampled_points[COMPOSITION_TREE_INDEX].len;
        if (composition_columns == 0 or
            composition_columns % qm31.SECURE_EXTENSION_DEGREE != 0)
        {
            return error.InvalidCompositionGeometry;
        }
        const chunk_count = composition_columns / qm31.SECURE_EXTENSION_DEGREE;
        if (!std.math.isPowerOfTwo(chunk_count))
            return error.InvalidCompositionGeometry;
        const split: u32 = @intCast(std.math.log2_int(usize, chunk_count));
        const expected_composition_columns = verifier_types.compositionColumnCount(
            split,
            qm31.SECURE_EXTENSION_DEGREE,
        ) orelse return error.InvalidCompositionGeometry;
        if (split != verifier_types.COMPOSITION_LOG_SPLIT or
            composition_columns != expected_composition_columns)
        {
            return error.InvalidCompositionGeometry;
        }

        var composition_log_size: u32 = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const geometry = manifest.placements[row].?.geometry;
            const degree_minus_one: u32 = geometry.protocol_constraint_degree - 1;
            const quotient_blowup: u32 = @max(
                1,
                std.math.log2_int_ceil(u32, degree_minus_one),
            );
            composition_log_size = @max(
                composition_log_size,
                std.math.add(u32, geometry.log_size, quotient_blowup) catch
                    return error.ArithmeticOverflow,
            );
        }
        if (composition_log_size <= split)
            return error.InvalidCompositionGeometry;
        const quotient_bound = composition_log_size - split;

        const expected_columns = [TREE_COUNT]usize{
            @intCast(manifest.total_preprocessed_columns),
            @intCast(manifest.total_main_columns),
            @intCast(manifest.total_interaction_columns),
            expected_composition_columns,
        };
        for (capture.sampled_points, capture.column_log_sizes, expected_columns) |
            points,
            logs,
            expected,
        | if (points.len != expected or logs.len != expected)
            return error.InvalidSampleGeometry;

        const fri_log_blowup = try deriveFriLogBlowup(manifest, capture.column_log_sizes);
        try validateColumnLogs(
            manifest,
            capture.column_log_sizes,
            quotient_bound,
            fri_log_blowup,
        );

        var offsets: [TREE_COUNT][]usize = undefined;
        var initialized: usize = 0;
        errdefer for (offsets[0..initialized]) |tree| allocator.free(tree);
        var value_cursor: usize = 0;
        for (capture.sampled_points, &offsets, 0..) |tree, *tree_offsets, tree_index| {
            tree_offsets.* = try allocator.alloc(usize, tree.len + 1);
            initialized += 1;
            for (tree, 0..) |column, column_index| {
                const expected_samples = try expectedSampleCount(
                    manifest,
                    tree_index,
                    column_index,
                );
                if (column.len != expected_samples)
                    return error.InvalidSampleGeometry;
                tree_offsets.*[column_index] = value_cursor;
                value_cursor = std.math.add(
                    usize,
                    value_cursor,
                    column.len,
                ) catch return error.ArithmeticOverflow;
            }
            tree_offsets.*[tree.len] = value_cursor;
        }
        if (value_cursor != capture.sampled_values.len)
            return error.InvalidSampleGeometry;
        return .{
            .allocator = allocator,
            .offsets = offsets,
            .composition_log_size = composition_log_size,
            .composition_log_split = split,
            .quotient_max_log_degree_bound = quotient_bound,
            .fri_log_blowup = fri_log_blowup,
        };
    }

    pub fn deinit(self: *CaptureLayout) void {
        for (self.offsets) |tree| self.allocator.free(tree);
        self.* = undefined;
    }

    pub fn at(
        self: *const CaptureLayout,
        values: []const recorder.Scalar,
        tree: usize,
        column: usize,
        sample: usize,
    ) Error!recorder.Scalar {
        if (tree >= TREE_COUNT or column + 1 >= self.offsets[tree].len)
            return error.InvalidSampleGeometry;
        const start = self.offsets[tree][column];
        const end = self.offsets[tree][column + 1];
        if (sample >= end - start or start + sample >= values.len)
            return error.InvalidSampleGeometry;
        return values[start + sample];
    }
};

pub fn expectedSampleCount(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    column: usize,
) Error!usize {
    if (tree != manifest_mod.INTERACTION_TREE_INDEX) return 1;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = @intCast(placement.interaction_offset);
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == @intFromEnum(roster.Component.poseidon2)) return 2;
            const final_start = end - 4;
            return if (column >= final_start) 2 else 1;
        }
    }
    return error.InvalidSampleGeometry;
}

pub fn deriveFriLogBlowup(
    manifest: *const manifest_mod.Manifest,
    logs: anytype,
) Error!u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const candidates = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (candidates) |candidate| {
            if (candidate.count == 0) continue;
            const observed = logs[candidate.tree][candidate.start];
            if (observed < geometry.log_size)
                return error.InvalidTraceLogGeometry;
            return observed - geometry.log_size;
        }
    }
    return error.InvalidTraceLogGeometry;
}

pub fn validateColumnLogs(
    manifest: *const manifest_mod.Manifest,
    logs: anytype,
    composition_chunk_log_size: u32,
    fri_log_blowup: u32,
) Error!void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        const expected = std.math.add(
            u32,
            geometry.log_size,
            fri_log_blowup,
        ) catch return error.ArithmeticOverflow;
        const ranges = [_]struct { tree: usize, start: u32, count: u16 }{
            .{ .tree = manifest_mod.PREPROCESSED_TREE_INDEX, .start = placement.preprocessed_offset, .count = geometry.preprocessed_columns },
            .{ .tree = manifest_mod.MAIN_TREE_INDEX, .start = placement.main_offset, .count = geometry.main_columns },
            .{ .tree = manifest_mod.INTERACTION_TREE_INDEX, .start = placement.interaction_offset, .count = geometry.interaction_columns },
        };
        for (ranges) |range| {
            for (logs[range.tree][range.start..][0..range.count]) |actual|
                if (actual != expected) return error.InvalidTraceLogGeometry;
        }
    }
    const expected_composition = std.math.add(
        u32,
        composition_chunk_log_size,
        fri_log_blowup,
    ) catch return error.ArithmeticOverflow;
    for (logs[COMPOSITION_TREE_INDEX]) |actual|
        if (actual != expected_composition)
            return error.InvalidTraceLogGeometry;
}

pub fn takeSecure(inputs: []const recorder.Scalar, cursor: *usize) recorder.Scalar {
    var words: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar = undefined;
    @memcpy(&words, inputs[cursor.*..][0..qm31.SECURE_EXTENSION_DEGREE]);
    cursor.* += qm31.SECURE_EXTENSION_DEGREE;
    return recorder.fromPartialEvals(words);
}

pub fn secureWord(values: anytype, item: u32, word: u32) Error!M31 {
    if (item >= values.len or word >= qm31.SECURE_EXTENSION_DEGREE)
        return error.InvalidInputShape;
    return values[item].toM31Array()[word];
}

pub fn secureValueWord(value: QM31, word: u32) Error!M31 {
    if (word >= qm31.SECURE_EXTENSION_DEGREE)
        return error.InvalidInputShape;
    return value.toM31Array()[word];
}

pub fn circuitDigest(circuit: *const Circuit) [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update(CIRCUIT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&circuit.manifest_seal);
    hash.update(&circuit.recorded.identity_digest);
    hashInt(&hash, u32, circuit.input_profile.sampled_value_count);
    hashInt(&hash, u32, circuit.input_profile.claimed_sum_count);
    hashInt(&hash, u32, circuit.input_profile.relation_challenge_count);
    for (circuit.statistics.constraints_per_kind) |count|
        hashInt(&hash, u64, @intCast(count));
    for (circuit.statistics.roster_rows_per_kind) |count|
        hashInt(&hash, u8, count);
    hashInt(&hash, u64, @intCast(circuit.statistics.sampled_values));
    hashInt(&hash, u64, @intCast(circuit.statistics.graph_inputs));
    hashInt(&hash, u64, @intCast(circuit.statistics.graph_nodes));
    hashInt(&hash, u32, circuit.statistics.composition_log_size);
    hashInt(&hash, u32, circuit.statistics.composition_log_split);
    hashInt(&hash, u32, circuit.statistics.quotient_max_log_degree_bound);
    hashInt(&hash, u32, circuit.statistics.fri_log_blowup);
    return hash.finalResult();
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn allZero(value: []const u8) bool {
    var accumulator: u8 = 0;
    for (value) |byte| accumulator |= byte;
    return accumulator == 0;
}
