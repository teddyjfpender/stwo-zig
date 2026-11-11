//! Coverage and shape validation for an admitted Cairo arena schedule.

const std = @import("std");
const stwo = @import("stwo");
const composition_bundle_mod = stwo.frontends.cairo.witness.composition_bundle;
const fixed_table_bundle_mod = stwo.frontends.cairo.witness.fixed_table_bundle;
const relation_bundle_mod = stwo.frontends.cairo.witness.relation_bundle;

pub const RelationCoverage = struct {
    instances: usize,
    output_buffers: usize,
    output_bytes: u64,
    scan_scratch_bytes: u64,
};
pub const PreprocessedCoverage = struct { sources: []?u32, buffers: usize, bytes: u64 };
pub const FixedTableCoverage = struct { components: usize, lookup_buffers: usize, lookup_bytes: u64 };
pub const MerkleParentCoverage = struct { sources: []?u32, buffers: usize, bytes: u64, chains: usize };
pub const MerkleCommitCoverage = struct { bottoms: []bool, commitments: usize, buffers: usize, bytes: u64 };
pub const EcOpCoverage = struct { rows: u64, output_buffers: usize, output_bytes: u64 };
pub const CompositionCoverage = struct { components: usize, parts: usize, output_buffers: usize, output_bytes: u64 };
const Coefficient = struct { id: u32, words: u64 };
const RetainedDestination = struct { id: u32, words: u64 };
const RetentionCandidate = struct {
    tree: usize,
    group: usize,
    words: u64,
    weighted_log: u128,
};
const ScheduledColumn = struct { ordinal: u32, words: u64 };
const ScheduledGroup = struct { start: usize, len: usize, rows: u64 };

pub fn buildPreprocessedSources(allocator: std.mem.Allocator, schedule: []const std.json.Value) !PreprocessedCoverage {
    const sources = try allocator.alloc(?u32, schedule.len);
    errdefer allocator.free(sources);
    @memset(sources, null);
    var buffers: usize = 0;
    var bytes: u64 = 0;
    var inverse_twiddle_words: u64 = 0;
    for (schedule) |entry| {
        const object = entry.object;
        if (std.mem.eql(u8, object.get("purpose").?.string, "PreprocessedInverseTwiddles")) {
            inverse_twiddle_words = @max(inverse_twiddle_words, @as(u64, @intCast(object.get("len_words").?.integer)));
        }
    }
    for (schedule) |coefficient_entry| {
        const coefficient = coefficient_entry.object;
        if (!std.mem.eql(u8, coefficient.get("purpose").?.string, "PreprocessedCoefficients")) continue;
        const coefficient_id: u32 = @intCast(coefficient.get("id").?.integer);
        if (coefficient_id >= sources.len) return error.InvalidLogicalId;
        const ordinal = coefficient.get("ordinal").?.integer;
        const words: u64 = @intCast(coefficient.get("len_words").?.integer);
        var matched: ?u32 = null;
        for (schedule) |evaluation_entry| {
            const evaluation = evaluation_entry.object;
            if (!std.mem.eql(u8, evaluation.get("purpose").?.string, "PreprocessedEvaluations") or
                evaluation.get("ordinal").?.integer != ordinal or evaluation.get("len_words").?.integer != words)
                continue;
            if (matched != null) return error.DuplicatePreprocessedEvaluation;
            matched = @intCast(evaluation.get("id").?.integer);
        }
        if (matched) |source_id| {
            if (!std.math.isPowerOfTwo(words) or words < 8 or inverse_twiddle_words < words / 2)
                return error.PreprocessedTransformShapeMismatch;
            sources[coefficient_id] = source_id;
            buffers += 1;
            bytes += words * 4;
        }
    }
    return .{ .sources = sources, .buffers = buffers, .bytes = bytes };
}

pub fn validateFixedTableCoverage(
    schedule: []const std.json.Value,
    bundle: fixed_table_bundle_mod.Bundle,
    destinations: *std.StringHashMap(void),
) !FixedTableCoverage {
    var preprocessed_coefficients: usize = 0;
    var scheduled_components: usize = 0;
    var components: usize = 0;
    var lookup_buffers: usize = 0;
    var lookup_bytes: u64 = 0;
    for (bundle.entries) |entry| {
        const lookup = findScheduled(schedule, "LookupInputs", entry.component, null) orelse continue;
        const lookup_words: u64 = @intCast(lookup.get("len_words").?.integer);
        if (lookup_words != @as(u64, entry.row_count) * entry.lookupCount()) return error.FixedTableShapeMismatch;
        const multiplicity = findScheduled(schedule, "FixedMultiplicity", entry.component, null) orelse return error.FixedTableShapeMismatch;
        if (multiplicity.get("len_words").?.integer != @as(i64, entry.row_count) * entry.multiplicity_columns)
            return error.FixedTableShapeMismatch;
        var trace_columns: usize = 0;
        for (schedule) |scheduled| {
            const object = scheduled.object;
            if (std.mem.eql(u8, object.get("purpose").?.string, "BaseTrace") and
                object.get("component") != null and object.get("component").? == .string and
                std.mem.eql(u8, object.get("component").?.string, entry.component))
            {
                if (object.get("len_words").?.integer != entry.row_count) return error.FixedTableShapeMismatch;
                trace_columns += 1;
            }
        }
        if (trace_columns != entry.trace_multiplicity_columns.len) return error.FixedTableShapeMismatch;
        for (entry.preprocessed_sources) |identity| {
            const ordinal = bundle.identityOrdinal(identity) orelse return error.FixedTableIdentityMismatch;
            const evaluation = findScheduled(schedule, "PreprocessedEvaluations", null, ordinal) orelse return error.FixedTableIdentityMismatch;
            if (evaluation.get("len_words").?.integer != entry.row_count) return error.FixedTableIdentityMismatch;
        }
        const descriptor = findScheduled(schedule, "FixedTableLookupDescriptors", entry.component, null) orelse return error.FixedTableShapeMismatch;
        const source_pointers = findScheduled(schedule, "FixedTableSourcePointers", entry.component, null);
        const multiplicity_pointers = findScheduled(schedule, "FixedTableMultiplicityPointers", entry.component, null) orelse return error.FixedTableShapeMismatch;
        const output_pointers = findScheduled(schedule, "FixedTableLookupOutputPointers", entry.component, null) orelse return error.FixedTableShapeMismatch;
        if (descriptor.get("len_words").?.integer != entry.lookup_descriptors.len or
            multiplicity_pointers.get("len_words").?.integer != @as(i64, entry.multiplicity_columns) * 2 or
            output_pointers.get("len_words").?.integer != @as(i64, @intCast(entry.lookupCount())) * 2 or
            (entry.preprocessed_sources.len == 0 and source_pointers != null) or
            (entry.preprocessed_sources.len != 0 and (source_pointers == null or
                source_pointers.?.get("len_words").?.integer != @as(i64, @intCast(entry.preprocessed_sources.len)) * 2)))
            return error.FixedTableShapeMismatch;
        try destinations.put(entry.component, {});
        components += 1;
        lookup_buffers += 1;
        lookup_bytes += lookup_words * 4;
    }
    for (schedule) |scheduled| {
        const object = scheduled.object;
        const purpose = object.get("purpose").?.string;
        if (std.mem.eql(u8, purpose, "PreprocessedCoefficients")) {
            preprocessed_coefficients += 1;
            continue;
        }
        if (!std.mem.eql(u8, purpose, "FixedTableLookupDescriptors")) continue;
        const component = object.get("component") orelse return error.FixedTableCoverageMismatch;
        if (component != .string or bundle.find(component.string) == null)
            return error.FixedTableCoverageMismatch;
        scheduled_components += 1;
    }
    const entries_complete = switch (bundle.format_version) {
        fixed_table_bundle_mod.version => true,
        fixed_table_bundle_mod.projected_version => components == bundle.entries.len,
        else => return error.UnsupportedVersion,
    };
    if (!entries_complete or components == 0 or lookup_buffers != components or
        scheduled_components != components or
        preprocessed_coefficients != bundle.preprocessed_identities.len)
        return error.FixedTableCoverageMismatch;
    return .{ .components = components, .lookup_buffers = lookup_buffers, .lookup_bytes = lookup_bytes };
}

pub fn buildMerkleParentSources(allocator: std.mem.Allocator, schedule: []const std.json.Value) !MerkleParentCoverage {
    const sources = try allocator.alloc(?u32, schedule.len);
    errdefer allocator.free(sources);
    @memset(sources, null);
    var buffers: usize = 0;
    var bytes: u64 = 0;
    var chains: usize = 0;
    var previous: ?std.json.ObjectMap = null;
    for (schedule) |entry| {
        const object = entry.object;
        const purpose = object.get("purpose").?.string;
        if (!std.mem.eql(u8, purpose, "RetainedMerkleLayers") and !std.mem.eql(u8, purpose, "FriMerkleLayer")) continue;
        const words: u64 = @intCast(object.get("len_words").?.integer);
        var chained = false;
        if (previous) |parent_source| {
            chained = std.mem.eql(u8, parent_source.get("purpose").?.string, purpose) and
                std.mem.eql(u8, parent_source.get("first").?.string, object.get("first").?.string) and
                std.mem.eql(u8, parent_source.get("last").?.string, object.get("last").?.string) and
                @as(u64, @intCast(parent_source.get("len_words").?.integer)) == words * 2;
            if (chained) {
                const id: u32 = @intCast(object.get("id").?.integer);
                if (id >= sources.len) return error.InvalidLogicalId;
                sources[id] = @intCast(parent_source.get("id").?.integer);
                buffers += 1;
                bytes += words * 4;
            }
        }
        if (!chained) chains += 1;
        previous = object;
    }
    return .{ .sources = sources, .buffers = buffers, .bytes = bytes, .chains = chains };
}

pub fn buildMerkleCommitCoverage(allocator: std.mem.Allocator, schedule: []const std.json.Value) !MerkleCommitCoverage {
    const bottoms = try allocator.alloc(bool, schedule.len);
    errdefer allocator.free(bottoms);
    @memset(bottoms, false);
    var commitments: usize = 0;
    var buffers: usize = 0;
    var bytes: u64 = 0;
    var previous: ?std.json.ObjectMap = null;
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, "RetainedMerkleLayers")) continue;
        const words: u64 = @intCast(object.get("len_words").?.integer);
        const chained = if (previous) |child|
            std.mem.eql(u8, child.get("first").?.string, object.get("first").?.string) and
                std.mem.eql(u8, child.get("last").?.string, object.get("last").?.string) and
                @as(u64, @intCast(child.get("len_words").?.integer)) == words * 2
        else
            false;
        previous = object;
        if (chained) continue;
        const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
        const commitment = ordinal >> 20;
        if (commitment > 3 or (ordinal & 0xfffff) != 3) return error.InvalidRetainedTree;
        const base = commitment << 20;
        const leaf = findScheduled(schedule, "MerkleLeafState", null, base + 1) orelse return error.InvalidRetainedTree;
        const parent = findScheduled(schedule, "MerkleLayerScratch", null, base + 2) orelse return error.InvalidRetainedTree;
        const leaf_words: u64 = @intCast(leaf.get("len_words").?.integer);
        const parent_words: u64 = @intCast(parent.get("len_words").?.integer);
        if (leaf_words != words * 16 or parent_words != leaf_words / 2) return error.InvalidRetainedShape;
        var evaluation_count: usize = 0;
        var maximum_evaluation_words: u64 = 0;
        for (schedule) |candidate_entry| {
            const candidate = candidate_entry.object;
            const candidate_purpose = candidate.get("purpose").?.string;
            const matches = if (commitment == 0)
                std.mem.eql(u8, candidate_purpose, "PreprocessedEvaluations")
            else
                std.mem.eql(u8, candidate_purpose, "CommitRetainedEvaluation") and
                    (@as(u32, @intCast(candidate.get("ordinal").?.integer)) >> 20) == commitment;
            if (!matches) continue;
            evaluation_count += 1;
            maximum_evaluation_words = @max(maximum_evaluation_words, @as(u64, @intCast(candidate.get("len_words").?.integer)));
        }
        if (evaluation_count == 0 and commitment != 0) {
            const coefficient_purpose = switch (commitment) {
                1 => "BaseCoefficients",
                2 => "InteractionCoefficients",
                3 => "CompositionCoefficients",
                else => unreachable,
            };
            for (schedule) |candidate_entry| {
                const candidate = candidate_entry.object;
                if (!std.mem.eql(u8, candidate.get("purpose").?.string, coefficient_purpose)) continue;
                evaluation_count += 1;
                maximum_evaluation_words = @max(
                    maximum_evaluation_words,
                    @as(u64, @intCast(candidate.get("len_words").?.integer)) * 2,
                );
            }
        }
        if (evaluation_count == 0 or maximum_evaluation_words * 8 > leaf_words or
            !std.math.isPowerOfTwo(leaf_words / (maximum_evaluation_words * 8)))
            return error.InvalidRetainedShape;
        const id: u32 = @intCast(object.get("id").?.integer);
        if (id >= bottoms.len) return error.InvalidLogicalId;
        bottoms[id] = true;
        commitments += 1;
        buffers += 1;
        bytes += words * 4;
    }
    if (commitments != 4) return error.InvalidRetainedTree;
    return .{ .bottoms = bottoms, .commitments = commitments, .buffers = buffers, .bytes = bytes };
}

pub fn validateEcOpCoverage(schedule: []const std.json.Value) !EcOpCoverage {
    var rows: u64 = 0;
    var trace_count: usize = 0;
    var trace_bytes: u64 = 0;
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, "BaseTrace")) continue;
        const component = object.get("component") orelse continue;
        if (component != .string or !std.mem.eql(u8, component.string, "ec_op_builtin")) continue;
        const words: u64 = @intCast(object.get("len_words").?.integer);
        if (rows == 0) rows = words else if (rows != words) return error.EcOpShapeMismatch;
        if (object.get("ordinal").?.integer != trace_count) return error.EcOpShapeMismatch;
        trace_count += 1;
        trace_bytes += words * 4;
    }
    if (trace_count == 0) {
        for (schedule) |entry| {
            const object = entry.object;
            const purpose = object.get("purpose").?.string;
            const component = object.get("component") orelse continue;
            if (component != .string) continue;
            const is_ec_component = std.mem.eql(u8, component.string, "ec_op_builtin") or
                std.mem.eql(u8, component.string, "partial_ec_mul_generic");
            const is_ec_purpose = std.mem.eql(u8, purpose, "EcOpPartialIota") or
                std.mem.eql(u8, purpose, "EcOpSegmentStart");
            if (is_ec_component or is_ec_purpose) return error.EcOpShapeMismatch;
        }
        return .{ .rows = 0, .output_buffers = 0, .output_bytes = 0 };
    }
    if (rows < 16 or !std.math.isPowerOfTwo(rows) or trace_count != 273) return error.EcOpShapeMismatch;
    const lookup = findScheduled(schedule, "LookupInputs", "ec_op_builtin", 0) orelse return error.EcOpShapeMismatch;
    if (lookup.get("len_words").?.integer != @as(i64, @intCast(rows * 488))) return error.EcOpShapeMismatch;
    var partial_count: usize = 0;
    var partial_bytes: u64 = 0;
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, "WitnessInput")) continue;
        const component = object.get("component") orelse continue;
        if (component != .string or !std.mem.eql(u8, component.string, "partial_ec_mul_generic")) continue;
        if (object.get("ordinal").?.integer != partial_count or object.get("len_words").?.integer != @as(i64, @intCast(rows * 256)))
            return error.EcOpShapeMismatch;
        partial_count += 1;
        partial_bytes += rows * 256 * 4;
    }
    if (partial_count != 126) return error.EcOpShapeMismatch;
    const iota = findScheduled(schedule, "EcOpPartialIota", "ec_op_builtin", 0) orelse return error.EcOpShapeMismatch;
    const segment = findScheduled(schedule, "EcOpSegmentStart", "ec_op_builtin", 0) orelse return error.EcOpShapeMismatch;
    if (iota.get("len_words").?.integer != @as(i64, @intCast(rows * 256)) or segment.get("len_words").?.integer != 1)
        return error.EcOpShapeMismatch;
    if (findScheduled(schedule, "ExecutionTableRawAddressToId", null, 0) == null) return error.EcOpShapeMismatch;
    for (0..28) |ordinal| if (findScheduled(schedule, "ExecutionTableBigLimb", null, @intCast(ordinal)) == null) return error.EcOpShapeMismatch;
    for (0..8) |ordinal| if (findScheduled(schedule, "ExecutionTableSmallLimb", null, @intCast(ordinal)) == null) return error.EcOpShapeMismatch;
    const address_counts = findScheduled(schedule, "RuntimeMultiplicity", "memory_address_to_id", 21) orelse return error.EcOpShapeMismatch;
    const big_counts = findScheduled(schedule, "RuntimeMultiplicity", "memory_id_to_big", 22) orelse return error.EcOpShapeMismatch;
    const small_counts = findScheduled(schedule, "RuntimeMultiplicity", "memory_id_to_big", 23) orelse return error.EcOpShapeMismatch;
    const range_counts = findScheduled(schedule, "FixedMultiplicity", "range_check_8", 0) orelse return error.EcOpShapeMismatch;
    if (address_counts.get("len_words").?.integer == 0 or big_counts.get("len_words").?.integer == 0 or
        small_counts.get("len_words").?.integer == 0 or range_counts.get("len_words").?.integer < 256)
        return error.EcOpShapeMismatch;
    const lookup_bytes = rows * 488 * 4;
    return .{
        .rows = rows,
        .output_buffers = trace_count + 1 + partial_count + 1,
        .output_bytes = trace_bytes + lookup_bytes + partial_bytes + rows * 256 * 4,
    };
}

pub fn validateCompositionCoverage(
    schedule: []const std.json.Value,
    bundle: composition_bundle_mod.Bundle,
) !CompositionCoverage {
    if (bundle.components.len == 0 or bundle.total_constraints == 0 or bundle.max_evaluation_log_size >= 31)
        return error.CompositionShapeMismatch;
    var tree_columns = [_]u32{ 0, 0, 0 };
    for (schedule) |entry| {
        const purpose = entry.object.get("purpose").?.string;
        if (std.mem.eql(u8, purpose, "PreprocessedCoefficients")) tree_columns[0] += 1;
        if (std.mem.eql(u8, purpose, "BaseCoefficients")) tree_columns[1] += 1;
        if (std.mem.eql(u8, purpose, "InteractionCoefficients")) tree_columns[2] += 1;
    }
    var parts: usize = 0;
    var accumulator_logs: u32 = 0;
    for (bundle.components, 0..) |component, component_index| {
        if (component.trace_spans.len != 3 or component.random_coefficient_offset >= bundle.total_constraints)
            return error.CompositionShapeMismatch;
        for (component.trace_spans) |span| if (span.end > tree_columns[span.tree]) return error.CompositionShapeMismatch;
        for (component.preprocessed_indices) |index| if (index >= tree_columns[0]) return error.CompositionShapeMismatch;
        const ext = findScheduled(schedule, "CompositionExtParams", null, @intCast(component_index)) orelse
            return error.CompositionShapeMismatch;
        if (ext.get("len_words").?.integer < component.ext_sources.len * 4) return error.CompositionShapeMismatch;
        parts += component.parts.len;
        accumulator_logs |= @as(u32, 1) << @intCast(component.evaluation_log_size);
    }
    var accumulator_words: u64 = 0;
    for (0..31) |log_size| {
        if (accumulator_logs & (@as(u32, 1) << @intCast(log_size)) != 0)
            accumulator_words += @as(u64, 4) << @intCast(log_size);
    }
    const accumulators = findScheduled(schedule, "CompositionAccumulators", null, 0) orelse return error.CompositionShapeMismatch;
    if (accumulators.get("len_words").?.integer != accumulator_words) return error.CompositionShapeMismatch;
    const powers = findScheduled(schedule, "CompositionRandomCoefficientPowers", null, 0) orelse return error.CompositionShapeMismatch;
    if (powers.get("len_words").?.integer != bundle.total_constraints * 4) return error.CompositionShapeMismatch;
    const forward = findScheduled(schedule, "ForwardTwiddles", null, 0) orelse return error.CompositionShapeMismatch;
    const inverse = findScheduled(schedule, "InverseTwiddles", null, 0) orelse return error.CompositionShapeMismatch;
    const required_twiddles = @as(u64, 1) << @intCast(bundle.max_evaluation_log_size - 1);
    if (forward.get("len_words").?.integer < required_twiddles or inverse.get("len_words").?.integer < required_twiddles)
        return error.CompositionShapeMismatch;
    const descriptors = findScheduled(schedule, "CompositionDescriptors", null, 0) orelse return error.CompositionShapeMismatch;
    const tile = findScheduled(schedule, "CompositionLdeTile", null, 0) orelse return error.CompositionShapeMismatch;
    if (descriptors.get("len_words").?.integer == 0 or tile.get("len_words").?.integer == 0)
        return error.CompositionShapeMismatch;
    var output_bytes: u64 = 0;
    const output_words = @as(u64, 1) << @intCast(bundle.max_evaluation_log_size - 1);
    for (0..8) |ordinal| {
        const output = findScheduled(schedule, "CompositionCoefficients", null, @intCast(ordinal)) orelse
            return error.CompositionShapeMismatch;
        if (output.get("len_words").?.integer != output_words) return error.CompositionShapeMismatch;
        output_bytes += output_words * 4;
    }
    return .{ .components = bundle.components.len, .parts = parts, .output_buffers = 8, .output_bytes = output_bytes };
}

fn findScheduled(
    schedule: []const std.json.Value,
    purpose: []const u8,
    component: ?[]const u8,
    ordinal: ?u32,
) ?std.json.ObjectMap {
    var result: ?std.json.ObjectMap = null;
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, purpose)) continue;
        if (component) |name| {
            const value = object.get("component") orelse continue;
            if (value != .string or !std.mem.eql(u8, value.string, name)) continue;
        }
        if (ordinal) |value| if (object.get("ordinal").?.integer != value) continue;
        if (result != null) return null;
        result = object;
    }
    return result;
}

pub fn buildRetainedSources(allocator: std.mem.Allocator, schedule: []const std.json.Value) ![]?u32 {
    const result = try allocator.alloc(?u32, schedule.len);
    errdefer allocator.free(result);
    @memset(result, null);
    var coefficients = [_]std.ArrayList(Coefficient){ .empty, .empty, .empty };
    defer for (&coefficients) |*list| list.deinit(allocator);
    var destinations = [_]std.ArrayList(RetainedDestination){ .empty, .empty, .empty };
    defer for (&destinations) |*list| list.deinit(allocator);

    for (schedule) |entry| {
        const object = entry.object;
        const purpose = object.get("purpose").?.string;
        const id: u32 = @intCast(object.get("id").?.integer);
        const words: u64 = @intCast(object.get("len_words").?.integer);
        const tree: ?usize = if (std.mem.eql(u8, purpose, "BaseCoefficients"))
            0
        else if (std.mem.eql(u8, purpose, "InteractionCoefficients"))
            1
        else if (std.mem.eql(u8, purpose, "CompositionCoefficients"))
            2
        else
            null;
        if (tree) |index| try coefficients[index].append(allocator, .{ .id = id, .words = words });
        if (std.mem.eql(u8, purpose, "CommitRetainedEvaluation")) {
            const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
            const commitment = ordinal >> 20;
            if (commitment < 1 or commitment > 3) return error.InvalidRetainedTree;
            try destinations[commitment - 1].append(allocator, .{ .id = id, .words = words });
        }
    }
    var destination_count: usize = 0;
    for (destinations) |list| destination_count += list.items.len;
    if (destination_count == 0) return result;
    for (&coefficients) |*list| std.mem.sortUnstable(Coefficient, list.items, {}, struct {
        fn lessThan(_: void, lhs: Coefficient, rhs: Coefficient) bool {
            if (lhs.words != rhs.words) return lhs.words < rhs.words;
            return lhs.id < rhs.id;
        }
    }.lessThan);

    var candidates = std.ArrayList(RetentionCandidate).empty;
    defer candidates.deinit(allocator);
    for (coefficients, 0..) |list, tree| {
        var group: usize = 0;
        while (group * 16 < list.items.len) : (group += 1) {
            const columns = list.items[group * 16 .. @min((group + 1) * 16, list.items.len)];
            var words: u64 = 0;
            var weighted_log: u128 = 0;
            for (columns) |column| {
                const output_words = std.math.mul(u64, column.words, 2) catch return error.SizeOverflow;
                if (!std.math.isPowerOfTwo(output_words)) return error.InvalidRetainedShape;
                words = std.math.add(u64, words, output_words) catch return error.SizeOverflow;
                weighted_log += @as(u128, output_words) * std.math.log2_int(u64, output_words);
            }
            try candidates.append(allocator, .{ .tree = tree, .group = group, .words = words, .weighted_log = weighted_log });
        }
    }
    std.mem.sortUnstable(RetentionCandidate, candidates.items, {}, struct {
        fn lessThan(_: void, lhs: RetentionCandidate, rhs: RetentionCandidate) bool {
            const left_score = rhs.weighted_log * @as(u128, lhs.words);
            const right_score = lhs.weighted_log * @as(u128, rhs.words);
            if (left_score != right_score) return right_score > left_score;
            if (lhs.words != rhs.words) return lhs.words < rhs.words;
            if (lhs.tree != rhs.tree) return lhs.tree < rhs.tree;
            return lhs.group < rhs.group;
        }
    }.lessThan);
    var selected = [_]std.DynamicBitSetUnmanaged{ .{}, .{}, .{} };
    defer for (&selected) |*bits| bits.deinit(allocator);
    for (&selected, coefficients) |*bits, list| bits.* = try std.DynamicBitSetUnmanaged.initEmpty(allocator, (list.items.len + 15) / 16);
    var remaining_words: u64 = (8 * 1024 * 1024 * 1024) / 4;
    for (candidates.items) |candidate| {
        if (candidate.words <= remaining_words) {
            selected[candidate.tree].set(candidate.group);
            remaining_words -= candidate.words;
        }
    }

    for (coefficients, destinations, selected) |sources, outputs, kept| {
        var output_index: usize = 0;
        var group: usize = 0;
        while (group * 16 < sources.items.len) : (group += 1) {
            if (!kept.isSet(group)) continue;
            const columns = sources.items[group * 16 .. @min((group + 1) * 16, sources.items.len)];
            for (columns) |source| {
                if (output_index >= outputs.items.len) return error.MissingRetainedDestination;
                const destination = outputs.items[output_index];
                if (destination.words != source.words * 2) {
                    std.log.err("retained mapping mismatch: source id={d} words={d}, destination id={d} words={d}", .{
                        source.id, source.words, destination.id, destination.words,
                    });
                    return error.InvalidRetainedShape;
                }
                result[destination.id] = source.id;
                output_index += 1;
            }
        }
        if (output_index != outputs.items.len) return error.ExtraRetainedDestination;
    }
    return result;
}

pub fn validateRelationCoverage(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    bundle: relation_bundle_mod.Bundle,
) !RelationCoverage {
    var source_pointer_words = std.ArrayList(u64).empty;
    defer source_pointer_words.deinit(allocator);
    var output_pointer_words = std.ArrayList(u64).empty;
    defer output_pointer_words.deinit(allocator);
    var denominator_words = std.ArrayList(u64).empty;
    defer denominator_words.deinit(allocator);
    var claimed_sums: usize = 0;
    var scheduled_output_buffers: usize = 0;
    for (schedule) |entry| {
        const object = entry.object;
        const purpose = object.get("purpose").?.string;
        const words: u64 = @intCast(object.get("len_words").?.integer);
        if (std.mem.eql(u8, purpose, "RelationSourcePointers")) try source_pointer_words.append(allocator, words);
        if (std.mem.eql(u8, purpose, "RelationOutputPointers")) try output_pointer_words.append(allocator, words);
        if (std.mem.eql(u8, purpose, "RelationDenominators")) try denominator_words.append(allocator, words);
        if (std.mem.eql(u8, purpose, "InteractionTrace")) scheduled_output_buffers += 1;
        if (std.mem.eql(u8, purpose, "RelationClaimedSum")) {
            if (words != 4) return error.RelationShapeMismatch;
            claimed_sums += 1;
        }
    }
    if (source_pointer_words.items.len != output_pointer_words.items.len or
        source_pointer_words.items.len != denominator_words.items.len or source_pointer_words.items.len != claimed_sums)
        return error.RelationShapeMismatch;

    var instance_index: usize = 0;
    var output_buffers: usize = 0;
    var output_bytes: u64 = 0;
    var scan_scratch_bytes: u64 = 0;
    for (bundle.components) |component| {
        var columns = std.ArrayList(ScheduledColumn).empty;
        defer columns.deinit(allocator);
        for (schedule) |entry| {
            const object = entry.object;
            if (!std.mem.eql(u8, object.get("purpose").?.string, "InteractionTrace")) continue;
            const component_value = object.get("component") orelse continue;
            const component_name = switch (component_value) {
                .string => |name| name,
                else => continue,
            };
            if (!std.mem.eql(u8, component_name, component.name)) continue;
            try columns.append(allocator, .{
                .ordinal = @intCast(object.get("ordinal").?.integer),
                .words = @intCast(object.get("len_words").?.integer),
            });
        }
        if (columns.items.len == 0) continue;
        var groups = std.ArrayList(ScheduledGroup).empty;
        defer groups.deinit(allocator);
        var start: usize = 0;
        while (start < columns.items.len) {
            if (columns.items[start].ordinal != 0) return error.RelationShapeMismatch;
            var end = start + 1;
            while (end < columns.items.len and columns.items[end].ordinal != 0) : (end += 1) {}
            const rows = columns.items[start].words;
            for (columns.items[start..end], 0..) |column, ordinal| {
                if (column.ordinal != ordinal or column.words != rows) return error.RelationShapeMismatch;
            }
            try groups.append(allocator, .{ .start = start, .len = end - start, .rows = rows });
            start = end;
        }

        var group_index: usize = 0;
        var component_scan_blocks: u64 = 0;
        for (component.traces, 0..) |trace, trace_index| {
            const remaining_fixed = countFixedTraces(component.traces[trace_index + 1 ..]);
            const trace_instances: usize = switch (trace.part) {
                .component, .memory_small => 1,
                .each_memory_big => groups.items.len - group_index - remaining_fixed,
            };
            if (trace_instances == 0) return error.RelationShapeMismatch;
            for (0..trace_instances) |_| {
                if (group_index >= groups.items.len or instance_index >= source_pointer_words.items.len)
                    return error.RelationShapeMismatch;
                const group = groups.items[group_index];
                const expected_outputs = @as(usize, trace.output_columns) * 4;
                const expected_sources: u64 = switch (trace.layout) {
                    .lookup_words => 1,
                    .memory_address => @as(u64, trace.layout_arg) * 2,
                    .memory_big, .memory_small => @as(u64, trace.layout_arg) + 1,
                    .bitwise_xor_12 => trace.layout_arg,
                };
                if (group.len != expected_outputs or source_pointer_words.items[instance_index] != expected_sources * 2 or
                    output_pointer_words.items[instance_index] != @as(u64, expected_outputs) * 2 or
                    denominator_words.items[instance_index] != group.rows * trace.output_columns * 4)
                    return error.RelationShapeMismatch;
                output_buffers += group.len;
                output_bytes += group.rows * group.len * 4;
                component_scan_blocks = std.math.add(
                    u64,
                    component_scan_blocks,
                    std.math.divCeil(u64, group.rows, 256) catch return error.SizeOverflow,
                ) catch return error.SizeOverflow;
                group_index += 1;
                instance_index += 1;
            }
        }
        if (group_index != groups.items.len) return error.RelationShapeMismatch;
        scan_scratch_bytes = @max(
            scan_scratch_bytes,
            std.math.mul(u64, component_scan_blocks, 16) catch return error.SizeOverflow,
        );
    }
    if (instance_index != claimed_sums or output_buffers != scheduled_output_buffers) return error.RelationShapeMismatch;
    return .{
        .instances = instance_index,
        .output_buffers = output_buffers,
        .output_bytes = output_bytes,
        .scan_scratch_bytes = scan_scratch_bytes,
    };
}

fn countFixedTraces(traces: []const relation_bundle_mod.Trace) usize {
    var count: usize = 0;
    for (traces) |trace| if (trace.part != .each_memory_big) {
        count += 1;
    };
    return count;
}

const fixed_table_test_identities = [_][]u8{
    @constCast("identity_a"),
    @constCast("identity_b"),
};
const fixed_table_test_source_a = [_][]u8{@constCast("identity_a")};
const fixed_table_test_source_b = [_][]u8{@constCast("identity_b")};
const fixed_table_test_trace_columns = [_]u32{0};
const fixed_table_test_descriptors = [_]u32{ 0, 7, 0, 0 };
const fixed_table_test_entries = [_]fixed_table_bundle_mod.Entry{
    .{
        .component = @constCast("table_a"),
        .log_size = 3,
        .row_count = 8,
        .multiplicity_columns = 1,
        .trace_multiplicity_columns = @constCast(fixed_table_test_trace_columns[0..]),
        .preprocessed_sources = @constCast(fixed_table_test_source_a[0..]),
        .lookup_descriptors = @constCast(fixed_table_test_descriptors[0..]),
    },
    .{
        .component = @constCast("table_b"),
        .log_size = 3,
        .row_count = 8,
        .multiplicity_columns = 1,
        .trace_multiplicity_columns = @constCast(fixed_table_test_trace_columns[0..]),
        .preprocessed_sources = @constCast(fixed_table_test_source_b[0..]),
        .lookup_descriptors = @constCast(fixed_table_test_descriptors[0..]),
    },
};

fn fixedTableTestBundle(format_version: u32) fixed_table_bundle_mod.Bundle {
    return .{
        .allocator = std.testing.allocator,
        .format_version = format_version,
        .graph_hash = fixed_table_bundle_mod.expected_graph_hash,
        .preprocessed_identities = @constCast(fixed_table_test_identities[0..]),
        .entries = @constCast(fixed_table_test_entries[0..]),
    };
}

const fixed_table_active_schedule =
    \\[
    \\  {"id":0,"purpose":"LookupInputs","component":"table_a","ordinal":0,"len_words":8},
    \\  {"id":1,"purpose":"FixedMultiplicity","component":"table_a","ordinal":0,"len_words":8},
    \\  {"id":2,"purpose":"BaseTrace","component":"table_a","ordinal":0,"len_words":8},
    \\  {"id":3,"purpose":"PreprocessedEvaluations","ordinal":0,"len_words":8},
    \\  {"id":4,"purpose":"FixedTableLookupDescriptors","component":"table_a","ordinal":0,"len_words":4},
    \\  {"id":5,"purpose":"FixedTableSourcePointers","component":"table_a","ordinal":0,"len_words":2},
    \\  {"id":6,"purpose":"FixedTableMultiplicityPointers","component":"table_a","ordinal":0,"len_words":2},
    \\  {"id":7,"purpose":"FixedTableLookupOutputPointers","component":"table_a","ordinal":0,"len_words":2},
    \\  {"id":8,"purpose":"PreprocessedCoefficients","ordinal":0,"len_words":8},
    \\  {"id":9,"purpose":"PreprocessedEvaluations","ordinal":1,"len_words":8},
    \\  {"id":10,"purpose":"PreprocessedCoefficients","ordinal":1,"len_words":8}
    \\]
;

test "canonical fixed-table bundle may cover an active subset" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, fixed_table_active_schedule, .{});
    defer parsed.deinit();
    var destinations = std.StringHashMap(void).init(std.testing.allocator);
    defer destinations.deinit();

    const coverage = try validateFixedTableCoverage(
        parsed.value.array.items,
        fixedTableTestBundle(fixed_table_bundle_mod.version),
        &destinations,
    );
    try std.testing.expectEqual(@as(usize, 1), coverage.components);
    try std.testing.expectEqual(@as(usize, 1), coverage.lookup_buffers);
    try std.testing.expect(destinations.contains("table_a"));
    try std.testing.expect(!destinations.contains("table_b"));
}

test "projected fixed-table bundle rejects incomplete coverage" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, fixed_table_active_schedule, .{});
    defer parsed.deinit();
    var destinations = std.StringHashMap(void).init(std.testing.allocator);
    defer destinations.deinit();

    try std.testing.expectError(
        error.FixedTableCoverageMismatch,
        validateFixedTableCoverage(
            parsed.value.array.items,
            fixedTableTestBundle(fixed_table_bundle_mod.projected_version),
            &destinations,
        ),
    );
}

test "fixed-table coverage rejects an unknown scheduled descriptor component" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, fixed_table_active_schedule, .{});
    defer parsed.deinit();
    var unknown = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        "{\"id\":11,\"purpose\":\"FixedTableLookupDescriptors\",\"component\":\"unknown\",\"ordinal\":0,\"len_words\":4}",
        .{},
    );
    defer unknown.deinit();
    var schedule = std.ArrayList(std.json.Value).empty;
    defer schedule.deinit(std.testing.allocator);
    try schedule.appendSlice(std.testing.allocator, parsed.value.array.items);
    try schedule.append(std.testing.allocator, unknown.value);
    var destinations = std.StringHashMap(void).init(std.testing.allocator);
    defer destinations.deinit();

    try std.testing.expectError(
        error.FixedTableCoverageMismatch,
        validateFixedTableCoverage(schedule.items, fixedTableTestBundle(fixed_table_bundle_mod.version), &destinations),
    );
}

test "empty schedule has no optional coverage" {
    const allocator = std.testing.allocator;
    const schedule = &[_]std.json.Value{};

    const preprocessed = try buildPreprocessedSources(allocator, schedule);
    defer allocator.free(preprocessed.sources);
    try std.testing.expectEqual(@as(usize, 0), preprocessed.buffers);
    try std.testing.expectEqual(@as(u64, 0), preprocessed.bytes);

    const parents = try buildMerkleParentSources(allocator, schedule);
    defer allocator.free(parents.sources);
    try std.testing.expectEqual(@as(usize, 0), parents.chains);

    const retained = try buildRetainedSources(allocator, schedule);
    defer allocator.free(retained);
    try std.testing.expectEqual(@as(usize, 0), retained.len);

    const ec_op = try validateEcOpCoverage(schedule);
    try std.testing.expectEqual(@as(u64, 0), ec_op.rows);
    try std.testing.expectEqual(@as(usize, 0), ec_op.output_buffers);
}
