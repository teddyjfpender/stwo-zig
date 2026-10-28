//! Derive the detached-parent component geometry from child keys alone.
//! The parent key's serialized manifest is an equality check, never the
//! authority that chooses Tree 0 placement or the provider trace height.
const std = @import("std");
const child_mod = @import("detached_child_capture_v1.zig");
const cohort = @import("detached_parent_prepared_v1.zig");
const components = @import("detached_parent_components_v1.zig");
const base_mod = @import("detached_parent_fixed_base_v1.zig");
const graph_mod = @import("detached_parent_arithmetic_v1.zig");
const pcs_template = @import("detached_pcs_key_template_v1.zig");
const pcs_shape = @import("detached_pcs_key_shape_v1.zig");
const pcs_source = @import("binary_fri_outer_source.zig");
const provider = @import("air/universal_shared_provider.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const tags = @import("air/verifier_parameter_tags.zig");
const proof_kind = @import("air/proof_kind.zig");
const pcs_airs = struct {
    const query_bits = @import("air/query_bits.zig");
    const query_mapping = @import("air/query_mapping.zig");
    const merkle_root = @import("air/merkle_root.zig");
    const trace_merkle = @import("air/trace_merkle.zig");
    const pcs_deep = @import("air/pcs_deep_input.zig");
    const fri_leaf = @import("air/fri_merkle_leaf.zig");
    const fri_node = @import("air/fri_merkle_node.zig");
    const fri_anchor = @import("air/fri_merkle_anchor.zig");
    const fri_control = @import("air/fri_verifier_control.zig");
    const fri_input = @import("air/fri_verifier_input.zig");
};

pub fn fromChildKeys(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype, mode: @import("span_continuation_v1.zig").Mode) !cohort.manifest_mod.Manifest {
    return derive(family, allocator, keys, mode, null);
}

fn derive(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype, mode: @import("span_continuation_v1.zig").Mode, proposed_parameters: ?*const components.ParametersV1) !cohort.manifest_mod.Manifest {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var base = try base_mod.OwnedV1.init(family, a, keys);
    defer base.deinit();
    var graph = try graph_mod.fixedFromChildKeys(family, a, keys, mode);
    defer graph.deinit();
    var counts: [cohort.manifest_mod.COMPONENT_COUNT]usize = @splat(0);
    inline for (.{ 0, 2, 3, 4, 5, 8, 9, 10 }) |row|
        counts[row] = base.rows[cohort.logicalIndex(row)].len;
    counts[1] = counts[2]; // one transcript-air call per binding
    if (counts[10] % 2 != 0) return error.DetachedParentManifestMismatch;
    counts[6] = counts[10] / 2; // two nonce limbs per PoW row
    counts[7] = counts[6];
    counts[11] = graph.input_rows.len;
    counts[12] = graph.poseidon_rows.len;
    counts[13] = graph.wire_rows.len;
    inline for (.{ 14, 30, 31, 32 }, 0..) |row, slot|
        counts[row] = graph.arithmetic.fixed[slot].len;

    var templates: [2]pcs_template.TemplateV1 = undefined;
    var vm_plans: [2]@import("air/verifier_schedule.zig").Plan = undefined;
    var recursion_plans: [2]@import("air/verifier_schedule.zig").Plan = undefined;
    var fixed_pcs: [2]pcs_source.FriRowsAuthority = undefined;
    inline for (0..2) |index| {
        templates[index] = try pcs_template.TemplateV1.init(a, keys[index]);
        vm_plans[index] = try pcs_shape.planFromKey(a, keys[index], .vm);
        recursion_plans[index] = try pcs_shape.planFromKey(a, keys[index], .recursion);
        fixed_pcs[index] = try pcs_source.FriRowsAuthority.initInactiveFromTemplate(a, &vm_plans[index], &recursion_plans[index], &templates[index]);
        const lane: u32 = index + 1;
        // The canonical path writer opens only the final trace sponge row for
        // each query, and one path per selected FRI anchor. Geometry-wide
        // query_count * height counts inactive rows and is not the authority.
        for (fixed_pcs[index].trace_merkle_preprocessing.rows) |row| {
            if (row.verifier_id != lane or row.last != 1) continue;
            if (row.tree >= templates[index].trace_tree_heights.len) return error.DetachedParentManifestMismatch;
            counts[33] = try std.math.add(usize, counts[33], templates[index].trace_tree_heights[row.tree]);
        }
        for (fixed_pcs[index].fri_anchor_preprocessing.rows) |row| {
            if (row.verifier_id != lane) continue;
            if (row.layer >= templates[index].fri_layer_profiles.len) return error.DetachedParentManifestMismatch;
            counts[33] = try std.math.add(usize, counts[33], try templates[index].fri_layer_profiles[row.layer].siblingPathDepth());
        }
    }
    inline for (.{
        .{ 20, pcs_airs.query_bits, "query_bits_preprocessing" },
        .{ 21, pcs_airs.query_mapping, "query_mapping_preprocessing" },
        .{ 22, pcs_airs.merkle_root, "merkle_root_preprocessing" },
        .{ 23, pcs_airs.trace_merkle, "trace_merkle_preprocessing" },
        .{ 24, pcs_airs.pcs_deep, "pcs_preprocessing" },
        .{ 25, pcs_airs.fri_leaf, "fri_leaf_preprocessing" },
        .{ 26, pcs_airs.fri_node, "fri_node_preprocessing" },
        .{ 27, pcs_airs.fri_anchor, "fri_anchor_preprocessing" },
        .{ 28, pcs_airs.fri_control, "control_preprocessing" },
        .{ 29, pcs_airs.fri_input, "input_preprocessing" },
    }) |entry| {
        _ = entry[1];
        const left = @field(fixed_pcs[0], entry[2]).rows;
        const right = @field(fixed_pcs[1], entry[2]).rows;
        for (left) |row| counts[entry[0]] += @intFromBool(row.verifier_id == 1);
        for (right) |row| counts[entry[0]] += @intFromBool(row.verifier_id == 2);
    }
    // PCS preprocessing includes inactive segment-only rows under the binary
    // verifier. Only the binary-masked hash rows request Poseidon2; counting
    // every physical hash row would overstate the provider trace height.
    var pcs_hash_requests: usize = counts[33];
    inline for (.{ "trace_merkle_preprocessing", "fri_leaf_preprocessing", "fri_node_preprocessing" }) |field| {
        for (@field(fixed_pcs[0], field).rows) |row| {
            if (row.verifier_id == 1 and row.binary_mask == 1)
                pcs_hash_requests = try std.math.add(usize, pcs_hash_requests, 1);
        }
        for (@field(fixed_pcs[1], field).rows) |row| {
            if (row.verifier_id == 2 and row.binary_mask == 1)
                pcs_hash_requests = try std.math.add(usize, pcs_hash_requests, 1);
        }
    }
    // The remaining requests are transcript permutations and the key-derived
    // boundary graph, including its native-memory Poseidon2 calls.
    counts[34] = counts[1];
    for ([_]usize{ graph.provider_count, pcs_hash_requests }) |count|
        counts[34] = try std.math.add(usize, counts[34], count);
    if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_CALL_CENSUS transcript={d} graph={d} pcs={d} paths={d} hash_rows={d}/{d}/{d} total={d}\n", .{ counts[1], graph.provider_count, pcs_hash_requests, counts[33], counts[23], counts[25], counts[26], counts[34] });

    var builder = cohort.manifest_mod.Builder{};
    inline for (cohort.LOGICAL_ROWS) |entry| {
        const row = @intFromEnum(entry.row);
        _ = try builder.append(components.Component(entry).manifestGeometry(entry.row, try traceLogSize(counts[row])));
    }
    const PoseidonAdapter = provider.Poseidon2Degree3AdapterForManifest(cohort.manifest_mod);
    _ = try builder.append(PoseidonAdapter.manifestGeometry(try traceLogSize(counts[34])));
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
    const manifest = try builder.seal();
    if (proposed_parameters) |parameters| {
        try parameters.validate(&manifest);
        const active = std.math.cast(u32, counts[34]) orelse return error.DetachedParentManifestMismatch;
        if (parameters.poseidon_active_rows != active) {
            if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_ACTIVE_CALLS derived={d} proposed={d}\n", .{ active, parameters.poseidon_active_rows });
            return error.DetachedParentParameterMismatch;
        }
        inline for (.{ 0, 2, 3, 4, 5, 8, 9, 10 }) |row|
            try checkParameters(row, base.rows[cohort.logicalIndex(row)], parameters);
        try checkParameters(11, graph.input_rows, parameters);
        try checkParameters(12, graph.poseidon_rows, parameters);
        try checkParameters(13, graph.wire_rows, parameters);
        inline for (.{ 14, 30, 31, 32 }, 0..) |row, slot|
            try checkParameters(row, graph.arithmetic.fixed[slot], parameters);
        try checkPcsParameters(&fixed_pcs, parameters);
    }
    return manifest;
}

fn checkParameters(comptime row: usize, rows: anytype, proposed: *const components.ParametersV1) !void {
    const entry = cohort.LOGICAL_ROWS[cohort.logicalIndex(row)];
    const count = components.Component(entry).PARAMETER_COLUMN_COUNT;
    if (count == 0) return;
    if (rows.len == 0 or proposed.words[row].len != count) {
        if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_PARAM_SHAPE row={d} rows={d} proposed={d} expected={d}\n", .{ row, rows.len, proposed.words[row].len, count });
        return error.DetachedParentParameterMismatch;
    }
    const first = rows[0][rows[0].len - count ..];
    for (first, proposed.words[row], 0..) |actual, expected, index| if (!actual.eql(expected)) {
        if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_PARAM_VALUE row={d} index={d} derived={d} proposed={d}\n", .{ row, index, actual.toU32(), expected.toU32() });
        return error.DetachedParentParameterMismatch;
    };
    for (rows[1..]) |source| for (first, source[source.len - count ..], 0..) |actual, candidate, index| if (!actual.eql(candidate)) {
        if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_PARAM_INCONSISTENT row={d} index={d} first={d} next={d}\n", .{ row, index, actual.toU32(), candidate.toU32() });
        return error.DetachedParentParameterMismatch;
    };
}

fn checkPcsParameters(fixed: *const [2]pcs_source.FriRowsAuthority, proposed: *const components.ParametersV1) !void {
    const selectors = proof_kind.ProofKind.binary_node.selectors();
    for (fixed) |source|
        try checkParameterWords(20, try @import("air/query_bits_witness.zig").parameterValues(source.query_bits_reference, .binary_node), proposed);
    try checkParameterWords(21, [_]M31{ selectors[0], selectors[1] }, proposed);
    try checkParameterWords(22, [_]M31{ selectors[0], selectors[1] }, proposed);
    try checkParameterWords(23, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.trace_merkle.LEAF_TAG), M31.fromCanonical(tags.trace_merkle.TRACE_POSITION_KIND) }, proposed);
    try checkParameterWords(24, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.pcs.SAMPLED_VALUE_KIND), M31.fromCanonical(tags.pcs.OODS_POINT_KIND), M31.fromCanonical(tags.pcs.DEEP_RANDOMNESS_KIND), M31.fromCanonical(tags.pcs.DEEP_POSITION_KIND) }, proposed);
    try checkParameterWords(25, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.fri_leaf.LEAF_TAG) }, proposed);
    try checkParameterWords(26, [_]M31{ selectors[0], selectors[1] }, proposed);
    try checkParameterWords(27, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.fri_anchor.FRI_MERKLE_KIND) }, proposed);
    try checkParameterWords(28, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.control.POSITION_FIELD), M31.fromCanonical(tags.control.OFFSET_FIELD) }, proposed);
    try checkParameterWords(29, [_]M31{ selectors[0], selectors[1], M31.fromCanonical(tags.input.FRI_ALPHA_KIND), M31.fromCanonical(tags.input.FRI_FOLD_KIND), M31.fromCanonical(tags.input.LAST_LAYER_KIND), M31.fromCanonical(tags.input.POSITION_FIELD), M31.fromCanonical(tags.input.OFFSET_FIELD), M31.fromCanonical(tags.input.COEFFICIENT_KIND) }, proposed);
}

fn checkParameterWords(comptime row: usize, expected: anytype, proposed: *const components.ParametersV1) !void {
    if (expected.len != proposed.words[row].len) return error.DetachedParentParameterMismatch;
    for (expected, proposed.words[row], 0..) |actual, candidate, index| if (!actual.eql(candidate)) {
        if (@import("builtin").is_test) std.debug.print("DETACHED_PARENT_KEY_PCS_PARAM row={d} index={d} derived={d} proposed={d}\n", .{ row, index, actual.toU32(), candidate.toU32() });
        return error.DetachedParentParameterMismatch;
    };
}

fn traceLogSize(count: usize) !u32 {
    if (count > @as(usize, 1) << 28) return error.DetachedParentTraceTooLarge;
    return @max(4, std.math.log2_int_ceil(usize, @max(count, 1)));
}

pub fn assertMatches(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype, mode: @import("span_continuation_v1.zig").Mode, proposed: *const cohort.manifest_mod.Manifest, parameters: *const components.ParametersV1) !void {
    const derived = try derive(family, allocator, keys, mode, parameters);
    try proposed.validate();
    if (!std.mem.eql(u8, &derived.seal, &proposed.seal)) {
        if (@import("builtin").is_test) for (derived.roster_rows[0..derived.roster_count]) |row| {
            const actual = proposed.placements[row] orelse return error.DetachedParentManifestMismatch;
            const computed = derived.placements[row].?;
            if (actual.geometry.log_size != computed.geometry.log_size)
                std.debug.print("DETACHED_PARENT_KEY_MANIFEST_LOG row={d} derived={d} proposed={d}\n", .{ row, computed.geometry.log_size, actual.geometry.log_size });
        };
        return error.DetachedParentManifestMismatch;
    }
}
