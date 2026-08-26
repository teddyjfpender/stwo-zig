const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.universal_adapter_manifest;
const universal_manifest = recursion.air.universal_manifest;
const roster = recursion.air.universal_roster;
const relation_interaction = recursion.air.relation_interaction;
const fri_source_mod = recursion.binary_fri_outer_source;
const global_closure = recursion.binary_global_closure_outer_source;
const statement_source = recursion.outer_parent_statement_air_source;
const COMPLETE_ROW_COUNT: usize = roster.COMPONENT_COUNT;
const FRI_ROW_COUNT: usize = fri_source_mod.ROW_COUNT;

pub fn validateCrossCustodyEnvelope(inputs: anytype) !void {
    const non_fri = inputs.non_fri;
    const fri = inputs.fri_source;
    const shared = fri.shared_arithmetic orelse
        return error.CrossCustodyMismatch;
    const expected_lane = statement_source.loweringLane(
        non_fri.statement_authority,
    );
    const expected_evaluation = non_fri.statement_prepared.loweringEvaluation();
    if (fri.pair != non_fri.transcript_prepared or
        fri.vm_plan != non_fri.vm_plan or
        fri.recursion_plans[0] != non_fri.recursion_plans[0] or
        fri.recursion_plans[1] != non_fri.recursion_plans[1] or
        !std.meta.eql(fri.root_pin, non_fri.root_pin) or
        shared.lane.circuit_id != expected_lane.circuit_id or
        shared.lane.active_in != expected_lane.active_in or
        !std.mem.eql(
            u8,
            &shared.lane.circuit_identity,
            &expected_lane.circuit_identity,
        ) or
        shared.lane.graph.nodes.ptr != expected_lane.graph.nodes.ptr or
        shared.lane.graph.nodes.len != expected_lane.graph.nodes.len or
        shared.lane.graph.outputs.ptr != expected_lane.graph.outputs.ptr or
        shared.lane.graph.outputs.len != expected_lane.graph.outputs.len or
        !std.mem.eql(
            u8,
            &shared.lane.graph.identity_digest,
            &expected_lane.graph.identity_digest,
        ) or
        shared.evaluation.values.ptr != expected_evaluation.values.ptr or
        shared.evaluation.values.len != expected_evaluation.values.len or
        !std.mem.eql(
            u8,
            &shared.evaluation.circuit_identity,
            &expected_evaluation.circuit_identity,
        ))
    {
        return error.CrossCustodyMismatch;
    }
}

pub fn validateCrossCustodyCold(inputs: anytype) !void {
    try validateCrossCustodyEnvelope(inputs);
    const fri = inputs.fri_source;
    try fri.requireFullBundleAuthority();
}

pub fn globalBoundaryEvidence(
    evidence: fri_source_mod.PublicBoundaryEvidence,
) global_closure.BoundaryEvidenceV2 {
    return .{
        .source_authority_id = evidence.source_authority_id,
        .snapshot_id = evidence.snapshot_id,
        .tuple_provenance_id = evidence.tuple_provenance_id,
        .tuple_count = evidence.tuple_count,
        .claimed_sum = evidence.claimed_sum,
    };
}

pub fn validateManifestComposition(
    non_fri: anytype,
    fri: anytype,
    manifest: *const manifest_mod.Manifest,
) !void {
    try manifest.validate();
    if (manifest.roster_count != COMPLETE_ROW_COUNT)
        return error.ManifestGeometryMismatch;
    for (manifest.roster_rows[0..manifest.roster_count], 0..) |row, index|
        if (row != index) return error.RosterOrderMismatch;

    var logs = [_]u32{0} ** roster.COMPONENT_COUNT;
    non_fri.installLogSizes(&logs);
    try fri.source.installLogSizes(&logs);
    const rebuilt = try universal_manifest.build(logs);
    if (!std.meta.eql(rebuilt, manifest.*))
        return error.ManifestGeometryMismatch;

    // Independently ask the FRI bundle for its exact geometries, then compare
    // each row to the corresponding placement in the complete manifest.
    var builder = manifest_mod.Builder{};
    try fri.appendManifestGeometries(&builder);
    const partial = try builder.seal();
    if (partial.roster_count != FRI_ROW_COUNT)
        return error.ManifestGeometryMismatch;
    for (partial.roster_rows[0..partial.roster_count]) |row| {
        if (!std.meta.eql(
            partial.placements[row].?.geometry,
            manifest.placements[row].?.geometry,
        )) return error.ManifestGeometryMismatch;
    }
}

pub fn rowClaim(
    row: roster.Component,
    values: [global_closure.DOMAIN_COUNT]QM31,
    total: QM31,
) global_closure.RowClaimsV1 {
    var domains: [global_closure.DOMAIN_COUNT]global_closure.DomainClaimV1 =
        undefined;
    for (&domains, values, 0..) |*destination, value, index| {
        destination.* = .{
            .active = if (value.isZero()) 0 else global_closure.ACTIVE,
            .domain = @enumFromInt(index),
            .value = value,
        };
    }
    return .{
        .row = row,
        .domains = domains,
        .claimed_sum = total,
    };
}

pub fn poseidonRowClaim(
    audit: fri_source_mod.Poseidon2DomainAudit,
) global_closure.RowClaimsV1 {
    var values = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
    const Domain = @TypeOf(@as(global_closure.DomainClaimV1, undefined).domain);
    values[@intFromEnum(@as(Domain, .poseidon2))] = audit.poseidon2;
    values[@intFromEnum(@as(Domain, .poseidon2_io))] = audit.poseidon2_io;
    return rowClaim(.poseidon2, values, audit.total);
}

/// Cold diagnostic only: retain the exact typed tuples from rows 18--33 beside
/// the rows 0--17 tuples already published by the non-FRI source. This makes a
/// missing producer distinguishable from a challenge-dependent sum mismatch
/// without granting the cohort any authority to synthesize a closing claim.
pub fn appendFriTupleContributions(
    cohort: anytype,
    ledger: *relation_interaction.TupleLedger,
) !void {
    const source = cohort.fri.source;
    const rows = &cohort.fri.relation_rows;
    const composition = source.composition_rows orelse
        return error.MissingCompositionAuthority;
    const arithmetic = source.arithmetic_rows orelse
        return error.MissingCompositionAuthority;
    const mask = relation_interaction.allDomainMask();

    try composition.input_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.vm_air_composition_input),
        rows.composition_input,
        mask,
    );
    try composition.control_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.vm_air_composition_control),
        rows.composition_control,
        mask,
    );
    try source.fri_rows.query_bits_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.query_bits),
        rows.query_bits,
        mask,
    );
    try source.fri_rows.query_mapping_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.query_mapping),
        rows.query_mapping,
        mask,
    );
    try source.fri_rows.merkle_root_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.merkle_root),
        rows.merkle_root,
        mask,
    );
    try source.fri_rows.trace_merkle_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.trace_merkle),
        rows.trace_merkle,
        mask,
    );
    try source.fri_rows.pcs_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.pcs_deep_input),
        rows.pcs_deep,
        mask,
    );
    try source.fri_rows.fri_leaf_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.fri_merkle_leaf),
        rows.fri_leaf,
        mask,
    );
    try source.fri_rows.fri_node_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.fri_merkle_node),
        rows.fri_node,
        mask,
    );
    try source.fri_rows.fri_anchor_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.fri_merkle_anchor),
        rows.fri_anchor,
        mask,
    );
    try source.fri_rows.control_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.fri_verifier_control),
        rows.fri_control,
        mask,
    );
    try source.fri_rows.input_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.fri_verifier_input),
        rows.fri_input,
        mask,
    );
    try arithmetic.multiply_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.qm31_mul),
        rows.multiply,
        mask,
    );
    try arithmetic.inverse_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.qm31_inv),
        rows.inverse,
        mask,
    );
    try arithmetic.linear_relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.linear_ops),
        rows.linear,
        mask,
    );
    try source.merkle_rows.relation.appendPreparedTupleContributions(
        ledger,
        componentIndex(.merkle_path),
        rows.merkle_path,
        mask,
    );
}

fn componentIndex(component: roster.Component) u8 {
    return @intCast(@intFromEnum(component));
}

pub fn printUnmatchedTupleGroups(
    ledger: *relation_interaction.TupleLedger,
) void {
    const max_groups: usize = 16;
    const max_contributions_per_group: usize = 8;
    const report = ledger.classify();
    std.debug.print(
        "binary cohort tuple closure: contributions={d} unmatched={d} red_domains={d}\n",
        .{
            report.contribution_count,
            report.unmatched_tuple_count,
            report.redDomainCount(),
        },
    );
    const items = ledger.contributions.items;
    var cursor: usize = 0;
    var printed_groups: usize = 0;
    var omitted_groups: usize = 0;
    while (cursor < items.len) {
        const first = items[cursor];
        var end = cursor + 1;
        var signed_weight = first.signed_weight;
        while (end < items.len and items[end].domain == first.domain and
            std.mem.eql(u8, &items[end].tuple_hash, &first.tuple_hash)) : (end += 1)
        {
            signed_weight = signed_weight.add(items[end].signed_weight);
        }
        if (!signed_weight.isZero()) {
            if (printed_groups == max_groups) {
                omitted_groups += 1;
                cursor = end;
                continue;
            }
            printed_groups += 1;
            const tuple_hex = std.fmt.bytesToHex(first.tuple_hash, .lower);
            std.debug.print(
                "  unmatched {s} tuple={s} net={any}\n",
                .{
                    @tagName(first.domain),
                    &tuple_hex,
                    signed_weight.toM31Array(),
                },
            );
            const contribution_end = @min(
                end,
                cursor + max_contributions_per_group,
            );
            for (items[cursor..contribution_end]) |contribution| {
                const component = roster.DESCRIPTORS[contribution.component];
                std.debug.print(
                    "    row={d}:{s} event={d} role={s} signed={any}\n",
                    .{
                        contribution.component,
                        component.name,
                        contribution.event,
                        @tagName(contribution.role),
                        contribution.signed_weight.toM31Array(),
                    },
                );
            }
            if (contribution_end != end) std.debug.print(
                "    ... {d} additional contributions omitted\n",
                .{end - contribution_end},
            );
        }
        cursor = end;
    }
    if (omitted_groups != 0) std.debug.print(
        "  ... {d} additional unmatched tuple groups omitted\n",
        .{omitted_groups},
    );
}

pub fn generatedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-binary-outer-generated/v1\x00");
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.padding);
    hash.update(&value.cohort_id);
    hash.update(&value.manifest_seal);
    hash.update(&value.non_fri.identity);
    hash.update(&value.fri.identity);
    return hash.finalResult();
}

pub fn cohortIdentity(
    cohort: anytype,
    format_version: u16,
    protocol_substrate_only: bool,
    authenticated_temporal_v2: bool,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-binary-outer-cohort/v1\x00");
    hashInt(&hash, u16, format_version);
    hash.update(&cohort.complete_manifest.seal);
    hash.update(&cohort.non_fri.authority_seal);
    hash.update(&cohort.fri.authority_seal);
    hash.update(&cohort.closure_authority.source_authority_id);
    hash.update(&cohort.closure_authority.provider_source_authority_id);
    for (cohort.inputs.non_fri.transcript_prepared.authenticated_root.pair.node_id) |
        word,
    | hashInt(&hash, u32, word);
    hashInt(&hash, u8, @intFromBool(protocol_substrate_only));
    hashInt(&hash, u8, @intFromBool(authenticated_temporal_v2));
    return hash.finalResult();
}

pub const TreeScratch = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !TreeScratch {
        const column_count = treeColumnCount(manifest, tree);
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);

        var cell_count: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            cell_count = std.math.add(
                usize,
                cell_count,
                std.math.mul(
                    usize,
                    rows,
                    treeGeometryColumns(placement.geometry, tree),
                ) catch return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
        }
        const storage = try allocator.alloc(M31, cell_count);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());

        var cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            const offset = treeOffset(placement, tree);
            const count = treeGeometryColumns(placement.geometry, tree);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..rows];
                cursor += rows;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *TreeScratch) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub fn preflightTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: [][]M31,
) !void {
    if (destination.len != treeColumnCount(manifest, tree))
        return error.DestinationShapeMismatch;

    var canonical_contiguous = destination.len != 0;
    var prior_end: usize = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = treeGeometryColumns(placement.geometry, tree);
        const expected_rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
        for (destination[offset..][0..count]) |column| {
            if (column.len != expected_rows)
                return error.DestinationShapeMismatch;
            for (column) |value| if (!value.isZero())
                return error.DestinationNotFresh;
            const start = @intFromPtr(column.ptr);
            const bytes = std.math.mul(usize, column.len, @sizeOf(M31)) catch
                return error.ArithmeticOverflow;
            const end = std.math.add(usize, start, bytes) catch
                return error.ArithmeticOverflow;
            if (prior_end != 0 and start != prior_end)
                canonical_contiguous = false;
            prior_end = end;
        }
    }
    if (canonical_contiguous) return;

    // General caller-owned slices may be independently allocated. Retain a
    // no-allocation slow path for them; Engine-owned trees take the linear
    // contiguous fast path above.
    for (destination, 0..) |left, left_index| {
        const left_start = @intFromPtr(left.ptr);
        const left_bytes = std.math.mul(usize, left.len, @sizeOf(M31)) catch
            return error.ArithmeticOverflow;
        const left_end = std.math.add(usize, left_start, left_bytes) catch
            return error.ArithmeticOverflow;
        for (destination[left_index + 1 ..]) |right| {
            const right_start = @intFromPtr(right.ptr);
            const right_bytes = std.math.mul(usize, right.len, @sizeOf(M31)) catch
                return error.ArithmeticOverflow;
            const right_end = std.math.add(usize, right_start, right_bytes) catch
                return error.ArithmeticOverflow;
            if (left_start < right_end and right_start < left_end)
                return error.DestinationAlias;
        }
    }
}

pub fn clearTree(destination: [][]M31) void {
    for (destination) |column| @memset(column, M31.zero());
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
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

pub fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = std.mem.readInt(
        u32,
        value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
        .little,
    );
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}
