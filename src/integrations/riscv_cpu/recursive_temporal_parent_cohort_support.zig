const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const suffix_mod = @import("recursive_temporal_parent_suffix_v3.zig");
const temporal_manifest = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const roster = recursion.air.universal_roster;
const universal = recursion.air.universal_challenges;
const relation_interaction = recursion.air.relation_interaction;
const global_closure = recursion.binary_global_closure_outer_source;
const manifest_mod = temporal_manifest;
const PROVIDER_ROW: usize = 35;

pub fn ensurePrefixBaseTrees(self: anytype) !void {
    if (self.prefix.phase == .cold) _ = try self.prefix.fillBaseTrees();
}

pub fn requireManifest(
    self: anytype,
    active_manifest: *const manifest_mod.Manifest,
) !void {
    try self.validate();
    if (active_manifest != &self.manifest_value and
        !std.meta.eql(active_manifest.*, self.manifest_value))
    {
        return error.ManifestGeometryMismatch;
    }
}

/// Test-build mutation fleet over the publication trust boundary. Each
/// adversary recomputes the outer audit identity, proving rejection comes
/// from source/closure authority rather than a stale checksum alone.
pub fn runAuditMutationFleetForTest(
    self: anytype,
    audited: anytype,
    claims: anytype,
    relations: anytype,
    provider_relations: anytype,
) !void {
    if (!@import("builtin").is_test) return;
    try self.validateAuditedInteractions(
        audited,
        claims,
        relations,
        provider_relations,
    );

    var forged = audited.*;
    forged.rows[@intFromEnum(roster.Component.query_bits)].claimed_sum =
        forged.rows[@intFromEnum(roster.Component.query_bits)]
            .claimed_sum.add(QM31.one());
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    forged = audited.*;
    forged.wire_boundary.tuple_count +%= 1;
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    forged = audited.*;
    forged.verifier_input_boundary.claimed_sum =
        forged.verifier_input_boundary.claimed_sum.add(QM31.one());
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    // Every suffix row is independently compared with the source-derived
    // audit. This loop guards against an accidentally omitted roster slot
    // when rows 20--34 evolve independently.
    var suffix_row: usize = 20;
    while (suffix_row < PROVIDER_ROW) : (suffix_row += 1) {
        forged = audited.*;
        forged.rows[suffix_row].claimed_sum =
            forged.rows[suffix_row].claimed_sum.add(QM31.one());
        forged.identity = auditedIdentity(&forged);
        try expectAuditRejected(
            self,
            &forged,
            claims,
            relations,
            provider_relations,
        );
    }

    // Row 35 is not stored in `rows`: it is the separately authenticated
    // range provider and must fail closed through that exact authority.
    forged = audited.*;
    forged.provider_claim.claimed_sum =
        forged.provider_claim.claimed_sum.add(QM31.one());
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    // Coherently reseal hostile context mutations before resealing the
    // enclosing audit. Rejection therefore proves source equality, not
    // merely detection of a stale context or audit checksum.
    forged = audited.*;
    forged.context.pair_authority_id[0] ^= 1;
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    forged = audited.*;
    forged.context.parent_statement_id[0] ^= 1;
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    forged = audited.*;
    std.mem.swap(
        suffix_mod.Digest,
        &forged.context.child_publication_ids[0],
        &forged.context.child_publication_ids[1],
    );
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.identity = auditedIdentity(&forged);
    try expectAuditRejected(
        self,
        &forged,
        claims,
        relations,
        provider_relations,
    );

    var forged_claims = claims.*;
    forged_claims.values[@intFromEnum(roster.Component.query_bits)] =
        forged_claims.values[@intFromEnum(roster.Component.query_bits)]
            .add(QM31.one());
    try forged_claims.sealClaims(&self.manifest_value);
    try expectAuditRejected(
        self,
        audited,
        &forged_claims,
        relations,
        provider_relations,
    );
}

fn expectAuditRejected(
    self: anytype,
    audited: anytype,
    claims: anytype,
    relations: anytype,
    provider_relations: anytype,
) !void {
    self.validateAuditedInteractions(
        audited,
        claims,
        relations,
        provider_relations,
    ) catch return;
    return error.AdversarialMutationAccepted;
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
    return .{ .row = row, .domains = domains, .claimed_sum = total };
}

pub fn poseidonRowClaim(
    audit: recursion.binary_fri_outer_source.Poseidon2DomainAudit,
) global_closure.RowClaimsV1 {
    var values = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
    const Domain = @TypeOf(@as(global_closure.DomainClaimV1, undefined).domain);
    values[@intFromEnum(@as(Domain, .poseidon2))] = audit.poseidon2;
    values[@intFromEnum(@as(Domain, .poseidon2_io))] = audit.poseidon2_io;
    return rowClaim(.poseidon2, values, audit.total);
}

pub fn globalBoundaryEvidence(
    evidence: recursion.binary_fri_outer_source.PublicBoundaryEvidence,
) global_closure.BoundaryEvidenceV2 {
    return .{
        .source_authority_id = evidence.source_authority_id,
        .snapshot_id = evidence.snapshot_id,
        .tuple_provenance_id = evidence.tuple_provenance_id,
        .tuple_count = evidence.tuple_count,
        .claimed_sum = evidence.claimed_sum,
    };
}

pub fn reportClosureResidual(
    rows: *const [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
    provider: *const global_closure.ProviderClaimV1,
    wire: global_closure.BoundaryEvidenceV2,
    verifier_input: global_closure.BoundaryEvidenceV2,
) void {
    var totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
    for (rows) |row| {
        for (row.domains, 0..) |claim, domain_index|
            totals[domain_index] = totals[domain_index].add(claim.value);
    }
    totals[@intFromEnum(provider.domain)] =
        totals[@intFromEnum(provider.domain)].add(provider.claimed_sum);
    const wire_domain = @intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN);
    totals[wire_domain] = totals[wire_domain].add(wire.claimed_sum);
    const verifier_domain =
        @intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN);
    totals[verifier_domain] = totals[verifier_domain].add(
        verifier_input.claimed_sum,
    );
    for (totals, 0..) |value, domain_index| {
        if (value.isZero()) continue;
        reportQm31("TEMPORAL_CLOSURE_RESIDUAL", null, domain_index, value);
        for (rows) |row| {
            const term = row.domains[domain_index].value;
            if (!term.isZero()) reportQm31(
                "TEMPORAL_CLOSURE_TERM",
                @intFromEnum(row.row),
                domain_index,
                term,
            );
        }
        if (domain_index == verifier_domain) reportQm31(
            "TEMPORAL_CLOSURE_BOUNDARY",
            null,
            domain_index,
            verifier_input.claimed_sum,
        );
    }
}

fn reportQm31(
    label: []const u8,
    row: ?usize,
    domain_index: usize,
    value: QM31,
) void {
    const limbs = value.toM31Array();
    if (row) |row_index| {
        std.debug.print(
            "{s} row={d} domain={d} value={d},{d},{d},{d}\n",
            .{
                label,
                row_index,
                domain_index,
                limbs[0].toU32(),
                limbs[1].toU32(),
                limbs[2].toU32(),
                limbs[3].toU32(),
            },
        );
    } else {
        std.debug.print(
            "{s} domain={d} value={d},{d},{d},{d}\n",
            .{
                label,
                domain_index,
                limbs[0].toU32(),
                limbs[1].toU32(),
                limbs[2].toU32(),
                limbs[3].toU32(),
            },
        );
    }
}

pub fn reportTupleLedger(ledger: *relation_interaction.TupleLedger) void {
    const report = ledger.classify();
    std.debug.print(
        "TEMPORAL_TUPLE_AUDIT contributions={d} unmatched={d} red_domains={d}\n",
        .{
            report.contribution_count,
            report.unmatched_tuple_count,
            report.redDomainCount(),
        },
    );
    for (report.unmatched_by_domain, 0..) |count, domain_index| {
        if (count != 0) std.debug.print(
            "TEMPORAL_TUPLE_DOMAIN domain={d} unmatched={d}\n",
            .{ domain_index, count },
        );
    }
    var component_roles = [_][roster.COMPONENT_COUNT][2]usize{
        [_][2]usize{[_]usize{0} ** 2} ** roster.COMPONENT_COUNT,
    } ** universal.RELATION_COUNT;
    var samples = [_]u8{0} ** universal.RELATION_COUNT;
    var cursor: usize = 0;
    while (cursor < ledger.contributions.items.len) {
        const first = ledger.contributions.items[cursor];
        var end = cursor + 1;
        var signed_weight = first.signed_weight;
        while (end < ledger.contributions.items.len and
            ledger.contributions.items[end].domain == first.domain and
            std.mem.eql(
                u8,
                &ledger.contributions.items[end].tuple_hash,
                &first.tuple_hash,
            )) : (end += 1)
        {
            signed_weight = signed_weight.add(
                ledger.contributions.items[end].signed_weight,
            );
        }
        if (!signed_weight.isZero()) {
            const domain_index = @intFromEnum(first.domain);
            for (ledger.contributions.items[cursor..end]) |contribution| {
                const role: usize = switch (contribution.role) {
                    .emit => 0,
                    .request, .consume => 1,
                };
                component_roles[domain_index][contribution.component][role] += 1;
            }
            if (samples[domain_index] < 4) {
                const weight = signed_weight.toM31Array();
                std.debug.print(
                    "TEMPORAL_TUPLE_UNMATCHED domain={d} arity={d} hash={x} weight={d},{d},{d},{d}\n",
                    .{
                        domain_index,
                        first.arity,
                        first.tuple_hash[0..8],
                        weight[0].toU32(),
                        weight[1].toU32(),
                        weight[2].toU32(),
                        weight[3].toU32(),
                    },
                );
                const sample_terms = ledger.contributions.items[cursor..end];
                for (sample_terms[0..@min(sample_terms.len, 4)]) |contribution| {
                    var prefix: [relation_interaction.TUPLE_DIAGNOSTIC_PREFIX_ARITY]u32 =
                        undefined;
                    for (&prefix, contribution.tuple_prefix) |*target, coordinate|
                        target.* = coordinate.toM31Array()[0].toU32();
                    std.debug.print(
                        "TEMPORAL_TUPLE_TERM component={d} event={d} role={s} prefix={d},{d},{d},{d},{d}\n",
                        .{
                            contribution.component,
                            contribution.event,
                            @tagName(contribution.role),
                            prefix[0],
                            prefix[1],
                            prefix[2],
                            prefix[3],
                            prefix[4],
                        },
                    );
                }
                if (sample_terms.len > 4) std.debug.print(
                    "TEMPORAL_TUPLE_TERM_OMITTED count={d}\n",
                    .{sample_terms.len - 4},
                );
                samples[domain_index] += 1;
            }
        }
        cursor = end;
    }
    for (component_roles, 0..) |by_component, domain_index| {
        for (by_component, 0..) |counts, component_index| {
            if (counts[0] == 0 and counts[1] == 0) continue;
            std.debug.print(
                "TEMPORAL_TUPLE_COMPONENT domain={d} component={d} emit={d} consume={d}\n",
                .{ domain_index, component_index, counts[0], counts[1] },
            );
        }
    }
}

pub fn copyPrefixTree(
    prefix: *prefix_runtime.OwnerV1,
    tree: usize,
    destination: [][]M31,
) !void {
    const source = try prefix.treeColumns(tree);
    if (source.len > destination.len)
        return error.DestinationShapeMismatch;
    for (source, destination[0..source.len]) |from, to| {
        if (from.len != to.len) return error.DestinationShapeMismatch;
        @memcpy(to, from);
    }
}

pub fn row35Columns(
    comptime count: usize,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: [][]M31,
) ![count][]M31 {
    const placement = manifest.placements[PROVIDER_ROW] orelse
        return error.ManifestGeometryMismatch;
    const offset = treeOffset(placement, tree);
    if (treeGeometryColumns(placement.geometry, tree) != count or
        offset + count > destination.len)
    {
        return error.ManifestGeometryMismatch;
    }
    var result: [count][]M31 = undefined;
    @memcpy(&result, destination[offset..][0..count]);
    return result;
}

pub fn generatedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-generated/v3\x00");
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.padding);
    hash.update(&value.cohort_id);
    hash.update(&value.manifest_seal);
    hash.update(&value.prefix.identity);
    hash.update(&value.suffix.identity);
    hash.update(&value.row35.identity);
    return hash.finalResult();
}

pub fn auditedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-audit/v3\x00");
    hash.update(&value.prefix.identity);
    hash.update(&value.suffix.identity);
    hash.update(&value.row35.identity);
    for (value.rows) |row| hashGlobalRowClaim(&hash, row);
    hash.update(&value.provider_claim.identity);
    hashBoundaryEvidence(&hash, value.wire_boundary);
    hashBoundaryEvidence(&hash, value.verifier_input_boundary);
    hash.update(&value.closure.closure_id);
    hash.update(&value.context.identity);
    return hash.finalResult();
}

fn hashGlobalRowClaim(
    hash: *std.crypto.hash.sha2.Sha256,
    row: global_closure.RowClaimsV1,
) void {
    hashInt(hash, u16, row.format_version);
    hashInt(hash, u8, row.present);
    hashInt(hash, u8, row.padding);
    hashInt(hash, u8, @intFromEnum(row.row));
    hashInt(hash, u8, row.domain_count);
    hash.update(&row.header_padding);
    for (row.domains) |domain| {
        hashInt(hash, u8, domain.present);
        hashInt(hash, u8, domain.active);
        hash.update(&domain.padding);
        hashInt(hash, u8, @intFromEnum(domain.domain));
        hashQm31(hash, domain.value);
    }
    hashQm31(hash, row.claimed_sum);
}

fn hashBoundaryEvidence(
    hash: *std.crypto.hash.sha2.Sha256,
    evidence: global_closure.BoundaryEvidenceV2,
) void {
    hash.update(&evidence.source_authority_id);
    hash.update(&evidence.snapshot_id);
    hash.update(&evidence.tuple_provenance_id);
    hashInt(hash, u32, evidence.tuple_count);
    hashQm31(hash, evidence.claimed_sum);
}

fn hashQm31(hash: *std.crypto.hash.sha2.Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

pub fn cohortIdentity(value: anytype, format_version: u16) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-cohort/v3\x00");
    hashInt(&hash, u16, format_version);
    hash.update(&value.manifest_value.seal);
    hash.update(&value.prefix.authority_sha_id);
    const suffix_id = value.suffix.authorityIdentity();
    hash.update(&suffix_id);
    hash.update(&value.verifier_input_source.identity);
    const row18_id = value.inputs.row18.authorityIdentity();
    hash.update(&row18_id);
    hash.update(&value.row35.identity);
    hash.update(&value.suffix.contextReceipt().identity);
    hash.update(&value.closure_authority.source_authority_id);
    hash.update(&value.closure_authority.provider_source_authority_id);
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
        var cells: usize = 0;
        for (manifest.roster_rows) |row| {
            const placement = manifest.placements[row].?;
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            cells = std.math.add(
                usize,
                cells,
                try std.math.mul(
                    usize,
                    rows,
                    treeGeometryColumns(placement.geometry, tree),
                ),
            ) catch return error.ArithmeticOverflow;
        }
        const storage = try allocator.alloc(M31, cells);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows) |row| {
            const placement = manifest.placements[row].?;
            const rows = @as(usize, 1) << @intCast(placement.geometry.log_size);
            const offset = treeOffset(placement, tree);
            const count = treeGeometryColumns(placement.geometry, tree);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[cursor..][0..rows];
                cursor += rows;
            }
        }
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
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
    for (manifest.roster_rows) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = treeGeometryColumns(placement.geometry, tree);
        const expected = @as(usize, 1) << @intCast(placement.geometry.log_size);
        for (destination[offset..][0..count]) |column| {
            if (column.len != expected) return error.DestinationShapeMismatch;
            for (column) |value| if (!value.isZero())
                return error.DestinationNotFresh;
        }
    }
    for (destination, 0..) |left, left_index| {
        const left_start = @intFromPtr(left.ptr);
        const left_end = left_start + left.len * @sizeOf(M31);
        for (destination[left_index + 1 ..]) |right| {
            const right_start = @intFromPtr(right.ptr);
            const right_end = right_start + right.len * @sizeOf(M31);
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
        value[index * 4 ..][0..4],
        .little,
    );
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
