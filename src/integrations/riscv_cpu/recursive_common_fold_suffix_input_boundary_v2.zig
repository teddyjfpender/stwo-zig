//! Authenticated public inputs consumed by the common-fold verifier suffix.
//!
//! The field-native common fold deliberately has no legacy rows-0--17
//! transcript implementation. Rows 18--33 nevertheless consume the exact
//! child proof statement, transcript randomness, relation challenges, and
//! verifier control schedule. This module publishes those values from the
//! already authenticated fixed-wire source. It never observes a closure
//! residual: every producer tuple is reconstructed from the sealed relation
//! plan and retained source row that owns the corresponding consumer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.PROVIDER_DOMAIN);

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const DOMAIN_COUNT: usize = 5;

pub const DOMAINS = [DOMAIN_COUNT]RelationDomain{
    .recursion_step,
    .recursion_verifier_input_word,
    .recursion_relation_challenge_word,
    .recursion_verifier_randomness_word,
    .recursion_statement_word,
};

/// Exact suffix consumers whose matching producer is external to rows 18--33.
/// These masks are protocol data, not observations from a failed closure.
pub const ROW_MASKS = [DOMAIN_COUNT]u64{
    rowMask(&.{ 19, 23, 27, 28 }),
    rowMask(&.{ 18, 22, 24, 29 }),
    rowMask(&.{18}),
    rowMask(&.{ 18, 20, 24, 29 }),
    rowMask(&.{18}),
};

const BOUNDARY_DOMAIN =
    "stwo-zig/recursive-common-fold-suffix-input-boundary/v2\x00";
const DOMAIN_PROVENANCE =
    "stwo-zig/recursive-common-fold-suffix-domain-tuples/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    CommonFoldSuffixBoundaryMismatch,
    CommonFoldSuffixBoundaryPolicyMismatch,
    ZeroDenominator,
};

pub const DomainEvidenceV2 = struct {
    domain: RelationDomain,
    source_row_mask: u64,
    tuple_count: u32,
    claimed_sum: QM31,
    tuple_provenance_sha256: [32]u8,

    pub fn validate(
        self: *const DomainEvidenceV2,
        ordinal: usize,
    ) !void {
        if (ordinal >= DOMAIN_COUNT or self.domain != DOMAINS[ordinal] or
            self.source_row_mask != ROW_MASKS[ordinal] or
            self.tuple_count == 0 or
            std.mem.allEqual(u8, &self.tuple_provenance_sha256, 0))
        {
            return error.CommonFoldSuffixBoundaryMismatch;
        }
        try requireCanonical(self.claimed_sum);
    }
};

/// Pointer-free evidence. Fresh/cold verifier admission rederives it from the
/// live fixed-wire owner; this value alone grants no capability.
pub const BoundaryEvidenceV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source_authority_identity_sha256: [32]u8,
    relation_rows_identity_sha256: [32]u8,
    domains: [DOMAIN_COUNT]DomainEvidenceV2,
    identity_sha256: [32]u8,

    pub fn validate(self: *const BoundaryEvidenceV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            std.mem.allEqual(
                u8,
                &self.source_authority_identity_sha256,
                0,
            ) or std.mem.allEqual(
            u8,
            &self.relation_rows_identity_sha256,
            0,
        )) return error.CommonFoldSuffixBoundaryMismatch;
        for (&self.domains, 0..) |*domain, ordinal|
            try domain.validate(ordinal);
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &boundaryIdentity(self),
        )) return error.CommonFoldSuffixBoundaryMismatch;
    }

    pub fn verifierInputEvidence(
        self: *const BoundaryEvidenceV2,
    ) !global_closure.BoundaryEvidenceV2 {
        try self.validate();
        const evidence = self.domains[
            domainIndex(
                .recursion_verifier_input_word,
            ).?
        ];
        return .{
            .source_authority_id = self.source_authority_identity_sha256,
            .snapshot_id = self.relation_rows_identity_sha256,
            .tuple_provenance_id = evidence.tuple_provenance_sha256,
            .tuple_count = evidence.tuple_count,
            .claimed_sum = evidence.claimed_sum,
        };
    }

    pub fn claim(
        self: *const BoundaryEvidenceV2,
        domain: RelationDomain,
    ) !QM31 {
        try self.validate();
        const ordinal = domainIndex(domain) orelse
            return error.CommonFoldSuffixBoundaryPolicyMismatch;
        return self.domains[ordinal].claimed_sum;
    }

    pub fn validateAgainst(
        self: *const BoundaryEvidenceV2,
        source: anytype,
        rows: anytype,
        relations: *const universal.UniversalRelations,
    ) !void {
        const expected = try derive(source, rows, relations);
        if (!std.meta.eql(self.*, expected))
            return error.CommonFoldSuffixBoundaryMismatch;
    }
};

const Accumulator = struct {
    tuple_count: u32 = 0,
    observed_row_mask: u64 = 0,
    claimed_sum: QM31 = QM31.zero(),
    provenance: std.crypto.hash.sha2.Sha256,
};

pub fn derive(
    source: anytype,
    rows: anytype,
    relations: *const universal.UniversalRelations,
) !BoundaryEvidenceV2 {
    try source.requireFullBundleAuthority();
    try rows.validateReadyFor(source);
    try relations.validate();

    var accumulators: [DOMAIN_COUNT]Accumulator = undefined;
    for (&accumulators, 0..) |*accumulator, ordinal| {
        accumulator.* = .{
            .provenance = std.crypto.hash.sha2.Sha256.init(.{}),
        };
        accumulator.provenance.update(DOMAIN_PROVENANCE);
        hashInt(&accumulator.provenance, u16, FORMAT_VERSION);
        hashInt(&accumulator.provenance, u16, SCHEMA_VERSION);
        hashInt(
            &accumulator.provenance,
            u8,
            @intFromEnum(DOMAINS[ordinal]),
        );
        hashInt(&accumulator.provenance, u64, ROW_MASKS[ordinal]);
        accumulator.provenance.update(&source.source_authority_digest);
        accumulator.provenance.update(&rows.authority_digest);
    }

    const composition = source.composition_rows orelse
        return error.CommonFoldSuffixBoundaryMismatch;
    const arithmetic = source.arithmetic_rows orelse
        return error.CommonFoldSuffixBoundaryMismatch;
    try visitPlan(
        &accumulators,
        &composition.input_relation,
        rows.composition_input,
        18,
        relations,
    );
    try visitPlan(
        &accumulators,
        &composition.control_relation,
        rows.composition_control,
        19,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.query_bits_relation,
        rows.query_bits,
        20,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.query_mapping_relation,
        rows.query_mapping,
        21,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.merkle_root_relation,
        rows.merkle_root,
        22,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.trace_merkle_relation,
        rows.trace_merkle,
        23,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.pcs_relation,
        rows.pcs_deep,
        24,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.fri_leaf_relation,
        rows.fri_leaf,
        25,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.fri_node_relation,
        rows.fri_node,
        26,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.fri_anchor_relation,
        rows.fri_anchor,
        27,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.control_relation,
        rows.fri_control,
        28,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.fri_rows.input_relation,
        rows.fri_input,
        29,
        relations,
    );
    try visitPlan(
        &accumulators,
        &arithmetic.multiply_relation,
        rows.multiply,
        30,
        relations,
    );
    try visitPlan(
        &accumulators,
        &arithmetic.inverse_relation,
        rows.inverse,
        31,
        relations,
    );
    try visitPlan(
        &accumulators,
        &arithmetic.linear_relation,
        rows.linear,
        32,
        relations,
    );
    try visitPlan(
        &accumulators,
        &source.merkle_rows.relation,
        rows.merkle_path,
        33,
        relations,
    );

    var result = BoundaryEvidenceV2{
        .source_authority_identity_sha256 = source.source_authority_digest,
        .relation_rows_identity_sha256 = rows.authority_digest,
        .domains = undefined,
        .identity_sha256 = undefined,
    };
    for (&result.domains, &accumulators, 0..) |
        *destination,
        *accumulator,
        ordinal,
    | {
        if (accumulator.tuple_count == 0 or
            accumulator.observed_row_mask != ROW_MASKS[ordinal])
        {
            return error.CommonFoldSuffixBoundaryPolicyMismatch;
        }
        hashInt(&accumulator.provenance, u32, accumulator.tuple_count);
        destination.* = .{
            .domain = DOMAINS[ordinal],
            .source_row_mask = accumulator.observed_row_mask,
            .tuple_count = accumulator.tuple_count,
            .claimed_sum = accumulator.claimed_sum,
            .tuple_provenance_sha256 = accumulator.provenance.finalResult(),
        };
    }
    result.identity_sha256 = boundaryIdentity(&result);
    try result.validate();
    return result;
}

fn visitPlan(
    accumulators: *[DOMAIN_COUNT]Accumulator,
    plan: anytype,
    rows: anytype,
    component_row: u8,
    relations: *const universal.UniversalRelations,
) !void {
    const component_bit = @as(u64, 1) << @as(u6, @intCast(component_row));
    for (accumulators, 0..) |*accumulator, ordinal| {
        if (ROW_MASKS[ordinal] & component_bit == 0) continue;
        hashInt(&accumulator.provenance, u8, component_row);
        accumulator.provenance.update(&plan.semantic_digest);
        accumulator.provenance.update(&plan.registry_order_digest);
    }
    for (rows) |row| {
        const entries = plan.preparedEntries(row);
        for (entries) |entry| {
            const ordinal = domainIndex(entry.domain) orelse continue;
            try accumulateEntry(
                &accumulators[ordinal],
                ordinal,
                entry,
                component_bit,
                relations,
            );
        }
    }
}

fn accumulateEntry(
    accumulator: *Accumulator,
    ordinal: usize,
    entry: anytype,
    component_bit: u64,
    relations: *const universal.UniversalRelations,
) !void {
    if (ordinal >= DOMAIN_COUNT or entry.domain != DOMAINS[ordinal] or
        ROW_MASKS[ordinal] & component_bit == 0 or entry.role != .consume)
    {
        return error.CommonFoldSuffixBoundaryPolicyMismatch;
    }
    if (entry.numerator.isZero()) return;
    const denominator = try entry.denominator(relations);
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    const producer = entry.numerator.neg().mul(inverse);
    accumulator.claimed_sum = accumulator.claimed_sum.add(producer);
    accumulator.tuple_count = std.math.add(
        u32,
        accumulator.tuple_count,
        1,
    ) catch return error.ArithmeticOverflow;
    accumulator.observed_row_mask |= component_bit;
}

fn domainIndex(domain: RelationDomain) ?usize {
    return switch (domain) {
        .recursion_step => 0,
        .recursion_verifier_input_word => 1,
        .recursion_relation_challenge_word => 2,
        .recursion_verifier_randomness_word => 3,
        .recursion_statement_word => 4,
        else => null,
    };
}

fn boundaryIdentity(value: *const BoundaryEvidenceV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.source_authority_identity_sha256);
    hash.update(&value.relation_rows_identity_sha256);
    for (value.domains) |domain| {
        hashInt(&hash, u8, @intFromEnum(domain.domain));
        hashInt(&hash, u64, domain.source_row_mask);
        hashInt(&hash, u32, domain.tuple_count);
        hashQm31(&hash, domain.claimed_sum);
        hash.update(&domain.tuple_provenance_sha256);
    }
    return hash.finalResult();
}

fn requireCanonical(value: QM31) !void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= stwo_core.fields.m31.Modulus)
            return error.CommonFoldSuffixBoundaryMismatch;
}

fn rowMask(comptime rows: []const u8) u64 {
    var result: u64 = 0;
    for (rows) |row| result |= @as(u64, 1) << @as(u6, @intCast(row));
    return result;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or DOMAIN_COUNT != 5 or
        DOMAINS[0] != .recursion_step or
        DOMAINS[1] != .recursion_verifier_input_word or
        DOMAINS[2] != .recursion_relation_challenge_word or
        DOMAINS[3] != .recursion_verifier_randomness_word or
        DOMAINS[4] != .recursion_statement_word)
    {
        @compileError("common-fold suffix boundary contract drifted");
    }
}

test "suffix input producer is tuple-derived and policy rejects wrong role" {
    const Entry = recursion.air.relation_interaction.Entry;
    const relations = universal.UniversalRelations.dummy();
    var accumulator = Accumulator{
        .provenance = std.crypto.hash.sha2.Sha256.init(.{}),
    };
    var entry = Entry{
        .ordinal = 0,
        .schema = @enumFromInt(0),
        .schema_version = 1,
        .domain = .recursion_step,
        .role = .consume,
        .numerator = QM31.one().neg(),
        .values = [_]QM31{QM31.zero()} ** universal.MAX_ARITY,
        .arity = 7,
    };
    for (entry.values[0..entry.arity], 0..) |*word, index|
        word.* = QM31.fromBase(stwo_core.fields.m31.M31.fromCanonical(
            @intCast(index + 1),
        ));
    const denominator = try entry.denominator(&relations);
    const consumer = entry.numerator.mul(try denominator.inv());
    const row_bit = @as(u64, 1) << 19;
    try accumulateEntry(&accumulator, 0, entry, row_bit, &relations);
    try std.testing.expect(consumer.add(accumulator.claimed_sum).isZero());
    try std.testing.expectEqual(@as(u32, 1), accumulator.tuple_count);
    try std.testing.expectEqual(row_bit, accumulator.observed_row_mask);

    entry.role = .emit;
    try std.testing.expectError(
        error.CommonFoldSuffixBoundaryPolicyMismatch,
        accumulateEntry(&accumulator, 0, entry, row_bit, &relations),
    );
}
