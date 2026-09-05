//! Final common-fold closure over independently authenticated public inputs.
//!
//! The frozen binary closure consumes wire and verifier-input boundaries.
//! Common fold additionally supplies its field-public Poseidon caller and the
//! four non-verifier-input domains published by the authenticated suffix
//! fixed-wire authority. No claim in this module is selected from a residual.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_boundary =
    @import("recursive_common_fold_field_public_closure_v2.zig");
const suffix_boundary =
    @import("recursive_common_fold_suffix_input_boundary_v2.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const global_closure = frontend.recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.PROVIDER_DOMAIN);

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

const CLOSURE_DOMAIN =
    "stwo-zig/recursive-common-fold-suffix-closure/v2\x00";

pub const Error = field_boundary.Error || suffix_boundary.Error || error{
    CommonFoldSuffixClosureMismatch,
    RelationNotClosed,
};

pub const ClosureReceiptV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    input_identity_sha256: [32]u8,
    field_boundary_identity_sha256: [32]u8,
    suffix_boundary_identity_sha256: [32]u8,
    prefix_totals: [global_closure.DOMAIN_COUNT]QM31,
    closed_totals: [global_closure.DOMAIN_COUNT]QM31,
    framework_total: QM31,
    closure_id: [32]u8,

    pub fn validateAgainst(
        self: *const ClosureReceiptV2,
        input: *const global_closure.ClosureInputV2,
        field: *const field_boundary.BoundaryEvidenceV2,
        suffix: *const suffix_boundary.BoundaryEvidenceV2,
    ) !void {
        try field.validate();
        try suffix.validate();
        try validateVerifierBoundary(input, suffix);
        var prefix: [global_closure.DOMAIN_COUNT]QM31 =
            [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
        var framework = QM31.zero();
        for (input.rows) |row| {
            for (row.domains, 0..) |claim, index|
                prefix[index] = prefix[index].add(claim.value);
            framework = framework.add(row.claimed_sum);
        }
        var closed = prefix;
        addBaseBoundaries(&closed, &framework, input, field);
        try addSuffixBoundaries(&closed, &framework, suffix);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.input_identity_sha256,
                &input.identity,
            ) or !std.mem.eql(
            u8,
            &self.field_boundary_identity_sha256,
            &field.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.suffix_boundary_identity_sha256,
            &suffix.identity_sha256,
        ) or !qm31ArraysEql(&self.prefix_totals, &prefix) or
            !qm31ArraysEql(&self.closed_totals, &closed) or
            !self.framework_total.eql(framework) or
            !std.mem.eql(u8, &self.closure_id, &closureIdentity(self)))
        {
            return error.CommonFoldSuffixClosureMismatch;
        }
        for (closed) |value| if (!value.isZero())
            return error.RelationNotClosed;
        if (!framework.isZero()) return error.RelationNotClosed;
    }
};

pub fn close(
    prepared: *const global_closure.PreparedAuthorityV2,
    input: *const global_closure.ClosureInputV2,
    field: *const field_boundary.BoundaryEvidenceV2,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) !ClosureReceiptV2 {
    try input.validateAgainst(prepared);
    try field.validate();
    try suffix.validate();
    try validateVerifierBoundary(input, suffix);
    var result = ClosureReceiptV2{
        .input_identity_sha256 = input.identity,
        .field_boundary_identity_sha256 = field.identity_sha256,
        .suffix_boundary_identity_sha256 = suffix.identity_sha256,
        .prefix_totals = [_]QM31{QM31.zero()} **
            global_closure.DOMAIN_COUNT,
        .closed_totals = undefined,
        .framework_total = QM31.zero(),
        .closure_id = undefined,
    };
    for (input.rows) |row| {
        for (row.domains, 0..) |claim, index|
            result.prefix_totals[index] =
                result.prefix_totals[index].add(claim.value);
        result.framework_total = result.framework_total.add(row.claimed_sum);
    }
    result.closed_totals = result.prefix_totals;
    addBaseBoundaries(
        &result.closed_totals,
        &result.framework_total,
        input,
        field,
    );
    try addSuffixBoundaries(
        &result.closed_totals,
        &result.framework_total,
        suffix,
    );
    result.closure_id = closureIdentity(&result);
    try result.validateAgainst(input, field, suffix);
    return result;
}

/// Exact non-wire framework boundaries consumed by the composition graph.
/// The caller must first validate all three authorities. The verifier-input
/// suffix entry is deliberately skipped because the frozen V2 boundary is
/// already supplied separately.
pub fn frameworkBoundarySumExceptWireAssumeValidated(
    verifier_input_claimed_sum: QM31,
    field_public_claimed_sum: QM31,
    suffix_domains: *const [suffix_boundary.DOMAIN_COUNT]suffix_boundary.DomainEvidenceV2,
) QM31 {
    var result = verifier_input_claimed_sum.add(
        field_public_claimed_sum,
    );
    for (suffix_domains) |domain| {
        if (domain.domain == .recursion_verifier_input_word) continue;
        result = result.add(domain.claimed_sum);
    }
    return result;
}

/// Failure-only decomposition retaining every authenticated boundary term.
pub fn reportResidual(
    input: *const global_closure.ClosureInputV2,
    field: *const field_boundary.BoundaryEvidenceV2,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) void {
    var totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
    var framework = QM31.zero();
    for (input.rows) |row| {
        for (row.domains, 0..) |claim, index|
            totals[index] = totals[index].add(claim.value);
        framework = framework.add(row.claimed_sum);
    }
    addBaseBoundaries(&totals, &framework, input, field);
    addSuffixBoundaries(&totals, &framework, suffix) catch return;
    for (totals, 0..) |value, domain_index| {
        if (value.isZero()) continue;
        reportQm31(
            "COMMON_FOLD_CLOSURE_FINAL_RESIDUAL",
            null,
            domain_index,
            value,
        );
        for (input.rows) |row| {
            const term = row.domains[domain_index].value;
            if (!term.isZero()) reportQm31(
                "COMMON_FOLD_CLOSURE_ROW_TERM",
                @intFromEnum(row.row),
                domain_index,
                term,
            );
        }
        for (suffix.domains) |boundary| {
            if (@intFromEnum(boundary.domain) != domain_index) continue;
            reportQm31(
                "COMMON_FOLD_CLOSURE_SUFFIX_INPUT_BOUNDARY",
                null,
                domain_index,
                boundary.claimed_sum,
            );
        }
        if (domain_index == @intFromEnum(field.domain))
            reportQm31(
                "COMMON_FOLD_CLOSURE_FIELD_CALLER_BOUNDARY",
                null,
                domain_index,
                field.claimed_sum,
            );
    }
    if (!framework.isZero()) reportQm31(
        "COMMON_FOLD_CLOSURE_FRAMEWORK_RESIDUAL",
        null,
        0,
        framework,
    );
}

fn addBaseBoundaries(
    totals: *[global_closure.DOMAIN_COUNT]QM31,
    framework: *QM31,
    input: *const global_closure.ClosureInputV2,
    field: *const field_boundary.BoundaryEvidenceV2,
) void {
    totals[@intFromEnum(global_closure.PROVIDER_DOMAIN)] = totals[
        @intFromEnum(global_closure.PROVIDER_DOMAIN)
    ].add(input.provider_claim.claimed_sum);
    totals[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)] = totals[
        @intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)
    ].add(input.public_boundaries.wire.claimed_sum);
    totals[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)] =
        totals[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)]
            .add(input.public_boundaries.verifier_input.claimed_sum);
    totals[@intFromEnum(field.domain)] = totals[@intFromEnum(field.domain)]
        .add(field.claimed_sum);
    framework.* = framework.*
        .add(input.provider_claim.claimed_sum)
        .add(input.public_boundaries.claimedSum())
        .add(field.claimed_sum);
}

fn addSuffixBoundaries(
    totals: *[global_closure.DOMAIN_COUNT]QM31,
    framework: *QM31,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) !void {
    try suffix.validate();
    for (suffix.domains) |domain| {
        // recursion_verifier_input_word is already the frozen V2 public
        // boundary installed in `ClosureInputV2`.
        if (domain.domain == .recursion_verifier_input_word) continue;
        const index = @intFromEnum(domain.domain);
        totals[index] = totals[index].add(domain.claimed_sum);
        framework.* = framework.*.add(domain.claimed_sum);
    }
}

fn validateVerifierBoundary(
    input: *const global_closure.ClosureInputV2,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) !void {
    const expected = try suffix.verifierInputEvidence();
    const actual = input.public_boundaries.verifier_input;
    if (!std.mem.eql(
        u8,
        &actual.source_authority_id,
        &expected.source_authority_id,
    ) or !std.mem.eql(
        u8,
        &actual.snapshot_id,
        &expected.snapshot_id,
    ) or !std.mem.eql(
        u8,
        &actual.tuple_provenance_id,
        &expected.tuple_provenance_id,
    ) or actual.tuple_count != expected.tuple_count or
        !actual.claimed_sum.eql(expected.claimed_sum))
    {
        return error.CommonFoldSuffixClosureMismatch;
    }
}

fn closureIdentity(value: *const ClosureReceiptV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.input_identity_sha256);
    hash.update(&value.field_boundary_identity_sha256);
    hash.update(&value.suffix_boundary_identity_sha256);
    for (value.prefix_totals) |claim| hashQm31(&hash, claim);
    for (value.closed_totals) |claim| hashQm31(&hash, claim);
    hashQm31(&hash, value.framework_total);
    return hash.finalResult();
}

fn qm31ArraysEql(left: anytype, right: anytype) bool {
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn reportQm31(
    label: []const u8,
    row: ?usize,
    domain: usize,
    value: QM31,
) void {
    const limbs = value.toM31Array();
    if (row) |row_index| {
        std.debug.print(
            "{s} row={d} domain={d} value={d},{d},{d},{d}\n",
            .{ label, row_index, domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() },
        );
    } else {
        std.debug.print(
            "{s} domain={d} value={d},{d},{d},{d}\n",
            .{ label, domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() },
        );
    }
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1)
        @compileError("common-fold suffix closure contract drifted");
}
