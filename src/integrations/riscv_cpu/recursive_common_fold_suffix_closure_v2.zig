//! Common-fold closure over verifier-owned public inputs.
//! The binary wire/verifier-input boundaries, published parent words and the
//! remaining native suffix inputs are all explicit. No boundary is derived
//! from a residual, and parent hash calls are balanced by committed AIRs.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_boundary =
    @import("recursive_common_fold_public_output_v3.zig");
const suffix_boundary =
    @import("recursive_common_fold_suffix_input_boundary_v2.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const global_closure = frontend.recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.PROVIDER_DOMAIN);

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 5;

const CLOSURE_DOMAIN =
    "stwo-zig/recursive-common-fold-suffix-closure/v2\x00";

pub const Error = field_boundary.Error || suffix_boundary.Error || error{
    CommonFoldSuffixClosureMismatch,
    RelationNotClosed,
};

/// Common-fold input: anchors are internal; remaining suffix boundaries may
/// be empty. The shared row/provider contract is reused without weakening V2.
pub const Input = struct {
    rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
    provider_claim: global_closure.ProviderClaimV1,
    wire_anchors: global_closure.BoundaryEvidenceV2,
    identity: [32]u8,

    pub fn init(
        rows: *const [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
        provider: *const global_closure.ProviderClaimV1,
        wire: global_closure.BoundaryEvidenceV2,
    ) !Input {
        const prepared = try global_closure.prepareAuthority();
        const checked = try global_closure.preflightInputs(&prepared, rows, provider);
        const anchor = try global_closure.BoundarySourceV2.init(.wire, wire);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/common-fold-closure-input/v1\x00");
        hash.update(&checked.input_id);
        hash.update(&anchor.identity);
        return .{ .rows = rows.*, .provider_claim = provider.*, .wire_anchors = wire, .identity = hash.finalResult() };
    }

    pub fn validate(self: *const Input) !void {
        const expected = try init(&self.rows, &self.provider_claim, self.wire_anchors);
        if (!std.mem.eql(u8, &self.identity, &expected.identity)) return error.CommonFoldSuffixClosureMismatch;
    }
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
        input: *const Input,
        field: *const field_boundary.BoundaryEvidenceV3,
        suffix: *const suffix_boundary.BoundaryEvidenceV2,
    ) !void {
        try input.validate();
        try field.validate();
        try suffix.validate();
        try validateWireAnchors(input);
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
    input: *const Input,
    field: *const field_boundary.BoundaryEvidenceV3,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) !ClosureReceiptV2 {
    try input.validate();
    try field.validate();
    try suffix.validate();
    try validateWireAnchors(input);
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

/// Every remaining suffix contribution is included once, including an empty
/// verifier-input boundary. These authorities must already be validated.
pub fn frameworkBoundarySumExceptWireAssumeValidated(
    field_public_claimed_sum: QM31,
    suffix_domains: *const [suffix_boundary.DOMAIN_COUNT]suffix_boundary.DomainEvidenceV2,
) QM31 {
    var result = field_public_claimed_sum;
    for (suffix_domains) |domain| result = result.add(domain.claimed_sum);
    return result;
}

/// Failure-only decomposition retaining every authenticated boundary term.
pub fn reportResidual(
    input: *const Input,
    field: *const field_boundary.BoundaryEvidenceV3,
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
    input: *const Input,
    field: *const field_boundary.BoundaryEvidenceV3,
) void {
    totals[@intFromEnum(global_closure.PROVIDER_DOMAIN)] = totals[
        @intFromEnum(global_closure.PROVIDER_DOMAIN)
    ].add(input.provider_claim.claimed_sum);
    totals[@intFromEnum(field.domain)] = totals[@intFromEnum(field.domain)]
        .add(field.claimed_sum);
    framework.* = framework.*
        .add(input.provider_claim.claimed_sum)
        .add(field.claimed_sum);
}

fn addSuffixBoundaries(
    totals: *[global_closure.DOMAIN_COUNT]QM31,
    framework: *QM31,
    suffix: *const suffix_boundary.BoundaryEvidenceV2,
) !void {
    try suffix.validate();
    for (suffix.domains) |domain| {
        const index = @intFromEnum(domain.domain);
        totals[index] = totals[index].add(domain.claimed_sum);
        framework.* = framework.*.add(domain.claimed_sum);
    }
}

fn validateWireAnchors(input: *const Input) !void {
    const row = input.rows[10];
    const expected = input.wire_anchors.claimed_sum;
    if (!row.claimed_sum.eql(expected.add(row.domains[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)].value)) or
        !row.domains[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)].value.eql(expected))
        return error.CommonFoldSuffixClosureMismatch;
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 5)
        @compileError("common-fold suffix closure contract drifted");
}
