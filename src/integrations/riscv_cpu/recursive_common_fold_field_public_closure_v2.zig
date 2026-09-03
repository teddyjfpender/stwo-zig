//! Authenticated caller-side closure for the common-fold field-public hashes.
//!
//! Row 34 owns one combined Poseidon provider trace. Its prefix is the exact
//! 116-call parent-public schedule, while rows 18--33 own only the verifier
//! core callers. This module independently replays that authenticated prefix
//! and publishes its caller-side `poseidon2_io` boundary. The value is never
//! derived from a closure residual.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public = @import("recursive_common_fold_field_public_v2.zig");
const schedule_mod = @import("recursive_common_fold_poseidon_schedule_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const recursion = frontend.recursion;
const provider = recursion.air.universal_shared_provider;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.PROVIDER_DOMAIN);

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FIELD_PUBLIC_DOMAIN: RelationDomain = .poseidon2_io;
pub const CALL_COUNT: usize = field_public.POSEIDON_CALL_COUNT;

const BOUNDARY_DOMAIN =
    "stwo-zig/recursive-common-fold-field-public-boundary/v2\x00";
const CLOSURE_DOMAIN =
    "stwo-zig/recursive-common-fold-field-public-closure/v2\x00";

pub const Error = schedule_mod.Error || provider.Error || error{
    CommonFoldFieldBoundaryMismatch,
    CommonFoldFieldBoundaryPoseidonMismatch,
    RelationNotClosed,
};

/// Pointer-free evidence derived from the exact authenticated call prefix.
pub const BoundaryEvidenceV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    domain: RelationDomain = FIELD_PUBLIC_DOMAIN,
    tuple_count: u32 = CALL_COUNT,
    provider_log_size: u32,
    source_authority_identity_sha256: [32]u8,
    layout_identity_sha256: [32]u8,
    call_buffer_identity_sha256: [32]u8,
    provider_relations_identity_sha256: [32]u8,
    provider_poseidon2_claim: QM31,
    provider_poseidon2_io_claim: QM31,
    claimed_sum: QM31,
    identity_sha256: [32]u8,

    pub fn validate(self: *const BoundaryEvidenceV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.domain != FIELD_PUBLIC_DOMAIN or
            self.tuple_count != CALL_COUNT or
            self.provider_log_size < field_public.MINIMUM_POSEIDON_LOG_SIZE or
            std.mem.allEqual(
                u8,
                &self.source_authority_identity_sha256,
                0,
            ) or std.mem.allEqual(u8, &self.layout_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.call_buffer_identity_sha256, 0) or
            std.mem.allEqual(
                u8,
                &self.provider_relations_identity_sha256,
                0,
            ) or !self.provider_poseidon2_claim.isZero() or
            !self.provider_poseidon2_io_claim.add(self.claimed_sum).isZero() or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &boundaryIdentity(self),
            )) return error.CommonFoldFieldBoundaryMismatch;
    }

    pub fn validateAgainst(
        self: *const BoundaryEvidenceV2,
        calls: []const poseidon_air.Call,
        layout: *const schedule_mod.Layout,
        source_authority_identity_sha256: [32]u8,
        provider_log_size: u32,
        provider_relations: *const provider.SharedProviderRelations,
    ) !void {
        const expected = try derive(
            calls,
            layout,
            source_authority_identity_sha256,
            provider_log_size,
            provider_relations,
        );
        if (!boundaryEql(self, &expected))
            return error.CommonFoldFieldBoundaryMismatch;
    }
};

/// Common-fold-specific successful closure. The generic binary closure keeps
/// its frozen two-boundary contract; this receipt adds only the independently
/// authenticated field-public source.
pub const ClosureReceiptV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    input_identity_sha256: [32]u8,
    field_boundary_identity_sha256: [32]u8,
    prefix_totals: [global_closure.DOMAIN_COUNT]QM31,
    closed_totals: [global_closure.DOMAIN_COUNT]QM31,
    framework_total: QM31,
    closure_id: [32]u8,

    pub fn validateAgainst(
        self: *const ClosureReceiptV2,
        input: *const global_closure.ClosureInputV2,
        boundary: *const BoundaryEvidenceV2,
    ) !void {
        try boundary.validate();
        var prefix: [global_closure.DOMAIN_COUNT]QM31 =
            [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
        var framework = QM31.zero();
        for (input.rows) |row| {
            for (row.domains, 0..) |claim, index|
                prefix[index] = prefix[index].add(claim.value);
            framework = framework.add(row.claimed_sum);
        }
        var closed = prefix;
        closed[@intFromEnum(global_closure.PROVIDER_DOMAIN)] = closed[
            @intFromEnum(global_closure.PROVIDER_DOMAIN)
        ].add(input.provider_claim.claimed_sum);
        closed[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)] = closed[
            @intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)
        ].add(input.public_boundaries.wire.claimed_sum);
        closed[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)] =
            closed[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)]
                .add(input.public_boundaries.verifier_input.claimed_sum);
        closed[@intFromEnum(FIELD_PUBLIC_DOMAIN)] = closed[
            @intFromEnum(FIELD_PUBLIC_DOMAIN)
        ].add(boundary.claimed_sum);
        framework = framework
            .add(input.provider_claim.claimed_sum)
            .add(input.public_boundaries.claimedSum())
            .add(boundary.claimed_sum);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.input_identity_sha256,
                &input.identity,
            ) or !std.mem.eql(
            u8,
            &self.field_boundary_identity_sha256,
            &boundary.identity_sha256,
        ) or !qm31ArraysEql(&self.prefix_totals, &prefix) or
            !qm31ArraysEql(&self.closed_totals, &closed) or
            !self.framework_total.eql(framework) or
            !std.mem.eql(
                u8,
                &self.closure_id,
                &closureIdentity(self),
            )) return error.CommonFoldFieldBoundaryMismatch;
        for (closed) |value| if (!value.isZero())
            return error.RelationNotClosed;
        if (!framework.isZero()) return error.RelationNotClosed;
    }
};

pub fn derive(
    calls: []const poseidon_air.Call,
    layout: *const schedule_mod.Layout,
    source_authority_identity_sha256: [32]u8,
    provider_log_size: u32,
    provider_relations: *const provider.SharedProviderRelations,
) !BoundaryEvidenceV2 {
    try layout.validate(calls);
    try provider_relations.validate();
    if (calls.len != CALL_COUNT or
        std.mem.allEqual(u8, &source_authority_identity_sha256, 0))
    {
        return error.CommonFoldFieldBoundaryMismatch;
    }
    var outputs: [CALL_COUNT][poseidon_air.WIDTH]u32 = undefined;
    for (calls, &outputs) |call, *output| {
        if (call.wide or !call.io or call.narrow_output != null)
            return error.CommonFoldFieldBoundaryMismatch;
        var state: poseidon.State = undefined;
        for (&state, call.input) |*destination, word|
            destination.* = M31.fromCanonical(word);
        poseidon.permute(&state);
        for (output, state) |*destination, word|
            destination.* = word.toU32();
    }
    const claims = try poseidon_air.claimsFromIoOutputs(
        calls,
        &outputs,
        provider_log_size,
        &provider_relations.native,
    );
    if (!claims.sums[0].isZero())
        return error.CommonFoldFieldBoundaryPoseidonMismatch;
    var result = BoundaryEvidenceV2{
        .provider_log_size = provider_log_size,
        .source_authority_identity_sha256 = source_authority_identity_sha256,
        .layout_identity_sha256 = layout.identity,
        .call_buffer_identity_sha256 = schedule_mod.callBufferIdentity(calls),
        .provider_relations_identity_sha256 = try provider_relations.identityDigest(),
        .provider_poseidon2_claim = claims.sums[0],
        .provider_poseidon2_io_claim = claims.sums[1],
        .claimed_sum = claims.sums[1].neg(),
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = boundaryIdentity(&result);
    try result.validate();
    return result;
}

pub fn close(
    prepared: *const global_closure.PreparedAuthorityV2,
    input: *const global_closure.ClosureInputV2,
    boundary: *const BoundaryEvidenceV2,
) !ClosureReceiptV2 {
    try input.validateAgainst(prepared);
    try boundary.validate();
    var result = ClosureReceiptV2{
        .input_identity_sha256 = input.identity,
        .field_boundary_identity_sha256 = boundary.identity_sha256,
        .prefix_totals = undefined,
        .closed_totals = undefined,
        .framework_total = undefined,
        .closure_id = undefined,
    };
    result.prefix_totals = [_]QM31{QM31.zero()} **
        global_closure.DOMAIN_COUNT;
    result.framework_total = QM31.zero();
    for (input.rows) |row| {
        for (row.domains, 0..) |claim, index|
            result.prefix_totals[index] =
                result.prefix_totals[index].add(claim.value);
        result.framework_total = result.framework_total.add(row.claimed_sum);
    }
    result.closed_totals = result.prefix_totals;
    result.closed_totals[@intFromEnum(global_closure.PROVIDER_DOMAIN)] =
        result.closed_totals[@intFromEnum(global_closure.PROVIDER_DOMAIN)]
            .add(input.provider_claim.claimed_sum);
    result.closed_totals[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)] =
        result.closed_totals[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)]
            .add(input.public_boundaries.wire.claimed_sum);
    result.closed_totals[
        @intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)
    ] = result.closed_totals[
        @intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)
    ].add(input.public_boundaries.verifier_input.claimed_sum);
    result.closed_totals[@intFromEnum(FIELD_PUBLIC_DOMAIN)] =
        result.closed_totals[@intFromEnum(FIELD_PUBLIC_DOMAIN)]
            .add(boundary.claimed_sum);
    result.framework_total = result.framework_total
        .add(input.provider_claim.claimed_sum)
        .add(input.public_boundaries.claimedSum())
        .add(boundary.claimed_sum);
    result.closure_id = closureIdentity(&result);
    try result.validateAgainst(input, boundary);
    return result;
}

/// Failure-only decomposition. It reports both the historical two-boundary
/// residual and the final residual after the authenticated field boundary.
pub fn reportResidual(
    input: *const global_closure.ClosureInputV2,
    boundary: *const BoundaryEvidenceV2,
) void {
    var base = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
    for (input.rows) |row| {
        for (row.domains, 0..) |claim, index|
            base[index] = base[index].add(claim.value);
    }
    base[@intFromEnum(global_closure.PROVIDER_DOMAIN)] = base[
        @intFromEnum(global_closure.PROVIDER_DOMAIN)
    ].add(input.provider_claim.claimed_sum);
    base[@intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)] = base[
        @intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN)
    ].add(input.public_boundaries.wire.claimed_sum);
    base[@intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)] = base[
        @intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN)
    ].add(input.public_boundaries.verifier_input.claimed_sum);
    var final = base;
    final[@intFromEnum(FIELD_PUBLIC_DOMAIN)] = final[
        @intFromEnum(FIELD_PUBLIC_DOMAIN)
    ].add(boundary.claimed_sum);
    for (base, final, 0..) |base_value, final_value, domain_index| {
        if (base_value.isZero() and final_value.isZero()) continue;
        reportQm31("COMMON_FOLD_CLOSURE_BASE_RESIDUAL", null, domain_index, base_value);
        reportQm31("COMMON_FOLD_CLOSURE_FINAL_RESIDUAL", null, domain_index, final_value);
        for (input.rows) |row| {
            const term = row.domains[domain_index].value;
            if (!term.isZero()) reportQm31(
                "COMMON_FOLD_CLOSURE_ROW_TERM",
                @intFromEnum(row.row),
                domain_index,
                term,
            );
        }
        if (domain_index == @intFromEnum(global_closure.PROVIDER_DOMAIN))
            reportQm31("COMMON_FOLD_CLOSURE_RANGE_PROVIDER", null, domain_index, input.provider_claim.claimed_sum);
        if (domain_index == @intFromEnum(global_closure.WIRE_BOUNDARY_DOMAIN))
            reportQm31("COMMON_FOLD_CLOSURE_WIRE_BOUNDARY", null, domain_index, input.public_boundaries.wire.claimed_sum);
        if (domain_index == @intFromEnum(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN))
            reportQm31("COMMON_FOLD_CLOSURE_VERIFIER_BOUNDARY", null, domain_index, input.public_boundaries.verifier_input.claimed_sum);
        if (domain_index == @intFromEnum(FIELD_PUBLIC_DOMAIN)) {
            reportQm31("COMMON_FOLD_CLOSURE_FIELD_PROVIDER_PREFIX", null, domain_index, boundary.provider_poseidon2_io_claim);
            reportQm31("COMMON_FOLD_CLOSURE_FIELD_CALLER_BOUNDARY", null, domain_index, boundary.claimed_sum);
        }
    }
}

fn boundaryIdentity(value: *const BoundaryEvidenceV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.domain));
    hashInt(&hash, u32, value.tuple_count);
    hashInt(&hash, u32, value.provider_log_size);
    hash.update(&value.source_authority_identity_sha256);
    hash.update(&value.layout_identity_sha256);
    hash.update(&value.call_buffer_identity_sha256);
    hash.update(&value.provider_relations_identity_sha256);
    hashQm31(&hash, value.provider_poseidon2_claim);
    hashQm31(&hash, value.provider_poseidon2_io_claim);
    hashQm31(&hash, value.claimed_sum);
    return hash.finalResult();
}

fn closureIdentity(value: *const ClosureReceiptV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.input_identity_sha256);
    hash.update(&value.field_boundary_identity_sha256);
    for (value.prefix_totals) |claim| hashQm31(&hash, claim);
    for (value.closed_totals) |claim| hashQm31(&hash, claim);
    hashQm31(&hash, value.framework_total);
    return hash.finalResult();
}

fn boundaryEql(left: *const BoundaryEvidenceV2, right: *const BoundaryEvidenceV2) bool {
    return std.meta.eql(left.*, right.*);
}

fn qm31ArraysEql(left: anytype, right: anytype) bool {
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn reportQm31(label: []const u8, row: ?usize, domain: usize, value: QM31) void {
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CALL_COUNT != 116 or
        FIELD_PUBLIC_DOMAIN != .poseidon2_io)
    {
        @compileError("common-fold field-public closure contract drifted");
    }
}

test "common-fold field-public boundary is replay-derived and closes only its IO claim" {
    var calls = [_]poseidon_air.Call{.{
        .input = [_]u32{0} ** poseidon_air.WIDTH,
        .io = true,
    }} ** CALL_COUNT;
    for (&calls, 0..) |*call, index|
        call.input[0] = @intCast(index + 1);
    const layout = try schedule_mod.Layout.initBoundary(&calls);
    const relations = recursion.air.universal_challenges
        .UniversalRelations.dummy();
    const provider_relations = try provider.SharedProviderRelations.init(
        &relations,
    );
    const source_identity = [_]u8{0x5a} ** 32;
    const boundary = try derive(
        &calls,
        &layout,
        source_identity,
        field_public.MINIMUM_POSEIDON_LOG_SIZE,
        &provider_relations,
    );
    try std.testing.expect(boundary.provider_poseidon2_claim.isZero());
    try std.testing.expect(boundary.provider_poseidon2_io_claim.add(
        boundary.claimed_sum,
    ).isZero());

    var forged = boundary;
    forged.claimed_sum = forged.claimed_sum.add(QM31.one());
    try std.testing.expectError(
        error.CommonFoldFieldBoundaryMismatch,
        forged.validate(),
    );

    var changed_calls = calls;
    changed_calls[17].input[3] = 1;
    const changed_layout = try schedule_mod.Layout.initBoundary(&changed_calls);
    try std.testing.expectError(
        error.CommonFoldFieldBoundaryMismatch,
        boundary.validateAgainst(
            &changed_calls,
            &changed_layout,
            source_identity,
            field_public.MINIMUM_POSEIDON_LOG_SIZE,
            &provider_relations,
        ),
    );
}
