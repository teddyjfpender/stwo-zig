//! Algebraic padding and fixed-public-output contract for common wrappers.
//!
//! The functions in this module record equations into a caller-supplied
//! symbolic sink. They never accept a host-side zeroing result as authority.
//! Role-specific verifier circuits must supply the `derived` NodePublic side;
//! this contract binds every public field to that side and exposes the absent
//! hash/source authorities separately.

const std = @import("std");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const manifest_mod = @import("recursive_common_wrapper_manifest_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const NODE_PUBLIC_OWNER_COMPONENT: u8 = 0;
pub const IDENTITY_FIELD_COUNT: usize = 4;
pub const IDENTITY_BYTE_COUNT: usize = 32;
pub const IDENTITY_BIT_COUNT: usize = 8;

const COMPONENT_DOMAIN =
    "stwo-zig/recursive-common-wrapper-component-padding/v1\x00";

pub const Error = manifest_mod.Error || error{
    ArithmeticOverflow,
    InvalidComponentPaddingContract,
    InvalidConstraintShape,
    InvalidNodePublicConstraintShape,
};

/// This value becomes a circuit constant and is covered by the circuit and
/// preprocessed-root identities. Its constructor is not a cold-proof mint.
pub const ComponentContractV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    role: manifest_mod.WrapperRoleV1,
    component_ordinal: u8,
    binds_node_public: bool,
    reserved: [3]u8 = .{ 0, 0, 0 },
    padded_row_count: u32,
    active_row_count: u32,
    main_column_count: u16,
    interaction_weight_column_count: u16,
    composition_column_count: u16,
    claim_column_count: u16,
    binding_column_count: u16,
    identity_sha256: [32]u8,

    pub fn init(
        manifest: *const manifest_mod.ManifestV1,
        role: manifest_mod.WrapperRoleV1,
        component_ordinal: usize,
        active_row_count: u32,
        main_column_count: u16,
        interaction_weight_column_count: u16,
        composition_column_count: u16,
        claim_column_count: u16,
        binding_column_count: u16,
    ) Error!ComponentContractV1 {
        try manifest.validateSelfConsistency();
        if (component_ordinal >= manifest_mod.COMPONENT_COUNT)
            return error.InvalidComponentPaddingContract;
        const padded_row_count = try rowsForLog(
            manifest.padded_component_log_sizes[component_ordinal],
        );
        var result = ComponentContractV1{
            .role = role,
            .component_ordinal = @intCast(component_ordinal),
            .binds_node_public = component_ordinal ==
                NODE_PUBLIC_OWNER_COMPONENT,
            .padded_row_count = padded_row_count,
            .active_row_count = active_row_count,
            .main_column_count = main_column_count,
            .interaction_weight_column_count = interaction_weight_column_count,
            .composition_column_count = composition_column_count,
            .claim_column_count = claim_column_count,
            .binding_column_count = binding_column_count,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = componentIdentity(&result);
        try result.validateAgainst(manifest, role, component_ordinal);
        return result;
    }

    pub fn validateAgainst(
        self: *const ComponentContractV1,
        manifest: *const manifest_mod.ManifestV1,
        role: manifest_mod.WrapperRoleV1,
        component_ordinal: usize,
    ) Error!void {
        try manifest.validateSelfConsistency();
        if (component_ordinal >= manifest_mod.COMPONENT_COUNT or
            self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.role != role or
            @as(usize, self.component_ordinal) != component_ordinal or
            self.binds_node_public !=
                (component_ordinal == NODE_PUBLIC_OWNER_COMPONENT) or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.padded_row_count != try rowsForLog(
                manifest.padded_component_log_sizes[component_ordinal],
            ) or self.active_row_count > self.padded_row_count or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &componentIdentity(self),
            )) return error.InvalidComponentPaddingContract;
    }
};

pub fn TraceInputV1(comptime Scalar: type) type {
    return struct {
        active_mask: []const Scalar,
        main_columns: []const []const Scalar,
        interaction_weight_columns: []const []const Scalar,
        composition_columns: []const []const Scalar,
        claim_columns: []const []const Scalar,
        binding_columns: []const []const Scalar,
    };
}

pub fn NodePublicScalarsV1(comptime Scalar: type) type {
    return struct {
        format_version: Scalar,
        schema_version: Scalar,
        reserved: [4]Scalar,
        statement_words: [artifact_mod.STATEMENT_WORD_COUNT]Scalar,
        statement_identity_bytes: [IDENTITY_BYTE_COUNT]Scalar,
        node_authority_bytes: [IDENTITY_BYTE_COUNT]Scalar,
        subtree_sha256_bytes: [IDENTITY_BYTE_COUNT]Scalar,
        subtree_digest: [artifact_mod.DIGEST_WORD_COUNT]Scalar,
        output_identity_bytes: [IDENTITY_BYTE_COUNT]Scalar,
    };
}

pub fn NodePublicAuxV1(comptime Scalar: type) type {
    return struct {
        identity_bits: [IDENTITY_FIELD_COUNT][IDENTITY_BYTE_COUNT][
            IDENTITY_BIT_COUNT
        ]Scalar,
        identity_nonzero_inverses: [IDENTITY_FIELD_COUNT]Scalar,
        digest_nonzero_flags: [artifact_mod.DIGEST_WORD_COUNT]Scalar,
        digest_word_inverses: [artifact_mod.DIGEST_WORD_COUNT]Scalar,
        digest_any_inverse: Scalar,
    };
}

pub fn NodePublicInputV1(comptime Scalar: type) type {
    return struct {
        published: NodePublicScalarsV1(Scalar),
        /// Must be wired directly to the role verifier/hash circuit. A host
        /// copy does not satisfy the source-authority contract.
        derived: NodePublicScalarsV1(Scalar),
        aux: NodePublicAuxV1(Scalar),
    };
}

pub const ConstraintTallyV1 = struct {
    active_boolean: usize = 0,
    active_monotone: usize = 0,
    active_exact_count: usize = 0,
    inactive_main_zero: usize = 0,
    inactive_interaction_weight_zero: usize = 0,
    inactive_composition_zero: usize = 0,
    inactive_claim_zero: usize = 0,
    inactive_binding_zero: usize = 0,
    node_public_equality: usize = 0,
    identity_byte_range: usize = 0,
    identity_nonzero: usize = 0,
    digest_nonzero: usize = 0,
    role_derivation: usize = 0,

    pub fn total(self: ConstraintTallyV1) usize {
        var result: usize = 0;
        inline for (@typeInfo(ConstraintTallyV1).@"struct".fields) |field|
            result += @field(self, field.name);
        return result;
    }
};

/// Receipt returned by a circuit-bound role owner after it records the
/// source/hash equations which derive the `derived` NodePublic payload. This
/// is not caller data: the owner is a compile-time circuit dependency and its
/// code is covered by the registered circuit/preprocessed identities.
pub const RoleDerivationTallyV1 = struct {
    statement_word_count: u16,
    identity_field_count: u8,
    digest_word_count: u8,
    source_constraint_count: usize,

    pub fn validate(self: RoleDerivationTallyV1) Error!void {
        if (self.statement_word_count != artifact_mod.STATEMENT_WORD_COUNT or
            self.identity_field_count != IDENTITY_FIELD_COUNT or
            self.digest_word_count != artifact_mod.DIGEST_WORD_COUNT or
            self.source_constraint_count == 0)
        {
            return error.InvalidNodePublicConstraintShape;
        }
    }
};

/// Records boolean, monotone-prefix, exact-count and inactive-zero equations.
/// `Sink` must expose `zero`, `one`, `constantU64`, and `constrainZero`; its
/// scalar must expose `add`, `sub`, and `mul`.
pub fn recordTracePadding(
    sink: anytype,
    manifest: *const manifest_mod.ManifestV1,
    role: manifest_mod.WrapperRoleV1,
    contract: *const ComponentContractV1,
    input: anytype,
) !ConstraintTallyV1 {
    try contract.validateAgainst(manifest, role, contract.component_ordinal);
    try validateTraceShape(contract, input);
    const one = sink.one();
    var active_sum = sink.zero();
    var tally = ConstraintTallyV1{};
    for (input.active_mask, 0..) |active, row| {
        try sink.constrainZero(active.mul(active.sub(one)));
        tally.active_boolean += 1;
        active_sum = active_sum.add(active);
        if (row + 1 < input.active_mask.len) {
            try sink.constrainZero(
                input.active_mask[row + 1].mul(one.sub(active)),
            );
            tally.active_monotone += 1;
        }
        const inactive = one.sub(active);
        try zeroInactiveColumns(
            sink,
            inactive,
            input.main_columns,
            row,
            &tally.inactive_main_zero,
        );
        try zeroInactiveColumns(
            sink,
            inactive,
            input.interaction_weight_columns,
            row,
            &tally.inactive_interaction_weight_zero,
        );
        try zeroInactiveColumns(
            sink,
            inactive,
            input.composition_columns,
            row,
            &tally.inactive_composition_zero,
        );
        try zeroInactiveColumns(
            sink,
            inactive,
            input.claim_columns,
            row,
            &tally.inactive_claim_zero,
        );
        try zeroInactiveColumns(
            sink,
            inactive,
            input.binding_columns,
            row,
            &tally.inactive_binding_zero,
        );
    }
    try sink.constrainZero(active_sum.sub(
        sink.constantU64(contract.active_row_count),
    ));
    tally.active_exact_count = 1;
    return tally;
}

/// Invokes the circuit-bound role derivation owner, then binds the complete
/// fixed public ABI to those derived values. SHA bytes are range constrained
/// and nonzero here; computing their exact hash/source relations belongs to
/// that owner and remains explicitly unavailable for real wrappers today.
pub fn recordNodePublicBinding(
    sink: anytype,
    manifest: *const manifest_mod.ManifestV1,
    role: manifest_mod.WrapperRoleV1,
    contract: *const ComponentContractV1,
    derivation_owner: anytype,
    input: anytype,
) !ConstraintTallyV1 {
    try contract.validateAgainst(manifest, role, contract.component_ordinal);
    if (!contract.binds_node_public)
        return error.InvalidComponentPaddingContract;
    const one = sink.one();
    const zero = sink.zero();
    var tally = ConstraintTallyV1{};
    const derivation_tally = try derivation_owner.recordNodePublicDerivation(
        sink,
        &input.derived,
    );
    try derivation_tally.validate();
    tally.role_derivation = derivation_tally.source_constraint_count;
    try constrainEqual(
        sink,
        input.published.format_version,
        sink.constantU64(artifact_mod.FORMAT_VERSION),
        &tally.node_public_equality,
    );
    try constrainEqual(
        sink,
        input.published.schema_version,
        sink.constantU64(artifact_mod.SCHEMA_VERSION),
        &tally.node_public_equality,
    );
    for (input.published.reserved) |value|
        try constrainEqual(
            sink,
            value,
            zero,
            &tally.node_public_equality,
        );
    try constrainNodePublicPayload(
        sink,
        &input.published,
        &input.derived,
        &tally.node_public_equality,
    );

    const published_identities = .{
        &input.published.statement_identity_bytes,
        &input.published.node_authority_bytes,
        &input.published.subtree_sha256_bytes,
        &input.published.output_identity_bytes,
    };
    const derived_identities = .{
        &input.derived.statement_identity_bytes,
        &input.derived.node_authority_bytes,
        &input.derived.subtree_sha256_bytes,
        &input.derived.output_identity_bytes,
    };
    inline for (
        published_identities,
        derived_identities,
        &input.aux.identity_bits,
        input.aux.identity_nonzero_inverses,
    ) |published, derived, *bits, nonzero_inverse| {
        try recordIdentityBytes(
            sink,
            published,
            derived,
            bits,
            nonzero_inverse,
            &tally,
        );
    }

    var nonzero_digest_count = zero;
    for (
        input.derived.subtree_digest,
        input.aux.digest_nonzero_flags,
        input.aux.digest_word_inverses,
    ) |word, flag, inverse| {
        try sink.constrainZero(flag.mul(flag.sub(one)));
        try sink.constrainZero(word.mul(inverse).sub(flag));
        try sink.constrainZero(word.mul(one.sub(flag)));
        tally.digest_nonzero += 3;
        nonzero_digest_count = nonzero_digest_count.add(flag);
    }
    try sink.constrainZero(nonzero_digest_count
        .mul(input.aux.digest_any_inverse).sub(one));
    tally.digest_nonzero += 1;

    return tally;
}

fn validateTraceShape(contract: *const ComponentContractV1, input: anytype) !void {
    if (input.active_mask.len != contract.padded_row_count or
        input.main_columns.len != contract.main_column_count or
        input.interaction_weight_columns.len !=
            contract.interaction_weight_column_count or
        input.composition_columns.len != contract.composition_column_count or
        input.claim_columns.len != contract.claim_column_count or
        input.binding_columns.len != contract.binding_column_count)
    {
        return error.InvalidConstraintShape;
    }
    inline for (.{
        input.main_columns,
        input.interaction_weight_columns,
        input.composition_columns,
        input.claim_columns,
        input.binding_columns,
    }) |columns| for (columns) |column|
        if (column.len != input.active_mask.len)
            return error.InvalidConstraintShape;
}

fn zeroInactiveColumns(
    sink: anytype,
    inactive: anytype,
    columns: anytype,
    row: usize,
    count: *usize,
) !void {
    for (columns) |column| {
        try sink.constrainZero(inactive.mul(column[row]));
        count.* += 1;
    }
}

fn constrainNodePublicPayload(
    sink: anytype,
    published: anytype,
    derived: anytype,
    count: *usize,
) !void {
    try constrainEqual(sink, published.format_version, derived.format_version, count);
    try constrainEqual(sink, published.schema_version, derived.schema_version, count);
    for (published.reserved, derived.reserved) |actual, expected|
        try constrainEqual(sink, actual, expected, count);
    for (published.statement_words, derived.statement_words) |actual, expected|
        try constrainEqual(sink, actual, expected, count);
    for (published.subtree_digest, derived.subtree_digest) |actual, expected|
        try constrainEqual(sink, actual, expected, count);
}

fn recordIdentityBytes(
    sink: anytype,
    published: anytype,
    derived: anytype,
    bits: anytype,
    nonzero_inverse: anytype,
    tally: *ConstraintTallyV1,
) !void {
    const one = sink.one();
    var byte_sum = sink.zero();
    for (published, derived, bits) |actual, expected, byte_bits| {
        try constrainEqual(
            sink,
            actual,
            expected,
            &tally.node_public_equality,
        );
        var reconstructed = sink.zero();
        for (byte_bits, 0..) |bit, bit_index| {
            try sink.constrainZero(bit.mul(bit.sub(one)));
            tally.identity_byte_range += 1;
            reconstructed = reconstructed.add(bit.mul(
                sink.constantU64(
                    @as(u64, 1) << @as(u6, @intCast(bit_index)),
                ),
            ));
        }
        try sink.constrainZero(expected.sub(reconstructed));
        tally.identity_byte_range += 1;
        byte_sum = byte_sum.add(expected);
    }
    try sink.constrainZero(byte_sum.mul(nonzero_inverse).sub(one));
    tally.identity_nonzero += 1;
}

fn constrainEqual(
    sink: anytype,
    actual: anytype,
    expected: anytype,
    count: *usize,
) !void {
    try sink.constrainZero(actual.sub(expected));
    count.* += 1;
}

fn rowsForLog(log_size: u8) Error!u32 {
    if (log_size >= 31) return error.ArithmeticOverflow;
    return @as(u32, 1) << @as(u5, @intCast(log_size));
}

fn componentIdentity(value: *const ComponentContractV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COMPONENT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.role));
    hashInt(&hash, u8, value.component_ordinal);
    hashInt(&hash, u8, @intFromBool(value.binds_node_public));
    hashInt(&hash, u32, value.padded_row_count);
    hashInt(&hash, u32, value.active_row_count);
    hashInt(&hash, u16, value.main_column_count);
    hashInt(&hash, u16, value.interaction_weight_column_count);
    hashInt(&hash, u16, value.composition_column_count);
    hashInt(&hash, u16, value.claim_column_count);
    hashInt(&hash, u16, value.binding_column_count);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or artifact_mod.STATEMENT_WORD_COUNT != 412 or
        artifact_mod.DIGEST_WORD_COUNT != 8 or
        manifest_mod.COMPONENT_COUNT != 36)
    {
        @compileError("common wrapper padding contract drifted");
    }
}
