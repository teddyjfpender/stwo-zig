//! Pure typed Poseidon relation identities, event projections and batch contracts.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup_equations.zig");
const challenges = @import("../relation_challenges.zig");
const compat = @import("typed_poseidon2_compat.zig");
const digest = @import("digest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const RELATION_DIGEST_FORMAT_VERSION = @import("typed_poseidon2_identity_codec.zig").RELATION_DIGEST_FORMAT_VERSION;
pub const RELATION_DIGEST_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-relations/v1";
pub const WIDTH: usize = poseidon.WIDTH;
pub const N_EVENTS: usize = 4;
pub const N_BATCHES: usize = 2;
pub const N_SUMS: usize = N_BATCHES;
pub const N_INTERACTION_COLUMNS: usize = 4 * N_SUMS;
pub const MAX_ARITY: usize = 32;
pub const OUTPUT_COLUMN_START: usize =
    compat.TEMPORARY_START + compat.OUTPUT_START;

pub const Error = error{
    BatchPlanMismatch,
    BindingSealMismatch,
    ClaimMismatch,
    EntryArityMismatch,
    EntryDomainMismatch,
    EntryNumeratorMismatch,
    EntryOrderMismatch,
    EntryRoleMismatch,
    EntryTupleMismatch,
    EventPlanMismatch,
    FormatVersionMismatch,
    GeometryMismatch,
    InteractionColumnMismatch,
    InteractionGeometryMismatch,
    InvalidTraceShape,
    PolicyMismatch,
    PolicyVersionMismatch,
    RelationSchemaMismatch,
    RelationSumNonZero,
};
pub const AuthenticationError = Error || materializer.Error || compat.BindingError;
pub const ClaimError = AuthenticationError || QM31.Error;
pub const InteractionError = AuthenticationError || logup.LogupError;

pub const PolicyId = enum(u32) {
    stark_v_poseidon2_relations = 0x5032_5231,
    _,
};

pub const Identity = struct {
    format_version: u16,
    policy: PolicyId,
    policy_version: u16,
    events: u8,
    batches: u8,
    sums: u8,
    interaction_columns: u8,

    pub fn canonical() Identity {
        return .{
            .format_version = FORMAT_VERSION,
            .policy = .stark_v_poseidon2_relations,
            .policy_version = POLICY_VERSION,
            .events = N_EVENTS,
            .batches = N_BATCHES,
            .sums = N_SUMS,
            .interaction_columns = N_INTERACTION_COLUMNS,
        };
    }

    pub fn validate(self: Identity) Error!void {
        const expected = canonical();
        if (self.format_version != expected.format_version)
            return error.FormatVersionMismatch;
        if (self.policy != expected.policy) return error.PolicyMismatch;
        if (self.policy_version != expected.policy_version)
            return error.PolicyVersionMismatch;
        if (self.events != expected.events or self.batches != expected.batches or
            self.sums != expected.sums or
            self.interaction_columns != expected.interaction_columns)
        {
            return error.GeometryMismatch;
        }
    }
};

pub const EventId = enum(u8) {
    input,
    narrow_output,
    wide_output,
    io,
};

pub const NumeratorFormula = enum(u8) {
    negative_enabled_non_io,
    enabled_narrow,
    enabled_wide,
    enabled_io,
};

pub const TupleProjection = enum(u8) {
    input,
    narrow_output,
    wide_output,
    input_output,
};

/// Static effect metadata. `relation_arity` is the denominator ABI width;
/// `semantic_width` pins the shorter source slice used by diagnostics.
pub const EventPlan = struct {
    id: EventId,
    ordinal: u8,
    schema: types.RelationSchemaId,
    schema_version: u16,
    domain: relation.Domain,
    role: relation.Role,
    access_ordinal: ?u8,
    relation_arity: u8,
    semantic_width: u8,
    numerator: NumeratorFormula,
    projection: TupleProjection,

    pub fn validate(self: EventPlan, ordinal: usize) !void {
        if (ordinal >= N_EVENTS) return error.EventPlanMismatch;
        if (!std.meta.eql(self, canonicalEvent(ordinal)))
            return error.EventPlanMismatch;
        const schema = relation.getById(self.schema) orelse
            return error.RelationSchemaMismatch;
        if (schema.domain != self.domain or schema.version != self.schema_version or
            schema.challenge != .stark_v_alpha_powers_minus_z or
            schema.multiplicity != .role_signed_liveness or
            schema.padding != .inactive_zero)
        {
            return error.RelationSchemaMismatch;
        }
        var field_types = [_]types.Type{.felt} ** MAX_ARITY;
        relation.validateEvent(
            self.schema,
            self.role,
            field_types[0..self.relation_arity],
            self.access_ordinal,
        ) catch return error.RelationSchemaMismatch;
    }
};

pub const BatchPlan = struct {
    ordinal: u8,
    first: EventId,
    second: EventId,
    interaction_column_start: u8,

    pub fn validate(self: BatchPlan, ordinal: usize) Error!void {
        if (ordinal >= N_BATCHES) return error.BatchPlanMismatch;
        if (!std.meta.eql(self, canonicalBatch(ordinal)))
            return error.BatchPlanMismatch;
    }
};

/// All authority needed to reauthenticate a relation plan at a use boundary.
pub fn canonicalEvent(ordinal: usize) EventPlan {
    return switch (ordinal) {
        0 => makeEvent(.input, .poseidon2, 16, 16, .negative_enabled_non_io, .input),
        1 => makeEvent(.narrow_output, .poseidon2, 16, 1, .enabled_narrow, .narrow_output),
        2 => makeEvent(.wide_output, .poseidon2, 16, 8, .enabled_wide, .wide_output),
        3 => makeEvent(.io, .poseidon2_io, 32, 32, .enabled_io, .input_output),
        else => unreachable,
    };
}

fn makeEvent(
    id: EventId,
    domain: relation.Domain,
    relation_arity: u8,
    semantic_width: u8,
    formula: NumeratorFormula,
    projection: TupleProjection,
) EventPlan {
    const schema = relation.get(domain);
    return .{
        .id = id,
        .ordinal = @intFromEnum(id),
        .schema = schema.id,
        .schema_version = schema.version,
        .domain = domain,
        .role = .request,
        .access_ordinal = null,
        .relation_arity = relation_arity,
        .semantic_width = semantic_width,
        .numerator = formula,
        .projection = projection,
    };
}

pub fn canonicalBatch(ordinal: usize) BatchPlan {
    return switch (ordinal) {
        0 => .{ .ordinal = 0, .first = .input, .second = .narrow_output, .interaction_column_start = 0 },
        1 => .{ .ordinal = 1, .first = .wide_output, .second = .io, .interaction_column_start = 4 },
        else => unreachable,
    };
}
