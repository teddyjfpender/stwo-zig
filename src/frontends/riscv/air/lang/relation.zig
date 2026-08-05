//! Typed, versioned relation ABIs for the current RISC-V proof protocol.
//!
//! Callers select a `Domain`; human-readable names are descriptive metadata,
//! never lookup keys. Schema order is the pinned transcript challenge order.

const std = @import("std");
const types = @import("types.zig");

pub const Domain = enum(u8) {
    registers_state,
    memory_access,
    program_access,
    merkle,
    poseidon2,
    poseidon2_io,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const Role = enum(u8) {
    request,
    consume,
    emit,
};

pub const RoleSet = struct {
    bits: u8,

    pub fn allows(self: RoleSet, role: Role) bool {
        return self.bits & roleMask(role) != 0;
    }
};

pub const FieldSpec = union(enum) {
    exact: types.Type,
    field_scalar,

    pub fn accepts(self: FieldSpec, actual: types.Type) bool {
        return switch (self) {
            .exact => |expected| std.meta.eql(expected, actual),
            .field_scalar => actual.isFieldScalar(),
        };
    }
};

pub const ChallengeConvention = enum(u8) {
    stark_v_alpha_powers_minus_z,
};

pub const MultiplicityPolicy = enum(u8) {
    /// The event role determines the sign and a scalar liveness expression
    /// determines whether the row contributes.
    role_signed_liveness,
};

pub const AccessOrdinalPolicy = enum(u8) {
    forbidden,
    optional,
};

pub const PaddingPolicy = enum(u8) {
    inactive_zero,
};

pub const PublicBoundaryPolicy = enum(u8) {
    none,
    statement_bound,
};

pub const CoefficientBoundPolicy = enum(u8) {
    /// Checked by the statement-wide all-source certificate, because a local
    /// per-event bound is insufficient when malicious tuples collide.
    statement_all_source,
    /// Supply multiplicities are bounded by the table's declared geometry.
    preprocessed_table_geometry,
};

pub const Schema = struct {
    id: types.RelationSchemaId,
    domain: Domain,
    version: u16,
    name: []const u8,
    fields: []const FieldSpec,
    allowed_roles: RoleSet,
    challenge: ChallengeConvention,
    multiplicity: MultiplicityPolicy,
    access_ordinal: AccessOrdinalPolicy,
    padding: PaddingPolicy,
    public_boundary: PublicBoundaryPolicy,
    coefficient_bound: CoefficientBoundPolicy,
};

pub const Error = error{
    InvalidArity,
    InvalidFieldType,
    InvalidRole,
    UnexpectedAccessOrdinal,
    UnknownSchema,
};

const scalar = FieldSpec.field_scalar;
const felt = FieldSpec{ .exact = .felt };
const byte = FieldSpec{ .exact = .byte };
const uint20 = FieldSpec{ .exact = .uint20 };
const pc = FieldSpec{ .exact = .pc };
const clock = FieldSpec{ .exact = .clock };
const address = FieldSpec{ .exact = .address };
const uint2 = FieldSpec{ .exact = boundedField(2) };
const uint4 = FieldSpec{ .exact = boundedField(4) };
const uint7 = FieldSpec{ .exact = boundedField(7) };
const uint11 = FieldSpec{ .exact = boundedField(11) };

const registers_state_fields = [_]FieldSpec{ pc, clock };
const memory_access_fields = [_]FieldSpec{
    scalar,
    address,
    clock,
    byte,
    byte,
    byte,
    byte,
};
const program_access_fields = [_]FieldSpec{ pc, scalar, scalar, scalar, scalar };
const merkle_fields = [_]FieldSpec{felt} ** 4;
const poseidon2_fields = [_]FieldSpec{felt} ** 16;
const poseidon2_io_fields = [_]FieldSpec{felt} ** 32;
const bitwise_fields = [_]FieldSpec{ byte, byte, byte, uint2 };
const range_check_20_fields = [_]FieldSpec{uint20};
const range_check_8_11_fields = [_]FieldSpec{ byte, uint11 };
const range_check_8_8_4_fields = [_]FieldSpec{ byte, byte, uint4 };
const range_check_8_8_fields = [_]FieldSpec{ byte, byte };
const range_check_m31_fields = [_]FieldSpec{ byte, uint7 };

const request_only = roleSet([_]Role{.request});
const state_roles = roleSet([_]Role{ .request, .consume, .emit });

pub const schemas = [_]Schema{
    schema(.registers_state, "stwo.riscv.registers_state", &registers_state_fields, state_roles, .forbidden, .statement_bound, .statement_all_source),
    schema(.memory_access, "stwo.riscv.memory_access", &memory_access_fields, state_roles, .optional, .statement_bound, .statement_all_source),
    schema(.program_access, "stwo.riscv.program_access", &program_access_fields, request_only, .forbidden, .statement_bound, .statement_all_source),
    schema(.merkle, "stwo.riscv.merkle", &merkle_fields, request_only, .forbidden, .statement_bound, .statement_all_source),
    schema(.poseidon2, "stwo.riscv.poseidon2", &poseidon2_fields, request_only, .forbidden, .none, .statement_all_source),
    schema(.poseidon2_io, "stwo.riscv.poseidon2_io", &poseidon2_io_fields, request_only, .forbidden, .none, .statement_all_source),
    schema(.bitwise, "stwo.riscv.bitwise", &bitwise_fields, request_only, .forbidden, .none, .preprocessed_table_geometry),
    schema(.range_check_20, "stwo.riscv.range_check_20", &range_check_20_fields, request_only, .optional, .none, .preprocessed_table_geometry),
    schema(.range_check_8_11, "stwo.riscv.range_check_8_11", &range_check_8_11_fields, request_only, .forbidden, .none, .preprocessed_table_geometry),
    schema(.range_check_8_8_4, "stwo.riscv.range_check_8_8_4", &range_check_8_8_4_fields, request_only, .forbidden, .none, .preprocessed_table_geometry),
    schema(.range_check_8_8, "stwo.riscv.range_check_8_8", &range_check_8_8_fields, request_only, .forbidden, .none, .preprocessed_table_geometry),
    schema(.range_check_m31, "stwo.riscv.range_check_m31", &range_check_m31_fields, request_only, .forbidden, .none, .preprocessed_table_geometry),
};

pub fn get(domain: Domain) *const Schema {
    return &schemas[@intFromEnum(domain)];
}

pub fn getById(schema_id: types.RelationSchemaId) ?*const Schema {
    const index = types.idIndex(schema_id);
    if (index >= schemas.len) return null;
    return &schemas[index];
}

pub fn id(domain: Domain) types.RelationSchemaId {
    return @enumFromInt(@intFromEnum(domain));
}

pub fn validateEvent(
    schema_id: types.RelationSchemaId,
    role: Role,
    field_types: []const types.Type,
    access_ordinal: ?u8,
) Error!void {
    const item = try validateEventShape(
        schema_id,
        role,
        field_types.len,
        access_ordinal,
    );
    for (item.fields, field_types) |expected, actual| {
        actual.validate() catch return error.InvalidFieldType;
        if (!expected.accepts(actual)) return error.InvalidFieldType;
    }
}

/// Validates compatibility metadata when the source representation carries
/// field polynomials but not yet their semantic column types. Full typed
/// authoring must call `validateEvent`; shadow import may call this narrower
/// boundary without claiming type evidence it does not possess.
pub fn validateEventShape(
    schema_id: types.RelationSchemaId,
    role: Role,
    arity: usize,
    access_ordinal: ?u8,
) Error!*const Schema {
    const item = getById(schema_id) orelse return error.UnknownSchema;
    if (!item.allowed_roles.allows(role)) return error.InvalidRole;
    if (arity != item.fields.len) return error.InvalidArity;
    if (item.access_ordinal == .forbidden and access_ordinal != null)
        return error.UnexpectedAccessOrdinal;
    return item;
}

fn schema(
    domain: Domain,
    name: []const u8,
    fields: []const FieldSpec,
    roles: RoleSet,
    ordinal: AccessOrdinalPolicy,
    public_boundary: PublicBoundaryPolicy,
    coefficient_bound: CoefficientBoundPolicy,
) Schema {
    return .{
        .id = id(domain),
        .domain = domain,
        .version = 1,
        .name = name,
        .fields = fields,
        .allowed_roles = roles,
        .challenge = .stark_v_alpha_powers_minus_z,
        .multiplicity = .role_signed_liveness,
        .access_ordinal = ordinal,
        .padding = .inactive_zero,
        .public_boundary = public_boundary,
        .coefficient_bound = coefficient_bound,
    };
}

fn roleSet(comptime roles: anytype) RoleSet {
    var bits: u8 = 0;
    inline for (roles) |role| bits |= roleMask(role);
    return .{ .bits = bits };
}

fn roleMask(role: Role) u8 {
    return @as(u8, 1) << @intCast(@intFromEnum(role));
}

fn boundedField(bits: u8) types.Type {
    return .{ .bounded_uint = .{
        .bits = bits,
        .representation = .canonical_field,
    } };
}

comptime {
    if (schemas.len != @typeInfo(Domain).@"enum".fields.len)
        @compileError("relation registry must cover every domain");
    for (schemas, 0..) |item, index| {
        if (@intFromEnum(item.domain) != index or types.idIndex(item.id) != index)
            @compileError("relation registry order must match stable domain IDs");
        if (item.version == 0 or item.name.len == 0 or item.fields.len == 0)
            @compileError("relation schemas require identity, version, and fields");
        for (item.fields) |field| switch (field) {
            .exact => |ty| ty.validate() catch
                @compileError("relation schema contains an invalid field type"),
            .field_scalar => {},
        };
    }
}
