//! Profile-composed relation registry for the Poseidon2 guest extension.
//!
//! The shipped base registry remains a closed twelve-schema type.  This view
//! appends the guest relation only for the exact extension profile, so base
//! callers cannot discover schema ID 12 by accidentally iterating a widened
//! global registry.

const std = @import("std");
const base = @import("../lang/relation.zig");
const types = @import("../lang/types.zig");
const execution_profile = @import("../../isa/execution_profile.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const Role = base.Role;

pub const guest_schema_numeric_id: u32 = 12;
pub const guest_schema_id: types.RelationSchemaId =
    @enumFromInt(guest_schema_numeric_id);
pub const guest_schema_version: u16 = 1;
pub const guest_relation_arity: usize = 32;
pub const guest_relation_name = "stwo.riscv.guest_poseidon2_io";
pub const guest_relation_abi = "guest_poseidon2_io_v1";

const guest_fields = [_]base.FieldSpec{
    .{ .exact = .felt },
} ** guest_relation_arity;
const guest_roles = base.RoleSet{
    .bits = (@as(u8, 1) << @intFromEnum(Role.request)) |
        (@as(u8, 1) << @intFromEnum(Role.emit)),
};

pub const GuestSchema = struct {
    id: types.RelationSchemaId,
    version: u16,
    name: []const u8,
    abi: []const u8,
    fields: []const base.FieldSpec,
    allowed_roles: base.RoleSet,
    challenge: base.ChallengeConvention,
    multiplicity: base.MultiplicityPolicy,
    access_ordinal: base.AccessOrdinalPolicy,
    padding: base.PaddingPolicy,
    public_boundary: base.PublicBoundaryPolicy,
    coefficient_bound: base.CoefficientBoundPolicy,
};

pub const guest_schema = GuestSchema{
    .id = guest_schema_id,
    .version = guest_schema_version,
    .name = guest_relation_name,
    .abi = guest_relation_abi,
    .fields = &guest_fields,
    .allowed_roles = guest_roles,
    .challenge = .stark_v_alpha_powers_minus_z,
    .multiplicity = .role_signed_liveness,
    .access_ordinal = .forbidden,
    .padding = .inactive_zero,
    .public_boundary = .none,
    .coefficient_bound = .statement_all_source,
};

/// Borrowed schema reference without erasing which registry owns it.
pub const SchemaRef = union(enum) {
    base: *const base.Schema,
    guest_poseidon2_io: *const GuestSchema,

    pub fn id(self: SchemaRef) types.RelationSchemaId {
        return switch (self) {
            .base => |schema| schema.id,
            .guest_poseidon2_io => |schema| schema.id,
        };
    }

    pub fn version(self: SchemaRef) u16 {
        return switch (self) {
            .base => |schema| schema.version,
            .guest_poseidon2_io => |schema| schema.version,
        };
    }

    pub fn name(self: SchemaRef) []const u8 {
        return switch (self) {
            .base => |schema| schema.name,
            .guest_poseidon2_io => |schema| schema.name,
        };
    }

    pub fn fields(self: SchemaRef) []const base.FieldSpec {
        return switch (self) {
            .base => |schema| schema.fields,
            .guest_poseidon2_io => |schema| schema.fields,
        };
    }

    pub fn allows(self: SchemaRef, role: Role) bool {
        return switch (self) {
            .base => |schema| schema.allowed_roles.allows(role),
            .guest_poseidon2_io => |schema| schema.allowed_roles.allows(role),
        };
    }

    pub fn accessOrdinalPolicy(self: SchemaRef) base.AccessOrdinalPolicy {
        return switch (self) {
            .base => |schema| schema.access_ordinal,
            .guest_poseidon2_io => |schema| schema.access_ordinal,
        };
    }
};

pub const Error = base.Error;

/// Immutable registry authority selected once during statement admission.
pub const Registry = struct {
    profile: ExecutionProfile,

    pub fn forProfile(profile: ExecutionProfile) Registry {
        return .{ .profile = profile };
    }

    pub fn schemaCount(self: Registry) usize {
        return base.schemas.len + @intFromBool(self.admitsGuestPoseidon2());
    }

    pub fn getByIndex(self: Registry, index: usize) ?SchemaRef {
        if (index < base.schemas.len) return .{ .base = &base.schemas[index] };
        if (index == base.schemas.len and self.admitsGuestPoseidon2()) {
            return .{ .guest_poseidon2_io = &guest_schema };
        }
        return null;
    }

    pub fn getById(
        self: Registry,
        schema_id: types.RelationSchemaId,
    ) ?SchemaRef {
        const index = types.idIndex(schema_id);
        // Stable IDs and registry positions are intentionally identical in v1.
        const schema = self.getByIndex(index) orelse return null;
        if (schema.id() != schema_id) return null;
        return schema;
    }

    pub fn validateEvent(
        self: Registry,
        schema_id: types.RelationSchemaId,
        role: Role,
        field_types: []const types.Type,
        access_ordinal: ?u8,
    ) Error!void {
        const schema = self.getById(schema_id) orelse
            return error.UnknownSchema;
        if (!schema.allows(role)) return error.InvalidRole;
        if (field_types.len != schema.fields().len) return error.InvalidArity;
        if (schema.accessOrdinalPolicy() == .forbidden and
            access_ordinal != null)
        {
            return error.UnexpectedAccessOrdinal;
        }
        for (schema.fields(), field_types) |expected, actual| {
            actual.validate() catch return error.InvalidFieldType;
            if (!expected.accepts(actual)) return error.InvalidFieldType;
        }
    }

    pub fn admitsGuestPoseidon2(self: Registry) bool {
        return self.profile == .rv32im_zkvm_poseidon2_v1;
    }
};

comptime {
    if (base.schemas.len != guest_schema_numeric_id) {
        @compileError("guest relation must append after the exact base registry");
    }
    if (guest_schema.fields.len != guest_relation_arity) {
        @compileError("guest relation arity drifted");
    }
    if (!guest_schema.allowed_roles.allows(.request) or
        !guest_schema.allowed_roles.allows(.emit) or
        guest_schema.allowed_roles.allows(.consume))
    {
        @compileError("guest relation roles drifted");
    }
    for (guest_schema.fields) |field| switch (field) {
        .exact => |ty| if (!std.meta.eql(ty, types.Type.felt)) {
            @compileError("guest relation fields must be exact felt values");
        },
        .field_scalar => @compileError(
            "guest relation may not admit unrefined field scalar types",
        ),
    };
}
