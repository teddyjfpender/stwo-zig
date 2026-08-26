//! Typed, versioned relation ABIs shared by the RISC-V and recursion AIRs.
//!
//! The first `schemas.len` domains are the pinned RISC-V transcript challenge
//! order. Recursion-local extensions are appended without changing that base
//! registry or its challenge schedule. Human-readable names are descriptive
//! metadata, never lookup keys.

const std = @import("std");
const types = @import("types.zig");

pub const BASE_RELATION_COUNT: usize = 12;
pub const RECURSION_RELATION_COUNT: usize = 35;
pub const UNIVERSAL_RELATION_COUNT: usize =
    BASE_RELATION_COUNT + RECURSION_RELATION_COUNT;
pub const REGISTRY_ORDER_FORMAT_VERSION: u16 = 1;
pub const REGISTRY_ORDER_DIGEST_HEX =
    "44be542099a38d0f5df6acae11c7c4a04babfed88a97a34ad092ca275adb5a85";

pub const Domain = enum(u8) {
    registers_state = 0,
    memory_access = 1,
    program_access = 2,
    merkle = 3,
    poseidon2 = 4,
    poseidon2_io = 5,
    bitwise = 6,
    range_check_20 = 7,
    range_check_8_11 = 8,
    range_check_8_8_4 = 9,
    range_check_8_8 = 10,
    range_check_m31 = 11,
    recursion_merkle_node = 12,
    recursion_wire = 13,
    recursion_step = 14,
    recursion_hash_state = 15,
    recursion_hash_data = 16,
    recursion_hash_output = 17,
    recursion_hash_call_control = 18,
    recursion_transcript_frame_word = 19,
    recursion_transcript_frame_output = 20,
    recursion_transcript_pow_frame = 21,
    recursion_transcript_digest_state = 22,
    recursion_transcript_draw_output = 23,
    recursion_transcript_payload_word = 24,
    recursion_verifier_input_word = 25,
    recursion_pow_check = 26,
    recursion_relation_challenge_word = 27,
    recursion_verifier_randomness_word = 28,
    recursion_statement_word = 29,
    recursion_vm_public_claim_word = 30,
    recursion_vm_public_claim_byte = 31,
    recursion_vm_public_io_word = 32,
    recursion_vm_public_claim_hash_state = 33,
    recursion_vm_public_io_hash_state = 34,
    recursion_vm_public_io_digest = 35,
    recursion_query_bits = 36,
    recursion_query_bit_value = 37,
    recursion_query_position = 38,
    recursion_trace_leaf_hash_state = 39,
    recursion_trace_query_value = 40,
    recursion_pcs_deep_answer_word = 41,
    recursion_fri_merkle_leaf_state = 42,
    recursion_fri_merkle_value_word = 43,
    recursion_fri_merkle_route = 44,
    recursion_fri_merkle_local_root = 45,
    recursion_fri_verifier_route_word = 46,
};

pub const Role = types.RelationRole;

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
    /// The role supplies the sign and the component supplies a constrained
    /// field-valued weight. Used by recursion wires whose result is emitted
    /// exactly `uses` times while operand consumes remain unit-weighted.
    role_signed_weight,
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
    UniversalSchemaMismatch,
    UnknownSchema,
};

/// One challenge-draw descriptor from pinned Stark-V commit
/// `59172a201bd01f2f4b699bc2f7d4442d8ee81597`. These descriptors are the
/// authority for the recursion transcript. They are deliberately distinct
/// from the currently shipped VM schemas: the latter still expose the older
/// four-field Merkle ABI while the recursion verifier requires eighteen.
pub const UniversalDescriptor = struct {
    domain: Domain,
    reference_name: []const u8,
    arity: u8,
};

pub const BASE_MERKLE_SHIPPED_ARITY: u8 = 4;
pub const BASE_MERKLE_UNIVERSAL_ARITY: u8 = 18;
pub const BASE_MERKLE_ABI_GAP = "base_merkle_abi_4_vs_recursion_18";

/// Exact universal challenge order. Do not derive this from local schema
/// display names or tuple geometry: doing so would silently erase the Merkle
/// ABI incompatibility above.
pub const universal_descriptors = [_]UniversalDescriptor{
    descriptor(.registers_state, "registers_state", 2),
    descriptor(.memory_access, "memory_access", 7),
    descriptor(.program_access, "program_access", 5),
    descriptor(.merkle, "merkle", BASE_MERKLE_UNIVERSAL_ARITY),
    descriptor(.poseidon2, "poseidon2", 16),
    descriptor(.poseidon2_io, "poseidon2_io", 32),
    descriptor(.bitwise, "bitwise", 4),
    descriptor(.range_check_20, "range_check_20", 1),
    descriptor(.range_check_8_11, "range_check_8_11", 2),
    descriptor(.range_check_8_8_4, "range_check_8_8_4", 3),
    descriptor(.range_check_8_8, "range_check_8_8", 2),
    descriptor(.range_check_m31, "range_check_m31", 2),
    descriptor(.recursion_merkle_node, "MerkleNodeRelation", 11),
    descriptor(.recursion_wire, "WireRelation", 6),
    descriptor(.recursion_step, "VerifierStepRelation", 7),
    descriptor(.recursion_hash_state, "HashStateRelation", 19),
    descriptor(.recursion_hash_data, "HashDataRelation", 11),
    descriptor(.recursion_hash_output, "HashOutputRelation", 12),
    descriptor(.recursion_hash_call_control, "HashCallControlRelation", 7),
    descriptor(.recursion_transcript_frame_word, "TranscriptFrameWordRelation", 4),
    descriptor(.recursion_transcript_frame_output, "TranscriptFrameOutputRelation", 10),
    descriptor(.recursion_transcript_pow_frame, "TranscriptPowFrameRelation", 14),
    descriptor(.recursion_transcript_digest_state, "TranscriptDigestStateRelation", 10),
    descriptor(.recursion_transcript_draw_output, "TranscriptDrawOutputRelation", 15),
    descriptor(.recursion_transcript_payload_word, "TranscriptPayloadWordRelation", 9),
    descriptor(.recursion_verifier_input_word, "VerifierInputWordRelation", 5),
    descriptor(.recursion_pow_check, "PowCheckRelation", 5),
    descriptor(.recursion_relation_challenge_word, "RelationChallengeWordRelation", 5),
    descriptor(.recursion_verifier_randomness_word, "VerifierRandomnessWordRelation", 5),
    descriptor(.recursion_statement_word, "StatementWordRelation", 3),
    descriptor(.recursion_vm_public_claim_word, "VmPublicClaimWordRelation", 3),
    descriptor(.recursion_vm_public_claim_byte, "VmPublicClaimByteRelation", 3),
    descriptor(.recursion_vm_public_io_word, "VmPublicIoWordRelation", 3),
    descriptor(.recursion_vm_public_claim_hash_state, "VmPublicClaimHashStateRelation", 17),
    descriptor(.recursion_vm_public_io_hash_state, "VmPublicIoHashStateRelation", 18),
    descriptor(.recursion_vm_public_io_digest, "VmPublicIoDigestRelation", 3),
    descriptor(.recursion_query_bits, "QueryBitsRelation", 33),
    descriptor(.recursion_query_bit_value, "QueryBitValueRelation", 4),
    descriptor(.recursion_query_position, "QueryPositionRelation", 6),
    descriptor(.recursion_trace_leaf_hash_state, "TraceLeafHashStateRelation", 20),
    descriptor(.recursion_trace_query_value, "TraceQueryValueRelation", 5),
    descriptor(.recursion_pcs_deep_answer_word, "PcsDeepAnswerWordRelation", 4),
    descriptor(.recursion_fri_merkle_leaf_state, "FriMerkleLeafStateRelation", 21),
    descriptor(.recursion_fri_merkle_value_word, "FriMerkleValueWordRelation", 6),
    descriptor(.recursion_fri_merkle_route, "FriMerkleRouteRelation", 4),
    descriptor(.recursion_fri_merkle_local_root, "FriMerkleLocalRootRelation", 11),
    descriptor(.recursion_fri_verifier_route_word, "FriVerifierRouteWordRelation", 6),
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
// Stark-V recursion relations carry `BaseField` coordinates. Accept every
// injective scalar refinement (byte, selector, bounded canonical field, ...)
// without erasing its stronger local type merely to cross the relation ABI.
const recursion_fields = [_]FieldSpec{scalar} ** 33;

const request_only = roleSet([_]Role{.request});
const state_roles = roleSet([_]Role{ .request, .consume, .emit });
const consume_emit_roles = roleSet([_]Role{ .consume, .emit });

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

/// Extensions deliberately live outside `schemas`: that array is the frozen
/// 12-relation RISC-V transcript prefix consumed by existing manifests.
pub const extension_schemas = [_]Schema{
    weightedSchema(.recursion_merkle_node, "MerkleNodeRelation", 11),
    weightedSchema(.recursion_wire, "WireRelation", 6),
    weightedSchema(.recursion_step, "VerifierStepRelation", 7),
    weightedSchema(.recursion_hash_state, "HashStateRelation", 19),
    weightedSchema(.recursion_hash_data, "HashDataRelation", 11),
    weightedSchema(.recursion_hash_output, "HashOutputRelation", 12),
    weightedSchema(.recursion_hash_call_control, "HashCallControlRelation", 7),
    weightedSchema(.recursion_transcript_frame_word, "TranscriptFrameWordRelation", 4),
    weightedSchema(.recursion_transcript_frame_output, "TranscriptFrameOutputRelation", 10),
    weightedSchema(.recursion_transcript_pow_frame, "TranscriptPowFrameRelation", 14),
    weightedSchema(.recursion_transcript_digest_state, "TranscriptDigestStateRelation", 10),
    weightedSchema(.recursion_transcript_draw_output, "TranscriptDrawOutputRelation", 15),
    weightedSchema(.recursion_transcript_payload_word, "TranscriptPayloadWordRelation", 9),
    weightedSchema(.recursion_verifier_input_word, "VerifierInputWordRelation", 5),
    weightedSchema(.recursion_pow_check, "PowCheckRelation", 5),
    weightedSchema(.recursion_relation_challenge_word, "RelationChallengeWordRelation", 5),
    weightedSchema(.recursion_verifier_randomness_word, "VerifierRandomnessWordRelation", 5),
    weightedSchema(.recursion_statement_word, "StatementWordRelation", 3),
    weightedSchema(.recursion_vm_public_claim_word, "VmPublicClaimWordRelation", 3),
    weightedSchema(.recursion_vm_public_claim_byte, "VmPublicClaimByteRelation", 3),
    weightedSchema(.recursion_vm_public_io_word, "VmPublicIoWordRelation", 3),
    weightedSchema(.recursion_vm_public_claim_hash_state, "VmPublicClaimHashStateRelation", 17),
    weightedSchema(.recursion_vm_public_io_hash_state, "VmPublicIoHashStateRelation", 18),
    weightedSchema(.recursion_vm_public_io_digest, "VmPublicIoDigestRelation", 3),
    weightedSchema(.recursion_query_bits, "QueryBitsRelation", 33),
    weightedSchema(.recursion_query_bit_value, "QueryBitValueRelation", 4),
    weightedSchema(.recursion_query_position, "QueryPositionRelation", 6),
    weightedSchema(.recursion_trace_leaf_hash_state, "TraceLeafHashStateRelation", 20),
    weightedSchema(.recursion_trace_query_value, "TraceQueryValueRelation", 5),
    weightedSchema(.recursion_pcs_deep_answer_word, "PcsDeepAnswerWordRelation", 4),
    weightedSchema(.recursion_fri_merkle_leaf_state, "FriMerkleLeafStateRelation", 21),
    weightedSchema(.recursion_fri_merkle_value_word, "FriMerkleValueWordRelation", 6),
    weightedSchema(.recursion_fri_merkle_route, "FriMerkleRouteRelation", 4),
    weightedSchema(.recursion_fri_merkle_local_root, "FriMerkleLocalRootRelation", 11),
    weightedSchema(.recursion_fri_verifier_route_word, "FriVerifierRouteWordRelation", 6),
};

pub fn get(domain: Domain) *const Schema {
    const index = @intFromEnum(domain);
    if (index < schemas.len) return &schemas[index];
    return &extension_schemas[index - schemas.len];
}

pub fn getById(schema_id: types.RelationSchemaId) ?*const Schema {
    const index = types.idIndex(schema_id);
    if (index < schemas.len) return &schemas[index];
    const extension_index = index - schemas.len;
    if (extension_index >= extension_schemas.len) return null;
    return &extension_schemas[extension_index];
}

pub fn id(domain: Domain) types.RelationSchemaId {
    return @enumFromInt(@intFromEnum(domain));
}

pub fn universalDescriptor(domain: Domain) *const UniversalDescriptor {
    return &universal_descriptors[@intFromEnum(domain)];
}

/// Require the local typed schema to be byte-for-byte compatible in tuple
/// geometry with the exact recursion registry. This is the admission check
/// for universal adapters; it intentionally rejects the current base Merkle
/// relation until its cross-cutting ABI migration lands.
pub fn requireExactUniversalSchema(domain: Domain) Error!*const Schema {
    const item = get(domain);
    const exact = universalDescriptor(domain);
    if (item.domain != exact.domain or item.fields.len != exact.arity)
        return error.UniversalSchemaMismatch;
    return item;
}

/// Identity of the exact universal challenge-draw order. This deliberately
/// commits only order-bearing descriptor data: stable domain tag, reference
/// relation name, and tuple arity. Schema semantics remain covered by typed
/// AIR identity and per-schema validation.
pub fn registryOrderDigest() [32]u8 {
    return computeRegistryOrderDigest(&universal_descriptors);
}

pub fn computeRegistryOrderDigest(descriptors: []const UniversalDescriptor) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/universal-relation-order/v1\x00");
    hashInt(&hash, u16, REGISTRY_ORDER_FORMAT_VERSION);
    hashInt(&hash, u16, descriptors.len);
    for (descriptors) |item| hashOrderDescriptor(&hash, item);
    return hash.finalResult();
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

fn weightedSchema(
    comptime domain: Domain,
    comptime name: []const u8,
    comptime arity: usize,
) Schema {
    comptime if (arity == 0 or arity > recursion_fields.len)
        @compileError("invalid recursion relation arity");
    var result = schema(
        domain,
        name,
        recursion_fields[0..arity],
        consume_emit_roles,
        .forbidden,
        .none,
        .statement_all_source,
    );
    result.multiplicity = .role_signed_weight;
    return result;
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

fn descriptor(
    comptime domain: Domain,
    comptime reference_name: []const u8,
    comptime arity: u8,
) UniversalDescriptor {
    return .{
        .domain = domain,
        .reference_name = reference_name,
        .arity = arity,
    };
}

fn hashOrderDescriptor(hash: anytype, item: UniversalDescriptor) void {
    hashInt(hash, u8, @intFromEnum(item.domain));
    hashInt(hash, u16, item.reference_name.len);
    hash.update(item.reference_name);
    hashInt(hash, u16, item.arity);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (schemas.len != BASE_RELATION_COUNT or
        extension_schemas.len != RECURSION_RELATION_COUNT or
        schemas.len + extension_schemas.len != UNIVERSAL_RELATION_COUNT or
        universal_descriptors.len != UNIVERSAL_RELATION_COUNT or
        UNIVERSAL_RELATION_COUNT !=
            @typeInfo(Domain).@"enum".fields.len)
    {
        @compileError("base and extension relation registries must cover every domain");
    }
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
    for (extension_schemas, schemas.len..) |item, index| {
        if (@intFromEnum(item.domain) != index or types.idIndex(item.id) != index)
            @compileError("relation extension order must match stable domain IDs");
        if (item.version == 0 or item.name.len == 0 or item.fields.len == 0)
            @compileError("relation extension schemas require identity, version, and fields");
        for (item.fields) |field| switch (field) {
            .exact => |ty| ty.validate() catch
                @compileError("relation extension schema contains an invalid field type"),
            .field_scalar => {},
        };
    }
    for (universal_descriptors, 0..) |item, index| {
        if (@intFromEnum(item.domain) != index or
            item.reference_name.len == 0 or item.arity == 0)
        {
            @compileError("universal descriptor order must match stable domain IDs");
        }
        const local = get(item.domain);
        if (item.domain == .merkle) {
            if (local.fields.len != BASE_MERKLE_SHIPPED_ARITY or
                item.arity != BASE_MERKLE_UNIVERSAL_ARITY)
            {
                @compileError("the declared base Merkle ABI gap drifted");
            }
        } else if (local.fields.len != item.arity) {
            @compileError("universal descriptor and typed schema arity drifted");
        }
    }
}
