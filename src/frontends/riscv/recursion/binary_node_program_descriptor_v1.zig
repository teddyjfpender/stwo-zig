//! Complete transport authority for one heterogeneous binary-node program.
//!
//! The serialized descriptor is never a verifier selector. Minting and
//! re-admission both validate every compiler-owned row authority (0--35)
//! against the trusted VM/left/right inputs, rebuild the universal manifest,
//! and compare the complete expected value. Proof-instance PCS and graph
//! evaluations are deliberately excluded; they belong to a later verified
//! node receipt.

const std = @import("std");
const digest = @import("../air/lang/digest.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const control = @import("air/control_witness_heterogeneous_v2.zig");
const transcript_data = @import("air/transcript_data_rows_heterogeneous_v2.zig");
const transcript_state = @import("air/transcript_state_heterogeneous_v2.zig");
const transcript_execution =
    @import("air/transcript_execution_program_heterogeneous_v2.zig");
const transcript_schedule =
    @import("air/transcript_schedule_rows_heterogeneous_v2.zig");
const schedule = @import("air/verifier_schedule.zig");
const fri_rows = @import("air/fri_rows_authority_heterogeneous_v2.zig");
const fri_descriptor = @import("air/fri_rows_program_descriptor_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const public_rows = @import("binary_public_rows_program_heterogeneous_v2.zig");
const composition = @import("binary_composition_rows_heterogeneous_v2.zig");
const arithmetic = @import("binary_arithmetic_rows_heterogeneous_v2.zig");
const merkle_path = @import("binary_merkle_path_program_heterogeneous_v2.zig");
const poseidon_provider =
    @import("binary_poseidon_provider_program_heterogeneous_v2.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROW_COUNT: usize = universal_roster.COMPONENT_COUNT;
pub const CHILD_COUNT: usize = 2;
pub const LANE_COUNT: usize = 3;
pub const ENCODED_BYTE_COUNT: usize = 1626;
/// Candidate compiler transport is available, but production admission waits
/// for the ProfileV2-derived Ethereum composition program and committed
/// preprocessed-root binding.
pub const PRODUCTION_ACTIVATION = false;

const ROW_DOMAIN = "stwo-zig/typed-air/binary-node-row-program/v1\x00";
const CHILD_DOMAIN = "stwo-zig/typed-air/binary-node-child-program/v1\x00";
const PROTOCOL_DOMAIN = "stwo-zig/typed-air/binary-node-protocol/v1\x00";
const TRANSCRIPT_DOMAIN = "stwo-zig/typed-air/binary-node-transcript/v1\x00";
const SECURITY_DOMAIN = "stwo-zig/typed-air/binary-node-security/v1\x00";
const PROGRAM_DOMAIN = "stwo-zig/typed-air/binary-node-program/v1\x00";
const COMPILER_DOMAIN =
    "stwo-zig/typed-air/binary-node-compiler-authority/v1\x00";
const DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/binary-node-program-descriptor/v1\x00";
const RANGE_PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-node-range-provider/v1\x00";

pub const Error = error{
    InvalidNodeProgramDescriptor,
    NodeProgramDescriptorMismatch,
    ProductionSecurityRequired,
    VerifierProgramAuthorityUnavailable,
};

/// Borrowed cold-compiler inputs. Every pointer is validated by value; pointer
/// identity is never hashed or serialized.
pub const CompilerInputV1 = struct {
    vm_plan: *const schedule.Plan,
    left_plan: *const schedule.Plan,
    right_plan: *const schedule.Plan,
    row0: *const control.PreprocessedV2,
    transcript_calls: *const transcript_data.TranscriptBindingPreprocessedV2,
    row3: *const transcript_state.PreprocessedV2,
    row4: *const transcript_data.TranscriptWordPreprocessedV2,
    row5: *const transcript_data.TranscriptPayloadPreprocessedV2,
    transcript_program: *const transcript_execution.ProgramAuthorityV2,
    row8: *const transcript_schedule.RelationChallengePreprocessedV2,
    row9: *const transcript_schedule.VerifierRandomnessPreprocessedV2,
    public_program: *const public_rows.ProgramAuthorityV2,
    composition_program: *const composition.CompositionRowsAuthorityV2,
    composition_input: composition.ProgramInputV2,
    fri_program: *const fri_rows.FriRowsAuthorityV2,
    fri_input: fri_rows.ProgramInputV2,
    arithmetic_program: *const arithmetic.ArithmeticRowsAuthorityV2,
    merkle_program: *const merkle_path.MerklePathProgramAuthorityV2,
    provider_program: *const poseidon_provider.ProgramAuthorityV2,
};

/// Pointer-free transport. `compiler_authority_sha256` seals the deterministic
/// compiler output; it is deliberately not named or treated as a verifier key.
/// A concrete proof adapter must bind the preprocessed commitment root before
/// a later verified-node instance may publish verifier-program authority.
pub const NodeProgramDescriptorV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    row_count: u8 = ROW_COUNT,
    lane_count: u8 = LANE_COUNT,
    child_count: u8 = CHILD_COUNT,
    proof_kind: u8 = 2, // binary_node
    reserved: u16 = 0,
    row_log_sizes: [ROW_COUNT]u32,
    row_program_sha256: [ROW_COUNT]digest.Digest,
    child_composition_manifest_sha256: [CHILD_COUNT]digest.Digest,
    fri_rows_descriptor_sha256: digest.Digest,
    protocol_sha256: digest.Digest,
    transcript_sha256: digest.Digest,
    security_sha256: digest.Digest,
    parent_outer_manifest_sha256: digest.Digest,
    program_sha256: digest.Digest,
    compiler_authority_sha256: digest.Digest,
    descriptor_sha256: digest.Digest,

    pub fn mint(input: CompilerInputV1) !NodeProgramDescriptorV1 {
        const fri = try validateCompiler(input);
        const result = try mintUnchecked(input, fri);
        try result.validateAgainst(input);
        return result;
    }

    /// Production-only constructor. Candidate schedules remain describable for
    /// differential tests, but cannot cross the verified-node boundary.
    pub fn mintProduction(input: CompilerInputV1) !NodeProgramDescriptorV1 {
        if (!PRODUCTION_ACTIVATION)
            return error.VerifierProgramAuthorityUnavailable;
        try requireProductionSecurity(input);
        return mint(input);
    }

    pub fn validate(self: *const NodeProgramDescriptorV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.row_count != ROW_COUNT or self.lane_count != LANE_COUNT or
            self.child_count != CHILD_COUNT or self.proof_kind != 2 or
            self.reserved != 0)
        {
            return error.InvalidNodeProgramDescriptor;
        }
        for (self.row_log_sizes) |log_size| if (log_size == 0 or log_size > 30)
            return error.InvalidNodeProgramDescriptor;
        for (self.row_program_sha256) |value| try requireSha(value);
        for (self.child_composition_manifest_sha256) |value| try requireSha(value);
        inline for (.{
            self.fri_rows_descriptor_sha256,
            self.protocol_sha256,
            self.transcript_sha256,
            self.security_sha256,
            self.parent_outer_manifest_sha256,
            self.program_sha256,
            self.compiler_authority_sha256,
        }) |value| try requireSha(value);
        const manifest = try universal_manifest.build(self.row_log_sizes);
        try manifest.validate();
        if (!std.mem.eql(
            u8,
            &self.parent_outer_manifest_sha256,
            &manifest.seal,
        ) or !std.mem.eql(
            u8,
            &self.protocol_sha256,
            &protocolIdentity(),
        ) or !std.mem.eql(
            u8,
            &self.transcript_sha256,
            &transcriptIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.security_sha256,
            &securityIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.program_sha256,
            &programIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.compiler_authority_sha256,
            &compilerAuthorityIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.descriptor_sha256,
            &descriptorIdentity(self),
        )) return error.InvalidNodeProgramDescriptor;
    }

    /// Cold re-admission. Serialized hashes are compared only after every row
    /// has been reconstructed from the trusted compiler inputs.
    pub fn validateAgainst(
        self: *const NodeProgramDescriptorV1,
        input: CompilerInputV1,
    ) !void {
        try self.validate();
        const fri = try validateCompiler(input);
        const expected = try mintUnchecked(input, fri);
        if (!std.meta.eql(self.*, expected))
            return error.NodeProgramDescriptorMismatch;
    }

    pub fn validateProductionAgainst(
        self: *const NodeProgramDescriptorV1,
        input: CompilerInputV1,
    ) !void {
        if (!PRODUCTION_ACTIVATION)
            return error.VerifierProgramAuthorityUnavailable;
        try requireProductionSecurity(input);
        try self.validateAgainst(input);
    }

    pub fn encodeCanonical(
        self: *const NodeProgramDescriptorV1,
    ) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var bytes: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &bytes };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u8Value(self.row_count);
        writer.u8Value(self.lane_count);
        writer.u8Value(self.child_count);
        writer.u8Value(self.proof_kind);
        writer.u16Value(self.reserved);
        for (self.row_log_sizes) |value| writer.u32Value(value);
        for (self.row_program_sha256) |value| writer.sha(value);
        for (self.child_composition_manifest_sha256) |value| writer.sha(value);
        inline for (.{
            self.fri_rows_descriptor_sha256,
            self.protocol_sha256,
            self.transcript_sha256,
            self.security_sha256,
            self.parent_outer_manifest_sha256,
            self.program_sha256,
            self.compiler_authority_sha256,
            self.descriptor_sha256,
        }) |value| writer.sha(value);
        std.debug.assert(writer.at == bytes.len);
        return bytes;
    }

    pub fn decodeCanonical(bytes: []const u8) !NodeProgramDescriptorV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidNodeProgramDescriptor;
        var reader = Reader{ .bytes = bytes };
        var result = NodeProgramDescriptorV1{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .row_count = reader.u8Value(),
            .lane_count = reader.u8Value(),
            .child_count = reader.u8Value(),
            .proof_kind = reader.u8Value(),
            .reserved = reader.u16Value(),
            .row_log_sizes = undefined,
            .row_program_sha256 = undefined,
            .child_composition_manifest_sha256 = undefined,
            .fri_rows_descriptor_sha256 = undefined,
            .protocol_sha256 = undefined,
            .transcript_sha256 = undefined,
            .security_sha256 = undefined,
            .parent_outer_manifest_sha256 = undefined,
            .program_sha256 = undefined,
            .compiler_authority_sha256 = undefined,
            .descriptor_sha256 = undefined,
        };
        for (&result.row_log_sizes) |*value| value.* = reader.u32Value();
        for (&result.row_program_sha256) |*value| value.* = reader.sha();
        for (&result.child_composition_manifest_sha256) |*value|
            value.* = reader.sha();
        result.fri_rows_descriptor_sha256 = reader.sha();
        result.protocol_sha256 = reader.sha();
        result.transcript_sha256 = reader.sha();
        result.security_sha256 = reader.sha();
        result.parent_outer_manifest_sha256 = reader.sha();
        result.program_sha256 = reader.sha();
        result.compiler_authority_sha256 = reader.sha();
        result.descriptor_sha256 = reader.sha();
        if (reader.at != bytes.len) return error.InvalidNodeProgramDescriptor;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidNodeProgramDescriptor;
        return result;
    }
};

fn validateCompiler(
    input: CompilerInputV1,
) !fri_descriptor.FriRowsProgramDescriptorV2 {
    try input.vm_plan.validate();
    try input.left_plan.validate();
    try input.right_plan.validate();
    try input.row0.validateAgainst(input.vm_plan, input.left_plan, input.right_plan);
    try input.transcript_calls.validateAgainst(
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    );
    try input.row3.validateAgainst(
        input.transcript_calls,
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    );
    try input.row4.validateAgainst(input.vm_plan, input.left_plan, input.right_plan);
    try input.row5.validateAgainst(input.vm_plan, input.left_plan, input.right_plan);
    try input.transcript_program.validateAgainst(
        input.transcript_calls,
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    );
    try input.row8.validateAgainst(input.vm_plan, input.left_plan, input.right_plan);
    try input.row9.validateAgainst(input.vm_plan, input.left_plan, input.right_plan);
    try input.public_program.validateAgainst(
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    );
    try input.composition_program.validateProgramAgainst(input.composition_input);
    try input.fri_program.validateProgramAgainst(input.fri_input);
    try input.arithmetic_program.validateProgramAgainst(.{
        .composition_authority = input.composition_program,
        .composition_program = input.composition_input,
        .fri_authority = input.fri_program,
        .fri_program = input.fri_input,
    });
    try input.merkle_program.validateProgramAgainst(.{
        .fri_authority = input.fri_program,
        .fri_program = input.fri_input,
    });
    try input.provider_program.validateAgainst(.{
        .transcript_authority = input.transcript_program,
        .transcript_calls = input.transcript_calls,
        .vm_plan = input.vm_plan,
        .left_plan = input.left_plan,
        .right_plan = input.right_plan,
        .fri_authority = input.fri_program,
        .fri_program = input.fri_input,
        .merkle_path_authority = input.merkle_program,
    });
    try input.public_program.statement.validate();
    const plans = [_]*const schedule.Plan{
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    };
    for (plans, input.fri_input.lanes) |plan, lane| if (plan.schema != lane.plan.schema or
        !std.meta.eql(plan.authority_digest, lane.plan.authority_digest)) return error.NodeProgramDescriptorMismatch;
    if (!samePlan(input.vm_plan, input.composition_input.vm_plan) or
        !samePlan(input.left_plan, input.composition_input.children[0].plan) or
        !samePlan(input.right_plan, input.composition_input.children[1].plan))
    {
        return error.NodeProgramDescriptorMismatch;
    }
    return fri_descriptor.FriRowsProgramDescriptorV2.mint(
        input.fri_program,
        input.fri_input,
    );
}

fn mintUnchecked(
    input: CompilerInputV1,
    fri: fri_descriptor.FriRowsProgramDescriptorV2,
) !NodeProgramDescriptorV1 {
    var result = NodeProgramDescriptorV1{
        .row_log_sizes = rowLogSizes(input),
        .row_program_sha256 = undefined,
        .child_composition_manifest_sha256 = undefined,
        .fri_rows_descriptor_sha256 = fri.descriptor_sha256,
        .protocol_sha256 = protocolIdentity(),
        .transcript_sha256 = undefined,
        .security_sha256 = undefined,
        .parent_outer_manifest_sha256 = undefined,
        .program_sha256 = undefined,
        .compiler_authority_sha256 = undefined,
        .descriptor_sha256 = undefined,
    };
    result.row_program_sha256 = rowProgramIdentities(input, result.row_log_sizes);
    for (&result.child_composition_manifest_sha256, 0..) |*destination, index|
        destination.* = childProgramIdentity(input, fri, index);
    const manifest = try universal_manifest.build(result.row_log_sizes);
    try manifest.validate();
    result.parent_outer_manifest_sha256 = manifest.seal;
    result.transcript_sha256 = transcriptIdentity(&result);
    result.security_sha256 = securityIdentity(&result);
    result.program_sha256 = programIdentity(&result);
    result.compiler_authority_sha256 = compilerAuthorityIdentity(&result);
    result.descriptor_sha256 = descriptorIdentity(&result);
    try result.validate();
    return result;
}

fn rowLogSizes(input: CompilerInputV1) [ROW_COUNT]u32 {
    var result: [ROW_COUNT]u32 = undefined;
    result[0] = input.row0.log_size;
    result[1] = input.transcript_program.transcript_log_sizes[1];
    result[2] = input.transcript_calls.log_size;
    result[3] = input.row3.log_size;
    result[4] = input.row4.log_size;
    result[5] = input.row5.log_size;
    result[6] = input.transcript_program.pow_log_sizes[1];
    result[7] = input.transcript_program.pow_log_sizes[1];
    result[8] = input.row8.log_size;
    result[9] = input.row9.log_size;
    @memcpy(result[10..18], &input.public_program.log_sizes);
    @memcpy(result[18..20], &input.composition_program.log_sizes);
    @memcpy(result[20..30], &input.fri_program.log_sizes);
    @memcpy(result[30..33], &input.arithmetic_program.rows.log_sizes);
    result[33] = input.merkle_program.geometry.log_size;
    result[34] = input.provider_program.log_size;
    result[35] = range_bridge.LOG_SIZE;
    return result;
}

fn rowProgramIdentities(
    input: CompilerInputV1,
    log_sizes: [ROW_COUNT]u32,
) [ROW_COUNT]digest.Digest {
    var owners: [ROW_COUNT]digest.Digest = undefined;
    owners[0] = input.row0.authority_sha256;
    owners[1] = input.transcript_program.program_sha256;
    owners[2] = input.transcript_calls.authority_sha256;
    owners[3] = input.row3.authority_sha256;
    owners[4] = input.row4.authority_sha256;
    owners[5] = input.row5.authority_sha256;
    owners[6] = input.transcript_program.program_sha256;
    owners[7] = input.transcript_program.program_sha256;
    owners[8] = input.row8.authority_sha256;
    owners[9] = input.row9.authority_sha256;
    for (owners[10..18]) |*value| value.* = input.public_program.program_sha256;
    for (owners[18..20]) |*value| value.* = input.composition_program.program_sha256;
    for (owners[20..30]) |*value| value.* = input.fri_program.program_sha256;
    for (owners[30..33]) |*value| value.* = input.arithmetic_program.program_sha256;
    owners[33] = input.merkle_program.program_sha256;
    owners[34] = input.provider_program.program_sha256;
    owners[35] = rangeProgramIdentity();
    var result: [ROW_COUNT]digest.Digest = undefined;
    for (&result, owners, log_sizes, 0..) |*destination, owner, log_size, row|
        destination.* = rowIdentity(row, log_size, owner);
    return result;
}

fn childProgramIdentity(
    input: CompilerInputV1,
    fri: fri_descriptor.FriRowsProgramDescriptorV2,
    child_index: usize,
) digest.Digest {
    const child = input.composition_input.children[child_index];
    const profile = child.composition.profile;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CHILD_DOMAIN);
    hashInt(&hash, u8, child_index);
    hashInt(&hash, u16, @intFromEnum(child.plan.schema));
    hashNativeDigest(&hash, child.plan.authority_digest);
    hashInt(&hash, u32, child.composition.verifier_id);
    hashInt(&hash, u32, child.composition.circuit_id);
    hashInt(&hash, u32, child.composition.statement_scope);
    hash.update(&child.composition.graph.identity_digest);
    hashInt(&hash, u32, profile.sampled_value_count);
    hashInt(&hash, u32, profile.claimed_sum_count);
    hashInt(&hash, u32, profile.relation_challenge_count);
    hashInt(&hash, u32, profile.transcript_claimed_sum_count);
    hashInt(&hash, u32, profile.public_wire_boundary_count);
    hashInt(&hash, u64, child.composition.bindings.len);
    hash.update(&fri.lanes[child_index + 1].lane_sha256);
    return hash.finalResult();
}

fn requireProductionSecurity(input: CompilerInputV1) !void {
    try (protocol.Profile{}).validate();
    const expected_protocol = protocol.protocolId();
    for (input.fri_input.lanes) |lane| {
        if (!std.meta.eql(lane.plan.protocol_id, expected_protocol) or
            lane.mapping.query_count != protocol.FRI_QUERY_COUNT or
            lane.trace.query_count != protocol.FRI_QUERY_COUNT or
            lane.fri.query_count != protocol.FRI_QUERY_COUNT or
            lane.pcs.profile.query_count != protocol.FRI_QUERY_COUNT or
            lane.fri_circuit.query_count != protocol.FRI_QUERY_COUNT)
        {
            return error.ProductionSecurityRequired;
        }
        try validatePowSteps(lane.plan);
        if (lane.mapping.lifting_log_size < protocol.FRI_LOG_BLOWUP_FACTOR)
            return error.ProductionSecurityRequired;
        const column_log_degree = lane.mapping.lifting_log_size -
            protocol.FRI_LOG_BLOWUP_FACTOR;
        const expected = fixed_profile.FriSchedule.init(
            column_log_degree,
            protocol.PCS_CONFIG.fri_config,
        ) catch return error.ProductionSecurityRequired;
        if (lane.mapping.fri_fold_widths.len != expected.active().len or
            lane.fri.layers.len != expected.active().len)
        {
            return error.ProductionSecurityRequired;
        }
        for (lane.mapping.fri_fold_widths, lane.fri.layers, expected.active()) |
            mapping_width,
            layer,
            round,
        | if (mapping_width != round.fold_width or
            layer.width != round.fold_width or
            layer.tree_height != round.merkle_tree_height)
        {
            return error.ProductionSecurityRequired;
        };
    }
}

fn validatePowSteps(plan: *const schedule.Plan) !void {
    var interaction_count: usize = 0;
    var pcs_count: usize = 0;
    for (plan.steps) |step| switch (step) {
        .verify_and_absorb_interaction_pow => |value| {
            interaction_count += 1;
            if (value.bits != protocol.INTERACTION_POW_BITS)
                return error.ProductionSecurityRequired;
        },
        .verify_and_absorb_pcs_pow => |value| {
            pcs_count += 1;
            if (value.bits != protocol.PCS_POW_BITS)
                return error.ProductionSecurityRequired;
        },
        else => {},
    };
    if (interaction_count != 1 or pcs_count != 1)
        return error.ProductionSecurityRequired;
}

fn samePlan(left: *const schedule.Plan, right: *const schedule.Plan) bool {
    return left.schema == right.schema and
        std.meta.eql(left.authority_digest, right.authority_digest);
}

fn rowIdentity(row: usize, log_size: u32, owner: digest.Digest) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROW_DOMAIN);
    hashInt(&hash, u8, row);
    hashInt(&hash, u32, log_size);
    hash.update(&owner);
    return hash.finalResult();
}

fn rangeProgramIdentity() digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(RANGE_PROGRAM_DOMAIN);
    hash.update(&range_bridge.SOURCE_AUTHORITY_DIGEST);
    hash.update(&range_bridge.SEMANTIC_DIGEST);
    hash.update(&range_bridge.BINDING_DIGEST);
    hashInt(&hash, u32, range_bridge.LOG_SIZE);
    return hash.finalResult();
}

fn protocolIdentity() digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROTOCOL_DOMAIN);
    hashNativeDigest(&hash, protocol.PROTOCOL_ID_WORDS);
    hashNativeDigest(&hash, protocol.POSEIDON_PARAMETER_ID_WORDS);
    inline for (.{
        protocol.PROTOCOL_VERSION,
        protocol.FIELD_ID,
        protocol.HASH_SUITE_ID,
        protocol.INTERACTION_POW_BITS,
        protocol.PCS_POW_BITS,
        protocol.FRI_LOG_BLOWUP_FACTOR,
        protocol.FRI_QUERY_COUNT,
        protocol.FRI_FOLD_STEP,
        protocol.FRI_LOG_LAST_LAYER_DEGREE_BOUND,
        protocol.TARGET_SECURITY_BITS,
    }) |value| hashInt(&hash, u32, value);
    return hash.finalResult();
}

fn transcriptIdentity(value: *const NodeProgramDescriptorV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRANSCRIPT_DOMAIN);
    for (value.row_program_sha256[0..10]) |row| hash.update(&row);
    return hash.finalResult();
}

fn securityIdentity(value: *const NodeProgramDescriptorV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SECURITY_DOMAIN);
    hash.update(&value.protocol_sha256);
    hash.update(&value.transcript_sha256);
    hash.update(&value.fri_rows_descriptor_sha256);
    for (value.child_composition_manifest_sha256) |child| hash.update(&child);
    return hash.finalResult();
}

fn programIdentity(value: *const NodeProgramDescriptorV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    for (value.row_log_sizes) |log_size| hashInt(&hash, u32, log_size);
    for (value.row_program_sha256) |row| hash.update(&row);
    for (value.child_composition_manifest_sha256) |child| hash.update(&child);
    hash.update(&value.fri_rows_descriptor_sha256);
    hash.update(&value.protocol_sha256);
    hash.update(&value.transcript_sha256);
    hash.update(&value.security_sha256);
    hash.update(&value.parent_outer_manifest_sha256);
    return hash.finalResult();
}

fn compilerAuthorityIdentity(value: *const NodeProgramDescriptorV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMPILER_DOMAIN);
    hash.update(&value.program_sha256);
    hash.update(&value.parent_outer_manifest_sha256);
    hash.update(&value.security_sha256);
    return hash.finalResult();
}

fn descriptorIdentity(value: *const NodeProgramDescriptorV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DESCRIPTOR_DOMAIN);
    hash.update(&value.program_sha256);
    hash.update(&value.compiler_authority_sha256);
    return hash.finalResult();
}

fn requireSha(value: digest.Digest) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidNodeProgramDescriptor;
}

fn hashNativeDigest(hash: anytype, value: [8]u32) void {
    for (value) |word| hashInt(hash, u32, word);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn sha(self: *Writer, value: digest.Digest) void {
        @memcpy(self.bytes[self.at..][0..32], &value);
        self.at += 32;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn u8Value(self: *Reader) u8 {
        defer self.at += 1;
        return self.bytes[self.at];
    }
    fn u16Value(self: *Reader) u16 {
        defer self.at += 2;
        return std.mem.readInt(u16, self.bytes[self.at..][0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        defer self.at += 4;
        return std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
    }
    fn sha(self: *Reader) digest.Digest {
        defer self.at += 32;
        return self.bytes[self.at..][0..32].*;
    }
};

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or ROW_COUNT != 36 or
        CHILD_COUNT != 2 or LANE_COUNT != 3 or ENCODED_BYTE_COUNT != 1626 or
        PRODUCTION_ACTIVATION)
    {
        @compileError("binary node program descriptor contract drifted");
    }
}
