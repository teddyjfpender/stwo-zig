//! Proof-independent composition verifier program for one ordered provider shard.
//!
//! The compiler reopens the typed provider plan and ordered calls, then records
//! the exact native component order: the narrow-memory Poseidon2 component
//! followed by the four ordered-call constraints.  Proof samples, claims,
//! transcript challenges, composition randomness, and the OODS point remain
//! graph inputs.  The shard count is deliberately absent: dynamic N belongs
//! to the wrapper manifest fold, not to any individual child program.

const std = @import("std");
const core = @import("stwo_core");

const hash_component = @import("../air/memory_commitment/hash_component.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const provider_authority =
    @import("../prover/memory_provider_shards/authority.zig");
const provider_order =
    @import("../prover/memory_provider_shards/provider_order_component.zig");
const proof_authority =
    @import("../prover/memory_provider_shards/joint_proof_authority.zig");
const graph_mod = @import("air/composition_circuit.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const protocol = @import("protocol.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");

const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = support.Scalar;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 2;
pub const TREE_COUNT: usize = 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 2;
pub const MAIN_COLUMN_COUNT: usize = poseidon2_air.N_MAIN_COLUMNS;
pub const POSEIDON_INTERACTION_COLUMN_COUNT: usize =
    poseidon2_air.N_INTERACTION_COLUMNS;
pub const ORDER_INTERACTION_COLUMN_COUNT: usize =
    provider_order.interaction_column_count;
pub const INTERACTION_COLUMN_COUNT: usize =
    POSEIDON_INTERACTION_COLUMN_COUNT + ORDER_INTERACTION_COLUMN_COUNT;
pub const COMPOSITION_SPLIT: u32 = 1;
pub const COMPOSITION_COLUMN_COUNT: usize = 8;
pub const CLAIMED_SUM_COUNT: usize = poseidon2_air.N_SUMS + 1;
pub const RELATION_CHALLENGE_COUNT: usize = 12;

pub const TREE0_OFFSET: usize = 0;
pub const TREE1_OFFSET: usize = TREE0_OFFSET + PREPROCESSED_COLUMN_COUNT;
pub const TREE2_OFFSET: usize = TREE1_OFFSET + MAIN_COLUMN_COUNT;
pub const TREE3_OFFSET: usize = TREE2_OFFSET + 2 * INTERACTION_COLUMN_COUNT;
pub const SAMPLED_VALUE_COUNT: usize = TREE3_OFFSET + COMPOSITION_COLUMN_COUNT;

const AIR_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/provider-shard-air-program/v1\x00";
const VERIFIER_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/provider-shard-verifier-program/v1\x00";
const PROTOCOL_PROFILE_DOMAIN =
    "stwo-zig/riscv/recursion/provider-shard-protocol-profile/v1\x00";

pub const CompilerInputV1 = struct {
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
};

pub const SemanticGeometryV1 = struct {
    first_call: u64,
    call_count: u32,
    log_size: u32,
    max_constraint_log_degree_bound: u32,
    composition_log_size: u32,
    composition_log_split: u32,

    fn init(input: CompilerInputV1) !SemanticGeometryV1 {
        try input.plan.validate(input.calls);
        const index: usize = input.shard_index;
        if (index >= input.plan.shards.len)
            return error.ProviderShardIndexOutOfRange;
        const descriptor = input.plan.shards[index];
        const tree2 = try proof_authority.ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        );
        return .{
            .first_call = descriptor.first_call,
            .call_count = descriptor.call_count,
            .log_size = descriptor.expected_log_size,
            .max_constraint_log_degree_bound = tree2.max_constraint_log_degree_bound,
            .composition_log_size = tree2.composition_log_size,
            .composition_log_split = tree2.composition_log_split,
        };
    }

    pub fn validate(self: SemanticGeometryV1) !void {
        const canonical = try proof_authority.ProviderTree2GeometryV2.canonical(
            self.log_size,
        );
        if (self.call_count == 0 or
            self.call_count > (@as(u32, 1) << @intCast(self.log_size)) or
            self.max_constraint_log_degree_bound !=
                canonical.max_constraint_log_degree_bound or
            self.composition_log_size != canonical.composition_log_size or
            self.composition_log_split != canonical.composition_log_split)
        {
            return error.InvalidProviderShardVerifierProgram;
        }
    }
};

/// Pointer-owning verifier-program authority.  It contains no proof-instance
/// commitment and no verifier-minted publication capability.
pub const ProviderShardCompositionProgramV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    geometry: SemanticGeometryV1,
    nodes: []graph_mod.Node,
    outputs: []u32,
    bindings: []graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    protocol_profile_sha256: [32]u8,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,

    pub fn deinit(self: *ProviderShardCompositionProgramV1) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graph(self: *const @This()) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.graph_sha256,
        };
    }

    pub fn lane(self: *const @This()) graph_mod.VmLane {
        return .{
            .circuit_id = CIRCUIT_ID,
            .graph = self.graph(),
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }

    pub fn validate(self: *const @This()) !void {
        try self.geometry.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.input_profile, canonicalInputProfile()) or
            anyZero(.{
                self.protocol_profile_sha256,
                self.graph_sha256,
                self.reference_sha256,
                self.schedule_sha256,
                self.air_program_identity,
                self.verifier_program_authority,
            }))
        {
            return error.InvalidProviderShardVerifierProgram;
        }
        try self.graph().validate();
        const lane_value = self.lane();
        const reference_sha256 = graph_mod.computeReferenceDigest(
            lane_value,
            &.{},
            &.{},
        );
        if (!std.meta.eql(reference_sha256, self.reference_sha256))
            return error.InvalidProviderShardVerifierProgram;
        const reference = try graph_mod.Reference.authenticate(
            lane_value,
            &.{},
            &.{},
            reference_sha256,
        );
        var schedule = try graph_mod.compile(self.allocator, &reference);
        defer schedule.deinit();
        if (!std.meta.eql(schedule.authority_digest, self.schedule_sha256) or
            !std.meta.eql(self.air_program_identity, self.computeAirIdentity()) or
            !std.meta.eql(
                self.verifier_program_authority,
                self.computeVerifierAuthority(),
            ))
        {
            return error.InvalidProviderShardVerifierProgram;
        }
    }

    pub fn validateAgainst(
        self: *const @This(),
        input: CompilerInputV1,
    ) !void {
        try self.validate();
        var expected = try compile(self.allocator, input);
        defer expected.deinit();
        if (!programsEqual(self, &expected))
            return error.ProviderShardVerifierProgramMismatch;
    }

    fn computeAirIdentity(self: *const @This()) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(AIR_PROGRAM_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u32, CIRCUIT_ID);
        hashGeometry(&hash, self.geometry);
        hashInputProfile(&hash, self.input_profile);
        hash.update(&self.graph_sha256);
        hash.update(&self.reference_sha256);
        hash.update(&self.schedule_sha256);
        return hash.finalResult();
    }

    fn computeVerifierAuthority(self: *const @This()) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(VERIFIER_PROGRAM_DOMAIN);
        hash.update(&self.air_program_identity);
        hash.update(&self.protocol_profile_sha256);
        hash.update(&self.schedule_sha256);
        return hash.finalResult();
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    input: CompilerInputV1,
) !ProviderShardCompositionProgramV1 {
    const geometry = try SemanticGeometryV1.init(input);
    try geometry.validate();
    try (protocol.Profile{}).validate();
    const input_profile = canonicalInputProfile();

    var builder = support.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(
        try graph_mod.vmInputCount(input_profile),
        hash_component.N_POSEIDON_COMPONENT_CONSTRAINTS +
            provider_order.constraint_count + 16,
    );
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const selector = try builder.input(.segment_selector);
    var sampled: [SAMPLED_VALUE_COUNT]Scalar = undefined;
    for (&sampled, 0..) |*value, index| value.* = try support.secureInput(
        &builder,
        .sampled_value,
        @intCast(index),
    );
    var claims: [CLAIMED_SUM_COUNT]Scalar = undefined;
    for (&claims, 0..) |*value, index| value.* = try support.secureInput(
        &builder,
        .claimed_sum,
        @intCast(index),
    );
    var challenge_draws: [RELATION_CHALLENGE_COUNT][2]Scalar = undefined;
    for (&challenge_draws, 0..) |*draw, index| {
        draw[0] = try support.challengeInput(&builder, @intCast(index), 0);
        draw[1] = try support.challengeInput(&builder, @intCast(index), 4);
    }
    const composition_randomness = try support.scalarInput(
        &builder,
        .composition_randomness,
    );
    const oods_seed = try support.scalarInput(&builder, .oods_point);
    try builder.check();

    const is_first = sampled[TREE0_OFFSET];
    const is_active = sampled[TREE0_OFFSET + 1];
    const main = sampled[TREE1_OFFSET..][0..MAIN_COLUMN_COUNT].*;
    const poseidon_current = interactionSecureValues(
        sampled[TREE2_OFFSET..],
        0,
        poseidon2_air.N_SUMS,
    );
    const poseidon_previous = interactionSecureValues(
        sampled[TREE2_OFFSET..],
        1,
        poseidon2_air.N_SUMS,
    );
    const relations = circuit.GraphRelations.init(challenge_draws);
    const point = support.pointFromSeed(oods_seed);
    var denominator_cache: [31]?Scalar = .{null} ** 31;
    const denominator = support.quotientDenominator(
        geometry.log_size,
        geometry.max_constraint_log_degree_bound,
        point,
        &denominator_cache,
    );
    var accumulation = Scalar.zero();
    const poseidon_constraints = hash_component.poseidonConstraintsGeneric(
        Scalar,
        main,
        is_active,
        is_first,
        poseidon_current,
        poseidon_previous,
        claims[0..poseidon2_air.N_SUMS].*,
        &relations,
    );
    for (poseidon_constraints) |constraint| support.accumulate(
        &accumulation,
        composition_randomness,
        constraint,
        denominator,
    );

    const order_column_offset = 2 * POSEIDON_INTERACTION_COLUMN_COUNT;
    const order_current = secureInteraction(
        sampled[TREE2_OFFSET..],
        order_column_offset,
        0,
    );
    const order_previous = secureInteraction(
        sampled[TREE2_OFFSET..],
        order_column_offset,
        1,
    );
    const order_constraints = provider_order.evaluateGeneric(
        Scalar,
        main,
        order_current,
        order_previous,
        is_first,
        is_active,
        relations.poseidon2.z.add(Scalar.fromBase(
            core.fields.m31.M31.fromCanonical(0x4f52_4452),
        )),
        relations.poseidon2.alphaValue().add(Scalar.fromBase(
            core.fields.m31.M31.fromCanonical(0x4143_4355),
        )),
        geometry.first_call,
        geometry.call_count,
        claims[poseidon2_air.N_SUMS],
    );
    for (order_constraints) |constraint| support.accumulate(
        &accumulation,
        composition_randomness,
        constraint,
        denominator,
    );

    var chunks: [2]Scalar = undefined;
    for (&chunks, 0..) |*chunk, chunk_index| {
        var coordinates: [4]Scalar = undefined;
        for (&coordinates, 0..) |*coordinate, coordinate_index| {
            coordinate.* = sampled[
                TREE3_OFFSET + chunk_index * 4 + coordinate_index
            ];
        }
        chunk.* = support.fromPartialEvals(coordinates);
    }
    const composition = chunks[0].add(
        point.repeatedDouble(geometry.composition_log_size - 2).x.mul(chunks[1]),
    );
    try builder.constrainZero(selector.mul(composition.sub(accumulation)));
    try builder.check();

    const nodes = try builder.nodes.toOwnedSlice(allocator);
    errdefer allocator.free(nodes);
    const outputs = try builder.outputs.toOwnedSlice(allocator);
    errdefer allocator.free(outputs);
    const bindings = try builder.bindings.toOwnedSlice(allocator);
    errdefer allocator.free(bindings);
    const graph_sha256 = graph_mod.computeGraphDigest(nodes, outputs);
    const lane = graph_mod.VmLane{
        .circuit_id = CIRCUIT_ID,
        .graph = .{
            .nodes = nodes,
            .outputs = outputs,
            .identity_digest = graph_sha256,
        },
        .profile = input_profile,
        .bindings = bindings,
    };
    const reference_sha256 = graph_mod.computeReferenceDigest(lane, &.{}, &.{});
    const reference = try graph_mod.Reference.authenticate(
        lane,
        &.{},
        &.{},
        reference_sha256,
    );
    var schedule = try graph_mod.compile(allocator, &reference);
    defer schedule.deinit();
    var result = ProviderShardCompositionProgramV1{
        .allocator = allocator,
        .geometry = geometry,
        .nodes = nodes,
        .outputs = outputs,
        .bindings = bindings,
        .input_profile = input_profile,
        .protocol_profile_sha256 = protocolProfileIdentity(),
        .graph_sha256 = graph_sha256,
        .reference_sha256 = reference_sha256,
        .schedule_sha256 = schedule.authority_digest,
        .air_program_identity = undefined,
        .verifier_program_authority = undefined,
    };
    result.air_program_identity = result.computeAirIdentity();
    result.verifier_program_authority = result.computeVerifierAuthority();
    try result.validate();
    return result;
}

fn canonicalInputProfile() graph_mod.InputProfile {
    return .{
        .sampled_value_count = SAMPLED_VALUE_COUNT,
        .claimed_sum_count = CLAIMED_SUM_COUNT,
        .relation_challenge_count = RELATION_CHALLENGE_COUNT,
    };
}

fn interactionSecureValues(
    sampled: []const Scalar,
    point_index: usize,
    comptime count: usize,
) [count]Scalar {
    var result: [count]Scalar = undefined;
    for (&result, 0..) |*value, index| value.* = secureInteraction(
        sampled,
        index * 8,
        point_index,
    );
    return result;
}

fn secureInteraction(
    sampled: []const Scalar,
    column_sample_offset: usize,
    point_index: usize,
) Scalar {
    var coordinates: [4]Scalar = undefined;
    for (&coordinates, 0..) |*value, coordinate| {
        value.* = sampled[column_sample_offset + coordinate * 2 + point_index];
    }
    return support.fromPartialEvals(coordinates);
}

fn protocolProfileIdentity() [32]u8 {
    const profile = protocol.Profile{};
    var hash = Sha256.init(.{});
    hash.update(PROTOCOL_PROFILE_DOMAIN);
    for (profile.words()) |word| hashInt(&hash, u32, word);
    for (protocol.protocolId()) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn programsEqual(left: *const ProviderShardCompositionProgramV1, right: *const ProviderShardCompositionProgramV1) bool {
    if (!std.meta.eql(left.geometry, right.geometry) or
        !std.meta.eql(left.input_profile, right.input_profile) or
        !std.meta.eql(left.protocol_profile_sha256, right.protocol_profile_sha256) or
        !std.meta.eql(left.graph_sha256, right.graph_sha256) or
        !std.meta.eql(left.reference_sha256, right.reference_sha256) or
        !std.meta.eql(left.schedule_sha256, right.schedule_sha256) or
        !std.meta.eql(left.air_program_identity, right.air_program_identity) or
        !std.meta.eql(left.verifier_program_authority, right.verifier_program_authority) or
        left.nodes.len != right.nodes.len or left.outputs.len != right.outputs.len or
        left.bindings.len != right.bindings.len)
    {
        return false;
    }
    for (left.nodes, right.nodes) |a, b| if (!std.meta.eql(a, b)) return false;
    for (left.outputs, right.outputs) |a, b| if (a != b) return false;
    for (left.bindings, right.bindings) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

fn hashGeometry(hash: *Sha256, value: SemanticGeometryV1) void {
    hashInt(hash, u64, value.first_call);
    hashInt(hash, u32, value.call_count);
    hashInt(hash, u32, value.log_size);
    hashInt(hash, u32, value.max_constraint_log_degree_bound);
    hashInt(hash, u32, value.composition_log_size);
    hashInt(hash, u32, value.composition_log_split);
}

fn hashInputProfile(hash: *Sha256, value: graph_mod.InputProfile) void {
    hashInt(hash, u32, value.sampled_value_count);
    hashInt(hash, u32, value.claimed_sum_count);
    hashInt(hash, u32, value.relation_challenge_count);
    hashInt(hash, u32, value.transcript_claimed_sum_count);
    hashInt(hash, u32, value.public_wire_boundary_count);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn anyZero(values: anytype) bool {
    inline for (values) |value| if (std.mem.allEqual(u8, &value, 0)) return true;
    return false;
}

pub const testing = struct {
    /// Rebuild every public transport seal after an adversarial retained-graph
    /// mutation. Cold validation must still reject against the typed plan.
    pub fn reseal(value: *ProviderShardCompositionProgramV1) !void {
        value.graph_sha256 = graph_mod.computeGraphDigest(
            value.nodes,
            value.outputs,
        );
        const lane_value = value.lane();
        value.reference_sha256 = graph_mod.computeReferenceDigest(
            lane_value,
            &.{},
            &.{},
        );
        const reference = try graph_mod.Reference.authenticate(
            lane_value,
            &.{},
            &.{},
            value.reference_sha256,
        );
        var schedule = try graph_mod.compile(value.allocator, &reference);
        defer schedule.deinit();
        value.schedule_sha256 = schedule.authority_digest;
        value.air_program_identity = value.computeAirIdentity();
        value.verifier_program_authority = value.computeVerifierAuthority();
    }
};

comptime {
    if (TREE_COUNT != 4 or PREPROCESSED_COLUMN_COUNT != 2 or
        MAIN_COLUMN_COUNT != 445 or POSEIDON_INTERACTION_COLUMN_COUNT != 8 or
        ORDER_INTERACTION_COLUMN_COUNT != 4 or INTERACTION_COLUMN_COUNT != 12 or
        COMPOSITION_COLUMN_COUNT != 8 or CLAIMED_SUM_COUNT != 3 or
        RELATION_CHALLENGE_COUNT != 12 or SAMPLED_VALUE_COUNT != 479 or
        hash_component.N_POSEIDON_COMPONENT_CONSTRAINTS != 435 or
        provider_order.constraint_count != 4 or COMPOSITION_SPLIT != 1)
    {
        @compileError("provider-shard verifier-program geometry drifted");
    }
}
