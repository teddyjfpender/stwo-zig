//! Proof-independent verifier program for one dynamic Ethereum VM leaf.
//!
//! This compiler consumes only trusted statements and frozen typed program
//! authorities.  Sampled values, claimed sums, transcript draws, and proof
//! commitments are graph inputs and therefore cannot alter the AIR program.
//! A later fresh-verifier capability must bind this authority to the actual
//! preprocessed commitment root before publishing a verified-node descriptor.

const std = @import("std");
const graph_mod = @import("air/composition_circuit.zig");
const component_order = @import("../air/component_order.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const lookup_manifest = @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");

const base_geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const base_graph = @import("ethereum_vm_composition_graph_base_v2.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const extension_geometry_mod =
    @import("ethereum_composition_extension_geometry_v2.zig");
const extension_graph =
    @import("ethereum_vm_composition_graph_extension_v2.zig");
const relations_mod = @import("ethereum_composition_relations_v2.zig");
const selected_lookup = @import("vm_selected_lookup_compiler_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const protocol = @import("protocol.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = support.Scalar;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = circuit.CIRCUIT_ID;
pub const BASE_TRANSCRIPT_CLAIM_COUNT: usize = transcript_claims.COMPONENT_COUNT;
pub const EXTENSION_TRANSCRIPT_CLAIM_COUNT: usize =
    ethereum_statement.component_count;
pub const TRANSCRIPT_CLAIM_COUNT: usize = BASE_TRANSCRIPT_CLAIM_COUNT +
    EXTENSION_TRANSCRIPT_CLAIM_COUNT;

const AIR_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-vm-air-program/v2\x00";
const VERIFIER_PROGRAM_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-vm-verifier-program/v2\x00";
const PROTOCOL_PROFILE_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-vm-protocol-profile/v2\x00";

pub const CompilerInputV2 = struct {
    core_statement: *const statement_mod.RiscVStatement,
    extension_statement: *const ethereum_statement.Statement,
    lookup_manifest: *const lookup_manifest.Manifest,
    authenticated_lookup: *const lookup_manifest.AuthenticatedStatement,
    base_profile: *const profile_mod.ProfileV2,
};

/// Pointer-free AIR program authority. It intentionally carries no proof
/// instance identity and no preprocessed commitment root.
pub const EthereumVmCompositionProgramV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    nodes: []graph_mod.Node,
    outputs: []u32,
    bindings: []graph_mod.VmInputBinding,
    input_profile: graph_mod.InputProfile,
    base_profile_sha256: [32]u8,
    base_geometry_sha256: [32]u8,
    extension_geometry_sha256: [32]u8,
    selected_lookup_compiler_sha256: [32]u8,
    protocol_profile_sha256: [32]u8,
    graph_sha256: [32]u8,
    reference_sha256: [32]u8,
    schedule_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,

    pub fn deinit(self: *EthereumVmCompositionProgramV2) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graph(self: *const EthereumVmCompositionProgramV2) graph_mod.CircuitGraph {
        return .{
            .nodes = self.nodes,
            .outputs = self.outputs,
            .identity_digest = self.graph_sha256,
        };
    }

    pub fn lane(self: *const EthereumVmCompositionProgramV2) graph_mod.VmLane {
        return .{
            .circuit_id = CIRCUIT_ID,
            .graph = self.graph(),
            .profile = self.input_profile,
            .bindings = self.bindings,
        };
    }

    pub fn validate(self: *const EthereumVmCompositionProgramV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.input_profile.relation_challenge_count !=
                relations_mod.RELATION_COUNT or
            self.input_profile.transcript_claimed_sum_count !=
                TRANSCRIPT_CLAIM_COUNT or
            self.input_profile.public_wire_boundary_count != 0 or
            anyZero(.{
                self.base_profile_sha256,
                self.base_geometry_sha256,
                self.extension_geometry_sha256,
                self.selected_lookup_compiler_sha256,
                self.protocol_profile_sha256,
                self.graph_sha256,
                self.reference_sha256,
                self.schedule_sha256,
                self.air_program_identity,
                self.verifier_program_authority,
            }))
        {
            return error.InvalidVerifierProgram;
        }
        try self.graph().validate();
        const lane_value = self.lane();
        const reference_sha256 = graph_mod.computeReferenceDigest(
            lane_value,
            &.{},
            &.{},
        );
        if (!std.mem.eql(u8, &reference_sha256, &self.reference_sha256))
            return error.InvalidVerifierProgram;
        const reference = try graph_mod.Reference.authenticate(
            lane_value,
            &.{},
            &.{},
            reference_sha256,
        );
        var schedule = try graph_mod.compile(self.allocator, &reference);
        defer schedule.deinit();
        if (!std.mem.eql(
            u8,
            &schedule.authority_digest,
            &self.schedule_sha256,
        ) or !std.mem.eql(
            u8,
            &protocolProfileIdentity(),
            &self.protocol_profile_sha256,
        ) or !std.mem.eql(
            u8,
            &self.computeAirProgramIdentity(),
            &self.air_program_identity,
        ) or !std.mem.eql(
            u8,
            &self.computeVerifierProgramAuthority(),
            &self.verifier_program_authority,
        )) return error.InvalidVerifierProgram;
    }

    /// Cold recompile against trusted typed sources. A serialized program is
    /// never permitted to route its own evaluator, mask, or lookup schedule.
    pub fn validateAgainst(
        self: *const EthereumVmCompositionProgramV2,
        input: CompilerInputV2,
    ) !void {
        try self.validate();
        var expected = try compile(self.allocator, input);
        defer expected.deinit();
        if (!programsEqual(self, &expected))
            return error.VerifierProgramMismatch;
    }

    fn computeAirProgramIdentity(
        self: *const EthereumVmCompositionProgramV2,
    ) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(AIR_PROGRAM_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u32, CIRCUIT_ID);
        hash.update(&self.base_profile_sha256);
        hash.update(&self.base_geometry_sha256);
        hash.update(&self.extension_geometry_sha256);
        hash.update(&self.selected_lookup_compiler_sha256);
        hash.update(&self.graph_sha256);
        hash.update(&self.reference_sha256);
        hash.update(&self.schedule_sha256);
        hashInputProfile(&hash, self.input_profile);
        return hash.finalResult();
    }

    fn computeVerifierProgramAuthority(
        self: *const EthereumVmCompositionProgramV2,
    ) [32]u8 {
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
    input: CompilerInputV2,
) !EthereumVmCompositionProgramV2 {
    try input.base_profile.validateAuthority(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
    );
    try input.extension_statement.validateStructure(input.core_statement);
    try (protocol.Profile{}).validate();

    var base_geometry = try base_geometry_mod.GeometryV2.init(
        allocator,
        input.base_profile,
    );
    defer base_geometry.deinit();
    var extension_geometry = try extension_geometry_mod.GeometryV2.init(
        allocator,
        input.base_profile,
        input.core_statement,
        input.extension_statement,
    );
    defer extension_geometry.deinit();
    const selected = try selected_lookup.CompilerV2.init(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
        input.base_profile,
    );
    try selected.validateAuthority(
        allocator,
        input.core_statement,
        input.lookup_manifest,
        input.authenticated_lookup,
        input.base_profile,
    );

    const sampled_value_count = try add(
        base_geometry.sampled_value_count,
        extension_geometry.sampled_value_count,
    );
    const claimed_sum_count = try add(
        input.base_profile.input_profile.claimed_sum_count,
        extension_geometry.detailed_claim_count,
    );
    const input_profile = graph_mod.InputProfile{
        .sampled_value_count = sampled_value_count,
        .claimed_sum_count = claimed_sum_count,
        .relation_challenge_count = relations_mod.RELATION_COUNT,
        .transcript_claimed_sum_count = TRANSCRIPT_CLAIM_COUNT,
    };
    const input_count = try graph_mod.vmInputCount(input_profile);
    const air_instruction_count = try add(
        input.base_profile.air_instruction_count,
        extension_geometry.air_instruction_count,
    );

    var builder = support.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(
        input_count,
        try add(air_instruction_count, TRANSCRIPT_CLAIM_COUNT + 1),
    );
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const selector = try builder.input(.segment_selector);
    const sampled = try allocator.alloc(Scalar, sampled_value_count);
    defer allocator.free(sampled);
    for (sampled, 0..) |*value, item| value.* = try support.secureInput(
        &builder,
        .sampled_value,
        @intCast(item),
    );
    const claims = try allocator.alloc(Scalar, claimed_sum_count);
    defer allocator.free(claims);
    for (claims, 0..) |*value, item| value.* = try support.secureInput(
        &builder,
        .claimed_sum,
        @intCast(item),
    );
    var transcript_aggregates: [TRANSCRIPT_CLAIM_COUNT]Scalar = undefined;
    for (&transcript_aggregates, 0..) |*value, item| {
        value.* = try support.secureInput(
            &builder,
            .transcript_claimed_sum,
            @intCast(item),
        );
    }
    var base_draws: [relations_mod.BASE_RELATION_COUNT][2]Scalar = undefined;
    for (&base_draws, 0..) |*pair, challenge| {
        pair[0] = try support.challengeInput(&builder, @intCast(challenge), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(challenge), 4);
    }
    var extension_draws: [relations_mod.EXTENSION_RELATION_COUNT][2]Scalar =
        undefined;
    for (&extension_draws, 0..) |*pair, extension_challenge| {
        const challenge = relations_mod.BASE_RELATION_COUNT + extension_challenge;
        pair[0] = try support.challengeInput(&builder, @intCast(challenge), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(challenge), 4);
    }
    const composition_randomness = try support.scalarInput(
        &builder,
        .composition_randomness,
    );
    const oods_seed = try support.scalarInput(&builder, .oods_point);
    try builder.check();

    try bindTranscriptAggregates(
        &builder,
        selector,
        input.base_profile,
        &extension_geometry,
        claims,
        transcript_aggregates,
    );
    const relations = relations_mod.RelationsV2.init(
        base_draws,
        extension_draws,
    );
    var layout = try support.SampleLayoutV2.init(
        allocator,
        &base_geometry,
        &extension_geometry,
        sampled,
    );
    defer layout.deinit();
    const point = support.pointFromSeed(oods_seed);
    var denominators: [31]?Scalar = .{null} ** 31;
    const base_result = try base_graph.record(
        input.base_profile,
        input.lookup_manifest,
        &selected,
        &layout,
        claims[0..@as(usize, input.base_profile.input_profile.claimed_sum_count)],
        &relations,
        point,
        composition_randomness,
        extension_geometry.max_log_degree_bound,
        &denominators,
    );
    const extension_result = try extension_graph.record(
        &extension_geometry,
        &layout,
        claims[@as(usize, input.base_profile.input_profile.claimed_sum_count)..],
        &relations,
        point,
        composition_randomness,
        &denominators,
        base_result.accumulation,
    );
    if (try add(base_result.instruction_count, extension_result.instruction_count) !=
        air_instruction_count)
    {
        return error.InvalidInstructionCount;
    }
    const composition = try support.reconstructComposition(
        &layout,
        point,
        extension_geometry.max_log_degree_bound,
        input.base_profile.composition_log_split,
    );
    try builder.constrainZero(selector.mul(
        composition.sub(extension_result.accumulation),
    ));
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

    var result = EthereumVmCompositionProgramV2{
        .allocator = allocator,
        .nodes = nodes,
        .outputs = outputs,
        .bindings = bindings,
        .input_profile = input_profile,
        .base_profile_sha256 = input.base_profile.identity_digest,
        .base_geometry_sha256 = base_geometry.identity_sha256,
        .extension_geometry_sha256 = extension_geometry.identity_sha256,
        .selected_lookup_compiler_sha256 = selected.identity_sha256,
        .protocol_profile_sha256 = protocolProfileIdentity(),
        .graph_sha256 = graph_sha256,
        .reference_sha256 = reference_sha256,
        .schedule_sha256 = schedule.authority_digest,
        .air_program_identity = undefined,
        .verifier_program_authority = undefined,
    };
    result.air_program_identity = result.computeAirProgramIdentity();
    result.verifier_program_authority =
        result.computeVerifierProgramAuthority();
    try result.validate();
    return result;
}

fn bindTranscriptAggregates(
    builder: *support.Builder,
    selector: Scalar,
    profile: *const profile_mod.ProfileV2,
    extension: *const extension_geometry_mod.GeometryV2,
    claims: []const Scalar,
    transcript_aggregates: [TRANSCRIPT_CLAIM_COUNT]Scalar,
) !void {
    var reconstructed = [_]Scalar{Scalar.zero()} ** TRANSCRIPT_CLAIM_COUNT;
    for (profile.entries) |entry| switch (entry.registry) {
        .opcode_lookup => |key| try addClaimRange(
            &reconstructed[
                @intFromEnum(
                    component_order.transcriptComponentForOpcodeFamily(key.family),
                )
            ],
            claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
        .infrastructure => |key| try addClaimRange(
            &reconstructed[@intFromEnum(transcriptComponentForInfra(key.kind))],
            claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
        .opcode_semantic => {},
    };
    var claim_cursor: u32 = profile.input_profile.claimed_sum_count;
    for (extension.components, 0..) |component, component_index| {
        try addClaimRange(
            &reconstructed[BASE_TRANSCRIPT_CLAIM_COUNT + component_index],
            claims,
            claim_cursor,
            component.interaction_batch_count,
        );
        claim_cursor = try add(claim_cursor, component.interaction_batch_count);
    }
    if (@as(usize, claim_cursor) != claims.len) return error.InvalidClaimCount;
    for (transcript_aggregates, reconstructed) |authenticated, aggregate| {
        try builder.constrainZero(selector.mul(authenticated.sub(aggregate)));
    }
    try builder.check();
}

fn addClaimRange(
    destination: *Scalar,
    claims: []const Scalar,
    offset: u32,
    count: u32,
) !void {
    const start: usize = offset;
    const end = std.math.add(usize, start, @as(usize, count)) catch
        return error.ArithmeticOverflow;
    if (end > claims.len) return error.InvalidClaimCount;
    for (claims[start..end]) |claim|
        destination.* = destination.add(claim);
}

fn transcriptComponentForInfra(
    kind: statement_mod.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn protocolProfileIdentity() [32]u8 {
    const profile = protocol.Profile{};
    var hash = Sha256.init(.{});
    hash.update(PROTOCOL_PROFILE_DOMAIN);
    for (profile.words()) |word| hashInt(&hash, u32, word);
    for (protocol.protocolId()) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn programsEqual(
    left: *const EthereumVmCompositionProgramV2,
    right: *const EthereumVmCompositionProgramV2,
) bool {
    if (left.format_version != right.format_version or
        left.schema_version != right.schema_version or
        !std.meta.eql(left.input_profile, right.input_profile) or
        !std.meta.eql(left.base_profile_sha256, right.base_profile_sha256) or
        !std.meta.eql(left.base_geometry_sha256, right.base_geometry_sha256) or
        !std.meta.eql(left.extension_geometry_sha256, right.extension_geometry_sha256) or
        !std.meta.eql(left.selected_lookup_compiler_sha256, right.selected_lookup_compiler_sha256) or
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

fn hashInputProfile(hash: *Sha256, profile: graph_mod.InputProfile) void {
    hashInt(hash, u32, profile.sampled_value_count);
    hashInt(hash, u32, profile.claimed_sum_count);
    hashInt(hash, u32, profile.relation_challenge_count);
    hashInt(hash, u32, profile.transcript_claimed_sum_count);
    hashInt(hash, u32, profile.public_wire_boundary_count);
}

fn anyZero(values: anytype) bool {
    inline for (values) |value| if (std.mem.allEqual(u8, &value, 0)) return true;
    return false;
}

fn add(left: u32, right: anytype) !u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        return error.ArithmeticOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    /// Adversarial helper: rebuild every public seal after a retained graph
    /// mutation. `validate` then exercises structural custody, while the cold
    /// `validateAgainst` comparison must still reject the self-consistent but
    /// untrusted verifier program.
    pub fn reseal(value: *EthereumVmCompositionProgramV2) !void {
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
        value.air_program_identity = value.computeAirProgramIdentity();
        value.verifier_program_authority =
            value.computeVerifierProgramAuthority();
    }
};

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        relations_mod.RELATION_COUNT != 25 or TRANSCRIPT_CLAIM_COUNT != 42)
    {
        @compileError("Ethereum VM verifier-program inventory drifted");
    }
}
