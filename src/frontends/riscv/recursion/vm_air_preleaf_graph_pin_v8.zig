//! Capture-free VM AIR graph authority for the direct SegmentV2 leaf.
//!
//! A verifier selects a public statement geometry and two expected IDs before
//! accepting the child proof. This compiler rebuilds the exact base row-18
//! graph from that statement and the native lookup manifest. Proof-specific
//! sampled values, claims, challenges and OODS seed are only graph inputs.
//! It does not accept `NativeCapture` or mint its expected IDs from one.
const std = @import("std");
const statement_mod = @import("../air/statement.zig");
const manifest_mod = @import("../air/lang/lookup_physical_manifest_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const lookup_compiler = @import("vm_selected_lookup_compiler_v2.zig");
const graph = @import("air/composition_circuit.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const circuit_validation = @import("vm_air_composition_circuit_validate_sample_geometry.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const transcript = @import("../air/transcript/claims.zig");
const base_graph = @import("ethereum_vm_composition_graph_base_v2.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const program = @import("ethereum_vm_composition_program_v2.zig");
const full_key = @import("segment_direct_transcript_lowering_fixed_v8.zig");
const Scalar = support.Scalar;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const FORMAT_VERSION: u16 = 1;
const DOMAIN = "stwo-zig/riscv-vm-preleaf-graph-pin/v1\x00";

/// `statement` is an independently admitted public shape, not reconstructed
/// from `capture.vm_air`. The expected IDs are chosen by the verifier before
/// the leaf arrives; caller-derived IDs from the leaf violate this contract.
pub const Selected = struct {
    statement: *const statement_mod.RiscVStatement,
    expected_statement_geometry_id: [32]u8,
    expected_profile_id: [32]u8,
};

pub const Candidate = struct {
    allocator: std.mem.Allocator,
    nodes: []graph.Node,
    outputs: []u32,
    bindings: []graph.VmInputBinding,
    input_profile: graph.InputProfile,
    statement_geometry_id: [32]u8,
    profile_id: [32]u8,
    graph_id: [32]u8,
    reference_id: [32]u8,
    schedule_id: [32]u8,
    circuit_id: [32]u8,
    seal: [32]u8,

    pub fn compile(allocator: std.mem.Allocator, selected: Selected) !Candidate {
        if (std.mem.allEqual(u8, &selected.expected_statement_geometry_id, 0) or
            std.mem.allEqual(u8, &selected.expected_profile_id, 0))
            return error.MissingPreleafVmAuthorityV8;
        const manifest = manifest_mod.Manifest.native();
        const authenticated = try manifest_mod.AuthenticatedStatement.init(selected.statement, &manifest);
        if (!std.mem.eql(u8, &authenticated.statement_identity, &selected.expected_statement_geometry_id))
            return error.PreleafVmStatementGeometryMismatchV8;
        const sample_count = try geometry_mod.expectedSampledValueCount(selected.statement, &manifest);
        var profile = try profile_mod.deriveAuthority(allocator, selected.statement, &manifest, &authenticated, sample_count);
        defer profile.deinit();
        if (!std.mem.eql(u8, &profile.identity_digest, &selected.expected_profile_id))
            return error.PreleafVmProfileMismatchV8;
        var geometry = try geometry_mod.GeometryV2.init(allocator, &profile);
        defer geometry.deinit();
        const selected_lookup = try lookup_compiler.CompilerV2.init(allocator, selected.statement, &manifest, &authenticated, &profile);
        const input_profile = graph.InputProfile{
            .sampled_value_count = geometry.sampled_value_count,
            .claimed_sum_count = profile.input_profile.claimed_sum_count,
            .relation_challenge_count = relations_mod.RELATION_COUNT,
            .transcript_claimed_sum_count = transcript.COMPONENT_COUNT,
        };
        var builder = support.Builder.init(allocator);
        defer builder.deinit();
        try builder.reserve(try graph.vmInputCount(input_profile), profile.air_instruction_count + transcript.COMPONENT_COUNT + 1);
        circuit.installBuilder(&builder);
        defer circuit.uninstallBuilder();

        const selector = try builder.input(.segment_selector);
        const sampled = try allocator.alloc(Scalar, input_profile.sampled_value_count);
        defer allocator.free(sampled);
        for (sampled, 0..) |*value, index|
            value.* = try support.secureInput(&builder, .sampled_value, @intCast(index));
        const claims = try allocator.alloc(Scalar, input_profile.claimed_sum_count);
        defer allocator.free(claims);
        for (claims, 0..) |*value, index|
            value.* = try support.secureInput(&builder, .claimed_sum, @intCast(index));
        var aggregates: [transcript.COMPONENT_COUNT]Scalar = undefined;
        for (&aggregates, 0..) |*value, index|
            value.* = try support.secureInput(&builder, .transcript_claimed_sum, @intCast(index));
        var draws: [relations_mod.RELATION_COUNT][2]Scalar = undefined;
        for (&draws, 0..) |*pair, index| {
            pair[0] = try support.challengeInput(&builder, @intCast(index), 0);
            pair[1] = try support.challengeInput(&builder, @intCast(index), 4);
        }
        const randomness = try support.scalarInput(&builder, .composition_randomness);
        const seed = try support.scalarInput(&builder, .oods_point);
        try program.bindTranscriptAggregates(&builder, selector, &profile, null, claims, &aggregates);
        const relations = circuit.GraphRelations.init(draws);
        var layout = try support.SampleLayoutV2.init(allocator, &geometry, null, sampled);
        defer layout.deinit();
        const point = support.pointFromSeed(seed);
        var denominators: [31]?Scalar = .{null} ** 31;
        const recorded = try base_graph.record(.legacy_role_filtered_v1, &profile, &manifest, &selected_lookup, &layout, claims, &relations, point, randomness, profile.max_log_degree_bound, &denominators);
        const composition = try support.reconstructComposition(&layout, point, profile.composition_log_degree_bound, profile.composition_log_split);
        try builder.constrainZero(selector.mul(composition.sub(recorded.accumulation)));
        try builder.check();

        const nodes = try allocator.dupe(graph.Node, builder.nodes.items);
        errdefer allocator.free(nodes);
        const outputs = try allocator.dupe(u32, builder.outputs.items);
        errdefer allocator.free(outputs);
        const bindings = try allocator.dupe(graph.VmInputBinding, builder.bindings.items);
        errdefer allocator.free(bindings);
        const graph_id = graph.computeGraphDigest(nodes, outputs);
        const lane = graph.VmLane{
            .circuit_id = circuit.CIRCUIT_ID,
            .graph = try graph.CircuitGraph.authenticate(nodes, outputs, graph_id),
            .profile = input_profile,
            .bindings = bindings,
        };
        const reference_id = graph.computeReferenceDigest(lane, &.{}, &.{});
        const reference = try graph.Reference.authenticate(lane, &.{}, &.{}, reference_id);
        var schedule = try graph.compile(allocator, &reference);
        defer schedule.deinit();
        const circuit_id = circuit_validation.circuitDigest(
            profile.identity_digest,
            graph_id,
            reference_id,
            schedule.authority_digest,
            input_profile,
            bindings,
        );
        var result = Candidate{
            .allocator = allocator,
            .nodes = nodes,
            .outputs = outputs,
            .bindings = bindings,
            .input_profile = input_profile,
            .statement_geometry_id = authenticated.statement_identity,
            .profile_id = profile.identity_digest,
            .graph_id = graph_id,
            .reference_id = reference_id,
            .schedule_id = schedule.authority_digest,
            .circuit_id = circuit_id,
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    pub fn deinit(self: *Candidate) void {
        self.allocator.free(self.bindings);
        self.allocator.free(self.outputs);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn graphView(self: *const Candidate) !graph.CircuitGraph {
        return graph.CircuitGraph.authenticate(self.nodes, self.outputs, self.graph_id);
    }

    pub fn vmPin(self: *const Candidate) full_key.VmPin {
        return .{ .circuit_identity = self.circuit_id, .graph_id = self.graph_id };
    }

    pub fn validate(self: *const Candidate, allocator: std.mem.Allocator, selected: Selected) !void {
        const view = try self.graphView();
        try self.vmPin().validate(view);
        var fresh = try compile(allocator, selected);
        defer fresh.deinit();
        if (!std.mem.eql(u8, &self.seal, &self.computeSeal()) or
            !std.mem.eql(u8, &self.seal, &fresh.seal) or
            !std.mem.eql(u8, &self.circuit_id, &fresh.circuit_id) or
            !std.mem.eql(u8, &self.graph_id, &fresh.graph_id))
            return error.PreleafVmPinMismatchV8;
    }

    pub fn validateCapturedPrepared(
        self: *const Candidate,
        allocator: std.mem.Allocator,
        selected: Selected,
        prepared: *const circuit.Prepared,
    ) !void {
        try self.validate(allocator, selected);
        try prepared.validate();
        if (!std.mem.eql(u8, &self.graph_id, &prepared.circuit.graph_digest) or
            !std.mem.eql(u8, &self.circuit_id, &prepared.circuit.identity_digest) or
            !std.mem.eql(u8, &self.reference_id, &prepared.circuit.reference_digest) or
            !std.mem.eql(u8, &self.schedule_id, &prepared.circuit.schedule_digest) or
            !std.mem.eql(u8, &self.profile_id, &prepared.circuit.air_profile_digest))
            return error.CapturedVmGraphMismatchV8;
    }

    fn computeSeal(self: *const Candidate) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.statement_geometry_id);
        hash.update(&self.profile_id);
        hash.update(&self.graph_id);
        hash.update(&self.reference_id);
        hash.update(&self.schedule_id);
        hash.update(&self.circuit_id);
        return hash.finalResult();
    }
};

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    const bytes = std.mem.toBytes(std.mem.nativeToLittle(T, value));
    hash.update(&bytes);
}

test "V8 VM preleaf compiler rejects absent and changed public shape pins" {
    const allocator = std.testing.allocator;
    const fixture = @import("ethereum_leaf_context_v1_test_support.zig");
    const statement = fixture.retainedSegmentZeroCore();
    const manifest = manifest_mod.Manifest.native();
    const authenticated = try manifest_mod.AuthenticatedStatement.init(&statement, &manifest);
    const sample_count = try geometry_mod.expectedSampledValueCount(&statement, &manifest);
    var profile = try profile_mod.deriveAuthority(allocator, &statement, &manifest, &authenticated, sample_count);
    defer profile.deinit();
    const selected = Selected{
        .statement = &statement,
        .expected_statement_geometry_id = authenticated.statement_identity,
        .expected_profile_id = profile.identity_digest,
    };
    var candidate = try Candidate.compile(allocator, selected);
    defer candidate.deinit();
    try candidate.validate(allocator, selected);
    try std.testing.expect(candidate.nodes.len > candidate.bindings.len);
    var missing = selected;
    missing.expected_statement_geometry_id = [_]u8{0} ** 32;
    try std.testing.expectError(error.MissingPreleafVmAuthorityV8, Candidate.compile(allocator, missing));
    var wrong_statement = selected;
    wrong_statement.expected_statement_geometry_id[0] ^= 1;
    try std.testing.expectError(error.PreleafVmStatementGeometryMismatchV8, Candidate.compile(allocator, wrong_statement));
    var wrong_profile = selected;
    wrong_profile.expected_profile_id[0] ^= 1;
    try std.testing.expectError(error.PreleafVmProfileMismatchV8, Candidate.compile(allocator, wrong_profile));
    var changed_statement = statement;
    changed_statement.component_descs[0].n_rows += 1;
    var changed_selected = selected;
    changed_selected.statement = &changed_statement;
    try std.testing.expectError(error.PreleafVmStatementGeometryMismatchV8, Candidate.compile(allocator, changed_selected));
    var mutated = candidate;
    mutated.seal[0] ^= 1;
    try std.testing.expectError(error.PreleafVmPinMismatchV8, mutated.validate(allocator, selected));
}
