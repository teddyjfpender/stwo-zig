//! Opaque real-child custody for temporal-parent recursion rows 18 and 19.
//!
//! Both SegmentV2 children are re-admitted through their verifier-minted
//! publication/capture/witness chain, evaluated by one finalized heterogeneous
//! recorder, and lowered through the existing binary rows-18/19 authority.
//! This module owns no AIR equations and accepts no detached graph, binding,
//! configuration, witness value, or evaluation from its caller.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const binary_composition = @import("recursive_binary_composition_authority.zig");
const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const rows_source = recursion.binary_fri_outer_source;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 3;
pub const CHILD_COUNT: usize = 2;
pub const LEFT_CHILD: usize = 0;
pub const RIGHT_CHILD: usize = 1;
pub const LEFT_CIRCUIT_ID: u32 = 531;
pub const RIGHT_CIRCUIT_ID: u32 = 532;
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row18-source/v3.3\x00";

/// The seam itself is executable; proof readiness remains owned by the
/// complete 36-row manifest/prover/verifier transaction.
pub const REAL_CHILD_ROW18_AUTHORITY_AVAILABLE = true;
pub const ROWS_18_19_REUSE_AVAILABLE = true;
pub const COMPLETE_SUFFIX_AVAILABLE = false;
pub const PRODUCTION_CAPABILITY = false;

pub const Row18AuthorityV3 = opaque {
    pub fn init(
        allocator: std.mem.Allocator,
        inputs: prefix_runtime.RuntimeInputsV1,
        recording: *const composition_v3.RecordedHeterogeneousCircuitV3,
        manifests: composition_v3.TrustedManifestsV3,
        air_program_ids: composition_v3.AirProgramIdsV3,
    ) !*Row18AuthorityV3 {
        _ = try inputs.validate();
        try recording.validate(manifests, air_program_ids);
        const configuration = try recording.configurationSnapshot(
            manifests,
            air_program_ids,
        );
        const descriptor = configuration.program_roster
            .forKind(.segment_leaf).*;
        const circuit_authority_id = (try recording.validatedAuthority(
            manifests,
            air_program_ids,
        )).identity();

        var bridges: [CHILD_COUNT]binary_composition.SegmentV2RecorderBridgeV3 =
            undefined;
        var bridge_count: usize = 0;
        errdefer for (bridges[0..bridge_count]) |*bridge| bridge.deinit();
        for (inputs.artifacts.children, 0..) |child, child_index| {
            bridges[child_index] = try binary_composition
                .SegmentV2RecorderBridgeV3.init(
                allocator,
                inputs.artifacts.segment_composition_profile,
                descriptor,
                inputs.artifacts.segment_manifests[child_index],
                child.capture,
                child.publication,
                child.recursive_witness,
            );
            bridge_count += 1;
        }

        const graph = recording.graph();
        const graph_input_count = try composition.recursionInputCount(
            configuration.graphInputProfile(),
        );
        const input_scratch = try allocator.alloc(QM31, graph_input_count);
        errdefer allocator.free(input_scratch);
        const padded_samples = try allocator.alloc(
            QM31,
            configuration.sampled_value_count,
        );
        errdefer allocator.free(padded_samples);
        const value_count = std.math.mul(
            usize,
            graph.nodes.len,
            CHILD_COUNT,
        ) catch return error.ArithmeticOverflow;
        const node_values = try allocator.alloc(QM31, value_count);
        errdefer allocator.free(node_values);
        const validation_values = try allocator.alloc(QM31, graph.nodes.len);
        errdefer allocator.free(validation_values);

        var evaluations: [CHILD_COUNT]lowering.Evaluation = undefined;
        for (
            inputs.artifacts.children,
            &bridges,
            0..,
        ) |child, *bridge, child_index| {
            const start = child_index * graph.nodes.len;
            const destination = node_values[start..][0..graph.nodes.len];
            const witness = try bridge.concreteWitness(
                allocator,
                inputs.artifacts.segment_manifests[child_index],
                child.capture,
                child.publication,
                child.recursive_witness,
            );
            try recording.evaluateSegmentInto(
                manifests,
                air_program_ids,
                &bridge.layout,
                witness,
                padded_samples,
                input_scratch,
                destination,
            );
            evaluations[child_index] = .{
                .circuit_identity = graph.identity_digest,
                .values = destination,
            };
        }

        const view = try recording.validatedView(manifests, air_program_ids);
        const lanes = [CHILD_COUNT]composition.RecursionLane{
            try view.validatedLane(
                manifests,
                air_program_ids,
                rows_source.LEFT_RECURSION_VERIFIER_ID,
                LEFT_CIRCUIT_ID,
                rows_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
            ),
            try view.validatedLane(
                manifests,
                air_program_ids,
                rows_source.RIGHT_RECURSION_VERIFIER_ID,
                RIGHT_CIRCUIT_ID,
                rows_source.RIGHT_COMPOSITION_STATEMENT_SCOPE,
            ),
        };
        const authority_id = computeAuthorityIdentity(
            configuration,
            circuit_authority_id,
            &bridges,
            lanes,
            evaluations,
            inputs,
        );
        const owned_storage = try allocator.create(Storage);
        owned_storage.* = .{
            .allocator = allocator,
            .recording = recording,
            .manifests = manifests,
            .air_program_ids = air_program_ids,
            .configuration = configuration,
            .circuit_authority_id = circuit_authority_id,
            .bridges = bridges,
            .input_scratch = input_scratch,
            .padded_samples = padded_samples,
            .node_values = node_values,
            .validation_values = validation_values,
            .evaluations = evaluations,
            .lanes = lanes,
            .authority_id = authority_id,
        };
        return handle(owned_storage);
    }

    pub fn deinit(self: *Row18AuthorityV3) void {
        const owner = storage(self);
        const allocator = owner.allocator;
        owner.deinitOwned();
        allocator.destroy(owner);
    }

    pub fn authorityIdentity(self: *const Row18AuthorityV3) [32]u8 {
        return storageConst(self).authority_id;
    }

    /// Creates an independently owned rows-18/19 authority for the exact
    /// outer-proof verifier schedule. The recorder graph and both evaluated
    /// lanes remain borrowed from this opaque authority; no child proof bytes
    /// are reparsed and no claimed-sum coordinate is projected away.
    pub fn cloneRows(
        self: *Row18AuthorityV3,
        allocator: std.mem.Allocator,
        inputs: prefix_runtime.RuntimeInputsV1,
        vm_plan: *const recursion.air.verifier_schedule.Plan,
        recursion_plan: *const recursion.air.verifier_schedule.Plan,
        sampled_value_count: u32,
    ) !rows_source.CompositionRowsAuthority {
        try self.validateAgainst(inputs);
        const owner = storageConst(self);
        var result = try rows_source.CompositionRowsAuthority
            .initFromAuthenticatedRecorderLanes(
            allocator,
            vm_plan,
            recursion_plan,
            sampled_value_count,
            owner.lanes,
            owner.evaluations,
        );
        errdefer result.deinit();
        try result.control_preprocessing.validateAgainst(
            vm_plan,
            recursion_plan,
        );
        try result.validateAuthenticatedRecorderLanes(owner.evaluations);
        return result;
    }

    /// Borrowed composition views for the shared arithmetic lowering. The
    /// evaluation slices remain owned by this opaque authority and are valid
    /// until `deinit`; callers may not replace either graph or evaluation.
    pub fn arithmeticLanes(
        self: *const Row18AuthorityV3,
    ) [CHILD_COUNT]rows_source.AuthenticatedCompositionLane {
        const owner = storageConst(self);
        const graph = owner.recording.graph();
        return .{
            .{
                .circuit_id = LEFT_CIRCUIT_ID,
                .circuit_identity = graph.identity_digest,
                .graph = graph,
                .evaluation = owner.evaluations[LEFT_CHILD],
            },
            .{
                .circuit_id = RIGHT_CIRCUIT_ID,
                .circuit_identity = graph.identity_digest,
                .graph = graph,
                .evaluation = owner.evaluations[RIGHT_CHILD],
            },
        };
    }

    /// Replays both external child chains and the opaque recorder into a
    /// separate scratch evaluation before comparing every graph node. No
    /// rejected mutation can rewrite the retained row-18 schedule authority.
    pub fn validateAgainst(
        self: *Row18AuthorityV3,
        inputs: prefix_runtime.RuntimeInputsV1,
    ) !void {
        const owner = storage(self);
        _ = try inputs.validate();
        try owner.recording.validate(owner.manifests, owner.air_program_ids);
        const configuration = try owner.recording.configurationSnapshot(
            owner.manifests,
            owner.air_program_ids,
        );
        const current_circuit_authority_id = (try owner.recording
            .validatedAuthority(
            owner.manifests,
            owner.air_program_ids,
        )).identity();
        if (!std.meta.eql(configuration, owner.configuration) or
            !std.mem.eql(
                u8,
                &current_circuit_authority_id,
                &owner.circuit_authority_id,
            ))
        {
            return error.AuthorityMismatch;
        }

        for (
            inputs.artifacts.children,
            &owner.bridges,
            owner.evaluations,
            inputs.artifacts.segment_manifests,
        ) |child, *bridge, expected, child_manifest| {
            const witness = try bridge.concreteWitness(
                owner.allocator,
                child_manifest,
                child.capture,
                child.publication,
                child.recursive_witness,
            );
            try owner.recording.evaluateSegmentInto(
                owner.manifests,
                owner.air_program_ids,
                &bridge.layout,
                witness,
                owner.padded_samples,
                owner.input_scratch,
                owner.validation_values,
            );
            if (!qm31SliceEql(expected.values, owner.validation_values))
                return error.AuthorityMismatch;
        }
        const view = try owner.recording.validatedView(
            owner.manifests,
            owner.air_program_ids,
        );
        const current_lanes = [CHILD_COUNT]composition.RecursionLane{
            try view.validatedLane(
                owner.manifests,
                owner.air_program_ids,
                rows_source.LEFT_RECURSION_VERIFIER_ID,
                LEFT_CIRCUIT_ID,
                rows_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
            ),
            try view.validatedLane(
                owner.manifests,
                owner.air_program_ids,
                rows_source.RIGHT_RECURSION_VERIFIER_ID,
                RIGHT_CIRCUIT_ID,
                rows_source.RIGHT_COMPOSITION_STATEMENT_SCOPE,
            ),
        };
        for (owner.lanes, current_lanes, owner.evaluations) |
            expected_lane,
            current_lane,
            evaluation,
        | {
            try current_lane.graph.validate();
            if (expected_lane.verifier_id != current_lane.verifier_id or
                expected_lane.circuit_id != current_lane.circuit_id or
                expected_lane.statement_scope != current_lane.statement_scope or
                !std.mem.eql(
                    u8,
                    &expected_lane.graph.identity_digest,
                    &current_lane.graph.identity_digest,
                ) or
                !std.meta.eql(expected_lane.profile, current_lane.profile) or
                !std.mem.eql(
                    u8,
                    &current_lane.graph.identity_digest,
                    &evaluation.circuit_identity,
                ) or evaluation.values.len != current_lane.graph.nodes.len)
            {
                return error.AuthorityMismatch;
            }
        }
        if (!std.mem.eql(
            u8,
            &owner.authority_id,
            &computeAuthorityIdentity(
                owner.configuration,
                owner.circuit_authority_id,
                &owner.bridges,
                owner.lanes,
                owner.evaluations,
                inputs,
            ),
        )) return error.AuthorityMismatch;
    }
};

const Storage = struct {
    allocator: std.mem.Allocator,
    recording: *const composition_v3.RecordedHeterogeneousCircuitV3,
    manifests: composition_v3.TrustedManifestsV3,
    air_program_ids: composition_v3.AirProgramIdsV3,
    configuration: composition_v3.ConfigurationV3,
    circuit_authority_id: [32]u8,
    bridges: [CHILD_COUNT]binary_composition.SegmentV2RecorderBridgeV3,
    input_scratch: []QM31,
    padded_samples: []QM31,
    node_values: []QM31,
    validation_values: []QM31,
    evaluations: [CHILD_COUNT]lowering.Evaluation,
    lanes: [CHILD_COUNT]composition.RecursionLane,
    authority_id: [32]u8,

    fn deinitOwned(self: *Storage) void {
        for (&self.bridges) |*bridge| bridge.deinit();
        self.allocator.free(self.validation_values);
        self.allocator.free(self.node_values);
        self.allocator.free(self.padded_samples);
        self.allocator.free(self.input_scratch);
        self.* = undefined;
    }
};

fn handle(value: *Storage) *Row18AuthorityV3 {
    return @ptrCast(value);
}

fn storage(value: *Row18AuthorityV3) *Storage {
    return @ptrCast(@alignCast(value));
}

fn storageConst(value: *const Row18AuthorityV3) *const Storage {
    return @ptrCast(@alignCast(value));
}

fn computeAuthorityIdentity(
    configuration: composition_v3.ConfigurationV3,
    circuit_authority_id: [32]u8,
    bridges: *const [CHILD_COUNT]binary_composition.SegmentV2RecorderBridgeV3,
    lanes: [CHILD_COUNT]composition.RecursionLane,
    evaluations: [CHILD_COUNT]lowering.Evaluation,
    inputs: prefix_runtime.RuntimeInputsV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&configuration.identity);
    hash.update(&circuit_authority_id);
    for (lanes, evaluations) |lane, evaluation| {
        hashInt(&hash, u32, lane.verifier_id);
        hashInt(&hash, u32, lane.circuit_id);
        hashInt(&hash, u32, lane.statement_scope);
        hash.update(&lane.graph.identity_digest);
        hashInt(&hash, u32, lane.profile.sampled_value_count);
        hashInt(&hash, u32, lane.profile.claimed_sum_count);
        hashInt(&hash, u32, lane.profile.relation_challenge_count);
        hashInt(&hash, u32, lane.profile.transcript_claimed_sum_count);
        hashInt(&hash, u32, lane.profile.public_wire_boundary_count);
        hashInt(&hash, u64, @intCast(evaluation.values.len));
        for (evaluation.values) |value| hashQm31(&hash, value);
    }
    for (bridges, inputs.prepared_leaves, inputs.artifacts.children) |
        bridge,
        prepared,
        child,
    | {
        hash.update(&bridge.identity);
        hash.update(&prepared.identity);
        for (child.publication.publication_id) |word|
            hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 3 or CHILD_COUNT != 2 or
        LEFT_CIRCUIT_ID == RIGHT_CIRCUIT_ID or
        !REAL_CHILD_ROW18_AUTHORITY_AVAILABLE or
        !ROWS_18_19_REUSE_AVAILABLE or COMPLETE_SUFFIX_AVAILABLE or
        PRODUCTION_CAPABILITY)
    {
        @compileError("temporal row-18 authority boundary drifted");
    }
    switch (@typeInfo(Row18AuthorityV3)) {
        .@"opaque" => {},
        else => @compileError("temporal row-18 authority must remain opaque"),
    }
}
