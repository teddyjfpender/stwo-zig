//! Owned stage-102 materialization boundary for one full Ethereum V4 leaf.
//!
//! This module consumes a live stage-101 cold-verifier capability, rebuilds
//! the trusted base+Ethereum+bridge composition program, replays the exact
//! native Poseidon transcript, and snapshots the complete FRI witness. It
//! does not yet claim a recursive proof: a role-0 universal-36 cohort must
//! still authenticate these sources under the common fixed wire.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const materializer_support =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4_support.zig");
const public_semantics =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const transcript_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_v4.zig");

const recursion = frontend.recursion;
const captured_fri = recursion.captured_fri;
const base_geometry = recursion.vm_composition_base_geometry_v2;
const base_profile_mod = recursion.vm_air_profile_v2;
const ethereum_geometry = recursion.ethereum_composition_extension_geometry_v2;
const full_program = recursion.incremental_ethereum_vm_composition_program_v4;
const vm_composition = recursion.vm_air_composition_circuit;
const composition_graph = recursion.air.composition_circuit;
const bridge = frontend.air.memory_commitment.incremental_bridge_v2;

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const TREE_COUNT: usize = 4;
pub const BASE_TRANSCRIPT_CLAIM_COUNT: u32 = 28;
pub const ETHEREUM_TRANSCRIPT_CLAIM_COUNT: u32 = 14;
pub const BRIDGE_TRANSCRIPT_CLAIM_COUNT: u32 =
    materializer_support.BRIDGE_TRANSCRIPT_CLAIM_COUNT;
pub const FULL_TRANSCRIPT_CLAIM_COUNT: u32 =
    BASE_TRANSCRIPT_CLAIM_COUNT +
    ETHEREUM_TRANSCRIPT_CLAIM_COUNT +
    BRIDGE_TRANSCRIPT_CLAIM_COUNT;
pub const BRIDGE_DETAILED_CLAIM_COUNT: u32 =
    materializer_support.BRIDGE_DETAILED_CLAIM_COUNT;
pub const BRIDGE_TRACE_SAMPLED_VALUE_COUNT: u32 =
    materializer_support.BRIDGE_TRACE_SAMPLED_VALUE_COUNT;

pub const PRODUCTION_ACTIVATION = false;
pub const UNIVERSAL_COHORT_AVAILABLE = false;
pub const V4_TRANSCRIPT_SOURCE_AVAILABLE = true;
pub const BRIDGE_COMPOSITION_GRAPH_AVAILABLE = true;
pub const WRAPPER_PROOF_AVAILABLE = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalMaterializerMismatchV4,
    EthereumIncrementalProofCaptureShapeMismatchV4,
    MissingBridgeCompositionGraphV4,
};

pub const MaterializationMetricsV4 = materializer_support.MetricsV4;
pub const MaterializationExecutionV4 = materializer_support.ExecutionV4;
pub const ProgramConstructionCustodyV4 =
    materializer_support.ProgramConstructionCustodyV4;
pub const BridgeProjectionV4 = materializer_support.BridgeProjectionV4;

/// Complete owned capture substrate.  `initOwned` moves `input` only after
/// every independently rebuilt authority and FRI replay has succeeded.
pub fn PreparedCaptureV4(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        input: input_mod.FreshInputV4(Engine),
        role_aware_io: role_io.OwnedWitnessV4,
        schedule: field_public.OwnedPoseidonScheduleV4,
        provider_geometry: field_public.LiveProviderGeometryV4,
        completion_program_claim: public_semantics.CompletionProgramClaimV4,
        completion_program_circuit: public_semantics.CompletionProgramCircuitV4,
        completion_program_prepared: public_semantics.PreparedCircuitV4,
        transcript: transcript_mod.ReplayV4,
        base_profile: base_profile_mod.ProfileV2,
        composition_program: full_program.ProgramV4,
        composition_program_custody: ProgramConstructionCustodyV4,
        composition_prepared: vm_composition.Prepared,
        captured_fri: captured_fri.Owned,
        bridge: BridgeProjectionV4,
        base_sampled_value_count: u32,
        ethereum_sampled_value_count: u32,
        full_sampled_value_count: u32,
        full_detailed_claim_count: u32,
        identity_sha256: [32]u8,

        const Self = @This();

        pub fn initOwned(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
        ) !Self {
            return initOwnedMeasuredWithExecution(
                allocator,
                input,
                .{},
                null,
            );
        }

        /// Identical constructor with process-local phase/resource telemetry.
        /// Metrics are diagnostics only and do not enter any proof identity.
        pub fn initOwnedMeasured(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            metrics: ?*MaterializationMetricsV4,
        ) !Self {
            return initOwnedMeasuredWithExecution(
                allocator,
                input,
                .{},
                metrics,
            );
        }

        pub fn initOwnedMeasuredWithExecution(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            execution: MaterializationExecutionV4,
            metrics: ?*MaterializationMetricsV4,
        ) !Self {
            comptime requireEngine(Engine);
            try execution.validate();
            if (metrics) |value| value.* = .{};
            if (metrics) |value| value.schedule_projection_worker_count =
                @intCast(execution.worker_count);
            var total_timer = try std.time.Timer.start();
            var phase_timer = try std.time.Timer.start();
            defer {
                if (metrics) |value| value.total_ns = total_timer.read();
            }
            try input.validate();
            const capture = &input.stage101;
            if (capture.proof.commitments.len != TREE_COUNT or
                capture.proof.column_log_sizes.len != TREE_COUNT)
            {
                return error.EthereumIncrementalProofCaptureShapeMismatchV4;
            }
            if (metrics) |value| value.input_validation_ns = phase_timer.lap();

            var role_aware_io = try role_io.OwnedWitnessV4.initLive(
                allocator,
                &capture.public_data.data,
                &capture.role_aware_public.value,
                &capture.relations.base,
            );
            errdefer role_aware_io.deinit();
            try role_aware_io.public_sum_row.validateAgainstVerified(
                &capture.public_sums,
            );
            var schedule = try field_public.OwnedPoseidonScheduleV4.init(
                Engine,
                allocator,
                input,
                &role_aware_io,
            );
            errdefer schedule.deinit();
            const provider_geometry = try schedule.liveProviderGeometry();
            const completion_program_claim =
                try public_semantics.CompletionProgramClaimV4.init(
                    Engine,
                    input,
                );
            var completion_program_circuit =
                try public_semantics.CompletionProgramCircuitV4.init(allocator);
            errdefer completion_program_circuit.deinit();
            var completion_program_prepared =
                try completion_program_circuit.prepare(
                    allocator,
                    &completion_program_claim,
                );
            errdefer completion_program_prepared.deinit();
            if (metrics) |value| value.public_witness_ns = phase_timer.lap();
            var transcript_replay = try transcript_mod.replay(
                Engine,
                allocator,
                input,
            );
            errdefer transcript_replay.deinit();
            if (metrics) |value| value.transcript_ns = phase_timer.lap();
            const base_sampled = try base_geometry.expectedSampledValueCount(
                &capture.statement.core,
                &capture.manifest,
            );
            var profile = try base_profile_mod.deriveAuthority(
                allocator,
                &capture.statement.core,
                &capture.manifest,
                &capture.authenticated,
                base_sampled,
            );
            errdefer profile.deinit();
            if (metrics) |value| value.base_profile_ns = phase_timer.lap();
            var retained_schedule: composition_graph.CompiledSchedule = undefined;
            var program = try full_program.compileRetainingSchedule(allocator, .{
                .core_statement = &capture.statement.core,
                .extension_statement = &capture.extension,
                .lookup_manifest = &capture.manifest,
                .authenticated_lookup = &capture.authenticated,
                .base_profile = &profile,
                .bridge = .{
                    .geometry = capture.profile.bridge_geometry,
                    .entry_root = capture.profile.continuation_roots.entry,
                    .exit_root = capture.profile.continuation_roots.exit,
                },
            }, &retained_schedule);
            errdefer program.deinit();
            var retained_schedule_owned = true;
            errdefer if (retained_schedule_owned) retained_schedule.deinit();
            const program_custody = try ProgramConstructionCustodyV4.mint(
                &program,
            );
            if (metrics) |value| try materializer_support.recordProgramResources(
                value,
                &program,
                &retained_schedule,
            );
            if (metrics) |value| value.program_compile_ns = phase_timer.lap();
            // `prepareCompositionProgram` takes the retained schedule on every
            // success/error path, so this frame must never free it afterward.
            retained_schedule_owned = false;
            var composition_prepared = try prepareCompositionProgram(
                allocator,
                &program,
                program_custody,
                &retained_schedule,
                &profile,
                capture,
                execution.worker_count,
                metrics,
            );
            errdefer composition_prepared.deinit();
            if (metrics) |value| value.composition_prepare_ns = phase_timer.lap();
            const bridge_projection = try BridgeProjectionV4.init(
                &capture.profile,
            );
            const full_sampled = program.input_profile.sampled_value_count;
            const full_claims = program.input_profile.claimed_sum_count;
            const captured_sampled = std.math.cast(
                u32,
                capture.proof.sampled_values.len,
            ) orelse return error.EthereumIncrementalProofCaptureShapeMismatchV4;
            const expected_ethereum_sampled = try sub(
                try sub(full_sampled, base_sampled),
                bridge_projection.trace_sampled_value_count,
            );
            const expected_ethereum_claims = try sub(
                try sub(
                    full_claims,
                    profile.input_profile.claimed_sum_count,
                ),
                bridge_projection.detailed_claim_count,
            );
            if (captured_sampled != full_sampled or
                program.input_profile.transcript_claimed_sum_count !=
                    FULL_TRANSCRIPT_CLAIM_COUNT or
                expected_ethereum_sampled == 0 or expected_ethereum_claims == 0)
            {
                return error.EthereumIncrementalProofCaptureShapeMismatchV4;
            }

            var fri_config = captured_fri.ProfileConfig.fromPcs(
                try capture.profile.pcsConfig(),
            );
            fri_config.claimed_sum_count = full_claims;
            var fri = try captured_fri.Owned.init(
                allocator,
                fri_config,
                &capture.proof,
            );
            errdefer fri.deinit();
            if (metrics) |value| value.fri_capture_ns = phase_timer.lap();

            var result = Self{
                .allocator = allocator,
                .input = input.*,
                .role_aware_io = role_aware_io,
                .schedule = schedule,
                .provider_geometry = provider_geometry,
                .completion_program_claim = completion_program_claim,
                .completion_program_circuit = completion_program_circuit,
                .completion_program_prepared = completion_program_prepared,
                .transcript = transcript_replay,
                .base_profile = profile,
                .composition_program = program,
                .composition_program_custody = program_custody,
                .composition_prepared = composition_prepared,
                .captured_fri = fri,
                .bridge = bridge_projection,
                .base_sampled_value_count = base_sampled,
                .ethereum_sampled_value_count = expected_ethereum_sampled,
                .full_sampled_value_count = full_sampled,
                .full_detailed_claim_count = full_claims,
                .identity_sha256 = undefined,
            };
            result.identity_sha256 = materializerIdentity(Engine, &result);
            try result.validate();
            if (metrics) |value| value.final_seal_ns = phase_timer.lap();
            transcript_replay = undefined;
            input.* = undefined;
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.schedule.deinit();
            self.role_aware_io.deinit();
            self.completion_program_prepared.deinit();
            self.completion_program_circuit.deinit();
            self.captured_fri.deinit();
            self.composition_prepared.deinit();
            self.composition_program.deinit();
            self.base_profile.deinit();
            self.transcript.deinit();
            self.input.deinit();
            self.* = undefined;
        }

        /// O(1) process-local custody validation. The only large arrays are
        /// checked by exact allocation/pointer identity minted during fresh
        /// construction. Use `auditDeep` at an independent trust boundary.
        pub fn validate(self: *const Self) !void {
            try self.input.validate();
            try self.composition_program_custody.validateBorrowed(
                &self.composition_program,
            );
            const capture = &self.input.stage101;
            const expected_provider_geometry =
                try self.schedule.liveProviderGeometry();
            const captured_sampled = std.math.cast(
                u32,
                capture.proof.sampled_values.len,
            ) orelse return error.EthereumIncrementalMaterializerMismatchV4;
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                !self.composition_prepared.circuit
                    .borrowsFreshProgramStorage() or
                self.composition_prepared.circuit.nodes.ptr !=
                    self.composition_program.nodes.ptr or
                self.composition_prepared.circuit.nodes.len !=
                    self.composition_program.nodes.len or
                self.composition_prepared.circuit.outputs.ptr !=
                    self.composition_program.outputs.ptr or
                self.composition_prepared.circuit.outputs.len !=
                    self.composition_program.outputs.len or
                self.composition_prepared.circuit.bindings.ptr !=
                    self.composition_program.bindings.ptr or
                self.composition_prepared.circuit.bindings.len !=
                    self.composition_program.bindings.len or
                captured_sampled != self.full_sampled_value_count or
                self.full_sampled_value_count !=
                    self.composition_program.input_profile.sampled_value_count or
                self.full_detailed_claim_count !=
                    self.composition_program.input_profile.claimed_sum_count or
                !std.meta.eql(self.provider_geometry, expected_provider_geometry) or
                !std.mem.eql(
                    u8,
                    &self.composition_prepared.circuit.air_profile_digest,
                    &self.composition_program.air_program_identity,
                ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.graph_digest,
                &self.composition_program.graph_sha256,
            ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.reference_digest,
                &self.composition_program.reference_sha256,
            ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.schedule_digest,
                &self.composition_program.schedule_sha256,
            ) or !std.mem.eql(
                u8,
                &self.identity_sha256,
                &materializerIdentity(Engine, self),
            )) return error.EthereumIncrementalMaterializerMismatchV4;
        }

        /// Explicit O(graph) hostile-input audit. This recompiles the complete
        /// composition authority and is intentionally absent from hot-path
        /// intra-process validation.
        pub fn auditDeep(self: *const Self) !void {
            try self.validate();
            try self.input.validate();
            const capture = &self.input.stage101;
            try self.role_aware_io.validateAgainst(
                &capture.public_data.data,
                &capture.role_aware_public.value,
                &capture.relations.base,
            );
            try self.role_aware_io.public_sum_row.validateAgainstVerified(
                &capture.public_sums,
            );
            try self.schedule.validateAgainst(
                Engine,
                &self.input,
                &self.role_aware_io,
            );
            const expected_provider_geometry =
                try self.schedule.liveProviderGeometry();
            try self.completion_program_claim.validateAgainst(
                Engine,
                &self.input,
            );
            try self.completion_program_prepared.validateAgainst(
                &self.completion_program_circuit,
                &self.completion_program_claim,
            );
            try self.transcript.validateAgainst(Engine, &self.input);
            try self.base_profile.validateAuthority(
                self.allocator,
                &capture.statement.core,
                &capture.manifest,
                &capture.authenticated,
            );
            try self.composition_program.validateAgainst(.{
                .core_statement = &capture.statement.core,
                .extension_statement = &capture.extension,
                .lookup_manifest = &capture.manifest,
                .authenticated_lookup = &capture.authenticated,
                .base_profile = &self.base_profile,
                .bridge = .{
                    .geometry = capture.profile.bridge_geometry,
                    .entry_root = capture.profile.continuation_roots.entry,
                    .exit_root = capture.profile.continuation_roots.exit,
                },
            });
            try self.composition_prepared.validate();
            try self.bridge.validateAgainst(&capture.profile);
            try self.captured_fri.evaluation.validateAgainst(
                &self.captured_fri.circuit,
            );
            try self.captured_fri.pcs_evaluation.validateAgainst(
                &self.captured_fri.pcs_circuit,
            );
            const expected_base = try base_geometry.expectedSampledValueCount(
                &capture.statement.core,
                &capture.manifest,
            );
            const expected_full =
                self.composition_program.input_profile.sampled_value_count;
            const expected_claims =
                self.composition_program.input_profile.claimed_sum_count;
            const expected_ethereum = try sub(
                try sub(expected_full, expected_base),
                self.bridge.trace_sampled_value_count,
            );
            const expected_ethereum_claims = try sub(
                try sub(
                    expected_claims,
                    self.base_profile.input_profile.claimed_sum_count,
                ),
                self.bridge.detailed_claim_count,
            );
            var extension_geometry = try ethereum_geometry.GeometryV2.init(
                self.allocator,
                &self.base_profile,
                &capture.statement.core,
                &capture.extension,
            );
            defer extension_geometry.deinit();
            const captured_sampled = std.math.cast(
                u32,
                capture.proof.sampled_values.len,
            ) orelse return error.EthereumIncrementalMaterializerMismatchV4;
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.base_sampled_value_count != expected_base or
                self.ethereum_sampled_value_count != expected_ethereum or
                self.ethereum_sampled_value_count !=
                    extension_geometry.sampled_value_count or
                extension_geometry.detailed_claim_count !=
                    expected_ethereum_claims or
                self.full_sampled_value_count != expected_full or
                self.full_detailed_claim_count != expected_claims or
                captured_sampled != expected_full or
                !std.mem.eql(
                    u8,
                    &self.composition_prepared.circuit.air_profile_digest,
                    &self.composition_program.air_program_identity,
                ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.graph_digest,
                &self.composition_program.graph_sha256,
            ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.reference_digest,
                &self.composition_program.reference_sha256,
            ) or !std.mem.eql(
                u8,
                &self.composition_prepared.circuit.schedule_digest,
                &self.composition_program.schedule_sha256,
            ) or
                self.captured_fri.trace_roots.len != TREE_COUNT or
                self.captured_fri.sampled_value_count != expected_full or
                self.captured_fri.claimed_sum_count != expected_claims or
                !std.meta.eql(
                    self.provider_geometry,
                    expected_provider_geometry,
                ) or
                !std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &materializerIdentity(Engine, self),
                ))
            {
                return error.EthereumIncrementalMaterializerMismatchV4;
            }
        }

        pub fn requireTranscriptSource(self: *const Self) !void {
            try self.transcript.validateAgainst(Engine, &self.input);
        }

        pub fn requireBridgeCompositionGraph(self: *const Self) !void {
            try self.composition_program_custody.validateBorrowed(
                &self.composition_program,
            );
        }
    };
}

fn materializerIdentity(
    comptime Engine: type,
    value: *const PreparedCaptureV4(Engine),
) [32]u8 {
    return materializer_support.materializerIdentity(Engine, value);
}

fn prepareCompositionProgram(
    allocator: std.mem.Allocator,
    program: *const full_program.ProgramV4,
    program_custody: ProgramConstructionCustodyV4,
    retained_schedule: *composition_graph.CompiledSchedule,
    profile: *const base_profile_mod.ProfileV2,
    capture: anytype,
    worker_count: usize,
    metrics: ?*MaterializationMetricsV4,
) !vm_composition.Prepared {
    // Schedule ownership transfers into Prepared even when a later check
    // fails. No second O(graph) compile or retained graph copy is permitted.
    var schedule = retained_schedule.*;
    retained_schedule.* = undefined;
    var schedule_owned = true;
    defer if (schedule_owned) schedule.deinit();
    try program_custody.validateBorrowed(program);
    const input_values = try allocator.alloc(M31, program.bindings.len);
    defer allocator.free(input_values);
    const detailed_claims = try allocator.alloc(
        QM31,
        program.input_profile.claimed_sum_count,
    );
    defer allocator.free(detailed_claims);
    if (metrics) |value| {
        value.input_value_bytes = @intCast(std.mem.sliceAsBytes(input_values).len);
        value.detailed_claim_bytes = @intCast(
            std.mem.sliceAsBytes(detailed_claims).len,
        );
    }
    try fillDetailedClaims(profile, capture, detailed_claims);
    var transcript_claims: [FULL_TRANSCRIPT_CLAIM_COUNT]QM31 = undefined;
    try fillTranscriptClaims(capture, &transcript_claims);

    for (program.bindings, input_values) |binding, *destination| {
        destination.* = switch (binding.source) {
            .segment_selector => M31.one(),
            .sampled_value => |coordinate| try secureWord(
                capture.proof.sampled_values,
                coordinate.item_index,
                coordinate.word_index,
            ),
            .claimed_sum => |coordinate| try secureWord(
                detailed_claims,
                coordinate.item_index,
                coordinate.word_index,
            ),
            .transcript_claimed_sum => |coordinate| try secureWord(
                &transcript_claims,
                coordinate.item_index,
                coordinate.word_index,
            ),
            .relation_challenge => |coordinate| try relationWord(
                &capture.ethereum_air.relation_draws,
                coordinate.challenge,
                coordinate.word_index,
            ),
            .composition_randomness => |word| try scalarWord(
                capture.proof.composition_randomness,
                word,
            ),
            .oods_point => |word| try scalarWord(
                capture.proof.oods_seed,
                word,
            ),
        };
    }
    schedule_owned = false;
    return vm_composition.Prepared.initFromAuthenticatedLaneBorrowedParallelV4(
        allocator,
        program.lane(),
        program.air_program_identity,
        input_values,
        &schedule,
        worker_count,
    );
}

fn fillDetailedClaims(
    profile: *const base_profile_mod.ProfileV2,
    capture: anytype,
    destination: []QM31,
) !void {
    @memset(destination, QM31.zero());
    const core = &capture.statement.core;
    for (profile.entries) |entry| switch (entry.registry) {
        .opcode_semantic => {},
        .opcode_lookup => |key| {
            const component_index = try opcodeComponentIndex(
                core,
                key.family,
                entry.shard_ordinal,
            );
            const claims = try capture.base_claim.opcodeClaims(
                key.family,
                component_index,
            );
            try copyClaimRange(destination, entry.claimed_sum_offset, claims);
        },
        .infrastructure => |key| {
            const claims = try capture.base_claim.infraClaims(
                key.kind,
                entry.shard_ordinal,
            );
            try copyClaimRange(destination, entry.claimed_sum_offset, claims);
        },
    };
    var at: usize = profile.input_profile.claimed_sum_count;
    const extension = &capture.extension_claim;
    try appendClaims(destination, &at, &extension.keccak_shard.batch_sums);
    try appendClaims(destination, &at, &.{extension.keccak_chi_table});
    try appendClaims(destination, &at, &.{extension.keccak_xor5_table});
    inline for (.{
        extension.product_base,
        extension.product_scalar,
        extension.linear_base,
        extension.linear_scalar,
        extension.point,
        extension.split,
        extension.scalar,
        extension.table,
        extension.recovery,
        extension.byte,
        extension.recovery_caller,
    }) |claim| try appendClaims(destination, &at, &claim.batch_sums);
    try appendClaims(destination, &at, &.{capture.bridge_claim});
    if (at != destination.len)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
}

fn fillTranscriptClaims(capture: anytype, destination: *[43]QM31) !void {
    const canonical = try capture.base_claim.canonical(&capture.statement.core);
    @memcpy(destination[0..BASE_TRANSCRIPT_CLAIM_COUNT], &canonical.claimed_sums);
    const extension = &capture.extension_claim;
    destination[28] = extension.keccak_shard.component_sum;
    destination[29] = extension.keccak_chi_table;
    destination[30] = extension.keccak_xor5_table;
    inline for (.{
        extension.product_base.component_sum,
        extension.product_scalar.component_sum,
        extension.linear_base.component_sum,
        extension.linear_scalar.component_sum,
        extension.point.component_sum,
        extension.split.component_sum,
        extension.scalar.component_sum,
        extension.table.component_sum,
        extension.recovery.component_sum,
        extension.byte.component_sum,
        extension.recovery_caller.component_sum,
    }, 31..) |claim, index| destination[index] = claim;
    destination[42] = capture.bridge_claim;
}

fn opcodeComponentIndex(
    core: anytype,
    family: anytype,
    shard_ordinal: u32,
) !usize {
    var seen: u32 = 0;
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        if (descriptor.family != family) continue;
        if (seen == shard_ordinal) return index;
        seen = std.math.add(u32, seen, 1) catch return error.ArithmeticOverflow;
    }
    return error.EthereumIncrementalProofCaptureShapeMismatchV4;
}

fn copyClaimRange(
    destination: []QM31,
    offset: u32,
    claims: []const QM31,
) !void {
    const start: usize = offset;
    const end = std.math.add(usize, start, claims.len) catch
        return error.ArithmeticOverflow;
    if (end > destination.len)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    @memcpy(destination[start..end], claims);
}

fn appendClaims(
    destination: []QM31,
    at: *usize,
    claims: []const QM31,
) !void {
    const end = std.math.add(usize, at.*, claims.len) catch
        return error.ArithmeticOverflow;
    if (end > destination.len)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    @memcpy(destination[at.*..end], claims);
    at.* = end;
}

fn secureWord(values: []const QM31, item: u32, word: u32) !M31 {
    if (item >= values.len or word >= 4)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    return values[item].toM31Array()[word];
}

fn relationWord(
    draws: []const QM31,
    challenge: u32,
    word: u32,
) !M31 {
    if (word >= 8)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    const index = std.math.add(
        usize,
        std.math.mul(usize, challenge, 2) catch
            return error.ArithmeticOverflow,
        word / 4,
    ) catch return error.ArithmeticOverflow;
    if (index >= draws.len)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    return draws[index].toM31Array()[word % 4];
}

fn scalarWord(value: QM31, word: u32) !M31 {
    if (word >= 4)
        return error.EthereumIncrementalProofCaptureShapeMismatchV4;
    return value.toM31Array()[word];
}

fn add(left: u32, right: u32) Error!u32 {
    return std.math.add(u32, left, right) catch error.ArithmeticOverflow;
}

fn sub(left: u32, right: u32) Error!u32 {
    return std.math.sub(u32, left, right) catch error.ArithmeticOverflow;
}

fn requireEngine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != frontend.recursion.poseidon2_channel.Digest or
        Engine.Channel != frontend.recursion.poseidon2_channel.Channel)
    {
        @compileError("stage-102 V4 materializer requires Poseidon q193");
    }
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or TREE_COUNT != 4 or
        BASE_TRANSCRIPT_CLAIM_COUNT != 28 or
        ETHEREUM_TRANSCRIPT_CLAIM_COUNT != 14 or
        FULL_TRANSCRIPT_CLAIM_COUNT != 43 or
        BRIDGE_TRACE_SAMPLED_VALUE_COUNT != 17 or
        bridge.N_CONSTRAINTS != 6 or
        field_public.MINIMUM_PROVIDER_ACTIVE_ROW_COUNT != 129 or
        field_public.MINIMUM_PROVIDER_LOG_SIZE != 8 or
        field_public.CAMPAIGN_PROVIDER_GEOMETRY_FROZEN or
        PRODUCTION_ACTIVATION or UNIVERSAL_COHORT_AVAILABLE or
        !V4_TRANSCRIPT_SOURCE_AVAILABLE or
        !BRIDGE_COMPOSITION_GRAPH_AVAILABLE or WRAPPER_PROOF_AVAILABLE or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental materializer V4 drifted");
    }
}
