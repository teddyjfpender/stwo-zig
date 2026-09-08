//! Fixed schema-4 arithmetic authority for the role-0 V4 public sums.
//!
//! One value-independent graph is derived from the campaign's checked tuple
//! capacity. Per-leaf evaluations consume the exact 412-word SpanStatement,
//! fixed register-clock limbs from the authenticated V2 wire, the complete
//! committed role-aware tuple stream, and the verifier-drawn native relation
//! challenges. Sparse-RW and continuation-tree terms are absent by design;
//! role-aware I/O and the actual Ethereum-profile completion fetch replace
//! them exactly once.

const std = @import("std");
const builtin = @import("builtin");

// Counts independent evaluation replay, not initial witness construction.
// Nodes/bindings are the inventory submitted to an attempted replay.
var evaluation_audit_attempts = std.atomic.Value(u64).init(0);
var evaluation_audit_completions = std.atomic.Value(u64).init(0);
var evaluation_audit_nodes = std.atomic.Value(u64).init(0);
var evaluation_audit_bindings = std.atomic.Value(u64).init(0);
pub const testing = if (builtin.is_test) struct {
    pub fn snapshot() struct { attempts: u64, completions: u64, nodes: u64, bindings: u64 } {
        return .{
            .attempts = evaluation_audit_attempts.load(.monotonic),
            .completions = evaluation_audit_completions.load(.monotonic),
            .nodes = evaluation_audit_nodes.load(.monotonic),
            .bindings = evaluation_audit_bindings.load(.monotonic),
        };
    }
} else struct {};
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const compact = @import("recursive_common_ethereum_initial_public_sums_v1.zig");
const packets = @import("recursive_common_ethereum_initial_input_packet_v1.zig");
const InitialInputAdmission = @import("recursive_common_ethereum_initial_input_admission_v1.zig").InitialInputAdmissionV1;
const support =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const arithmetic = frontend.recursion.arithmetic_circuit;
const graph_mod = frontend.recursion.air.composition_circuit;
const lowering = frontend.recursion.air.verifier_arithmetic_lowering;
const native_sum = frontend.recursion.segment_public_native_sum_authority_v2;
const segment_v2 = frontend.recursion.segment_statement_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 8;
pub const CIRCUIT_ID: u32 = native_sum.CIRCUIT_ID;
pub const PRODUCTION_LEAF_COUNT = campaign_mod.PRODUCTION_LEAF_COUNT;
pub const FIXED_VALUE_INDEPENDENT_PROGRAM = true;
pub const SPARSE_RW_TERMS_INCLUDED = false;
pub const CONTINUATION_COMPENSATION_INCLUDED = false;
pub const ROLE_AWARE_IO_TERMS_INCLUDED = true;
pub const ACTUAL_COMPLETION_PROGRAM_TERM_INCLUDED = true;
pub const PRODUCTION_ACTIVATION = false;

const PROGRAM_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-sums-program/v4-schema8\x00";
const EVALUATION_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-sums-evaluation/v4-schema8\x00";

pub const InputSourceV4 = support.InputSourceV4;
pub const ClockAuxSourceV4 = support.ClockAuxSourceV4;
pub const GlobalAuxSourceV1 = support.global_binding.AuxSource;
pub const RoleSourceV4 = support.role_binding.Source;
pub const ProgramAdmissionV1 = support.program_admission.ProgramAdmissionV1;
pub const NONFINAL_PROGRAM_PROFILE_VERSION: u16 = 2;
pub const AdmissionKindV1 = enum(u16) { diagnostic = 0, nonfinal_declared_program_v1 = 1, nonfinal_global_program_v1 = 2, terminal_global_halt_v1 = 3, initial_global_program_v1 = 4 };
pub const CANONICAL_CLAIM_COUNT = support.CANONICAL_CLAIM_COUNT;
pub const Boundary = support.Boundary;
pub const Selector = support.Selector;
pub const Domain = support.Domain;
pub const RegisterClockCoordinateV4 = support.RegisterClockCoordinateV4;
pub const RegisterByteCoordinateV4 = support.RegisterByteCoordinateV4;
pub const TupleSelectorCoordinateV4 = support.TupleSelectorCoordinateV4;

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalPublicSumEvaluationMismatchV4,
    EthereumIncrementalPublicSumProgramMismatchV4,
    InvalidFieldElement,
};

pub fn FixedProgramV4ForCount(comptime campaign_leaf_count: usize) type {
    const Campaign = campaign_mod.CampaignProviderGeometryAuthorityV4ForCount(
        campaign_leaf_count,
    );
    return FixedProgramV4ForAuthority(Campaign);
}

pub const OwnedFixedProgramV4 = FixedProgramV4ForAuthority(
    campaign_mod.OwnedCampaignProviderGeometryV4,
);

fn FixedProgramV4ForAuthority(comptime Campaign: type) type {
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        tuple_capacity: u32,
        campaign_geometry_identity_sha256: [32]u8,
        admission_kind: AdmissionKindV1,
        circuit_profile: support.CircuitProfileV1 = .legacy_v4,
        native_continuation_roots: bool = false,
        initial_claim_shape: ?frontend.recursion.vm_public_claim.Shape = null,
        declared_program_identity_sha256: ?[32]u8,
        completion_opening_version: u16 = 0,
        completion_opening_word_count: u16 = 0,
        circuit: arithmetic.Circuit,
        bindings: []InputSourceV4,
        graph_nodes: []graph_mod.Node,
        graph_outputs: []u32,
        graph: graph_mod.CircuitGraph,
        program_identity_sha256: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            campaign: *const Campaign,
        ) !Self {
            return initInternal(allocator, campaign, null, false, .legacy_v4, .nonfinal_program_v1, false, null);
        }

        /// Admits one whole-program, explicitly nonfinal wrapper profile.
        /// The graph owns all recorded table constants; it retains no pointer
        /// to the external program owner after construction.
        pub fn initWithProgram(allocator: std.mem.Allocator, campaign: *const Campaign, admission: *const ProgramAdmissionV1) !Self {
            return initInternal(allocator, campaign, admission, false, .legacy_v4, .nonfinal_program_v1, false, null);
        }

        pub fn initWithGlobalProgram(allocator: std.mem.Allocator, campaign: *const Campaign, admission: *const ProgramAdmissionV1) !Self {
            return initInternal(allocator, campaign, admission, true, .legacy_v4, .nonfinal_program_v1, false, null);
        }

        pub fn initWithCircuitProfile(allocator: std.mem.Allocator, campaign: *const Campaign, admission: ?*const ProgramAdmissionV1, global_admitted: bool, circuit_profile: support.CircuitProfileV1) !Self {
            return initInternal(allocator, campaign, admission, global_admitted, circuit_profile, .nonfinal_program_v1, false, null);
        }

        pub fn initWithCompletionPolicy(allocator: std.mem.Allocator, campaign: *const Campaign, admission: ?*const ProgramAdmissionV1, global_admitted: bool, circuit_profile: support.CircuitProfileV1, policy: support.CompletionPolicyV1) !Self {
            return initInternal(allocator, campaign, admission, global_admitted, circuit_profile, policy, false, null);
        }

        pub fn completionPolicy(self: *const Self) support.CompletionPolicyV1 {
            return if (self.admission_kind == .terminal_global_halt_v1) .terminal_halt_v1 else .nonfinal_program_v1;
        }

        pub fn initWithNativeRoots(allocator: std.mem.Allocator, campaign: *const Campaign, admission: ?*const ProgramAdmissionV1, global_admitted: bool, circuit_profile: support.CircuitProfileV1, policy: support.CompletionPolicyV1) !Self {
            return initInternal(allocator, campaign, admission, global_admitted, circuit_profile, policy, true, null);
        }

        pub fn initForInitialInputs(allocator: std.mem.Allocator, campaign: *const Campaign, admission: *const ProgramAdmissionV1, initial: *const InitialInputAdmission) !Self {
            return initInternal(allocator, campaign, admission, true, .fixed_program_narrow_v1, .nonfinal_program_v1, true, initial.claimShape());
        }

        pub fn initialPacketFirstInput(self: *const Self) !u32 {
            if (self.initial_claim_shape == null) return error.InvalidEthereumInitialInputAdmission;
            for (self.bindings, 0..) |source, index| if (source == .initial_packet_limb and source.initial_packet_limb == 0) return @intCast(index);
            return error.InvalidEthereumInitialInputAdmission;
        }

        fn initInternal(allocator: std.mem.Allocator, campaign: *const Campaign, admission: ?*const ProgramAdmissionV1, global_admitted: bool, circuit_profile: support.CircuitProfileV1, policy: support.CompletionPolicyV1, native_roots: bool, initial_shape: ?frontend.recursion.vm_public_claim.Shape) !Self {
            try campaign.validateStructure();
            const capacity =
                campaign.view().provider_geometry.role_io_tuple_capacity;
            if (global_admitted and admission == null) return error.EthereumGlobalAdmissionRequired;
            if (initial_shape) |shape| {
                if (!native_roots or !global_admitted or circuit_profile != .fixed_program_narrow_v1 or policy != .nonfinal_program_v1 or capacity != (try packets.Air.lane.Shape.init(shape.max_input_words)).role_capacity) return error.InvalidEthereumInitialInputAdmission;
            }
            var built = if (initial_shape) |shape| try buildInitial(allocator, shape, admission orelse return error.EthereumInitialProgramOpeningRequired) else if (native_roots) try support.buildWithNativeRoots(allocator, capacity, admission, global_admitted, circuit_profile, policy) else try support.buildWithCompletionPolicy(allocator, capacity, admission, global_admitted, circuit_profile, policy);
            var built_owned = true;
            defer if (built_owned) built.deinit(allocator);
            const graph_nodes = try allocator.alloc(
                graph_mod.Node,
                built.circuit.nodes().len,
            );
            errdefer allocator.free(graph_nodes);
            for (graph_nodes, built.circuit.nodes()) |*destination, source|
                destination.* = support.graphNode(source);
            const graph_outputs = try allocator.dupe(
                u32,
                built.circuit.outputs(),
            );
            errdefer allocator.free(graph_outputs);
            const graph_identity = graph_mod.computeGraphDigest(
                graph_nodes,
                graph_outputs,
            );
            const graph = try graph_mod.CircuitGraph.authenticate(
                graph_nodes,
                graph_outputs,
                graph_identity,
            );
            var result = Self{
                .allocator = allocator,
                .tuple_capacity = capacity,
                .campaign_geometry_identity_sha256 = campaign.view().geometry_identity_sha256,
                .circuit_profile = circuit_profile,
                .native_continuation_roots = native_roots,
                .initial_claim_shape = initial_shape,
                .admission_kind = if (initial_shape != null) .initial_global_program_v1 else if (policy == .terminal_halt_v1) .terminal_global_halt_v1 else if (global_admitted) .nonfinal_global_program_v1 else if (admission != null) .nonfinal_declared_program_v1 else .diagnostic,
                .declared_program_identity_sha256 = if (admission) |program| program.identitySha256() else null,
                .completion_opening_version = if (policy == .terminal_halt_v1) 0 else if (admission) |program| program.openingVersion() else 0,
                .completion_opening_word_count = if (policy == .terminal_halt_v1) 0 else if (admission) |program| @intCast(program.openingInputWordCount()) else 0,
                .circuit = built.circuit,
                .bindings = built.bindings,
                .graph_nodes = graph_nodes,
                .graph_outputs = graph_outputs,
                .graph = graph,
                .program_identity_sha256 = undefined,
            };
            result.program_identity_sha256 = programIdentity(&result);
            try result.validateAgainstCampaign(campaign);
            built_owned = false;
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.graph_outputs);
            self.allocator.free(self.graph_nodes);
            self.allocator.free(self.bindings);
            self.circuit.deinit();
            self.* = undefined;
        }

        pub fn validateAgainstCampaign(
            self: *const Self,
            campaign: *const Campaign,
        ) !void {
            try campaign.validateStructure();
            try self.circuit.validate();
            try self.graph.validate();
            const expected_graph_identity = graph_mod.computeGraphDigest(
                self.graph_nodes,
                self.graph_outputs,
            );
            const expected_program_identity = programIdentity(self);
            const base_input_count = if (self.initial_claim_shape != null) 0 else if ((self.admission_kind == .nonfinal_global_program_v1 or self.admission_kind == .terminal_global_halt_v1)) try support.inputCountWithGlobalProgram(self.tuple_capacity) else if (self.declared_program_identity_sha256 != null) try support.inputCountWithProgram(self.tuple_capacity) else try support.inputCount(self.tuple_capacity);
            const expected_input_count = if (self.initial_claim_shape != null) try compact.inputCount(self.completion_opening_word_count) else try std.math.add(usize, try std.math.add(usize, base_input_count, self.completion_opening_word_count), if (self.native_continuation_roots) 2 else 0);
            if ((self.initial_claim_shape != null) != (self.admission_kind == .initial_global_program_v1)) return error.EthereumIncrementalPublicSumProgramMismatchV4;
            if (self.initial_claim_shape) |shape| {
                if (!self.native_continuation_roots or self.circuit_profile != .fixed_program_narrow_v1 or self.completion_opening_word_count == 0 or shape.max_output_words != compact.EXPECTED_OUTPUT_CAPACITY or self.tuple_capacity != (try packets.Air.lane.Shape.init(shape.max_input_words)).role_capacity) return error.EthereumIncrementalPublicSumProgramMismatchV4;
                const first = try self.initialPacketFirstInput();
                for (0..packets.INPUT_COUNT) |index| {
                    if (first + index >= self.bindings.len or !std.meta.eql(self.bindings[first + index], InputSourceV4{ .initial_packet_limb = @intCast(index) })) return error.EthereumIncrementalPublicSumProgramMismatchV4;
                }
            }
            if (self.completion_opening_version > support.program_admission.COMPLETION_OPENING_VERSION or (self.completion_opening_version == 0 and self.completion_opening_word_count != 0) or self.completion_opening_word_count > support.program_admission.MAX_COMPLETION_OPENING_WORD_COUNT or self.completion_opening_word_count % 9 != 0)
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            if ((self.admission_kind != .diagnostic) != (self.declared_program_identity_sha256 != null))
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.tuple_capacity !=
                    campaign.view().provider_geometry.role_io_tuple_capacity or
                self.bindings.len != expected_input_count or
                self.circuit.inputNodes().len != self.bindings.len or
                self.graph_nodes.len != self.circuit.nodes().len or
                self.graph_outputs.len != self.circuit.outputs().len or
                self.graph.nodes.ptr != self.graph_nodes.ptr or
                self.graph.outputs.ptr != self.graph_outputs.ptr or
                !std.mem.eql(
                    u8,
                    &self.campaign_geometry_identity_sha256,
                    &campaign.view().geometry_identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.graph.identity_digest,
                    &expected_graph_identity,
                ) or
                !std.mem.eql(
                    u8,
                    &self.program_identity_sha256,
                    &expected_program_identity,
                ))
            {
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            }
            for (
                self.graph_nodes,
                self.circuit.nodes(),
            ) |graph_node, circuit_node| if (!std.meta.eql(
                graph_node,
                support.graphNode(circuit_node),
            )) return error.EthereumIncrementalPublicSumProgramMismatchV4;
            if (!std.mem.eql(u32, self.graph_outputs, self.circuit.outputs()))
                return error.EthereumIncrementalPublicSumProgramMismatchV4;
            for (self.circuit.inputNodes(), 0..) |node, index| {
                const expected = std.math.cast(u32, index) orelse
                    return error.EthereumIncrementalPublicSumProgramMismatchV4;
                if (node != expected)
                    return error.EthereumIncrementalPublicSumProgramMismatchV4;
            }
        }

        pub fn loweringLane(self: *const Self) lowering.Lane {
            return .{
                .circuit_id = CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = self.program_identity_sha256,
                .graph = self.graph,
            };
        }

        pub fn requireGlobalProgramAdmission(self: *const Self) !void {
            if ((self.admission_kind != .nonfinal_global_program_v1 and self.admission_kind != .terminal_global_halt_v1 and self.admission_kind != .initial_global_program_v1) or self.declared_program_identity_sha256 == null)
                return error.EthereumGlobalAdmissionRequired;
        }

        pub fn requireNonfinalProgramAdmission(self: *const Self) !void {
            if (self.admission_kind == .diagnostic or self.admission_kind == .terminal_global_halt_v1 or self.declared_program_identity_sha256 == null)
                return error.EthereumNonfinalProgramAdmissionRequired;
        }
    };
}

fn buildInitial(allocator: std.mem.Allocator, shape: frontend.recursion.vm_public_claim.Shape, admission: *const ProgramAdmissionV1) !support.BuiltProgramV4 {
    var built = try compact.build(allocator, shape, admission);
    errdefer built.deinit(allocator);
    const bindings = try allocator.alloc(InputSourceV4, built.bindings.len);
    for (bindings, built.bindings) |*out, source| out.* = switch (source) {
        .existing => |value| value,
        .packet_limb => |index| .{ .initial_packet_limb = index },
    };
    allocator.free(built.bindings);
    return .{ .circuit = built.circuit, .bindings = bindings };
}

pub const FixedProgramV4 = FixedProgramV4ForCount(PRODUCTION_LEAF_COUNT);

pub fn OwnedEvaluationV4ForCount(
    comptime Engine: type,
    comptime campaign_leaf_count: usize,
) type {
    const Program = FixedProgramV4ForCount(campaign_leaf_count);
    const Materialized = campaign_materializer.PreparedCampaignCaptureV4ForCount(
        Engine,
        campaign_leaf_count,
    );
    return OwnedEvaluationV4ForTypes(Engine, Program, Materialized);
}

pub fn OwnedRuntimeEvaluationV4(comptime Engine: type) type {
    return OwnedEvaluationV4ForTypes(
        Engine,
        OwnedFixedProgramV4,
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine),
    );
}

fn OwnedEvaluationV4ForTypes(
    comptime Engine: type,
    comptime Program: type,
    comptime Materialized: type,
) type {
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        program_identity_sha256: [32]u8,
        materialized_identity_sha256: [32]u8,
        campaign_authority_identity_sha256: [32]u8,
        evaluation: arithmetic.Evaluation,
        evaluation_identity_sha256: [32]u8,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            program: *const Program,
            materialized: *const Materialized,
        ) !Self {
            try materialized.validate();
            try program.validateAgainstCampaign(
                materialized.campaign_authority,
            );
            if (program.circuit_profile != materialized.base.input.stage101.profile.circuitProfile() or program.native_continuation_roots != materialized.base.composition.program().input_profile.vm_native_continuation_roots) return error.EthereumIncrementalPublicSumProgramMismatchV4;
            try validateProgramAdmission(program, materialized);
            const inputs = try allocator.alloc(QM31, program.bindings.len);
            defer allocator.free(inputs);
            try fillInputs(Engine, materialized, program.bindings, inputs);
            var evaluation = try program.circuit.evaluate(allocator, inputs);
            errdefer evaluation.deinit();
            if (!try program.circuit.outputsAreZero(evaluation.values))
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            var result = Self{
                .allocator = allocator,
                .program_identity_sha256 = program.program_identity_sha256,
                .materialized_identity_sha256 = materialized.identity_sha256,
                .campaign_authority_identity_sha256 = materialized.campaign_authority.view().authority_identity_sha256,
                .evaluation = evaluation,
                .evaluation_identity_sha256 = undefined,
            };
            result.evaluation_identity_sha256 = evaluationIdentity(&result);
            try result.validateAgainst(program, materialized);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.evaluation.deinit();
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const Self,
            program: *const Program,
            materialized: *const Materialized,
        ) !void {
            try materialized.validate();
            try program.validateAgainstCampaign(
                materialized.campaign_authority,
            );
            if (program.circuit_profile != materialized.base.input.stage101.profile.circuitProfile() or program.native_continuation_roots != materialized.base.composition.program().input_profile.vm_native_continuation_roots) return error.EthereumIncrementalPublicSumProgramMismatchV4;
            try validateProgramAdmission(program, materialized);
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.evaluation.values.len != program.circuit.nodes().len or
                !std.mem.eql(
                    u8,
                    &self.program_identity_sha256,
                    &program.program_identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.materialized_identity_sha256,
                    &materialized.identity_sha256,
                ) or
                !std.mem.eql(
                    u8,
                    &self.campaign_authority_identity_sha256,
                    &materialized.campaign_authority.view().authority_identity_sha256,
                ) or
                !try program.circuit.outputsAreZero(self.evaluation.values) or
                !std.mem.eql(
                    u8,
                    &self.evaluation_identity_sha256,
                    &evaluationIdentity(self),
                ))
            {
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            }
            const inputs = try self.allocator.alloc(
                QM31,
                program.bindings.len,
            );
            defer self.allocator.free(inputs);
            try fillInputs(Engine, materialized, program.bindings, inputs);
            if (builtin.is_test) {
                _ = evaluation_audit_attempts.fetchAdd(1, .monotonic);
                _ = evaluation_audit_nodes.fetchAdd(program.circuit.nodes().len, .monotonic);
                _ = evaluation_audit_bindings.fetchAdd(inputs.len, .monotonic);
            }
            var expected = try program.circuit.evaluate(
                self.allocator,
                inputs,
            );
            defer expected.deinit();
            if (!std.mem.eql(
                u8,
                std.mem.sliceAsBytes(self.evaluation.values),
                std.mem.sliceAsBytes(expected.values),
            )) return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            if (builtin.is_test) _ = evaluation_audit_completions.fetchAdd(1, .monotonic);
        }

        pub fn loweringEvaluation(
            self: *const Self,
            program: *const Program,
        ) !lowering.Evaluation {
            if (!std.mem.eql(
                u8,
                &self.program_identity_sha256,
                &program.program_identity_sha256,
            ) or self.evaluation.values.len != program.graph.nodes.len)
                return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
            return .{
                .circuit_identity = self.program_identity_sha256,
                .values = self.evaluation.values,
            };
        }
    };
}

pub fn OwnedEvaluationV4(comptime Engine: type) type {
    return OwnedEvaluationV4ForCount(Engine, PRODUCTION_LEAF_COUNT);
}

fn fillInputs(
    comptime Engine: type,
    materialized: anytype,
    bindings: []const InputSourceV4,
    destination: []QM31,
) !void {
    if (destination.len != bindings.len)
        return error.EthereumIncrementalPublicSumEvaluationMismatchV4;
    const capture = &materialized.base.input.stage101;
    const native_words = capture.public_data.data.words();
    const role = &capture.role_aware_public.value;
    const claim_codec = frontend.recursion.vm_public_claim;
    var encoded_claim = try claim_codec.encodeWithBoundCompletionV4(materialized.allocator, role, try materialized.claimShape(), role.completion orelse return error.EthereumIncrementalPublicSumEvaluationMismatchV4);
    defer encoded_claim.deinit();
    const base = try capture.authenticated.canonicalInteractionClaim(&capture.statement.core, &capture.manifest, capture.base_claim);
    var canonical_claims: [CANONICAL_CLAIM_COUNT]QM31 = undefined;
    @memcpy(canonical_claims[0..support.BASE_CANONICAL_CLAIM_COUNT], &base.claimed_sums);
    for (capture.extension_claim.componentClaims(), support.BASE_CANONICAL_CLAIM_COUNT..) |claim, index|
        canonical_claims[index] = claim.total;
    canonical_claims[CANONICAL_CLAIM_COUNT - 1] = capture.bridge_claim;
    var packet_words: ?[packets.INPUT_COUNT]M31 = null;
    if (materialized.initial_input_admission) |initial| {
        const shape = initial.claimShape();
        const words = materialized.role_aware_io.canonical_words;
        const first = role_io.HEADER_WORD_COUNT + role_io.TUPLE_WORD_COUNT * @as(usize, shape.max_input_words);
        if (first + 18 > words.len) return error.InvalidEthereumInitialInputAdmission;
        var program_words: [18]M31 = undefined;
        for (&program_words, words[first..][0..18]) |*out, word| out.* = M31.fromCanonical(word);
        const header = [4]M31{ encoded_claim.words[241], encoded_claim.words[242], encoded_claim.words[254], encoded_claim.words[255] };
        packet_words = packets.witnessWords(capture.relations.base.memory_access.z, capture.relations.base.memory_access.alpha, header, materialized.role_aware_io.claims.memory_access, program_words);
    }
    for (bindings, destination) |binding, *output| output.* = switch (binding) {
        .segment_selector => QM31.one(),
        .initial_packet_limb => |index| if (index < packets.INPUT_COUNT) QM31.fromBase((packet_words orelse return error.InvalidEthereumInitialInputAdmission)[index]) else return error.InvalidEthereumInitialInputAdmission,
        .native_continuation_root => |side| QM31.fromBase(M31.fromCanonical(if (side == 0) materialized.base.input.stage101.statement.core.public_data.initial_rw_root.? else materialized.base.input.stage101.statement.core.public_data.final_rw_root.?)),
        .statement_word => |index| QM31.fromBase(M31.fromCanonical(
            materialized.base.input.statement_words[index],
        )),
        .register_clock_limb => |coordinate| QM31.fromBase(native_words[
            registerClockIndex(coordinate)
        ]),
        .clock_aux => |source| try support.clockAuxValue(source, &materialized.base.input.statement_words, native_words),
        .completion_opening_word => |index| blk: {
            const admission = materialized.program_admission orelse return error.EthereumCompletionOpeningNotAdmitted;
            const completion = role.completion orelse return error.EthereumNonfinalWrapperRequired;
            break :blk QM31.fromBase(M31.fromCanonical(try admission.openingWord(completion.address, index)));
        },
        .global_statement_word => |index| blk: {
            try materialized.base.input.requireGlobalAdmission();
            break :blk QM31.fromBase(M31.fromCanonical(materialized.base.input.global_admission.?.global_words[index]));
        },
        .global_aux => |source| blk: {
            try materialized.base.input.requireGlobalAdmission();
            break :blk try support.global_binding.auxValue(source, &materialized.base.input.global_admission.?.global_words);
        },
        .register_byte => |coordinate| QM31.fromBase(M31.fromCanonical(
            registerByte(role, coordinate),
        )),
        .role_io_word => |index| QM31.fromBase(M31.fromCanonical(
            materialized.role_aware_io.canonical_words[index],
        )),
        .tuple_selector => |coordinate| QM31.fromBase(M31.fromCanonical(
            tupleSelector(&materialized.role_aware_io, coordinate),
        )),
        .canonical_claim_word => |coordinate| QM31.fromBase(
            canonical_claims[coordinate.item].toM31Array()[coordinate.limb],
        ),
        .role_source => |source| switch (source) {
            .completion_word => |limb| blk: {
                const completion = role.completion orelse return error.EthereumNonfinalWrapperRequired;
                const raw = if (limb < 2) completion.address else completion.value;
                break :blk QM31.fromBase(M31.fromCanonical(if (limb % 2 == 0) raw & 65535 else raw >> 16));
            },
            .completion_decoded_word => |limb| QM31.fromBase(M31.fromCanonical(materialized.schedule.source.base.completion.program_values[limb])),
            .completion_policy_word => |index| blk: {
                const completion = role.completion orelse return error.EthereumNonfinalWrapperRequired;
                const word: u32 = switch (index) {
                    0 => @intFromEnum(completion.kind),
                    1 => completion.clock & 65535,
                    2 => completion.clock >> 16,
                    3 => return error.InvalidEthereumRoleBinding,
                };
                break :blk QM31.fromBase(M31.fromCanonical(word));
            },
            .nonfinal_inverse => try support.role_binding.nonfinalInverse(&materialized.base.input.statement_words),
            .terminal_reserved => QM31.zero(),
            else => try support.role_binding.read(source, encoded_claim.words, materialized.role_aware_io.canonical_words),
        },
        .relation_challenge_word => |coordinate| blk: {
            const value = switch (coordinate.domain) {
                .registers_state => if (coordinate.alpha)
                    capture.relations.base.registers_state.alpha
                else
                    capture.relations.base.registers_state.z,
                .memory_access => if (coordinate.alpha)
                    capture.relations.base.memory_access.alpha
                else
                    capture.relations.base.memory_access.z,
                .program_access => if (coordinate.alpha)
                    capture.relations.base.program_access.alpha
                else
                    capture.relations.base.program_access.z,
                .merkle => if (coordinate.alpha)
                    capture.relations.base.merkle.alpha
                else
                    capture.relations.base.merkle.z,
            };
            break :blk QM31.fromBase(value.toM31Array()[coordinate.limb]);
        },
    };
    _ = Engine;
}

fn validateProgramAdmission(program: anytype, materialized: anytype) !void {
    const shape = if (materialized.initial_input_admission) |initial| @as(?frontend.recursion.vm_public_claim.Shape, initial.claimShape()) else null;
    if (!std.meta.eql(program.initial_claim_shape, shape)) return error.EthereumIncrementalPublicSumProgramMismatchV4;
    const expected: ?[32]u8 = if (materialized.program_admission) |admission| admission.identitySha256() else null;
    if (!std.meta.eql(program.declared_program_identity_sha256, expected)) return error.EthereumIncrementalPublicSumProgramMismatchV4;
    if (materialized.program_admission) |admission| {
        if (program.completion_opening_version != (if (program.completionPolicy() == .terminal_halt_v1) @as(u16, 0) else admission.openingVersion()) or program.completion_opening_word_count != (if (program.completionPolicy() == .terminal_halt_v1) @as(usize, 0) else admission.openingInputWordCount())) return error.EthereumIncrementalPublicSumProgramMismatchV4;
    }
}

fn registerClockIndex(
    coordinate: RegisterClockCoordinateV4,
) usize {
    const start = if (coordinate.boundary == .entry)
        segment_v2.fixed_layout.entry_register_clocks
    else
        segment_v2.fixed_layout.exit_register_clocks;
    return start + @as(usize, coordinate.register) * 2 + coordinate.limb;
}

fn registerByte(
    public: anytype,
    coordinate: RegisterByteCoordinateV4,
) u32 {
    const value = if (coordinate.boundary == .entry)
        public.initial_regs[coordinate.register]
    else
        public.final_regs[coordinate.register];
    const byte_index: u32 = coordinate.byte;
    const shift: u5 = @intCast(8 * byte_index);
    return @as(u8, @truncate(value >> shift));
}

fn tupleSelector(
    witness: *const role_io.OwnedWitnessV4,
    coordinate: TupleSelectorCoordinateV4,
) u32 {
    const tuple = witness.tuples[coordinate.slot];
    const actual: Selector = if (tuple.isZero())
        .padding
    else
        @enumFromInt(@intFromEnum(tuple.kind));
    return @intFromBool(actual == coordinate.selector);
}

fn programIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, CIRCUIT_ID);
    hashInt(&hash, u32, value.tuple_capacity);
    hashInt(&hash, u16, @intFromEnum(value.admission_kind));
    hashInt(&hash, u16, NONFINAL_PROGRAM_PROFILE_VERSION);
    if (value.circuit_profile != .legacy_v4) {
        hash.update("ethereum-circuit-profile/v1\x00");
        hashInt(&hash, u16, @intFromEnum(value.circuit_profile));
    }
    if (value.initial_claim_shape) |shape| {
        hash.update("compact-initial-inputs/v1\x00");
        hashInt(&hash, u16, compact.POLICY_VERSION);
        hashInt(&hash, u32, shape.max_input_words);
        hashInt(&hash, u32, shape.max_output_words);
        hash.update(&packets.Air.SEMANTIC_DIGEST);
        hash.update(&packets.Air.lane.SEMANTIC_DIGEST);
    }
    if (value.native_continuation_roots) {
        hash.update("native-continuation-roots/v1\x00");
        hashInt(&hash, u32, frontend.recursion.air.vm_statement_roots.NATIVE_CONTINUATION_SCOPE);
    }
    if (value.declared_program_identity_sha256) |identity| hash.update(&identity);
    if (value.completion_opening_version != 0) {
        hashInt(&hash, u16, value.completion_opening_version);
        hashInt(&hash, u16, value.completion_opening_word_count);
    }
    hash.update(&value.campaign_geometry_identity_sha256);
    hash.update(&value.graph.identity_digest);
    hashInt(&hash, u64, value.bindings.len);
    for (value.bindings) |binding| hashBinding(&hash, binding);
    for (value.circuit.useCounts()) |count| hashInt(&hash, u32, count);
    return hash.finalResult();
}

fn evaluationIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(EVALUATION_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.materialized_identity_sha256);
    hash.update(&value.campaign_authority_identity_sha256);
    hashInt(&hash, u64, value.evaluation.values.len);
    for (value.evaluation.values) |field| for (field.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashBinding(hash: anytype, value: InputSourceV4) void {
    hashInt(hash, u8, @intFromEnum(value));
    switch (value) {
        .segment_selector => {},
        .native_continuation_root => |side| hashInt(hash, u8, side),
        .initial_packet_limb => |index| hashInt(hash, u8, index),
        .statement_word, .global_statement_word, .completion_opening_word => |index| hashInt(hash, u16, index),
        .global_aux => |source| {
            hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
            switch (source) {
                .bit => |part| {
                    hashInt(hash, u8, @intFromEnum(part.integer));
                    hashInt(hash, u8, part.bit);
                },
                .carry => |part| {
                    hashInt(hash, u8, part.addition);
                    hashInt(hash, u8, part.limb);
                },
                .initial_limb_inverse => |limb| hashInt(hash, u8, limb),
            }
        },
        .register_clock_limb => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.boundary));
            hashInt(hash, u8, coordinate.register);
            hashInt(hash, u8, coordinate.limb);
        },
        .clock_aux => |source| {
            hashInt(hash, u8, @intFromEnum(source));
            switch (source) {
                .register_bit => |coordinate| {
                    hashInt(hash, u8, @intFromEnum(coordinate.boundary));
                    hashInt(hash, u8, coordinate.register);
                    hashInt(hash, u8, coordinate.bit);
                },
                .cycle_bit => |coordinate| {
                    hashInt(hash, u8, @intFromEnum(coordinate.kind));
                    hashInt(hash, u8, coordinate.bit);
                },
            }
        },
        .register_byte => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.boundary));
            hashInt(hash, u8, coordinate.register);
            hashInt(hash, u8, coordinate.byte);
        },
        .role_io_word => |index| hashInt(hash, u32, index),
        .tuple_selector => |coordinate| {
            hashInt(hash, u32, coordinate.slot);
            hashInt(hash, u8, @intFromEnum(coordinate.selector));
        },
        .canonical_claim_word => |coordinate| {
            hashInt(hash, u8, coordinate.item);
            hashInt(hash, u8, coordinate.limb);
        },
        .relation_challenge_word => |coordinate| {
            hashInt(hash, u8, @intFromEnum(coordinate.domain));
            hashInt(hash, u8, @intFromBool(coordinate.alpha));
            hashInt(hash, u8, coordinate.limb);
        },
        .role_source => |source| {
            hashInt(hash, u8, @intFromEnum(source));
            switch (source) {
                .claim_word => |index| hashInt(hash, u32, index),
                .claim_byte => |coordinate| {
                    hashInt(hash, u32, coordinate.word_index);
                    hashInt(hash, u8, coordinate.byte_index);
                },
                .limb_bit => |coordinate| {
                    hashInt(hash, u32, coordinate.slot);
                    hashInt(hash, u8, coordinate.limb);
                    hashInt(hash, u8, coordinate.bit);
                },
                .input_carry => |slot| hashInt(hash, u32, slot),
                .completion_word, .completion_decoded_word, .completion_policy_word => |limb| hashInt(hash, u8, limb),
                .nonfinal_inverse, .terminal_reserved => {},
            }
        },
    }
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 8 or
        PRODUCTION_LEAF_COUNT != 210 or
        !FIXED_VALUE_INDEPENDENT_PROGRAM or SPARSE_RW_TERMS_INCLUDED or
        CONTINUATION_COMPENSATION_INCLUDED or
        !ROLE_AWARE_IO_TERMS_INCLUDED or
        !ACTUAL_COMPLETION_PROGRAM_TERM_INCLUDED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public-sum V4 drifted");
    }
}
