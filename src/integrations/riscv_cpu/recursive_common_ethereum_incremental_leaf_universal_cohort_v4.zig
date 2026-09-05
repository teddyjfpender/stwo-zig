//! Fail-closed role-0 universal-cohort boundary for an Ethereum V4 leaf.
//!
//! The source view below is already complete: it borrows one live stage-101
//! cold-verifier capability, its exact native Poseidon transcript replay, the
//! base+fourteen-Ethereum+bridge composition graph, captured FRI witness, and
//! field-native NodePublic schedule. It is not yet a universal cohort. The 36
//! concrete row materializers, claim closure, and proof gate remain a separate
//! transaction and therefore have no success constructor in this module.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const materializer =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4.zig");
const complete_cohort =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const node_public_mod = @import("recursive_field_node_public_v2.zig");
const public_semantics =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const captured_fri = recursion.captured_fri;
const composition = recursion.air.composition_circuit;
const channel = recursion.poseidon2_channel;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const RELATION_DRAW_COUNT = materializer.FULL_TRANSCRIPT_CLAIM_COUNT + 7;
pub const QUERY_WORD_COUNT: usize = 193;

pub const SOURCE_AUTHORITY_AVAILABLE = true;
pub const COMPLETION_PROGRAM_GRAPH_AVAILABLE = true;
pub const ROLE_AWARE_IO_WITNESS_AVAILABLE = true;
pub const CAMPAIGN_PROVIDER_GEOMETRY_FROZEN = false;
pub const UNIVERSAL_ROW_MATERIALIZERS_AVAILABLE = true;
pub const UNIVERSAL_CLAIM_CLOSURE_AVAILABLE = true;
pub const UNIVERSAL_PROOF_GATE_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-source/v4\x00";

pub const CompleteGeneratedV4 = complete_cohort.GeneratedV4;
pub const CompleteCohortV4 = complete_cohort.CohortV4;

pub const Error = error{
    EthereumIncrementalUniversalCohortMismatchV4,
    EthereumIncrementalUniversalCohortUnavailableV4,
};

/// Exact borrowed input to the future 36-row cohort. Every slice remains
/// backed by `materialized`; identities are comparison aids, never admission.
pub fn SourceViewV4(comptime Engine: type) type {
    return struct {
        materialized: *const materializer.PreparedCaptureV4(Engine),
        role: registry_mod.CircuitRoleV4 = ROLE,
        node_public: *const node_public_mod.NodePublicV2,
        role_aware_io: *const role_io.OwnedWitnessV4,
        provider_geometry: *const manifest_mod.LiveProviderGeometryV4,
        native_statement_authority: *const channel.Digest,
        transcript_relation_draws: *const [RELATION_DRAW_COUNT]QM31,
        transcript_query_words: *const [QUERY_WORD_COUNT]M31,
        completion_program_claim: *const public_semantics.CompletionProgramClaimV4,
        completion_program_circuit: *const public_semantics.CompletionProgramCircuitV4,
        completion_program_prepared: *const public_semantics.PreparedCircuitV4,
        captured_fri: *const captured_fri.Owned,
        vm_lane: composition.VmLane,
        source_identity_sha256: [32]u8,

        const Self = @This();

        pub fn validateBorrowed(self: Self) !void {
            try self.materialized.validate();
            const capture = &self.materialized.input.stage101;
            const expected_lane = self.materialized.composition_program.lane();
            try expected_lane.graph.validate();
            if (self.role != ROLE or
                self.node_public != &self.materialized.schedule.node_public or
                self.role_aware_io != &self.materialized.role_aware_io or
                self.provider_geometry !=
                    &self.materialized.provider_geometry or
                self.native_statement_authority !=
                    &capture.statement.authority_id or
                self.transcript_relation_draws !=
                    &self.materialized.transcript.relation_draws or
                self.transcript_query_words !=
                    &self.materialized.transcript.query_words or
                self.completion_program_claim !=
                    &self.materialized.completion_program_claim or
                self.completion_program_circuit !=
                    &self.materialized.completion_program_circuit or
                self.completion_program_prepared !=
                    &self.materialized.completion_program_prepared or
                self.captured_fri != &self.materialized.captured_fri or
                !laneAliases(self.vm_lane, expected_lane) or
                !std.mem.eql(
                    u8,
                    &self.source_identity_sha256,
                    &sourceIdentity(Engine, self.materialized),
                ))
            {
                return error.EthereumIncrementalUniversalCohortMismatchV4;
            }
        }

        pub fn requireUniversalCohort(_: Self) Error!void {
            return error.EthereumIncrementalUniversalCohortUnavailableV4;
        }
    };
}

/// Constructs the only valid borrowed source view. No digest-only or
/// caller-authored log-size constructor exists.
pub fn sourceView(
    comptime Engine: type,
    value: *const materializer.PreparedCaptureV4(Engine),
) !SourceViewV4(Engine) {
    try value.validate();
    var result = SourceViewV4(Engine){
        .materialized = value,
        .node_public = &value.schedule.node_public,
        .role_aware_io = &value.role_aware_io,
        .provider_geometry = &value.provider_geometry,
        .native_statement_authority = &value.input.stage101.statement.authority_id,
        .transcript_relation_draws = &value.transcript.relation_draws,
        .transcript_query_words = &value.transcript.query_words,
        .completion_program_claim = &value.completion_program_claim,
        .completion_program_circuit = &value.completion_program_circuit,
        .completion_program_prepared = &value.completion_program_prepared,
        .captured_fri = &value.captured_fri,
        .vm_lane = value.composition_program.lane(),
        .source_identity_sha256 = sourceIdentity(Engine, value),
    };
    try result.validateBorrowed();
    return result;
}

fn sourceIdentity(
    comptime Engine: type,
    value: *const materializer.PreparedCaptureV4(Engine),
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(ROLE));
    hash.update(&value.identity_sha256);
    hash.update(&value.input.stage101.identity_sha256);
    hash.update(&value.transcript.identity_sha256);
    hash.update(&value.completion_program_claim.identity_sha256);
    for (value.input.stage101.statement.authority_id) |word|
        hashInt(&hash, u32, word);
    hash.update(&value.composition_program.graph_sha256);
    hash.update(&value.captured_fri.circuit.identity_digest);
    hash.update(&value.captured_fri.pcs_circuit.identity_digest);
    for (value.schedule.source.source_digest) |word|
        hashInt(&hash, u32, word);
    hashInt(
        &hash,
        u32,
        @as(u32, @intCast(value.transcript.execution.poseidon_calls.len)),
    );
    hashInt(
        &hash,
        u32,
        @as(u32, @intCast(value.transcript.execution.operations.len)),
    );
    hashInt(&hash, u32, value.transcript.query_log_size);
    return hash.finalResult();
}

fn laneAliases(left: composition.VmLane, right: composition.VmLane) bool {
    return left.circuit_id == right.circuit_id and
        std.meta.eql(left.profile, right.profile) and
        std.mem.eql(u8, &left.graph.identity_digest, &right.graph.identity_digest) and
        left.graph.nodes.ptr == right.graph.nodes.ptr and
        left.graph.nodes.len == right.graph.nodes.len and
        left.graph.outputs.ptr == right.graph.outputs.ptr and
        left.graph.outputs.len == right.graph.outputs.len and
        left.bindings.ptr == right.bindings.ptr and
        left.bindings.len == right.bindings.len;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or COMPONENT_COUNT != 36 or
        RELATION_DRAW_COUNT != 50 or QUERY_WORD_COUNT != 193 or
        !SOURCE_AUTHORITY_AVAILABLE or
        !COMPLETION_PROGRAM_GRAPH_AVAILABLE or
        !ROLE_AWARE_IO_WITNESS_AVAILABLE or
        CAMPAIGN_PROVIDER_GEOMETRY_FROZEN or
        !UNIVERSAL_ROW_MATERIALIZERS_AVAILABLE or
        !UNIVERSAL_CLAIM_CLOSURE_AVAILABLE or
        UNIVERSAL_PROOF_GATE_AVAILABLE or PRODUCTION_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental universal cohort V4 drifted");
    }
}
