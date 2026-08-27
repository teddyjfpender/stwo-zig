//! Owned CPU handoff from one successful native segment-V2 verification to
//! the exact transcript, authority, FRI, PCS, and VM-AIR inputs needed by the
//! recursive outer proof.
//!
//! This module is intentionally a preparation boundary, not a recursive proof
//! receipt.  It consumes `VerifiedSegmentV2CaptureForEngine`, snapshots every
//! proof-derived input, validates the exact ProgramV2 transcript against the
//! captured challenges, and appends both transcript and statement-authority
//! permutations into the canonical boundary prefix of one row-34 provider
//! schedule. Rows 18--33 still owe their verifier-core Merkle/Poseidon calls;
//! the prefix is never represented as a complete provider. Rows 0--9 and the
//! 47-domain closure remain unpublished until their typed AIR source and the
//! complete outer STARK are verified.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const recursive_fri_outer = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;
const recursion = frontend.recursion;
const shared_schedule_v2 = recursion.segment_shared_poseidon_schedule_v2;
const transcript_v2 = recursion.transcript_program_v2;
const authority_v2 = recursion.segment_leaf_outer_authority_v2;
const source_v2 = recursion.segment_leaf_authority_v2;
const air_v2 = recursion.segment_leaf_outer_air_v2;
const universal = recursion.air.universal_challenges;
const schedule = recursion.air.verifier_schedule;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const statement = frontend.air.statement;
const transcript_claims = frontend.air.transcript.claims;
const opcode_entries = frontend.air.lookups.opcode_entries;

/// Recursive ingestion is deliberately restricted to the Poseidon2-M31 suite;
/// Blake2s native captures have a different Merkle digest representation and
/// cannot populate the universal Poseidon verifier rows.
pub const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
pub const NativeCapture = frontend.prover_mod.VerifiedSegmentV2CaptureForEngine(Engine);
pub const Digest = recursion.poseidon2_channel.Digest;
pub const Sha256Digest = [32]u8;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CALL_LAYOUT_SCHEMA_VERSION = shared_schedule_v2.SCHEMA_VERSION;
pub const BUNDLE_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-leaf-outer/v1\x00";
pub const CALL_LAYOUT_ID_DOMAIN = shared_schedule_v2.CALL_LAYOUT_ID_DOMAIN;
pub const CALL_BUFFER_ID_DOMAIN = shared_schedule_v2.CALL_BUFFER_ID_DOMAIN;
pub const TRACE_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-authority-traces/v1\x00";

pub const CAPTURE_CUSTODY_REQUIRED = true;
pub const TRANSCRIPT_PROGRAM_V2_EXACT = true;
pub const SHARED_ROW34_PROVIDER_COUNT: usize = 1;
pub const ROW34_BOUNDARY_PREFIX_AVAILABLE = true;
pub const ROW34_COMPLETE_LAYOUT_SUPPORTED = true;
pub const ROW34_VERIFIER_CORE_RANGE_POPULATED = false;
pub const ROW34_CALL_SET_COMPLETE = false;
pub const ROWS_0_9_PUBLISHABLE = false;
pub const EXACT_47_DOMAIN_CLOSURE_AVAILABLE = false;
pub const OUTER_STARK_VERIFIED = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = error{
    ArithmeticOverflow,
    CaptureChallengeMismatch,
    CallLayoutMismatch,
    IdentityMismatch,
    InvalidCanonicalClaim,
    InvalidTranscriptInput,
    TraceMutation,
};

pub const CallRange = shared_schedule_v2.CallRange;
pub const SharedPoseidonCallLayoutV2 =
    shared_schedule_v2.SharedPoseidonCallLayoutV2;
pub const OwnedCompletePoseidonScheduleV2 =
    shared_schedule_v2.OwnedCompletePoseidonScheduleV2;

pub const OwnedAuthorityTracesV2 = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    statement_preprocessed: [air_v2.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_main: [air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    statement_interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31,
    public_logup_preprocessed: [air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    public_logup_main: [air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    public_logup_interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,

    /// Allocates one exact, contiguous trace slab for the two boundary
    /// components.  This is public so the outer cohort can independently
    /// rebuild relation-bound Tree 2 columns without copying the storage
    /// geometry or borrowing the ingress bundle's staging memory.
    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const authority_v2.OuterManifestV2,
    ) !OwnedAuthorityTracesV2 {
        const statement_rows: usize = manifest.components[0].trace_rows;
        const public_rows: usize = manifest.components[1].trace_rows;
        const statement_columns =
            air_v2.Statement.PREPROCESSED_COLUMN_COUNT +
            air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
            air_v2.Statement.INTERACTION_COLUMN_COUNT;
        const public_columns =
            air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
            air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
            air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT;
        const statement_words = try multiply(statement_rows, statement_columns);
        const public_words = try multiply(public_rows, public_columns);
        const storage = try allocator.alloc(M31, try add(statement_words, public_words));
        errdefer allocator.free(storage);
        var cursor: usize = 0;
        var statement_preprocessed: [air_v2.Statement.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_preprocessed) |*column| {
            column.* = storage[cursor..][0..statement_rows];
            cursor += statement_rows;
        }
        var statement_main: [air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&statement_main) |*column| {
            column.* = storage[cursor..][0..statement_rows];
            cursor += statement_rows;
        }
        var statement_interaction: [air_v2.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&statement_interaction) |*column| {
            column.* = storage[cursor..][0..statement_rows];
            cursor += statement_rows;
        }
        var public_logup_preprocessed: [air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_preprocessed) |*column| {
            column.* = storage[cursor..][0..public_rows];
            cursor += public_rows;
        }
        var public_logup_main: [air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_main) |*column| {
            column.* = storage[cursor..][0..public_rows];
            cursor += public_rows;
        }
        var public_logup_interaction: [air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&public_logup_interaction) |*column| {
            column.* = storage[cursor..][0..public_rows];
            cursor += public_rows;
        }
        std.debug.assert(cursor == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .statement_preprocessed = statement_preprocessed,
            .statement_main = statement_main,
            .statement_interaction = statement_interaction,
            .public_logup_preprocessed = public_logup_preprocessed,
            .public_logup_main = public_logup_main,
            .public_logup_interaction = public_logup_interaction,
        };
    }

    pub fn deinit(self: *OwnedAuthorityTracesV2) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn view(self: *OwnedAuthorityTracesV2) authority_v2.TracesV2 {
        return .{
            .statement = .{
                .preprocessed = self.statement_preprocessed,
                .main = self.statement_main,
                .interaction = self.statement_interaction,
            },
            .public_logup = .{
                .preprocessed = self.public_logup_preprocessed,
                .main = self.public_logup_main,
                .interaction = self.public_logup_interaction,
            },
        };
    }
};

/// All allocations and verifier-owned source values required to continue one
/// native V2 leaf into recursive proving.  Construction takes ownership of
/// `capture` only after every derived artifact has passed validation; on any
/// error the caller retains the original capture unchanged.
pub const PreparedNativeV2LeafOuter = struct {
    allocator: std.mem.Allocator,
    capture_allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    pcs_config: PcsConfig,
    interaction_pow: u64,
    verifier_keys: source_v2.VerifierKeyAuthorityV2,
    outer_relations: universal.UniversalRelations,
    capture: NativeCapture,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    captured_fri: recursion.captured_fri.Owned,
    vm_air: recursion.vm_air_composition_circuit.Prepared,
    transcript_program: transcript_v2.Program,
    transcript_execution: transcript_v2.Execution,
    transcript_evidence: transcript_v2.Evidence,
    authority_traces: OwnedAuthorityTracesV2,
    authority_trace_id: Sha256Digest,
    authority_prepared: authority_v2.PreparedNativeVerifierOuterAuthorityV2,
    /// Materialized prefix only. It is not the complete row-34 call set until
    /// `shared_poseidon_layout.verifier_core` is populated and authenticated.
    row34_boundary_prefix_calls: []poseidon2_air.Call,
    shared_poseidon_layout: SharedPoseidonCallLayoutV2,
    /// Sealed construction receipt for the boundary-independent universal
    /// verifier cohort. It admits exactly rows 18--34: no V1 boundary and no
    /// V2-owned range provider are synthesized by the reuse seam.
    rows_18_34_core: recursive_fri_outer.V2CoreRows18Through34PreflightReceipt,
    rows_18_35: recursive_fri_outer.V2Rows18Through35PreflightReceipt,
    identity: Sha256Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        capture_allocator: std.mem.Allocator,
        capture: *NativeCapture,
        pcs_config: PcsConfig,
        interaction_pow: u64,
        verifier_keys: source_v2.VerifierKeyAuthorityV2,
        outer_relations: universal.UniversalRelations,
        verifier_plans: recursive_fri_outer.VerifierPlans,
    ) !PreparedNativeV2LeafOuter {
        try capture.validate();
        try verifier_keys.validate();
        try outer_relations.validate();

        var vm_plan = try clonePlan(allocator, verifier_plans.vm);
        errdefer vm_plan.deinit();
        var recursion_plan = try clonePlan(allocator, verifier_plans.recursion);
        errdefer recursion_plan.deinit();
        if (vm_plan.schema != .vm or recursion_plan.schema != .recursion)
            return error.InvalidTranscriptInput;
        const owned_plans = recursive_fri_outer.VerifierPlans{
            .vm = &vm_plan,
            .recursion = &recursion_plan,
        };

        var captured_fri = try recursion.captured_fri.Owned.init(
            allocator,
            recursion.captured_fri.ProfileConfig.fromPcs(pcs_config),
            &capture.proof,
        );
        errdefer captured_fri.deinit();
        var vm_air = try recursion.vm_air_composition_circuit.Prepared.init(
            allocator,
            &capture.vm_air,
            &capture.proof,
        );
        errdefer vm_air.deinit();

        var transcript_program = try transcript_v2.Program.initAuthenticatedLookupV2(
            allocator,
            &vm_plan,
            pcs_config,
            &capture.public_data.data,
            capture.vm_air.component_descs,
            capture.vm_air.infra_descs,
        );
        errdefer transcript_program.deinit();
        const canonical_claims = try canonicalClaimsFromCapture(capture);
        const transcript_inputs = transcript_v2.Inputs{
            .trace_commitments = captured_fri.trace_roots,
            .interaction_pow = interaction_pow,
            .claimed_sums = &canonical_claims,
            .sampled_values = captured_fri.sampled_values,
            .fri_commitments = captured_fri.fri_roots,
            .last_layer_coefficients = captured_fri.last_layer_coefficients,
            .pcs_pow = capture.proof.proof_of_work,
        };
        var transcript_execution = try transcript_v2.execute(
            allocator,
            &transcript_program,
            &capture.public_data.data,
            transcript_inputs,
        );
        errdefer transcript_execution.deinit();
        try transcript_execution.replayNative(&transcript_program);
        try validateTranscriptChallengesAgainstCapture(
            &transcript_program,
            &transcript_execution,
            capture,
            &captured_fri,
        );
        const transcript_evidence = try transcript_execution.evidence(
            &transcript_program,
        );

        const authority_shape = try authority_v2.preflight(
            &capture.public_data.data,
            &verifier_keys,
        );
        var typed_authority = try authority_v2.AuthorityV2.init(allocator);
        defer typed_authority.deinit();
        var authority_workspace = try authority_v2.WorkspaceV2.init(
            allocator,
            &authority_shape.manifest,
        );
        defer authority_workspace.deinit();
        var authority_traces = try OwnedAuthorityTracesV2.init(
            allocator,
            &authority_shape.manifest,
        );
        errdefer authority_traces.deinit();
        const native_relations = frontend.air.relation_challenges.Relations
            .fromDrawSequence(&capture.vm_air.relation_draws);
        var authority_prepared: authority_v2.PreparedNativeVerifierOuterAuthorityV2 = undefined;
        try authority_v2.prepareNativeVerifierInto(
            &authority_prepared,
            &authority_workspace,
            &typed_authority,
            authority_traces.view(),
            &capture.public_data.data,
            &verifier_keys,
            &native_relations,
            &capture.native_public_sums,
            &capture.receipt,
            capture.vm_air.component_descs,
            capture.vm_air.infra_descs,
            &outer_relations,
        );
        try authority_prepared.validateAgainst(
            &capture.public_data.data,
            &verifier_keys,
            &native_relations,
            &capture.native_public_sums,
            &capture.receipt,
            capture.vm_air.component_descs,
            capture.vm_air.infra_descs,
            &outer_relations,
        );
        const authority_trace_id = traceIdentity(authority_traces.storage);

        const transcript_call_count = transcript_execution.poseidonCalls().len;
        const authority_call_count = try authority_prepared.authorityPoseidonCallCount();
        const total_call_count = try add(transcript_call_count, authority_call_count);
        const row34_boundary_prefix_calls = try allocator.alloc(
            poseidon2_air.Call,
            total_call_count,
        );
        errdefer allocator.free(row34_boundary_prefix_calls);
        writeTranscriptCalls(
            row34_boundary_prefix_calls[0..transcript_call_count],
            transcript_execution.poseidonCalls(),
        );
        try authority_prepared.appendAuthorityPoseidonCallsInto(
            row34_boundary_prefix_calls[transcript_call_count..],
            &capture.public_data.data,
            &capture.receipt,
            capture.vm_air.component_descs,
            capture.vm_air.infra_descs,
        );
        const shared_poseidon_layout = try SharedPoseidonCallLayoutV2.initBoundaryPrefix(
            transcript_call_count,
            authority_call_count,
            row34_boundary_prefix_calls,
        );
        try validateTranscriptCallRange(
            row34_boundary_prefix_calls[0..transcript_call_count],
            &transcript_execution,
        );

        const rows_18_35 = try recursive_fri_outer.preflightV2Rows18Through35(
            &captured_fri,
            &vm_air,
            owned_plans,
            pcs_config,
            &capture.public_data.data,
            capture.vm_air.component_descs,
            capture.vm_air.infra_descs,
            &transcript_program,
            &transcript_execution,
            &transcript_evidence,
            capture.receipt.wire_id,
            capture.receipt.authority_id,
            authority_prepared.manifest.identity,
            authority_prepared.identity,
            authority_call_count,
        );
        const rows_18_34_core =
            try recursive_fri_outer.preflightV2CoreRows18Through34(
                allocator,
                &captured_fri,
                &vm_air,
                owned_plans,
            );

        var result = PreparedNativeV2LeafOuter{
            .allocator = allocator,
            .capture_allocator = capture_allocator,
            .pcs_config = pcs_config,
            .interaction_pow = interaction_pow,
            .verifier_keys = verifier_keys,
            .outer_relations = outer_relations,
            .capture = capture.*,
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .captured_fri = captured_fri,
            .vm_air = vm_air,
            .transcript_program = transcript_program,
            .transcript_execution = transcript_execution,
            .transcript_evidence = transcript_evidence,
            .authority_traces = authority_traces,
            .authority_trace_id = authority_trace_id,
            .authority_prepared = authority_prepared,
            .row34_boundary_prefix_calls = row34_boundary_prefix_calls,
            .shared_poseidon_layout = shared_poseidon_layout,
            .rows_18_34_core = rows_18_34_core,
            .rows_18_35 = rows_18_35,
            .identity = undefined,
        };
        result.identity = bundleIdentity(&result);
        // This check still borrows the caller-owned capture.  Ownership moves
        // only after every fallible operation has succeeded.
        try result.validate();
        capture.* = undefined;
        return result;
    }

    pub fn deinit(self: *PreparedNativeV2LeafOuter) void {
        self.allocator.free(self.row34_boundary_prefix_calls);
        self.authority_traces.deinit();
        self.transcript_execution.deinit();
        self.transcript_program.deinit();
        self.vm_air.deinit();
        self.captured_fri.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.capture.deinit(self.capture_allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedNativeV2LeafOuter) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.IdentityMismatch;
        }
        try self.capture.validate();
        try self.verifier_keys.validate();
        try self.outer_relations.validate();
        try self.vm_plan.validate();
        try self.recursion_plan.validate();
        if (self.vm_plan.schema != .vm or self.recursion_plan.schema != .recursion)
            return error.InvalidTranscriptInput;
        try self.captured_fri.evaluation.validateAgainst(&self.captured_fri.circuit);
        try self.captured_fri.pcs_evaluation.validateAgainst(
            &self.captured_fri.pcs_circuit,
        );
        try self.vm_air.validate();
        try self.transcript_program.validateAgainst(
            &self.vm_plan,
            self.pcs_config,
            &self.capture.public_data.data,
            self.capture.vm_air.component_descs,
            self.capture.vm_air.infra_descs,
        );
        try self.transcript_execution.validateAgainst(&self.transcript_program);
        try self.transcript_execution.replayNative(&self.transcript_program);
        try self.transcript_evidence.validateAgainst(
            &self.transcript_execution,
            &self.transcript_program,
        );
        try validateTranscriptChallengesAgainstCapture(
            &self.transcript_program,
            &self.transcript_execution,
            &self.capture,
            &self.captured_fri,
        );
        const native_relations = frontend.air.relation_challenges.Relations
            .fromDrawSequence(&self.capture.vm_air.relation_draws);
        try self.authority_prepared.validateAgainst(
            &self.capture.public_data.data,
            &self.verifier_keys,
            &native_relations,
            &self.capture.native_public_sums,
            &self.capture.receipt,
            self.capture.vm_air.component_descs,
            self.capture.vm_air.infra_descs,
            &self.outer_relations,
        );
        if (!std.mem.eql(
            u8,
            &self.authority_trace_id,
            &traceIdentity(self.authority_traces.storage),
        )) return error.TraceMutation;
        try self.shared_poseidon_layout.validate(self.row34_boundary_prefix_calls);
        const transcript_end: usize = self.shared_poseidon_layout.transcript.end;
        try validateTranscriptCallRange(
            self.row34_boundary_prefix_calls[0..transcript_end],
            &self.transcript_execution,
        );
        try self.rows_18_34_core.validate();
        try self.rows_18_35.validate();
        if (self.rows_18_34_core.first_row != 18 or
            self.rows_18_34_core.last_row != 34 or
            self.rows_18_34_core.row_count != 17 or
            self.rows_18_35.universal_roster_count !=
                recursive_fri_outer.V2_UNIVERSAL_ROSTER_COMPONENT_COUNT or
            self.rows_18_35.authority_source_count !=
                authority_v2.COMPONENT_COUNT or
            self.rows_18_35.target_component_count !=
                recursive_fri_outer.V2_TARGET_COMPONENT_COUNT or
            !std.meta.eql(self.rows_18_35.wire_id, self.capture.receipt.wire_id) or
            !std.meta.eql(
                self.rows_18_35.statement_authority_id,
                self.capture.receipt.authority_id,
            ) or !std.meta.eql(
            self.rows_18_35.transcript_evidence_id,
            self.transcript_evidence.identity,
        ) or self.rows_18_35.authority_poseidon_call_count !=
            try self.shared_poseidon_layout.statement_authority.count() or
            !std.mem.eql(u8, &self.identity, &bundleIdentity(self)))
        {
            return error.IdentityMismatch;
        }
    }

    pub fn rows0Through9Publishable(_: *const PreparedNativeV2LeafOuter) bool {
        return false;
    }

    pub fn exact47DomainClosureVerified(_: *const PreparedNativeV2LeafOuter) bool {
        return false;
    }

    pub fn productionReady(_: *const PreparedNativeV2LeafOuter) bool {
        return false;
    }
};

fn clonePlan(
    allocator: std.mem.Allocator,
    source: *const schedule.Plan,
) !schedule.Plan {
    try source.validate();
    const steps = try allocator.dupe(schedule.VerifierStep, source.steps);
    errdefer allocator.free(steps);
    const result = schedule.Plan{
        .allocator = allocator,
        .schema = source.schema,
        .spec = source.spec,
        .protocol_id = source.protocol_id,
        .shape_id = source.shape_id,
        .authority_digest = source.authority_digest,
        .steps = steps,
    };
    try result.validate();
    return result;
}

fn canonicalClaimsFromCapture(
    capture: *const NativeCapture,
) ![transcript_claims.COMPONENT_COUNT]QM31 {
    var result = [_]QM31{QM31.zero()} ** transcript_claims.COMPONENT_COUNT;
    var cursor: usize = 0;
    for (capture.vm_air.component_descs) |descriptor| {
        const count = opcode_entries.batchCount(descriptor.family);
        const end = try add(cursor, count);
        if (end > capture.vm_air.detailed_claims.len)
            return error.InvalidCanonicalClaim;
        var total = QM31.zero();
        for (capture.vm_air.detailed_claims[cursor..end]) |value|
            total = total.add(value);
        const index = @intFromEnum(componentForFamily(descriptor.family));
        result[index] = result[index].add(total);
        cursor = end;
    }
    for (capture.vm_air.infra_descs) |descriptor| {
        const count: usize = @intCast(statement.nClaimedSumsForInfra(
            descriptor.kind,
        ));
        const end = try add(cursor, count);
        if (end > capture.vm_air.detailed_claims.len)
            return error.InvalidCanonicalClaim;
        var total = QM31.zero();
        for (capture.vm_air.detailed_claims[cursor..end]) |value|
            total = total.add(value);
        const index = @intFromEnum(componentForInfra(descriptor.kind));
        result[index] = result[index].add(total);
        cursor = end;
    }
    if (cursor != capture.vm_air.detailed_claims.len)
        return error.InvalidCanonicalClaim;
    return result;
}

fn componentForFamily(
    family: frontend.runner.trace.OpcodeFamily,
) transcript_claims.Component {
    return switch (family) {
        .auipc => .auipc,
        .base_alu_imm => .base_alu_imm,
        .base_alu_reg => .base_alu_reg,
        .branch_eq => .branch_eq,
        .branch_lt => .branch_lt,
        .div => .div,
        .jal => .jal,
        .jalr => .jalr,
        .load_store => .load_store,
        .lt_imm => .lt_imm,
        .lt_reg => .lt_reg,
        .lui => .lui,
        .mul => .mul,
        .mulh => .mulh,
        .shifts_imm => .shifts_imm,
        .shifts_reg => .shifts_reg,
        .fence => .fence,
    };
}

fn componentForInfra(kind: statement.InfraKind) transcript_claims.Component {
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

/// The only caller-supplied dynamic word is the interaction PoW nonce.  Exact
/// equality of every downstream relation/composition/FRI/query draw with the
/// successful verifier capture binds that nonce to the native transcript.
fn validateTranscriptChallengesAgainstCapture(
    program: *const transcript_v2.Program,
    execution: *const transcript_v2.Execution,
    capture: *const NativeCapture,
    captured_fri: *const recursion.captured_fri.Owned,
) !void {
    if (program.instructions.len != execution.operations.len or
        captured_fri.circuit.lifting_log_size >= 31)
    {
        return error.CaptureChallengeMismatch;
    }
    var relation_count: usize = 0;
    var composition_count: usize = 0;
    var oods_count: usize = 0;
    var deep_count: usize = 0;
    var fri_alpha_count: usize = 0;
    var query_count: usize = 0;
    const query_mask = (@as(u32, 1) << @intCast(
        captured_fri.circuit.lifting_log_size,
    )) - 1;
    for (program.instructions, execution.operations) |instruction, operation| {
        switch (instruction.kind) {
            .relation_draw => {
                const draw = operation.draw orelse
                    return error.CaptureChallengeMismatch;
                const relation_index: usize = @intCast(instruction.args[0]);
                if (relation_index != relation_count or
                    2 * relation_index + 1 >= capture.vm_air.relation_draws.len)
                {
                    return error.CaptureChallengeMismatch;
                }
                try expectQm31(draw, 0, capture.vm_air.relation_draws[2 * relation_index]);
                try expectQm31(draw, 4, capture.vm_air.relation_draws[2 * relation_index + 1]);
                relation_count += 1;
            },
            .composition_draw => {
                try expectQm31(
                    operation.draw orelse return error.CaptureChallengeMismatch,
                    0,
                    capture.proof.composition_randomness,
                );
                composition_count += 1;
            },
            .oods_draw => {
                try expectQm31(
                    operation.draw orelse return error.CaptureChallengeMismatch,
                    0,
                    capture.proof.oods_seed,
                );
                oods_count += 1;
            },
            .deep_draw => {
                try expectQm31(
                    operation.draw orelse return error.CaptureChallengeMismatch,
                    0,
                    capture.proof.deep_randomness,
                );
                deep_count += 1;
            },
            .fri_alpha_draw => {
                const layer: usize = @intCast(instruction.args[0]);
                if (layer != fri_alpha_count or layer >= captured_fri.fri_alphas.len)
                    return error.CaptureChallengeMismatch;
                try expectQm31(
                    operation.draw orelse return error.CaptureChallengeMismatch,
                    0,
                    captured_fri.fri_alphas[layer],
                );
                fri_alpha_count += 1;
            },
            .query_draw => {
                const draw = operation.draw orelse
                    return error.CaptureChallengeMismatch;
                const first: usize = @intCast(instruction.args[1]);
                const count: usize = @intCast(instruction.args[2]);
                const end = try add(first, count);
                if (first != query_count or count > transcript_v2.RATE or
                    end > captured_fri.raw_queries.len)
                {
                    return error.CaptureChallengeMismatch;
                }
                for (captured_fri.raw_queries[first..end], draw[0..count]) |
                    expected,
                    raw,
                | if (expected.toU32() != (raw.toU32() & query_mask))
                    return error.CaptureChallengeMismatch;
                query_count = end;
            },
            else => if (operation.draw != null)
                return error.CaptureChallengeMismatch,
        }
    }
    if (relation_count * 2 != capture.vm_air.relation_draws.len or
        composition_count != 1 or oods_count != 1 or deep_count != 1 or
        fri_alpha_count != captured_fri.fri_alphas.len or
        query_count != captured_fri.raw_queries.len)
    {
        return error.CaptureChallengeMismatch;
    }
}

fn expectQm31(
    draw: transcript_v2.Draw,
    offset: usize,
    expected: QM31,
) Error!void {
    if (offset + 4 > draw.len) return error.CaptureChallengeMismatch;
    const words = expected.toM31Array();
    for (draw[offset..][0..4], words) |actual, word|
        if (!actual.eql(word)) return error.CaptureChallengeMismatch;
}

fn writeTranscriptCalls(
    destination: []poseidon2_air.Call,
    source: []const transcript_v2.PoseidonCall,
) void {
    std.debug.assert(destination.len == source.len);
    for (destination, source) |*output, input| {
        var words: [poseidon2_air.WIDTH]u32 = undefined;
        for (&words, input.input) |*word, value| word.* = value.toU32();
        output.* = .{
            .input = words,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
    }
}

fn validateTranscriptCallRange(
    calls: []const poseidon2_air.Call,
    execution: *const transcript_v2.Execution,
) Error!void {
    const expected = execution.poseidonCalls();
    if (calls.len != expected.len) return error.CallLayoutMismatch;
    for (calls, expected) |call, source| {
        if (call.wide or !call.io or call.narrow_output != null)
            return error.CallLayoutMismatch;
        for (call.input, source.input) |actual, word|
            if (actual != word.toU32()) return error.CallLayoutMismatch;
    }
}

fn traceIdentity(words: []const M31) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRACE_ID_DOMAIN);
    hashInt(&hash, u64, words.len);
    for (words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn bundleIdentity(bundle: *const PreparedNativeV2LeafOuter) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BUNDLE_ID_DOMAIN);
    hashInt(&hash, u16, bundle.format_version);
    hashInt(&hash, u16, bundle.schema_version);
    hashInt(&hash, u64, bundle.interaction_pow);
    hashDigest(&hash, bundle.capture.receipt.identity);
    hashDigest(&hash, bundle.capture.native_public_sums.identity);
    hash.update(&bundle.capture.vm_air.identity_digest);
    hashDigest(&hash, bundle.vm_plan.authority_digest);
    hashDigest(&hash, bundle.recursion_plan.authority_digest);
    hash.update(&bundle.captured_fri.circuit.identity_digest);
    hash.update(&bundle.captured_fri.pcs_circuit.identity_digest);
    hash.update(&bundle.vm_air.circuit.identity_digest);
    hashDigest(&hash, bundle.transcript_program.identity);
    hashDigest(&hash, bundle.transcript_execution.identity);
    hashDigest(&hash, bundle.transcript_evidence.identity);
    hash.update(&bundle.transcript_evidence.trace_receipt);
    hashDigest(&hash, bundle.authority_prepared.identity);
    hash.update(&bundle.authority_trace_id);
    hash.update(&bundle.shared_poseidon_layout.identity);
    hash.update(&bundle.rows_18_34_core.identity);
    hash.update(&bundle.rows_18_35.identity);
    return hash.finalResult();
}

fn hashDigest(hash: *std.crypto.hash.sha2.Sha256, digest: Digest) void {
    for (digest) |word| hashInt(hash, u32, word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn usizeToU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.ArithmeticOverflow;
}

fn multiply(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

fn add(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

comptime {
    if (FORMAT_VERSION == 1 or SCHEMA_VERSION == 0 or
        transcript_claims.COMPONENT_COUNT != 28 or
        SHARED_ROW34_PROVIDER_COUNT != 1 or !ROW34_BOUNDARY_PREFIX_AVAILABLE or
        ROW34_VERIFIER_CORE_RANGE_POPULATED or ROW34_CALL_SET_COMPLETE or
        ROWS_0_9_PUBLISHABLE or
        EXACT_47_DOMAIN_CLOSURE_AVAILABLE or OUTER_STARK_VERIFIED or
        PRODUCTION_ACTIVATION)
    {
        @compileError("recursive V2 leaf-outer capability boundary drifted");
    }
}
