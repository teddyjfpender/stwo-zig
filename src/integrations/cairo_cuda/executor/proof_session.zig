//! Direct, single-request Cairo CUDA proof-session sequencing.
//!
//! This coordinator is intentionally not a generic graph runner. It executes
//! each authenticated Cairo phase exactly once, in transcript order, and
//! delegates only the two controller boundaries that are not yet complete:
//! interaction-tree commitment and constraint evaluation/composition commit.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const compact = @import(
    "../../../frontends/cairo/compact_verifier_interchange.zig",
);
const relation_stage = @import(
    "../../../backends/cuda/runtime/stages/relation.zig",
);
const runtime_stages = @import(
    "../../../backends/cuda/runtime/stages/mod.zig",
);
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const proof_transaction = @import(
    "../../../backends/cuda/runtime/proof_transaction.zig",
);
const proof_capture = @import(
    "../../native_cuda/common/proof_assembly.zig",
);
const request_compiler = @import("../request_compiler.zig");
const resident_plan = @import("resident_plan.zig");
const trace_writer = @import("trace_writer_controller.zig");
const trace_commit = @import("trace_commit.zig");
const eval_controller = @import("eval/controller.zig");
const pcs_types = @import("pcs_hooks_types.zig");
const oods_controller = @import("pcs_oods_controller.zig");
const quotient_controller = @import("quotient/controller.zig");
const fri_controller = @import("pcs_fri_controller.zig");
const decommit_controller = @import("pcs_decommit_controller.zig");
const transcript_controller = @import("transcript/controller.zig");
const transcript_schedule = @import("transcript/schedule.zig");
const terminal_controller = @import("terminal_controller.zig");

pub const production_ready = false;

pub const Gap = enum {
    production_ingress_binding_compiler,
    statement_bootstrap_payload_binding,
    oracle_verification,
};

pub const gaps = [_]Gap{
    .production_ingress_binding_compiler,
    .statement_bootstrap_payload_binding,
    .oracle_verification,
};

pub const Controllers = struct {
    trace_writers: *const trace_writer.Prepared,
    preprocessed_commit: *trace_commit.Bound,
    main_commit: *trace_commit.Bound,
    interaction_commit: *trace_commit.Bound,
    composition_commit: *trace_commit.Bound,
    evaluation: *const eval_controller.Bound,
    pcs_bindings: pcs_types.Bindings,
    relation: *const relation_stage.PreparedPlan,
    oods: *oods_controller.Prepared,
    quotient: *const quotient_controller.Prepared,
    fri: *fri_controller.Prepared,
    decommit: *decommit_controller.Prepared,
};

/// Resident transcript inputs not already owned by a tail controller.
///
/// The eleven bootstrap entries are in
/// `transcript_schedule.bootstrap_mix_ordinals` order. The final entry must be
/// the exact root destination owned by `Controllers.main_commit`.
pub const TranscriptBindings = struct {
    view: transcript_controller.View,
    bootstrap: [transcript_schedule.bootstrap_mix_ordinals.len]common.Words,
    interaction_pow: transcript_controller.PowView,
    relation_elements: common.SecureFields,
    interaction_claims: common.Words,
    interaction_root: common.Words,
    composition_alpha: common.SecureFields,
    composition_root: common.Words,
    query_pow: transcript_controller.PowView,

    pub fn validate(
        self: TranscriptBindings,
        schedule: transcript_schedule.Schedule,
        main_root: common.Hashes,
    ) !void {
        if (self.view.state.len != transcript_controller.state_words or
            self.view.boundary_snapshot.len !=
                transcript_controller.boundary_snapshot_words or
            self.relation_elements.len != 2 or
            self.composition_alpha.len != 1 or
            self.interaction_root.len != 8 or
            self.composition_root.len != 8 or
            self.bootstrap.len == 0)
        {
            return error.InvalidProofSessionBindings;
        }
        try requireSameDevice(
            self.view.state,
            self.view.boundary_snapshot,
        );
        for (self.bootstrap, 0..) |source, step| {
            try schedule.validateInputWords(@intCast(step), source.len);
            try requireSameDevice(self.view.state, source);
        }
        try schedule.validateOutputWords(
            12,
            self.relation_elements.len * 4,
        );
        try schedule.validateInputWords(13, self.interaction_claims.len);
        try schedule.validateInputWords(14, self.interaction_root.len);
        try schedule.validateOutputWords(
            15,
            self.composition_alpha.len * 4,
        );
        try schedule.validateInputWords(16, self.composition_root.len);
        try validatePow(self.interaction_pow);
        try validatePow(self.query_pow);
        try schedule.validateInputWords(
            11,
            self.interaction_pow.transcript_nonce.len,
        );
        try schedule.validateInputWords(
            schedule.operation_count - 2,
            self.query_pow.transcript_nonce.len,
        );
        const bootstrap_main = self.bootstrap[self.bootstrap.len - 1];
        if (!sameWords(bootstrap_main, try main_root.cast(u32)))
            return error.InvalidProofSessionBindings;

        inline for (.{
            self.interaction_pow.prefix_digest,
            self.interaction_pow.completed_blocks,
            self.interaction_pow.transcript_nonce,
            self.interaction_claims,
            self.interaction_root,
            self.composition_root,
            self.query_pow.prefix_digest,
            self.query_pow.completed_blocks,
            self.query_pow.transcript_nonce,
        }) |words| try requireSameDevice(self.view.state, words);
        inline for (.{
            self.interaction_pow.best_nonce,
            self.query_pow.best_nonce,
        }) |nonce| try requireSameDevice(
            self.view.state,
            try nonce.cast(u32),
        );
        try requireSameDevice(
            self.view.state,
            try self.relation_elements.cast(u32),
        );
        try requireSameDevice(
            self.view.state,
            try self.composition_alpha.cast(u32),
        );
    }
};

pub const State = enum {
    prepared,
    poisoned,
    graph_complete,
    terminal_complete,
};

pub const Prepared = struct {
    program_identity: proof_ir.Digest,
    resident_identity: proof_ir.Digest,
    execution_identity: proof_ir.Digest,
    transcript: transcript_schedule.Schedule,
    controllers: Controllers,
    bindings: TranscriptBindings,
    identity: proof_ir.Digest,
    state: State = .prepared,

    pub fn init(
        request: *const request_compiler.PreparedRequest,
        protocol: compact.CompactProtocolV1,
        controllers: Controllers,
        bindings: TranscriptBindings,
    ) !Prepared {
        try request.execution_schedule.validate(request.proof_program);
        const schedule = try transcript_schedule.Schedule.init(
            request.proof_program,
            protocol,
        );
        try controllers.preprocessed_commit.prepared
            .validateProducedAuthority(
            request.proof_program,
            request.resident,
            .preprocessed,
        );
        try controllers.main_commit.prepared.validateMainAuthority(
            request.proof_program,
            request.resident,
            request.trace_dispatch,
        );
        try controllers.interaction_commit.prepared
            .validateProducedAuthority(
            request.proof_program,
            request.resident,
            .interaction,
        );
        try controllers.composition_commit.prepared
            .validateProducedAuthority(
            request.proof_program,
            request.resident,
            .composition,
        );
        if (!std.mem.eql(
            u8,
            &controllers.evaluation.prepared.plan_identity,
            &request.resident.identity,
        ) or !std.mem.eql(
            u8,
            &controllers.pcs_bindings.identity,
            &request.resident.identity,
        )) {
            return error.InvalidProofSessionAuthority;
        }
        if (request.missing_lowerings.len != 0 or
            request.receipt.missing_lowering_count != 0 or
            request.receipt.hasBlocker(.component_aot_lowerings) or
            !std.mem.eql(
                u8,
                &request.resident.program_identity,
                &request.proof_program.program_digest,
            ) or !std.mem.eql(
            u8,
            &relation_stage.topologyIdentity(controllers.relation),
            &request.relation_plan.topology_identity,
        ) or !std.mem.eql(
            u8,
            &controllers.trace_writers.schedule_identity,
            &request.trace_dispatch.identity,
        ) or controllers.main_commit.prepared.tree_ordinal >=
            request.proof_program.commitments.len or
            request.proof_program.commitments[
                controllers.main_commit.prepared.tree_ordinal
            ].role != .main or
            std.mem.allEqual(
                u8,
                &controllers.main_commit.prepared.identity,
                0,
            ) or
            !sameWords(
                bindings.bootstrap[2],
                try controllers.preprocessed_commit.root.cast(u32),
            ) or
            !sameWords(
                bindings.interaction_root,
                try controllers.interaction_commit.root.cast(u32),
            ) or
            !sameWords(
                bindings.composition_root,
                try controllers.composition_commit.root.cast(u32),
            ))
        {
            return error.InvalidProofSessionAuthority;
        }
        try bindings.validate(schedule, controllers.main_commit.root);
        try controllers.oods.validate(schedule);
        try controllers.fri.validate(schedule);
        try controllers.decommit.validate(
            &request.resident,
            protocol,
            schedule,
        );
        try requireControllerPlan(
            request.resident.identity,
            controllers.oods.plan_identity,
        );
        try requireControllerPlan(
            request.resident.identity,
            controllers.quotient.plan_identity,
        );
        try requireControllerPlan(
            request.resident.identity,
            controllers.fri.plan_identity,
        );
        try requireControllerPlan(
            request.resident.identity,
            controllers.decommit.plan_identity,
        );
        try relation_stage.validateTranscriptChallenge(
            controllers.relation,
            bindings.relation_elements,
        );
        try requireSameTranscript(
            bindings.view,
            controllers.oods.transcript_view,
        );
        try requireSameTranscript(
            bindings.view,
            controllers.fri.transcript_view,
        );
        try requireSameTranscript(
            bindings.view,
            controllers.decommit.transcript_view,
        );
        if (std.mem.allEqual(u8, &controllers.quotient.identity, 0))
            return error.InvalidProofSessionAuthority;

        var result = Prepared{
            .program_identity = request.proof_program.program_digest,
            .resident_identity = request.resident.identity,
            .execution_identity = request.execution_schedule.identity,
            .transcript = schedule,
            .controllers = controllers,
            .bindings = bindings,
            .identity = undefined,
        };
        result.identity = preparedIdentity(result);
        return result;
    }

    /// Executes the complete admitted resident request. All constraint parts,
    /// heterogeneous LDEs, accumulator lifts, and composition output columns
    /// are owned by the authenticated evaluator bound during ingress.
    pub fn executeDevelopment(
        self: *Prepared,
        transaction: anytype,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
    ) !decommit_controller.TerminalRoute {
        try self.validate(plan, protocol);
        if (self.state != .prepared)
            return error.InvalidProofSessionState;
        self.state = .poisoned;
        var cursor = transcript_controller.Cursor{};
        const session = transaction.proofSession();

        transaction.finishIngress() catch |err| {
            std.debug.print(
                "cairo-cuda proof finish-ingress failed: {s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        transaction.beginStage(.trace_generation) catch |err| {
            std.debug.print(
                "cairo-cuda proof begin trace-generation failed: {s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        self.controllers.trace_writers.execute(session) catch |err| {
            std.debug.print(
                "cairo-cuda proof trace-writers failed: {s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        transaction.endStage(.trace_generation) catch |err| {
            std.debug.print(
                "cairo-cuda proof end trace-generation failed: {s}\n",
                .{@errorName(err)},
            );
            return err;
        };

        try transaction.beginStage(.trace_commit);
        try self.controllers.preprocessed_commit.execute(session);
        try self.controllers.main_commit.execute(session);
        try proof_capture.captureStaticTraceRoot(
            session,
            .{ .proof = self.controllers.oods.proof },
            0,
            self.bindings.bootstrap[2],
        );
        try proof_capture.captureTraceRoot(
            session,
            .{ .proof = self.controllers.oods.proof },
            1,
            self.controllers.main_commit.root,
        );
        try transcript_controller.initialize(
            runtime_stages.transcript.Native,
            session,
            self.transcript,
            &cursor,
            self.bindings.view,
        );
        for (
            transcript_schedule.bootstrap_mix_ordinals,
            self.bindings.bootstrap,
        ) |ordinal, source| {
            try transcript_controller.mixInput(
                runtime_stages.transcript.Native,
                session,
                .trace_commit,
                self.transcript,
                &cursor,
                self.bindings.view,
                ordinal,
                source,
            );
        }
        try transcript_controller.executePow(
            runtime_stages.fri.Native,
            runtime_stages.transcript.Native,
            session,
            .trace_commit,
            self.transcript,
            &cursor,
            self.bindings.view,
            self.bindings.interaction_pow,
        );
        try capturePow(
            session,
            self.controllers.oods.proof.pow_nonce,
            0,
            self.bindings.interaction_pow.transcript_nonce,
        );
        try transcript_controller.drawSecure(
            runtime_stages.transcript.Native,
            session,
            .trace_commit,
            self.transcript,
            &cursor,
            self.bindings.view,
            1,
            self.bindings.relation_elements,
        );
        try relation_stage.TraceCommitNative.execute(
            session,
            self.controllers.relation,
        );
        try session.context.copyDeviceSlice(
            u32,
            self.bindings.interaction_claims,
            try relation_stage.transcriptClaims(
                self.controllers.relation,
            ),
        );
        try self.controllers.interaction_commit.execute(session);
        try proof_capture.captureTraceRoot(
            session,
            .{ .proof = self.controllers.oods.proof },
            2,
            self.controllers.interaction_commit.root,
        );
        try captureInteractionClaims(
            session,
            self.controllers.oods.proof.trace_commitments,
            self.bindings.interaction_claims,
        );
        try common.requireStage(session, .trace_commit);
        try transcript_controller.mixInput(
            runtime_stages.transcript.Native,
            session,
            .trace_commit,
            self.transcript,
            &cursor,
            self.bindings.view,
            22,
            self.bindings.interaction_claims,
        );
        try transcript_controller.mixInput(
            runtime_stages.transcript.Native,
            session,
            .trace_commit,
            self.transcript,
            &cursor,
            self.bindings.view,
            23,
            self.bindings.interaction_root,
        );
        try transcript_controller.drawSecure(
            runtime_stages.transcript.Native,
            session,
            .trace_commit,
            self.transcript,
            &cursor,
            self.bindings.view,
            2,
            self.bindings.composition_alpha,
        );
        try transaction.endStage(.trace_commit);

        try transaction.beginStage(.constraint_evaluation);
        try self.controllers.evaluation.execute(
            transaction,
            self.controllers.pcs_bindings,
            self.bindings.composition_alpha,
        );
        try common.requireStage(session, .constraint_evaluation);
        try self.controllers.composition_commit.execute(session);
        try proof_capture.captureTraceRoot(
            session,
            .{ .proof = self.controllers.oods.proof },
            3,
            self.controllers.composition_commit.root,
        );
        try transcript_controller.mixInput(
            runtime_stages.transcript.Native,
            session,
            .constraint_evaluation,
            self.transcript,
            &cursor,
            self.bindings.view,
            24,
            self.bindings.composition_root,
        );
        try self.controllers.oods.drawParameter(
            session,
            self.transcript,
            &cursor,
        );
        try transaction.endStage(.constraint_evaluation);

        try transaction.beginStage(.oods);
        try self.controllers.oods.execute(
            session,
            self.transcript,
            &cursor,
        );
        try transaction.endStage(.oods);

        try transaction.beginStage(.quotient);
        try self.controllers.quotient.execute(session);
        try transaction.endStage(.quotient);

        try transaction.beginStage(.fri_commit);
        try self.controllers.fri.execute(
            session,
            self.transcript,
            &cursor,
        );
        try transaction.endStage(.fri_commit);

        try transaction.beginStage(.pow);
        try transcript_controller.executePow(
            runtime_stages.fri.Native,
            runtime_stages.transcript.Native,
            session,
            .pow,
            self.transcript,
            &cursor,
            self.bindings.view,
            self.bindings.query_pow,
        );
        try capturePow(
            session,
            self.controllers.oods.proof.pow_nonce,
            2,
            self.bindings.query_pow.transcript_nonce,
        );
        try transaction.endStage(.pow);

        try transaction.beginStage(.decommit);
        const route = try self.controllers.decommit.execute(
            session,
            plan,
            protocol,
            self.transcript,
            &cursor,
        );
        try transaction.endStage(.decommit);
        // The graph and transcript are complete, but no proof is accepted
        // until proof_assembly performs its sole D2H, strict terminal decode,
        // resident/AOT evidence validation, and pinned-oracle verification.
        self.state = .graph_complete;
        return route;
    }

    pub fn finish(
        self: *Prepared,
        allocator: std.mem.Allocator,
        transaction: *proof_transaction.ResidentProofTransaction,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
    ) !terminal_controller.Output {
        if (self.state != .graph_complete)
            return error.InvalidProofSessionState;
        const output = try terminal_controller.finish(
            allocator,
            transaction,
            plan,
            protocol,
        );
        self.state = .terminal_complete;
        return output;
    }

    pub fn validate(
        self: Prepared,
        plan: *const resident_plan.Plan,
        protocol: compact.CompactProtocolV1,
    ) !void {
        if (std.mem.allEqual(u8, &self.identity, 0) or
            !std.mem.eql(u8, &self.resident_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &self.program_identity,
                &plan.program_identity,
            ) or !std.mem.eql(
            u8,
            &self.identity,
            &preparedIdentity(self),
        )) {
            return error.InvalidProofSessionAuthority;
        }
        try self.bindings.validate(
            self.transcript,
            self.controllers.main_commit.root,
        );
        try self.controllers.oods.validate(self.transcript);
        try self.controllers.fri.validate(self.transcript);
        try self.controllers.decommit.validate(
            plan,
            protocol,
            self.transcript,
        );
        try requireControllerPlan(
            plan.identity,
            self.controllers.oods.plan_identity,
        );
        try requireControllerPlan(
            plan.identity,
            self.controllers.quotient.plan_identity,
        );
        try requireControllerPlan(
            plan.identity,
            self.controllers.fri.plan_identity,
        );
        try requireControllerPlan(
            plan.identity,
            self.controllers.decommit.plan_identity,
        );
        if (!std.mem.eql(
            u8,
            &self.controllers.evaluation.prepared.plan_identity,
            &plan.identity,
        ) or !std.mem.eql(
            u8,
            &self.controllers.pcs_bindings.identity,
            &plan.identity,
        )) {
            return error.InvalidProofSessionAuthority;
        }
        try relation_stage.validateTranscriptChallenge(
            self.controllers.relation,
            self.bindings.relation_elements,
        );
        try requireSameTranscript(
            self.bindings.view,
            self.controllers.oods.transcript_view,
        );
        try requireSameTranscript(
            self.bindings.view,
            self.controllers.fri.transcript_view,
        );
        try requireSameTranscript(
            self.bindings.view,
            self.controllers.decommit.transcript_view,
        );
    }
};

pub fn requireProductionReady() !void {
    return error.MissingProductionIngressBindingCompiler;
}

fn requireSameDevice(reference: common.Words, other: common.Words) !void {
    if (other.len == 0 or other.address == 0 or
        reference.owner == 0 or reference.generation == 0 or
        other.owner != reference.owner or
        other.generation != reference.generation)
    {
        return error.InvalidProofSessionBindings;
    }
}

fn validatePow(pow: transcript_controller.PowView) !void {
    if (pow.prefix_digest.len != 8 or
        pow.best_nonce.len != 1 or
        pow.completed_blocks.len != 1 or
        pow.transcript_nonce.len != 2)
    {
        return error.InvalidProofSessionBindings;
    }
}

fn capturePow(
    session: anytype,
    destination: common.Words,
    first: usize,
    nonce: common.Words,
) !void {
    if (nonce.len != 2 or destination.len != 4 or first + 2 > 4)
        return error.InvalidProofSessionBindings;
    try session.context.copyDeviceSlice(
        u32,
        try destination.sub(first, 2),
        nonce,
    );
}

fn captureInteractionClaims(
    session: anytype,
    destination: common.Words,
    claims: common.Words,
) !void {
    const root_words: usize = 4 * 8;
    if (claims.len == 0 or destination.len != root_words + claims.len)
        return error.InvalidProofSessionBindings;
    try session.context.copyDeviceSlice(
        u32,
        try destination.sub(root_words, claims.len),
        claims,
    );
}

fn sameWords(left: common.Words, right: common.Words) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

fn requireSameTranscript(
    expected: transcript_controller.View,
    actual: transcript_controller.View,
) !void {
    if (!sameWords(expected.state, actual.state) or
        !sameWords(
            expected.boundary_snapshot,
            actual.boundary_snapshot,
        ))
    {
        return error.TranscriptStorageFork;
    }
}

fn requireControllerPlan(
    expected: proof_ir.Digest,
    actual: proof_ir.Digest,
) !void {
    if (!std.mem.eql(u8, &expected, &actual))
        return error.CrossPlanControllerBinding;
}

fn preparedIdentity(value: Prepared) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/proof-session/v1\x00");
    hash.update(&value.program_identity);
    hash.update(&value.resident_identity);
    hash.update(&value.execution_identity);
    hash.update(&value.transcript.schedule_identity);
    hash.update(&value.controllers.trace_writers.identity);
    hash.update(&value.controllers.preprocessed_commit.prepared.identity);
    hash.update(&value.controllers.main_commit.prepared.identity);
    hash.update(&value.controllers.interaction_commit.prepared.identity);
    hash.update(&value.controllers.composition_commit.prepared.identity);
    hash.update(&value.controllers.evaluation.prepared.identity);
    hash.update(&value.controllers.pcs_bindings.identity);
    hash.update(&relation_stage.topologyIdentity(value.controllers.relation));
    hash.update(&value.controllers.oods.identity);
    hash.update(&value.controllers.quotient.identity);
    hash.update(&value.controllers.fri.identity);
    hash.update(&value.controllers.decommit.identity);
    hashWords(&hash, value.bindings.view.state);
    hashWords(&hash, value.bindings.view.boundary_snapshot);
    for (value.bindings.bootstrap) |entry| hashWords(&hash, entry);
    hashPow(&hash, value.bindings.interaction_pow);
    hashWords(&hash, tryCastWords(value.bindings.relation_elements));
    hashWords(&hash, value.bindings.interaction_claims);
    hashWords(&hash, value.bindings.interaction_root);
    hashWords(&hash, tryCastWords(value.bindings.composition_alpha));
    hashWords(&hash, value.bindings.composition_root);
    hashPow(&hash, value.bindings.query_pow);
    return hash.finalResult();
}

fn tryCastWords(value: common.SecureFields) common.Words {
    return value.cast(u32) catch unreachable;
}

fn hashWords(hash: *std.crypto.hash.sha2.Sha256, words: common.Words) void {
    hashInt(hash, u64, words.address);
    hashInt(hash, u64, words.len);
    hashInt(hash, u64, words.owner);
    hashInt(hash, u64, words.generation);
}

fn hashPow(
    hash: *std.crypto.hash.sha2.Sha256,
    pow: transcript_controller.PowView,
) void {
    hashWords(hash, pow.prefix_digest);
    hashWords(hash, pow.best_nonce.cast(u32) catch unreachable);
    hashWords(hash, pow.completed_blocks);
    hashWords(hash, pow.transcript_nonce);
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

fn compileConcreteExecution(
    prepared: *Prepared,
    transaction: *proof_transaction.ResidentProofTransaction,
    plan: *const resident_plan.Plan,
    protocol: compact.CompactProtocolV1,
) !decommit_controller.TerminalRoute {
    return prepared.executeDevelopment(
        transaction,
        plan,
        protocol,
    );
}

test "production coordinator names every remaining root boundary" {
    try std.testing.expectEqualSlices(
        Gap,
        &.{
            .production_ingress_binding_compiler,
            .statement_bootstrap_payload_binding,
            .oracle_verification,
        },
        &gaps,
    );
    try std.testing.expectError(
        error.MissingProductionIngressBindingCompiler,
        requireProductionReady(),
    );
    _ = &compileConcreteExecution;
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
