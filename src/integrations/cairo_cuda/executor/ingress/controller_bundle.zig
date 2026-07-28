//! Concrete ingress preparation for one resident Cairo CUDA proof.
//!
//! This module owns the host-side controller closure and its device bindings.
//! It deliberately does not invent writer or relation sources: those are
//! supplied by the semantic ingress compiler after it has mapped the adapted
//! input into authenticated resident views.

const std = @import("std");
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const request_compiler = @import("../../request_compiler.zig");
const eval_controller = @import("../eval/controller.zig");
const decommit_controller = @import("../pcs_decommit_controller.zig");
const fri_controller = @import("../pcs_fri_controller.zig");
const hooks = @import("../pcs_hooks.zig");
const oods_controller = @import("../pcs_oods_controller.zig");
const quotient_controller = @import("../quotient/controller.zig");
const resident_session = @import("../resident_session.zig");
const statement_ingress = @import("../statement_ingress.zig");
const trace_commit = @import("../trace_commit.zig");
const trace_writer = @import("../trace_writer_controller.zig");
const proof_session = @import("../proof_session.zig");
const preprocessed_cache = @import("../preprocessed_cache.zig");
const proof_capture = @import("stwo_native_cuda_integration").common.proof_assembly;
const resident_plan = @import("../resident_plan.zig");
const transcript_controller = @import("../transcript/controller.zig");
const transcript_schedule = @import("../transcript/schedule.zig");

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    resident: resident_session.Prepared,
    preprocessed_commit: trace_commit.Prepared,
    main_commit: trace_commit.Prepared,
    interaction_commit: trace_commit.Prepared,
    composition_commit: trace_commit.Prepared,
    evaluation: eval_controller.Prepared,
    transcript: transcript_schedule.Schedule,

    pub fn init(
        allocator: std.mem.Allocator,
        request: *const request_compiler.PreparedRequest,
        protocol: compact.CompactProtocolV1,
        bundle: composition.Bundle,
        preprocessed_logs: []const u32,
    ) !Prepared {
        if (request.missing_lowerings.len != 0)
            return error.IncompleteCairoCudaLowering;
        var resident = try resident_session.Prepared.init(
            allocator,
            request.resident,
            request.trace_dispatch,
        );
        errdefer resident.deinit();
        var preprocessed_commit = try trace_commit.Prepared.initProduced(
            allocator,
            request.proof_program,
            request.resident,
            .preprocessed,
        );
        errdefer preprocessed_commit.deinit();
        var main_commit = try trace_commit.Prepared.initMain(
            allocator,
            request.proof_program,
            request.resident,
            request.trace_dispatch,
        );
        errdefer main_commit.deinit();
        var interaction_commit = try trace_commit.Prepared.initProduced(
            allocator,
            request.proof_program,
            request.resident,
            .interaction,
        );
        errdefer interaction_commit.deinit();
        var composition_commit = try trace_commit.Prepared.initProduced(
            allocator,
            request.proof_program,
            request.resident,
            .composition,
        );
        errdefer composition_commit.deinit();
        var evaluation = try eval_controller.Prepared.init(
            allocator,
            &request.resident,
            &resident.combined_arena,
            request.proof_program,
            bundle,
            preprocessed_logs,
        );
        errdefer evaluation.deinit();
        return .{
            .allocator = allocator,
            .resident = resident,
            .preprocessed_commit = preprocessed_commit,
            .main_commit = main_commit,
            .interaction_commit = interaction_commit,
            .composition_commit = composition_commit,
            .evaluation = evaluation,
            .transcript = try transcript_schedule.Schedule.init(
                request.proof_program,
                protocol,
            ),
        };
    }

    pub fn deinit(self: *Prepared) void {
        self.evaluation.deinit();
        self.composition_commit.deinit();
        self.interaction_commit.deinit();
        self.main_commit.deinit();
        self.preprocessed_commit.deinit();
        self.resident.deinit();
        self.* = undefined;
    }

    /// Uploads immutable controller metadata and binds every existing PCS
    /// controller. Writer/relation source graphs remain separate because they
    /// depend on the adapted-input semantic mapper, not on PCS geometry.
    pub fn bindControllers(
        self: *Prepared,
        transaction: anytype,
        provider: anytype,
        request: *const request_compiler.PreparedRequest,
        protocol: compact.CompactProtocolV1,
        bundle: composition.Bundle,
    ) !Bound {
        const Uploader = RoutedUploader(
            @TypeOf(transaction.proofSession()),
            @TypeOf(provider),
        );
        var uploader = Uploader{
            .session = transaction.proofSession(),
            .provider = provider,
        };
        inline for (.{
            &self.preprocessed_commit,
            &self.main_commit,
            &self.interaction_commit,
            &self.composition_commit,
        }) |prepared| try prepared.uploadMetadata(&uploader);

        var preprocessed_commit = try trace_commit.Bound.init(
            self.allocator,
            &self.preprocessed_commit,
            provider,
        );
        errdefer preprocessed_commit.deinit();
        var main_commit = try trace_commit.Bound.init(
            self.allocator,
            &self.main_commit,
            provider,
        );
        errdefer main_commit.deinit();
        var interaction_commit = try trace_commit.Bound.init(
            self.allocator,
            &self.interaction_commit,
            provider,
        );
        errdefer interaction_commit.deinit();
        var composition_commit = try trace_commit.Bound.init(
            self.allocator,
            &self.composition_commit,
            provider,
        );
        errdefer composition_commit.deinit();

        const pcs = try hooks.bind(
            provider,
            &request.resident,
            request.proof_program,
            protocol,
        );
        var evaluation = try self.evaluation.uploadIngress(transaction);
        errdefer evaluation.deinit();
        var oods = try oods_controller.prepare(
            self.allocator,
            transaction.proofSession(),
            &request.resident,
            bundle,
            request.proof_program,
            protocol,
            pcs,
            self.transcript,
        );
        errdefer oods.deinit();
        var quotient = try quotient_controller.prepare(
            self.allocator,
            transaction.proofSession(),
            &request.resident,
            bundle,
            request.proof_program,
            protocol,
            pcs,
        );
        errdefer quotient.deinit();
        var fri = try fri_controller.prepare(
            self.allocator,
            transaction.proofSession(),
            &request.resident,
            request.proof_program,
            protocol,
            pcs,
            self.transcript,
        );
        errdefer fri.deinit();
        var decommit = try decommit_controller.prepare(
            self.allocator,
            transaction.proofSession(),
            &request.resident,
            request.proof_program,
            protocol,
            pcs,
            self.transcript,
        );
        errdefer decommit.deinit();
        return .{
            .preprocessed_commit = preprocessed_commit,
            .main_commit = main_commit,
            .interaction_commit = interaction_commit,
            .composition_commit = composition_commit,
            .pcs = pcs,
            .evaluation = evaluation,
            .oods = oods,
            .quotient = quotient,
            .fri = fri,
            .decommit = decommit,
        };
    }
};

pub const Bound = struct {
    preprocessed_commit: trace_commit.Bound,
    main_commit: trace_commit.Bound,
    interaction_commit: trace_commit.Bound,
    composition_commit: trace_commit.Bound,
    pcs: hooks.Bindings,
    evaluation: eval_controller.Bound,
    oods: oods_controller.Prepared,
    quotient: quotient_controller.Prepared,
    fri: fri_controller.Prepared,
    decommit: decommit_controller.Prepared,

    pub const StaticInputs = struct {
        adapted_input: []align(@alignOf(u32)) const u8,
        forward_twiddles: []const u32,
        inverse_twiddles: []const u32,
        preprocessed_path: []const u8,
        preprocessed_artifact_identity: [32]u8,
        preprocessed_column_identities: []const []const u8,
    };

    pub const StaticReceipt = struct {
        preprocessed: preprocessed_cache.Receipt,
    };

    pub fn deinit(self: *Bound) void {
        self.decommit.deinit();
        self.fri.deinit();
        self.quotient.deinit();
        self.oods.deinit();
        self.evaluation.deinit();
        self.composition_commit.deinit();
        self.interaction_commit.deinit();
        self.main_commit.deinit();
        self.preprocessed_commit.deinit();
        self.* = undefined;
    }

    /// Initializes every immutable proof/session input that is already
    /// structurally defined. The preprocessed commitment itself must be
    /// executed once on the trace-commit stream after this method returns.
    pub fn initializeStatic(
        self: *Bound,
        transaction: anytype,
        provider: anytype,
        request: *const request_compiler.PreparedRequest,
        inputs: StaticInputs,
    ) !StaticReceipt {
        const session = transaction.proofSession();
        try proof_capture.validateLayout(
            .{ .proof = request.resident.terminal_bundle },
            .{ .proof = self.pcs.proof },
        );
        try session.zeroResidentSlice(
            u32,
            .ingress,
            self.pcs.proof.terminal,
        );
        try session.context.uploadSlice(
            u32,
            self.pcs.proof.bundle,
            request.resident.terminal_bundle.static_header,
        );

        const adapted = try exactSlot(
            provider,
            &request.resident,
            .adapted_input,
            0,
        );
        if (inputs.adapted_input.len % @sizeOf(u32) != 0 or
            adapted.len != inputs.adapted_input.len / @sizeOf(u32))
        {
            return error.AdaptedInputResidentExtentMismatch;
        }
        const adapted_words = std.mem.bytesAsSlice(
            u32,
            inputs.adapted_input,
        );
        try session.context.uploadSlice(
            u32,
            adapted,
            adapted_words,
        );
        try uploadExactWords(
            session,
            provider,
            &request.resident,
            .twiddles_forward,
            inputs.forward_twiddles,
        );
        try uploadExactWords(
            session,
            provider,
            &request.resident,
            .twiddles_inverse,
            inputs.inverse_twiddles,
        );
        const preprocessed = try preprocessed_cache.load(
            request.allocator,
            session,
            inputs.preprocessed_path,
            inputs.preprocessed_artifact_identity,
            inputs.preprocessed_column_identities,
            self.preprocessed_commit.prepared,
            &self.preprocessed_commit,
        );
        try self.preprocessed_commit.materializeBaseEvaluations(
            session,
            .ingress,
        );
        return .{ .preprocessed = preprocessed };
    }

    pub fn bindStatement(
        self: *const Bound,
        allocator: std.mem.Allocator,
        uploader: anytype,
        provider: anytype,
        request: *const request_compiler.PreparedRequest,
    ) !statement_ingress.Binding {
        return statement_ingress.uploadAndBind(
            allocator,
            uploader,
            provider,
            &request.resident,
            &request.statement_bootstrap,
            try self.preprocessed_commit.root.cast(u32),
            try self.main_commit.root.cast(u32),
        );
    }

    pub fn sessionControllers(
        self: *Bound,
        writers: *const trace_writer.Prepared,
        relation: *const relation_stage.PreparedPlan,
    ) proof_session.Controllers {
        return .{
            .trace_writers = writers,
            .preprocessed_commit = &self.preprocessed_commit,
            .main_commit = &self.main_commit,
            .interaction_commit = &self.interaction_commit,
            .composition_commit = &self.composition_commit,
            .evaluation = &self.evaluation,
            .pcs_bindings = self.pcs,
            .relation = relation,
            .oods = &self.oods,
            .quotient = &self.quotient,
            .fri = &self.fri,
            .decommit = &self.decommit,
        };
    }

    pub fn transcriptBindings(
        self: *const Bound,
        statement: statement_ingress.Binding,
        relation_elements: common.SecureFields,
    ) !proof_session.TranscriptBindings {
        if (relation_elements.len != 2)
            return error.InvalidRelationChallengeBinding;
        return .{
            .view = try transcript_controller.View.bind(
                self.pcs.transcript_storage,
            ),
            .bootstrap = statement.inputs,
            .interaction_pow = powView(self.pcs.pow),
            .relation_elements = relation_elements,
            .interaction_claims = try self.pcs
                .composition.interaction_claims.cast(u32),
            .interaction_root = try self.interaction_commit.root.cast(u32),
            .composition_alpha = self.pcs.composition.alpha,
            .composition_root = try self.composition_commit.root.cast(u32),
            .query_pow = powView(self.pcs.query_pow),
        };
    }
};

fn powView(value: anytype) transcript_controller.PowView {
    return .{
        .prefix_digest = value.prefix_digest,
        .best_nonce = value.best_nonce,
        .completed_blocks = value.completed_blocks,
        .transcript_nonce = value.transcript_nonce,
    };
}

fn RoutedUploader(
    comptime Session: type,
    comptime Provider: type,
) type {
    return struct {
        session: Session,
        provider: Provider,

        pub fn upload(
            self: *@This(),
            comptime F: type,
            id: u32,
            values: []const F,
        ) !void {
            const destination = try (try self.provider.slot(id)).cast(F);
            if (destination.len != values.len)
                return error.InvalidIngressUploadExtent;
            try self.session.context.uploadSlice(F, destination, values);
        }

        pub fn uploadSlice(
            self: *@This(),
            comptime F: type,
            destination: anytype,
            values: []const F,
        ) !void {
            if (destination.len != values.len)
                return error.InvalidIngressUploadExtent;
            try self.session.context.uploadSlice(F, destination, values);
        }
    };
}

fn exactSlot(
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !common.Words {
    const descriptor = plan.slot(kind, ordinal) orelse
        return error.MissingResidentSlot;
    const value = try provider.slot(descriptor.id);
    if (value.len != descriptor.words)
        return error.InvalidIngressUploadExtent;
    return value;
}

fn uploadExactWords(
    session: anytype,
    provider: anytype,
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
    values: []const u32,
) !void {
    const destination = try exactSlot(provider, plan, kind, 0);
    if (destination.len != values.len)
        return error.InvalidIngressUploadExtent;
    try session.context.uploadSlice(u32, destination, values);
}
