//! Phase-checked exact Blake transaction over resident CUDA operations.

const arena_plan = @import("arena_plan.zig");
const facades = @import("facades.zig");
const geometry = @import("geometry.zig");
const topology = @import("topology.zig");
const transcript_mod = @import("transcript.zig");

pub const Phase = enum {
    prepared,
    ingress,
    preprocessed_committed,
    statement0_mixed,
    main_committed,
    relations_drawn,
    statement1_mixed,
    interaction_committed,
    composition_challenge_drawn,
    composition_committed,
    oods_sampled,
    sampled_values_mixed,
    quotient_challenge_drawn,
    quotient_built,
    fri_committed,
    pow_mixed,
    decommitted,
    assembled,
};

pub const Executor = struct {
    prepared: *const arena_plan.Prepared,
    proof_topology: *const topology.Plan,
    kernels: facades.Ready,
    phase: Phase = .prepared,

    /// `Ops` is a compile-time product policy. Runtime-selected frontend
    /// callbacks are deliberately not part of the production scheduling ABI.
    pub fn runWith(
        self: *Executor,
        comptime Ops: type,
        context: anytype,
    ) !void {
        comptime assertOperations(Ops);
        if (self.phase != .prepared) return error.InvalidExactBlakePhase;
        try self.prepared.validate();
        try self.proof_topology.validate(self.prepared.geometry);
        const invocation = facades.invocation(
            self.prepared.geometry,
            self.prepared.views,
        );

        try Ops.ingress(context, self.prepared);
        self.phase = .ingress;
        try self.kernels.trace.generate_preprocessed(
            self.kernels.trace.context,
            invocation,
        );
        try self.commit(Ops, context, .preprocessed);
        try self.applyTranscript(Ops, context, .mix_preprocessed_root);
        self.phase = .preprocessed_committed;

        try self.applyTranscript(Ops, context, .mix_statement0);
        self.phase = .statement0_mixed;
        try self.kernels.trace.generate_main(
            self.kernels.trace.context,
            invocation,
        );
        try self.commit(Ops, context, .main);
        try self.applyTranscript(Ops, context, .mix_main_root);
        self.phase = .main_committed;

        try self.applyTranscript(Ops, context, .draw_relation_elements);
        self.phase = .relations_drawn;
        try self.kernels.constraint.generate_interaction(
            self.kernels.constraint.context,
            invocation,
        );
        try self.applyTranscript(Ops, context, .mix_statement1_claims);
        self.phase = .statement1_mixed;
        try self.commit(Ops, context, .interaction);
        try self.applyTranscript(Ops, context, .mix_interaction_root);
        self.phase = .interaction_committed;

        try self.applyTranscript(Ops, context, .draw_composition_coefficient);
        self.phase = .composition_challenge_drawn;
        try self.kernels.constraint.evaluate_composition(
            self.kernels.constraint.context,
            invocation,
        );
        try self.commit(Ops, context, .composition);
        try self.applyTranscript(Ops, context, .mix_composition_root);
        self.phase = .composition_committed;

        try self.applyTranscript(Ops, context, .draw_oods_point);
        try Ops.oods(
            context,
            self.proof_topology,
            self.prepared,
        );
        self.phase = .oods_sampled;
        try self.applyTranscript(Ops, context, .mix_sampled_values);
        self.phase = .sampled_values_mixed;
        try self.applyTranscript(Ops, context, .draw_quotient_coefficient);
        self.phase = .quotient_challenge_drawn;
        try Ops.quotient(
            context,
            self.proof_topology,
            self.prepared,
        );
        self.phase = .quotient_built;
        for (self.proof_topology.fri_layers) |layer| {
            try Ops.friLayer(
                context,
                layer,
                self.proof_topology,
                self.prepared,
            );
            try self.applyTranscript(Ops, context, .{
                .mix_fri_root = layer.index,
            });
            try self.applyTranscript(Ops, context, .{
                .draw_fri_alpha = layer.index,
            });
        }
        try Ops.friLast(
            context,
            self.proof_topology,
            self.prepared,
        );
        try self.applyTranscript(Ops, context, .mix_last_layer);
        self.phase = .fri_committed;
        try Ops.pow(context, self.prepared);
        try self.applyTranscript(Ops, context, .grind_and_mix_pow);
        self.phase = .pow_mixed;
        try self.applyTranscript(Ops, context, .draw_queries);
        try Ops.decommit(
            context,
            self.proof_topology,
            self.prepared,
        );
        self.phase = .decommitted;
        try Ops.assemble(context, self.prepared);
        self.phase = .assembled;
    }

    fn commit(
        self: *Executor,
        comptime Ops: type,
        context: anytype,
        tree: geometry.Tree,
    ) !void {
        try Ops.commitTree(context, tree, self.prepared);
    }

    fn applyTranscript(
        self: *Executor,
        comptime Ops: type,
        context: anytype,
        operation: transcript_mod.Operation,
    ) !void {
        _ = self;
        try Ops.transcriptOperation(context, operation);
    }
};

fn assertOperations(comptime Ops: type) void {
    inline for (&.{
        "ingress",
        "commitTree",
        "transcriptOperation",
        "oods",
        "quotient",
        "friLayer",
        "friLast",
        "pow",
        "decommit",
        "assemble",
    }) |name| {
        if (!@hasDecl(Ops, name))
            @compileError("exact Blake executor policy requires " ++ name);
    }
}
