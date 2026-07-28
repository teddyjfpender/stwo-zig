//! Resident challenge-derived State Machine statement policy.

const runtime = @import("stwo_cuda_backend").runtime.statements.state_machine;

pub const DeferredTraceMix = struct {
    pub fn mix(
        comptime _: type,
        _: anytype,
        _: anytype,
        _: anytype,
    ) !void {}
};

pub const ConstraintPrelude = struct {
    pub fn run(
        session: anytype,
        prepared: anytype,
        views: anytype,
    ) !void {
        const boundary = try prepared.transcript.boundary(3);
        var launch = try runtime.prepare(
            session,
            .{
                .transcript_state = views.transcript.state,
                .statement_words = views.statement_words,
                .input_snapshot = views.transcript.input_snapshot,
                .output_snapshot = views.transcript.output_snapshot,
                .boundary_snapshot = views.transcript.boundary_snapshot,
            },
            .{
                .expected_step = boundary.expected_step,
                .expected_chain = boundary.expected_chain,
                .next_chain = boundary.next_chain,
            },
        );
        try launch.launch(session);
    }
};
