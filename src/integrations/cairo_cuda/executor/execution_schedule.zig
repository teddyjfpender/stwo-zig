//! Authenticated phase coalescing for one Cairo resident CUDA proof.
//!
//! Cairo's backend-neutral graph contains one node per structural operation,
//! while each resident stage controller executes a complete protocol phase.
//! This schedule accounts for every source node exactly once and prevents the
//! generic node driver from invoking a whole-phase controller repeatedly.

const std = @import("std");
const execution_plan = @import("stwo_cuda_backend").runtime.execution_plan;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const phase_count = 8;

pub const Phase = enum(u8) {
    trace_generation,
    trace_commit,
    constraint_evaluation,
    oods,
    quotient,
    fri_commit,
    pow,
    decommit,
};

pub const SourceSpan = struct {
    first: u32,
    count: u32,
};

pub const Schedule = struct {
    nodes: [phase_count]execution_plan.ScheduledNode,
    source_spans: [phase_count]SourceSpan,
    transcript_counts: [phase_count]u32,
    program_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn derive(program: proof_ir.ProofProgram) !Schedule {
        try program.validate();
        if (program.identity.frontend != .cairo)
            return error.InvalidCairoExecutionSchedule;

        var spans = [_]SourceSpan{
            .{ .first = 0, .count = 0 },
        } ** phase_count;
        var previous_phase: ?Phase = null;
        for (program.nodes, 0..) |node, index| {
            const phase = try phaseFor(node);
            const ordinal = @intFromEnum(phase);
            if (previous_phase) |previous| {
                const previous_ordinal = @intFromEnum(previous);
                if (ordinal < previous_ordinal or
                    ordinal > previous_ordinal + 1)
                {
                    return error.InvalidCairoExecutionSchedule;
                }
            } else if (ordinal != 0) {
                return error.InvalidCairoExecutionSchedule;
            }
            if (spans[ordinal].count == 0)
                spans[ordinal].first = std.math.cast(u32, index) orelse
                    return error.CairoExecutionScheduleOverflow;
            spans[ordinal].count = std.math.add(
                u32,
                spans[ordinal].count,
                1,
            ) catch return error.CairoExecutionScheduleOverflow;
            try validateDependencies(program, node, phase);
            previous_phase = phase;
        }
        for (spans) |span| {
            if (span.count == 0)
                return error.InvalidCairoExecutionSchedule;
        }

        var transcript_counts = [_]u32{0} ** phase_count;
        for (program.transcript) |barrier| {
            if (barrier.node >= program.nodes.len)
                return error.InvalidCairoExecutionSchedule;
            const phase = try phaseFor(program.nodes[barrier.node]);
            const ordinal = @intFromEnum(phase);
            transcript_counts[ordinal] = std.math.add(
                u32,
                transcript_counts[ordinal],
                1,
            ) catch return error.CairoExecutionScheduleOverflow;
        }
        try validateTranscriptPlacement(program, transcript_counts);

        const nodes = canonicalNodes();
        return .{
            .nodes = nodes,
            .source_spans = spans,
            .transcript_counts = transcript_counts,
            .program_identity = program.program_digest,
            .identity = scheduleIdentity(
                program,
                spans,
                transcript_counts,
            ),
        };
    }

    pub fn validate(
        self: Schedule,
        program: proof_ir.ProofProgram,
    ) !void {
        const expected = try derive(program);
        if (!std.meta.eql(self, expected))
            return error.CairoExecutionScheduleIdentityMismatch;
    }

    pub fn scheduledNodes(
        self: *const Schedule,
    ) []const execution_plan.ScheduledNode {
        return &self.nodes;
    }
};

fn phaseFor(node: proof_ir.Node) !Phase {
    return switch (node.stage) {
        .trace_generation => if (node.kind == .trace_generation)
            .trace_generation
        else
            error.InvalidCairoExecutionSchedule,
        .trace_commit => switch (node.kind) {
            .commitment, .pow, .constraint_evaluation => .trace_commit,
            else => error.InvalidCairoExecutionSchedule,
        },
        .constraint_evaluation => switch (node.kind) {
            .constraint_evaluation, .commitment => .constraint_evaluation,
            else => error.InvalidCairoExecutionSchedule,
        },
        .oods => if (node.kind == .oods)
            .oods
        else
            error.InvalidCairoExecutionSchedule,
        .quotient => if (node.kind == .quotient)
            .quotient
        else
            error.InvalidCairoExecutionSchedule,
        .fri_commit => if (node.kind == .fri_commit)
            .fri_commit
        else
            error.InvalidCairoExecutionSchedule,
        .pow => if (node.kind == .pow)
            .pow
        else
            error.InvalidCairoExecutionSchedule,
        .decommit => if (node.kind == .decommit)
            .decommit
        else
            error.InvalidCairoExecutionSchedule,
        .ingress, .proof_assembly => error.InvalidCairoExecutionSchedule,
    };
}

fn validateDependencies(
    program: proof_ir.ProofProgram,
    node: proof_ir.Node,
    phase: Phase,
) !void {
    const first: usize = node.dependencies.first;
    const count: usize = node.dependencies.count;
    const end = std.math.add(usize, first, count) catch
        return error.CairoExecutionScheduleOverflow;
    if (end > program.dependency_ids.len)
        return error.InvalidCairoExecutionSchedule;
    for (program.dependency_ids[first..end]) |dependency_id| {
        if (dependency_id >= program.nodes.len)
            return error.InvalidCairoExecutionSchedule;
        const dependency_phase = try phaseFor(program.nodes[dependency_id]);
        if (@intFromEnum(dependency_phase) > @intFromEnum(phase))
            return error.InvalidCairoExecutionSchedule;
    }
}

fn validateTranscriptPlacement(
    program: proof_ir.ProofProgram,
    counts: [phase_count]u32,
) !void {
    if (counts[@intFromEnum(Phase.trace_generation)] != 0 or
        counts[@intFromEnum(Phase.quotient)] != 0 or
        counts[@intFromEnum(Phase.decommit)] != 0)
    {
        return error.InvalidCairoExecutionSchedule;
    }
    var pow_count: u32 = 0;
    var queries_count: u32 = 0;
    for (program.transcript) |barrier| {
        const phase = try phaseFor(program.nodes[barrier.node]);
        switch (barrier.kind) {
            .pow => {
                if (phase != .trace_commit and phase != .pow)
                    return error.InvalidCairoExecutionSchedule;
                pow_count += 1;
            },
            .queries => {
                if (phase != .pow)
                    return error.InvalidCairoExecutionSchedule;
                queries_count += 1;
            },
            .mix, .challenge => {
                if (phase == .trace_generation or
                    phase == .quotient or
                    phase == .pow or
                    phase == .decommit)
                {
                    return error.InvalidCairoExecutionSchedule;
                }
            },
        }
    }
    if (pow_count != 2 or queries_count != 1)
        return error.InvalidCairoExecutionSchedule;
}

fn canonicalNodes() [phase_count]execution_plan.ScheduledNode {
    const phases = [_]Phase{
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const kinds = [_]proof_ir.OperationKind{
        .trace_generation,
        .commitment,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    const stages = [_]telemetry.Stage{
        .trace_generation,
        .trace_commit,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        .pow,
        .decommit,
    };
    var nodes: [phase_count]execution_plan.ScheduledNode = undefined;
    for (&nodes, phases, kinds, stages, 0..) |
        *node,
        phase,
        kind,
        stage,
        index,
    | {
        std.debug.assert(@intFromEnum(phase) == index);
        node.* = .{
            .node_id = @intCast(index),
            .kind = kind,
            .stage = stage,
            .stream_index = 0,
            .graph_region = @intCast(index),
            // Enable graphs only after every first-proof controller is
            // proven capture-safe under the unified arena.
            .graph_candidate = false,
            .dependency_count = if (index == 0) 0 else 1,
        };
    }
    return nodes;
}

fn scheduleIdentity(
    program: proof_ir.ProofProgram,
    spans: [phase_count]SourceSpan,
    transcript_counts: [phase_count]u32,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/coalesced-execution-schedule/v1\x00");
    hash.update(&program.program_digest);
    for (spans, transcript_counts, 0..) |span, barriers, phase| {
        hashInt(&hash, u8, phase);
        hashInt(&hash, u32, span.first);
        hashInt(&hash, u32, span.count);
        hashInt(&hash, u32, barriers);
    }
    for (program.nodes) |node| {
        hashInt(&hash, u32, node.id);
        hashInt(&hash, u8, @intFromEnum(node.kind));
        hashInt(&hash, u8, @intFromEnum(node.stage));
        hashInt(&hash, u8, @intFromEnum(phaseFor(node) catch unreachable));
    }
    for (program.transcript) |barrier| {
        hashInt(&hash, u32, barrier.ordinal);
        hashInt(&hash, u32, barrier.node);
        hashInt(&hash, u32, barrier.phase);
        hashInt(&hash, u8, @intFromEnum(barrier.kind));
        hashInt(&hash, u32, barrier.value_count);
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime F: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(F)]u8 = undefined;
    std.mem.writeInt(F, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
