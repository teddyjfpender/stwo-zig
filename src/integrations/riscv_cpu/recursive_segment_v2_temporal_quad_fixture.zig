//! Four-leaf real SegmentV2 fixture used by the multi-level recursion gate.
//! Keeping this transaction separate prevents the single-leaf proof authority
//! from becoming a second integration facade.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
const subject = integration.recursive_segment_v2_leaf_outer;
const runner = frontend.runner;
const recursion = frontend.recursion;
const span = recursion.span_statement;
const protocol = recursion.protocol;

/// Four adjacent independently verified SegmentV2 leaves. Every leaf crosses
/// prove/serialize/preflight/decode/fresh-verify custody before the hook can
/// observe the fixed array.
pub fn runTemporalQuadGateWithHook(
    allocator: std.mem.Allocator,
    comptime Hook: type,
) !void {
    comptime {
        if (!@hasDecl(Hook, "run"))
            @compileError("temporal V2 quad hook must declare run");
        @import("stwo_prover_api").assertProverEngine(subject.Engine);
    }

    const elf = frontend.testing.guest_precompile_test_elf.buildTemporalQuad();
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var profile0 = try session.startSegment(1);
    defer profile0.deinit();
    var profile1 = try session.resumeSegment(profile0.base.continuation.?, 1);
    defer profile1.deinit();
    var profile2 = try session.resumeSegment(profile1.base.continuation.?, 1);
    defer profile2.deinit();
    var profile3 = try session.resumeSegment(profile2.base.continuation.?, 16);
    defer profile3.deinit();
    const results = [4]*const runner.SegmentResult{
        &profile0.base,
        &profile1.base,
        &profile2.base,
        &profile3.base,
    };

    var declared_program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        results[0].execution_trace.rows.items,
        results[0].rw_memory.program_words,
        null,
    );
    defer declared_program.deinit(allocator);
    const public_input = ingress.digest("recursive-v2-quad-input");
    const public_output = ingress.digest("recursive-v2-quad-output");
    const states = [5]span.MachineState{
        try ingress.machineState(
            results[0].entry_cpu,
            ingress.digest("recursive-v2-quad-rw-entry"),
            ingress.digest("recursive-v2-quad-io-entry"),
        ),
        try ingress.machineState(
            results[0].exit_cpu,
            ingress.digest("recursive-v2-quad-rw-1"),
            ingress.digest("recursive-v2-quad-io-1"),
        ),
        try ingress.machineState(
            results[1].exit_cpu,
            ingress.digest("recursive-v2-quad-rw-2"),
            ingress.digest("recursive-v2-quad-io-2"),
        ),
        try ingress.machineState(
            results[2].exit_cpu,
            ingress.digest("recursive-v2-quad-rw-3"),
            ingress.digest("recursive-v2-quad-io-3"),
        ),
        try ingress.machineState(
            results[3].exit_cpu,
            ingress.digest("recursive-v2-quad-rw-exit"),
            ingress.digest("recursive-v2-quad-io-exit"),
        ),
    };
    const entry_states = [3]span.MachineState{
        try ingress.machineState(
            results[1].entry_cpu,
            ingress.digest("recursive-v2-quad-rw-1"),
            ingress.digest("recursive-v2-quad-io-1"),
        ),
        try ingress.machineState(
            results[2].entry_cpu,
            ingress.digest("recursive-v2-quad-rw-2"),
            ingress.digest("recursive-v2-quad-io-2"),
        ),
        try ingress.machineState(
            results[3].entry_cpu,
            ingress.digest("recursive-v2-quad-rw-3"),
            ingress.digest("recursive-v2-quad-io-3"),
        ),
    };
    for (entry_states, states[1..4]) |entry, previous_exit|
        if (!std.meta.eql(entry, previous_exit))
            return error.InvalidTemporalBoundary;

    var total_cycles: u64 = 0;
    for (results) |result|
        total_cycles = try std.math.add(
            u64,
            total_cycles,
            @intCast(result.cycle_count),
        );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            ingress.scalarDigest(declared_program.tree.root),
            states[0],
            states[4],
            public_input,
            public_output,
            total_cycles,
        ),
        4,
    );
    const statements = [4]span.SpanStatement{
        try ingress.leafStatement(
            job,
            results[0],
            states[0],
            states[1],
            try span.EdgeClaim.present(public_input),
            span.EdgeClaim.absent(),
        ),
        try ingress.leafStatement(
            job,
            results[1],
            states[1],
            states[2],
            span.EdgeClaim.absent(),
            span.EdgeClaim.absent(),
        ),
        try ingress.leafStatement(
            job,
            results[2],
            states[2],
            states[3],
            span.EdgeClaim.absent(),
            span.EdgeClaim.absent(),
        ),
        try ingress.leafStatement(
            job,
            results[3],
            states[3],
            states[4],
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(public_output),
        ),
    };
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        ingress.digest("recursive-v2-segment-vk"),
        ingress.digest("recursive-v2-parent-vk"),
    );

    var prepared: [4]subject.PreparedNativeV2LeafOuter = undefined;
    var prepared_count: usize = 0;
    defer for (prepared[0..prepared_count]) |*leaf| leaf.deinit();
    for (&prepared, results, statements) |*destination, result, statement| {
        destination.* = try ingress.prepareTemporalNativeLeaf(
            allocator,
            result,
            statement,
            keys,
        );
        prepared_count += 1;
    }
    for (prepared, 0..) |left, left_index|
        for (prepared[left_index + 1 ..]) |right|
            if (std.mem.eql(u8, &left.identity, &right.identity))
                return error.DuplicateTemporalLeaf;
    try Hook.run(allocator, &prepared);
}
