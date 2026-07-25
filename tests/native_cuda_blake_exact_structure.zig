const std = @import("std");
const stwo = @import("stwo_under_test");
const exact = stwo.integrations.native_cuda.blake.exact;

test {
    std.testing.refAllDecls(exact);
}

test "exact Blake host contract seals variable-height arena and facades" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = stwo.core.pcs.PcsConfig.default(),
    });
    var prepared = try exact.arena_plan.Prepared.init(
        allocator,
        geometry,
    );
    defer prepared.deinit(allocator);
    try prepared.validate();

    var calls = Calls{};
    const ready = try (exact.facades.Set{
        .trace = facadeTrace(&calls),
        .interaction = facadeInteraction(&calls),
        .constraint = facadeConstraint(&calls),
    }).requireReady(authority());
    const invocation = exact.facades.invocation(
        geometry,
        prepared.views,
    );
    try ready.trace.generate_preprocessed(
        ready.trace.context,
        invocation,
    );
    try ready.trace.generate_main(
        ready.trace.context,
        invocation,
    );
    try ready.interaction.generate_interaction(
        ready.interaction.context,
        invocation,
    );
    try ready.constraint.evaluate_composition(
        ready.constraint.context,
        invocation,
    );

    try std.testing.expectEqual(@as(usize, 4), calls.kernel_count);
    try std.testing.expectEqual(
        exact.slots.main_evaluations,
        calls.last_main_slot,
    );
    try std.testing.expectEqual(
        exact.slots.relation_sources,
        calls.last_relation_slot,
    );
    try std.testing.expectEqual(
        @as(u32, 16),
        calls.last_max_trace_log,
    );
}

test "exact Blake route prerequisites reject missing kernel authorities" {
    var calls = Calls{};
    const trace_only = exact.facades.Set{
        .trace = facadeTrace(&calls),
    };
    try std.testing.expectError(
        error.UnavailableExactBlakeInteractionFacade,
        trace_only.requireReady(authority()),
    );
}

test "exact Blake executor exposes every Fiat-Shamir root and alpha barrier" {
    const allocator = std.testing.allocator;
    const geometry = try exact.geometry.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = stwo.core.pcs.PcsConfig.default(),
    });
    var prepared = try exact.arena_plan.Prepared.init(
        allocator,
        geometry,
    );
    defer prepared.deinit(allocator);
    var topology = try exact.topology.Plan.init(
        allocator,
        geometry,
        prepared.views,
    );
    defer topology.deinit(allocator);

    var calls = Calls{};
    var executor = exact.executor.Executor{
        .prepared = &prepared,
        .proof_topology = &topology,
        .kernels = try (exact.facades.Set{
            .trace = facadeTrace(&calls),
            .interaction = facadeInteraction(&calls),
            .constraint = facadeConstraint(&calls),
        }).requireReady(authority()),
    };
    try executor.runWith(TestOps, &calls);
    try std.testing.expectEqual(exact.executor.Phase.assembled, executor.phase);
    try std.testing.expectEqual(@as(usize, 4), calls.kernel_count);
    try std.testing.expectEqual(@as(usize, 4), calls.commit_count);
    try std.testing.expectEqual(@as(usize, 16), calls.fri_count);
    try std.testing.expectEqual(@as(u32, 17), calls.fri_logs[0]);
    try std.testing.expectEqual(@as(u32, 2), calls.fri_logs[15]);

    const schedule = exact.transcript.Schedule.init(geometry);
    try std.testing.expectEqual(
        @as(usize, schedule.operationCount()),
        calls.transcript_count,
    );
    for (calls.transcripts[0..calls.transcript_count], 0..) |
        actual,
        index,
    | {
        try std.testing.expect(std.meta.eql(
            try schedule.operation(@intCast(index)),
            actual,
        ));
    }
}

const Calls = struct {
    kernel_count: usize = 0,
    last_main_slot: exact.slots.SlotId = 0,
    last_relation_slot: exact.slots.SlotId = 0,
    last_max_trace_log: u32 = 0,
    commit_count: usize = 0,
    commits: [4]exact.geometry.Tree = undefined,
    transcript_count: usize = 0,
    transcripts: [64]exact.transcript.Operation = undefined,
    fri_count: usize = 0,
    fri_logs: [64]u32 = undefined,
    oods_count: usize = 0,
    quotient_count: usize = 0,
    pow_count: usize = 0,
    decommit_count: usize = 0,
    assembly_count: usize = 0,
};

fn callback(
    context: *anyopaque,
    invocation: exact.facades.Invocation,
) anyerror!void {
    const calls: *Calls = @ptrCast(@alignCast(context));
    try invocation.views.validate(invocation.geometry);
    calls.kernel_count += 1;
    calls.last_main_slot = invocation.main_slot;
    calls.last_relation_slot = invocation.relation_sources_slot;
    calls.last_max_trace_log = invocation.geometry.max_trace_log;
}

const TestOps = struct {
    pub fn ingress(
        _: *anyopaque,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {}

    pub fn commitTree(
        context: *anyopaque,
        tree: exact.geometry.Tree,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        if (state.commit_count == state.commits.len)
            return error.InvalidTestSequence;
        state.commits[state.commit_count] = tree;
        state.commit_count += 1;
    }

    pub fn transcriptOperation(
        context: *anyopaque,
        operation: exact.transcript.Operation,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        if (state.transcript_count == state.transcripts.len)
            return error.InvalidTestSequence;
        state.transcripts[state.transcript_count] = operation;
        state.transcript_count += 1;
    }

    pub fn oods(
        context: *anyopaque,
        _: *const exact.topology.Plan,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        state.oods_count += 1;
    }

    pub fn quotient(
        context: *anyopaque,
        _: *const exact.topology.Plan,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        state.quotient_count += 1;
    }

    pub fn friLayer(
        context: *anyopaque,
        layer: exact.topology.FriLayer,
        _: *const exact.topology.Plan,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        if (state.fri_count == state.fri_logs.len)
            return error.InvalidTestSequence;
        state.fri_logs[state.fri_count] = layer.evaluation_log;
        state.fri_count += 1;
    }

    pub fn friLast(
        _: *anyopaque,
        _: *const exact.topology.Plan,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {}

    pub fn pow(
        context: *anyopaque,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        state.pow_count += 1;
    }

    pub fn decommit(
        context: *anyopaque,
        _: *const exact.topology.Plan,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        state.decommit_count += 1;
    }

    pub fn assemble(
        context: *anyopaque,
        _: *const exact.arena_plan.Prepared,
    ) anyerror!void {
        const state: *Calls = @ptrCast(@alignCast(context));
        state.assembly_count += 1;
    }
};

fn facadeTrace(calls: *Calls) exact.facades.Trace {
    return .{
        .version = exact.facades.abi_version,
        .identity = [_]u8{0x31} ** 32,
        .context = calls,
        .generate_preprocessed = callback,
        .generate_main = callback,
    };
}

fn facadeConstraint(calls: *Calls) exact.facades.Constraint {
    return .{
        .version = exact.facades.abi_version,
        .identity = [_]u8{0x42} ** 32,
        .context = calls,
        .evaluate_composition = callback,
    };
}

fn facadeInteraction(calls: *Calls) exact.facades.Interaction {
    return .{
        .version = exact.facades.abi_version,
        .identity = [_]u8{0x37} ** 32,
        .context = calls,
        .generate_interaction = callback,
    };
}

fn authority() exact.facades.Authority {
    return .{
        .trace_identity = [_]u8{0x31} ** 32,
        .interaction_identity = [_]u8{0x37} ** 32,
        .constraint_identity = [_]u8{0x42} ** 32,
    };
}
