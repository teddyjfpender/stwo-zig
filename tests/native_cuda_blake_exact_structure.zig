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
        .constraint = facadeConstraint(&calls),
    }).requireReady();
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
    try ready.constraint.generate_interaction(
        ready.constraint.context,
        invocation,
    );
    try ready.constraint.evaluate_composition(
        ready.constraint.context,
        invocation,
    );

    try std.testing.expectEqual(@as(usize, 4), calls.count);
    try std.testing.expectEqual(
        exact.slots.main_evaluations,
        calls.last_main_slot,
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
        error.UnavailableExactBlakeConstraintFacade,
        trace_only.requireReady(),
    );
}

const Calls = struct {
    count: usize = 0,
    last_main_slot: exact.slots.SlotId = 0,
    last_max_trace_log: u32 = 0,
};

fn callback(
    context: *anyopaque,
    invocation: exact.facades.Invocation,
) anyerror!void {
    const calls: *Calls = @ptrCast(@alignCast(context));
    try invocation.views.validate(invocation.geometry);
    calls.count += 1;
    calls.last_main_slot = invocation.main_slot;
    calls.last_max_trace_log = invocation.geometry.max_trace_log;
}

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
        .generate_interaction = callback,
        .evaluate_composition = callback,
    };
}
