//! Actual PCS-root checks, not complete RISC-V execution proof acceptance.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const G = @import("global_manifest.zig");
const Stage = @import("staged_precommit.zig");
const a = std.testing.allocator;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;

const Anchors = G.ExecutionAnchors{
    .initial_pc = 4096,
    .initial_registers = @splat(1),
    .terminal_pc = 4104,
    .terminal_registers = @splat(3),
    .total_steps = 10,
};
fn context() G.Context {
    return .{ .scope = .full_execution_unqualified, .execution = @splat(1), .program = @splat(2), .image = @splat(3), .policy = @splat(4), .opcode_map = @splat(5), .total_steps = 10 };
}
fn inventory() [4]G.Spec {
    var result: [4]G.Spec = undefined;
    for (&result, 0..) |*entry, i| {
        const epoch: u16 = @intCast(if (i == 3) 2 else i);
        const pc: u64 = if (i < 2) 4096 else if (i == 2) 4100 else 4104;
        const finish: u64 = if (i == 0) 4096 else if (i == 1) 4100 else 4104;
        const before: u8 = if (i < 2) 1 else if (i == 2) 2 else 3;
        const after: u8 = if (i == 0) 1 else if (i == 1) 2 else 3;
        entry.* = .{
            .ordinal = @intCast(i),
            .role = if (i == 0) .initial else if (i == 3) .terminal else .execution,
            .coverage = .{ .first_step = if (i < 2) 0 else if (i == 2) 5 else 10, .steps = if (i == 1 or i == 2) 5 else 0, .epoch = epoch, .initial_pc = pc, .final_pc = finish, .initial_registers = @splat(before), .final_registers = @splat(after) },
            .schema = @splat(0x17),
            .statement = @splat(0x18),
            .fixed = .{ .bytes = @splat(0) },
            .fixed_logs = &.{5},
            .main_logs = &.{5},
            .positive_mass = .{ 1, 2, 3 },
        };
    }
    return result;
}
test "staged global RAM precommit seals real PCS fixed and main roots before challenge selection" {
    var specs = inventory();
    var fixed: [32]M = @splat(M.zero());
    fixed[0] = M.one();
    const fixed_columns = [_]Col{.{ .log_size = 5, .values = &fixed }};
    var main: [4][32]M = undefined;
    var schemes: [4]G.Scheme = undefined;
    var made: usize = 0;
    defer for (schemes[0..made]) |*scheme| scheme.deinit(a);
    var receipts: [4]G.Receipt = undefined;
    for (0..4) |i| {
        for (&main[i], 0..) |*value, j| value.* = M.fromCanonical(@intCast(1 + i + j));
        schemes[i] = try G.Scheme.init(a, G.P.config());
        made += 1;
        var ch = G.P.Channel{};
        try schemes[i].commitBorrowedStreaming(a, &fixed_columns, 2, &ch);
        const main_columns = [_]Col{.{ .log_size = 5, .values = &main[i] }};
        try schemes[i].commitBorrowedStreaming(a, &main_columns, 2, &ch);
        var roots = try schemes[i].roots(a);
        defer roots.deinit(a);
        try std.testing.expectEqual(@as(usize, 2), roots.items.len);
        specs[i].fixed.bytes = roots.items[0];
        receipts[i] = try G.fromCommitted(a, &schemes[i], specs[i]);
    }
    const expected = G.Expected{ .context = context(), .specs = &specs };
    var plan = try Stage.Plan.init(a, expected, Anchors, &receipts);
    defer plan.deinit();
    try plan.check();
    const owners = [_]*G.Scheme{ &schemes[0], &schemes[1], &schemes[2], &schemes[3] };
    try std.testing.expectError(error.IncompleteStagedPhysicalPrecommit, plan.diagnosticChallenges(a, owners[0..3]));
    try plan.verifyStage1(a, 0, &schemes[0]);
    try std.testing.expectError(error.IncompleteStagedPhysicalPrecommit, plan.diagnosticChallenges(a, owners[0..3]));
    const challenges = try plan.diagnosticChallenges(a, &owners);
    try std.testing.expect(!challenges.ram.offset.eql(challenges.owner.offset));

    // The plan owns a deep snapshot. A caller cannot mutate live commitments
    // after sealing by changing its original borrow.
    specs[1].schema[0] ^= 1;
    try plan.check();
    specs[1].schema[0] ^= 1;
    const original_root = plan.receipts[1].main.bytes;
    plan.receipts[1].main.bytes[0] ^= 1;
    try std.testing.expectError(error.StagedGlobalPrecommitChanged, plan.check());
    plan.receipts[1].main.bytes = original_root;
    try plan.check();

    var forged = receipts;
    forged[2].main.bytes[0] ^= 1;
    var candidate = try Stage.Plan.init(a, expected, Anchors, &forged);
    defer candidate.deinit();
    try std.testing.expectError(error.StagedGlobalStage1RootMismatch, candidate.verifyStage1(a, 2, &schemes[2]));
    try std.testing.expectError(error.StagedGlobalStage1RootMismatch, candidate.diagnosticChallenges(a, &owners));
    try std.testing.expectError(error.IncompleteStagedGlobalPrecommit, Stage.Plan.init(a, expected, Anchors, receipts[0..3]));
    var other = Anchors;
    other.terminal_pc ^= 4;
    try std.testing.expectError(error.InvalidStagedGlobalTerminal, Stage.Plan.init(a, expected, other, &receipts));
}
