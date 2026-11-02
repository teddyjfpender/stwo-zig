//! Admission must reject malformed public geometry before indexing or allocation.
const std = @import("std");
const S = @import("../statement.zig");
const T = @import("../trace.zig");
const W = @import("../witness.zig");
const P = @import("../projection.zig");
const E = @import("../evaluation.zig");
const relation = @import("../relations.zig");
const program = [_]u32{0x00100093};
fn valid() S.Statement {
    const initial: [32]u64 = @splat(0);
    var final = initial;
    final[1] = 1;
    return .{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = 0x100001004, .initial_registers = initial, .final_registers = final, .memory = &.{}, .steps = 1 };
}
test "rv64 AIR: public bounds and malformed metadata reject before trace construction" {
    const a = std.testing.allocator;
    var witness = try W.Witness.build(a, valid());
    defer witness.deinit();
    for ([_]u32{ 0, S.MAX_STEPS + 1 }) |steps| {
        var statement = valid();
        statement.steps = steps;
        try std.testing.expectError(error.InvalidRv64StatementSize, T.Trace.init(a, statement, witness.metadata, null));
    }
    for ([_]usize{ 0, 31, 33, 512 }) |size| try std.testing.expectError(error.InvalidRv64ProjectionGeometry, P.Projection.init(a, valid(), witness.metadata, size));
    var metadata = witness.metadata;
    metadata.path = &.{};
    try std.testing.expectError(error.InvalidRv64Metadata, T.Trace.init(a, valid(), metadata, null));
    metadata = witness.metadata;
    metadata.register_clocks[1] = 5;
    try std.testing.expectError(error.InvalidRv64Clock, T.Trace.init(a, valid(), metadata, null));
    metadata = witness.metadata;
    metadata.register_clocks[0] = 1;
    try std.testing.expectError(error.InvalidRv64Metadata, T.Trace.init(a, valid(), metadata, null));
    var statement = valid();
    statement.final_registers[0] = 1;
    try std.testing.expectError(error.InvalidRv64ZeroRegister, statement.validate());
    const cell = S.Cell{ .address = 0x200004000, .initial = 1, .final = 1 };
    const duplicate = [_]S.Cell{ cell, cell };
    statement = valid();
    statement.memory = &duplicate;
    try std.testing.expectError(error.InvalidRv64CellOrder, statement.validate());
    var readonly = [_]S.Cell{cell};
    readonly[0].writable = false;
    readonly[0].final = 2;
    statement.memory = &readonly;
    try std.testing.expectError(error.InvalidRv64ReadOnlyFinal, statement.validate());
}

test "rv64 AIR: zero denominator failure leaves interaction unpublished and permits retry" {
    const a = std.testing.allocator;
    var witness = try W.Witness.build(a, valid());
    defer witness.deinit();
    var trace = try T.Trace.init(a, valid(), witness.metadata, witness.rows);
    defer trace.deinit();
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(.{ .offset = E.Q.zero(), .coefficients = @splat(E.Q.zero()) }));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    // This is caller-directed trace phase testing, not transcript challenge
    // resampling. The production prover never redraws after a failure.
    var channel = @import("../protocol.zig").Channel{};
    const challenges = relation.Challenges.draw(&channel);
    try std.testing.expect((try trace.generateInteraction(challenges)).eql(try relation.expected(valid(), witness.metadata, challenges)));
    try std.testing.expectError(error.InvalidRv64TracePhase, trace.generateInteraction(challenges));
}
