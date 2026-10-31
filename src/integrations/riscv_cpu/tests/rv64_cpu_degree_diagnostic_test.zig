const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const D = @import("../rv64_cpu_degree_diagnostic.zig");
const a = std.testing.allocator;
test "full D3 cyclic Ethereum CPU all admitted opcodes must obey declared degree four" {
    const profile = rv.execution_profile.Profile.ethereum_services_v2;
    var opcodes: [65]air.evaluation.O = undefined;
    var n: usize = 0;
    for (0..65) |i| {
        const op: air.evaluation.O = @enumFromInt(i);
        if (!rv.execution_profile.admitted(profile, op)) continue;
        opcodes[n] = op;
        n += 1;
    }
    try checkOpcodes(opcodes[0..n], 0x4453435945544832, .bytes_v1);
    try checkOpcodes(opcodes[0..n], 0x4453435945544832, .limbs24_v2);
}
// Actual immutable ROM union from the freshly verified batches0..46, ELF
// 31c55e23d722b251168ba225edfdcfd0f15e5d44ee805aa16e05eb7f1b87a8dc.
test "actual frozen Ethereum 52-op D3 cyclic CPU must obey degree four" {
    const indices = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 52, 54, 56, 59, 62, 63 };
    var opcodes: [indices.len]air.evaluation.O = undefined;
    for (&opcodes, indices) |*op, index| op.* = @enumFromInt(index);
    try checkOpcodes(&opcodes, 0x5245414c35324f50, .bytes_v1);
    try checkOpcodes(&opcodes, 0x5245414c35324f50, .limbs24_v2);
}
fn checkOpcodes(opcodes: []const air.evaluation.O, seed: u64, control: air.control_policy.Policy) !void {
    const profile = rv.execution_profile.Profile.ethereum_services_v2;
    var plan = try air.encoding.Plan.fromOpcodesWithProfiles(opcodes, .division_multiplication_services_v3, profile);
    plan.state_policy = .cyclic_v2;
    plan.control_policy = control;
    var channel = air.protocol.Channel{};
    const challenges = air.full.component.Challenges{ .state = air.state_cyclic.draw(&channel), .rom = air.program.provider.Challenges.draw(&channel), .bytes = channel.drawSecureFelt(), .bitwise = air.providers.tables.Challenges.draw(&channel), .shifts = air.providers.tables.Challenges.draw(&channel) };
    const zero = air.evaluation.Q.zero();
    const component = try air.full.component.Component.initWithEthereum(22, &plan, .{ .steps = (1 << 22) - 1, .initial_pc = 4096, .final_pc = 8192 }, challenges, .{ .state = zero, .rom = zero, .bytes = zero, .bitwise = zero, .shifts = zero }, .{}, .{ .challenges = air.arithmetic.division.provider.Challenges.draw(&channel), .claim = zero }, .{ .challenges = air.crypto.keccak.bridge.equations.CallChallenges.draw(&channel), .claim = zero, .calls = 7, .first_call_id = 41 }, .{ .challenges = air.arithmetic.multiplication.provider.Challenges.draw(&channel), .claim = zero }, .{ .challenges = air.crypto.secp256k1.bridge.equations.CallChallenges.draw(&channel), .claim = zero, .calls = .{ 11, 13 }, .first_ids = .{ 31, 97 }, .execution_profile = profile });
    const legacy_count: usize = if (opcodes.len == 52) 1006 else 994;
    try std.testing.expectEqual(legacy_count - @as(usize, if (control == .limbs24_v2) 60 else 0), component.constraint_count);
    var result = try D.inspect(a, &component, seed);
    defer result.deinit();
    for (result.violations) |failure| std.debug.print("D3 cyclic ETH2 degree violation constraint={d} degree>={d} fifth={any}\n", .{ failure.constraint_index, failure.observed_degree_at_least, failure.fifth_difference });
    std.debug.print("D3 cyclic ETH2 degree audit control={s} admitted={d} constraints={d} violations={d}\n", .{ @tagName(control), opcodes.len, result.constraints, result.violations.len });
    try std.testing.expectEqual(@as(usize, 0), result.violations.len);
}
