//! The new producer seam must replay every packet word through the ordinary
//! chronological RAM ledger, including the read-only tail and epoch boundary.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Prepared = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const C = @import("../../word16_global_execution/services/collector.zig");
const Tower = A.crypto.bn254_tower.execution;
const a = std.testing.allocator;
const ADDRESS: u64 = 0x8000000000000fe0;
const marker: u8 = 0;
fn initialWords() [Tower.WORDS]u64 {
    var words: [Tower.WORDS]u64 = @splat(0);
    for (0..12) |coordinate| words[4 * coordinate] = 7 + 31 * coordinate;
    words[12 * 4] = 1;
    words[18 * 4] = 1;
    words[19 * 4] = 1;
    return words;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address >= ADDRESS + Tower.PACKET_BYTES or address & 7 != 0) return error.UntrustedTowerAddress;
    return initialWords()[(address - ADDRESS) / 8];
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address >= ADDRESS + Tower.PACKET_BYTES) return error.UntrustedTowerAddress;
    return if (address < ADDRESS + Tower.WRITTEN_BYTES) 3 else 1;
}
fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn registers() [32]u64 {
    var out: [32]u64 = @splat(0);
    out[10] = ADDRESS;
    out[17] = Tower.TAG;
    return out;
}
fn boundary(index: usize) A.word16_execution.types.Boundary {
    var out = A.word16_execution.types.Boundary{ .steps = 1, .initial_pc = 4096 + 4 * index, .final_pc = 4100 + 4 * index, .initial_registers = registers(), .final_registers = registers(), .register_clocks = @splat(0) };
    out.register_clocks[10] = 1;
    out.register_clocks[17] = 2;
    return out;
}
test "OP tower collector binds all80words through readonly tail and cross-shard predecessors" {
    var program = try Program.initWithProfile(a, .{ .base = 4096, .words = &.{ 0x73, 0x73 } }, .ethereum_services_op_v1);
    defer program.deinit();
    var tapes: [2]front.rv64.compact_tape.Tape = undefined;
    var natives: [2]Prepared = undefined;
    var made: usize = 0;
    defer for (natives[0..made]) |*native| native.deinit();
    defer for (tapes[0..made]) |*tape| tape.deinit();
    var words = initialWords();
    for (0..2) |index| {
        var tape = try front.rv64.compact_tape.Tape.init(a, 1, 4096 + 4 * index, index, .ethereum_services_op_v1);
        errdefer tape.deinit();
        const after = try Tower.execute(&words);
        const call = front.rv64.ethereum_services.TowerCall{ .call_id = index + 1, .clock = index + 1, .pc = 4096 + 4 * index, .pointer = ADDRESS, .before = words, .output = after[0..Tower.WRITTEN_WORDS].* };
        try tape.appendTower(&call);
        natives[index] = try Prepared.captureForOpServices(a, &program, boundary(index), @intCast(index + 1), 5, &tape, .{});
        tapes[index] = tape;
        made += 1;
        words = after;
    }
    var advice = try C.collect(a, &.{ &natives[0], &natives[1] }, &.{ &tapes[0], &tapes[1] }, image());
    defer advice.deinit();
    try std.testing.expectEqual(@as(usize, Tower.WORDS), advice.initial.len);
    try std.testing.expectEqual(@as(usize, Tower.WORDS), advice.terminal.len);
    try std.testing.expectEqual(@as(usize, 2), advice.tower.len);
    for (0..2) |index| {
        try std.testing.expectEqual(@as(usize, 1), advice.tower[index].len);
        const call = advice.tower[index][0];
        try A.crypto.secp256k1.word16_bridge.source.validateTower(.bn254_sparse034, call);
        for (0..Tower.WORDS) |word| {
            try std.testing.expectEqual(@as(u16, @intCast(index)), call.predecessors[word].epoch);
            try std.testing.expectEqual(@as(u24, if (index == 0) 0 else 4), call.predecessors[word].tick);
            try std.testing.expectEqual(@as(u2, if (word < Tower.WRITTEN_WORDS) 3 else 1), call.predecessors[word].rights);
        }
    }
    // A consistent captured packet over bytes absent from the initial image
    // is refused before any new proof route can use its truth advice.
    tapes[0].tower_calls.items[0].before[Tower.WORDS - 1] ^= 1;
    try std.testing.expectError(error.InvalidWord16SecpPredecessor, C.collect(a, &.{ &natives[0], &natives[1] }, &.{ &tapes[0], &tapes[1] }, image()));
    tapes[0].tower_calls.items[0].before[Tower.WORDS - 1] ^= 1;
    // Existing setup/worker APIs must fail closed on the optional OP block.
    const R = @import("../../word16_global_execution/services/roster.zig");
    const Pipeline = @import("../../word16_global_execution/services/pipeline.zig");
    const Protocol = @import("../../word16_global_execution/services/protocol.zig");
    const Types = @import("../../word16_global_execution/services/types.zig");
    var geometry = try natives[0].geometry();
    geometry.initial_log = 7;
    const bridges = Types.Logs{ .tower = 5 };
    try std.testing.expectError(error.UnqualifiedOpSetup, R.CpuSetup.initProgramWithProfile(a, .{ .base = 4096, .words = &.{ 0x73, 0x73 } }, geometry, bridges, .ethereum_services_op_v1));
    var setup = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &.{ 0x73, 0x73 } }, geometry, bridges);
    defer setup.deinit();
    const request = Protocol.Request{ .calls = @splat(0), .base = .{ .cpu = natives[0].cpu.?.public, .epoch = 1, .division_requests = 0, .multiplication_requests = 0, .memory = .{ .initial = advice.initial, .terminal = &.{}, .epoch = 1, .ls_count = 0 } } };
    const expected = Protocol.Expected{ .admission = .{ .image = image(), .image_identity = @splat(0x4e), .initial_pc = 4096, .initial_registers = registers(), .max_prefix_steps = 2 }, .program_identity = setup.materials.program.identity, .total_steps = 2, .max_total_steps = 2, .final_pc = 4104, .final_registers = registers() };
    try std.testing.expectError(error.UnqualifiedOpProtocol, Protocol.admit(a, &.{&setup}, &.{}, &.{request}, expected));
    try std.testing.expectError(error.UnqualifiedOpProtocol, Pipeline.buildCpuSource(a, &setup, request, &natives[0], &advice, 0, @splat(1), false, null));
    try std.testing.expectError(error.UnqualifiedOpProtocol, @import("../../word16_global_execution/services/gkr_local/roster.zig").fromSetup(a, &setup));
    try std.testing.expectError(error.UnqualifiedOpProtocol, @import("../../word16_global_execution/services/gkr_local/service_scope.zig").profile(.ethereum_services_op_v1));
    const span = Types.OpTowerSpan{ .calls = 1, .first_id = 1 };
    const mass = try span.mass(bridges);
    try std.testing.expectEqual(@as(u64, 160), mass.ram);
    try std.testing.expectEqual(@as(u64, 32), mass.wire);
    var source = try Pipeline.buildCpuSourceForOp(a, &setup, request, span, &natives[0], &advice, 0, @splat(1), false, null);
    defer source.deinit();
    try std.testing.expect(source.tower != null);
    const headers = try source.columns(a, &setup, 1);
    defer a.free(headers);
    try std.testing.expectEqual(setup.columnCount(1), headers.len);
    const trace_headers = try source.mainTraceColumns(a, &setup);
    defer a.free(trace_headers);
    const tower_main = source.tower.?.main;
    source.tower.?.main = source.core.range16.main[0..tower_main.len];
    try std.testing.expectError(error.AliasedCombinedMain, source.takeMain(&setup));
    source.tower.?.main = tower_main;
    try std.testing.expect(source.tower.?.owns_main and source.core.cpu.main.len != 0);
    const commit = try source.takeMain(&setup);
    defer commit.deinit(a);
    try std.testing.expectEqual(setup.columnCount(1), commit.columns.len);
    try std.testing.expect(!source.tower.?.owns_main and source.tower.?.main.len == 0);
}
