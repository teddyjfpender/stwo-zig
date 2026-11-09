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
    const CpuComponents = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
    try std.testing.expectError(error.UnqualifiedOpProtocol, CpuComponents.Plan.init(a, &setup));
    var op_plan = try CpuComponents.Plan.initForOp(a, &setup);
    defer op_plan.deinit();
    const local_instances = try @import("../../word16_global_execution/services/gkr_local/roster.zig").fromOpSetup(a, &setup);
    defer a.free(local_instances);
    try std.testing.expect(local_instances[local_instances.len - 1].origin == .tower);
    try std.testing.expectEqual(setup.towerOffset(1), local_instances[local_instances.len - 1].main_offset);
    try std.testing.expectEqual(op_plan.binding_count, local_instances.len);
    const span = Types.OpTowerSpan{ .calls = 1, .first_id = 1 };
    const retention = try @import("../../word16_global_execution/services/gkr_local/retention_plan.zig").forOpCpuWithSourceStorage(a, &setup, request, span, .{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } }, 1 << 30, 1 << 30, true);
    try std.testing.expect(retention.global_metadata_bytes >= @sizeOf(A.crypto.secp256k1.word16_bridge.types.TowerCall));
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
    const core = @import("stwo_core");
    const M = core.fields.m31.M31;
    const O = core.fields.om31.OM31;
    const GL = @import("../../word16_global_execution/services/gkr_local/inputs.zig");
    const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
    const Authority = @import("../../word16_global_execution/services/gkr_local/source_authority.zig");
    const Projection = @import("../../word16_global_execution/services/gkr_local/op_tower_projection.zig");
    const Metadata = @import("../../word16_global_execution/services/gkr_local/native_provider.zig");
    const GlobalMetadata = @import("../../word16_global_execution/services/gkr_local/global_metadata.zig");
    const Classic = @import("../../word16_global_execution/services/gkr_local/classic_witness.zig");
    const Manifest = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
    var channel = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig").Channel{ .inner = .{} };
    const challenges = @import("../../word16_global_execution/services/gkr_local/challenges.zig").For(O).drawForInstances(&channel, local_instances);
    const sink_adapter = struct {
        target: *GL.RowSink,
        pub fn emit(self: *@This(), relation: @import("../../word16_global_execution/services/gkr_local/fractions.zig").Relation, tuple: anytype, weight: M) void {
            self.target.emitBase(relation, tuple, weight);
        }
    };
    const instance = local_instances[local_instances.len - 1];
    try std.testing.expectEqual([_]u32{ 5, 0 }, Frame.originWords(instance.origin));
    try std.testing.expectEqual([_]u32{ 1, 7 }, Frame.originWords(.{ .bridge = .bn254_fp2_mul }));
    const authority = Authority.Descriptor{ .origin = .{ .tower = {} } };
    try std.testing.expectEqual(Projection.LOCAL_TERMS, try authority.terms());
    const shared = Manifest.drawShared(@splat(0x5c));
    try std.testing.expectError(error.InvalidWideCpuClaims, CpuComponents.Set.initForOpChecked(a, &setup, request, [_]u32{1} ** Types.FAMILIES, span, &op_plan, .{ .artifact = undefined, .challenges = undefined, .eta = undefined }, shared, &.{}));
    var shape_probe = @import("../../word16_global_execution/services/gkr_local/op_tower_role.zig").Component{ .data = undefined, .span = .{ .calls = 1, .first_id = 1 }, .offsets = .{ setup.towerOffset(0), setup.towerOffset(1) }, .inter_offset = 0, .shared = shared, .claims = .zero() };
    _ = shape_probe.asVerifierComponent();
    _ = shape_probe.asProverComponent();

    const global_provider = GlobalMetadata.Provider{ .source = &source, .origin = .{ .tower = {} }, .log_size = 5, .shared = shared };
    for (0..32) |row_index| {
        var native_n: [Projection.LOCAL_TERMS]M = undefined;
        var native_d: [Projection.LOCAL_TERMS]O = undefined;
        var point_n: [Projection.LOCAL_TERMS]M = undefined;
        var point_d: [Projection.LOCAL_TERMS]O = undefined;
        var native_sink = GL.RowSink{ .challenges = &challenges, .numerator = &native_n, .denominator = &native_d };
        try (Metadata.Provider{ .source = &source }).emit(instance, row_index, &native_sink);
        const packet_call = if (row_index < 20) source.tower.?.calls[0] else null;
        const row = A.crypto.secp256k1.word16_bridge.source.nativeTowerRow(packet_call, row_index % 20, 1 + @as(u32, @intCast(row_index / 20)));
        var fixed: [8]M = undefined;
        const physical = A.memory.closed_ram.trace.physical(row_index, 5);
        for (&fixed, 0..) |*field, col| field.* = source.tower.?.fixed[col * 32 + physical];
        var point_sink = GL.RowSink{ .challenges = &challenges, .numerator = &point_n, .denominator = &point_d };
        var adapter = sink_adapter{ .target = &point_sink };
        const previous: [134]M = @splat(M.zero());
        const public_values: [Authority.Public.count]M = @splat(M.zero());
        try authority.emit(M, &fixed, &row, &previous, &public_values, &adapter);
        try std.testing.expect(!native_sink.invalid and !point_sink.invalid);
        try std.testing.expectEqual(Projection.LOCAL_TERMS, native_sink.count);
        try std.testing.expectEqualSlices(M, &native_n, &point_n);
        try std.testing.expectEqualSlices(O, &native_d, &point_d);
        var denominators: [5]O = undefined;
        var numerators: [5]Classic.Numerator = undefined;
        try global_provider.fill(row_index, &denominators, &numerators);
    }
}

test "absent OP block preserves pinned legacy JSON and origin words" {
    const Types = @import("../../word16_global_execution/services/types.zig");
    const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
    const old = try std.json.Stringify.valueAlloc(a, Types.Logs{}, .{});
    defer a.free(old);
    try std.testing.expectEqualStrings("{\"keccak\":null,\"add\":null,\"double\":null}", old);
    const legacy = try std.json.Stringify.valueAlloc(a, Types.Logs{ .keccak = 5, .sha256 = 8 }, .{});
    defer a.free(legacy);
    try std.testing.expectEqualStrings("{\"keccak\":5,\"add\":null,\"double\":null,\"sha256\":8}", legacy);
    try std.testing.expectEqual([_]u32{ 0, 0 }, Frame.originWords(.{ .core = .cpu }));
    try std.testing.expectEqual([_]u32{ 1, 7 }, Frame.originWords(.{ .bridge = .bn254_fp2_mul }));
    try std.testing.expectEqual([_]u32{ 2, 0 }, Frame.originWords(.{ .bulk = .desc }));
    try std.testing.expectEqual([_]u32{ 3, 1 }, Frame.originWords(.{ .dword = 1 }));
    try std.testing.expectEqual([_]u32{ 4, 0 }, Frame.originWords(.{ .sponge = .call }));
}
