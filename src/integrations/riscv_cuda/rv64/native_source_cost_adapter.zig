//! Typed, non-consuming Source allocation adapter. No Headers.take, GPU call,
//! RAM reconstruction, histogram or MAIN matrix is produced here.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Air = @import("stwo_riscv_frontend").rv64_air;
const Stage = CPU.rv64_device_source_stage;
const T = CPU.rv64_services_types;
const D = CPU.rv64_device_pcs;
const Tail = CPU.rv64_provider_tails;
const Memory = CPU.rv64_memory_input;
const Family = CPU.rv64_family_input;
const Cost = @import("native_source_cost.zig");
const CpuCost = @import("native_cpu_projection_cost.zig");
const Compact = @import("cpu_witness.zig");
const Bridge = @import("bridge_witness.zig");
const Bulk = @import("bulk_sponge.zig");
const K = Air.crypto.keccak.word16_bridge;
const W = Air.crypto.secp256k1.word16_bridge;
const B = Air.crypto.bulk_memory;
const S = Air.crypto.keccak_sponge;
pub const Options = struct {
    compact_ingress: bool,
    retain_ledgers: bool,
    /// Conservative cold=true is safe without a protected cache lookup. A
    /// warm plan requires a real immutable-owner pin across execution.
    cold_rom: bool = true,
    commit: Cost.Commit,
};
fn words(comptime V: type) u32 {
    if (@sizeOf(V) == 0 or @sizeOf(V) % 4 != 0) @compileError("Source ABI is not whole u32 words");
    return @intCast(@sizeOf(V) / 4);
}
fn u32size(n: usize) !u32 {
    return std.math.cast(u32, n) orelse error.SourceCostSizeOverflow;
}
fn addCount(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b);
}
fn capacity(count: u64, log: u32, strict: bool) !void {
    if (log < 5 or log > 26 or count > @as(u64, 1) << @intCast(log) or (strict and count == @as(u64, 1) << @intCast(log))) return error.InvalidSourceCostCapacity;
}
/// Compare canonical source-column logs, not sorted/multiset height masses.
/// The formatter allocation order differs from roster order for DIV and ZBB.
fn checkLogs(a: std.mem.Allocator, request: Stage.Request, shapes: []const Cost.Shape, extras: []const Cost.Extra) !void {
    const expected = try request.setup.logs(a, 1);
    defer a.free(expected);
    var logs: std.ArrayList(u32) = .empty;
    defer logs.deinit(a);
    for (shapes) |shape| try logs.appendNTimes(a, shape.log, shape.width);
    for (extras) |extra| try logs.appendNTimes(a, extra.log, extra.width);
    if (!std.mem.eql(u32, expected, logs.items)) return error.SourceCostColumnLogMismatch;
}
fn bind(a: std.mem.Allocator, request: Stage.Request, cpu: *const CpuCost.Plan) ![32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/native-source-cost/typed-request/v1\x00");
    h.update(@embedFile("native_source_cost_adapter.zig"));
    h.update(&request.scope.statement);
    h.update(&request.scope.fixed);
    h.update(&request.scope.main);
    h.update(&request.setup.materials.program.identity);
    h.update(&request.native.program_identity);
    h.update(&cpu.identity);
    var ordinal: [8]u8 = undefined;
    std.mem.writeInt(u64, &ordinal, request.ordinal, .little);
    h.update(&ordinal);
    // Scope.statement binds the independently authorized public content; these
    // small metadata views additionally pin every operational dimension. Avoid
    // copying/serializing the complete public RAM cell lists during planning.
    const metadata = try std.json.Stringify.valueAlloc(a, .{ .geometry = request.setup.materials.geometry, .bridges = request.setup.bridges, .first_ids = request.first_ids, .calls = request.request.calls, .bulk = request.request.bulk, .sponge = request.request.sponge, .ls_dword = request.request.ls_dword, .cpu = request.request.base.cpu, .memory = .{ .epoch = request.request.base.memory.epoch, .ls_count = request.request.base.memory.ls_count, .initial_count = request.request.base.memory.initial.len, .terminal_count = request.request.base.memory.terminal.len } }, .{});
    defer a.free(metadata);
    h.update(metadata);
    return h.finalResult();
}
fn bridgeStride(a: std.mem.Allocator, family: T.Family) !u32 {
    // Derive encoding stride from the production encoder, including its ABI
    // framing. Even an empty admitted family has a defined input stride. This
    // synthetic record is initialized and never admitted or sent to a device.
    const encoded = if (family == .keccak) try Bridge.encodeKeccak(a, &.{std.mem.zeroes(K.types.Call)}) else try Bridge.encodeWire(a, T.bridgeKind(family), &.{std.mem.zeroes(W.types.Call)});
    defer a.free(encoded);
    return u32size(encoded.len);
}
pub fn init(a: std.mem.Allocator, request: Stage.Request, options: Options) !Cost.Plan {
    if (request.ordinal != request.scope.ordinal or !std.mem.allEqual(u8, &request.scope.main, 0) or std.mem.allEqual(u8, &request.scope.statement, 0) or std.mem.allEqual(u8, &request.scope.fixed, 0)) return error.InvalidSourceCostScope;
    const p = request.native;
    const g = request.setup.materials.geometry;
    try g.validate();
    const program = &request.setup.materials.program;
    if (!std.mem.eql(u8, &p.program_identity, &program.identity)) return error.PreparedProgramMismatch;
    const cpu = p.cpu orelse return error.PreparedExecutionConsumed;
    const jalr = p.jalr orelse return error.PreparedExecutionConsumed;
    if (cpu.log_size != g.cpu_log or cpu.compact != g.cpu_compact_decode or cpu.compact != program.compact or cpu.epoch != request.request.base.memory.epoch or jalr.log_size != g.jalr_log or cpu.main_projection_closed or cpu.main.len != 0 or cpu.device_main.len != 0) return error.PreparedGeometryMismatch;
    if (cpu.rom_counts.len != program.size()) return error.InvalidCpuRomGeometry;
    const splits = try Tail.validate(g, p);
    const ls_counts = try g.lsCounts(request.request.base.memory.ls_count);
    if (g.omit_empty_division and p.division.len != 0) return error.OmittedDivisionRequests;
    try capacity(p.division.len, g.division_log, false);
    try capacity(p.multiplication.len, g.multiplication_log, false);
    const cpu_layout = try CpuCost.layoutFor(CPU.rv64_cpu_source.Metadata, Air.word16_execution.layout, Compact.CompactRecord, Compact.CompactSeed, D.TraceColumn, Compact.compact_chunk_rows);
    const cpu_plan = try CpuCost.init(.{ .layout = cpu_layout, .program_identity = program.identity, .program_profile = @intFromEnum(program.profile), .log = cpu.log_size, .rom_log = program.log_size, .active = cpu.metadata.len, .public_steps = cpu.public.steps, .source_compact = cpu.compact, .program_compact = program.compact, .program_fixed_retired = program.fixed_retired, .compact_ingress = options.compact_ingress, .retain_ledgers = options.retain_ledgers, .cold_rom = options.cold_rom });
    var shapes: std.ArrayList(Cost.Shape) = .empty;
    defer shapes.deinit(a);
    for (request.setup.materials.shapes()) |shape| {
        const classified: struct { role: Cost.Role, count: u64 } = switch (shape.role) {
            .cpu => .{ .role = .cpu, .count = cpu.metadata.len },
            .alu => .{ .role = .fact, .count = splits.alu.head },
            .alu_tail => .{ .role = .fact, .count = splits.alu.tail },
            .binary => .{ .role = .fact, .count = splits.binary.head },
            .binary_tail => .{ .role = .fact, .count = splits.binary.tail },
            .shift => .{ .role = .fact, .count = splits.shift.head },
            .shift_tail => .{ .role = .fact, .count = splits.shift.tail },
            .jalr => .{ .role = .fact, .count = jalr.facts.len },
            .ls => .{ .role = .memory, .count = ls_counts.head },
            .ls_tail => .{ .role = .memory, .count = ls_counts.tail },
            .initial => .{ .role = .boundary, .count = request.request.base.memory.initial.len },
            .terminal => .{ .role = .boundary, .count = request.request.base.memory.terminal.len },
            .division => .{ .role = .division, .count = p.division.len },
            .multiplication => .{ .role = .multiplication, .count = p.multiplication.len },
            .rom, .boundary, .range16, .range8, .and_table, .shift_table, .selection => .{ .role = .table, .count = 0 },
        };
        if (shape.widths[1] != 0) try capacity(classified.count, shape.log, classified.role == .boundary);
        try shapes.append(a, .{ .role = classified.role, .log = shape.log, .width = try u32size(shape.widths[1]), .count = classified.count });
    }
    // Validate stable general/D64 routing without allocating encoded events.
    if (request.ordinal >= request.advice.events.len) return error.InvalidSourceCostAdvice;
    var dwords: u64 = 0;
    var general: u64 = 0;
    for (request.advice.events[request.ordinal]) |event| {
        _ = try Air.memory.load_store_v2.native.describe(event.opcode);
        if (request.setup.bridges.ls_dword != null and Air.memory.load_store_dword.source.admits(event)) dwords = try addCount(dwords, 1) else general = try addCount(general, 1);
    }
    if (general != request.request.base.memory.ls_count or dwords != request.request.ls_dword) return error.InvalidCombinedServiceCount;
    var extras: std.ArrayList(Cost.Extra) = .empty;
    defer extras.deinit(a);
    for (0..T.FAMILIES) |index| {
        const family: T.Family = @enumFromInt(index);
        const log = request.setup.bridges.at(family) orelse {
            if (request.request.calls[index] != 0) return error.MissingSourceCostFamily;
            continue;
        };
        const count = request.request.calls[index];
        if (family == .keccak) {
            if (request.ordinal >= request.advice.keccak.len) return error.InvalidSourceCostAdvice;
            const calls = request.advice.keccak[request.ordinal];
            if (calls.len != count) return error.InvalidCombinedServiceCount;
            _ = try K.types.validateGeometry(calls.len, request.first_ids[index], log);
        } else {
            const calls = switch (family) {
                .add, .double => blk: {
                    if (request.ordinal >= request.advice.secp.len) return error.InvalidSourceCostAdvice;
                    break :blk request.advice.secp[request.ordinal][if (family == .add) 0 else 1];
                },
                .sha256 => blk: {
                    if (request.ordinal >= request.advice.sha256.len) return error.InvalidSourceCostAdvice;
                    break :blk request.advice.sha256[request.ordinal];
                },
                .arith256_mod => blk: {
                    if (request.ordinal >= request.advice.arith256_mod.len) return error.InvalidSourceCostAdvice;
                    break :blk request.advice.arith256_mod[request.ordinal];
                },
                else => blk: {
                    if (request.ordinal >= request.advice.curves.len) return error.InvalidSourceCostAdvice;
                    break :blk request.advice.curves[request.ordinal][index - T.FIRST_CURVE];
                },
            };
            if (calls.len != count) return error.InvalidCombinedServiceCount;
            _ = try W.types.validateGeometry(T.bridgeKind(family), calls.len, request.first_ids[index], log);
        }
        try extras.append(a, .{ .kind = .bridge, .log = log, .width = try u32size(T.widths(family)[1]), .count = count, .input_words_per_record = try bridgeStride(a, family) });
    }
    var bulk: ?Cost.Bulk = null;
    if (request.setup.bridges.bulk.any()) {
        if (request.ordinal >= request.advice.bulk.len) return error.InvalidSourceCostAdvice;
        const advice = request.advice.bulk[request.ordinal];
        var nw: u64 = 0;
        var scans: u64 = 0;
        for (advice.calls) |call| {
            const end = try addCount(nw, call.entries());
            if (end > advice.words.len) return error.InvalidBulkMemoryWords;
            try B.types.validateCall(call, advice.words[@intCast(nw)..@intCast(end)]);
            nw = end;
            if (call.op == .jumpdest) scans = try addCount(scans, call.bodyRows());
        }
        if (nw != advice.words.len or scans > std.math.maxInt(u32)) return error.InvalidBulkMemoryWords;
        bulk = .{ .calls = advice.calls.len, .words = advice.words.len, .scans = scans };
        for (T.bulk_kinds) |kind| if (request.setup.bridges.bulk.at(kind)) |log| {
            const count = B.source.Source.rowsFor(kind, advice.calls);
            _ = try B.types.validateGeometry(kind, count, log);
            try extras.append(a, .{ .kind = .bulk, .log = log, .width = try u32size(B.layout.main(kind)), .count = count, .input_count = if (kind == .jtab) 0 else count, .input_words_per_record = 0 });
        };
    }
    var sponge: ?Cost.Sponge = null;
    if (request.setup.bridges.sponge.any()) {
        if (request.ordinal >= request.advice.sponge.len) return error.InvalidSourceCostAdvice;
        const advice = request.advice.sponge[request.ordinal];
        var nw: u64 = 0;
        var np: u64 = 0;
        for (advice.calls) |call| {
            if (call.first_word != nw or call.first_perm != np) return error.InvalidKeccakSpongeCallOrder;
            const end = try addCount(nw, call.words());
            if (end > advice.words.len) return error.InvalidKeccakSpongeWords;
            try S.types.validateCall(call, advice.words[@intCast(nw)..@intCast(end)]);
            nw = end;
            np = try addCount(np, call.permutations());
        }
        if (nw != advice.words.len or np != advice.inputs.len or np > std.math.maxInt(u32)) return error.InvalidKeccakSpongeWords;
        sponge = .{ .calls = advice.calls.len, .words = advice.words.len, .permutations = np };
        for (T.sponge_kinds) |kind| if (request.setup.bridges.sponge.at(kind)) |log| {
            const count = if (kind == .call) advice.calls.len else np;
            _ = try S.types.validateGeometry(kind, count, log);
            try extras.append(a, .{ .kind = .sponge, .log = log, .width = try u32size(S.layout.main(kind)), .count = count, .input_words_per_record = 0 });
        };
    }
    // Canonical roster order, even though the factory executes ZBB first.
    const dword_counts = try T.dwordCounts(request.setup.bridges, request.request.ls_dword);
    for (dword_counts, 0..) |count, k| if (request.setup.bridges.dwordLog(k)) |log| try extras.append(a, .{ .kind = .dword, .log = log, .width = try u32size(T.dwordWidthsFor(g)[1]), .count = count, .input_words_per_record = 0 });
    if (request.setup.bridges.zbb) |log| {
        try Tail.weights(p.zbb.facts.len, p.zbb.weights);
        try capacity(p.zbb.facts.len, log, false);
        try extras.append(a, .{ .kind = .zbb, .log = log, .width = try u32size(T.zbbWidths()[1]), .count = p.zbb.facts.len, .input_words_per_record = 0 });
    } else if (p.zbb.facts.len != 0) return error.MissingZbbComponent;
    try checkLogs(a, request, shapes.items, extras.items);
    return Cost.init(a, .{ .binding = try bind(a, request, &cpu_plan), .cpu = cpu_plan, .layout = .{ .fact_words = words(Family.Fact), .memory_event_words = words(Memory.Event), .boundary_cell_words = words(Memory.Cell), .bulk_call_words = words(Bulk.BulkCall), .bulk_word_words = words(Bulk.Word), .sponge_call_words = words(Bulk.SpongeCall), .sponge_state_words = words(Bulk.State), .service_row_words = words(Bulk.Row) }, .rom_rows = program.size(), .multiplication_count = p.multiplication.len, .raw_multiplication_count = p.raw_counts.multiplication, .division_count = p.division.len, .shapes = shapes.items, .extras = extras.items, .bulk = bulk, .sponge = sponge, .commit = options.commit });
}

test "complete typed source cost adapter is instantiated" {
    std.mem.doNotOptimizeAway(&init);
}

test "typed source geometry plans preserve owners and match complete real layout logs" {
    const a = std.testing.allocator;
    const Setup = CPU.rv64_services_roster.CpuSetup;
    const Materials = @FieldType(Setup, "materials");
    const Prepared = std.meta.Child(@FieldType(Stage.Request, "native"));
    const Advice = std.meta.Child(@FieldType(Stage.Request, "advice"));
    const Event = Air.memory.load_store_v2.native.Event;
    const Call = K.types.Call;
    // These are allocation-geometry fixtures, not claimed valid executions or
    // proofs. Real Materials/types supply every width, ROM and optional role.
    for (0..3) |case| {
        var setup: Setup = undefined;
        setup.materials = try Materials.init(a, .{ .base = 4096, .words = &.{ 0x00000013, 0x0000006f } }, .{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true, .cpu_compact_decode = true, .omit_empty_division = case == 1, .alu_tail_log = if (case == 2) 5 else null, .ls_tail_log = if (case == 2) 5 else null });
        defer setup.materials.deinit();
        setup.bridges = .{};
        if (case == 1) setup.bridges.keccak = 5;
        var p: Prepared = .{ .allocator = a, .program_identity = setup.materials.program.identity, .cpu = null, .jalr = null, .alu = .{ .allocator = a, .facts = &.{}, .weights = &.{} }, .binary = .{ .allocator = a, .facts = &.{}, .weights = &.{} }, .shift = &.{}, .shift_weights = &.{}, .division = &.{}, .multiplication = &.{}, .zbb = .{ .allocator = a, .facts = &.{}, .weights = &.{} }, .raw_counts = std.mem.zeroes(@FieldType(Prepared, "raw_counts")), .unique_memory_words = 0 };
        var metadata = [_]CPU.rv64_cpu_source.Metadata{.{ .values = @splat(0), .clocks = @splat(0), .rom_row = 0 }};
        const rom_counts = try a.alloc(u64, setup.materials.program.size());
        defer a.free(rom_counts);
        @memset(rom_counts, 0);
        p.cpu = .{ .allocator = a, .program = &setup.materials.program, .public = std.mem.zeroes(@FieldType(CPU.rv64_cpu_source.Source, "public")), .epoch = 1, .log_size = 5, .metadata = &metadata, .compact = true, .rom_counts = rom_counts, .counts16 = &.{}, .counts8 = &.{} };
        p.cpu.?.public.steps = 1;
        const Jalr = std.meta.Child(@FieldType(Prepared, "jalr"));
        p.jalr = .{ .allocator = a, .facts = &.{}, .fixed = &.{}, .main = &.{}, .rows = 0, .log_size = 5 };
        _ = Jalr;
        const facts = try a.alloc(std.meta.Child(@FieldType(@FieldType(Prepared, "alu"), "facts")), if (case == 2) 33 else 0);
        defer a.free(facts);
        @memset(facts, std.mem.zeroes(std.meta.Child(@TypeOf(facts))));
        const weights = try a.alloc(u32, facts.len);
        defer a.free(weights);
        @memset(weights, 1);
        p.alu.facts = facts;
        p.alu.weights = weights;
        var events: [32]Event = undefined;
        @memset(&events, std.mem.zeroes(Event));
        for (&events) |*event| event.opcode = .LD;
        var event_shards = [_][]Event{events[0..if (case == 2) 32 else 0]};
        var advice: Advice = .{ .allocator = a, .events = &event_shards, .keccak = &.{}, .secp = &.{}, .sha256 = &.{}, .arith256_mod = &.{}, .curves = &.{}, .bulk = &.{}, .sponge = &.{}, .initial = &.{}, .terminal = &.{} };
        var keccak_shards = [_][]Call{&.{}};
        advice.keccak = &keccak_shards;
        var request: Stage.Request = .{ .setup = &setup, .native = &p, .advice = &advice, .ordinal = 0, .first_ids = @splat(1), .scope = .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(0), .ordinal = 0 }, .request = .{ .base = .{ .cpu = p.cpu.?.public, .division_requests = 0, .multiplication_requests = 0, .memory = .{ .initial = &.{}, .terminal = &.{}, .epoch = 1, .ls_count = if (case == 2) 32 else 0 } }, .calls = @splat(0) } };
        const plan = try init(a, request, .{ .compact_ingress = true, .retain_ledgers = true, .commit = .{ .beta = 2, .separate_coefficients = false, .exact_prefix_banks = true } });
        try std.testing.expect(p.cpu != null and p.jalr != null);
        try std.testing.expectEqual(metadata[0].rom_row, p.cpu.?.metadata[0].rom_row);
        const logs = try setup.logs(a, 1);
        defer a.free(logs);
        var words_sum: u64 = 0;
        for (logs) |log| words_sum += @as(u64, 1) << @intCast(log);
        try std.testing.expectEqual(words_sum, plan.trace.coefficient_words);
        try std.testing.expect(!plan.host_cost_known);
        request.scope.main = @splat(3);
        try std.testing.expectError(error.InvalidSourceCostScope, init(a, request, .{ .compact_ingress = true, .retain_ledgers = true, .commit = .{ .beta = 2, .separate_coefficients = false } }));
        request.scope.main = @splat(0);
        p.program_identity[0] ^= 1;
        try std.testing.expectError(error.PreparedProgramMismatch, init(a, request, .{ .compact_ingress = true, .retain_ledgers = true, .commit = .{ .beta = 2, .separate_coefficients = false } }));
    }
}
