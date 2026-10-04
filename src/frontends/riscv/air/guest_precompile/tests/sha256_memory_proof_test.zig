//! Canonical proof of compression plus exact public CPU/memory transitions.
//! Combined VM profile activation and recursive guest wrapping are separate.
const std = @import("std");
const f = @import("../../../recursion/air/blake3_proof_fixture.zig");
const gate = @import("../../../recursion/air/blake3_proof_gate_test_support.zig");
const memory_rows = @import("../sha256_memory_rows.zig");
const preprocessing = @import("../sha256_preprocessed.zig");
const boundary = @import("../sha256_memory_proof_boundary.zig");
const sha = @import("../sha256_compression.zig");
const combined = @import("../../../runner/guest_precompile/ethereum_sha.zig");
const Record = @import("../sha256_memory_record.zig").Record;
const F = @import("../../../recursion/air/universal_component_roster.zig").ForAirs(memory_rows.Airs ++ .{boundary}, &(memory_rows.names ++ [_][:0]const u8{"public_vm_tuples"}));
const logs = [_]u32{ 7, 6, 6, 3, 4, 6 };
const kinds = @import("../sha256_component_profile.zig").lookup_kinds;
fn trusted(a: std.mem.Allocator, statement: Record) ![]f.Column {
    const public = try boundary.rows(a, statement);
    defer a.free(public);
    var columns: std.ArrayList(f.Column) = .empty;
    errdefer {
        for (columns.items) |column| a.free(column.values);
        columns.deinit(a);
    }
    try preprocessing.append(a, 1, true, &columns);
    try f.project(boundary, a, public, logs[5], 0, &columns);
    for (kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn executeTape(a: std.mem.Allocator, statement: Record, mixed: bool) !combined.State {
    const Memory = @import("../../../runner/memory.zig").Memory;
    const Tracker = @import("../../../runner/state_chain.zig").StateChainTracker;
    const Trace = @import("../../../runner/trace.zig").Trace;
    var memory = try Memory.initFallible(a);
    defer memory.deinit();
    var tracker = Tracker.init(a);
    defer tracker.deinit();
    var trace = Trace.init(a);
    defer trace.deinit();
    try trace.bindExtractedClockRange(statement.execution_clock - 1, statement.execution_clock - 1, 0);
    var cpu = @import("../../../runner/cpu.zig").Cpu.init(statement.pc, 0x4000);
    cpu.writeReg(statement.state_register, statement.state_ptr);
    cpu.writeReg(statement.block_register, statement.block_ptr);
    tracker.reg_last_clk[statement.state_register] = statement.pointer_previous_clocks[0];
    tracker.reg_last_clk[statement.block_register] = statement.pointer_previous_clocks[1];
    var addresses: [24]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = statement.address(i);
    try memory.prepareAlignedWordWrites(&addresses);
    for (addresses, 0..) |address, i| {
        memory.writeU32AssumePrepared(address, statement.before(i));
        try tracker.mem_last_clk.put(address, statement.memory_previous_clocks[i]);
    }
    var tape = try combined.State.init(a, if (mixed) 3 else 1, 0);
    errdefer tape.deinit();
    const layout = @import("../../../runner/memory_state.zig").MemoryLayout{
        .program_base = 0x400,
        .program_end = 0x800,
        .data_base = 0x1000,
        .data_end = 0x3000,
        .stack_bottom = 0x4000,
        .stack_top = 0x5000,
        .io_base = 0x6000,
        .io_end = 0x7000,
        .input_base = 0x6000,
        .input_end = 0x6100,
        .output_len_addr = 0x6200,
        .output_data_addr = 0x6204,
        .output_base = 0x6200,
        .output_end = 0x7000,
    };
    try combined.executeWithRecordedClock(@import("../../../isa/sha256_compression_v1.zig").encode(statement.state_register, statement.block_register), statement.execution_clock, &cpu, &memory, layout, &tracker, &trace, &tape);
    try std.testing.expectEqualDeep(statement, tape.sha.entries.items[0].call);
    try std.testing.expect(tape.validateExternalCount(1));
    try std.testing.expectEqual(@as(usize, 1), trace.recordedExternalSteps());
    try std.testing.expectEqual(statement.pc + 4, cpu.pc);
    for (addresses, 0..) |address, i| try std.testing.expectEqual(statement.after(i), memory.readU32(address));
    if (mixed) {
        const keccak_word = @import("../../../isa/custom0.zig").encodeKeccakf(statement.state_register);
        // A legacy per-tape count must not authorize retirement after SHA.
        try std.testing.expectError(error.ProfileClockCountMismatch, @import("../../../runner/guest_precompile/ethereum_v1.zig").executeWithRecordedClock(.rv32im_zkvm_ethereum_v1, keccak_word, statement.execution_clock + 1, &cpu, &memory, layout, &tracker, &trace, &tape.ethereum));
        try std.testing.expectEqual(statement.pc + 4, cpu.pc);
        try std.testing.expect(tape.validateExternalCount(1));
        try std.testing.expectEqual(@as(usize, 1), trace.recordedExternalSteps());
        try combined.executeWithRecordedClock(keccak_word, statement.execution_clock + 1, &cpu, &memory, layout, &tracker, &trace, &tape);
        try std.testing.expect(tape.validateExternalCount(2));
        try std.testing.expectEqual(@as(usize, 1), tape.ethereum.keccakf_calls.len());
        try std.testing.expectEqual(@as(usize, 2), trace.recordedExternalSteps());
        const sha_word = @import("../../../isa/sha256_compression_v1.zig").encode(statement.state_register, statement.block_register);
        try combined.executeWithRecordedClock(sha_word, statement.execution_clock + 2, &cpu, &memory, layout, &tracker, &trace, &tape);
        try std.testing.expect(tape.validateExternalCount(3));
        try std.testing.expectEqual(@as(usize, 2), tape.sha.len());
        try std.testing.expectEqual(@as(usize, 3), trace.recordedExternalSteps());
        try std.testing.expectEqual(statement.pc + 12, cpu.pc);
        const last = tape.sha.entries.items[1].call;
        const access = @import("../../../access_clock.zig");
        for (last.memory_previous_clocks[0..8]) |previous| try std.testing.expectEqual(access.encode(statement.execution_clock + 1, .second), previous);
        try std.testing.expectError(error.PrecompileCallLimitExceeded, combined.executeWithRecordedClock(sha_word, statement.execution_clock + 3, &cpu, &memory, layout, &tracker, &trace, &tape));
        try std.testing.expectEqual(statement.pc + 12, cpu.pc);
        try std.testing.expect(tape.validateExternalCount(3));
        try std.testing.expectEqual(@as(usize, 3), trace.recordedExternalSteps());
    }
    return tape;
}

const Protocol = struct {
    witness: *const memory_rows.Rows,
    pub fn registerLookups(self: @This(), a: std.mem.Allocator, counters: *[kinds.len]f.Counter) !void {
        const View = struct {
            counters: *[kinds.len]f.Counter,
            pub fn get(view: *@This(), kind: f.schema.Kind) *f.Counter {
                for (kinds, 0..) |candidate, i| if (candidate == kind) return &view.counters[i];
                unreachable;
            }
        };
        var view = View{ .counters = counters };
        try @import("../sha256_lookup_registration.zig").register(a, self.witness, &view);
        const bounds = try @import("../sha256_coefficient_bounds.zig").derive(a, @intCast(self.witness.geometry.calls));
        for (kinds) |kind| try std.testing.expectEqual(f.M31.fromU64(bounds.tables[@intFromEnum(kind)]).neg(), view.get(kind).signedTotal());
    }

    pub const format_version = 2;
    pub fn drawRelations(_: @This(), a: std.mem.Allocator, channel: *f.Channel) !f.universal.UniversalRelations {
        const vm = try f.universal.UniversalRelations.draw(a, channel);
        return @import("../sha256_relations.zig").draw(a, channel, vm);
    }

    pub fn config(_: @This()) !f.core.pcs.PcsConfig {
        return @import("../../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    }
    pub fn mix(self: @This(), channel: *f.Channel) !void {
        channel.mixU32s(&.{ 0x53484d43, 1, format_version });
        (try self.config()).mixInto(channel);
        try (try @import("../sha256_component_profile.zig").Profile.canonical(1)).mixInto(channel);
    }
    pub fn admitRoot(_: @This(), _: f.Hasher.Hash) !void {}
    pub fn mixClaims(_: @This(), channel: *f.Channel, claims: []const f.QM31) !void {
        channel.mixU32s(&.{ 0x53484d43, 2, format_version });
        channel.mixFelts(claims);
    }
};
test "SHA canonical memory call STARK verifies exact CPU and memory claims" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(71 * i + 9);
    const statement = Record{ .execution_clock = 17, .pc = 1024, .state_register = 3, .block_register = 9, .state_ptr = 4096, .block_ptr = 8192, .pointer_previous_clocks = .{ 1, 2 }, .memory_previous_clocks = @splat(3), .state = sha.initial_state, .block = block, .output = sha.compress(sha.initial_state, block) };
    var tape = try executeTape(a, statement, false);
    defer tape.deinit();
    var frozen = try tape.freeze(1);
    defer frozen.deinit();
    var prepared = try memory_rows.prepare(a, frozen.sha_calls.records(), statement.execution_clock);
    defer prepared.deinit();
    const rows = prepared.tuple() ++ .{try boundary.rows(a, statement)};
    const pp = try trusted(a, statement);
    var wrong = statement;
    wrong.output[0] ^= 1;
    const false_pp = try trusted(a, wrong);
    const parameters: [F.Airs.len][0]f.M31 = @splat(.{});
    var timer = try std.time.Timer.start();
    try gate.ForBackendWithTables(f.Cpu, kinds).runForParametersProtocol(F, a, rows, logs, pp, false_pp, parameters, Protocol{ .witness = &prepared }, void);
    std.debug.print("SHA_MEMORY_STARK verified=true queries=70 pow_bits=26 elapsed_ns={d} production_vm_profile=false\n", .{timer.read()});
}

fn mixedSessionAllocationCase(a: std.mem.Allocator) !void {
    const block = [_]u8{0} ** 64;
    const statement = Record{ .execution_clock = 17, .pc = 1024, .state_register = 3, .block_register = 9, .state_ptr = 4096, .block_ptr = 8192, .pointer_previous_clocks = .{ 1, 2 }, .memory_previous_clocks = @splat(3), .state = sha.initial_state, .block = block, .output = sha.compress(sha.initial_state, block) };
    var state = try executeTape(a, statement, true);
    defer state.deinit();
    const sha_ptr = state.sha.entries.items.ptr;
    const keccak_ptr = state.ethereum.keccakf_calls.records().ptr;
    try std.testing.expectError(error.ProfileClockCountMismatch, state.freeze(2));
    try std.testing.expect(state.validateExternalCount(3));
    var frozen = try state.freeze(3);
    defer frozen.deinit();
    try std.testing.expectEqual(sha_ptr, frozen.sha_calls.records().ptr);
    try std.testing.expectEqual(keccak_ptr, frozen.keccakf_calls.records().ptr);
    try std.testing.expectEqual(@as(usize, 2), frozen.sha_calls.len());
    try std.testing.expectEqual(@as(usize, 0), state.sha.len());
    try std.testing.expectEqual(@as(usize, 0), state.budget);
}

test "SHA provider combined session interleaves SHA and Keccak under one retirement authority" {
    try mixedSessionAllocationCase(std.testing.allocator);
}

test "SHA provider combined session releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, mixedSessionAllocationCase, .{});
}
