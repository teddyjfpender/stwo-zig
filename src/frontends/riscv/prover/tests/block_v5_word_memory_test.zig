const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_v5_initial_source_test.zig");
const sources = @import("../block_v5_rw_endpoint_sources_v1.zig");
const initial = @import("../block_v5_initial_sources_v1.zig");
const registers = @import("../block_v5_register_endpoints_v1.zig");
const seal = @import("../block_v5_source_seal_v1.zig");
const memory = @import("../../air/block/memory_component.zig");
const trace = @import("../../air/block/word_memory_trace_v5.zig");
const air = @import("../../air/block/word_memory_v5.zig");
const protocol = @import("../block_v5_word_memory_protocol_v1.zig");
const artifact = @import("../block_v5_word_memory_artifact_v1.zig");
const request = @import("../block_v5_word_memory_proof_v1.zig");
const table = @import("../block_v5_range16_proof_v1.zig");
const receiver = @import("../block_v5_word_memory_receiver_v1.zig");
const Transition = @import("../../air/block/memory_transition.zig").Transition;
const H = @as(u64, 1) << 48;
const events = [_]Transition{
    .{ .space = 0, .address = 1, .clock = H + 1, .before = 7, .after = 7 },
    .{ .space = 1, .address = 0x2000, .clock = H + 2, .before = 9, .after = 10 },
    .{ .space = 1, .address = 0x2000, .clock = H + 3, .before = 10, .after = 11 },
    .{ .space = 1, .address = 0x2004, .clock = H + 4, .before = 0, .after = 1 },
    .{ .space = 1, .address = 0x6000, .clock = H + 5, .before = fixture.input_value, .after = fixture.input_value + 1 },
};
const Source = struct {
    a: std.mem.Allocator,
    claims: [2]memory.Claim,
    loads: u32 = 0,
    fn load(ctx: *anyopaque, index: u32) anyerror!trace.Trace {
        const self: *Source = @ptrCast(@alignCast(ctx));
        if (index >= 2) return error.InvalidWordFixtureIndex;
        self.loads += 1;
        var result = try trace.Trace.init(self.a, self.claims[index]);
        errdefer result.deinit();
        const offset: usize = if (index == 0) 0 else 2;
        for (events[offset..][0..self.claims[index].rows]) |event| try result.append(event);
        try result.seal();
        return result;
    }
    fn interface(self: *Source) artifact.Source {
        return .{ .context = self, .load = load };
    }
};
const Capture = struct {
    memories: [2]?request.Proof = .{ null, null },
    range: ?table.Proof = null,
    memory_taken: u32 = 0,
    range_taken: bool = false,
    fn memorySink(ctx: *anyopaque, index: u32, proof: *request.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index >= 2 or self.memories[index] != null) return error.InvalidWordCapture;
        self.memories[index] = proof.*;
        proof.* = undefined;
    }
    fn rangeSink(ctx: *anyopaque, index: u32, proof: *table.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.range != null) return error.InvalidWordCapture;
        self.range = proof.*;
        proof.* = undefined;
    }
    fn takeMemory(ctx: *anyopaque, index: u32) anyerror!request.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != self.memory_taken or index >= 2) return error.InvalidWordCapture;
        const proof = self.memories[index] orelse return error.InvalidWordCapture;
        self.memories[index] = null;
        self.memory_taken += 1;
        return proof;
    }
    fn takeRange(ctx: *anyopaque, index: u32) anyerror!table.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.memory_taken != 2) return error.InvalidWordCapture;
        const proof = self.range orelse return error.InvalidWordCapture;
        self.range = null;
        self.range_taken = true;
        return proof;
    }
    fn sink(self: *Capture) artifact.Sink {
        return .{ .context = self, .memory = memorySink, .range = rangeSink };
    }
    fn loader(self: *Capture) receiver.Loader {
        return .{ .context = self, .take_memory = takeMemory, .take_range = takeRange };
    }
    fn deinit(self: *Capture, a: std.mem.Allocator) void {
        for (&self.memories) |*proof| if (proof.*) |*owned| owned.deinit(a);
        if (self.range) |*owned| owned.deinit(a);
        self.* = undefined;
    }
};
fn endpointRecord(address: u32, clock: u64, value: u32) [16]u8 {
    var out: [16]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], address, .little);
    std.mem.writeInt(u64, out[4..12], clock, .little);
    std.mem.writeInt(u32, out[12..16], value, .little);
    return out;
}
test "block-v5 packed27 fresh range16 and global register RW endpoints" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input = fixture.recordWord(0x6000, fixture.input_value);
    const rw = [_][8]u8{ fixture.recordWord(0x2000, 9), fixture.recordWord(0x2008, 5) };
    const touches = [_][9]u8{ fixture.recordTouch(0, 1, 7), fixture.recordTouch(1, 0x2000, 9), fixture.recordTouch(1, 0x2004, 0), fixture.recordTouch(1, 0x6000, fixture.input_value) };
    const endpoints = [_][16]u8{ endpointRecord(0x2000, H + 3, 11), endpointRecord(0x2004, H + 4, 1), endpointRecord(0x6000, H + 5, fixture.input_value + 1) };
    try fixture.writeFile(tmp.dir, "input.bin", &input);
    try fixture.writeFile(tmp.dir, "rw.bin", std.mem.sliceAsBytes(&rw));
    try fixture.writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&touches));
    try fixture.writeFile(tmp.dir, "endpoints.bin", std.mem.sliceAsBytes(&endpoints));
    var opened = try fixture.OpenFiles.open(tmp.dir);
    defer opened.deinit();
    const endpoint_file = try tmp.dir.openFile("endpoints.bin", .{});
    defer endpoint_file.close();
    const files = sources.Sources{ .initial = opened.files, .endpoints = endpoint_file };
    var source_pins = try fixture.sourcePins(&input, std.mem.sliceAsBytes(&rw), std.mem.sliceAsBytes(&touches));
    const hasher = @import("../../air/memory_commitment/blake3_state_tree.zig").TreeHasher.init(.memory);
    source_pins.initial_rw_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 9 }, .{ .index = 0x2008 / 4, .value = 5 }, .{ .index = 0x6000 / 4, .value = fixture.input_value } })).bytes;
    const final_root = (try hasher.root(&.{ .{ .index = 0x2000 / 4, .value = 11 }, .{ .index = 0x2004 / 4, .value = 1 }, .{ .index = 0x2008 / 4, .value = 5 }, .{ .index = 0x6000 / 4, .value = fixture.input_value + 1 } })).bytes;
    const claims = [_]memory.Claim{
        try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = events[0], .last = events[1] }, 5, 8, null),
        try memory.Claim.fromSummary(.{ .first_row = 2, .rows = 3, .first = events[2], .last = events[4] }, 5, 9, events[1]),
    };
    var source = Source{ .a = a, .claims = claims };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try artifact.ForBackend(Cpu).collect(a, source.interface(), &claims, 5, config);
    defer first.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), first.plan.shards.len);
    try std.testing.expectEqual(@as(u64, 63), first.counters[0].total);
    var pins = try fixture.sealPins(source_pins, config);
    pins.counts[@intFromEnum(seal.Family.memory) - 1] = 2;
    pins.memory_plan_digest = first.plan_digest;
    pins.expected_final_rw_root = final_root;
    const endpoint_pins = sources.Pins{ .initial = source_pins, .memory_plan_digest = first.plan_digest, .expected_final_rw_root = final_root, .endpoints = .{ .sha256 = initial.sha256(std.mem.sliceAsBytes(&endpoints)), .records = 3 } };
    pins.rw_endpoint_plan_digest = try endpoint_pins.digest();
    var register_pins = registers.Pins{ .first_touch_mask = 1 << 1, .initial_registers = source_pins.initial_registers, .final_registers = source_pins.initial_registers, .final_clocks = @splat(0) };
    register_pins.final_clocks[1] = H + 1;
    pins.register_endpoint_plan_digest = try register_pins.digest();
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        first.memoryEntry(0),
        first.memoryEntry(1),
        first.rangeEntry(0),
    };
    var sealed = try seal.seal(pins, &entries);
    var capture = Capture{};
    defer capture.deinit(a);
    try first.prove(a, source.interface(), capture.sink(), pins, &entries, sealed.digest, sealed);
    var receive_pins = receiver.Pins{ .seal = pins, .expected_seal_digest = sealed.digest, .first_round = &entries, .claims = &claims, .request_counts = first.counts, .memory_roots = first.memory_roots, .range_roots = first.range_roots, .expected_total_events = 5, .source = endpoint_pins, .register_endpoints = register_pins };
    // Independent metadata mutations reject before a proof can be taken.
    var wrong = receive_pins;
    wrong.register_endpoints.?.first_touch_mask ^= 1 << 2;
    try std.testing.expectError(error.UntrustedV5RegisterEndpoints, receiver.verify(Cpu, a, wrong, &fixture.input, files, capture.loader(), sealed));
    try std.testing.expectEqual(@as(u32, 0), capture.memory_taken);
    const verified = try receiver.verify(Cpu, a, receive_pins, &fixture.input, files, capture.loader(), sealed);
    try std.testing.expectEqual(@as(u64, 1), verified.register_endpoint_count);
    try std.testing.expect(verified.register_endpoints_verified and capture.range_taken);
    try std.testing.expectEqualDeep(final_root, verified.final_rw_root);
    // Re-pin/re-seal a high-clock-bit error and regenerate all proofs. Fresh
    // quotients/range/source checks succeed, but global register closure fails.
    capture = .{};
    register_pins.final_clocks[1] ^= @as(u64, 1) << 32;
    pins.register_endpoint_plan_digest = try register_pins.digest();
    sealed = try seal.seal(pins, &entries);
    receive_pins.seal = pins;
    receive_pins.expected_seal_digest = sealed.digest;
    receive_pins.register_endpoints = register_pins;
    try first.prove(a, source.interface(), capture.sink(), pins, &entries, sealed.digest, sealed);
    try std.testing.expectError(error.UnclosedV5RegisterEndpointRelation, receiver.verify(Cpu, a, receive_pins, &fixture.input, files, capture.loader(), sealed));
    try std.testing.expect(capture.range_taken);
}
test "block-v5 packed projection preserves all native bytes and rejects non-range limbs" {
    const M = core.fields.m31.M31;
    const value = events[4];
    const old = @import("../block_memory_relation_v2.zig").transitionTuple(value);
    try std.testing.expectEqualDeep(protocol.transitionTuple(value), protocol.fromByteTransition(M, old));
    var changed = old;
    changed[11] = changed[11].add(M.one()); // high u64 clock byte, not a low clock truncation
    try std.testing.expect(!std.meta.eql(protocol.fromByteTransition(M, old), protocol.fromByteTransition(M, changed)));
    var row = try air.witness(events[1], events[2]);
    row[air.Layout.current_clock + 3] = M.fromCanonical(65536);
    try std.testing.expectError(error.InvalidV5WordLimb, protocol.readLimbs(row[air.Layout.current_clock..][0..4]));
}
