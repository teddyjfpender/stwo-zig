//! Original sorted-source census, retained raw/PCS, and unchanged fresh proofs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Transport = @import("../block_v6_ram_commitment_staging_v1.zig");
const Stage = @import("../block_v5_ram_lanes_stage_v1.zig");
const Ram = @import("../block_v5_ram_lanes_proof_v1.zig");
const Range = @import("../block_v5_range16_proof_v1.zig");
const Trace = @import("../../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Protocol = @import("../block_v5_ram_lanes_protocol_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Seal = @import("../block_v5_source_seal_v1.zig");
const Source = struct {
    reads: u32 = 0,
    reject: bool = false,
    fn event(index: u32) Event {
        return .{ .space = 1, .address = 0x2000, .clock = index + 1, .before = index, .after = index + 1 };
    }
    fn claim() Protocol.Claim {
        return .{ .first_event = 0, .total_events = 3, .events = 3, .row_log = 8, .first = event(0), .last = event(2), .preceding = null };
    }
    fn load(raw: *anyopaque, index: u32) !Trace {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.reject or index != 0) return error.UnexpectedSortedWitnessReplay;
        var trace = try Trace.init(std.testing.allocator, claim(), .{ .max_row_log = 8, .max_events = 4, .max_owned_bytes = 1 << 20 });
        errdefer trace.deinit();
        for (0..3) |i| try trace.append(event(@intCast(i)));
        try trace.seal();
        self.reads += 1;
        return trace;
    }
    fn source(self: *@This()) Stage.Source {
        return .{ .context = self, .load = load };
    }
};
const Capture = struct {
    memory: ?Ram.Proof = null,
    range: ?Range.Proof = null,
    fn putMemory(raw: *anyopaque, index: u32, proof: *Ram.Proof) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0 or self.memory != null) return error.InvalidCheckpointProofSink;
        self.memory = proof.*;
    }
    fn putRange(raw: *anyopaque, index: u32, proof: *Range.Proof) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0 or self.range != null) return error.InvalidCheckpointProofSink;
        self.range = proof.*;
    }
    fn sink(self: *@This()) Stage.Sink {
        return .{ .context = self, .memory = putMemory, .range = putRange };
    }
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.memory) |*proof| proof.deinit(a);
        if (self.range) |*proof| proof.deinit(a);
    }
};
test "RAM commitment checkpoint avoids second sorted replay and preserves verified memory range proofs" {
    try exercise(false);
}
test "RAM commitment checkpoint retains original coefficients with unchanged verified proofs" {
    try exercise(true);
}
fn exercise(retain_coefficients: bool) !void {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var retained = Transport.Transport{ .a = a, .dir = temp.dir, .policy = .{ .retain_coefficients = retain_coefficients } };
    defer retained.deinit();
    var source = Source{};
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var collected = try Stage.ForBackend(Cpu).collect(a, source.source(), &.{Source.claim()}, 3, config, .{ .checkpoints = &retained });
    defer collected.deinit(a);
    try std.testing.expectEqual(@as(u32, 1), source.reads);
    try retained.requireRoster(collected.pins, collected.plan.shards);
    var wrong = collected.pins[0];
    wrong.counter_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidRamCheckpointOrder, retained.loadMemory(a, wrong));
    try std.testing.expectError(error.IncompleteRamCheckpointRoster, retained.requireRoster(&.{}, collected.plan.shards));
    {
        var loaded = try retained.loadMemory(a, collected.pins[0]);
        defer loaded.deinit(a);
        try loaded.first.require(a, &loaded.trace, collected.pins[0]);
        for (loaded.first.pcs_first.scheme.trees.items) |tree| try std.testing.expectEqual(retain_coefficients, tree.coefficients != null);
        try std.testing.expectEqual(retain_coefficients, retained.memory.items[0].pcs.coefficient_bytes != 0);
        var original = try Source.load(&source, 0);
        defer original.deinit();
        try std.testing.expectEqualSlices(core.fields.m31.M31, original.main, loaded.trace.main);
        try std.testing.expectEqualSlices(core.fields.m31.M31, original.fixed, loaded.trace.fixed);
        try std.testing.checkAllAllocationFailures(a, loadAndRelease, .{ &retained, collected.pins[0] });
    }
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family| counts[@intFromEnum(family) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = collected.plan_digest, .initial_source_plan_digest = @splat(25), .expected_final_rw_root = @splat(26), .rw_endpoint_plan_digest = @splat(27), .register_endpoint_plan_digest = @splat(28), .register_custody_mode = 1, .config = config, .counts = counts };
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        try collected.memoryEntry(0),
        try collected.rangeEntry(0),
    };
    const sealed = try Seal.seal(pins, &entries);
    var baseline = Capture{};
    defer baseline.deinit(a);
    collected.limits.checkpoints = null;
    collected.prove(a, source.source(), baseline.sink(), pins, &entries, sealed.digest, sealed) catch |err| {
        std.debug.print("RAM_CHECKPOINT baseline_prove_error={s}\n", .{@errorName(err)});
        return err;
    };
    collected.limits.checkpoints = &retained;
    source.reject = true;
    var cached = Capture{};
    defer cached.deinit(a);
    collected.prove(a, source.source(), cached.sink(), pins, &entries, sealed.digest, sealed) catch |err| {
        std.debug.print("RAM_CHECKPOINT retained_prove_error={s}\n", .{@errorName(err)});
        return err;
    };
    try sameProof(a, baseline.memory.?.stark, cached.memory.?.stark);
    try sameProof(a, baseline.range.?.stark, cached.range.?.stark);
    const memory_proof = cached.memory.?;
    cached.memory = null;
    _ = try Ram.ForBackend(Cpu).verifyOwned(a, memory_proof, collected.pins[0], sealed, pins, &entries, .{});
    const range_proof = cached.range.?;
    cached.range = null;
    _ = try Range.ForBackend(Cpu).verifyOwned(a, range_proof, collected.plan.shards[0], collected.plan.digest, collected.range_roots[0], sealed, pins, &entries);
    if (retain_coefficients) {
        var coefficient_name: [64]u8 = undefined;
        const coefficient_file = try temp.dir.openFile(try Transport.memoryName(0, "pcs", &coefficient_name), .{ .mode = .read_write });
        defer coefficient_file.close();
        const position = (try coefficient_file.stat()).size - 4;
        var original: [4]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 4), try coefficient_file.preadAll(&original, position));
        var invalid: [4]u8 = undefined;
        std.mem.writeInt(u32, &invalid, core.fields.m31.Modulus, .little);
        try coefficient_file.pwriteAll(&invalid, position);
        try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, retained.loadMemory(a, collected.pins[0]));
        try coefficient_file.pwriteAll(&original, position);
    }
    var buffer: [64]u8 = undefined;
    const file = try temp.dir.openFile(try Transport.memoryName(0, "columns", &buffer), .{ .mode = .read_write });
    defer file.close();
    var value: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try file.preadAll(&value, 152));
    value[0] ^= 1;
    try file.pwriteAll(&value, 152);
    try std.testing.expectError(error.TamperedV5WitnessFile, retained.loadMemory(a, collected.pins[0]));
    std.debug.print("RAM_CHECKPOINT verified=true raw_witness_parity=true proof_byte_parity=true sorted_replay_omitted=true raw_bytes={d} pcs_bytes={d} max_live_bytes={d} global_claims_open=true\n", .{ retained.raw_written_bytes, retained.statistics.written_bytes, retained.max_live_bytes });
}
fn sameProof(a: std.mem.Allocator, left: core.proof_suites.Blake3.Proof, right: core.proof_suites.Blake3.Proof) !void {
    var lhs = std.Io.Writer.Allocating.init(a);
    defer lhs.deinit();
    var rhs = std.Io.Writer.Allocating.init(a);
    defer rhs.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &lhs.writer, left);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &rhs.writer, right);
    try std.testing.expectEqualSlices(u8, lhs.written(), rhs.written());
}
fn loadAndRelease(a: std.mem.Allocator, retained: *Transport.Transport, expected: Ram.Pin) !void {
    var loaded = try retained.loadMemory(a, expected);
    defer loaded.deinit(a);
}
