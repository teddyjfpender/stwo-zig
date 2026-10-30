//! Online first-pass provider -> immutable counters+PCS -> unchanged proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Groups = @import("../block_v5_cpu_lookup_groups_v1.zig");
const Proof = @import("../block_v5_native_lookup_proof_v1.zig");
const Store = @import("../block_v6_provider_commitment_store_v1.zig");
const Staging = @import("../block_v6_provider_commitment_staging_v1.zig");
const Tables = @import("../../air/lookups/tables/mod.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Sink = struct {
    proof: ?Proof.Proof = null,
    fn accept(raw: *anyopaque, index: u32, proof: *Proof.Proof) !void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != 0 or self.proof != null) return error.InvalidLookupCheckpointSink;
        self.proof = proof.*;
    }
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.proof) |*proof| proof.deinit(a);
    }
};
test "lookup commitment checkpoint restores online group with unchanged verified proof" {
    const a = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    for (&counters.counters, 0..) |*counter, index| try counter.registerBase(core.fields.m31.M31.one(), (try Tables.schema.tupleAt(counter.kind, index)).slice());
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var online = try Groups.ForBackend(Cpu).init(a, temp.dir, config, .{ .request_limit = 1000, .max_groups = 2, .max_metadata_bytes = 1 << 20, .max_counter_file_bytes = 16 << 20, .commitments = .{} });
    defer online.deinit();
    try online.addExecution(0, @splat(1), &counters);
    var groups = try online.finish(1);
    defer groups.deinit();
    try std.testing.expectEqual(@as(usize, 1), groups.commitment_pins.len);
    const record = groups.records[0];
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .native_lookup }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
        try record.entry(),
    };
    const sealed = try Seal.seal(pins, &entries);
    var original = Sink{};
    defer original.deinit(a);
    groups.commitment_policy = null;
    try groups.prove(Cpu, .{ .context = &original, .accept = Sink.accept }, pins, &entries, sealed);
    groups.commitment_policy = .{};
    var retained = Sink{};
    defer retained.deinit(a);
    try groups.prove(Cpu, .{ .context = &retained, .accept = Sink.accept }, pins, &entries, sealed);
    try std.testing.expectEqual(@as(u64, 1), groups.commitment_statistics.reused_first_rounds);
    var before = std.Io.Writer.Allocating.init(a);
    defer before.deinit();
    var after = std.Io.Writer.Allocating.init(a);
    defer after.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &before.writer, original.proof.?.stark);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &after.writer, retained.proof.?.stark);
    try std.testing.expectEqualSlices(u8, before.written(), after.written());
    const received = retained.proof.?;
    retained.proof = null;
    _ = try Proof.ForBackend(Cpu).verifyOwned(a, received, record.plan, record.roots, sealed, pins, &entries);
    var buffer: [64]u8 = undefined;
    const name = try Staging.lookupName(0, &buffer);
    var basis = try Store.loadLookupFixed(a, temp.dir, Staging.LOOKUP_FIXED_NAME, groups.fixed_checkpoint.?.root, config, groups.fixed_checkpoint.?.pin, .{});
    defer basis.deinit(a);
    var wrong_roots = record.roots;
    wrong_roots[1][0] ^= 1;
    try std.testing.expectError(error.InvalidProviderCheckpointScope, Store.loadLookupMain(a, temp.dir, name, record.plan, &counters, wrong_roots, &basis, groups.commitment_pins[0], .{}));
    const previous = counters.counters[0].values[0];
    counters.counters[0].values[0] = core.fields.m31.M31.zero();
    try std.testing.expectError(error.InvalidProviderCheckpointScope, Store.loadLookupMain(a, temp.dir, name, record.plan, &counters, record.roots, &basis, groups.commitment_pins[0], .{}));
    counters.counters[0].values[0] = previous;
    std.debug.print("LOOKUP_CHECKPOINT verified=true proof_byte_parity=true original_destroyed=true bytes={d} loaded_bytes={d} global_claims_open=true\n", .{ groups.commitment_statistics.written_bytes, groups.commitment_statistics.max_loaded_bytes });
}
