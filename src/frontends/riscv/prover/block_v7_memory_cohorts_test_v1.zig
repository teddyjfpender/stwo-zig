const std = @import("std");
const Cohort = @import("block_v7_memory_cohorts_v1.zig");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Event = @import("../air/block/memory_transition.zig").Transition;
const Raw = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
const elf = blk: {
    var bytes = Raw;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    std.mem.writeInt(u32, bytes[644..648], 0x44332211, .little);
    break :blk bytes;
};

test "v7 bounded spill cohorts equal original proofs and verify after producer destruction" {
    try run(false, false);
}
test "v7 coefficient checkpoint cohorts preserve exact proofs and reject changed coefficients" {
    try run(true, false);
}
test "v7 coefficient cohort interactions release all raw rows before proving" {
    try run(true, true);
}
fn run(compact: bool, consume: bool) !void {
    const a = std.testing.allocator;
    var initialized = try Initial.Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = undefined;
    for (&output, 0..) |*v, i| v.* = @intCast(i + 1);
    output[32] = 1;
    const policy = Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 100, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.config(if (std.process.hasEnvVarConstant("STWO_V7_MEMORY_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0) };
    const plan = try Terminal.Plan.init(policy.terminal);
    var guest: [16]Event = undefined;
    for (guest[0..13], 0..) |*event, i| {
        const read = try plan.transition(i, 0xa5);
        event.* = .{ .space = 1, .address = read.address, .clock = if (read.address == initialized.info.halt_flag) 4 * (policy.terminal.final_cycle - 1) + 1 else 4 * (i / 3) + i % 3 + 1, .before = (try initialized.find(read.address)).value, .after = read.before };
    }
    guest[13] = .{ .space = 1, .address = 0x100100, .clock = 21, .before = (try initialized.find(0x100100)).value, .after = 19 };
    guest[14] = .{ .space = 1, .address = 0x100100, .clock = 22, .before = 19, .after = 23 };
    guest[15] = .{ .space = 1, .address = initialized.info.input_start, .clock = 23, .before = 0xdeadbeef, .after = 7 };

    var sorted: [29]Event = undefined;
    @memcpy(sorted[0..16], &guest);
    for (sorted[16..], 0..) |*v, i| v.* = try plan.transition(i, 0xa5);
    std.mem.sort(Event, &sorted, {}, struct {
        fn less(_: void, l: Event, r: Event) bool {
            return if (l.address == r.address) l.clock < r.clock else l.address < r.address;
        }
    }.less);
    const Reader = struct {
        values: []const Event,
        at: usize = 0,
        pub fn next(self: *@This()) !?Event {
            if (self.at == self.values.len) return null;
            defer self.at += 1;
            return self.values[self.at];
        }
    };
    var reader = Reader{ .values = &sorted };
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const limits = Cohort.Limits{ .input_storage = if (compact) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident, .interaction_storage = if (consume) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident, .consume_rows = consume, .ram_quotient = if (std.process.hasEnvVarConstant("STWO_V7_MEMORY_RAM_TILES")) .{ .bounded_tiles = .{ .minimum_trace_log = 4, .tile_log = 3 } } else .whole_domain, .max_live_bytes = 96 << 20, .max_total_file_bytes = 32 << 20, .checkpoint = .{ .max_file_bytes = 32 << 20, .max_loaded_bytes = 32 << 20, .max_row_log = 16 } };
    var stage = try Cohort.Owner.collectSorted(a, dir.dir, policy, &reader, sorted.len, 7, 0xa5, limits);
    var live = true;
    defer if (live) stage.deinit();
    const entries = try stage.entries(a);
    defer a.free(entries);
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.ram)] = @intCast(stage.ram.len);
    inline for ([_]E.Family{ .interval, .range16, .terminal }) |family| counts[@intFromEnum(family)] = 1;
    const epoch = try E.Epoch.init(try policy.digest(), policy.config, counts, entries, entries.len);
    var original = try @import("block_v7_memory_stage_v1.zig").For(Cpu).init(a, policy, &guest, 0xa5, 7, .{});
    defer original.deinit();
    const old_entries = try original.entries(a);
    defer a.free(old_entries);
    try std.testing.expectEqualDeep(entries, old_entries);
    var expected = try original.prove(epoch, entries);
    defer expected.deinit(a);
    const Store = @import("block_v7_memory_cohort_checkpoint_v1.zig").For(@import("block_v7_ram_component_v1.zig").Spec);
    try std.testing.expectError(error.FileNotFound, Store.load(a, dir.dir, "missing.checkpoint", policy.config, stage.ram[0].pin, limits.checkpoint));
    try std.testing.expectError(error.InvalidV7CohortCheckpoint, Store.load(a, dir.dir, "memory-1.checkpoint", policy.config, stage.ram[0].pin, limits.checkpoint));
    var tiny = limits.checkpoint;
    tiny.max_loaded_bytes = 1;
    try std.testing.expectError(error.V7CohortCheckpointLimit, Store.load(a, dir.dir, "memory-0.checkpoint", policy.config, stage.ram[0].pin, tiny));
    const file = try dir.dir.openFile("memory-0.checkpoint", .{ .mode = .read_write });
    defer file.close();
    var saved: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&saved, 128));
    try file.pwriteAll(&@as([4]u8, @splat(255)), 128);
    try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, Store.load(a, dir.dir, "memory-0.checkpoint", policy.config, stage.ram[0].pin, limits.checkpoint));
    try file.pwriteAll(&saved, 128);
    if (compact) {
        try std.testing.expectEqual(.coefficients, stage.ram[0].pin.storage);
        var loaded = try Store.load(a, dir.dir, "memory-0.checkpoint", policy.config, stage.ram[0].pin, limits.checkpoint);
        defer loaded.deinit(a);
        for (loaded.first.scheme.trees.items) |tree| {
            try std.testing.expect(tree.compact_polynomials);
            for (tree.columns) |column| try std.testing.expectEqual(@as(usize, 0), column.values.len);
        }
        const Spec = @import("block_v7_ram_component_v1.zig").Spec;
        const coefficient_offset = 128 + (@as(u64, (Spec.FIXED_COUNT + Spec.MAIN_COUNT) * 4) << @intCast(stage.ram[0].pin.log)) + 8 + 4;
        var old_coefficient: [4]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 4), try file.preadAll(&old_coefficient, coefficient_offset));
        try file.pwriteAll(&@as([4]u8, @splat(255)), coefficient_offset);
        try std.testing.expectError(error.NonCanonicalNativeCheckpointM31, Store.load(a, dir.dir, "memory-0.checkpoint", policy.config, stage.ram[0].pin, limits.checkpoint));
        var changed: [4]u8 = undefined;
        std.mem.writeInt(u32, &changed, (std.mem.readInt(u32, &old_coefficient, .little) + 1) % core.fields.m31.Modulus, .little);
        try file.pwriteAll(&changed, coefficient_offset);
        // Canonical cache corruption grants no proof authority. Either the
        // original prover rejects inconsistent evaluations or fresh verification
        // rejects the resulting proof against the independently pinned roots.
        var hostile_stage = stage;
        if (hostile_stage.prove(dir.dir, epoch, entries)) |value| {
            var forged = value;
            defer forged.deinit();
            if (@import("block_v7_memory_source_v1.zig").For(Cpu).verify(a, policy, epoch, entries, &forged.bundle, .{})) |_| return error.AcceptedChangedCheckpointCoefficient else |err| if (err == error.OutOfMemory) return err;
        } else |err| if (err == error.OutOfMemory) return err;
        try file.pwriteAll(&old_coefficient, coefficient_offset);
    }
    var result = try stage.prove(dir.dir, epoch, entries);
    defer result.deinit();
    const charged_peak = stage.budget.snapshot().peak_live_bytes;
    stage.deinit();
    live = false;
    const Source = @import("block_v7_memory_source_v1.zig");
    const verified = try Source.For(Cpu).verify(a, policy, epoch, entries, &result.bundle, .{});
    try std.testing.expectEqual(@as(u64, guest.len), verified.event_count);
    const Wire = @import("interop_postcard");
    for (expected.ram, result.bundle.ram) |left, right| {
        var l = std.Io.Writer.Allocating.init(a);
        defer l.deinit();
        var r = std.Io.Writer.Allocating.init(a);
        defer r.deinit();
        try Wire.serializeProof(core.proof_suites.Blake3.Hasher, &l.writer, left.proof.stark);
        try Wire.serializeProof(core.proof_suites.Blake3.Hasher, &r.writer, right.proof.stark);
        try std.testing.expectEqualSlices(u8, l.written(), r.written());
    }
    inline for (.{ "interval", "range16", "terminal" }) |field| {
        var l = std.Io.Writer.Allocating.init(a);
        defer l.deinit();
        var r = std.Io.Writer.Allocating.init(a);
        defer r.deinit();
        try Wire.serializeProof(core.proof_suites.Blake3.Hasher, &l.writer, @field(expected, field).stark);
        try Wire.serializeProof(core.proof_suites.Blake3.Hasher, &r.writer, @field(result.bundle, field).stark);
        try std.testing.expectEqualSlices(u8, l.written(), r.written());
    }
    std.mem.swap(@import("block_v7_memory_bundle_v1.zig").RamItem, &result.bundle.ram[0], &result.bundle.ram[1]);
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Source.For(Cpu).verify(a, policy, epoch, entries, &result.bundle, .{}));
    std.mem.swap(@import("block_v7_memory_bundle_v1.zig").RamItem, &result.bundle.ram[0], &result.bundle.ram[1]);
    const old = result.bundle.ram[0].proof.sums[3];
    result.bundle.ram[0].proof.sums[3] = old.add(Q.one());
    try std.testing.expectError(error.OodsNotMatching, Source.For(Cpu).verify(a, policy, epoch, entries, &result.bundle, .{}));
    result.bundle.ram[0].proof.sums[3] = old;
    std.debug.print("V7_MEMORY_COHORTS ram=5 providers=3 verified=true byte_identical=true coefficient_inputs={} consumed_rows={} charged_peak={d} whole_block=false\n", .{ compact, consume, charged_peak });
}
