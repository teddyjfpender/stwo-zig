const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Producer = @import("../block_v7_streaming_execution_v1.zig");
const Metadata = @import("../../recursion/block_v7_mixed_metadata_v1.zig");
const Inputs = @import("../../recursion/block_v7_mixed_inputs_v1.zig");
const Global = @import("../block_v7_global_public_closure_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Consumer = struct {
    pub const Result = *Metadata.Owned;
    pub fn consume(fixture: Producer.Fixture) !Result {
        try qualifyBoundaryAdmission(fixture);
        const metadata = try Metadata.Owned.init(fixture.allocator, fixture.trusted, fixture.input);
        errdefer metadata.deinit();
        for (metadata.callers, 0..) |caller, index| for (try @import("../../recursion/block_v7_caller_geometry_census_v1.zig").rows(caller)) |row| {
            std.debug.print("V7_CALLER_CENSUS caller={d} data={f}\n", .{ index, std.json.fmt(row, .{}) });
        };
        return metadata;
    }
};
test "v7 bounded dynamic execution restores each committed witness once" {
    const iterations = if (std.posix.getenv("STWO_V7_SCALE_ITERATIONS")) |text| try std.fmt.parseInt(u32, text, 10) else 1;
    const cycles = try Guest.cycles(iterations);
    const segment_cycles = if (std.posix.getenv("STWO_V7_SCALE_SEGMENT_CYCLES")) |text| try std.fmt.parseInt(u32, text, 10) else @as(u32, @intCast(try std.math.divCeil(u64, cycles, 3)));
    const code = try Guest.instructions(iterations);
    const elf = Guest.releaseElf(&code);
    const selected: @import("../../recursion/blake3_execution_parent_protocol.zig").Profile = if (std.process.hasEnvVarConstant("STWO_V7_SCALE_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var dir = std.testing.tmpDir(.{ .iterate = true });
    defer dir.cleanup();
    const result = try Producer.run(budget, dir.dir, .{ .elf = &elf, .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .cycles = cycles, .output = try Guest.output(iterations), .config = selected.config() }, .{ .segment_cycles = segment_cycles, .max_segments = 58, .max_callers = 3, .active_callers = std.process.hasEnvVarConstant("STWO_V7_ACTIVE_CALLERS") }, &pool, Consumer);
    defer result.value.deinit();
    try std.testing.expectEqual(cycles, result.stats.cycles);
    try std.testing.expectEqual(try std.math.divCeil(u64, cycles, segment_cycles), result.stats.segments);
    try std.testing.expectEqual(cycles + result.stats.segments - 1, result.stats.fetches);
    try std.testing.expect(result.stats.checkpoint_bytes > 0 and result.stats.caller_checkpoint_bytes > 0);
    var iterator = dir.dir.iterate();
    try std.testing.expectEqual(@as(?std.fs.Dir.Entry, null), try iterator.next());
    // Only metadata survives Producer.run. No verifier receipt is carried by
    // Metadata; this call tests policy/ownership, NOT recursive authentication.
    var canonical = try Inputs.Owned.init(budget.allocator(), result.value.input());
    defer canonical.deinit();
    const summary = try Global.closePublic(budget.allocator(), result.value.trusted, result.value.input(), canonical.values(), .{});
    try std.testing.expectEqual(cycles, summary.cycles);
    std.debug.print("V7_STREAMING iterations={d} profile={s} active_callers={any} stats={f} original_verified=true recursive_root=false checkpoints_deleted=true\n", .{ iterations, @tagName(selected), result.value.active_callers.len != 0, std.json.fmt(result.stats, .{}) });
}
test "v7 scaling guest bounds and publication are explicit" {
    try std.testing.expectError(error.InvalidV7ScalingIterations, Guest.instructions(0));
    try std.testing.expectError(error.InvalidV7ScalingIterations, Guest.instructions(2049));
    try std.testing.expectEqual(@as(u64, 20495), try Guest.cycles(4096));
    const output = try Guest.output(4096);
    try std.testing.expectEqual(@as(u8, 1), output[32]);
    try std.testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, output[24..28], .little));
}

// Original proof verification already ran before this callback. These attacks
// change independently proposed boundary metadata, never an accepted receipt.
fn qualifyBoundaryAdmission(fixture: Producer.Fixture) !void {
    const Receive = @import("../block_v7_execution_receiver_v1.zig");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var count: usize = 0;
    var frames: usize = 0;
    for (fixture.input.natives, 0..) |native, index| {
        if (native.pin.shape.n_components != 0) continue;
        count += 1;
        const kind = try @import("../block_v7_native_geometry_v1.zig").classify(native.pin.shape, native.pin.template.external_retirements);
        frames += @intFromBool(kind == .external_frame);
        if (kind == .external_frame) {
            // This is the real original STARK's constrained interaction pad,
            // not a synthetic claim or shape-only equation evaluation.
            const values = native.proof.stark.commitment_scheme_proof.sampled_values.items[2][0];
            try std.testing.expectEqual(@as(usize, 1), values.len);
            const saved = values[0];
            defer values[0] = saved;
            values[0] = saved.add(@import("stwo_core").fields.qm31.QM31.one());
            try expectRejected(@import("../block_v7_native_proof_v1.zig").For(Cpu).verify(fixture.allocator, native.proof, native.pin, fixture.input.epoch, fixture.input.entries));
        }

        try std.testing.expectEqual(native.pin.shape.total_steps, native.pin.template.external_retirements);
        const proposed = try fixture.allocator.dupe(Receive.Native, fixture.input.natives);
        defer fixture.allocator.free(proposed);
        var input = fixture.input;
        input.natives = proposed;
        var shape = native.pin.shape.*;
        proposed[index].pin.shape = &shape;
        shape.public_data.final_regs[1] ^= 1;
        try expectRejected(Receive.For(Cpu).verify(fixture.allocator, fixture.trusted, input, .{}));
        shape = native.pin.shape.*;
        shape.public_data.final_pc ^= 4;
        shape.final_pc = shape.public_data.final_pc;
        try expectRejected(Receive.For(Cpu).verify(fixture.allocator, fixture.trusted, input, .{}));
        shape = native.pin.shape.*;
        proposed[index].pin.template.external_retirements -= 1;
        try expectRejected(proposed[index].pin.validate());
    }
    if (count != 0) {
        var wrong = fixture.trusted;
        wrong.terminal.halt_address += 4;
        try expectRejected(Receive.For(Cpu).verify(fixture.allocator, wrong, fixture.input, .{}));
        wrong = fixture.trusted;
        wrong.terminal.output[0] ^= 1;
        try expectRejected(Receive.For(Cpu).verify(fixture.allocator, wrong, fixture.input, .{}));
        var input = fixture.input;
        input.program_plan.program_root.bytes[0] ^= 1;
        try expectRejected(Receive.For(Cpu).verify(fixture.allocator, fixture.trusted, input, .{}));
        std.debug.print("V7_BOUNDARY_ENVELOPE segments={d} physical_frames={d} state_register_rom_halt_rejected=true full_source_verified=true\n", .{ count, frames });
    }
}
fn expectRejected(result: anytype) !void {
    if (result) |_| return error.AcceptedBoundaryEnvelopeForgery else |err| if (err == error.OutOfMemory) return err;
}
