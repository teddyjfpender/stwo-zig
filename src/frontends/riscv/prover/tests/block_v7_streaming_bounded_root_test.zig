//! Actual segmented execution -> bounded direct windows -> detached final root.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Source = @import("../block_v7_streaming_execution_v1.zig");
const Complete = @import("../../recursion/block_v7_bounded_complete_cpu_producer_v1.zig");
const Receiver = @import("../../recursion/block_v7_mixed_batch_receiver_v1.zig");
const Guest = @import("block_v7_scaling_guest_test_support.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
fn env(comptime name: [:0]const u8, default: u32) !u32 {
    return if (std.posix.getenv(name)) |text| std.fmt.parseInt(u32, text, 10) else default;
}
const Consumer = struct {
    pub const Result = union(enum) {
        proof: Complete.Output,
        cold: void,
        pub fn deinit(self: *Result) void {
            if (self.* == .proof) self.proof.deinit();
            self.* = undefined;
        }
    };
    pub fn consume(f: Source.Fixture) !Result {
        const profile: Profile = if (std.meta.eql(f.input.epoch.config, Profile.csp_q70_pow26.config())) .csp_q70_pow26 else if (std.meta.eql(f.input.epoch.config, Profile.diagnostic_q8_pow0.config())) .diagnostic_q8_pow0 else return error.UnsupportedCompleteFixtureSecurity;
        const family_bytes: ?usize = if (std.process.hasEnvVarConstant("STWO_V7_PROPAGATE_FAMILY_BUDGET")) 24 << 30 else null;
        // Explicit diagnostic budget only; production admission defaults remain
        // unchanged, and the enclosing request still has its 48 GiB hard cap.
        const direct_gib = try env("STWO_V7_DIRECT_GIB", 24);
        if (direct_gib == 0 or direct_gib > 40) return error.InvalidDiagnosticDirectBudget;
        const direct_bytes = @as(usize, direct_gib) << 30;
        if (std.process.hasEnvVarConstant("STWO_V7_REDUCTION_COLD_ONLY")) {
            try @import("block_v7_bounded_cold_probe_test_support.zig").run(f, .{
                .profile = profile,
                .family_max_bytes = family_bytes,
                .max_direct_children = try env("STWO_V7_DIRECT_CHILDREN", 4),
                .direct = .{ .max_planned_bytes = direct_bytes },
                .reduction = .{ .max_bytes = 28 << 30 },
            });
            return .{ .cold = {} };
        }
        if (std.process.hasEnvVarConstant("STWO_V7_COLD_ONLY")) {
            const metadata = try @import("../../recursion/block_v7_mixed_metadata_v1.zig").Owned.initWhole(f.allocator, f.trusted, f.input, 2048);
            defer metadata.deinit();
            const first = try env("STWO_V7_COLD_FIRST", @intCast(f.input.natives.len));
            var selected = try Complete.selectWindow(f.allocator, metadata.input(), first, 1, .{ .profile = profile, .family_max_bytes = family_bytes, .direct = .{ .max_planned_bytes = direct_bytes } });
            defer selected.cold.deinit();
            std.debug.print("V7_COLD_ONLY profile={s} first={d} count={d} estimate={f} recursive_proof_created=false\n", .{ @tagName(profile), first, selected.count, std.json.fmt(selected.estimate, .{}) });
            return .{ .cold = {} };
        }
        return .{ .proof = try Complete.produce(f.allocator, f.trusted, f.input, .{
            .profile = profile,
            .family_max_bytes = family_bytes,
            .max_direct_children = try env("STWO_V7_DIRECT_CHILDREN", 4),
            .direct = .{ .max_planned_bytes = direct_bytes },
            .reduction = .{ .max_bytes = 28 << 30 },
        }) };
    }
};
test "v7 bounded streaming execution reaches one independently verified root" {
    const profile: Profile = if (std.process.hasEnvVarConstant("STWO_V7_SCALE_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const iterations = try env("STWO_V7_SCALE_ITERATIONS", 1);
    const cycles = try Guest.cycles(iterations);
    const segment_cycles = try env("STWO_V7_SCALE_SEGMENT_CYCLES", @intCast(try std.math.divCeil(u64, cycles, 2)));
    const instructions = try Guest.instructions(iterations);
    const elf = Guest.releaseElf(&instructions);
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var dir = std.testing.tmpDir(.{ .iterate = true });
    defer dir.cleanup();
    var clock = try std.time.Timer.start();
    var result = try Source.run(budget, dir.dir, .{
        .elf = &elf,
        .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf),
        .cycles = cycles,
        .output = try Guest.output(iterations),
        .config = profile.config(),
    }, .{
        .segment_cycles = segment_cycles,
        .active_callers = true,
        .memory_cohorts = .{},
        .ram_events_per_shard = try env("STWO_V7_SCALE_RAM_EVENTS_PER_SHARD", 32),
        .max_segments = 64,
        .max_callers = 64,
    }, &pool, Consumer);
    defer result.value.deinit();
    const candidate_ns = clock.read();
    var entries = dir.dir.iterate();
    try std.testing.expectEqual(@as(?std.fs.Dir.Entry, null), try entries.next());
    if (result.value == .cold) return;
    const output = &result.value.proof;
    var verification_clock = try std.time.Timer.start();
    var verified = try Receiver.verify(budget.allocator(), output.root.bytes, output.metadata.trusted, output.metadata.input(), output.counts, output.pins, output.root.key, output.root.wires, .{ .global = .{ .max_entries = 2048 } });
    defer verified.deinit();
    const verification_ns = verification_clock.read();
    try std.testing.expectEqual(cycles, verified.summary.cycles);
    try std.testing.expectEqualDeep(try Guest.output(iterations), verified.summary.output);
    try std.testing.expectEqual(result.stats.events, verified.summary.ram_events);
    try std.testing.expectEqual(result.stats.fetches, verified.summary.program_fetches);
    for (output.windows) |window| try std.testing.expect(window.charged_peak_bytes <= window.planned_peak_bytes);
    try std.testing.expect(output.root.charged_peak_bytes <= output.root.planned_peak_bytes.?);
    const hash = @import("../block_v5_initial_sources_v1.zig").sha256(output.root.bytes);
    std.debug.print("V7_STREAMING_BOUNDED profile={s} iterations={d} source={f} producer={f} windows={f} reduction_planned_bytes={d} reduction_charged_bytes={d} candidate_ns={d} verification_ns={d} execution_to_verified_root_ns={d} root_bytes={d} root_sha256={x} charged_peak_bytes={d} original_and_intermediate_owners_destroyed=true complete_global_closure=true ethereum_block=false\n", .{ @tagName(profile), iterations, std.json.fmt(result.stats, .{}), std.json.fmt(output.stats, .{}), std.json.fmt(output.windows, .{}), output.root.planned_peak_bytes.?, output.root.charged_peak_bytes, candidate_ns, verification_ns, clock.read(), output.root.bytes.len, hash, budget.snapshot().peak_live_bytes });
}
