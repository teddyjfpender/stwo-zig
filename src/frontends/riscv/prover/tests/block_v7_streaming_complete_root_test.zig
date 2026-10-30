//! Variable-size genuine guest -> durable originals -> complete detached root.
pub fn qualify(comptime shared: bool) !void {
    return Fixture(shared).qualify();
}
fn Fixture(comptime shared: bool) type {
    return struct {
        const std = @import("std");
        const Engine = @import("stwo_prover_engine");
        const Producer = @import("../block_v7_streaming_execution_v1.zig");
        const Complete = @import("../../recursion/block_v7_complete_cpu_producer_v1.zig").For(shared);
        const Receiver = if (shared) @import("../../recursion/block_v7_shared_epoch_mixed_receiver_v1.zig") else @import("../../recursion/block_v7_mixed_receiver_v1.zig");
        const Guest = @import("block_v7_scaling_guest_test_support.zig");
        const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
        const Consumer = struct {
            pub const Result = Complete.Output;
            pub fn consume(f: Producer.Fixture) !Result {
                // One test consumer keeps source/prover codegen shared across profiles.
                // The producer still enforces exact root/original security equality.
                const profile: Profile = if (std.meta.eql(f.input.epoch.config, Profile.csp_q70_pow26.config())) .csp_q70_pow26 else if (std.meta.eql(f.input.epoch.config, Profile.diagnostic_q8_pow0.config())) .diagnostic_q8_pow0 else return error.UnsupportedCompleteFixtureSecurity;
                return Complete.produce(f.allocator, f.trusted, f.input, .{ .profile = profile, .reuse_fixed_commitment = !std.process.hasEnvVarConstant("STWO_V7_NO_FIXED_REUSE") });
            }
        };
        fn run(selected: Profile) !void {
            const iterations = if (std.posix.getenv("STWO_V7_SCALE_ITERATIONS")) |text| try std.fmt.parseInt(u32, text, 10) else 1;
            const cycles = try Guest.cycles(iterations);
            const segment_cycles = if (std.posix.getenv("STWO_V7_SCALE_SEGMENT_CYCLES")) |text| try std.fmt.parseInt(u32, text, 10) else @as(u32, @intCast(try std.math.divCeil(u64, cycles, 2)));
            const memory_cohorts = std.process.hasEnvVarConstant("STWO_V7_SCALE_MEMORY_COHORTS");
            const memory_shard = if (std.posix.getenv("STWO_V7_SCALE_RAM_EVENTS_PER_SHARD")) |text| try std.fmt.parseInt(u32, text, 10) else @as(u32, if (memory_cohorts) 32 else 1 << 15);
            const code = try Guest.instructions(iterations);
            const elf = Guest.releaseElf(&code);
            const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
            defer budget.destroy();
            var pool: Engine.work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = budget.allocator() });
            defer pool.deinit();
            var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            var dir = std.testing.tmpDir(.{ .iterate = true });
            defer dir.cleanup();
            var whole = try std.time.Timer.start();
            var result = try Producer.run(budget, dir.dir, .{ .elf = &elf, .elf_sha256 = @import("../block_v5_initial_sources_v1.zig").sha256(&elf), .cycles = cycles, .output = try Guest.output(iterations), .config = selected.config() }, .{ .segment_cycles = segment_cycles, .max_segments = 58, .max_callers = 3, .active_callers = std.process.hasEnvVarConstant("STWO_V7_ACTIVE_CALLERS"), .memory_cohorts = if (memory_cohorts) .{} else null, .ram_events_per_shard = memory_shard }, &pool, Consumer);
            defer result.value.deinit();
            var iterator = dir.dir.iterate();
            try std.testing.expectEqual(@as(?std.fs.Dir.Entry, null), try iterator.next());
            // Producer.run has destroyed all original proofs, traces and checkpoints.
            // The complete receiver sees only independently derived metadata and root.
            var clock = try std.time.Timer.start();
            var verified = try Receiver.verify(budget.allocator(), result.value.bytes, result.value.metadata.trusted, result.value.metadata.input(), result.value.key, result.value.wires, .{});
            defer verified.deinit();
            const verification_ns = clock.read();
            try std.testing.expectEqual(cycles, verified.summary.cycles);
            try std.testing.expectEqualDeep(try Guest.output(iterations), verified.summary.output);
            try std.testing.expectEqual(result.stats.events, verified.summary.ram_events);
            try std.testing.expectEqual(result.stats.fetches, verified.summary.program_fetches);
            if (result.value.metadata.input().separate_memory) |separate| {
                var incomplete = result.value.metadata.input();
                incomplete.separate_memory.?.ram = separate.ram[0 .. separate.ram.len - 1];
                try rejectRoot(budget.allocator(), result.value, incomplete);
                // Compensated alterations keep the public initialization residual
                // unchanged; the root must nevertheless bind each physical claim.
                var changed_ram = separate.ram[0].*;
                var changed_interval = separate.interval.*;
                const Q = @import("stwo_core").fields.qm31.QM31;
                changed_ram.input.sums[2] = changed_ram.input.sums[2].add(Q.one());
                changed_interval.input.sums[0] = changed_interval.input.sums[0].sub(Q.one());
                const ram = try budget.allocator().dupe(@TypeOf(separate.ram[0]), separate.ram);
                defer budget.allocator().free(ram);
                ram[0] = &changed_ram;
                var compensated = result.value.metadata.input();
                compensated.separate_memory.?.ram = ram;
                compensated.separate_memory.?.interval = &changed_interval;
                try rejectRoot(budget.allocator(), result.value, compensated);
            }
            std.debug.print("V7_STREAMING_COMPLETE iterations={d} profile={s} shared_epoch={} source={f} recursive={f} root_verification_ns={d} execution_to_verified_root_ns={d} proof_bytes={d} charged_peak_bytes={d} original_owners_destroyed=true complete_global_closure=true ethereum_block=false\n", .{ iterations, @tagName(selected), shared, std.json.fmt(result.stats, .{}), std.json.fmt(result.value.stats, .{}), verification_ns, whole.read(), result.value.bytes.len, budget.snapshot().peak_live_bytes });
        }
        fn rejectRoot(a: std.mem.Allocator, output: Complete.Output, input: @import("../../recursion/block_v7_mixed_inputs_v1.zig").Input) !void {
            if (Receiver.verify(a, output.bytes, output.metadata.trusted, input, output.key, output.wires, .{})) |value| {
                var accepted = value;
                accepted.deinit();
                return error.AcceptedChangedCompleteMemoryClaims;
            } else |_| {}
        }
        pub fn qualify() !void {
            if (std.process.hasEnvVarConstant("STWO_V7_SCALE_CANONICAL")) try run(.csp_q70_pow26) else try run(.diagnostic_q8_pow0);
        }
    };
}
test "v7 variable execution reaches one detached complete root" {
    try qualify(false);
}
