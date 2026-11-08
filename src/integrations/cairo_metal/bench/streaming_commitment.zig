//! Bounded production-callsite benchmark for Cairo's streaming commitment.

const std = @import("std");
const stwo = @import("stwo");

const arena_binding = stwo.integrations.cairo_metal.arena_binding;
const arena_plan = stwo.backends.metal.arena_plan;
const metal_runtime = stwo.backends.metal.runtime;
const m31 = stwo.core.fields.m31;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;
const circle_poly = stwo.prover.poly.circle.poly;
const twiddles = stwo.prover.poly.twiddles;
const merkle_prover = stwo.prover.vcs_lifted.prover;

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sPlainMerkleHasher;
const small_base_log: u32 = 4;
const small_eval_log: u32 = 5;
const large_base_log: u32 = 6;
const large_eval_log: u32 = 7;
const group_width = 16;
const column_count = group_width * 2;
const binding_count = 46;
const first_coefficient_binding = 13;
const twiddle_binding = 45;
const max_warmups = 2;
const max_samples = 11;

const schedule_json =
    \\[
    \\ {"purpose":"CommitColumnLogSizes","ordinal":0,"id":0},
    \\ {"purpose":"CommitColumnLogSizes","ordinal":1,"id":1},
    \\ {"purpose":"CommitLdeTile","ordinal":0,"id":2},
    \\ {"purpose":"MerkleLeafState","ordinal":0,"id":3},
    \\ {"purpose":"MerkleLayerScratch","ordinal":0,"id":4},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":0,"id":5},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":1,"id":6},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":2,"id":7},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":3,"id":8},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":4,"id":9},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":5,"id":10},
    \\ {"purpose":"RetainedMerkleLayers","ordinal":6,"id":11},
    \\ {"purpose":"TranscriptInput","ordinal":3,"id":12}
    \\]
;

const Args = struct {
    warmups: usize = 2,
    samples: usize = 11,
    mode: arena_binding.StreamingCommitmentBenchmarkMode = .automatic,
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    parsed_schedule: std.json.Parsed(std.json.Value),
    bindings: [binding_count]arena_plan.Binding,
    resident_arena: arena_plan.ResidentArena,
    expected_root: Hasher.Hash,
    total_bytes: u64,

    fn init(allocator: std.mem.Allocator, metal: *metal_runtime.Runtime) !Fixture {
        var parsed_schedule = try std.json.parseFromSlice(std.json.Value, allocator, schedule_json, .{});
        errdefer parsed_schedule.deinit();

        var small_base_tree = try twiddles.precomputeM31(
            allocator,
            stwo.prover.poly.circle.CanonicCoset.new(small_base_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &small_base_tree);
        var small_eval_tree = try twiddles.precomputeM31(
            allocator,
            stwo.prover.poly.circle.CanonicCoset.new(small_eval_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &small_eval_tree);
        var large_base_tree = try twiddles.precomputeM31(
            allocator,
            stwo.prover.poly.circle.CanonicCoset.new(large_base_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &large_base_tree);
        var large_eval_tree = try twiddles.precomputeM31(
            allocator,
            stwo.prover.poly.circle.CanonicCoset.new(large_eval_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &large_eval_tree);

        var small_coefficients: [group_width][1 << small_base_log]M31 = undefined;
        var small_evaluations: [group_width][1 << small_eval_log]M31 = undefined;
        var large_coefficients: [group_width][1 << large_base_log]M31 = undefined;
        var large_evaluations: [group_width][1 << large_eval_log]M31 = undefined;
        var small_coefficient_slices: [group_width][]M31 = undefined;
        var small_evaluation_slices: [group_width][]M31 = undefined;
        var large_coefficient_slices: [group_width][]M31 = undefined;
        var large_evaluation_slices: [group_width][]M31 = undefined;
        for (0..group_width) |column| {
            for (&small_coefficients[column], 0..) |*value, row|
                value.* = M31.fromCanonical(@intCast((column * 313 + row * 17 + 9) % m31.Modulus));
            for (&large_coefficients[column], 0..) |*value, row|
                value.* = M31.fromCanonical(@intCast(((column + group_width) * 313 + row * 17 + 9) % m31.Modulus));
            small_coefficient_slices[column] = &small_coefficients[column];
            small_evaluation_slices[column] = &small_evaluations[column];
            large_coefficient_slices[column] = &large_coefficients[column];
            large_evaluation_slices[column] = &large_evaluations[column];
        }
        try circle_poly.interpolateBuffersWithTwiddles(
            &small_coefficient_slices,
            stwo.prover.poly.circle.CanonicCoset.new(small_base_log).circleDomain(),
            twiddles.TwiddleTree([]const M31).init(small_base_tree.root_coset, small_base_tree.twiddles, small_base_tree.itwiddles),
        );
        try circle_poly.interpolateBuffersWithTwiddles(
            &large_coefficient_slices,
            stwo.prover.poly.circle.CanonicCoset.new(large_base_log).circleDomain(),
            twiddles.TwiddleTree([]const M31).init(large_base_tree.root_coset, large_base_tree.twiddles, large_base_tree.itwiddles),
        );
        for (small_coefficients, &small_evaluations) |coefficient, *evaluation| {
            @memcpy(evaluation[0..coefficient.len], &coefficient);
            @memset(evaluation[coefficient.len..], M31.zero());
        }
        for (large_coefficients, &large_evaluations) |coefficient, *evaluation| {
            @memcpy(evaluation[0..coefficient.len], &coefficient);
            @memset(evaluation[coefficient.len..], M31.zero());
        }
        try circle_poly.evaluateBuffersWithTwiddles(
            &small_evaluation_slices,
            stwo.prover.poly.circle.CanonicCoset.new(small_eval_log).circleDomain(),
            twiddles.TwiddleTree([]const M31).init(small_eval_tree.root_coset, small_eval_tree.twiddles, small_eval_tree.itwiddles),
        );
        try circle_poly.evaluateBuffersWithTwiddles(
            &large_evaluation_slices,
            stwo.prover.poly.circle.CanonicCoset.new(large_eval_log).circleDomain(),
            twiddles.TwiddleTree([]const M31).init(large_eval_tree.root_coset, large_eval_tree.twiddles, large_eval_tree.itwiddles),
        );

        var bindings: [binding_count]arena_plan.Binding = undefined;
        var cursor: u64 = 0;
        bind(&bindings, 0, group_width * @sizeOf(u32), &cursor);
        bind(&bindings, 1, group_width * @sizeOf(u32), &cursor);
        bind(&bindings, 2, group_width * (@as(u64, 1) << large_eval_log) * @sizeOf(u32), &cursor);
        bind(&bindings, 3, (@as(u64, 1) << large_eval_log) * 32, &cursor);
        bind(&bindings, 4, (@as(u64, 1) << large_eval_log) * 32, &cursor);
        var retained_hashes: u64 = (@as(u64, 1) << large_eval_log) / 2;
        for (5..12) |id| {
            bind(&bindings, id, retained_hashes * 32, &cursor);
            retained_hashes /= 2;
        }
        bind(&bindings, 12, 32, &cursor);
        for (0..column_count) |column| {
            const log_size = if (column < group_width) small_base_log else large_base_log;
            bind(&bindings, first_coefficient_binding + column, (@as(u64, 1) << @intCast(log_size)) * @sizeOf(u32), &cursor);
        }
        bind(&bindings, twiddle_binding, large_eval_tree.twiddles.len * @sizeOf(u32), &cursor);

        var resident_arena = try arena_plan.ResidentArena.initByteLength(metal, cursor);
        errdefer resident_arena.deinit();
        for (0..column_count) |column| {
            const binding = bindings[first_coefficient_binding + column];
            const destination = try resident_arena.bytes(binding);
            if (column < group_width) {
                @memcpy(destination, std.mem.sliceAsBytes(&small_coefficients[column]));
            } else {
                @memcpy(destination, std.mem.sliceAsBytes(&large_coefficients[column - group_width]));
            }
        }
        @memcpy(
            try resident_arena.bytes(bindings[twiddle_binding]),
            std.mem.sliceAsBytes(large_eval_tree.twiddles),
        );

        var cpu_columns: [column_count][]const M31 = undefined;
        for (0..column_count) |column| cpu_columns[column] = if (column < group_width)
            small_evaluations[column][0..]
        else
            large_evaluations[column - group_width][0..];
        const CpuTree = merkle_prover.MerkleProverLifted(Hasher);
        var cpu_tree = try CpuTree.commit(allocator, &cpu_columns);
        defer cpu_tree.deinit(allocator);

        return .{
            .allocator = allocator,
            .parsed_schedule = parsed_schedule,
            .bindings = bindings,
            .resident_arena = resident_arena,
            .expected_root = cpu_tree.root(),
            .total_bytes = cursor,
        };
    }

    fn deinit(self: *Fixture) void {
        self.resident_arena.deinit();
        self.parsed_schedule.deinit();
        self.* = undefined;
    }

    fn execute(
        self: *Fixture,
        metal: *metal_runtime.Runtime,
        mode: arena_binding.StreamingCommitmentBenchmarkMode,
    ) !arena_binding.CommitmentTelemetry {
        const empty_slots: []arena_plan.Slot = &.{};
        const empty_actions: []arena_plan.Action = &.{};
        const empty_offsets: []usize = &.{};
        const plan = arena_plan.Plan{
            .allocator = self.allocator,
            .bindings = &self.bindings,
            .slots = empty_slots,
            .actions = empty_actions,
            .action_offsets = empty_offsets,
            .total_bytes = self.total_bytes,
            .peak_live_bytes = self.total_bytes,
            .plan_hash = 0,
        };
        const telemetry = try arena_binding.executeStreamingCommitmentBenchmark(
            self.allocator,
            metal,
            &self.resident_arena,
            self.parsed_schedule.value.array.items,
            plan,
            self.bindings[first_coefficient_binding .. first_coefficient_binding + column_count],
            self.bindings[twiddle_binding],
            0,
            Hasher.leafSeed(),
            Hasher.nodeSeed(),
            mode,
        );
        const root = (try self.resident_arena.bytes(telemetry.root))[0..32];
        if (!std.mem.eql(u8, &self.expected_root, root)) return error.RootParityMismatch;
        const transcript_root = (try self.resident_arena.bytes(self.bindings[12]))[0..32];
        if (!std.mem.eql(u8, root, transcript_root)) return error.TranscriptRootMismatch;
        return telemetry;
    }
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try parseArgs(allocator);

    var init_timer = try std.time.Timer.start();
    var metal = try metal_runtime.Runtime.initFull();
    defer metal.deinit();
    const backend_init_seconds = seconds(init_timer.read());
    var fixture_timer = try std.time.Timer.start();
    var fixture = try Fixture.init(allocator, &metal);
    defer fixture.deinit();
    const fixture_setup_seconds = seconds(fixture_timer.read());

    var warmup_seconds: [max_warmups]f64 = undefined;
    for (warmup_seconds[0..args.warmups]) |*elapsed| {
        var timer = try std.time.Timer.start();
        _ = try fixture.execute(&metal, args.mode);
        elapsed.* = seconds(timer.read());
    }

    var request_seconds: [max_samples]f64 = undefined;
    var gpu_milliseconds: [max_samples]f64 = undefined;
    var epoch_stats: ?metal_runtime.CommandEpochStats = null;
    for (request_seconds[0..args.samples], gpu_milliseconds[0..args.samples]) |*request, *gpu| {
        var timer = try std.time.Timer.start();
        const telemetry = try fixture.execute(&metal, args.mode);
        request.* = seconds(timer.read());
        gpu.* = telemetry.gpu_ms;
        if (epochStats(telemetry)) |stats| {
            if (epoch_stats) |expected| try expectEqualStats(expected, stats);
            epoch_stats = stats;
        }
    }

    var sorted_request = request_seconds;
    var sorted_gpu = gpu_milliseconds;
    std.mem.sort(f64, sorted_request[0..args.samples], {}, std.sort.asc(f64));
    std.mem.sort(f64, sorted_gpu[0..args.samples], {}, std.sort.asc(f64));
    const root_hex = std.fmt.bytesToHex(fixture.expected_root, .lower);
    const result = .{
        .schema_version = 1,
        .scope = "cairo_streaming_commitment_only",
        .callsite = "integrations.cairo_metal.arena_binding.executeStreamingCommitmentBenchmark",
        .production_wrapper = "integrations.cairo_metal.arena_binding.executeStreamingCommitment",
        .execution_mode = @tagName(args.mode),
        .proof_generated = false,
        .prove_seconds = @as(?f64, null),
        .root_parity = true,
        .root_blake2s_hex = root_hex,
        .workload = .{
            .columns = column_count,
            .groups = 2,
            .base_logs = [_]u32{ small_base_log, large_base_log },
            .evaluation_logs = [_]u32{ small_eval_log, large_eval_log },
            .arena_bytes = fixture.total_bytes,
        },
        .warmups = args.warmups,
        .samples = args.samples,
        .backend_init_seconds = backend_init_seconds,
        .fixture_setup_seconds = fixture_setup_seconds,
        .warmup_request_seconds = warmup_seconds[0..args.warmups],
        .request_seconds = request_seconds[0..args.samples],
        .request_median_seconds = sorted_request[args.samples / 2],
        .gpu_milliseconds = gpu_milliseconds[0..args.samples],
        .gpu_median_milliseconds = sorted_gpu[args.samples / 2],
        .command_epoch = epoch_stats,
    };
    var buffer: [8192]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(result, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn bind(bindings: *[binding_count]arena_plan.Binding, id: usize, size_bytes: u64, cursor: *u64) void {
    cursor.* = std.mem.alignForward(u64, cursor.*, 256);
    bindings[id] = .{
        .logical_id = @intCast(id),
        .slot = @intCast(id),
        .offset_bytes = cursor.*,
        .size_bytes = size_bytes,
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
    cursor.* += size_bytes;
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);
    var result = Args{};
    var index: usize = 1;
    while (index < process_args.len) : (index += 2) {
        if (index + 1 >= process_args.len) return error.InvalidArguments;
        const name = process_args[index];
        const encoded = process_args[index + 1];
        if (std.mem.eql(u8, name, "--warmups")) {
            const value = try std.fmt.parseInt(usize, encoded, 10);
            if (value > max_warmups) return error.InvalidArguments;
            result.warmups = value;
        } else if (std.mem.eql(u8, name, "--samples")) {
            const value = try std.fmt.parseInt(usize, encoded, 10);
            if (value == 0 or value > max_samples or value % 2 == 0) return error.InvalidArguments;
            result.samples = value;
        } else if (std.mem.eql(u8, name, "--mode")) {
            result.mode = if (std.mem.eql(u8, encoded, "automatic"))
                .automatic
            else if (std.mem.eql(u8, encoded, "synchronous"))
                .synchronous
            else
                return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    return result;
}

fn epochStats(telemetry: arena_binding.CommitmentTelemetry) ?metal_runtime.CommandEpochStats {
    if (comptime @hasField(arena_binding.CommitmentTelemetry, "command_epoch_stats"))
        return telemetry.command_epoch_stats;
    return null;
}

fn expectEqualStats(expected: metal_runtime.CommandEpochStats, actual: metal_runtime.CommandEpochStats) !void {
    if (expected.command_buffers != actual.command_buffers or
        expected.wait_count != actual.wait_count or
        expected.intermediate_wait_count != actual.intermediate_wait_count or
        expected.compute_encoders != actual.compute_encoders or
        expected.blit_encoders != actual.blit_encoders or
        expected.dispatches != actual.dispatches)
        return error.CommandTelemetryDrift;
}

fn seconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
}

test "metal: bounded Cairo benchmark reaches the production streaming commitment" {
    var metal = try metal_runtime.Runtime.initFull();
    defer metal.deinit();
    var fixture = try Fixture.init(std.testing.allocator, &metal);
    defer fixture.deinit();
    const telemetry = try fixture.execute(&metal, .automatic);
    const stats = telemetry.command_epoch_stats orelse return error.MissingCommandEpochTelemetry;
    try std.testing.expectEqual(@as(u64, 1), stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 1), stats.wait_count);
    try std.testing.expectEqual(@as(u64, 0), stats.intermediate_wait_count);
    try std.testing.expectEqual(@as(u64, 17), stats.compute_encoders);
    try std.testing.expectEqual(@as(u64, 1), stats.blit_encoders);
    try std.testing.expectEqual(@as(u64, 17), stats.dispatches);
}
