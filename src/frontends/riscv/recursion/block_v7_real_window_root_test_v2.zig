//! Declared actual machine window -> v7 originals -> one detached complete
//! recursive root. This never claims the skipped prefix or an Ethereum block.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../prover/block_v7_real_window_capture_v1.zig");
const Run = @import("../prover/block_v7_real_window_execution_v2.zig");
const Complete = @import("block_v7_complete_cpu_producer_v1.zig");
const SharedComplete = Complete.For(true);
const Receiver = @import("block_v7_mixed_receiver_v1.zig");
const SharedReceiver = @import("block_v7_shared_epoch_mixed_receiver_v1.zig");
const Bounded = @import("block_v7_bounded_complete_cpu_producer_v1.zig");
const BatchReceiver = @import("block_v7_mixed_batch_receiver_v1.zig");
const Profile = @import("blake3_execution_parent_protocol.zig").Profile;
const RootResult = union(enum) {
    direct: Complete.Output,
    shared: SharedComplete.Output,
    bounded: Bounded.Output,
    fn deinit(self: *RootResult) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
    fn metadata(self: *const RootResult) *@import("block_v7_mixed_metadata_v1.zig").Owned {
        return switch (self.*) {
            inline else => |value| value.metadata,
        };
    }
    fn bytes(self: *const RootResult) []const u8 {
        return switch (self.*) {
            .direct => |value| value.bytes,
            .shared => |value| value.bytes,
            .bounded => |value| value.root.bytes,
        };
    }
    fn verify(self: *const RootResult, a: std.mem.Allocator, input: @import("block_v7_mixed_inputs_v1.zig").Input, limits: @import("../prover/block_v7_global_public_closure_v1.zig").Limits) !@import("../prover/block_v7_global_public_closure_v1.zig").Summary {
        const trusted = self.metadata().trusted;
        switch (self.*) {
            .direct => |value| {
                var verified = try Receiver.verify(a, value.bytes, trusted, input, value.key, value.wires, limits);
                defer verified.deinit();
                return verified.summary;
            },
            .shared => |value| {
                var verified = try SharedReceiver.verify(a, value.bytes, trusted, input, value.key, value.wires, limits);
                defer verified.deinit();
                return verified.summary;
            },
            .bounded => |value| {
                var verified = try BatchReceiver.verify(a, value.root.bytes, trusted, input, value.counts, value.pins, value.root.key, value.root.wires, .{ .global = limits });
                defer verified.deinit();
                return verified.summary;
            },
        }
    }
};
const Consumer = struct {
    pub const Result = RootResult;
    pub fn consume(f: Run.Fixture) !Result {
        if (f.original.scope != .declared_window) return error.WrongWindowTheorem;
        const selected: Profile = if (std.meta.eql(f.input.epoch.config, Profile.csp_q70_pow26.config()))
            .csp_q70_pow26
        else if (std.meta.eql(f.input.epoch.config, Profile.diagnostic_q8_pow0.config()))
            .diagnostic_q8_pow0
        else
            return error.UnsupportedWindowRootSecurity;
        // Resource policy is independent of AIR/PCS admission. The shared
        // request allocator remains the hard cap; the optional larger limits
        // allow this machine's RAM to reduce recursive proof count.
        const preparation_mib = try option(usize, "STWO_V7_WINDOW_ROOT_PREPARATION_MIB", 8192);
        const row_log = try option(u32, "STWO_V7_WINDOW_ROOT_ROW_LOG", 25);
        if (preparation_mib == 0 or preparation_mib > 32768 or row_log == 0 or row_log > 27) return error.InvalidWindowRootResources;
        const preparation_bytes = try std.math.mul(usize, preparation_mib, 1 << 20);
        const parallel_families = try option(u32, "STWO_V7_WINDOW_ROOT_PARALLEL_FAMILIES", 1);
        const parallel_preparation = try option(usize, "STWO_V7_WINDOW_ROOT_PARALLEL_PREPARATION", 1);
        const batch_size = try option(usize, "STWO_V7_WINDOW_ROOT_BATCH_SIZE", 0);
        const shared_epoch = (try option(u1, "STWO_V7_WINDOW_SHARED_EPOCH_PREFIX", 0)) == 1;
        if (f.original_captures != null and batch_size != 0) return error.UnsupportedBoundedCaptureReuse;
        if (shared_epoch and (batch_size != 0 or row_log > 25 or parallel_families != 1)) return error.UnsupportedSharedEpochWindowGeometry;
        if (batch_size != 0) {
            if (batch_size > 64 or row_log > 25) return error.InvalidWindowRootResources;
            return .{ .bounded = try Bounded.produce(f.allocator, f.trusted, f.input, .{
                .profile = selected,
                .quotient_executor = f.quotient_executor,
                .composition_executor = f.composition_executor,
                .interaction_executor = f.interaction_executor,
                .reuse_native_compiler = (try option(u1, "STWO_V7_WINDOW_REUSE_NATIVE_COMPILER", 0)) == 1,
                .max_native_compiler_bytes = try std.math.mul(usize, try option(usize, "STWO_V7_WINDOW_NATIVE_COMPILER_MIB", 2048), 1 << 20),
                .parallel_families = parallel_families,
                .parallel_preparation = parallel_preparation,
                .max_direct_children = batch_size,
                .direct = .{ .max_row_log = row_log, .max_retained_bytes = preparation_bytes / 2, .max_planned_bytes = preparation_bytes },
                .reduction = .{ .max_bytes = preparation_bytes },
            }) };
        }
        return if (shared_epoch)
            produceDirect(true, f, selected, preparation_bytes, row_log, parallel_families, parallel_preparation)
        else
            produceDirect(false, f, selected, preparation_bytes, row_log, parallel_families, parallel_preparation);
    }
    fn produceDirect(comptime shared: bool, f: Run.Fixture, selected: Profile, preparation_bytes: usize, row_log: u32, parallel_families: u32, parallel_preparation: usize) !Result {
        const Selected = Complete.For(shared);
        const output = try Selected.produce(f.allocator, f.trusted, f.input, .{
            .original_captures = f.original_captures,
            .profile = selected,
            .quotient_executor = f.quotient_executor,
            .composition_executor = f.composition_executor,
            .interaction_executor = f.interaction_executor,
            .reuse_native_compiler = (try option(u1, "STWO_V7_WINDOW_REUSE_NATIVE_COMPILER", 0)) == 1,
            .max_native_compiler_bytes = try std.math.mul(usize, try option(usize, "STWO_V7_WINDOW_NATIVE_COMPILER_MIB", 2048), 1 << 20),
            .native_compiler_parallelism = parallel_families,
            .parallel_preparation = parallel_preparation,
            .fixed = if (shared) .{ .max_bytes = preparation_bytes, .max_row_log = row_log } else .{ .parallel_families = parallel_families, .max_bytes = preparation_bytes, .max_row_log = row_log },
            .join = .{ .max_join_bytes = preparation_bytes, .max_row_log = row_log },
        });
        return if (shared) .{ .shared = output } else .{ .direct = output };
    }
};
test "v7 real nonterminal window reaches one detached complete recursive root" {
    try runWithExecutor(null);
}
/// Product-level benchmarks can inject an owned numeric implementation without
/// making this frontend depend on a CUDA integration or ambient device state.
pub fn runWithExecutor(quotient_executor: ?*const Engine.pcs.QuotientExecutor) !void {
    return runWithExecutors(quotient_executor, null);
}
pub fn runWithExecutors(quotient_executor: ?*const Engine.pcs.QuotientExecutor, composition_executor: ?*const @import("blake3_parent_composition_executor_v1.zig").Executor) !void {
    return runWithAllExecutors(quotient_executor, composition_executor, null);
}
pub fn runWithAllExecutors(quotient_executor: ?*const Engine.pcs.QuotientExecutor, composition_executor: ?*const @import("blake3_parent_composition_executor_v1.zig").Executor, interaction_executor: ?*const @import("blake3_parent_interaction_executor_v1.zig").Executor) !void {
    const benchmark = std.process.hasEnvVarConstant("STWO_V7_WINDOW_BENCHMARK");
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(if (benchmark) std.heap.smp_allocator else std.testing.allocator, 40 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const tiny = @import("../prover/tests/block_v7_keccak_execution_test_support.zig").elf();
    const real = std.posix.getenv("STWO_V7_WINDOW_ELF");
    const elf = if (real) |path| try std.fs.cwd().readFileAlloc(a, path, 32 << 20) else try a.dupe(u8, &tiny);
    defer a.free(elf);
    const input = if (std.posix.getenv("STWO_V7_WINDOW_INPUT")) |path| try std.fs.cwd().readFileAlloc(a, path, 4 << 20) else try a.dupe(u8, &.{});
    defer a.free(input);
    const loading_ns = phase.lap();
    const span = Capture.Window{
        .skip_cycles = try option(u64, "STWO_V7_WINDOW_SKIP", if (real != null) 1 else 6),
        .cycles = try option(u32, "STWO_V7_WINDOW_CYCLES", if (real != null) 32768 else 3),
    };
    var states = try WindowStates.prepare(a, elf, input, span);
    defer states.deinit(a);
    const capture_ns = phase.lap();
    const workers = try option(u32, "STWO_V7_WINDOW_WORKERS", 4);
    if (workers == 0 or workers > Engine.work_pool.MAX_WORKERS) return error.InvalidBenchmarkWorkerCount;
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const selected: Profile = if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_CANONICAL")) .csp_q70_pow26 else .diagnostic_q8_pow0;
    const cycles_per_segment = try option(u32, "STWO_V7_WINDOW_SEGMENT_CYCLES", @intCast(try std.math.divCeil(u64, span.cycles, 2)));
    const resources = @import("../prover/tests/block_v7_real_window_benchmark_resources.zig");
    const storage: @import("../prover/block_v7_input_storage_v1.zig").Policy = if ((try option(u1, "STWO_V7_WINDOW_RESIDENT_MEMORY", 0)) == 1) .resident else .{ .coefficients = .{} };
    var result = try Run.run(budget, temporary.dir, .{
        .elf = elf,
        .elf_sha256 = Capture.sha(elf),
        .cycles = span.cycles,
        .config = selected.config(),
        .state = .{ .incoming = states.incoming, .outgoing = states.outgoing, .trusted = .{
            .elf_sha256 = Capture.sha(elf),
            .incoming_sha256 = states.incoming.identity(),
            .outgoing_sha256 = states.outgoing.identity(),
            .window = span,
        } },
    }, .{
        .segment_cycles = cycles_per_segment,
        .reuse_original_captures = (try option(u1, "STWO_V7_WINDOW_REUSE_ORIGINAL_CAPTURES", 0)) == 1,
        .capture_limits = .{ .max_bytes = try std.math.mul(usize, try option(usize, "STWO_V7_WINDOW_ORIGINAL_CAPTURE_MIB", 4096), 1 << 20) },
        .quotient_executor = quotient_executor,
        .composition_executor = composition_executor,
        .interaction_executor = interaction_executor,
        .native_layout_mode = try nativeLayout(),
        .sparse_window_initialization = (try option(u1, "STWO_V7_WINDOW_SPARSE_INITIALIZATION", 0)) == 1,
        .native_prove = .{
            .fused_projection_rows = (try option(u1, "STWO_V7_WINDOW_FUSED_PROJECTION_ROWS", 0)) == 1,
            .native_main_cache_bytes = try std.math.mul(usize, try option(usize, "STWO_V7_WINDOW_NATIVE_MAIN_CACHE_MIB", 256), 1 << 20),
            .deep_group_budget = try Engine.pcs.DeepGroupBudget.parseMiB(try option(u32, "STWO_V7_WINDOW_DEEP_GROUP_MIB", 1)),
        },
        .max_segments = 64,
        .max_callers = 64,
        .max_events = 1 << 24,
        .active_callers = true,
        .memory = resources.memory(storage),
    }, &pool, Consumer);
    defer result.value.deinit();
    const metadata = result.value.metadata();
    const producer_ns = phase.lap();
    // Run has destroyed all original proof/witness/PCS owners and checkpoints.
    var remaining = temporary.dir.iterate();
    try std.testing.expect((try remaining.next()) == null);
    const verified = try result.value.verify(a, metadata.input(), resources.receiver(storage));
    const verification_ns = phase.lap();
    try std.testing.expectEqual(.declared_window, verified.scope);
    try std.testing.expectEqual(@as(u64, span.cycles), verified.cycles);
    try std.testing.expectEqual(result.stats.events, verified.ram_events);
    try std.testing.expectEqual(result.stats.fetches, verified.program_fetches);
    // These cancel in the public delta but must remain individually bound by
    // the root's original-verifier transcript and composition equations.
    if (!benchmark) {
        var changed = metadata.window_memory.?.*;
        const claims = try a.dupe(@TypeOf(changed.input.claims.ram[0]), changed.input.claims.ram);
        defer a.free(claims);
        const Q = @import("stwo_core").fields.qm31.QM31;
        claims[0].sums[29] = claims[0].sums[29].add(Q.one());
        claims[0].sums[30] = claims[0].sums[30].sub(Q.one());
        changed.input.claims.ram = claims;
        var proposed = metadata.input();
        proposed.window_memory = &changed;
        if (result.value.verify(a, proposed, resources.receiver(storage))) |_| {
            return error.AcceptedCompensatedWindowDelta;
        } else |_| {}
    }
    const request_ns = whole.read();
    const rss = try @import("../prover/block_v4_cpu_cli_rss_v1.zig").peakBytes();
    const report = .{
        .schema = 3,
        .scope = "declared_nonterminal_window_to_complete_recursive_root",
        .ethereum_block = false,
        .skipped_prefix_proved = false,
        .external_elf = real != null,
        .external_capsules = states.external_capsules,
        .capsule_bytes_loaded = states.bytes_loaded,
        .hostile_controls_included = !benchmark,
        .canonical_security = selected == .csp_q70_pow26,
        .external_quotient_executor = quotient_executor != null,
        .external_composition_executor = composition_executor != null,
        .external_interaction_executor = interaction_executor != null,
        .query_count = selected.config().fri_config.n_queries,
        .pow_bits = selected.config().pow_bits,
        .worker_count = workers,
        .native_layout_mode = @tagName(try nativeLayout()),
        .fused_projection_rows = (try option(u1, "STWO_V7_WINDOW_FUSED_PROJECTION_ROWS", 0)) == 1,
        .sparse_window_initialization = (try option(u1, "STWO_V7_WINDOW_SPARSE_INITIALIZATION", 0)) == 1,
        .resident_memory = (try option(u1, "STWO_V7_WINDOW_RESIDENT_MEMORY", 0)) == 1,
        .native_main_cache_mib = try option(usize, "STWO_V7_WINDOW_NATIVE_MAIN_CACHE_MIB", 256),
        .deep_group_mib = try option(u32, "STWO_V7_WINDOW_DEEP_GROUP_MIB", 1),
        .elf_sha256 = std.fmt.bytesToHex(Capture.sha(elf), .lower),
        .original_input_used = !states.external_capsules,
        .input_sha256 = if (states.external_capsules) @as(?[64]u8, null) else std.fmt.bytesToHex(Capture.sha(input), .lower),
        .incoming_sha256 = std.fmt.bytesToHex(states.incoming.identity(), .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(states.outgoing.identity(), .lower),
        .skip_cycles = span.skip_cycles,
        .cycles = span.cycles,
        .segment_cycles = cycles_per_segment,
        .root_preparation_mib = try option(usize, "STWO_V7_WINDOW_ROOT_PREPARATION_MIB", 8192),
        .root_row_log = try option(u32, "STWO_V7_WINDOW_ROOT_ROW_LOG", 25),
        .root_batch_size = try option(usize, "STWO_V7_WINDOW_ROOT_BATCH_SIZE", 0),
        .root_parallel_families = try option(u32, "STWO_V7_WINDOW_ROOT_PARALLEL_FAMILIES", 1),
        .root_parallel_preparation = try option(usize, "STWO_V7_WINDOW_ROOT_PARALLEL_PREPARATION", 1),
        .reuse_native_compiler = (try option(u1, "STWO_V7_WINDOW_REUSE_NATIVE_COMPILER", 0)) == 1,
        .shared_epoch_prefix = (try option(u1, "STWO_V7_WINDOW_SHARED_EPOCH_PREFIX", 0)) == 1,
        .materialized_parent_polynomials = std.process.hasEnvVarConstant("STWO_RISCV_MATERIALIZED_POLYNOMIALS"),
        .reuse_original_captures = (try option(u1, "STWO_V7_WINDOW_REUSE_ORIGINAL_CAPTURES", 0)) == 1,
        .original_capture_mib = try option(usize, "STWO_V7_WINDOW_ORIGINAL_CAPTURE_MIB", 4096),
        .native_compiler_mib = try option(usize, "STWO_V7_WINDOW_NATIVE_COMPILER_MIB", 2048),
        .root_kind = @tagName(result.value),
        .loading_ns = loading_ns,
        .capture_or_capsule_admission_ns = capture_ns,
        .producer_ns = producer_ns,
        .independent_verification_ns = verification_ns,
        .whole_ns = request_ns,
        .prepared_window_to_verified_ns = producer_ns + verification_ns,
        .source = result.stats,
        .recursive = if (result.value == .direct) result.value.direct.stats else @as(?Complete.Stats, null),
        .recursive_shared = if (result.value == .shared) result.value.shared.stats else @as(?SharedComplete.Stats, null),
        .recursive_bounded = if (result.value == .bounded) result.value.bounded.stats else @as(?Bounded.Stats, null),
        .recursive_windows = if (result.value == .bounded) result.value.bounded.windows else @as(?[]Bounded.WindowStats, null),
        .recursive_proof_count = if (result.value == .bounded) result.value.bounded.windows.len + 1 else @as(usize, 1),
        .root_bytes = result.value.bytes().len,
        .root_sha256 = std.fmt.bytesToHex(Capture.sha(result.value.bytes()), .lower),
        .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
        .process_peak_rss_bytes = rss,
        .originals_destroyed = true,
        .complete_global_closure = true,
        .verified = true,
    };
    std.debug.print("V7_WINDOW_ROOT {f}\n", .{std.json.fmt(report, .{})});
    if (std.posix.getenv("STWO_V7_WINDOW_REPORT")) |path| {
        const json = try std.json.Stringify.valueAlloc(a, report, .{});
        defer a.free(json);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = json });
    }
    if (std.posix.getenv("STWO_V7_WINDOW_ROOT_OUTPUT")) |path|
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = result.value.bytes() });
}
fn option(comptime T: type, name: [:0]const u8, default: T) !T {
    return if (std.posix.getenv(name)) |value| try std.fmt.parseInt(T, value, 10) else default;
}
fn nativeLayout() !@import("../prover/block_v7_native_source_v1.zig").LayoutMode {
    const value = std.posix.getenv("STWO_V7_WINDOW_NATIVE_LAYOUT") orelse "canonical";
    if (std.mem.eql(u8, value, "canonical")) return .canonical_v1;
    if (std.mem.eql(u8, value, "degree-bounded-q2")) return .degree_bounded_q2_v1;
    return error.InvalidWindowNativeLayout;
}

/// A selected capsule pins the statement boundary; it never proves its prefix.
/// Keep only snapshots, rather than retaining a second execution trace while
/// the streaming producer constructs the actual committed witnesses.
const WindowStates = struct {
    incoming: Capture.Snapshot,
    outgoing: Capture.Snapshot,
    external_capsules: bool,
    bytes_loaded: usize,

    fn prepare(a: std.mem.Allocator, elf: []const u8, input: []const u8, span: Capture.Window) !WindowStates {
        if (std.posix.getenv("STWO_V7_WINDOW_INCOMING")) |incoming_path| {
            const outgoing_path = std.posix.getenv("STWO_V7_WINDOW_OUTGOING") orelse return error.MissingBenchmarkSnapshot;
            const elf_pin = try digest("STWO_V7_WINDOW_ELF_SHA256");
            if (!std.meta.eql(Capture.sha(elf), elf_pin)) return error.UntrustedRealWindowSource;
            const before = try std.fs.cwd().readFileAlloc(a, incoming_path, 64 << 20);
            defer a.free(before);
            const after = try std.fs.cwd().readFileAlloc(a, outgoing_path, 64 << 20);
            defer a.free(after);
            var incoming = try Capture.Snapshot.decode(a, before, try digest("STWO_V7_WINDOW_INCOMING_SHA256"), .{});
            errdefer incoming.deinit(a);
            const outgoing = try Capture.Snapshot.decode(a, after, try digest("STWO_V7_WINDOW_OUTGOING_SHA256"), .{});
            return .{ .incoming = incoming, .outgoing = outgoing, .external_capsules = true, .bytes_loaded = before.len + after.len };
        }
        if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_OUTGOING")) return error.MissingBenchmarkSnapshot;
        var captured = try Capture.capture(a, elf, input, .{ .elf = Capture.sha(elf), .input = Capture.sha(input) }, span, .{});
        captured.releaseExecution();
        return .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .external_capsules = false, .bytes_loaded = 0 };
    }

    fn deinit(self: *WindowStates, a: std.mem.Allocator) void {
        self.incoming.deinit(a);
        self.outgoing.deinit(a);
        self.* = undefined;
    }
};
fn digest(name: [:0]const u8) !Capture.Digest {
    const value = std.posix.getenv(name) orelse return error.MissingBenchmarkPin;
    var result: Capture.Digest = undefined;
    if ((try std.fmt.hexToBytes(&result, value)).len != result.len) return error.InvalidBenchmarkPin;
    return result;
}
