//! Independent preprocessed commitment, optionally overlapped with the CPU
//! witness. Only the joined coordinator resumes the transcript and scheme.
const std = @import("std");
const builtin = @import("builtin");
const prover = @import("stwo_prover_engine");
const preprocessed = @import("../preprocessed/mod.zig");

pub fn commit(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    target: *const preprocessed.trace.Spec,
    pedersen: ?*const preprocessed.pedersen_table.Table,
    binding: preprocessed.product_cache.Binding,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*prover.stage_profile.Recorder,
) !void {
    var stage = try prover.stage_profile.StageScope.begin(recorder, "preprocessed_materialize_and_commit", "Preprocessed materialize and commit");
    defer stage.end();
    const native_compact = comptime if (@hasDecl(Engine.Backend, "supportsCompactStreaming")) Engine.Backend.supportsCompactStreaming(Engine.Hasher) else false;
    if (comptime Engine.Backend.MerkleTree(Engine.Hasher) == prover.vcs_lifted.prover.MerkleProverLifted(Engine.Hasher) or native_compact) {
        if (scheme.compact_polynomial_storage and !(if (recorder) |r| r.capture_work else false))
            return commitCompact(Engine, allocator, target, pedersen, binding, scheme, channel, recorder);
    }
    const columns = blk: {
        var materialize = try prover.stage_profile.StageScope.begin(recorder, "preprocessed_column_materialize", "Preprocessed column materialization");
        defer materialize.end();
        break :blk try target.materializeWithPedersen(allocator, pedersen);
    };
    // Arm only this thread's immediately following commit. Main-witness work
    // cannot observe or consume this protocol-bound artifact seam.
    preprocessed.tree_digest_cache.arm(allocator, binding, recorder);
    defer preprocessed.tree_digest_cache.disarm();
    const prepared_cache = comptime @hasDecl(Engine.Backend, "supports_preprocessed_preparation_cache") and Engine.Backend.supports_preprocessed_preparation_cache;
    if (prepared_cache) preprocessed.prepared_columns_cache.arm(allocator, binding, recorder);
    defer if (prepared_cache) preprocessed.prepared_columns_cache.disarm();
    var committing = try prover.stage_profile.StageScope.begin(recorder, "preprocessed_column_commit", "Preprocessed column commitment");
    defer committing.end();
    try Engine.commit(scheme, allocator, columns, recorder, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

/// Source generation shares the existing PCS batch builder. Only the fixed
/// trace is streamed here; no full public source allocation overlaps witness
/// production. The builder retains compact coefficients and bounded LDE scratch.
fn commitCompact(comptime Engine: type, allocator: std.mem.Allocator, target: *const preprocessed.trace.Spec, pedersen: ?*const preprocessed.pedersen_table.Table, binding: preprocessed.product_cache.Binding, scheme: *Engine.Scheme, channel: *Engine.Channel, recorder: ?*prover.stage_profile.Recorder) !void {
    preprocessed.tree_digest_cache.arm(allocator, binding, recorder);
    defer preprocessed.tree_digest_cache.disarm();
    const prepared_cache = comptime @hasDecl(Engine.Backend, "supports_preprocessed_preparation_cache") and Engine.Backend.supports_preprocessed_preparation_cache;
    if (prepared_cache) preprocessed.prepared_columns_cache.arm(allocator, binding, recorder);
    defer if (prepared_cache) preprocessed.prepared_columns_cache.disarm();
    var builder = scheme.streamingTreeBuilder(allocator, 64);
    errdefer builder.deinit();
    const plan = try allocator.alloc(prover.pcs.ColumnEvaluation, target.columns.len);
    defer allocator.free(plan);
    const order = try allocator.alloc(usize, target.columns.len);
    defer allocator.free(order);
    for (target.columns, plan, order, 0..) |column, *entry, *index, i| {
        entry.* = .{ .log_size = column.log_size, .values = &.{} };
        index.* = i;
    }
    try builder.planCompactTree(plan, order);
    const byte_limit = 512 * 1024 * 1024;
    const factor = std.math.add(usize, 1, @as(usize, 1) << @intCast(scheme.config.fri_config.log_blowup_factor)) catch return error.InvalidPreprocessedTrace;
    var next: usize = 0;
    while (next < target.columns.len) {
        var end = next;
        var bytes: usize = 0;
        while (end < target.columns.len and end - next < 64) : (end += 1) {
            const column = target.columns[end];
            if (column.log_size >= @bitSizeOf(usize)) return error.InvalidPreprocessedTrace;
            const required = try std.math.mul(usize, try std.math.mul(usize, @as(usize, 1) << @intCast(column.log_size), @sizeOf(@import("stwo_core").fields.m31.M31)), factor);
            if (end != next and (required > byte_limit or bytes > byte_limit - required)) break;
            bytes = try std.math.add(usize, bytes, required);
        }
        const columns = blk: {
            var stage = try prover.stage_profile.StageScope.begin(recorder, "preprocessed_column_materialize", "Preprocessed column materialization");
            defer stage.end();
            break :blk try target.materializeColumnRangeWithPedersen(allocator, pedersen, next, end);
        };
        // The standard builder consumes each source batch on success and error.
        try builder.addColumnsOwned(columns, recorder);
        next = end;
    }
    var stage = try prover.stage_profile.StageScope.begin(recorder, "preprocessed_column_commit", "Preprocessed column commitment");
    defer stage.end();
    try builder.commitWithRecorder(recorder, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

pub fn Worker(comptime Engine: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        target: *const preprocessed.trace.Spec,
        pedersen: ?*const preprocessed.pedersen_table.Table,
        binding: preprocessed.product_cache.Binding,
        scheme: *Engine.Scheme,
        channel: *Engine.Channel,
        recorder: ?prover.stage_profile.Recorder,
        // A background coordinator may borrow the request's existing pool.
        // Helpers still remain unbound, so transforms never create nested waves.
        pool: ?*prover.work_pool.WorkPool = null,
        thread: ?std.Thread = null,
        started: bool = false,
        err: ?anyerror = null,

        pub fn init(
            allocator: std.mem.Allocator,
            target: *const preprocessed.trace.Spec,
            pedersen: ?*const preprocessed.pedersen_table.Table,
            binding: preprocessed.product_cache.Binding,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            parent: ?*prover.stage_profile.Recorder,
        ) Self {
            return .{
                .allocator = allocator,
                .target = target,
                .pedersen = pedersen,
                .binding = binding,
                .scheme = scheme,
                .channel = channel,
                .pool = prover.work_pool.currentScopedPool(),
                .recorder = if (parent) |p| prover.stage_profile.Recorder.initWithOptions(allocator, p.runtime, p.example, .{
                    .capture_tasks = p.capture_tasks,
                    .capture_work = false,
                }) else null,
            };
        }

        pub fn start(self: *Self, parent: ?*prover.stage_profile.Recorder) void {
            const device = comptime @hasDecl(Engine, "Backend") and
                @hasDecl(Engine.Backend, "adopts_source_trace_arena") and Engine.Backend.adopts_source_trace_arena;
            const host = comptime @hasDecl(Engine, "Backend") and
                @hasDecl(Engine.Backend, "supports_preprocessed_overlap") and Engine.Backend.supports_preprocessed_overlap;
            if (comptime builtin.single_threaded or (!device and !host)) return;
            // Small preprocessed variants and exact-work audit requests keep
            // the serial lane. Thread creation failure also declines cleanly.
            if (self.target.variant.traceCellCount() < 1 << 26 or
                (if (parent) |p| p.capture_work else false)) return;
            const enabled = if (std.posix.getenv("STWO_CAIRO_OVERLAP_PREPROCESSED")) |flag| std.mem.eql(u8, flag, "1") else device or (comptime @hasDecl(Engine, "Backend") and @hasDecl(Engine.Backend, "default_preprocessed_overlap") and Engine.Backend.default_preprocessed_overlap);
            if (!enabled) return;
            self.thread = std.Thread.spawn(.{}, run, .{self}) catch return;
            self.started = true;
        }

        fn run(self: *Self) void {
            var pool_binding: ?prover.work_pool.ScopedPoolBinding = null;
            if (self.pool) |pool| {
                pool_binding = prover.work_pool.ScopedPoolBinding.initIfNeeded(pool) catch |err| {
                    self.err = err;
                    return;
                };
            }
            defer if (pool_binding) |*bound| bound.deinit();
            commit(Engine, self.allocator, self.target, self.pedersen, self.binding, self.scheme, self.channel, if (self.recorder) |*r| r else null) catch |err| {
                self.err = err;
            };
        }

        pub fn finish(self: *Self, parent: ?*prover.stage_profile.Recorder) !void {
            if (!self.started) return commit(Engine, self.allocator, self.target, self.pedersen, self.binding, self.scheme, self.channel, parent);
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }
            if (self.err) |err| return err;
            if (parent) |p| try p.adoptJoined(&self.recorder.?);
        }

        pub fn deinit(self: *Self) void {
            // Every witness/geometry/allocation error joins before the scheme,
            // tables, target or recorder may be destroyed by the caller.
            if (self.thread) |thread| thread.join();
            if (self.recorder) |*r| r.deinit();
            self.* = undefined;
        }
    };
}

test "preprocessed worker cleanup joins before borrowed storage may be reclaimed" {
    const MockEngine = struct {
        pub const Scheme = void;
        pub const Channel = void;
    };
    const Context = struct {
        completed: std.atomic.Value(bool) = .init(false),
        fn run(context: *@This()) void {
            // Simulate a worker that still owns borrowed state when cleanup
            // begins, as on witness allocation/geometry failure.
            std.Thread.sleep(std.time.ns_per_ms);
            context.completed.store(true, .release);
        }
    };
    var context = Context{};
    var worker = Worker(MockEngine){
        .allocator = std.testing.allocator,
        .target = undefined,
        .pedersen = null,
        .binding = undefined,
        .scheme = undefined,
        .channel = undefined,
        .recorder = null,
        .thread = try std.Thread.spawn(.{}, Context.run, .{&context}),
        .started = true,
    };
    worker.deinit();
    try std.testing.expect(context.completed.load(.acquire));
}
