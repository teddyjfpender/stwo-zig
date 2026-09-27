//! Versioned native-v3/OpenV2 staged producer. Ready parents prove every child
//! verifier equation, publish deterministic hash-pinned files, then release
//! dependents. Metadata is provisional; only fresh complete reception promotes
//! a globally closed block. No legacy claim-zero forest admission is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const normalized = @import("../recursion/block_v5_open_child_frames_v2.zig");
const bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const preparation = @import("../recursion/block_v5_open_parent_preparation_v2.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const verified_mod = @import("../recursion/blake3_native_parent_verifier.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const dag_mod = @import("block_v5_open_exact_forest_plan_v1.zig");
const queue_mod = @import("block_v5_open_forest_queue_v1.zig");
const setup_cache = @import("block_v5_open_parent_setup_cache_v1.zig");
const Cache = setup_cache.ForBackend(Cpu);
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Common = @import("block_v5_open_forest_stage_v1.zig");
pub fn ForLeafAdapter(comptime LeafAdapter: type) type {
    return struct {
        pub const LeafFile = struct { policy: LeafAdapter.Policy, file: exact.FilePin };
        pub const ParentPin = Common.ParentPin;
        pub const OuterPin = Common.OuterPin;
        pub const Options = Common.Options;
        pub const Stage = Common.Stage;
        const leafPath = Common.leafPath;
        const parentPath = Common.parentPath;
        const OUTER_FILE = Common.OUTER_FILE;
        const openPinned = Common.openPinned;
        const writeProof = Common.writeProof;
        const Shared = struct {
            metadata_a: std.mem.Allocator,
            work: std.mem.Allocator,
            dir: std.fs.Dir,
            dag: *const dag_mod.Plan,
            leaves: []const LeafFile,
            native: []const normalized.Child,
            nodes: []normalized.Child,
            pins: []ParentPin,
            queue: *queue_mod.Queue,
            options: Options,
            metadata_mutex: std.Thread.Mutex = .{},
        };
        const Lane = struct {
            shared: *Shared,
            pool: engine.work_pool.WorkPool = undefined,
            cache: Cache = undefined,
            fn effectivePool(self: *Lane) *engine.work_pool.WorkPool {
                return self.shared.options.shared_pool orelse &self.pool;
            }
            fn deinitPool(self: *Lane) void {
                if (self.shared.options.shared_pool == null) self.pool.deinit();
            }
            fn run(self: *Lane) void {
                var binding = engine.work_pool.ScopedPoolBinding.init(self.effectivePool()) catch |err| {
                    self.shared.queue.stop(err);
                    return;
                };
                defer binding.deinit();
                while (self.shared.queue.take()) |index| {
                    self.proveOne(index) catch |err| {
                        self.shared.queue.cancel(index, err);
                        return;
                    };
                    self.shared.queue.complete(index) catch unreachable;
                }
            }
            fn proveOne(self: *Lane, index: u32) !void {
                const shared = self.shared;
                const task = shared.dag.tasks[index];
                var children: [4]normalized.Child = undefined; // borrowed policy snapshots
                var equations: [4]verified_mod.Verified = undefined;
                var count: usize = 0;
                defer for (equations[0..count]) |*equation| equation.deinit();
                for (task.children[0..task.childCount()], 0..) |edge, i| {
                    children[i] = childPolicy(shared, edge);
                    if (children[i].span.first_index != edge.slots.first or children[i].span.segment_count != edge.slots.capacity()) return error.UntrustedV5OpenStageEdge;
                    equations[i] = try loadEquation(shared, edge, &children[i]);
                    count += 1;
                }
                var captures: [4]*const verified_mod.Verified = undefined;
                for (equations[0..count], captures[0..count]) |*equation, *capture| capture.* = equation;
                var folded = try proveFold(shared.work, .local, children[0..count], captures[0..count], &self.cache);
                defer folded.deinit();
                if (folded.span.first_index != task.slots.first or folded.span.segment_count != task.slots.capacity()) return error.UntrustedV5OpenStageSpan;
                var name_buffer: [80]u8 = undefined;
                const name = try parentPath(index, &name_buffer);
                const file = try writeProof(shared.dir, name, folded.bytes, shared.options.max_proof_bytes);
                errdefer shared.dir.deleteFile(name) catch {};
                // Caller allocator need not support concurrent allocation. Only these
                // returned pin/snapshot allocations are serialized; proof work is not.
                shared.metadata_mutex.lock();
                defer shared.metadata_mutex.unlock();
                const schedule = try shared.metadata_a.dupe(bus.Wire, folded.prepared.wires);
                errdefer shared.metadata_a.free(schedule);
                shared.nodes[index] = try normalized.fromOpenV2(shared.metadata_a, folded.admission);
                var slots: [4]spans.SlotSpan = @splat(.{ .first = 0, .height = 0 });
                for (task.children[0..count], slots[0..count]) |edge, *slot| slot.* = edge.slots;
                shared.pins[index] = .{ .kind = task.kind, .slots = task.slots, .child_slots = slots, .node = .{ .key = folded.admission.key, .expected_id = folded.admission.expected_id, .schedule = schedule }, .file = file };
            }
        };
        fn childPolicy(shared: *const Shared, edge: dag_mod.Child) normalized.Child {
            return switch (edge.node) {
                .leaf => |i| shared.native[i],
                .parent => |i| shared.nodes[i],
            };
        }
        fn loadEquation(shared: *const Shared, edge: dag_mod.Child, child: *const normalized.Child) !verified_mod.Verified {
            var buffer: [80]u8 = undefined;
            const pin: exact.FilePin = switch (edge.node) {
                .leaf => |i| shared.leaves[i].file,
                .parent => |i| shared.pins[i].file,
            };
            const name = switch (edge.node) {
                .leaf => |i| try leafPath(i, &buffer),
                .parent => |i| try parentPath(i, &buffer),
            };
            const bytes = try openPinned(shared.work, shared.dir, name, pin, shared.options.max_proof_bytes);
            defer shared.work.free(bytes);
            switch (edge.node) {
                .leaf => |i| {
                    const policy = shared.leaves[i].policy;
                    return LeafAdapter.verify(shared.work, bytes, policy);
                },
                .parent => {
                    const admitted = normalized.Admission.init(child, &.{});
                    var owned = try parent.codec.decode(shared.work, bytes, &admitted);
                    var fresh = try parent.verify(&owned, &admitted);
                    errdefer fresh.deinit();
                    try fresh.validate(&admitted, admitted.expected_id);
                    return fresh;
                },
            }
        }
        const Fold = struct {
            a: std.mem.Allocator,
            prepared: preparation.Prepared,
            admission: protocol.Admission,
            bytes: []u8,
            span: @import("../recursion/block_v5_pc_clock_span_v1.zig").Span,
            fn deinit(self: *Fold) void {
                self.a.free(self.bytes);
                self.prepared.deinit();
            }
        };
        fn proveFold(a: std.mem.Allocator, purpose: bus.Purpose, children: []const normalized.Child, captures: []const *const verified_mod.Verified, cache: *Cache) !Fold {
            var prepared = try preparation.prepare(a, purpose, children, captures, 2);
            errdefer prepared.deinit();
            const proved = try cache.proveConsuming(&prepared);
            var artifact = proved.proof;
            defer artifact.deinit();
            const admission = try protocol.Admission.init(proved.key, proved.key_id, prepared.wires, prepared.values);
            const bytes = try parent.codec.encode(a, &artifact, &admission);
            errdefer a.free(bytes);
            var owned = try parent.codec.decode(a, bytes, &admission);
            var fresh = try parent.verify(&owned, &admission);
            defer fresh.deinit();
            try fresh.validate(&admission, admission.expected_id);
            return .{ .a = a, .prepared = prepared, .admission = admission, .bytes = bytes, .span = try prepared.values.outputSpan() };
        }
        const OuterWork = struct {
            a: std.mem.Allocator,
            pool: *engine.work_pool.WorkPool,
            children: []const normalized.Child,
            captures: []const *const verified_mod.Verified,
            cache: *Cache,
            output: ?Fold = null,
            failure: ?anyerror = null,
            fn run(self: *OuterWork) void {
                var binding = engine.work_pool.ScopedPoolBinding.init(self.pool) catch |err| {
                    self.failure = err;
                    return;
                };
                defer binding.deinit();
                self.output = proveFold(self.a, .exact_outer, self.children, self.captures, self.cache) catch |err| {
                    self.failure = err;
                    return;
                };
            }
        };
        /// Incremental provisional producer. Common first-round seal/public endpoints
        /// must already be admitted. Native policy metadata is an immutable caller borrow
        /// until finish/abort; schedules and normalized public snapshots are owned here.
        /// One coordinator submits leaves. Lane workers access them only after fresh
        /// equation verification and the queue's publication barrier.
        pub const Stream = struct {
            budget: *Budget,
            work: std.mem.Allocator,
            dir: std.fs.Dir,
            public_pins: exact.OuterPins,
            options: Options,
            dag: dag_mod.Plan,
            queue: queue_mod.Queue,
            shared: Shared,
            leaves: []LeafFile,
            native: []normalized.Child,
            submitted: []bool,
            nodes: []normalized.Child,
            pins: []ParentPin,
            lanes: []Lane,
            threads: []std.Thread,
            started: usize = 0,
            joined: bool = false,
            open_sum: core.fields.qm31.QM31 = core.fields.qm31.QM31.zero(),

            /// Allocates all metadata/setup/proof work from one synchronized host budget.
            /// Lane coordinators bind a borrowed driver pool when supplied; standalone
            /// callers retain owned pools. No helper thread runs a whole recursive job.
            pub fn start(a: std.mem.Allocator, dir: std.fs.Dir, public_pins: exact.OuterPins, options: Options) !*Stream {
                if (public_pins.segment_count == 0 or options.lane_count == 0 or options.lane_count > 64 or
                    options.pool_workers_per_lane == 0 or options.total_host_limit == 0 or options.max_proof_bytes == 0 or
                    options.setup_cache_entries_per_lane == 0 or options.setup_cache_entries_per_lane > 64 or
                    options.retained_scratch_bytes_per_lane > options.total_host_limit)
                    return error.InvalidV5OpenForestOptions;
                const budget = try Budget.create(a, options.total_host_limit);
                errdefer budget.destroy();
                const work = budget.allocator();
                const self = try work.create(Stream);
                errdefer work.destroy(self);
                var dag = try dag_mod.plan(work, public_pins.segment_count, options.max_execution_count);
                errdefer dag.deinit();
                var queue = try queue_mod.Queue.initStreaming(work, &dag, public_pins.segment_count, options.lane_count);
                errdefer queue.deinit();
                const leaves = try work.alloc(LeafFile, public_pins.segment_count);
                errdefer work.free(leaves);
                const native = try work.alloc(normalized.Child, leaves.len);
                errdefer work.free(native);
                const submitted = try work.alloc(bool, leaves.len);
                errdefer work.free(submitted);
                @memset(submitted, false);
                const pins = try work.alloc(ParentPin, dag.tasks.len);
                errdefer work.free(pins);
                const nodes = try work.alloc(normalized.Child, dag.tasks.len);
                errdefer work.free(nodes);
                const lane_count = @min(options.lane_count, @max(1, dag.tasks.len));
                const lanes = try work.alloc(Lane, lane_count);
                errdefer work.free(lanes);
                const threads = try work.alloc(std.Thread, lane_count);
                errdefer work.free(threads);
                var pools: usize = 0;
                errdefer for (lanes[0..pools]) |*lane| {
                    lane.cache.deinit();
                    if (options.shared_pool == null) lane.pool.deinit();
                };
                for (lanes) |*lane| {
                    lane.* = .{ .shared = &self.shared };
                    if (options.shared_pool == null)
                        try lane.pool.initInPlaceWithOptions(.{ .worker_count = options.pool_workers_per_lane, .backing_allocator = work });
                    lane.cache = Cache.init(work, .{ .profile = options.profile, .max_entries = options.setup_cache_entries_per_lane, .retained_scratch_bytes = options.retained_scratch_bytes_per_lane }) catch |err| {
                        if (options.shared_pool == null) lane.pool.deinit();
                        return err;
                    };
                    pools += 1;
                }
                self.* = .{ .budget = budget, .work = work, .dir = dir, .public_pins = public_pins, .options = options, .dag = dag, .queue = queue, .shared = undefined, .leaves = leaves, .native = native, .submitted = submitted, .nodes = nodes, .pins = pins, .lanes = lanes, .threads = threads };
                self.queue.dag = &self.dag;
                self.shared = .{ .metadata_a = work, .work = work, .dir = dir, .dag = &self.dag, .leaves = leaves, .native = native, .nodes = nodes, .pins = pins, .queue = &self.queue, .options = options };
                for (lanes, threads) |*lane, *thread| {
                    thread.* = std.Thread.spawn(.{ .stack_size = 8 * 1024 * 1024 }, Lane.run, .{lane}) catch |err| {
                        self.queue.stop(err);
                        for (threads[0..self.started]) |running| running.join();
                        return err;
                    };
                    self.started += 1;
                }
                return self;
            }

            /// Success publishes one durable, freshly checked recursive equation. Raw
            /// proof metadata cannot choose native authority: the supplied native policy
            /// must be the producer's independently prepared immutable policy. The file
            /// and its schedule/keys are checked before any dependent task can run.
            pub fn submit(self: *Stream, index: u32, leaf: LeafFile) !void {
                if (self.joined or index >= self.leaves.len or self.submitted[index]) return error.InvalidMixedForestLeafPublication;
                if (self.queue.progress().failure) |err| return err;
                if (leaf.file.byte_len == 0 or leaf.file.byte_len > self.options.max_proof_bytes or
                    std.mem.allEqual(u8, &leaf.file.sha256, 0)) return error.InvalidV5OpenProofFilePin;
                const config = self.options.profile.config();
                if (!std.meta.eql(leaf.policy.native.config, config) or
                    !std.meta.eql(leaf.policy.recursive_key.config, config) or
                    !std.meta.eql(leaf.policy.recursive_key.context.child_config, config)) return error.V5OpenForestSecurityMismatch;
                const schedule = try self.work.dupe(LeafAdapter.Wire, leaf.policy.recursive_schedule);
                errdefer self.work.free(schedule);
                var admitted_leaf = leaf;
                admitted_leaf.policy.recursive_schedule = schedule;
                var child = try LeafAdapter.normalize(self.work, admitted_leaf.policy);
                errdefer child.deinit();
                if (child.span.first_index != index or child.span.segment_count != 1 or
                    child.span.job_segment_count != self.public_pins.segment_count or
                    !std.meta.eql(child.span.job_id, self.public_pins.job_id) or
                    !std.meta.eql(child.span.source_image_digest, self.public_pins.source_image_digest) or
                    !std.meta.eql(child.span.sealed_digest, self.public_pins.sealed_digest)) return error.UntrustedV5OpenStageNative;
                if ((index == 0 and (child.span.first_cycle != self.public_pins.first_cycle or child.span.initial_pc != self.public_pins.initial_pc)) or
                    (index + 1 == self.native.len and (child.span.last_cycle != self.public_pins.last_cycle or child.span.final_pc != self.public_pins.final_pc))) return error.UntrustedV5OpenStageNative;
                // Check adjacent already-published endpoints before releasing work. The
                // final merge below still authenticates the complete exact public span.
                const span_mod = @import("../recursion/block_v5_pc_clock_span_v1.zig");
                if (index > 0 and self.submitted[index - 1]) _ = try span_mod.merge(&.{ self.native[index - 1].span, child.span });
                if (index + 1 < self.native.len and self.submitted[index + 1]) _ = try span_mod.merge(&.{ child.span, self.native[index + 1].span });
                var name_buffer: [80]u8 = undefined;
                const bytes = try openPinned(self.work, self.dir, try leafPath(index, &name_buffer), leaf.file, self.options.max_proof_bytes);
                defer self.work.free(bytes);
                var fresh = try LeafAdapter.verify(self.work, bytes, admitted_leaf.policy);
                defer fresh.deinit();
                self.leaves[index] = admitted_leaf;
                self.native[index] = child;
                self.submitted[index] = true;
                self.open_sum = self.open_sum.add(admitted_leaf.policy.exported.open_sum);
                // A concurrent proof failure can reject the barrier. That slot was not
                // visible to workers; restore ownership to the errdefers in this call.
                self.queue.publishLeaf(index) catch |err| {
                    self.submitted[index] = false;
                    self.open_sum = self.open_sum.sub(admitted_leaf.policy.exported.open_sum);
                    return err;
                };
            }
            pub fn progress(self: *Stream) queue_mod.Queue.Progress {
                return self.queue.progress();
            }
            pub fn waitForParents(self: *Stream, count: usize) !void {
                return self.queue.waitForCompleted(count);
            }
            fn join(self: *Stream) void {
                if (self.joined) return;
                for (self.threads[0..self.started]) |thread| thread.join();
                self.joined = true;
            }
            /// Joins every lane before releasing any borrowed policy/dir/allocator.
            /// Published intermediate artifacts from this aborted stream are removed;
            /// input leaf files remain owned by their producer.
            pub fn abort(self: *Stream) void {
                self.queue.stop(error.V5OpenForestAborted);
                self.join();
                self.destroy(false);
            }
            fn destroy(self: *Stream, transfer: bool) void {
                const work = self.work;
                const budget = self.budget;
                // Cached admissions borrow normalized child snapshots, so caches die
                // before those snapshots and their frames/terms are released.
                for (self.lanes) |*lane| {
                    lane.cache.deinit();
                    lane.deinitPool();
                }
                work.free(self.lanes);
                work.free(self.threads);
                for (self.queue.completed, 0..) |done, i| if (done) {
                    self.nodes[i].deinit();
                    if (!transfer) {
                        work.free(self.pins[i].node.schedule);
                        var buffer: [80]u8 = undefined;
                        self.dir.deleteFile(parentPath(@intCast(i), &buffer) catch unreachable) catch {};
                    }
                };
                for (self.submitted, 0..) |done, i| if (done) {
                    self.native[i].deinit();
                    work.free(self.leaves[i].policy.recursive_schedule);
                };
                work.free(self.submitted);
                work.free(self.leaves);
                work.free(self.native);
                work.free(self.nodes);
                if (!transfer) work.free(self.pins);
                self.queue.deinit();
                self.dag.deinit();
                work.destroy(self);
                if (!transfer) budget.destroy();
            }
            /// Consumes this pointer on success. On failure it remains abortable. The
            /// result is a provisional stage, never globally closed block authority.
            pub fn finish(self: *Stream) !Stage {
                self.queue.closeLeaves() catch |err| {
                    self.join();
                    return err;
                };
                self.join();
                try self.queue.result();
                var public_span = self.native[0].span;
                for (self.native[1..]) |child| public_span = try @import("../recursion/block_v5_pc_clock_span_v1.zig").merge(&.{ public_span, child.span });
                try self.public_pins.require(public_span);
                var roots: [32]normalized.Child = undefined;
                var equations: [32]verified_mod.Verified = undefined;
                var root_count: usize = 0;
                defer for (equations[0..root_count]) |*equation| equation.deinit();
                for (self.dag.roots, 0..) |root, i| {
                    roots[i] = childPolicy(&self.shared, root);
                    equations[i] = try loadEquation(&self.shared, root, &roots[i]);
                    root_count += 1;
                }
                var captures: [32]*const verified_mod.Verified = undefined;
                for (equations[0..root_count], captures[0..root_count]) |*equation, *capture| capture.* = equation;
                var outer_work = OuterWork{ .a = self.work, .pool = self.lanes[0].effectivePool(), .cache = &self.lanes[0].cache, .children = roots[0..root_count], .captures = captures[0..root_count] };
                const outer_thread = try std.Thread.spawn(.{ .stack_size = 8 * 1024 * 1024 }, OuterWork.run, .{&outer_work});
                outer_thread.join();
                if (outer_work.failure) |err| return err;
                var outer = outer_work.output orelse return error.MissingV5OpenOuterArtifact;
                var outer_live = true;
                defer if (outer_live) outer.deinit();
                try self.public_pins.require(outer.span);
                const file = try writeProof(self.dir, OUTER_FILE, outer.bytes, self.options.max_proof_bytes);
                errdefer self.dir.deleteFile(OUTER_FILE) catch {};
                const schedule = try self.work.dupe(bus.Wire, outer.prepared.wires);
                // All fallible work is complete. Release captures/outer before destroying
                // stream-owned child arenas/budget metadata at the transfer boundary.
                const node = exact.NodePin{ .key = outer.admission.key, .expected_id = outer.admission.expected_id, .schedule = schedule };
                var stats = setup_cache.Stats{};
                for (self.lanes) |lane| {
                    stats.hits += lane.cache.stats.hits;
                    stats.misses += lane.cache.stats.misses;
                    stats.evictions += lane.cache.stats.evictions;
                }
                const result = Stage{ .a = self.work, .dir = self.dir, .execution_count = self.public_pins.segment_count, .parents = self.pins, .outer = .{ .node = node, .file = file }, .public_pins = self.public_pins, .combined_native_open_sum = self.open_sum, .stage_owned_peak_bytes = self.budget.snapshot().peak_live_bytes, .setup_cache_stats = stats, .budget = self.budget };
                outer.deinit();
                outer_live = false;
                for (equations[0..root_count]) |*equation| equation.deinit();
                root_count = 0;
                self.destroy(true);
                return result;
            }
        };

        /// Compatibility wrapper uses the same authenticated incremental implementation.
        pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: []const LeafFile, public_pins: exact.OuterPins, options: Options) !Stage {
            if (leaves.len != public_pins.segment_count) return error.InvalidV5OpenForestOptions;
            const stream = try Stream.start(a, dir, public_pins, options);
            errdefer stream.abort();
            for (leaves, 0..) |leaf, i| try stream.submit(@intCast(i), leaf);
            return stream.finish();
        }
    };
}
