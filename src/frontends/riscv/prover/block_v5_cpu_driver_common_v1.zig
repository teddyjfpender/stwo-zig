//! One bounded CPU collection/proving/forest/fresh-receiver orchestration.
//! Capacity selects actual B5CT/B5CF sources; default NativeV3 stays unchanged.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const std = @import("std");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const engine = @import("stwo_prover_engine");
        const Runner = @import("block_v4_cpu_runner_source.zig");
        const Admission = @import("block_v5_cpu_driver_admission_v1.zig").ForCapacity(capacity);
        const Collect = @import("block_v5_cpu_collect_v1.zig").ForCapacity(capacity);
        const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(capacity);
        const StagedExecution = @import("block_v5_cpu_staged_execution_source_v1.zig").ForCapacity(capacity);
        const Witness = @import("block_v5_cpu_witness_staging_v1.zig");
        const ProducerStack = @import("block_v5_block_producer_v1.zig").ForCapacity(capacity);
        const Producer = ProducerStack.ForBackend(Cpu);
        const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(capacity);
        const Policy = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(capacity);
        const NativeFused = if (capacity) @import("block_v5_native_capacity_fused_stage_v1.zig") else @import("block_v5_native_projection_fused_stage_v2.zig");
        const NativeReadonly = @import("block_v5_native_capacity_readonly_stage_v1.zig");
        const FamilyQueue = @import("block_v5_cpu_family_queue_v1.zig");
        const LeafQueueModule = @import("block_v5_native_capacity_leaf_queue_v1.zig");
        const LeafQueue = LeafQueueModule.ForBackend(Cpu);
        const Caller = @import("block_v5_caller_pipeline_v1.zig");
        const Native = if (capacity) @import("block_v5_native_capacity_proof_v1.zig") else @import("block_v5_native_execution_proof_v3.zig");
        const Leaf = if (capacity) @import("block_v5_native_capacity_recursive_stage_v1.zig") else @import("block_v5_native_recursive_leaf_stage_v1.zig");
        const Prepared = if (capacity) @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared else @import("block_v5_native_recursive_admission_v3.zig").Prepared;
        const Forest = if (capacity) @import("block_v5_capacity_open_forest_stage_v1.zig") else @import("block_v5_open_forest_stage_v1.zig");
        const Manifest = if (capacity) @import("block_v5_capacity_open_forest_manifest_v1.zig") else @import("block_v5_open_forest_manifest_v1.zig");
        const Exact = if (capacity) @import("../recursion/block_v5_capacity_exact_forest_receiver_v1.zig") else @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
        const Global = if (capacity) @import("block_v5_capacity_global_receiver_v1.zig") else @import("block_v5_global_receiver_v1.zig");
        const Parent = @import("../recursion/blake3_execution_parent_protocol.zig");
        const Sorted = @import("block_v5_memory_replay_adapter_v1.zig");
        const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(capacity);
        const Detached = @import("block_v5_cpu_detached_receive_v1.zig").ForCapacity(capacity);
        const RecursiveSources = @import("block_v5_cpu_recursive_sources_v1.zig");
        const RecursivePublication = @import("block_v5_cpu_recursive_publication_v1.zig");
        const RecursiveCaller = @import("block_v5_caller_recursive_pipeline_v1.zig").ForBackend(Cpu);
        const RecursiveReceive = @import("block_v5_cpu_recursive_receive_v1.zig");
        const ScopedJob = @import("block_v5_cpu_scoped_job_v1.zig");
        const SourcePages = @import("block_v5_cpu_source_pages_v1.zig");
        const PageDetached = @import("block_v5_cpu_source_pages_detached_receive_v1.zig");
        const Completion = @import("block_v5_cpu_recursive_completion_v1.zig");

        pub const Options = struct {
            profile: Parent.Profile,
            collection: Collect.Limits,
            max_roster_entries: usize,
            store: Store.Limits,
            forest: Forest.Options,
            manifest: Manifest.Limits,
            metadata: Metadata.Limits,
            cache: @import("block_v5_native_recursive_setup_cache_v1.zig").Options,
            workers: usize,
            /// Aggregate heap bound shared by collection, base and recursive work.
            total_host_limit: usize = 40 * 1024 * 1024 * 1024,
            families: FamilyQueue.Options = .{},
            recursive_leaf_queue: if (capacity) LeafQueueModule.Options else void = if (capacity) .{} else {},
            /// Explicit supplemental OPEN publication until full source/global
            /// recursive authority and detached hierarchy integration qualify.
            recursive_families: if (capacity) ?RecursivePublication.Options else void = if (capacity) null else {},
            /// Explicit OPEN topology over all genuine durable typed families.
            /// No default ClosedBlock/security change or source token.
            scoped_job: if (capacity) ?ScopedJob.Options else void = if (capacity) null else {},
            /// Opt-in original PAGE/source-transition proof path. Final
            /// recursive/global source closure remains a separate obligation.
            source_pages: if (capacity) ?SourcePages.Options else void = if (capacity) null else {},

            /// Selected requester -> PAGE/RAM -> FINAL22 compression.
            /// Mutually exclusive with the old all-family scoped fold.
            recursive_completion: if (capacity) ?Completion.Options else void = if (capacity) null else {},

            /// Admit the scheduling/security policy before creating a budget,
            /// worker pool, collector or proof owner. This grants no authority
            /// to the source or any proof family.
            pub fn validate(self: Options) !void {
                if (self.profile != self.forest.profile or self.profile != self.cache.profile or
                    self.workers == 0 or self.total_host_limit == 0)
                    return error.InvalidV5CpuDriverOptions;
                try self.families.validate(self.total_host_limit);
                if (self.collection.readonly != null and
                    (!capacity or self.collection.ordinary.memory.register_custody_mode != 1 or
                        self.collection.caller.register_custody_mode != 1 or self.collection.caller.readonly != null))
                    return error.InvalidV5ReadonlyCollectionMode;
                if (capacity) {
                    // The supplemental/PAGE grammars do not yet carry the
                    // original classifier and caller-readonly proof families.
                    // Reject before collecting or publishing any partial bundle.
                    if (self.collection.readonly != null and
                        (self.recursive_families != null or self.source_pages != null))
                        return error.UnsupportedReadonlyRecursiveClosure;
                    if (self.recursive_completion) |completion| {
                        try completion.requireDependencies(self.recursive_families != null, self.source_pages != null, self.scoped_job != null);
                        if (self.collection.ordinary.memory.register_custody_mode != 1 or self.collection.caller.register_custody_mode != 1) return error.RecursiveCompletionRequiresRegisterWindows;
                        const globals = self.collection.globals;
                        const lanes = try @import("block_v5_sorted_memory_replay_v1.zig").laneResources(globals.lane_resources, globals.maximum_memory_log, globals.max_memory_instances, globals.max_range_shards);
                        try completion.requireOriginalMemory(lanes.stage);
                    }
                    if (self.source_pages) |pages| try pages.validate();
                    try self.recursive_leaf_queue.validate();
                    if (self.recursive_families) |recursive| try recursive.validate();
                    if (self.scoped_job) |scoped| {
                        if (self.recursive_families == null) return error.ScopedJobRequiresRecursiveFamilies;
                        try scoped.validate();
                    }
                }
            }
        };
        pub const Result = struct {
            verified: Global.VerifiedGlobals,
            collection_ns: u64,
            proving_ns: u64,
            forest_ns: u64,
            verification_ns: u64,
            proof_file_bytes: u64,
            proof_files: usize,
            bundle_manifest_sha256: [32]u8,
            forest_manifest_sha256: [32]u8,
            receiver_policy_sha256: [32]u8,
            recursive_stage_peak_bytes: usize,
            aggregate_heap_peak_bytes: usize,
            sorter: @import("../air/block/memory_spool.zig").Statistics,
            witness_file_bytes: u64,
            parallel_family_peak: usize,
            family_reservation_peak_bytes: usize,
            family_proving_ns: struct { caller: u64, memory_and_range: u64, rom: u64, lookup: u64 },
            recursive_leaf_queue: LeafQueueModule.Statistics = .{},
            supplemental_recursive_files: usize = 0,
            supplemental_recursive_manifest_sha256: ?[32]u8 = null,
            supplemental_scoped_parents: usize = 0,
            supplemental_scoped_manifest_sha256: ?[32]u8 = null,
            source_pages: ?SourcePages.Report = null,
            source_page_policy_pin: ?SourcePages.PolicyPin = null,
            recursive_completion: ?Completion.Report = null,
            supplemental_recursive_workers: @TypeOf(RecursivePublication.emptyWorkerStatistics()) = RecursivePublication.emptyWorkerStatistics(),
        };

        pub const nativeMetadata = Admission.nativeMetadata;
        pub const externalRetirements = Admission.externalRetirements;
        const WitnessLimits = @TypeOf(@as(Collect.Limits, undefined).witness);
        const LeafStage = if (capacity) struct {
            options: Leaf.ForBackend(Cpu).Options,
            sink: Leaf.Sink,
        } else Leaf.ForBackend(Cpu);
        const Hooks = struct {
            collected: *Collect.Collected,
            assembly: *Assembly.Assembly,
            fused: *NativeFused.ForBackend(Cpu),
            leaf: *LeafStage,
            prepared: []const Prepared,
            families: *FamilyQueue.Queue,
            leaf_queue: if (capacity) *LeafQueue else void,
            ordinary_limits: @TypeOf(@as(Collect.Limits, undefined).ordinary),
            readonly_sink: ?NativeReadonly.Sink,
            fn requireHealthy(self: *Hooks) !void {
                try self.families.requireHealthy();
                if (capacity) try self.leaf_queue.requireHealthy();
            }
            fn firstRound(raw: *anyopaque, _: std.mem.Allocator, replay: *const ProducerStack.LightweightReplay, index: u32) !Native.ForBackend(Cpu).FirstRound {
                const self: *Hooks = @ptrCast(@alignCast(raw));
                try self.requireHealthy();
                return StagedExecution.Source.takeFirstRound(replay, index);
            }
            fn warm(raw: *anyopaque, a: std.mem.Allocator, execution: Producer.WarmExecution) !void {
                const self: *Hooks = @ptrCast(@alignCast(raw));
                try self.requireHealthy();
                var timer = try std.time.Timer.start();
                std.debug.print("BLOCK_V5_PROVE sidecars_started={d}/{d}\n", .{ execution.index + 1, self.assembly.executions.len });
                if (execution.index >= self.collected.planning.records.items.len) return error.InvalidV5CpuWarmExecutionIndex;
                try self.collected.planning.records.items[execution.index].physical.requireReplay(execution.first);
                if (capacity) {
                    try self.fused.produce(a, execution.first, execution.sealed, execution.pins, execution.entries, execution.catalog);
                    if (self.collected.readonly) |*selected| {
                        try self.requireHealthy();
                        if (execution.first.index != execution.index or execution.first.source != execution.replay.owner)
                            return error.UntrustedV5WarmReadonlySource;
                        const binding = try selected.nativeBinding(execution.index);
                        try NativeReadonly.ForBackend(Cpu).prove(a, execution.first.source, &self.collected.ordinary[execution.index], self.ordinary_limits, selected.native[execution.index], &binding, &selected.selection, selected.selectionPins(), selected.input, execution.first.instance_id, execution.sealed, execution.pins, execution.entries, self.readonly_sink orelse return error.MissingV5ReadonlySink);
                        try self.requireHealthy();
                    }
                } else {
                    const fused_callbacks = self.fused.hooks();
                    try fused_callbacks.on_first_round.?(fused_callbacks.context, a, execution);
                }
                std.debug.print("BLOCK_V5_PROVE sidecars_published={d}/{d} elapsed_ms={d}\n", .{ execution.index + 1, self.assembly.executions.len, timer.read() / std.time.ns_per_ms });
            }
            fn nativeProof(raw: *anyopaque, a: std.mem.Allocator, execution: Producer.WarmExecution, proof: *const Native.Proof) !void {
                const self: *Hooks = @ptrCast(@alignCast(raw));
                try self.requireHealthy();
                var timer = try std.time.Timer.start();
                std.debug.print("BLOCK_V5_PROVE native_published={d}/{d} recursive_leaf_async={any}\n", .{ execution.index + 1, self.assembly.executions.len, capacity });
                if (capacity) {
                    if (execution.index >= self.prepared.len or execution.first.index != execution.index or
                        execution.first.source != execution.replay.owner or execution.first.owns_scheme or
                        !std.meta.eql(execution.first.pin, execution.replay.admission) or
                        !std.meta.eql(proof.template_id, execution.first.template_id) or
                        !std.meta.eql(proof.instance_id, execution.first.instance_id)) return error.UntrustedV5WarmCapacityLeaf;
                    // The queue waits for capacity before fresh capture allocation.
                    // Native witness, replay and PCS remain foreground-owned.
                    try self.leaf_queue.enqueueProof(execution.index, proof);
                } else {
                    const callbacks = self.leaf.hooks();
                    try callbacks.on_proof.?(callbacks.context, a, execution, proof);
                }
                std.debug.print("BLOCK_V5_PROVE native_leaf_callback_finished={d}/{d} async={any} callback_ms={d}\n", .{ execution.index + 1, self.assembly.executions.len, capacity, timer.read() / std.time.ns_per_ms });
            }
        };

        /// Each job borrows immutable collection/admission data and owns its opened
        /// witness reader and PCS state. No job retains the live native replay owner.
        const IndependentFamilies = struct {
            a: std.mem.Allocator,
            collected: *Collect.Collected,
            assembly: *Assembly.Assembly,
            store: *Store.Store,
            pool: *engine.work_pool.WorkPool,
            dir: std.fs.Dir,
            witness_limits: WitnessLimits,
            families: *FamilyQueue.Queue,
            recursive: ?*RecursivePublication.Session = null,

            fn callers(raw: *anyopaque) !void {
                const self: *IndependentFamilies = @ptrCast(@alignCast(raw));
                try self.assembly.sealed.require(self.assembly.seal_pins, self.assembly.entries);
                for (self.assembly.callers, self.collected.caller_pins, 0..) |*bound, pin, index| {
                    try self.families.requireHealthy();
                    if (bound.*) |*caller| {
                        var name: [96]u8 = undefined;
                        if (capacity and self.recursive != null) {
                            const recursive = self.recursive.?;
                            const pair = try recursive.sources.callers.?.get(@intCast(index));
                            try RecursiveCaller.proveStagedWithAdmissions(self.a, self.dir, try Witness.callerName(@intCast(index), &name), pin orelse return error.MissingV5StagedCaller, caller, self.witness_limits.caller, self.pool, self.store.callerSink(Caller.Sink), recursive.callerSinks(), pair, try recursive.callerOptions(@intCast(index)));
                        } else try Caller.ForBackend(Cpu).proveStaged(self.a, self.dir, try Witness.callerName(@intCast(index), &name), pin orelse return error.MissingV5StagedCaller, caller, self.witness_limits.caller, self.assembly.sealed, self.assembly.seal_pins, self.assembly.entries, self.pool, self.store.callerSink(Caller.Sink), null);
                    } else if (pin != null) return error.UntrustedV5StagedCaller;
                }
            }
            fn memory(raw: *anyopaque) !void {
                const self: *IndependentFamilies = @ptrCast(@alignCast(raw));
                try self.families.requireHealthy();
                try self.collected.globals.memory.proveWithSinks(self.a, Sorted.fromReplay(&self.collected.replay), self.store.packedMemorySink(), if (capacity and self.recursive != null) self.recursive.?.lanesSink() else self.store.ramLanesSink(), self.assembly.seal_pins, self.assembly.entries, self.assembly.sealed, self.families.boundary());
            }
            fn program(raw: *anyopaque) !void {
                const self: *IndependentFamilies = @ptrCast(@alignCast(raw));
                try self.families.requireHealthy();
                try self.assembly.sealed.require(self.assembly.seal_pins, self.assembly.entries);
                var proof = try self.assembly.program.proveTable(self.assembly.sealed.programSeal());
                var owns = true;
                defer if (owns) proof.deinit(self.a);
                if (capacity and self.recursive != null) {
                    try self.recursive.?.publishProgram(&proof);
                } else {
                    const sink = self.store.executionSink();
                    try sink.table(sink.context, &proof);
                }
                owns = false;
            }
            fn lookup(raw: *anyopaque) !void {
                const self: *IndependentFamilies = @ptrCast(@alignCast(raw));
                try self.families.requireHealthy();
                try self.collected.groups.proveWithBoundary(Cpu, if (capacity and self.recursive != null) self.recursive.?.lookupSink() else self.store.providerSink(), self.assembly.seal_pins, self.assembly.entries, self.assembly.sealed, self.families.boundary());
            }
        };
        const Leaves = struct {
            a: std.mem.Allocator,
            dir: std.fs.Dir,
            artifacts: []Leaf.Artifact,
            next: u32 = 0,
            max_proof_bytes: usize,
            prepared: []const Prepared,
            leaf_files: []Forest.LeafFile,
            stream: *Forest.Stream,
            fn init(a: std.mem.Allocator, dir: std.fs.Dir, count: usize, cap: usize, prepared: []const Prepared, leaf_files: []Forest.LeafFile, stream: *Forest.Stream) !Leaves {
                const artifacts = try a.alloc(Leaf.Artifact, count);
                errdefer a.free(artifacts);
                return .{ .a = a, .dir = dir, .artifacts = artifacts, .max_proof_bytes = cap, .prepared = prepared, .leaf_files = leaf_files, .stream = stream };
            }
            fn deinit(self: *Leaves) void {
                for (self.artifacts[0..self.next]) |*artifact| artifact.deinit(self.a);
                self.a.free(self.artifacts);
            }
            fn put(raw: *anyopaque, index: u32, artifact: *Leaf.Artifact) !void {
                const self: *Leaves = @ptrCast(@alignCast(raw));
                if (index != self.next or index >= self.artifacts.len) return error.InvalidV5CpuLeafOrder;
                var buffer: [96]u8 = undefined;
                const pin = try Forest.writeProof(self.dir, try Forest.leafPath(index, &buffer), artifact.bytes, self.max_proof_bytes);
                const leaf_file = Forest.LeafFile{ .policy = .{ .native = &self.prepared[index], .exported = artifact.native, .recursive_key = artifact.key, .recursive_key_id = artifact.expected_key_id, .recursive_schedule = artifact.schedule }, .file = pin };
                // Fresh verification and exact publication precede ownership transfer.
                // Ready folds can now overlap subsequent base/provider proofs.
                try self.stream.submit(index, leaf_file);
                self.leaf_files[index] = leaf_file;
                self.artifacts[index] = artifact.*;
                self.a.free(self.artifacts[index].bytes);
                self.artifacts[index].bytes = &.{};
                self.next += 1;
            }
        };

        pub fn run(child_allocator: std.mem.Allocator, dir: std.fs.Dir, source: *Runner.Source, policy: Admission.InputPolicy, options: Options) !Result {
            try policy.runner_pins.execution_recipe.requireCompiled();
            if (source.execution_recipe != policy.runner_pins.execution_recipe) return error.MixedV5ExecutionRecipe;
            const config = options.profile.config();
            try options.validate();
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(child_allocator, options.total_host_limit);
            defer budget.destroy();
            const a = budget.allocator();
            var timer = try std.time.Timer.start();
            var pool: engine.work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = options.workers, .backing_allocator = a });
            defer pool.deinit();
            var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            const collected = try Collect.collect(a, dir, source, policy, config, options.collection);
            defer collected.deinit();
            const assembly = try Assembly.assemble(a, collected, policy, options.max_roster_entries);
            defer assembly.deinit();
            var source_pages: ?*SourcePages.Job = if (capacity) if (options.source_pages) |pages|
                try SourcePages.collect(a, dir, &collected.globals.sources, assembly.seal_pins, assembly.entries, assembly.sealed, source.input, config, pages)
            else
                null else null;
            defer if (source_pages) |job| job.deinit() catch @panic("CPU source PAGE job lifetime");
            const policies = try Policy.build(a, assembly.global_pins, options.store);
            defer a.free(policies);
            var writer = try Store.Store.initWriter(a, dir, policies, config, options.store);
            defer writer.deinit();
            const prepared = try a.alloc(Prepared, assembly.executions.len);
            defer a.free(prepared);
            var prepared_count: usize = 0;
            defer for (prepared[0..prepared_count]) |*pin| pin.deinit();
            for (assembly.executions, 0..) |pin, index| {
                prepared[index] = if (capacity)
                    try Prepared.init(a, pin.shape, pin.external_retirements, pin.admission, pin.template, pin.template_id, @intCast(index), assembly.sealed, assembly.seal_pins, assembly.entries, collected.bound.catalogAdmission(), pin.limits.native)
                else
                    try Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, @intCast(index), assembly.sealed, assembly.seal_pins, assembly.entries, collected.bound.catalogAdmission());
                prepared_count += 1;
                prepared[index].reusable_public_inputs = true;
            }
            // Stable original sources and templates outlive all worker joins,
            // stores and scoped readers. Defer order releases publication first.
            const recursive_sources: ?*RecursiveSources.Owner = if (capacity) if (options.recursive_families) |recursive|
                try RecursiveSources.Owner.create(a, collected, assembly, prepared, recursive.sources)
            else
                null else null;
            defer if (capacity) if (recursive_sources) |owned| owned.deinit();
            const recursive_publication: ?*RecursivePublication.Session = if (capacity) if (options.recursive_families) |recursive| publication: {
                var selected = recursive;
                // Session workers borrow the driver's already bounded pool;
                // publication is destroyed before that pool on every exit.
                selected.worker_options.shared_pool = &pool;
                break :publication try RecursivePublication.Session.create(a, dir, recursive_sources.?, &writer, options.profile, selected);
            } else null else null;
            defer if (capacity) if (recursive_publication) |owned| owned.deinit();
            // Later family/forest defers join readers before this rollback.
            // Success keeps the files; failure removes only session-owned ones.
            errdefer if (capacity) if (recursive_publication) |owned| owned.rollbackPublished();
            const leaf_files = try a.alloc(Forest.LeafFile, prepared.len);
            defer a.free(leaf_files);
            const outer = Exact.OuterPins{ .job_id = policy.job_id, .source_image_digest = assembly.seal_pins.source_image_digest, .sealed_digest = assembly.sealed.digest, .segment_count = source.schedule.segments, .first_cycle = collected.planning.records.items[0].physical.first_cycle, .last_cycle = collected.planning.records.items[prepared.len - 1].physical.last_cycle, .initial_pc = assembly.executions[0].shape.public_data.initial_pc, .final_pc = assembly.executions[prepared.len - 1].shape.public_data.final_pc };
            var forest_options = options.forest;
            forest_options.shared_pool = &pool;
            const stream = try Forest.Stream.start(a, dir, outer, forest_options);
            var leaves = Leaves.init(a, dir, source.schedule.segments, options.forest.max_proof_bytes, prepared, leaf_files, stream) catch |err| {
                stream.abort();
                return err;
            };
            defer leaves.deinit();
            // Abort joins all readers before leaf schedules/prepared policies are freed.
            var stream_live = true;
            defer if (stream_live) stream.abort();
            const collection_ns = timer.lap();
            std.debug.print("BLOCK_V5_DRIVER collected=true segments={d} memory_instances={d} base_files={d} collection_ms={d}\n", .{ source.schedule.segments, collected.globals.memory.instanceCount(), policies.len, collection_ns / std.time.ns_per_ms });
            const sorter = collected.replay.spooler.statistics;
            std.debug.print("BLOCK_V5_SORT initial_runs={d} merge_passes={d} read_bytes={d} written_bytes={d} sort_buffer_bytes={d}\n", .{ sorter.initial_runs, sorter.merge_passes, sorter.bytes_read, sorter.bytes_written, sorter.sort_buffer_bytes });
            var family_statistics: FamilyQueue.Statistics = .{};
            var leaf_statistics: LeafQueueModule.Statistics = .{};
            {
                var cache_options = options.cache;
                cache_options.worker_options.shared_pool = &pool;
                var cache = try Leaf.ForBackend(Cpu).SetupCache.init(a, cache_options);
                defer cache.deinit();
                var leaf_stage = LeafStage{ .options = .{ .profile = options.profile, .cache = &cache }, .sink = .{ .context = &leaves, .put_leaf = Leaves.put } };
                var fused = NativeFused.ForBackend(Cpu){ .proposals = collected.ordinary, .limits = options.collection.ordinary, .sink = if (capacity and recursive_publication != null) recursive_publication.?.fusedSink() else writer.fusedSink() };
                var execution = try StagedExecution.Source.init(a, dir, collected.planning.records.items, collected.native_pins, collected.bound.admissions, options.collection.witness.native);
                defer execution.deinit();
                if (capacity) execution.fixed_basis_limits = options.collection.fixed_basis orelse .{ .max_retained_bytes = 0 };
                const families = try FamilyQueue.Queue.start(a, &pool, options.families, options.total_host_limit);
                // Joined before execution/cache, writer, assembly or collected data
                // can be freed, on success and every native/callback failure path.
                defer families.deinit();
                if (capacity) {
                    if (recursive_publication) |recursive| recursive.boundary = families.boundary();
                }
                const leaf_queue = if (capacity)
                    try LeafQueue.start(a, &pool, prepared, leaf_stage.options, leaf_stage.sink, options.recursive_leaf_queue, families.boundary())
                else {};
                // Join the sole cache/sink user before families, execution,
                // setup cache, leaf metadata or shared pool can be destroyed.
                defer if (capacity) leaf_queue.deinit();
                var hooks = Hooks{ .collected = collected, .assembly = assembly, .fused = &fused, .leaf = &leaf_stage, .prepared = prepared, .families = families, .leaf_queue = leaf_queue, .ordinary_limits = options.collection.ordinary, .readonly_sink = if (capacity and collected.readonly != null) writer.nativeReadonlySink() else null };
                var independent = IndependentFamilies{ .a = a, .collected = collected, .assembly = assembly, .store = &writer, .pool = &pool, .dir = dir, .witness_limits = options.collection.witness, .families = families, .recursive = recursive_publication };
                for ([_]FamilyQueue.Job{
                    .{ .family = .memory, .context = &independent, .reservation = options.families.family_reservation, .run = IndependentFamilies.memory },
                    .{ .family = .caller, .context = &independent, .reservation = options.families.family_reservation, .run = IndependentFamilies.callers },
                    .{ .family = .program, .context = &independent, .reservation = options.families.family_reservation, .run = IndependentFamilies.program },
                    .{ .family = .lookup, .context = &independent, .reservation = options.families.family_reservation, .run = IndependentFamilies.lookup },
                }) |job| try families.submit(job);
                const stored_sink = writer.executionSink();
                const execution_sink: ProducerStack.LightweightExecutionSink = if (capacity)
                    .{ .context = stored_sink.context, .native = stored_sink.native, .table = stored_sink.table }
                else
                    stored_sink;
                _ = try Producer.proveExecutionsWithMemoryPlanHooks(a, &assembly.program, collected.globals.memory.memoryPlan(), assembly.seal_pins, assembly.entries, assembly.sealed, collected.bound.catalogAdmission(), execution.source(), execution_sink, .{ .context = &hooks, .fused_program_requests = true, .prepare_first_round = Hooks.firstRound, .on_first_round = Hooks.warm, .on_proof = Hooks.nativeProof });
                try execution.requireFinished();
                try fused.requireFinished();
                if (capacity) leaf_statistics = try leaf_queue.finish();
                family_statistics = try families.finish();
                if (capacity) if (recursive_publication) |recursive| {
                    recursive.boundary = null;
                };
            }
            if (leaves.next != leaves.artifacts.len) return error.IncompleteV5CpuRecursiveLeaves;
            var supplemental_files: usize = 0;
            var supplemental_manifest: ?[32]u8 = null;
            if (capacity) if (recursive_publication) |recursive| {
                supplemental_files = try recursive.requirePublished();
                supplemental_manifest = try recursive.writeOpenManifest(dir);
            };
            const files = try writer.filePins(a);
            defer a.free(files);
            const bundle_sha = try Store.writePins(a, dir, files, options.store);
            var source_publication: ?SourcePages.Published = null;
            if (capacity) if (source_pages) |job| {
                source_publication = try SourcePages.publish(job, assembly.global_pins, options.source_pages.?);
                // Original files and pinned normative policy own the durable
                // handoff. Producer PCS/setup/metadata need not overlap the
                // cold independently reconstructed receiver allocation.
                try job.deinit();
                source_pages = null;
            };
            const proving_ns = timer.lap();
            std.debug.print("BLOCK_V5_DRIVER base_and_recursive_leaves_published=true proving_ms={d} proof_files={d}\n", .{ proving_ns / std.time.ns_per_ms, files.len });
            const recursive_leaves = try a.alloc(Global.RecursiveLeafPin, prepared.len);
            defer a.free(recursive_leaves);
            for (recursive_leaves, leaves.artifacts) |*pin, artifact| {
                pin.* = .{ .key = artifact.key, .expected_id = artifact.expected_key_id, .schedule = artifact.schedule };
            }
            // finish consumes the stream on success; an error retains the abort owner.
            var forest = try stream.finish();
            stream_live = false;
            defer forest.deinit();
            const forest_sha = try Manifest.write(a, dir, &forest, leaf_files, options.profile, options.manifest);
            const recursive_parents = try a.alloc(Exact.NodePin, forest.parents.len);
            defer a.free(recursive_parents);
            for (recursive_parents, forest.parents) |*pin, parent_pin| pin.* = parent_pin.node;
            const recursion = Global.RecursivePins{ .leaves = recursive_leaves, .parents = recursive_parents, .outer = forest.outer.node, .file = forest.outer.file };
            const receiver_sha = try Metadata.write(a, dir, assembly.global_pins, recursion, options.metadata);
            const forest_ns = timer.lap();
            std.debug.print("BLOCK_V5_DRIVER exact_forest_published=true forest_ms={d} fresh_complete_receiver_started=true\n", .{forest_ns / std.time.ns_per_ms});
            // Reopen policy, manifests, source files and every proof from scratch.
            const detached_pins = Detached.Pins{
                .identity = .{ .execution_recipe = policy.runner_pins.execution_recipe, .job_id = policy.job_id, .source_image_digest = assembly.seal_pins.source_image_digest, .program_root = policy.runner_pins.program_root.bytes, .initial_rw_root = policy.runner_pins.initial_rw_root.bytes, .final_rw_root = policy.expected_final_rw_root, .config = config },
                .receiver_policy_sha256 = receiver_sha,
                .bundle_manifest_sha256 = bundle_sha,
                .forest_manifest_sha256 = forest_sha,
            };
            const detached_limits = Detached.Limits{ .metadata = options.metadata, .store = options.store, .forest = options.manifest };
            const verified = if (capacity) if (source_publication) |publication|
                try PageDetached.verify(a, dir, source.input, .{ .original = detached_pins, .pages = publication.policy }, .{
                    .original = detached_limits,
                    .pages = .{ .policy = options.source_pages.?.policy, .store = options.store, .max_owned_bytes = options.source_pages.?.loader_owned_bytes },
                    .join = options.source_pages.?.join,
                    .max_heap_bytes = options.source_pages.?.verification_heap_bytes,
                })
            else
                try Detached.verify(a, dir, source.input, detached_pins, detached_limits) else try Detached.verify(a, dir, source.input, detached_pins, detached_limits);
            const complete_verification_ns = timer.read();
            var source_page_report: ?SourcePages.Report = null;
            if (source_publication) |publication| {
                var report = publication.report;
                report.fresh_transition_events = verified.memory_events;
                report.independent_verification_ns = complete_verification_ns;
                report.verification_scope = .complete_bundle;
                source_page_report = report;
            }
            if (capacity) if (recursive_sources) |independent_sources| {
                // Reopen original proof files; every supplemental expected key
                // is rederived through its genuine fresh original verifier and
                // rows, never taken from the recursive artifact or writer.
                var original_reader = try Store.Store.initReader(a, dir, policies, files, config, options.store);
                defer original_reader.deinit();
                const reopened = try RecursiveReceive.verify(a, dir, independent_sources, &original_reader, supplemental_manifest.?, options.profile, options.recursive_families.?);
                if (reopened != supplemental_files) return error.IncompleteV5CpuSupplementalRecursiveLeaves;
            };
            // Validate existing report arithmetic before later publications.
            // Completion combines its own counts inside its rollback scope.
            var proof_totals = try (Completion.ProofTotals{ .bytes = writer.total_bytes, .files = files.len }).add(.{
                .bytes = if (source_page_report) |report| report.artifact_bytes else 0,
                .files = if (source_page_report) |report| report.artifact_files else 0,
            });
            var scoped_report: ?ScopedJob.Report = null;
            if (capacity) if (options.scoped_job) |scoped_options| {
                // All workers are joined, original complete CPU receiver ran,
                // and original-row-derived supplemental templates were freshly
                // checked above. Stable Prepared/catalog/store owners remain
                // live through actual bounded parent publication+verification.
                scoped_report = try ScopedJob.publish(a, dir, assembly, recursive_publication.?, leaf_files, scoped_options);
            };
            var completion_report: ?Completion.Report = null;
            if (capacity) if (options.recursive_completion) |completion_options| {
                const windows = collected.register_windows orelse return error.RecursiveCompletionRequiresRegisterWindows;
                completion_report = try Completion.publish(a, dir, .{
                    .assembly = assembly,
                    .publication = recursive_publication.?,
                    .natives = leaf_files,
                    .independently_expected_page = source_publication.?.policy,
                    .original_policies = policies,
                    .original_files = files,
                    .original_limits = options.store,
                    .windows = windows,
                    .profile = options.profile,
                    .prior_totals = proof_totals,
                }, completion_options);
                proof_totals = completion_report.?.combined_totals;
            };
            var recursive_workers = RecursivePublication.emptyWorkerStatistics();
            if (capacity) if (recursive_publication) |recursive| {
                recursive_workers = recursive.workerStatistics();
            };
            return .{ .verified = verified, .recursive_completion = completion_report, .source_pages = source_page_report, .source_page_policy_pin = if (source_publication) |value| value.policy else null, .supplemental_scoped_parents = if (scoped_report) |value| value.parent_files else 0, .supplemental_scoped_manifest_sha256 = if (scoped_report) |value| value.manifest else null, .collection_ns = collection_ns, .proving_ns = proving_ns, .forest_ns = forest_ns, .verification_ns = timer.lap(), .proof_file_bytes = proof_totals.bytes, .proof_files = proof_totals.files, .bundle_manifest_sha256 = bundle_sha, .forest_manifest_sha256 = forest_sha, .receiver_policy_sha256 = receiver_sha, .recursive_stage_peak_bytes = forest.stage_owned_peak_bytes, .aggregate_heap_peak_bytes = budget.snapshot().peak_live_bytes, .sorter = sorter, .witness_file_bytes = collected.witness_file_bytes, .parallel_family_peak = family_statistics.peak_active, .family_reservation_peak_bytes = family_statistics.peak_reservation, .recursive_leaf_queue = leaf_statistics, .supplemental_recursive_files = supplemental_files, .supplemental_recursive_manifest_sha256 = supplemental_manifest, .supplemental_recursive_workers = recursive_workers, .family_proving_ns = .{ .caller = family_statistics.family_ns[@intFromEnum(FamilyQueue.Family.caller)], .memory_and_range = family_statistics.family_ns[@intFromEnum(FamilyQueue.Family.memory)], .rom = family_statistics.family_ns[@intFromEnum(FamilyQueue.Family.program)], .lookup = family_statistics.family_ns[@intFromEnum(FamilyQueue.Family.lookup)] } };
        }
    };
}
