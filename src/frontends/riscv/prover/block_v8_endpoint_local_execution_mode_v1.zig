//! Bounded continuous-session producer for the late-memory architecture.
//! Each cohort is locally proved/serialized once and its wide witness is
//! destroyed. Only narrow endpoint rows + exact endpoint PCS survive until
//! one late global-memory epoch closes the complete declared window.
//! No per-cohort complete RAM snapshots or old WORD witnesses are constructed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Prepare = @import("block_v8_endpoint_execution_v1.zig");
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Proof = @import("block_v8_endpoint_local_proof_v1.zig");
const Program = @import("block_v8_endpoint_local_program_v1.zig");
const Codec = @import("block_v8_endpoint_local_codec_v1.zig");
const Metadata = @import("block_v8_endpoint_local_statement_wire_v1.zig");
const Collect = @import("block_v8_ram_endpoint_collector_v1.zig");
const Retained = @import("block_v8_endpoint_local_retained_v1.zig");
const ROM = @import("block_v7_program_provider_v1.zig");
const SparseROM = @import("block_v8_sparse_rom_provider_v1.zig");
const Sparse = @import("block_v8_sparse_rom_v1.zig");
const Memory = @import("block_v7_window_memory_joint_v1.zig");
const BridgeScope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
const Bridge = @import("block_v8_endpoint_global_bridge_proof_v1.zig");
const Bundle = @import("block_v8_endpoint_local_bundle_v1.zig");
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
/// Two explicit protocols share the same source producer and late-bridge
/// schedule. `compact` is compile-time, so old/new proof types and receivers
/// cannot be silently interchanged at runtime.
pub fn For(comptime compact: bool) type {
    return struct {
        pub const production_active = false;
        pub const Request = Prepare.Request;
        pub const Options = struct {
            boundary: @import("block_v8_execution_boundary_ports_v1.zig").Options = .{},
            batch_native_projections: bool = false,
            native_batch_options: @import("block_v8_native_projection_domain_batch_v1.zig").Options = .{},
            program_flavor: Scope.RomFlavor = .legacy_complete,
            native_profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile = .endpoint_v2,
            cohort_cycles: u32 = 1 << 17,
            /// Bounded independent CPU proof jobs; source execution stays ordered.
            parallel_local_proofs: u32 = 1,
            proof_workers: usize = 8,
            max_cohort_cycles: u32 = 1 << 20,
            max_cohorts: u32 = 4096,
            max_endpoint_events: usize = 1 << 24,
            max_retained_endpoint_bytes: usize = 16 << 30,
            max_staged_bytes: u64 = 16 << 30,
            collector: Collect.Limits = .{},
            proof: Proof.Limits = .{},
            codec: Codec.Limits = .{},
            metadata: Metadata.Limits = .{},
            memory: Memory.Limits = (Prepare.Options{}).memory,
            compact_limits: Compact.Limits = .{},
            memory_rows_per_shard: u32 = 1 << 18,
            bridge: Bridge.Limits = .{},
            bundle: if (compact) Bundle.CompactLimits else Bundle.Limits = if (compact) .{} else .{ .memory = (Prepare.Options{}).memory },
            initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
        };
        pub const Stats = struct {
            program_flavor: Scope.RomFlavor = .legacy_complete,
            parallel_local_proofs: u32 = 1,
            proof_workers: usize = 8,
            local_queue_wait_ns: u64 = 0,
            /// Job durations overlap when parallel_local_proofs > 1.
            policy_ns: u64 = 0,
            restore_ns: u64 = 0,
            execution_ns: u64 = 0,
            native_witness_ns: u64 = 0,
            endpoint_preparation_ns: u64 = 0,
            local_provider_ns: u64 = 0,
            runner_segment_release_ns: u64 = 0,
            local_original_ns: u64 = 0,
            local_core_proof_ns: u64 = 0,
            local_artifact_ns: u64 = 0,
            native_release_ns: u64 = 0,
            final_snapshot_ns: u64 = 0,
            global_endpoint_sort_ns: u64 = 0,
            global_memory_prepare_ns: u64 = 0,
            bridge_proof_ns: u64 = 0,
            narrow_release_ns: u64 = 0,
            global_memory_proof_ns: u64 = 0,
            global_artifact_ns: u64 = 0,
            fresh_bundle_verify_ns: u64 = 0,
            whole_ns: u64 = 0,
            cycles: u64 = 0,
            cohorts: u32 = 0,
            bridge_batches: u32 = 0,
            logical_ram_events: u64 = 0,
            endpoint_events: u64 = 0,
            staged_bytes: u64 = 0,
            retained_endpoint_peak_bytes: usize = 0,
            charged_peak_bytes: usize = 0,
        };
        pub const Result = struct {
            a: std.mem.Allocator,
            budget: *engine.host_budget_allocator.SharedHostBudget,
            global_memory: if (compact) Compact.Proof else Memory.Proof,
            bridges: []Bridge.Proof,
            selected_initial_addresses: []u32,
            stats: Stats,
            verified: Bundle.Summary,
            cohort_policy: Window.CohortPolicy,
            pub fn deinit(self: *Result) void {
                self.global_memory.deinit();
                for (self.bridges) |*bridge| bridge.deinit();
                self.a.free(self.bridges);
                self.a.free(self.selected_initial_addresses);
                const budget = self.budget;
                self.a.destroy(self);
                budget.destroy();
            }
        };
        const Narrow = struct {
            endpoints: Collect.Owned,
            lease: *Retained.Owned,
            source: Scope.Source,
            live: bool = true,
            fn deinit(self: *Narrow) void {
                if (!self.live) return;
                self.endpoints.deinit();
                self.lease.deinit();
                self.live = false;
            }
        };
        fn filename(buffer: *[64]u8, prefix: []const u8, index: u32, suffix: []const u8) ![]const u8 {
            return std.fmt.bufPrint(buffer, "{s}-{d}.{s}", .{ prefix, index, suffix });
        }
        const Job = @import("block_v8_endpoint_local_proof_job_v1.zig").For(Options, Narrow);
        fn finishOldest(a: std.mem.Allocator, directory: std.fs.Dir, pending: *std.ArrayList(*Job), narrow: *std.ArrayList(Narrow), stats: *Stats, retained_bytes: *usize, reserved_bytes: *usize, options: Options) !void {
            const job = pending.orderedRemove(0);
            defer job.deinit();
            var wait = try std.time.Timer.start();
            job.join();
            stats.local_queue_wait_ns += wait.read();
            var completed = try job.finish(directory, options.max_staged_bytes - stats.staged_bytes);
            errdefer completed.narrow.deinit();
            reserved_bytes.* -= job.reservation;
            if (completed.narrow.lease.retained_bytes > job.reservation) return error.EndpointLocalReservationUnderestimated;
            retained_bytes.* = try std.math.add(usize, retained_bytes.*, completed.narrow.lease.retained_bytes);
            if (try std.math.add(usize, retained_bytes.*, reserved_bytes.*) > options.max_retained_endpoint_bytes) return error.EndpointLocalRetentionLimit;
            stats.retained_endpoint_peak_bytes = @max(stats.retained_endpoint_peak_bytes, retained_bytes.*);
            stats.local_original_ns += completed.proof_ns;
            stats.local_core_proof_ns += completed.core_ns;
            stats.local_artifact_ns += completed.artifact_ns;
            stats.staged_bytes += completed.bytes;
            narrow.appendAssumeCapacity(completed.narrow);
            _ = a;
        }
        /// Header/schema plus bounded physical claims and original postcard. The
        /// companion report supplies external policy; this transport is no receipt.
        fn writeOriginal(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, magic: *const [8]u8, stark: core.proof_suites.Blake3.Proof, claims: anytype, maximum: usize) !usize {
            var out = @import("bounded_artifact_writer_v1.zig").Writer.init(a, maximum);
            defer out.deinit();
            try out.writeAll(magic);
            try out.writeAll(&@import("block_v7_union_claim_wire_v1.zig").schemaId(@TypeOf(claims)));
            var remaining: usize = 1 << 20;
            try @import("block_v7_union_claim_wire_v1.zig").encode(@TypeOf(claims), &out, claims, &remaining);
            try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &out, stark);
            try dir.writeFile(.{ .sub_path = name, .data = out.bytes.items });
            return out.bytes.items.len;
        }
        pub const FileProvider = struct {
            directory: std.fs.Dir,
            bridges: []const Bridge.Proof,
            source_count: u32,
            metadata_bytes: usize,
            proof_bytes: usize,
            pub const LocalLease = struct {
                a: std.mem.Allocator,
                metadata: []u8,
                proof: []u8,
                pub fn deinit(self: *@This()) void {
                    self.a.free(self.metadata);
                    self.a.free(self.proof);
                }
            };
            pub const BridgeLease = struct {
                first: u32,
                count: u32,
                proof: *const Bridge.Proof,
                pub fn deinit(_: *@This()) void {}
            };
            pub fn loadLocal(self: *const FileProvider, a: std.mem.Allocator, index: u32) !LocalLease {
                var name: [64]u8 = undefined;
                const metadata = try self.directory.readFileAlloc(a, try filename(&name, "local", index, "json"), self.metadata_bytes);
                errdefer a.free(metadata);
                const proof = try self.directory.readFileAlloc(a, try filename(&name, "local", index, "proof"), self.proof_bytes);
                return .{ .a = a, .metadata = metadata, .proof = proof };
            }
            pub fn loadBridge(self: *const FileProvider, _: std.mem.Allocator, index: u32) !BridgeLease {
                if (index >= self.bridges.len) return error.MissingEndpointBridgeBatch;
                const first = try std.math.mul(u32, index, BridgeScope.MAX_BATCH_SOURCES);
                if (first >= self.source_count) return error.MissingEndpointBridgeBatch;
                return .{ .first = first, .count = @min(BridgeScope.MAX_BATCH_SOURCES, self.source_count - first), .proof = &self.bridges[index] };
            }
        };
        pub fn run(budget: *engine.host_budget_allocator.SharedHostBudget, pool: *engine.work_pool.WorkPool, directory: std.fs.Dir, request: Request, options: Options) !*Result {
            const cycles = request.trusted_window.window.cycles;
            if (options.parallel_local_proofs == 0 or options.parallel_local_proofs > 2 or options.proof_workers == 0 or options.proof_workers > 64) return error.InvalidEndpointLocalConcurrency;
            if (!std.meta.eql(request.elf_sha256, request.trusted_window.elf_sha256) or cycles == 0 or options.cohort_cycles == 0 or options.cohort_cycles > options.max_cohort_cycles or options.max_cohorts == 0 or options.max_staged_bytes == 0 or options.max_retained_endpoint_bytes == 0) return error.InvalidEndpointLocalExecution;
            const count = try std.math.divCeil(u32, cycles, options.cohort_cycles);
            if (count > @min(options.max_cohorts, BridgeScope.MAX_SOURCES)) return error.EndpointLocalCohortLimit;
            var entries = directory.iterate();
            if (try entries.next() != null) return error.NonemptyEndpointLocalDirectory;
            const a = budget.allocator();
            var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
            defer binding.deinit();
            var whole = try std.time.Timer.start();
            var timer = try std.time.Timer.start();
            var stats = Stats{ .program_flavor = options.program_flavor, .cohorts = count, .parallel_local_proofs = options.parallel_local_proofs, .proof_workers = options.proof_workers };
            const cohort_policy = Window.CohortPolicy{ .cohort_count = count, .max_cohort_cycles = options.cohort_cycles };
            if (!compact and !options.boundary.isEmpty()) return error.UnsupportedLegacyExecutionBoundary;
            var window = try Window.Owned.deriveCohortsWithBoundary(a, request.elf, request.incoming, request.outgoing, request.trusted_window, cohort_policy, options.boundary, options.initial);
            defer window.deinit();
            var program_image = try Program.Owned.init(a, request.elf, request.elf_sha256, .rv32im_zkvm_ethereum_sha_v1, options.initial);
            defer program_image.deinit();
            if (!std.meta.eql(program_image.root.bytes, window.program_root)) return error.UntrustedEndpointLocalProgram;
            stats.policy_ns = timer.lap();
            const trusted = Scope.Trusted{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = request.config, .cohort_count = count, .terminal_cycle = if (options.boundary.terminal != null) cycles else null, .boundary_policy_id = if (options.boundary.terminal) |last| last.policy_id else @splat(0) };
            var session = try @import("../runner/mod.zig").EthereumShaExecutionSession.init(a, request.elf, .{ .input = &.{}, .trace_retention = .segment_owned, .clock_frame = .leaf_local, .direct_ram_wide = options.native_profile.isWide(), .direct_ram_max_clock = if (options.native_profile.isDirect()) @intCast(@import("../access_clock.zig").maximum(options.cohort_cycles)) else null, .stop_on_halt_flag = true, .require_current_output_accesses = false });
            var session_live = true;
            defer if (session_live) session.deinit();
            try Prepare.restoreSession(a, &session, request.incoming);
            stats.restore_ns = timer.lap();
            var narrow: std.ArrayList(Narrow) = .empty;
            defer {
                for (narrow.items) |*item| item.deinit();
                narrow.deinit(a);
            }
            try narrow.ensureTotalCapacity(a, count);
            var net: std.ArrayList(Collect.Transition) = .empty;
            defer net.deinit(a);
            var continuation: ?@import("../runner/result.zig").ContinuationToken = null;
            var retained_bytes: usize = 0;
            var reserved_bytes: usize = 0;
            var pending: std.ArrayList(*Job) = .empty;
            defer {
                for (pending.items) |job| job.deinit();
                pending.deinit(a);
            }
            try pending.ensureTotalCapacity(a, options.parallel_local_proofs);
            for (0..count) |cohort| {
                if (pending.items.len == options.parallel_local_proofs) try finishOldest(a, directory, &pending, &narrow, &stats, &retained_bytes, &reserved_bytes, options);
                timer.reset();
                {
                    const before = stats;
                    const cohort_cycles: u32 = @intCast(@min(options.cohort_cycles, cycles - stats.cycles));
                    const segment = if (continuation) |token| try session.resumeSegment(token, cohort_cycles) else try session.startSegment(cohort_cycles);
                    stats.execution_ns += timer.lap();
                    const current = try Prepare.makeCurrent(a, segment, program_image.root.bytes);
                    var current_live = true;
                    defer if (current_live) current.deinit();
                    stats.native_witness_ns += timer.lap();
                    if (current.segment.base.cycle_count != cohort_cycles) return error.EndpointLocalIncompleteWindow;
                    const terminal_cohort = options.boundary.terminal != null and cohort + 1 == count;
                    if (terminal_cohort) {
                        if (current.segment.base.continuation != null or current.segment.base.completion_reason != .halt_flag) return error.UntrustedTerminalSourceCompletion;
                    } else if (current.segment.base.continuation == null) return error.EndpointLocalIncompleteWindow;
                    continuation = current.segment.base.continuation;
                    const ram_clock_rows = current.segment.base.state_chain_tracker.clock_updates_mem.items.len;
                    const register_clock_rows = current.segment.base.state_chain_tracker.clock_updates_reg.items.len;
                    const owner = current.owner;
                    var native_taken = false;
                    defer if (native_taken) owner.deinit();
                    const frame = Collect.Frame{ .clock_frame = current.segment.base.clock_frame, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = cohort_cycles };
                    const events = try Prepare.extractEvents(a, owner, frame, options.collector.max_events);
                    defer a.free(events);
                    var endpoints = try Collect.collectGlobal(a, .{ .frame = frame, .cohort_ordinal = @intCast(cohort), .cohort_count = count }, events, options.collector);
                    var endpoints_live = true;
                    defer if (endpoints_live) endpoints.deinit();
                    stats.logical_ram_events = try std.math.add(u64, stats.logical_ram_events, events.len);
                    stats.endpoint_events = try std.math.add(u64, stats.endpoint_events, endpoints.endpoints.len);
                    if (stats.endpoint_events > options.max_endpoint_events) return error.EndpointLocalEventLimit;
                    try net.appendSlice(a, endpoints.net_transitions);
                    stats.endpoint_preparation_ns += timer.lap();
                    var providers = try Prepare.LookupPreparation.init(a, owner, &endpoints, request.config, .{}, options.proof.context.lookup);
                    var providers_live = true;
                    defer if (providers_live) providers.deinit();
                    var census = try Prepare.collectProgramCensus(a, current, program_image.root, program_image.leaves, program_image.info.memory_layout.program_base);
                    var census_live = true;
                    defer if (census_live) census.deinit();
                    var sparse_rom: ?Sparse.Owned = null;
                    var sparse_live = true;
                    defer if (sparse_live) if (sparse_rom) |*plan| plan.deinit();
                    if (options.program_flavor == .sparse_elf) {
                        var support: std.ArrayList(Sparse.Entry) = .empty;
                        defer support.deinit(a);
                        for (census.plan.multiplicities, 0..) |multiplicity, pc_index| if (multiplicity != 0) try support.append(a, .{ .pc = program_image.info.memory_layout.program_base + 4 * @as(u32, @intCast(pc_index)), .count = multiplicity });
                        sparse_rom = try Sparse.Owned.fromImage(a, .{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = trusted.profile, .program_root = program_image.root, .expected_fetches = census.plan.expected_fetches }, support.items, &program_image, .{ .initial = options.initial });
                        // Counts were collected once. The sparse owner retains only
                        // positive support; the dense census is no longer needed.
                        a.free(census.multiplicities);
                        census.multiplicities = &.{};
                        census.plan.multiplicities = &.{};
                    }
                    var program = if (sparse_rom) |*plan| try SparseROM.ForBackend(Cpu).commit(a, plan, request.config) else try ROM.ForBackend(Cpu).commit(a, census.plan, request.config);
                    var program_live = true;
                    defer if (program_live) program.deinit(a);
                    stats.local_provider_ns += timer.lap();
                    _ = try current.takeNativeOwner();
                    native_taken = true;
                    current.deinit();
                    current_live = false;
                    stats.runner_segment_release_ns += timer.lap();
                    const reservation = try @import("block_v8_endpoint_local_proof_job_v1.zig").retainedReservation(endpoints.matrix, request.config.fri_config.log_blowup_factor);
                    if (try std.math.add(usize, try std.math.add(usize, retained_bytes, reserved_bytes), reservation) > options.max_retained_endpoint_bytes) return error.EndpointLocalRetentionLimit;
                    const job = try a.create(Job);
                    job.* = .{
                        .a = a,
                        .index = @intCast(cohort),
                        .count = count,
                        .trusted = trusted,
                        .image = &program_image,
                        .owner = owner,
                        .endpoints = endpoints,
                        .providers = providers,
                        .census = census,
                        .program = program,
                        .sparse_rom = sparse_rom,
                        .frame = frame,
                        .preparation = .{
                            .execution_ns = stats.execution_ns - before.execution_ns,
                            .native_witness_ns = stats.native_witness_ns - before.native_witness_ns,
                            .endpoint_preparation_ns = stats.endpoint_preparation_ns - before.endpoint_preparation_ns,
                            .local_provider_ns = stats.local_provider_ns - before.local_provider_ns,
                            .runner_segment_release_ns = stats.runner_segment_release_ns - before.runner_segment_release_ns,
                            .logical_ram_events = events.len,
                            .ram_clock_rows = ram_clock_rows,
                            .register_clock_rows = register_clock_rows,
                        },
                        .options = options,
                        .reservation = reservation,
                        .workers = options.proof_workers,
                    };
                    // Move all owners together before a thread can observe this job.
                    native_taken = false;
                    endpoints_live = false;
                    providers_live = false;
                    census_live = false;
                    program_live = false;
                    sparse_live = false;
                    pending.appendAssumeCapacity(job);
                    reserved_bytes += reservation;
                    try job.start(options.parallel_local_proofs > 1);
                    stats.cycles += cohort_cycles;
                    // All per-cohort defers run here: only narrow endpoint rows/tree and
                    // serialized local bytes survive. No native witness is reconstructed.
                }
                stats.native_release_ns += timer.lap();
            }
            while (pending.items.len != 0) try finishOldest(a, directory, &pending, &narrow, &stats, &retained_bytes, &reserved_bytes, options);
            timer.reset();
            var outgoing = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_window_cycles = cycles });
            defer outgoing.deinit(a);
            if (!std.meta.eql(outgoing.identity(), request.trusted_window.outgoing_sha256)) return error.EndpointLocalOutgoingMismatch;
            session.deinit();
            session_live = false;
            stats.final_snapshot_ns = timer.lap();
            const Ordering = struct {
                fn less(_: void, left: Collect.Transition, right: Collect.Transition) bool {
                    if (left.address != right.address) return left.address < right.address;
                    return left.clock < right.clock;
                }
            };
            std.mem.sort(Collect.Transition, net.items, {}, Ordering.less);
            var addresses: std.ArrayList(u32) = .empty;
            defer addresses.deinit(a);
            for (net.items) |event| if (addresses.items.len == 0 or addresses.items[addresses.items.len - 1] != event.address) try addresses.append(a, event.address);
            try window.selectAddresses(addresses.items, options.initial);
            stats.global_endpoint_sort_ns = timer.lap();
            const info = window.initial.info;
            const legacy_policy = @import("block_v7_execution_policy_v1.zig").Policy{ .initialized = &window.initial, .program_root = window.program_root, .terminal = .{ .final_cycle = cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) }, .config = request.config, .window = &window };
            const policy = if (compact) Compact.Policy{ .window = &window, .config = request.config, .event_count = std.math.cast(u32, stats.endpoint_events) orelse return error.EndpointLocalEventLimit } else legacy_policy;
            const memory_stage = if (compact) try Compact.Stage.init(a, policy, net.items, options.compact_limits) else try Memory.For(Cpu).Stage.init(a, policy, net.items, 0, options.memory_rows_per_shard, options.memory);
            net.deinit(a);
            net = .empty;
            var memory_stage_live = true;
            defer if (memory_stage_live) memory_stage.deinit();
            const sources = try a.alloc(BridgeScope.Source, narrow.items.len);
            defer a.free(sources);
            for (sources, narrow.items) |*source, item| source.* = .{ .local_identity = item.source.local_identity, .local_epoch = item.source.local_epoch, .endpoint_root = item.source.endpoint_root, .endpoint_count = item.source.endpoint_count, .policy = item.source.policy };
            var global = try BridgeScope.Owned.init(a, try policy.digest(), request.config, sources, try memory_stage.entry());
            defer global.deinit();
            stats.global_memory_prepare_ns = timer.lap();
            const batch_count = try std.math.divCeil(usize, count, BridgeScope.MAX_BATCH_SOURCES);
            const bridges = try a.alloc(Bridge.Proof, batch_count);
            errdefer a.free(bridges);
            var bridge_ready: usize = 0;
            errdefer for (bridges[0..bridge_ready]) |*bridge| bridge.deinit();
            for (bridges, 0..) |*bridge, batch_index| {
                const first: u32 = @intCast(batch_index * BridgeScope.MAX_BATCH_SOURCES);
                const n: u32 = @min(BridgeScope.MAX_BATCH_SOURCES, count - first);
                var batch = try global.batch(a, first, n);
                defer batch.deinit();
                const stages = try a.alloc(Bridge.Stage, n);
                defer a.free(stages);
                for (stages, narrow.items[first..][0..n]) |*stage, *item| stage.* = .{ .endpoints = item.endpoints.matrix, .tree = &item.lease.tree, .tree_allocator = a };
                bridge.* = try Bridge.produceConditional(a, batch, stages, options.bridge);
                bridge_ready += 1;
                stats.bridge_proof_ns += timer.lap();
                for (narrow.items[first..][0..n]) |*item| item.deinit();
                stats.narrow_release_ns += timer.lap();
            }
            var memory = if (compact) try memory_stage.proveConditional(global.epoch, global.entries) else try memory_stage.prove(global.epoch, global.entries);
            errdefer memory.deinit();
            memory_stage.deinit();
            memory_stage_live = false;
            stats.global_memory_proof_ns = timer.lap();
            for (bridges, 0..) |bridge, index| {
                var name: [64]u8 = undefined;
                const bytes = try writeOriginal(a, directory, try filename(&name, "bridge", @intCast(index), "proof"), "B8GBR001", bridge.stark, bridge.claims, @intCast(@min(options.codec.artifact_bytes, options.max_staged_bytes - stats.staged_bytes)));
                stats.staged_bytes = try std.math.add(u64, stats.staged_bytes, bytes);
            }
            stats.staged_bytes = try std.math.add(u64, stats.staged_bytes, try writeOriginal(a, directory, "global-memory.proof", if (compact) "B8CMR001" else "B8GMR001", memory.stark, if (compact) memory.claims else memory.claims(), @intCast(@min(options.codec.artifact_bytes, options.max_staged_bytes - stats.staged_bytes))));
            if (stats.staged_bytes > options.max_staged_bytes) return error.EndpointLocalStagingLimit;
            const global_metadata = try std.json.Stringify.valueAlloc(a, .{
                .schema = if (compact) "stwo-b8-local-compact-global-memory-metadata-v1" else "stwo-b8-local-global-memory-metadata-v1",
                .global_argument = if (compact) "compact_endpoint" else "legacy_window",
                .authority = "Address nomination and public geometry only; receiver must supply independently pinned complete endpoint snapshots and ELF, freshly verify all local originals, reconstruct the full epoch, and verify bridge/global originals.",
                .elf_sha256 = std.fmt.bytesToHex(request.elf_sha256, .lower),
                .incoming_sha256 = std.fmt.bytesToHex(request.trusted_window.incoming_sha256, .lower),
                .outgoing_sha256 = std.fmt.bytesToHex(request.trusted_window.outgoing_sha256, .lower),
                .window = request.trusted_window.window,
                .cohort_policy = cohort_policy,
                .cohort_count = count,
                .bridge_batches = batch_count,
                .config = request.config,
                .selected_initial_addresses = if (options.boundary.isEmpty()) addresses.items else window.selection.?.addresses,
                .memory_roots = memory.roots,
                .memory_interval_log = if (compact) null else memory.interval_log,
                .compact_ram_log = if (compact) policy.ramLog() else null,
                .compact_boundary_log = if (compact) policy.boundaryLog() else null,
                .endpoint_events = stats.endpoint_events,
                .global_epoch = global.epoch.digest,
            }, .{ .whitespace = .indent_2 });
            defer a.free(global_metadata);
            if (global_metadata.len > options.codec.artifact_bytes) return error.EndpointLocalStagingLimit;
            stats.staged_bytes = try std.math.add(u64, stats.staged_bytes, global_metadata.len);
            if (stats.staged_bytes > options.max_staged_bytes) return error.EndpointLocalStagingLimit;
            try directory.writeFile(.{ .sub_path = "global-public.json", .data = global_metadata });
            stats.global_artifact_ns = timer.lap();
            const selection = try a.dupe(u32, if (options.boundary.isEmpty()) addresses.items else window.selection.?.addresses);
            errdefer a.free(selection);
            const provider = FileProvider{ .directory = directory, .bridges = bridges, .source_count = count, .metadata_bytes = options.metadata.bytes, .proof_bytes = options.codec.artifact_bytes };
            const verify_bundle = if (compact) Bundle.verifyCompact else Bundle.verify;
            const verified = try verify_bundle(a, .{ .elf = request.elf, .incoming = request.incoming, .outgoing = request.outgoing, .trusted = request.trusted_window, .config = request.config, .boundary = options.boundary }, .{ .cohort_count = count, .bridge_batches = @intCast(batch_count), .cohort_policy = cohort_policy, .selected_initial_addresses = selection, .global_memory = &memory }, &provider, options.bundle);
            stats.fresh_bundle_verify_ns = timer.lap();
            stats.bridge_batches = @intCast(batch_count);
            stats.whole_ns = whole.read();
            stats.charged_peak_bytes = budget.snapshot().peak_live_bytes;
            const result = try a.create(Result);
            result.* = .{ .a = a, .budget = budget.retain(), .global_memory = memory, .bridges = bridges, .selected_initial_addresses = selection, .stats = stats, .verified = verified, .cohort_policy = cohort_policy };
            return result;
        }
    };
}
