//! Shared durable execution pipeline with explicit terminal/window theorem.
pub fn ForMode(comptime window: bool) type {
    return struct {
        //! CPU execution producer with a one-segment wide-witness lifetime. Native and
        //! precompile PCS trees are durably staged before the common epoch is drawn.
        //! The default joint-memory builder retains all events. Opt-in memory cohorts
        //! externally sort transitions and spill each bounded prechallenge component.
        //! Caller owns the budget, pool and a dedicated empty checkpoint directory.
        const std = @import("std");
        const core = @import("stwo_core");
        const Engine = @import("stwo_prover_engine");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const Runner = @import("../runner/mod.zig");
        const Execution = @import("block_v5_cpu_execution_source_v1.zig");
        const Initial = @import("block_v7_initial_intervals_v1.zig");
        const Policy = @import("block_v7_execution_policy_v1.zig");
        const Epoch = @import("block_v7_execution_epoch_v1.zig");
        const NativeCache = @import("block_v7_native_checkpoint_v1.zig");
        const ResidentNative = @import("block_v7_resident_native_stage_v1.zig");
        const FullCallerCache = @import("block_v7_caller_checkpoint_v1.zig");
        const Native = @import("block_v7_native_proof_v1.zig");
        const FullCaller = @import("block_v7_caller_joint_proof_v1.zig");
        const ROM = @import("block_v7_program_provider_v1.zig");
        const Lookup = @import("block_v7_lookup_compact_proof_v1.zig");
        const LookupPlan = @import("block_v5_native_lookup_plan_v1.zig");
        const Memory = if (window) @import("block_v7_window_memory_joint_v1.zig") else @import("block_v7_memory_joint_proof_v1.zig");
        const StreamMemory = if (window) @import("block_v7_window_streaming_memory_v1.zig") else @import("block_v7_streaming_memory_v1.zig");
        const Capture = @import("block_v7_real_window_capture_v1.zig");
        const Window = @import("block_v7_real_window_policy_v2.zig");
        const Receive = @import("block_v7_execution_receiver_v1.zig");
        const Counters = @import("../air/lookups/tables/counter.zig");
        const Event = @import("../air/block/memory_transition.zig").Transition;
        pub const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
        pub const Request = if (window) struct {
            elf: []const u8,
            elf_sha256: [32]u8,
            input: []const u8 = &.{},
            output: [43]u8 = @splat(0),
            cycles: u64,
            config: core.pcs.PcsConfig,
            state: struct { incoming: Capture.Snapshot, outgoing: Capture.Snapshot, trusted: Window.Trusted },
        } else struct {
            elf: []const u8,
            elf_sha256: [32]u8,
            input: []const u8 = &.{},
            /// Independently selected result and exact retired-cycle count.
            output: [43]u8 = @splat(0),
            cycles: u64,
            config: core.pcs.PcsConfig,
        };
        pub const Options = struct {
            reuse_original_captures: bool = false,
            capture_limits: Receive.CaptureLimits = .{},
            /// Borrowed for the entire run and consumer callback; null keeps CPU execution.
            quotient_executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor = null,
            /// Borrowed only by recursive consumers; originals never consult it.
            composition_executor: ?*const @import("../recursion/blake3_parent_composition_executor_v1.zig").Executor = null,
            interaction_executor: ?*const @import("../recursion/blake3_parent_interaction_executor_v1.zig").Executor = null,
            segment_cycles: u32,
            max_segments: u32 = 4096,
            max_callers: u32 = 4096,
            max_events: usize = 1 << 20,
            max_checkpoint_bytes: u64 = 32 << 30,
            ram_events_per_shard: u32 = 1 << 15,
            /// Explicit recursion-aware sizing; null preserves fixed shards.
            ram_component_planning: ?@import("block_v7_ram_component_planner_v1.zig").Policy = null,
            initial: Initial.Limits = .{},
            /// Explicit nonterminal-only address selection; legacy/default
            /// initialization and proof identities remain unchanged.
            sparse_window_initialization: bool = false,
            native: NativeCache.Limits = .{ .columns = .{ .columns = .{ .max_columns = 4096, .max_log_size = 24, .max_file_bytes = 8 << 30, .max_loaded_bytes = 8 << 30 }, .max_public_words = 0, .max_public_bytes = 0 }, .pcs = .{ .max_columns = 4096, .max_log_size = 24, .max_file_bytes = 8 << 30, .max_loaded_bytes = 8 << 30 }, .source = .{ .max_slots = 4096, .max_witness_cells = 1 << 28, .max_metadata_bytes = 16 << 20, .register_custody_mode = 1 }, .max_total_bytes = 16 << 30 },
            /// Optional core-stage recording; default leaves telemetry disabled.
            native_prove: Native.ProveOptions = .{},
            native_layout_mode: @import("block_v7_native_source_v1.zig").LayoutMode = .canonical_v1,
            caller: FullCallerCache.Limits = .{},
            /// Explicit new commitment/recursive-key geometry; the old route remains default.
            active_callers: bool = window,
            /// Explicit native-only union-window storage. All original raw
            /// columns and PCS trees remain charged to the hard host budget.
            resident_original_stages: bool = false,
            memory: Memory.Limits = .{ .memory = .{ .max_events = 1 << 20, .max_matrix_bytes = 2 << 30, .max_row_log = 20 }, .max_live_bytes = 8 << 30 },
            lookup: Lookup.Limits = .{},
            memory_cohorts: ?@import("block_v7_memory_cohorts_v1.zig").Limits = null,
            memory_sort_chunk: usize = 1 << 18,
        };
        pub const Stats = struct {
            cycles: u64 = 0,
            segments: u32 = 0,
            callers: u32 = 0,
            events: u64 = 0,
            fetches: u64 = 0,
            original_proofs: u32 = 0,
            checkpoint_bytes: u64 = 0,
            native_checkpoint_bytes: u64 = 0,
            caller_checkpoint_bytes: u64 = 0,
            max_native_restore_codec_bytes: usize = 0,
            event_storage_bytes: usize = 0,
            setup_ns: u64 = 0,
            execution_ns: u64 = 0,
            collection_ns: u64 = 0,
            providers_first_ns: u64 = 0,
            provider_endpoint_ns: u64 = 0,
            provider_initial_selection_ns: u64 = 0,
            provider_memory_first_ns: u64 = 0,
            provider_rom_first_ns: u64 = 0,
            provider_lookup_first_ns: u64 = 0,
            provider_epoch_ns: u64 = 0,
            memory_preparation: @import("block_v7_memory_preparation_stats_v1.zig").Stats = .{},
            ram_component_plan: ?@import("block_v7_ram_component_planner_v1.zig").Plan = null,
            native_proof_ns: u64 = 0,
            caller_proof_ns: u64 = 0,
            memory_proof_ns: u64 = 0,
            rom_proof_ns: u64 = 0,
            lookup_proof_ns: u64 = 0,
            verification_ns: u64 = 0,
            retained_capture_bytes: usize = 0,
            capture_verification_peak_bytes: usize = 0,
            consumer_ns: u64 = 0,
            whole_ns: u64 = 0,
            charged_peak_bytes: usize = 0,
            initial_source_intervals: usize = 0,
            initial_proof_intervals: usize = 0,
            initial_selected_addresses: usize = 0,
            native_layout_mode: @import("block_v7_native_source_v1.zig").LayoutMode = .canonical_v1,
            resident_original_stages: bool = false,
        };
        pub const Fixture = struct {
            original_captures: ?*Receive.Captures = null,
            quotient_executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor = null,
            composition_executor: ?*const @import("../recursion/blake3_parent_composition_executor_v1.zig").Executor = null,
            interaction_executor: ?*const @import("../recursion/blake3_parent_interaction_executor_v1.zig").Executor = null,
            allocator: std.mem.Allocator,
            trusted: Receive.Trusted,
            input: Receive.Input,
            policy: Policy.Policy,
            original: Receive.Verified,
            stats: Stats,
        };
        /// First-round material only, never an authenticated original receipt.
        /// The consumer must produce/verify its own independently admitted union.
        /// All fields are borrowed until the callback returns.
        pub const StagedWindowFixture = struct {
            recorder: ?*@import("stwo_prover_engine").stage_profile.Recorder = null,
            allocator: std.mem.Allocator,
            directory: std.fs.Dir,
            trusted: Receive.Trusted,
            policy: Policy.Policy,
            epoch: Epoch.Epoch,
            entries: []const Epoch.Entry,
            natives: []const NativeCache.Record,
            resident_natives: ?[]const *ResidentNative.Owned = null,
            native_names: []const NativeCache.Names,
            native_limits: NativeCache.Limits,
            callers: []const @import("block_v7_caller_active_checkpoint_v1.zig").Record,
            caller_names: []const @import("block_v7_caller_active_checkpoint_v1.zig").Names,
            caller_limits: @import("block_v7_caller_active_checkpoint_v1.zig").Limits,
            program_plan: @import("block_v5_program_table_v1.zig").Plan,
            program: *ROM.ForBackend(Cpu).FirstRound,
            lookup_plan: LookupPlan.Plan,
            lookup: *Lookup.For(Cpu).Stage,
            memory: *@import("block_v7_window_memory_joint_v1.zig").For(Cpu).Stage,
            pool: *Engine.work_pool.WorkPool,
            stats: Stats,
        };
        pub const NoConsumer = struct {
            pub const Result = void;
            pub fn consume(_: Fixture) !void {}
        };
        pub fn Result(comptime Consumer: type) type {
            return struct { stats: Stats, value: Consumer.Result };
        }
        const Events = StreamMemory.Events;
        const Names = struct {
            buffers: [7][64]u8 = undefined,
            native: NativeCache.Names,
            caller: FullCallerCache.Names,
            fn init(self: *@This(), index: usize) !void {
                const suffixes = [_][]const u8{ "native.raw", "native.pcs", "access.pcs", "caller.raw", "caller.pcs", "external.raw", "external.pcs" };
                var names: [7][]const u8 = undefined;
                for (&self.buffers, suffixes, &names) |*buffer, suffix, *name| name.* = try std.fmt.bufPrint(buffer, "v7-{d}-{s}", .{ index, suffix });
                self.native = .{ .raw = names[0], .native = names[1], .access = names[2] };
                self.caller = .{ .raw = names[3], .pcs = names[4], .access_raw = names[5], .access_pcs = names[6] };
            }
            fn erase(self: *const @This(), dir: std.fs.Dir) void {
                for ([_][]const u8{ self.native.raw, self.native.native, self.native.access, self.caller.raw, self.caller.pcs, self.caller.access_raw, self.caller.access_pcs }) |name| dir.deleteFile(name) catch {};
            }
            fn eraseRequired(self: *const @This(), dir: std.fs.Dir, has_access: bool, has_caller: bool, active_callers: bool) !void {
                try dir.deleteFile(self.native.raw);
                try dir.deleteFile(self.native.native);
                if (has_access) try dir.deleteFile(self.native.access);
                if (has_caller) {
                    try dir.deleteFile(self.caller.raw);
                    try dir.deleteFile(self.caller.pcs);
                    if (!active_callers) {
                        try dir.deleteFile(self.caller.access_raw);
                        try dir.deleteFile(self.caller.access_pcs);
                    }
                }
            }
        };
        fn current(a: std.mem.Allocator, owned: @import("../runner/result.zig").EthereumShaSegmentResult, root: [32]u8) !*Execution.Current {
            var segment = owned;
            errdefer segment.deinit();
            var io = try @import("blake3_segment_public.zig").Owned.init(a, &segment.base);
            errdefer io.deinit();
            io.data.program_root = .{ .bytes = root };
            io.data.initial_rw_root = null;
            io.data.final_rw_root = null;
            io.data.io_entries.input_len = 0;
            io.data.io_entries.input_words = &.{};
            io.data.io_entries.output_len = 0;
            io.data.io_entries.output_words = &.{};
            const owner = try @import("blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, try Execution.externalCount(&segment));
            errdefer owner.deinit();
            try owner.sealNativeOnly();
            const out = try a.create(Execution.Current);
            out.* = .{ .a = a, .segment = segment, .io = io, .owner = owner, .recipe = .custody_v2 };
            return out;
        }
        /// Consumer runs only after every original STARK has independently verified.
        /// All source proofs and checkpoint descriptors expire on return; retained
        /// results must own their metadata and share the caller-owned budget lifetime.
        pub fn run(budget: *Engine.host_budget_allocator.SharedHostBudget, dir: std.fs.Dir, request: Request, options: Options, pool: *Engine.work_pool.WorkPool, comptime Consumer: type) !Result(Consumer) {
            return if (options.active_callers) runSelected(true, budget, dir, request, options, pool, Consumer) else runSelected(false, budget, dir, request, options, pool, Consumer);
        }
        fn runSelected(comptime active: bool, budget: *Engine.host_budget_allocator.SharedHostBudget, dir: std.fs.Dir, request: Request, options: Options, pool: *Engine.work_pool.WorkPool, comptime Consumer: type) !Result(Consumer) {
            const CallerCache = if (active) @import("block_v7_caller_active_checkpoint_v1.zig") else FullCallerCache;
            const Caller = if (active) @import("block_v7_caller_active_proof_v1.zig") else FullCaller;

            if (comptime @hasDecl(Consumer, "consumeStagedWindow")) {
                if (comptime !window or !active) return error.UnsupportedV7StagedUnionMode;
                if (options.reuse_original_captures) return error.UnsupportedV7StagedOriginalCaptures;
            }

            if (options.resident_original_stages) {
                if (comptime !window or !active or !@hasDecl(Consumer, "consumeStagedWindow")) return error.UnsupportedV7ResidentOriginalMode;
            }
            if (!window and options.sparse_window_initialization) return error.UnsupportedV7SparseTerminalInitialization;
            if (options.segment_cycles == 0 or options.max_segments == 0 or options.max_events == 0 or options.max_checkpoint_bytes == 0 or request.cycles == 0) return error.InvalidV7StreamingLimits;
            var directory_entries = dir.iterate();
            if (try directory_entries.next() != null) return error.NonemptyV7CheckpointDirectory;
            const a = budget.allocator();
            var timer = try std.time.Timer.start();
            var whole = try std.time.Timer.start();
            var stats = Stats{ .native_layout_mode = options.native_layout_mode, .resident_original_stages = options.resident_original_stages };
            var native_policy = options.native;
            if (native_policy.native_layout_mode != .canonical_v1 and native_policy.native_layout_mode != options.native_layout_mode) return error.ConflictingV7NativeLayoutPolicy;
            native_policy.native_layout_mode = options.native_layout_mode;
            if (window and (request.cycles != request.state.trusted.window.cycles or !std.meta.eql(request.elf_sha256, request.state.trusted.elf_sha256) or options.memory_cohorts != null)) return error.InvalidV7WindowRequest;
            var selected_window = if (window) try Window.Owned.derive(a, request.elf, request.state.incoming, request.state.outgoing, request.state.trusted, options.initial) else {};
            defer if (window) selected_window.deinit();
            var initialized = if (window) try selected_window.cloneInitial(a) else try Initial.Owned.derive(a, request.elf, request.elf_sha256, profile, options.initial);
            defer initialized.deinit();
            var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, request.elf, &initialized, options.initial);
            defer image.deinit();
            const policy = Policy.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = request.cycles, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = request.output }, .config = request.config, .window = if (window) &selected_window else null };
            try policy.validate();
            var session = try Runner.EthereumShaExecutionSession.init(a, request.elf, .{ .input = request.input, .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
            var session_live = true;
            defer if (session_live) session.deinit();
            if (window) {
                const addresses = try a.alloc(u32, request.state.incoming.words.len);
                defer a.free(addresses);
                for (addresses, request.state.incoming.words) |*address, word| address.* = word.address;
                // Complete snapshot semantics: absent mutable ELF/input words
                // mean zero, not the fresh loader's original value.
                for (try session.memory.canonicalAlignedWordAddresses()) |address| session.memory.writeU32AssumePrepared(address, 0);
                try session.memory.prepareAlignedWordWrites(addresses);
                for (request.state.incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
                session.cpu = request.state.incoming.cpu;
            }
            var counters = try Counters.Set.init(a);
            defer counters.deinit(a);
            const multiplicities = try a.alloc(u64, image.leaves.len / 4);
            defer a.free(multiplicities);
            @memset(multiplicities, 0);
            var events = try Events.init(a, dir, options.max_events, if (options.memory_cohorts != null) options.memory_sort_chunk else null);
            defer events.deinit();
            var records: std.ArrayList(NativeCache.Record) = .empty;
            defer {
                for (records.items) |*record| record.deinit();
                records.deinit(a);
            }
            var resident: std.ArrayList(*ResidentNative.Owned) = .empty;
            defer {
                for (resident.items) |stage| stage.deinit();
                resident.deinit(a);
            }
            var callers: std.ArrayList(CallerCache.Record) = .empty;
            defer callers.deinit(a);
            var demand: [6]u64 = @splat(0);
            var attempted: usize = 0;
            defer for (0..attempted) |i| {
                var names: Names = undefined;
                names.init(i) catch unreachable;
                names.erase(dir);
            };
            var continuation: ?@import("../runner/result.zig").ContinuationToken = null;
            var high_byte: u8 = 0;
            stats.setup_ns = timer.lap();
            while (true) {
                const collected = records.items.len + resident.items.len;
                if (collected >= options.max_segments) return error.V7ExecutionSegmentLimit;
                const index: u32 = @intCast(collected);
                const segment_cycles: usize = if (window) @intCast(@min(options.segment_cycles, request.cycles - stats.cycles)) else options.segment_cycles;
                const segment = if (continuation) |token| try session.resumeSegment(token, segment_cycles) else try session.startSegment(segment_cycles);
                stats.execution_ns += timer.lap();
                const live = try current(a, segment, image.root.bytes);
                defer live.deinit();
                continuation = live.segment.base.continuation;
                const next_cycles = try std.math.add(u64, stats.cycles, live.segment.base.cycle_count);
                if (next_cycles > request.cycles or (continuation == null and next_cycles != request.cycles)) return error.UnexpectedV7ExecutionLength;
                stats.cycles = next_cycles;
                if (window and (continuation == null or live.segment.base.completion_reason != null)) return error.NonterminalWindowHalted;
                if (!window and continuation == null) {
                    if (live.segment.base.completion_reason != .halt_flag or live.segment.base.output_len != 43 or !std.mem.eql(u8, live.segment.base.output orelse return error.MissingV7Output, &request.output)) return error.UnexpectedV7ExecutionOutput;
                    for (live.segment.base.output_words) |word| if (word.addr == policy.terminal.data_address + 40) {
                        high_byte = @truncate(word.value >> 24);
                    };
                }
                var names: Names = undefined;
                try names.init(index);
                if (!options.resident_original_stages) attempted += 1;
                var native_limits = native_policy;
                if (stats.checkpoint_bytes >= options.max_checkpoint_bytes) return error.V7ExecutionCheckpointLimit;
                native_limits.max_total_bytes = @min(native_limits.max_total_bytes, options.max_checkpoint_bytes - stats.checkpoint_bytes);
                const pin = if (options.resident_original_stages) blk: {
                    const stage = try ResidentNative.Owned.collect(a, live, request.config, profile, index, &counters, events.sink(), native_limits);
                    resident.append(a, stage) catch |err| {
                        stage.deinit();
                        return err;
                    };
                    break :blk stage.pin();
                } else blk: {
                    var record = try NativeCache.collect(a, dir, names.native, live.owner, request.config, profile, index, live.segment.base.global_first_cycle, &counters, events.sink(), native_limits);
                    records.append(a, record) catch |err| {
                        record.deinit();
                        return err;
                    };
                    stats.native_checkpoint_bytes += record.stats.written_bytes;
                    stats.checkpoint_bytes += record.stats.written_bytes;
                    stats.max_native_restore_codec_bytes = @max(stats.max_native_restore_codec_bytes, record.stats.retained_loaded_bytes);
                    break :blk records.items[index].pin();
                };
                try LookupPlan.addDemand(&demand, try LookupPlan.nativeDemand(pin.shape, pin.template.external_retirements));
                try LookupPlan.addDemand(&demand, try LookupPlan.sidecarMemoryDemand(pin.expected_events));
                const fetches = try Execution.fetches(a, live, false);
                defer a.free(fetches);
                for (fetches) |fetch| {
                    const base = initialized.info.memory_layout.program_base;
                    if (fetch.address < base or fetch.address & 3 != 0 or (fetch.address - base) / 4 >= multiplicities.len) return error.InvalidV7ProgramFetch;
                    const at = (fetch.address - base) / 4;
                    multiplicities[at] = try std.math.add(u64, multiplicities[at], fetch.multiplicity);
                    stats.fetches = try std.math.add(u64, stats.fetches, fetch.multiplicity);
                }
                if (pin.template.external_retirements != 0) {
                    if (callers.items.len >= options.max_callers) return error.V7ExecutionCallerLimit;
                    var witness = try @import("block_v5_precompile_witness_v1.zig").Witness.initSegment(a, &live.segment);
                    defer witness.deinit();
                    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = live.segment.extension.keccakf_calls.records(), .recovery = live.segment.extension.signer_recovery_calls.records() }).register(&counters);
                    if (active) try @import("block_v7_caller_active_columns_v1.zig").registerLookup(a, &witness, &counters) else try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, &counters);
                    var caller_limits = options.caller;
                    if (stats.checkpoint_bytes >= options.max_checkpoint_bytes) return error.V7ExecutionCheckpointLimit;
                    caller_limits.max_total_bytes = @min(caller_limits.max_total_bytes, options.max_checkpoint_bytes - stats.checkpoint_bytes);
                    const caller = try CallerCache.collect(a, dir, names.caller, &witness, pin, @intCast(callers.items.len), &counters, events.sink(), caller_limits);
                    try callers.append(a, caller);
                    stats.caller_checkpoint_bytes += caller.written_bytes;
                    stats.checkpoint_bytes += caller.written_bytes;
                    try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demand, &witness.statement, witness.total_steps, request.config);
                    try LookupPlan.addDemand(&demand, try LookupPlan.sidecarMemoryDemand(caller.event_count));
                }
                stats.collection_ns += timer.lap();
                if (continuation == null or (window and stats.cycles == request.cycles)) break;
            }
            var provider_timer = try std.time.Timer.start();
            if (window) {
                var actual = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_snapshot_words = options.initial.max_initialized_words });
                defer actual.deinit(a);
                if (!std.meta.eql(actual.identity(), request.state.trusted.outgoing_sha256)) return error.UntrustedV7WindowEndpoint;
            }
            session.deinit();
            session_live = false;
            stats.segments = @intCast(records.items.len + resident.items.len);
            stats.callers = @intCast(callers.items.len);
            stats.events = events.count();
            stats.event_storage_bytes = events.storageBytes();
            stats.initial_source_intervals = initialized.intervals.len;
            stats.provider_endpoint_ns = provider_timer.lap();
            if (window and options.sparse_window_initialization) {
                if (events.spool != null) return error.UnsupportedV7WindowCohorts;
                const addresses = try a.alloc(u32, events.values.items.len);
                defer a.free(addresses);
                for (events.values.items, addresses) |event, *address| {
                    if (event.space != 1) return error.InvalidV7WindowMemorySpace;
                    address.* = event.address;
                }
                try selected_window.selectAddresses(addresses, options.initial);
                const narrow = try selected_window.cloneInitial(a);
                initialized.deinit();
                initialized = narrow;
                stats.initial_selected_addresses = selected_window.selection.?.addresses.len;
            }
            stats.initial_proof_intervals = initialized.intervals.len;
            stats.provider_initial_selection_ns = provider_timer.lap();
            const windows = try a.alloc(Policy.Native, records.items.len + resident.items.len);
            defer a.free(windows);
            for (windows, 0..) |*native_window, index| {
                const pin = if (options.resident_original_stages) resident.items[index].pin() else records.items[index].pin();
                native_window.* = .{ .shape = pin.shape, .frame = pin.frame, .external_retirements = pin.template.external_retirements };
            }
            try policy.validateWindows(windows);
            var cohort_limits = options.memory_cohorts;
            if (cohort_limits) |*limits| {
                if (stats.checkpoint_bytes >= options.max_checkpoint_bytes) return error.V7ExecutionCheckpointLimit;
                limits.max_total_file_bytes = @min(limits.max_total_file_bytes, options.max_checkpoint_bytes - stats.checkpoint_bytes);
            }
            const memory_plan = if (options.ram_component_planning) |sizing| try @import("block_v7_ram_component_planner_v1.zig").select(std.math.cast(u32, stats.events) orelse return error.RamComponentPlanningResourceLimit, sizing, options.memory.memory) else null;
            stats.ram_component_plan = memory_plan;
            var memory = try StreamMemory.Stage.init(a, dir, policy, &events, high_byte, if (memory_plan) |selected| selected.events_per_component else options.ram_events_per_shard, options.memory, cohort_limits);
            stats.provider_memory_first_ns = provider_timer.lap();
            if (window) stats.memory_preparation = memory.value.preparation;
            var memory_live = true;
            defer if (memory_live) memory.deinit();
            stats.event_storage_bytes = events.storageBytes();
            events.deinit();
            stats.checkpoint_bytes += memory.checkpointBytes();
            const rom_plan = @import("block_v5_program_table_v1.zig").Plan{ .program_root = image.root, .leaves = image.leaves, .multiplicities = multiplicities, .expected_fetches = stats.fetches, .log_size = @max(7, std.math.log2_int_ceil(usize, multiplicities.len)) };
            var rom_first = try ROM.ForBackend(Cpu).commit(a, rom_plan, request.config);
            var rom_live = true;
            defer if (rom_live) rom_first.deinit(a);
            const rom_roots = rom_first.roots;
            stats.provider_rom_first_ns = provider_timer.lap();
            const lookup_plan = LookupPlan.Plan{ .index = 0, .first_execution = 0, .execution_count = stats.segments, .max_requests = demand };
            var lookup_first = try Lookup.For(Cpu).Stage.init(a, &counters, lookup_plan, request.config, null, options.lookup);
            var lookup_live = true;
            defer if (lookup_live) lookup_first.deinit();
            const lookup_roots = lookup_first.roots;
            const lookup_layout = lookup_first.layout;
            stats.provider_lookup_first_ns = provider_timer.lap();
            var roster: std.ArrayList(Epoch.Entry) = .empty;
            defer roster.deinit(a);
            for (records.items) |*record| try roster.append(a, try record.entry(a));
            for (resident.items) |stage| try roster.append(a, try stage.pin().entry(a));
            for (callers.items) |*caller| try roster.append(a, try caller.pin().entry(a));
            try roster.appendSlice(a, &.{ try ROM.firstEntry(rom_plan, rom_first.roots), try Lookup.firstEntry(lookup_plan, lookup_first.layout, lookup_first.roots) });
            const memory_entries = try memory.entries(a);
            defer a.free(memory_entries);
            try roster.appendSlice(a, memory_entries);
            var counts: Epoch.Counts = @splat(0);
            for (roster.items) |entry| counts[@intFromEnum(entry.family)] += 1;
            const epoch = try Epoch.Epoch.init(try policy.digest(), request.config, counts, roster.items, roster.items.len);
            try epoch.requireCompleteFamilies();
            stats.provider_epoch_ns = provider_timer.lap();
            stats.providers_first_ns = timer.lap();
            if (comptime @hasDecl(Consumer, "consumeStagedWindow")) {
                if (comptime !@hasDecl(Consumer, "discardStagedResult")) @compileError("a staged union consumer must destroy its returned result if checkpoint cleanup fails");
                if (comptime !window or !active) {
                    return error.UnsupportedV7StagedUnionMode;
                } else {
                    const names = try a.alloc(Names, records.items.len);
                    defer a.free(names);
                    const native_names = try a.alloc(NativeCache.Names, records.items.len);
                    defer a.free(native_names);
                    for (names, native_names, 0..) |*name, *out, index| {
                        try name.init(index);
                        out.* = name.native;
                    }
                    const caller_names = try a.alloc(CallerCache.Names, callers.items.len);
                    defer a.free(caller_names);
                    for (callers.items, caller_names) |record, *out| out.* = names[record.execution_index].caller;
                    const trusted = Receive.Trusted{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = profile, .terminal = policy.terminal, .config = request.config, .window = &selected_window };
                    const value = try Consumer.consumeStagedWindow(.{
                        .recorder = options.native_prove.recorder,
                        .allocator = a,
                        .directory = dir,
                        .trusted = trusted,
                        .policy = policy,
                        .epoch = epoch,
                        .entries = roster.items,
                        .natives = records.items,
                        .resident_natives = if (options.resident_original_stages) resident.items else null,
                        .native_names = native_names,
                        .native_limits = native_policy,
                        .callers = callers.items,
                        .caller_names = caller_names,
                        .caller_limits = options.caller,
                        .program_plan = rom_plan,
                        .program = &rom_first,
                        .lookup_plan = lookup_plan,
                        .lookup = &lookup_first,
                        .memory = memory.value,
                        .pool = pool,
                        .stats = stats,
                    });
                    errdefer Consumer.discardStagedResult(value);
                    stats.consumer_ns = timer.lap();
                    for (records.items, names) |record, name| try name.eraseRequired(dir, record.auxiliary != null, record.native.template.external_retirements != 0, true);
                    attempted = 0;
                    stats.whole_ns = whole.read();
                    stats.charged_peak_bytes = budget.snapshot().peak_live_bytes;
                    return .{ .stats = stats, .value = value };
                }
            } else {
                const proofs = try a.alloc(Native.Proof, records.items.len);
                defer a.free(proofs);
                var proved: usize = 0;
                defer for (proofs[0..proved]) |*proof| proof.deinit(a);
                const native_inputs = try a.alloc(Receive.Native, records.items.len);
                defer a.free(native_inputs);
                var native_prove = options.native_prove;
                native_prove.quotient_executor = options.quotient_executor;
                for (records.items, proofs, native_inputs, 0..) |*record, *proof, *input, index| {
                    var names: Names = undefined;
                    try names.init(index);
                    proof.* = NativeCache.proveOneWithOptions(a, dir, names.native, record, native_policy, epoch, roster.items, native_prove) catch |err| {
                        if (std.process.hasEnvVarConstant("STWO_V7_PROFILE_ERRORS")) std.debug.print("V7_SOURCE_FAILURE family=native index={d} error={s}\n", .{ index, @errorName(err) });
                        return err;
                    };
                    proved += 1;
                    input.* = .{ .pin = record.pin(), .proof = proof };
                }
                stats.native_proof_ns = timer.lap();
                const caller_proofs = try a.alloc(Caller.Proof, callers.items.len);
                defer a.free(caller_proofs);
                var callers_proved: usize = 0;
                defer for (caller_proofs[0..callers_proved]) |*proof| proof.deinit(a);
                const caller_inputs = try a.alloc(if (active) Receive.ActiveCaller else Receive.Caller, callers.items.len);
                defer a.free(caller_inputs);
                for (callers.items, caller_proofs, caller_inputs) |*record, *proof, *input| {
                    var names: Names = undefined;
                    try names.init(record.execution_index);
                    proof.* = try CallerCache.proveOneWithExecutor(a, dir, names.caller, record, options.caller, epoch, roster.items, pool, options.quotient_executor);
                    callers_proved += 1;
                    input.* = .{ .pin = record.pin(), .proof = proof };
                }
                stats.caller_proof_ns = timer.lap();
                var memory_proof = memory.proveWithExecutor(epoch, roster.items, options.quotient_executor) catch |err| {
                    if (std.process.hasEnvVarConstant("STWO_V7_PROFILE_ERRORS")) std.debug.print("V7_SOURCE_FAILURE family=memory error={s}\n", .{@errorName(err)});
                    return err;
                };
                defer memory_proof.deinit();
                memory.deinit();
                memory_live = false;
                stats.memory_proof_ns = timer.lap();
                rom_first.scheme.quotient_executor = options.quotient_executor;
                var rom = try ROM.ForBackend(Cpu).prove(a, &rom_first, .{ .plan = rom_plan, .expected_program_root = image.root, .roots = rom_first.roots, .epoch = epoch, .entries = roster.items });
                defer rom.deinit(a);
                rom_first.deinit(a);
                rom_live = false;
                stats.rom_proof_ns = timer.lap();
                lookup_first.scheme.quotient_executor = options.quotient_executor;
                var lookup = try lookup_first.prove(epoch, roster.items);
                defer lookup.deinit(a);
                lookup_first.deinit();
                lookup_live = false;
                stats.lookup_proof_ns = timer.lap();
                // Delete all durable witnesses before verification or any consumer callback.
                for (0..attempted) |index| {
                    var names: Names = undefined;
                    try names.init(index);
                    try names.eraseRequired(dir, records.items[index].auxiliary != null, records.items[index].native.template.external_retirements != 0, active);
                }
                attempted = 0;
                const trusted = Receive.Trusted{ .elf = request.elf, .elf_sha256 = request.elf_sha256, .profile = profile, .terminal = policy.terminal, .config = request.config, .window = if (window) &selected_window else null };
                const input = Receive.Input{ .epoch = epoch, .entries = roster.items, .natives = native_inputs, .callers = if (active) &.{} else caller_inputs, .active_callers = if (active) caller_inputs else &.{}, .program_plan = rom_plan, .program_roots = rom_roots, .program = &rom, .lookup_plan = lookup_plan, .lookup_roots = lookup_roots, .lookup = .{ .compact = .{ .layout = lookup_layout, .proof = &lookup } }, .memory = memory_proof.input() };
                const verification_limits = Receive.Limits{ .initial = options.initial, .memory = if (cohort_limits) |limits| limits.memory else .{}, .joint_memory = if (window) .{} else options.memory, .window_memory = if (window) options.memory else .{}, .compact_lookup = options.lookup, .max_segments = options.max_segments, .max_entries = roster.items.len };
                const captured: ?Receive.Captured = if (options.reuse_original_captures) try Receive.For(Cpu).verifyWithCaptures(a, trusted, input, verification_limits, options.capture_limits) else null;
                defer if (captured) |owned| owned.captures.deinit();
                const verified = if (captured) |owned| owned.verified else try Receive.For(Cpu).verify(a, trusted, input, verification_limits);
                stats.verification_ns = timer.lap();
                if (captured) |owned| {
                    const capture_memory = owned.captures.memory();
                    stats.retained_capture_bytes = capture_memory.live_bytes;
                    stats.capture_verification_peak_bytes = capture_memory.peak_live_bytes;
                }
                stats.original_proofs = @intCast(roster.items.len);
                const value = try Consumer.consume(.{ .original_captures = if (captured) |owned| owned.captures else null, .quotient_executor = options.quotient_executor, .composition_executor = options.composition_executor, .interaction_executor = options.interaction_executor, .allocator = a, .trusted = trusted, .input = input, .policy = policy, .original = verified, .stats = stats });
                stats.consumer_ns = timer.lap();
                stats.whole_ns = whole.read();
                stats.charged_peak_bytes = budget.snapshot().peak_live_bytes;
                return .{ .stats = stats, .value = value };
            }
        }
    };
}
