//! Real first pass: one live execution, sorted global replay, exact ROM and
//! field-safe provider counters. Physical proposals and bounded column-file
//! pins survive each leaf; the guest is not executed a second time.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Execution = @import("block_v5_cpu_execution_source_v1.zig");
const Runner = @import("block_v4_cpu_runner_source.zig");
const Caller = @import("block_v5_caller_pipeline_v1.zig");
const Groups = @import("block_v5_cpu_lookup_groups_v1.zig");
const Replay = @import("block_memory_replay.zig");
const Sorted = @import("block_v5_memory_replay_adapter_v1.zig");
const Global = @import("block_v5_cpu_global_plans_v1.zig");
const Tables = @import("../air/lookups/tables/mod.zig");
const Demand = @import("block_v5_native_lookup_plan_v1.zig");
const Rom = @import("../air/program/blake3_commitment.zig");
const Registers = @import("block_v5_register_windows_v1.zig");
const Witness = @import("block_v5_cpu_witness_staging_v1.zig");
const WitnessStore = @import("block_v5_witness_columns_store_v1.zig");
const Readonly = @import("block_v5_readonly_input_collection_v1.zig");
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;

pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const Driver = if (capacity) @import("block_v5_cpu_capacity_driver_admission_v1.zig") else @import("block_v5_cpu_driver_admission_v1.zig");
        const NativeRoots = if (capacity) @import("block_v5_cpu_capacity_root_proposal_v1.zig") else @import("block_v5_cpu_native_root_proposal_v1.zig");
        const NativeMemory = if (capacity) @import("block_v5_native_capacity_fused_stage_v1.zig") else @import("block_v5_native_memory_stage_v1.zig");
        const NativeStage = if (capacity) @import("block_v5_capacity_native_columns_stage_v1.zig") else @import("block_v5_native_columns_stage_v1.zig");
        pub const Limits = struct {
            planning: Driver.Limits,
            physical: NativeRoots.Limits,
            ordinary: NativeMemory.Limits,
            caller: Caller.Limits,
            groups: Groups.Limits,
            globals: Global.Limits,
            readonly: ?Readonly.Options = null,
            source_files: @import("block_v5_memory_source_writer_v1.zig").Caps = .{},
            sorter_chunk_events: usize,
            witness: Witness.Limits = .{},
            fixed_basis: if (capacity) ?@import("block_v5_native_capacity_fixed_basis_v1.zig").Limits else void = if (capacity) null else {},
        };

        pub const Collected = struct {
            a: std.mem.Allocator,
            readonly: ?Readonly.Owned = null,
            execution_recipe: @import("block_v5_execution_recipe_v1.zig").Recipe = @import("block_v5_execution_recipe_v1.zig").canonical,
            planning: Driver.Planning,
            replay: Replay.Replay,
            ordinary: []NativeMemory.Proposal,
            callers: []?Caller.Proposal,
            groups: Groups.Stage,
            globals: Global.ForBackend(Cpu),
            bound: Driver.Bound,
            register_windows: ?Registers.Plan = null,
            owned_register_windows: []Registers.Window,
            native_pins: []WitnessStore.Pin,
            caller_pins: []?WitnessStore.Pin,
            witness_file_bytes: u64,
            capacity_fused_limits: if (capacity) @import("block_v5_native_capacity_fused_proof_v1.zig").Limits else void = if (capacity) .{} else {},

            pub fn deinit(self: *Collected) void {
                const a = self.a;
                self.bound.deinit();
                if (self.readonly) |*owned| owned.deinit();
                a.free(self.native_pins);
                a.free(self.caller_pins);
                a.free(self.owned_register_windows);
                self.globals.deinit();
                self.groups.deinit();
                for (self.ordinary) |*proposal| proposal.deinit();
                a.free(self.ordinary);
                for (self.callers) |*proposal| if (proposal.*) |*owned| owned.deinit();
                a.free(self.callers);
                self.planning.deinit();
                self.replay.deinit();
                a.destroy(self);
            }
        };

        pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, source: *Runner.Source, policy: Driver.InputPolicy, config: core.pcs.PcsConfig, limits: Limits) !*Collected {
            try policy.requireSource(source, limits.planning);
            const recipe = policy.runner_pins.execution_recipe;
            try recipe.requireCompiled();
            if (limits.groups.request_limit != limits.planning.lookup_request_limit or limits.sorter_chunk_events == 0)
                return error.InvalidV5CpuCollectionLimits;
            const register_mode = ordinaryMode(limits.ordinary);
            if (register_mode > 1 or register_mode != limits.caller.register_custody_mode) return error.InvalidV5RegisterCustodyMode;
            try recipe.requireMode(register_mode);
            if (limits.caller.readonly != null or (limits.readonly != null and (!capacity or register_mode != 1))) return error.InvalidV5ReadonlyCollectionMode;
            // Heap stability matters: SortedSource borrows this Replay through proving.
            const result = try a.create(Collected);
            errdefer a.destroy(result);
            result.a = a;
            result.readonly = null;
            if (limits.readonly) |options| result.readonly = try Readonly.Owned.initWithStaging(a, options, source.input, source.schedule.segments, limits.planning.max_metadata_bytes, dir);
            errdefer if (result.readonly) |*owned| owned.deinit();
            result.execution_recipe = recipe;
            result.register_windows = null;
            result.witness_file_bytes = 0;
            result.capacity_fused_limits = if (capacity) limits.ordinary.fused else {};
            const pin_bytes = try std.math.mul(usize, source.schedule.segments, @sizeOf(WitnessStore.Pin) + @sizeOf(?WitnessStore.Pin));
            if (pin_bytes > limits.planning.max_metadata_bytes) return error.V5CpuRosterResourceLimit;
            result.native_pins = try a.alloc(WitnessStore.Pin, source.schedule.segments);
            errdefer a.free(result.native_pins);
            result.caller_pins = try a.alloc(?WitnessStore.Pin, source.schedule.segments);
            @memset(result.caller_pins, null);
            errdefer a.free(result.caller_pins);
            const window_count = if (register_mode == 1) source.schedule.segments else 0;
            if (try std.math.mul(usize, window_count, @sizeOf(Registers.Window)) > limits.planning.max_metadata_bytes) return error.V5CpuRosterResourceLimit;
            result.owned_register_windows = try a.alloc(Registers.Window, window_count);
            errdefer a.free(result.owned_register_windows);
            var has_planning = false;
            errdefer if (has_planning) result.planning.deinit();
            var has_replay = false;
            errdefer if (has_replay) result.replay.deinit();
            result.ordinary = try a.alloc(NativeMemory.Proposal, source.schedule.segments);
            errdefer a.free(result.ordinary);
            var ordinary_count: usize = 0;
            errdefer for (result.ordinary[0..ordinary_count]) |*proposal| proposal.deinit();
            result.callers = try a.alloc(?Caller.Proposal, source.schedule.segments);
            @memset(result.callers, null);
            errdefer a.free(result.callers);
            errdefer for (result.callers) |*proposal| if (proposal.*) |*owned| owned.deinit();
            var groups = try Groups.ForBackend(Cpu).init(a, dir, config, limits.groups);
            defer groups.deinit();
            var final_registers: [32]u32 = undefined;
            var fixed: FixedReuse = if (capacity) if (limits.fixed_basis) |caps| try FixedCache.Cache.init(a, caps) else null else {};
            defer if (capacity) {
                if (fixed) |*cache| cache.deinit() catch @panic("capacity collection retained a fixed PCS lease");
            };
            {
                var reader = try source.openPass(.first);
                defer reader.deinit();
                while (try reader.next()) |segment| {
                    const current = try Execution.Current.initForRecipe(a, segment, policy.runner_pins.program_root, recipe);
                    defer current.deinit();
                    const base = &current.segment.base;
                    const index = base.segment_index;
                    if (!has_planning) {
                        var rom = try Rom.buildDeclared(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, .{ .profile = profile }), .{}, base.rw_memory.program_words, null);
                        defer rom.deinit();
                        if (!std.meta.eql(rom.root, policy.runner_pins.program_root)) return error.UntrustedV5CpuProgramImage;
                        result.planning = try Driver.Planning.initFromSource(a, source, policy, rom.leaves, config, limits.planning);
                        has_planning = true;
                        result.replay = try Replay.Replay.initFromSnapshot(a, dir, base.entry_cpu.regs, &base.rw_memory, limits.sorter_chunk_events);
                        result.replay.register_custody_mode = register_mode;
                        has_replay = true;
                        // Admit the initial image before collecting the whole block.
                        // The source writer later repeats these shared checks with
                        // the actual event/final-register census and verifies roots.
                        _ = try @import("block_v5_memory_source_writer_v1.zig").validateInitial(.{
                            .layout = result.replay.layout orelse return error.MissingV5CpuMemoryLayout,
                            .initial_words = result.replay.words,
                            .public_input = source.input,
                            .initial_registers = result.replay.registers,
                            .expected_final_registers = @splat(0),
                            .expected_initial_rw_root = source.planned.first.machine.rw_memory.bytes,
                            .expected_final_rw_root = policy.expected_final_rw_root,
                            .expected_total_events = 0,
                            .register_custody_mode = register_mode,
                            .caps = limits.source_files,
                        });
                    }
                    var physical = try collectPhysical(a, current.owner, config, index, base.global_first_cycle, limits, &fixed);
                    const metadata = nativeMetadata(&physical);
                    if (register_mode == 1) result.owned_register_windows[index] = Registers.Window.fromPublic(index, base.global_first_cycle, &metadata.shape.public_data);
                    var owns_physical = true;
                    defer if (owns_physical) physical.deinit();
                    var native_name: [96]u8 = undefined;
                    result.native_pins[index] = try NativeStage.write(a, dir, try Witness.nativeName(index, &native_name), current.owner, &physical, limits.witness.native);
                    try Witness.admitBytes(&result.witness_file_bytes, result.native_pins[index], limits.witness);
                    const complete = try Execution.fetches(a, current, false);
                    defer a.free(complete);
                    const caller_fetches = try Execution.fetches(a, current, true);
                    defer a.free(caller_fetches);
                    var counters = try Tables.counter.Set.init(a);
                    defer counters.deinit(a);
                    if (current.owner.opcode_columns.lookup_counters) |*native_counters| counters.mergeFrom(native_counters);
                    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = base.clock_frame, .global_first_cycle = base.global_first_cycle, .cycle_count = @intCast(base.cycle_count) };
                    result.ordinary[index] = try collectOrdinary(a, current.owner, frame, &physical, &counters, limits.ordinary);
                    ordinary_count += 1;
                    if (capacity) if (result.readonly) |*selected| {
                        try selected.append(try @import("block_v5_native_capacity_readonly_stage_v1.zig").ForBackend(Cpu).collectWithCounters(a, current.owner, metadata, &result.ordinary[index], limits.ordinary, &selected.selection, selected.selectionPins(), selected.input, selected.native_limits, if (selected.counter_groups) |*groups_owned| groups_owned else null));
                    };
                    var demand = try Demand.nativeDemand(&metadata.shape, current.owner.external_retirements);
                    try Demand.addDemand(&demand, try Demand.sidecarMemoryDemand(ordinaryEvents(&result.ordinary[index])));
                    if (current.owner.external_retirements != 0) {
                        var caller_name: [96]u8 = undefined;
                        var caller_pin: WitnessStore.Pin = undefined;
                        var caller_limits = limits.caller;
                        if (result.readonly) |*selected| caller_limits.readonly = .{ .selection = selected.selectionPins(), .input = selected.input, .limits = selected.caller_limits, .counter_groups = if (selected.counter_groups) |*groups_owned| groups_owned else null };
                        result.callers[index] = Caller.ForBackend(Cpu).collectSegmentWithStaging(a, &current.segment, index, frame, config, caller_limits, &counters, .{ .dir = dir, .name = try Witness.callerName(index, &caller_name), .limits = limits.witness.caller, .pin_out = &caller_pin }) catch |err| {
                            std.debug.print("BLOCK_V5_COLLECT caller_failed=true segment={d}/{d} keccak_calls={d} signer_calls={d} sha_calls={d} error={s}\n", .{ index + 1, source.schedule.segments, current.segment.extension.keccakf_calls.records().len, current.segment.extension.signer_recovery_calls.records().len, current.segment.extension.sha_calls.records().len, @errorName(err) });
                            return err;
                        };
                        try Witness.admitBytes(&result.witness_file_bytes, caller_pin, limits.witness);
                        result.caller_pins[index] = caller_pin;
                        try Demand.addDemand(&demand, result.callers[index].?.caller_max_requests);
                        try Demand.addDemand(&demand, try Demand.sidecarMemoryDemand(result.callers[index].?.byte_demand.event_count));
                    }
                    try groups.addExecution(index, demand, &counters);
                    try result.planning.append(&physical, complete, caller_fetches, demand);
                    owns_physical = false;
                    if (try std.math.add(u64, result.replay.spooler.event_count, base.state_chain_tracker.accesses.items.len) > limits.source_files.max_events)
                        return error.V5SourceFileCapExceeded;
                    if (result.readonly) |*selected| {
                        const census = try result.replay.appendResultSelected(base, &selected.selection);
                        const native = selected.native[index].expected.census;
                        const caller_physical = if (result.callers[index]) |caller| caller.readonly_physical orelse return error.MissingV5CallerReadonlyAuthority else null;
                        const caller_all: u64 = if (caller_physical) |caller| caller.all_rw_events else 0;
                        const caller_readonly: u64 = if (caller_physical) |caller| caller.readonly_events else 0;
                        if (census.all_rw != try std.math.add(u64, native.all_rw, caller_all) or census.readonly != try std.math.add(u64, native.readonly, caller_readonly)) return error.StaleReadonlyInputCensus;
                    } else try result.replay.appendResult(base);
                    final_registers = base.exit_cpu.regs;
                    if (index % 16 == 0 or index + 1 == source.schedule.segments)
                        std.debug.print("BLOCK_V5_COLLECT segment={d}/{d} cycles={d} memory_events={d}\n", .{ index + 1, source.schedule.segments, base.global_first_cycle + base.cycle_count - 1, result.replay.spooler.event_count });
                }
            }
            if (!has_planning or !has_replay or ordinary_count != source.schedule.segments or !source.first_complete)
                return error.IncompleteV5CpuCollection;
            if (register_mode == 1) {
                if (!std.meta.eql(final_registers, source.planned.last.machine.registers)) return error.UntrustedV5CpuRegisterEndpoint;
                result.register_windows = .{ .version = recipe.windowVersion(), .initial_registers = source.planned.first.machine.registers, .final_registers = source.planned.last.machine.registers, .windows = result.owned_register_windows };
                _ = try result.register_windows.?.digest();
            }
            {
                var sorted_reader = try result.replay.finish();
                sorted_reader.deinit();
            }
            result.groups = try groups.finish(source.schedule.segments);
            errdefer result.groups.deinit();
            const sorted = Sorted.fromReplay(&result.replay);
            std.debug.print("BLOCK_V5_COLLECT sorted_events={d} lookup_groups={d} global_roots_started=true\n", .{ result.replay.spooler.event_count, result.groups.records.len });
            result.globals = try Global.ForBackend(Cpu).collect(a, dir, sorted, .{
                .layout = result.replay.layout orelse return error.MissingV5CpuMemoryLayout,
                .initial_words = result.replay.words,
                .public_input = source.input,
                .initial_registers = result.replay.registers,
                .expected_final_registers = final_registers,
                .expected_initial_rw_root = source.planned.first.machine.rw_memory.bytes,
                .expected_final_rw_root = policy.expected_final_rw_root,
                .expected_total_events = result.replay.spooler.event_count,
                .register_custody_mode = register_mode,
                .register_window_plan_digest = if (result.register_windows) |plan| try plan.digest() else @splat(0),
                .caps = limits.source_files,
            }, config, limits.globals);
            errdefer result.globals.deinit();
            if (result.readonly) |*selected| {
                if (selected.counter_groups) |*groups_owned| try groups_owned.finish();
                try selected.bind(result.globals.sources.initial_pins);
                const authority = try selected.authority();
                for (result.callers) |*caller| if (caller.*) |*present| {
                    if (present.readonly_physical == null) return error.MissingV5CallerReadonlyAuthority;
                    present.readonly_authority = authority;
                };
            }
            result.bound = try result.planning.bind(try result.globals.digests());
            errdefer result.bound.deinit();
            try result.globals.bindProviders(&result.bound, &result.groups);
            return result;
        }

        const FixedCache = @import("block_v5_native_capacity_fixed_cache_v1.zig").ForBackend(Cpu);
        const FixedReuse = if (capacity) ?FixedCache.Cache else void;
        fn collectPhysical(a: std.mem.Allocator, owner: *@import("blake3_execution_trace.zig").Owner, config: core.pcs.PcsConfig, index: u32, first_cycle: u64, limits: Limits, reuse: *FixedReuse) !NativeRoots.Proposal {
            if (capacity) if (reuse.*) |*cache| {
                if (try cache.acquire(a, &owner.statement, owner.external_retirements, config, profile, null)) |selected| {
                    var lease = selected;
                    // Root.collectWithBasis destroys its temporary native PCS
                    // owner before returning plain proposal metadata. The token
                    // release checks actual fixed references as well as phase.
                    defer lease.release() catch @panic("capacity collection retained a fixed PCS lease");
                    return NativeRoots.ForBackend(Cpu).collectWithBasis(a, owner, config, profile, index, first_cycle, limits.physical, lease.basis);
                }
                // Only the helper's admitted configured resource miss arrives
                // here; allocator, invalid source/config and expected ID errors
                // propagate. The real cold producer remains mandatory.
            };
            return NativeRoots.ForBackend(Cpu).collect(a, owner, config, profile, index, first_cycle, limits.physical);
        }
        pub fn nativeMetadata(native: *const NativeRoots.Proposal) *const (if (capacity) @import("block_v5_native_capacity_proof_v1.zig").Proposal else NativeRoots.Proposal) {
            return if (capacity) &native.physical else native;
        }
        pub fn ordinaryEvents(proposal: *const NativeMemory.Proposal) u64 {
            return if (capacity) proposal.event_count else proposal.ordinary_events;
        }
        fn ordinaryMode(limits: NativeMemory.Limits) u32 {
            return if (capacity) limits.memory.register_custody_mode else limits.register_custody_mode;
        }
        fn collectOrdinary(a: std.mem.Allocator, owner: *@import("blake3_execution_trace.zig").Owner, frame: @import("../air/block/memory_event.zig").Frame, native: *const NativeRoots.Proposal, counters: *Tables.counter.Set, limits: NativeMemory.Limits) !NativeMemory.Proposal {
            if (capacity) return NativeMemory.ForBackend(Cpu).collect(a, owner, &native.physical, frame, counters, limits);
            return NativeMemory.ForBackend(Cpu).collect(a, owner, frame, native, counters, limits);
        }
    };
}
