//! Independent metadata admission for a BOUNDED multi-window original STARK.
//! No proof or successful-source receipt is consumed or produced. The original
//! verifier equations, independent fixed-root checks and global closure must
//! still run. Input pin/statement storage must outlive this admission.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const E = @import("block_v7_execution_epoch_v1.zig");
        const Initial = @import("block_v7_initial_intervals_v1.zig");
        const Image = @import("block_v7_program_image_v1.zig");
        const Policy = @import("block_v7_execution_policy_v1.zig");
        const Receiver = @import("block_v7_execution_receiver_v1.zig");
        const Native = @import("block_v7_native_source_v1.zig");
        const Caller = @import("block_v7_caller_active_source_v1.zig");
        const Profile = @import("blake3_ethereum_sha_profile.zig");
        const LP = @import("block_v5_native_lookup_plan_v1.zig");
        const Placement = @import("block_v7_multi_union_placement_v1.zig");
        const Residency = @import("block_v7_multi_union_residency_v1.zig");
        const MemoryLayout = if (window) @import("block_v7_window_memory_joint_layout_v1.zig") else @import("block_v7_memory_joint_layout_v1.zig");
        const MemoryProtocol = if (window) @import("block_v7_window_memory_joint_protocol_v1.zig") else @import("block_v7_memory_joint_protocol_v1.zig");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        pub const Input = struct {
            epoch: E.Epoch,
            entries: []const E.Entry,
            natives: []const Native.Pin,
            callers: []const Caller.Pin,
            program_plan: @import("block_v5_program_table_v1.zig").Plan,
            program_roots: [2][32]u8,
            lookup_plan: LP.Plan,
            lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
            lookup_roots: [2][32]u8,
            memory_roots: [2][32]u8,
            memory_geometry: []const Geometry.Claim,
            interval_log: u32,
        };
        pub const Limits = struct {
            /// Mandatory policy: all admitted trace PCS columns/coefficients/Merkle
            /// storage, including retained original fixed trees. Composition/FRI and
            /// raw witness scratch require a separate hard allocator budget.
            max_retained_pcs_bytes: usize,
            max_windows: usize = 8,
            max_trace_trees: usize = 64,
            receiver: Receiver.Limits = .{},
        };
        pub const Local = struct { entry: E.Entry, logs: [5][]const u32, tree_count: u32 };
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            initial: Initial.Owned,
            owned_window: ?*@import("block_v7_real_window_policy_v2.zig").Owned = null,
            image: Image.Owned,
            policy: Policy.Policy,
            placement: Placement.Plan,
            sources: []Local,
            retained: Residency.Estimate,
            limits: Limits,
            pub fn init(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, limits: Limits) !*Owned {
                return initImpl(a, trusted, input, limits, null);
            }
            /// Identical independent statement admission; only the producer retained-PCS
            /// resource calculation differs. Callers must check actual committed storage.
            /// The default verifier init never consumes this physical storage selection.
            pub fn initForProducer(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, limits: Limits, storage: Residency.ProducerStorage) !*Owned {
                try storage.validate();
                return initImpl(a, trusted, input, limits, storage);
            }
            fn initImpl(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, limits: Limits, storage: ?Residency.ProducerStorage) !*Owned {
                if (limits.max_retained_pcs_bytes == 0 or limits.max_trace_trees == 0 or limits.max_trace_trees > 256 or limits.max_windows == 0 or limits.max_windows > 64 or input.natives.len == 0 or input.natives.len > @min(limits.max_windows, limits.receiver.max_segments) or input.callers.len > input.natives.len) return error.InvalidMultiUnionLimits;
                if ((trusted.window != null) != window) return error.InvalidMultiUnionTheorem;
                const source_count = try std.math.add(usize, try std.math.add(usize, input.natives.len, input.callers.len), 3);
                if (source_count > limits.receiver.max_entries or input.entries.len != source_count) return error.InvalidMultiUnionRoster;
                var counts: E.Counts = @splat(0);
                counts[@intFromEnum(E.Family.native)] = @intCast(input.natives.len);
                counts[@intFromEnum(E.Family.caller_fused)] = @intCast(input.callers.len);
                inline for (.{ E.Family.program, E.Family.lookup }) |family| counts[@intFromEnum(family)] = 1;
                counts[@intFromEnum(if (window) E.Family.window_memory_joint else E.Family.memory_joint)] = 1;
                if (!std.meta.eql(input.epoch.counts, counts)) return error.InvalidMultiUnionRoster;
                try input.epoch.requireCompleteFamilies();
                const self = try a.create(Owned);
                errdefer a.destroy(self);
                self.allocator = a;
                self.arena = std.heap.ArenaAllocator.init(a);
                errdefer self.arena.deinit();
                const temp = self.arena.allocator();
                self.owned_window = if (window) try trusted.window.?.cloneAlloc(a) else null;
                errdefer if (self.owned_window) |owned| {
                    owned.deinit();
                    a.destroy(owned);
                };
                var admitted = trusted;
                admitted.window = self.owned_window;
                self.initial = try Receiver.deriveInitialization(a, admitted, limits.receiver.initial);
                errdefer self.initial.deinit();
                self.image = try Image.Owned.init(a, trusted.elf, &self.initial, limits.receiver.initial);
                errdefer self.image.deinit();
                self.policy = .{ .initialized = &self.initial, .program_root = self.image.root.bytes, .terminal = trusted.terminal, .config = trusted.config, .window = self.owned_window };
                self.limits = limits;
                try input.epoch.require(try self.policy.digest(), trusted.config, counts, input.entries, limits.receiver.max_entries);
                self.sources = try temp.alloc(Local, source_count);
                const external = try temp.alloc(u32, input.natives.len);
                @memset(external, 0);
                const windows = try temp.alloc(Policy.Native, input.natives.len);
                var demands: [6]u64 = @splat(0);
                for (input.callers, 0..) |pin, index| {
                    if (trusted.profile != Profile.execution_profile or pin.index != index or pin.execution_index >= input.natives.len or (index != 0 and pin.execution_index <= input.callers[index - 1].execution_index)) return error.UntrustedV7CallerRoster;
                    const native = input.natives[pin.execution_index];
                    if (!std.meta.eql(pin.frame, native.frame) or pin.total_steps != native.frame.cycle_count or !std.meta.eql(pin.execution_identity, (try native.entry(temp)).identity)) return error.UntrustedV7CallerExecution;
                    const entry = try pin.require(temp, input.epoch, input.entries);
                    external[pin.execution_index] = Profile.externalCount(pin.statement);
                    const schedule = try @import("block_v7_caller_active_schedule_v1.zig").derive(temp, pin.statement, pin.total_steps, pin.frame);
                    const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(pin.statement, schedule.memory, 1);
                    try @import("block_v5_precompile_table_demand_v1.zig").add(temp, &demands, pin.statement, pin.total_steps, trusted.config);
                    try LP.addDemand(&demands, try LP.sidecarMemoryDemand(demand.event_count));
                    const layout = try @import("block_v7_caller_active_layout_v1.zig").Layout.derive(pin.statement, pin.total_steps);
                    self.sources[input.natives.len + index] = .{ .entry = entry, .tree_count = 5, .logs = .{ schedule.fixed, schedule.main, try schedule.witnessLogs(), try layout.columnLogs(temp, 2), try schedule.interactionLogs() } };
                }
                for (input.natives, windows, 0..) |pin, *native_window, index| {
                    if (pin.index != index or pin.template.execution_profile != trusted.profile or pin.template.external_retirements != external[index] or !std.meta.eql(pin.template.config, trusted.config)) return error.UntrustedV7NativeRoster;
                    const entry = try pin.entry(temp);
                    try input.epoch.requireEntry(input.entries, entry);
                    native_window.* = .{ .shape = pin.shape, .frame = pin.frame, .external_retirements = external[index] };
                    try LP.addDemand(&demands, try LP.nativeDemand(pin.shape, external[index]));
                    try LP.addDemand(&demands, try LP.sidecarMemoryDemand(pin.expected_events));
                    self.sources[index] = try nativeLogs(temp, pin, entry);
                }
                try self.policy.validateWindows(windows);
                const expected_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(input.natives.len), .max_requests = demands };
                if (!std.meta.eql(expected_plan, input.lookup_plan)) return error.UntrustedV7LookupDemand;
                if (!std.meta.eql(input.program_plan.program_root, self.image.root) or input.program_plan.leaves.len != self.image.leaves.len) return error.UntrustedV7ProgramImage;
                for (input.program_plan.leaves, self.image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedV7ProgramImage;
                const program_policy = @import("block_v7_program_provider_v1.zig").Policy{ .plan = input.program_plan, .expected_program_root = self.image.root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries };
                try program_policy.admit();
                const program_entry = try @import("block_v7_program_provider_v1.zig").firstEntry(input.program_plan, input.program_roots);
                const base = input.natives.len + input.callers.len;
                const ProgramAir = @import("block_v5_program_table_proof_v1.zig").Air;
                self.sources[base] = .{ .entry = program_entry, .tree_count = 3, .logs = .{ try repeated(temp, ProgramAir.PREPROCESSED_COLUMN_COUNT, input.program_plan.log_size), &.{}, try repeated(temp, ProgramAir.INTERACTION_COLUMN_COUNT, input.program_plan.log_size), &.{}, &.{} } };
                const lookup_policy = @import("block_v7_lookup_compact_proof_v1.zig").Policy{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries };
                try lookup_policy.validate();
                self.sources[base + 1] = .{ .entry = try lookup_policy.entry(), .tree_count = 3, .logs = .{ try input.lookup_layout.logs(temp, 0), try input.lookup_layout.logs(temp, 1), try input.lookup_layout.logs(temp, 2), &.{}, &.{} } };
                const ml = if (window) limits.receiver.window_memory else limits.receiver.joint_memory;
                if (input.memory_geometry.len == 0 or input.memory_geometry.len > ml.memory.max_shards) return error.V7MemoryResourceLimit;
                const total = input.memory_geometry[0].total_events;
                if (total < (if (window) @as(u64, 1) else @import("block_v7_terminal_protocol_v1.zig").READS) or total > ml.memory.max_events or @as(u64, total) * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
                const memory_layout = try MemoryLayout.Layout.init(temp, input.memory_geometry, input.interval_log, ml.layout);
                for (memory_layout.parts) |part| {
                    if (part.family == .ram and part.log > ml.memory.max_row_log) return error.V7MemoryResourceLimit;
                    try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(part.log, trusted.config);
                }
                const memory_entry = try MemoryProtocol.entry(self.policy, &memory_layout, input.memory_roots);
                try MemoryProtocol.requireEpoch(self.policy, input.epoch, input.entries, memory_entry);
                self.sources[base + 2] = .{ .entry = memory_entry, .tree_count = 3, .logs = .{ try memory_layout.logs(temp, 0), try memory_layout.logs(temp, 1), try memory_layout.logs(temp, 2), &.{}, &.{} } };
                const placement_sources = try temp.alloc(Placement.Source, source_count);
                self.retained = .{};
                for (self.sources, placement_sources, input.entries) |source, *destination, expected| {
                    if (!std.meta.eql(source.entry, expected)) return error.UntrustedV7SourceEntry;
                    destination.* = .{ .family = source.entry.family, .index = source.entry.index, .root_count = source.entry.root_count };
                    // All trace LDE/coefficients plus original fixed storage retained
                    // by source Stage owners. Summing per-source fixed Merkle bounds
                    // also upper-bounds the one merged fixed tree's Merkle storage.
                    for (source.logs[0..source.tree_count], 0..) |logs, tree| {
                        const physical: @import("block_v7_input_storage_v1.zig").Policy = if (storage != null and source.entry.family == (if (window) E.Family.window_memory_joint else E.Family.memory_joint))
                            (if (tree < 2) storage.?.memory_inputs else storage.?.memory_interaction)
                        else
                            .resident;
                        try self.retained.addTreeWithStorage(logs, trusted.config.fri_config.log_blowup_factor, physical);
                    }
                    try self.retained.addTree(source.logs[0], trusted.config.fri_config.log_blowup_factor);
                }
                try self.retained.require(limits.max_retained_pcs_bytes);
                self.placement = try Placement.Plan.deriveForMemory(temp, placement_sources, input.natives.len, input.callers.len, limits.max_trace_trees, if (window) .window_memory_joint else .memory_joint);
                return self;
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                self.image.deinit();
                self.initial.deinit();
                if (self.owned_window) |owned| {
                    owned.deinit();
                    a.destroy(owned);
                }
                self.arena.deinit();
                a.destroy(self);
            }
        };
        fn repeated(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
            const logs = try a.alloc(u32, count);
            @memset(logs, log);
            return logs;
        }
        pub fn nativeLogs(a: std.mem.Allocator, pin: Native.Pin, entry: E.Entry) !Local {
            const Template = @import("block_v5_native_template_protocol_v3.zig");
            const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
            const Frame = @import("block_v5_native_frame_v1.zig");
            const layout = try pin.layout(a);
            const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, pin.frame, 1);
            const fixed = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            const main = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            const witness = try Fused.witnessLogs(a, slots);
            const interactions = if (Frame.required(pin.shape)) try repeated(a, Frame.INTERACTION_COLUMNS, Frame.LOG_SIZE) else try Fused.interactionLogs(a, layout.slots, slots);
            if (entry.root_count != (if (slots.len == 0) @as(u32, 2) else 3)) return error.InvalidMultiUnionSourceTrees;
            return .{ .entry = entry, .tree_count = entry.root_count + 1, .logs = if (slots.len == 0) .{ fixed, main, interactions, &.{}, &.{} } else .{ fixed, main, witness, interactions, &.{} } };
        }
    };
}
