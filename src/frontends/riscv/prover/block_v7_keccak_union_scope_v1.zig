//! Independent metadata admission for the finite shared-Keccak union protocol.
//! No proof or successful-source receipt is consumed or produced. The original
//! verifier equations, independent fixed-root checks and global closure must
//! still run. Input pin/statement storage must outlive this admission.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const BatchSource = @import("block_v7_keccak_batch_source_v1.zig");
const BatchProof = @import("block_v7_keccak_batch_proof_v1.zig");
const BatchGeometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const BatchReceiver = @import("block_v7_keccak_execution_receiver_v1.zig");
const OldScope = @import("block_v7_multi_union_scope_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
const Placement = @import("block_v7_multi_union_placement_v1.zig");
const Residency = @import("block_v7_multi_union_residency_v1.zig");
const MemoryLayout = @import("block_v7_memory_joint_layout_v1.zig");
const MemoryProtocol = @import("block_v7_memory_joint_protocol_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
pub const Input = struct {
    epoch: E.Epoch,
    entries: []const E.Entry,
    natives: []const Native.Pin,
    batches: []const BatchSource.Pin,
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
    batch: BatchProof.Limits = .{},
};
pub const Local = OldScope.Local;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    initial: Initial.Owned,
    image: Image.Owned,
    policy: Policy.Policy,
    placement: Placement.Plan,
    sources: []Local,
    retained: Residency.Estimate,
    limits: Limits,
    /// Count of uniquely owned native windows, not the number of batch proofs.
    caller_windows: usize,
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
        if (limits.max_retained_pcs_bytes == 0 or limits.max_trace_trees == 0 or limits.max_trace_trees > 256 or limits.max_windows == 0 or limits.max_windows > 64 or input.natives.len == 0 or input.natives.len > @min(limits.max_windows, limits.receiver.max_segments) or input.batches.len == 0 or input.batches.len > input.natives.len) return error.InvalidKeccakUnionLimits;
        const source_count = try std.math.add(usize, try std.math.add(usize, input.natives.len, input.batches.len), 3);
        if (source_count > limits.receiver.max_entries or input.entries.len != source_count) return error.InvalidKeccakUnionRoster;
        var counts: E.Counts = @splat(0);
        counts[@intFromEnum(E.Family.native)] = @intCast(input.natives.len);
        counts[@intFromEnum(E.Family.caller_fused)] = @intCast(input.batches.len);
        inline for (.{ E.Family.program, E.Family.lookup, E.Family.memory_joint }) |family| counts[@intFromEnum(family)] = 1;
        if (!std.meta.eql(input.epoch.counts, counts)) return error.InvalidKeccakUnionRoster;
        try input.epoch.requireCompleteFamilies();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const temp = self.arena.allocator();
        self.initial = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.receiver.initial);
        errdefer self.initial.deinit();
        self.image = try Image.Owned.init(a, trusted.elf, &self.initial, limits.receiver.initial);
        errdefer self.image.deinit();
        self.policy = .{ .initialized = &self.initial, .program_root = self.image.root.bytes, .terminal = trusted.terminal, .config = trusted.config };
        self.limits = limits;
        self.caller_windows = 0;
        try input.epoch.require(try self.policy.digest(), trusted.config, counts, input.entries, limits.receiver.max_entries);
        self.sources = try temp.alloc(Local, source_count);
        const external = try temp.alloc(u32, input.natives.len);
        @memset(external, 0);
        const windows = try temp.alloc(Policy.Native, input.natives.len);
        var demands: [6]u64 = @splat(0);
        // Every batch retains independently admitted native identities/frames.
        // Sharing arithmetic never permits splitting or double-owning a window.
        if (trusted.profile != Profile.execution_profile) return error.UntrustedKeccakExecutionProfile;
        for (input.batches, 0..) |pin, index| {
            if (pin.index != index) return error.UntrustedKeccakBatchRoster;
            const entry = try pin.require(temp, input.natives, input.epoch, input.entries, limits.batch.owners);
            for (pin.windows) |window| {
                // require() already checks bounds, exact native identity/frame,
                // per-window external count, source config and canonical owners.
                if (external[window.execution_index] != 0) return error.DuplicateKeccakBatchOwner;
                external[window.execution_index] = window.calls;
                self.caller_windows = try std.math.add(usize, self.caller_windows, 1);
            }
            try LP.addDemand(&demands, try BatchReceiver.batchDemand(temp, pin, limits.batch));
            // All geometry allocations belong to the admission arena. Retain
            // their exact five column inventories until Owned.deinit().
            const geometry = try BatchGeometry.Owned.init(temp, pin, limits.batch.owners);
            self.sources[input.natives.len + index] = .{ .entry = entry, .tree_count = 5, .logs = .{ geometry.logs[0], geometry.logs[1], geometry.logs[2], geometry.logs[3], geometry.logs[4] } };
        }
        for (input.natives, windows, 0..) |pin, *window, index| {
            if (pin.index != index or pin.template.execution_profile != trusted.profile or pin.template.external_retirements != external[index] or !std.meta.eql(pin.template.config, trusted.config)) return error.UntrustedV7NativeRoster;
            const entry = try pin.entry(temp);
            try input.epoch.requireEntry(input.entries, entry);
            window.* = .{ .shape = pin.shape, .frame = pin.frame, .external_retirements = external[index] };
            try LP.addDemand(&demands, try LP.nativeDemand(pin.shape, external[index]));
            try LP.addDemand(&demands, try LP.sidecarMemoryDemand(pin.expected_events));
            self.sources[index] = try OldScope.nativeLogs(temp, pin, entry);
        }
        try self.policy.validateWindows(windows);
        const expected_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(input.natives.len), .max_requests = demands };
        if (!std.meta.eql(expected_plan, input.lookup_plan)) return error.UntrustedV7LookupDemand;
        if (!std.meta.eql(input.program_plan.program_root, self.image.root) or input.program_plan.leaves.len != self.image.leaves.len) return error.UntrustedV7ProgramImage;
        for (input.program_plan.leaves, self.image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedV7ProgramImage;
        const program_policy = @import("block_v7_program_provider_v1.zig").Policy{ .plan = input.program_plan, .expected_program_root = self.image.root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries };
        try program_policy.admit();
        const program_entry = try @import("block_v7_program_provider_v1.zig").firstEntry(input.program_plan, input.program_roots);
        const base = input.natives.len + input.batches.len;
        const ProgramAir = @import("block_v5_program_table_proof_v1.zig").Air;
        self.sources[base] = .{ .entry = program_entry, .tree_count = 3, .logs = .{ try repeated(temp, ProgramAir.PREPROCESSED_COLUMN_COUNT, input.program_plan.log_size), &.{}, try repeated(temp, ProgramAir.INTERACTION_COLUMN_COUNT, input.program_plan.log_size), &.{}, &.{} } };
        const lookup_policy = @import("block_v7_lookup_compact_proof_v1.zig").Policy{ .plan = input.lookup_plan, .layout = input.lookup_layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries };
        try lookup_policy.validate();
        self.sources[base + 1] = .{ .entry = try lookup_policy.entry(), .tree_count = 3, .logs = .{ try input.lookup_layout.logs(temp, 0), try input.lookup_layout.logs(temp, 1), try input.lookup_layout.logs(temp, 2), &.{}, &.{} } };
        const ml = limits.receiver.joint_memory;
        if (input.memory_geometry.len == 0 or input.memory_geometry.len > ml.memory.max_shards) return error.V7MemoryResourceLimit;
        const total = input.memory_geometry[0].total_events;
        if (total < @import("block_v7_terminal_protocol_v1.zig").READS or total > ml.memory.max_events or @as(u64, total) * 24 >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
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
                const physical: @import("block_v7_input_storage_v1.zig").Policy = if (storage != null and source.entry.family == .memory_joint)
                    (if (tree < 2) storage.?.memory_inputs else storage.?.memory_interaction)
                else
                    .resident;
                try self.retained.addTreeWithStorage(logs, trusted.config.fri_config.log_blowup_factor, physical);
            }
            try self.retained.addTree(source.logs[0], trusted.config.fri_config.log_blowup_factor);
        }
        try self.retained.require(limits.max_retained_pcs_bytes);
        self.placement = try Placement.Plan.derive(temp, placement_sources, input.natives.len, input.batches.len, limits.max_trace_trees);
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.image.deinit();
        self.initial.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};
fn repeated(a: std.mem.Allocator, count: usize, log: u32) ![]u32 {
    const logs = try a.alloc(u32, count);
    @memset(logs, log);
    return logs;
}

test "Keccak union metadata resource admission rejects before reading or allocating source state" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidKeccakUnionLimits, Owned.init(failing.allocator(), undefined, undefined, .{ .max_retained_pcs_bytes = 0 }));
    try std.testing.expectError(error.InvalidKeccakUnionLimits, Owned.init(failing.allocator(), undefined, undefined, .{ .max_retained_pcs_bytes = 1, .max_windows = 65 }));
}

test "Keccak union metadata requires a complete canonical source roster before allocations" {
    var input: Input = undefined;
    const natives = [_]Native.Pin{undefined};
    const batches = [_]BatchSource.Pin{undefined};
    input.natives = &natives;
    input.batches = &batches;
    input.entries = &.{};
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidKeccakUnionRoster, Owned.init(failing.allocator(), undefined, input, .{ .max_retained_pcs_bytes = 1 }));
    input.batches = &.{};
    try std.testing.expectError(error.InvalidKeccakUnionLimits, Owned.init(failing.allocator(), undefined, input, .{ .max_retained_pcs_bytes = 1 }));
}
