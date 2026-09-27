//! One owned runner segment supplies every warm native/caller projection.
//! The producer release callback closes this lifetime before the next load.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("block_v4_cpu_runner_source.zig");
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;
const native = @import("blake3_execution_trace.zig");
const public = @import("blake3_segment_public.zig");
const admission = @import("block_v5_native_public_admission_v1.zig");
const producer = @import("block_v5_block_producer_v1.zig");
const program = @import("../air/program/commitment.zig");
const fetch_mod = @import("block_v5_program_census_v1.zig");
const profile = @import("../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_ethereum_sha_v1;
const Recipe = @import("block_v5_execution_recipe_v1.zig").Recipe;

pub fn externalCount(segment: *const Segment) !u32 {
    return std.math.cast(u32, try std.math.add(usize, segment.extension.keccakf_calls.records().len, try std.math.add(usize, segment.extension.signer_recovery_calls.records().len, segment.extension.sha_calls.records().len))) orelse error.InvalidV5CpuExternalCount;
}

pub const Current = struct {
    a: std.mem.Allocator,
    segment: Segment,
    io: public.Owned,
    owner: *native.Owner,
    recipe: Recipe,

    pub fn init(a: std.mem.Allocator, owned_segment: Segment, program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest) !*Current {
        return initForRecipe(a, owned_segment, program_root, .custody_v2);
    }
    pub fn initForRecipe(a: std.mem.Allocator, owned_segment: Segment, program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest, recipe: Recipe) !*Current {
        var segment = owned_segment;
        errdefer segment.deinit();
        if (segment.base.state_chain_tracker.x0_local_custody_version != recipe.nativeVersion()) return error.MixedV5ExecutionRecipe;
        var io = try public.Owned.init(a, &segment.base);
        errdefer io.deinit();
        io.data.program_root = program_root;
        const owner = if (recipe == .local_zero_v1)
            try native.Owner.initLocalZeroWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, try externalCount(&segment))
        else
            try native.Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, try externalCount(&segment));
        errdefer owner.deinit();
        try recipe.requireNative(&owner.statement);
        try owner.sealNativeOnly();
        const current = try a.create(Current);
        current.* = .{ .a = a, .segment = segment, .io = io, .owner = owner, .recipe = recipe };
        return current;
    }
    pub fn deinit(self: *Current) void {
        const a = self.a;
        self.owner.deinit();
        self.io.deinit();
        self.segment.deinit();
        a.destroy(self);
    }
};

pub const Source = struct {
    a: std.mem.Allocator,
    reader: runner.Reader,
    admissions: []const admission.Admission,
    next: u32 = 0,
    outstanding: bool = false,

    pub fn init(a: std.mem.Allocator, runner_source: *runner.Source, admissions: []const admission.Admission) !Source {
        try runner_source.execution_recipe.requireCompiled();
        if (admissions.len != runner_source.schedule.segments) return error.InvalidV5CpuExecutionRoster;
        return .{ .a = a, .reader = try runner_source.openPass(.second), .admissions = admissions };
    }
    pub fn deinit(self: *Source) void {
        std.debug.assert(!self.outstanding);
        self.reader.deinit();
        self.* = undefined;
    }
    pub fn source(self: *Source) producer.LightweightExecutionSource {
        return .{ .context = self, .load = load };
    }
    pub fn requireFinished(self: *Source) !void {
        if (self.outstanding or self.next != self.admissions.len) return error.IncompleteV5CpuExecutionReplay;
        if (try self.reader.next()) |owned_segment| {
            var extra = owned_segment;
            extra.deinit();
            return error.IncompleteV5CpuExecutionReplay;
        }
        if (!self.reader.source.second_complete) return error.IncompleteV5CpuExecutionReplay;
    }
    fn load(raw: *anyopaque, index: u32) !producer.LightweightReplay {
        const self: *Source = @ptrCast(@alignCast(raw));
        if (self.outstanding or index != self.next or index >= self.admissions.len) return error.InvalidV5CpuExecutionOrder;
        const segment = try self.reader.next() orelse return error.IncompleteV5CpuExecutionReplay;
        const live_segment = try Current.initForRecipe(self.a, segment, self.reader.source.planned.first.program, self.reader.source.execution_recipe);
        self.outstanding = true;
        self.next += 1;
        // A stable wrapper carries both the source latch and the live segment.
        const lease = self.a.create(Lease) catch |err| {
            self.outstanding = false;
            live_segment.deinit();
            return err;
        };
        lease.* = .{ .source = self, .current = live_segment };
        return .{ .owner = live_segment.owner, .admission = self.admissions[index], .profile = profile, .context = lease, .release = release };
    }
    pub fn current(replay: *const producer.LightweightReplay) !*Current {
        const lease: *Lease = @ptrCast(@alignCast(replay.context));
        if (!lease.source.outstanding or lease.current.owner != replay.owner) return error.UntrustedV5CpuLiveSegment;
        return lease.current;
    }
    const Lease = struct { source: *Source, current: *Current };
    fn release(raw: *anyopaque, replay: *producer.LightweightReplay) void {
        const lease: *Lease = @ptrCast(@alignCast(raw));
        std.debug.assert(replay.owner == lease.current.owner);
        const source_owner = lease.source;
        lease.current.deinit();
        source_owner.outstanding = false;
        source_owner.a.destroy(lease);
    }
};

/// Canonical decode validates fetched words against the complete ELF image.
/// Only positive counters survive in per-segment metadata.
pub fn fetches(a: std.mem.Allocator, current: *const Current, comptime caller_only: bool) ![]fetch_mod.Fetch {
    const segment = &current.segment;
    const decoder = program.DeclaredDecodeAuthority{ .profile = profile };
    const callers = .{ segment.extension.keccakf_execution_rows.rows(), segment.extension.signer_recovery_execution_rows.rows(), segment.extension.sha_calls.records() };
    const rows = if (caller_only)
        try program.declaredRows(a, decoder, callers, segment.base.rw_memory.program_words, null)
    else
        try program.declaredRows(a, decoder, .{segment.base.execution_trace.rows.items} ++ callers, segment.base.rw_memory.program_words, @import("commitment_program_witness.zig").completionFetch(current.io.data.completion));
    defer a.free(rows);
    var count: usize = 0;
    for (rows) |row| if (row.multiplicity != 0) {
        count += 1;
    };
    const result = try a.alloc(fetch_mod.Fetch, count);
    var index: usize = 0;
    for (rows) |row| if (row.multiplicity != 0) {
        result[index] = .{ .address = row.addr, .multiplicity = row.multiplicity };
        index += 1;
    };
    return result;
}

// Keep CPU selection local to the product boundary, not in reusable kernels.
pub const Producer = producer.ForLightweightBackend(Cpu);
