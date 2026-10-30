//! Bounded prechallenge CPU handoff for v7. Original raw columns and committed
//! PCS trees are written once, then one segment is restored after the whole
//! epoch is known. These files are untrusted proving material, not receipts.
//! Storage codecs predate v7 but carry no v5 seal/admission; no old authority is
//! manufactured. Final acceptance always uses the v7 fresh-original receiver.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Owner = @import("blake3_execution_trace.zig").Owner;
const Root = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Stage = @import("block_v5_native_memory_stage_v1.zig");
const Columns = @import("block_v5_native_columns_stage_v1.zig");
const PCS = @import("block_v6_native_commitment_store_v1.zig");
const Access = @import("block_v6_access_commitment_store_v1.zig");
const Native = @import("block_v7_native_proof_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const E = @import("block_v7_execution_epoch_v1.zig");
pub const Names = struct {
    raw: []const u8,
    native: []const u8,
    access: []const u8,
    fn validate(self: Names) !void {
        const codec = @import("block_v6_cpu_checkpoint_codec_v1.zig");
        try codec.requireName(self.raw);
        try codec.requireName(self.native);
        try codec.requireName(self.access);
        if (std.mem.eql(u8, self.raw, self.native) or std.mem.eql(u8, self.raw, self.access) or std.mem.eql(u8, self.native, self.access)) return error.DuplicateV7CheckpointName;
    }
};
pub const Limits = struct {
    /// Explicit expected native protocol; never inferred from stored columns.
    native_layout_mode: @import("block_v7_native_source_v1.zig").LayoutMode = .canonical_v1,
    columns: Columns.Limits,
    pcs: PCS.Limits = .{},
    source: Stage.Limits,
    max_total_bytes: u64,
};
pub const Stats = struct {
    written_bytes: u64,
    raw_bytes: u64,
    native_pcs_bytes: u64,
    access_bytes: u64,
    /// Codec-owned persistent allocations on load. Native owner reconstruction
    /// and subsequent proof scratch are separately bounded, not included here.
    retained_loaded_bytes: usize,
};
pub const Record = struct {
    layout_mode: @import("block_v7_native_source_v1.zig").LayoutMode = .canonical_v1,
    native: Root.Proposal,
    access: Stage.Proposal,
    columns: Columns.Pin,
    pcs: PCS.Pin,
    auxiliary: ?Access.Pin,
    stats: Stats,
    pub fn deinit(self: *Record) void {
        self.access.deinit();
        self.native.deinit();
        self.* = undefined;
    }
    pub fn pin(self: *const Record) Native.Pin {
        return .{ .index = self.native.index, .shape = &self.native.shape, .frame = self.access.frame, .template = self.native.template, .roots = self.native.roots, .access_root = if (self.access.slots.len == 0) @splat(0) else self.access.witness_root, .expected_events = self.access.ordinary_events, .layout_mode = self.layout_mode };
    }
    pub fn entry(self: *const Record, a: std.mem.Allocator) !E.Entry {
        return self.pin().entry(a);
    }
};
pub const EventSink = struct {
    context: *anyopaque,
    put: *const fn (*anyopaque, @import("../air/block/memory_transition.zig").Transition) anyerror!void,
};
/// Sink events are provisional until collect succeeds; on failure the caller
/// must discard its partial event spool. Global counters change only on success.
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, owner: *Owner, config: core.pcs.PcsConfig, profile: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, first_cycle: u64, global: *Counters.Set, sink: EventSink, limits: Limits) !Record {
    try names.validate();
    if (limits.source.register_custody_mode != 1 or limits.max_total_bytes == 0) return error.InvalidV7CheckpointPolicy;
    var local = try Counters.Set.init(a);
    defer local.deinit(a);
    const counters = if (owner.opcode_columns.lookup_counters) |*value| value else return error.InvalidV7CheckpointPhase;
    local.mergeFrom(counters);
    var native = try Root.ForBackend(Cpu).collectRetained(a, owner, config, profile, index, first_cycle, .{ .max_public_words = 0, .max_metadata_bytes = @sizeOf(Root.Proposal) });
    defer native.first.deinit(a);
    errdefer native.proposal.deinit();
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = first_cycle, .cycle_count = owner.statement.public_data.clock };
    var access = try Stage.ForBackend(Cpu).collectRetainedTimed(a, owner, frame, &native.proposal, &local, limits.source, null);
    defer access.deinitPhysical(a);
    errdefer access.proposal.deinit();
    const source_pin = Native.Pin{ .index = index, .shape = &native.proposal.shape, .frame = frame, .template = native.first.template, .roots = native.first.roots, .access_root = if (access.proposal.slots.len == 0) @splat(0) else access.proposal.witness_root, .expected_events = access.proposal.ordinary_events, .layout_mode = limits.native_layout_mode };
    _ = try source_pin.entry(a);
    var raw_limits = limits.columns;
    raw_limits.columns.max_file_bytes = @min(raw_limits.columns.max_file_bytes, limits.max_total_bytes);
    const raw = try Columns.write(a, dir, names.raw, owner, &native.proposal, raw_limits);
    errdefer dir.deleteFile(names.raw) catch {};
    var pcs_limits = limits.pcs;
    pcs_limits.max_file_bytes = @min(pcs_limits.max_file_bytes, limits.max_total_bytes - raw.bytes);
    const pcs = try PCS.write(a, dir, names.native, &native.proposal, &native.first, pcs_limits);
    errdefer dir.deleteFile(names.native) catch {};
    var access_limits = limits.pcs;
    access_limits.max_file_bytes = @min(access_limits.max_file_bytes, limits.max_total_bytes - raw.bytes - pcs.bytes);
    const auxiliary: ?Access.Pin = if (access.proposal.slots.len != 0) try Access.write(a, dir, names.access, &native.proposal, &access, .{ .source = limits.source, .storage = access_limits }) else null;
    errdefer if (auxiliary != null) dir.deleteFile(names.access) catch {};
    const access_bytes = if (auxiliary) |pin| pin.bytes else 0;
    for (access.source.inputs) |input| for (0..input.trace.domainSize()) |row| {
        const event = try input.trace.row(row);
        if (event.active) try sink.put(sink.context, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(event.tuple));
    };
    const retained_loaded_bytes = try std.math.add(usize, pcs.loaded_bytes, if (auxiliary) |pin| pin.loaded_bytes else 0);
    global.mergeFrom(&local);
    return .{ .layout_mode = limits.native_layout_mode, .native = native.proposal, .access = access.proposal, .columns = raw, .pcs = pcs, .auxiliary = auxiliary, .stats = .{ .written_bytes = raw.bytes + pcs.bytes + access_bytes, .raw_bytes = raw.bytes, .native_pcs_bytes = pcs.bytes, .access_bytes = access_bytes, .retained_loaded_bytes = retained_loaded_bytes } };
}
pub const Loaded = struct {
    native: Columns.ForBackend(Cpu).Prepared,
    access: ?Access.Loaded,
    first: Native.For(Cpu).First,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.first.deinit(a);
        if (self.access) |*access| access.deinit(a);
        self.native.deinit(a);
        self.* = undefined;
    }
};
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits) !Loaded {
    try names.validate();
    if (record.layout_mode != limits.native_layout_mode) return error.InvalidV7CheckpointLayoutMode;
    if (limits.source.register_custody_mode != 1 or record.stats.written_bytes > limits.max_total_bytes or
        record.stats.written_bytes != try std.math.add(u64, record.columns.bytes, try std.math.add(u64, record.pcs.bytes, if (record.auxiliary) |pin| pin.bytes else 0))) return error.InvalidV7CheckpointPolicy;
    _ = try record.entry(a);
    var native = try Columns.ForBackend(Cpu).loadWithCommitment(a, dir, names.raw, &record.native, record.columns, limits.columns, record.native.template.execution_profile, names.native, record.pcs, limits.pcs);
    errdefer native.deinit(a);
    if ((record.access.slots.len == 0) != (record.auxiliary == null)) return error.InvalidV7CheckpointAccess;
    var access: ?Access.Loaded = if (record.auxiliary) |pin| try Access.load(a, dir, names.access, &record.native, &record.access, native.owner, pin, .{ .source = limits.source, .storage = limits.pcs }) else null;
    errdefer if (access) |*value| value.deinit(a);
    const first = if (access) |*value|
        try Stage.ForBackend(Cpu).borrowRetained(a, &native.first.scheme, &value.scheme, value.snapshots, &record.access)
    else
        try @import("block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu).borrowProjectionFirstRound(a, &native.first.scheme, @splat(0));
    return .{ .native = native, .access = access, .first = first };
}

/// The streaming producer's one-segment lifetime: release restored raw columns,
/// access witness and every PCS lease before returning the original proof. The
/// caller can then move to the next record without retaining wide source state.
/// This function still grants no receipt; the final receiver verifies the proof.
pub fn proveOne(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: E.Epoch, roster: []const E.Entry) !Native.Proof {
    return proveOneWithOptions(a, dir, names, record, limits, epoch, roster, .{});
}
pub fn proveOneWithOptions(a: std.mem.Allocator, dir: std.fs.Dir, names: Names, record: *const Record, limits: Limits, epoch: E.Epoch, roster: []const E.Entry, options: Native.ProveOptions) !Native.Proof {
    const Scope = @import("stwo_prover_engine").stage_profile.StageScope;
    var segment_scope = try Scope.begin(options.recorder, "native_segment", "Native segment including checkpoint restore");
    defer segment_scope.end();
    try epoch.requireEntry(roster, try record.entry(a));
    var restore_scope = try Scope.begin(options.recorder, "native_checkpoint_restore", "Restore original native and access commitments");
    defer restore_scope.end();
    var loaded = try load(a, dir, names, record, limits);
    defer loaded.deinit(a);
    restore_scope.end();
    var pin = record.pin();
    pin.shape = &loaded.native.owner.statement;
    return Native.For(Cpu).proveWithOptions(a, &loaded.first, loaded.native.owner, if (loaded.access) |*access| access.source.inputs else &.{}, pin, epoch, roster, options);
}
