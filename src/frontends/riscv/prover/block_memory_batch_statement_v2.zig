//! Trusted public statement and exact prechallenge roster admission for the
//! block-v2 batch receiver. No proof-carried root is an authority here.
const std = @import("std");
const memory = @import("../air/block/memory_component.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const execution_shard = @import("block_execution_range_shard_v2.zig");
const span = @import("../recursion/span_statement_blake3.zig");

pub const Digest = [32]u8;
pub const Roots = [2]Digest;

pub const MemoryPin = struct { claim: memory.Claim, roots: Roots };
pub const CompletePins = struct {
    /// Public job reconstructed from independently pinned ELF, input, output,
    /// execution geometry, and the initial-image root by the receiver.
    expected_job: span.JobContext,
    /// Invariant v3 span anchor, independently supplied by the public job.
    /// Native ordinary RW roots may differ at public-I/O boundaries.
    initial_rw_anchor: Digest,
    program_root: Digest,
    /// Independently admitted outer recursive key and exact forest roster.
    /// Neither may come from the recursive proof artifact being verified.
    outer_recursive_key_id: Digest,
    forest_roster_digest: Digest,
};
pub const PinnedStatement = struct {
    seal: seal_mod.SourceSeal,
    expected_events: u64,
    memory_instances: []const MemoryPin,
    range_table_roots: []const Roots,
    execution_roots: []const Roots,
    /// One witness root per native execution instance, encoded as
    /// `{witness_root, zero}` under family 7. Memory-only qualification may
    /// omit these; any complete-block receiver must require exact coverage.
    execution_sidecar_roots: []const Roots = &.{},
    /// Exact active access counts and separate 8x8 table roots for execution
    /// sidecars. Their B2ER plan digest is sealed as a family-nine pseudo-root.
    execution_active_counts: []const u64 = &.{},
    execution_range_table_roots: []const Roots = &.{},
    /// Sparse family-ten roots for exactly the execution instances with a
    /// nonzero SHA/Keccak caller census. Each root is `{witness_root, zero}`;
    /// its `index` is the actual execution instance index, not a compact slot.
    execution_extension_roots: []const seal_mod.FirstRoundEntry = &.{},
    /// Exact per-execution extension access counts; absent for a zero-call
    /// block, which retains the existing v3 SourceSeal transcript.
    execution_extension_active_counts: []const u64 = &.{},
    execution_extension_range_table_roots: []const Roots = &.{},
    /// Ordered initial-RW, initial-program, and hash provider roots. These
    /// must come from the independently authenticated public source roster.
    provider_roots: []const seal_mod.FirstRoundEntry,
    complete_pins: ?CompletePins = null,

    pub fn validate(self: PinnedStatement, a: std.mem.Allocator) !shard_mod.Plan {
        if (!self.seal.bound_rosters) return error.UnboundBlockProofRoster;
        if (self.memory_instances.len != self.seal.memory_instance_count or
            self.execution_roots.len != self.seal.execution_instance_count)
            return error.InvalidBlockProofRoster;
        const has_execution_extension = self.execution_sidecar_roots.len != 0 or
            self.execution_active_counts.len != 0 or self.execution_range_table_roots.len != 0;
        if (has_execution_extension) {
            if (self.execution_sidecar_roots.len != self.seal.execution_instance_count or
                self.execution_active_counts.len != self.seal.execution_instance_count)
                return error.InvalidExecutionSidecarRoster;
            var execution_plan = try execution_shard.plan(a, self.execution_active_counts);
            defer execution_plan.deinit(a);
            if (self.execution_range_table_roots.len != execution_plan.shards.len)
                return error.InvalidExecutionRangeTableRoster;
        }
        const extension_plan = try self.extensionPlan(a);
        if (extension_plan) |value| {
            var plan_value = value;
            defer plan_value.deinit(a);
            if (!self.seal.extension_rosters_bound or
                !std.meta.eql(self.seal.extension_range_shard_digest, plan_value.digest))
                return error.UnsealedExecutionExtensionRangeRoster;
        } else if (self.seal.extension_rosters_bound) return error.EmptyExecutionExtensionRoster;
        for (self.execution_sidecar_roots) |roots| {
            if (!std.meta.eql(roots[1], @as(Digest, @splat(0))))
                return error.InvalidExecutionSidecarRoster;
        }
        const claims = try a.alloc(memory.Claim, self.memory_instances.len);
        defer a.free(claims);
        for (self.memory_instances, claims) |entry, *claim| claim.* = entry.claim;
        var plan = try shard_mod.plan(a, claims, self.expected_events);
        errdefer plan.deinit(a);
        if (self.range_table_roots.len != plan.shards.len or
            !std.meta.eql(self.seal.range_shard_digest, plan.digest))
            return error.UnsealedRangeShardRoster;
        const first_digest = try self.firstRoundDigest(a);
        if (!std.meta.eql(first_digest, self.seal.first_round_roster_digest))
            return error.UnsealedFirstRoundRoster;
        return plan;
    }

    /// Admission gate for the later complete-block verifier. This prevents a
    /// memory-only seal from being reused as if execution witness roots were
    /// present before its relation challenge draw.
    pub fn requireExecutionSidecars(self: PinnedStatement, a: std.mem.Allocator) !void {
        if (self.execution_sidecar_roots.len != self.seal.execution_instance_count or
            self.execution_active_counts.len != self.seal.execution_instance_count)
            return error.MissingExecutionSidecarRoots;
        for (self.execution_sidecar_roots) |roots| {
            if (!std.meta.eql(roots[1], @as(Digest, @splat(0))))
                return error.InvalidExecutionSidecarRoster;
        }
        var execution_plan = try execution_shard.plan(a, self.execution_active_counts);
        defer execution_plan.deinit(a);
        if (self.execution_range_table_roots.len != execution_plan.shards.len)
            return error.InvalidExecutionRangeTableRoster;
    }

    /// Validate the sparse extension witness roster and its independent
    /// field-safe byte-table plan. No host-selected extension event can be
    /// omitted from an otherwise bound execution instance census.
    pub fn requireExecutionExtensions(self: PinnedStatement, a: std.mem.Allocator) !execution_shard.Plan {
        var plan = (try self.extensionPlan(a)) orelse return error.MissingExecutionExtensionRoster;
        errdefer plan.deinit(a);
        if (!self.seal.extension_rosters_bound or
            !std.meta.eql(self.seal.extension_range_shard_digest, plan.digest))
            return error.UnsealedExecutionExtensionRangeRoster;
        return plan;
    }

    fn extensionPlan(self: PinnedStatement, a: std.mem.Allocator) !?execution_shard.Plan {
        const present = self.execution_extension_active_counts.len != 0 or
            self.execution_extension_roots.len != 0 or
            self.execution_extension_range_table_roots.len != 0;
        if (!present) return null;
        if (self.execution_extension_active_counts.len != self.seal.execution_instance_count)
            return error.InvalidExecutionExtensionRoster;
        var next_root: usize = 0;
        var has_active_extension = false;
        for (self.execution_extension_active_counts, 0..) |count, index| {
            if (count == 0) continue;
            has_active_extension = true;
            if (next_root >= self.execution_extension_roots.len)
                return error.InvalidExecutionExtensionRoster;
            const entry = self.execution_extension_roots[next_root];
            if (entry.family != .execution_extension_witness or entry.index != index or
                !std.meta.eql(entry.roots[1], @as(Digest, @splat(0))))
                return error.InvalidExecutionExtensionRoster;
            next_root += 1;
        }
        if (!has_active_extension) return error.EmptyExecutionExtensionRoster;
        if (next_root != self.execution_extension_roots.len)
            return error.InvalidExecutionExtensionRoster;
        var plan = try execution_shard.plan(a, self.execution_extension_active_counts);
        errdefer plan.deinit(a);
        if (self.execution_extension_range_table_roots.len != plan.shards.len)
            return error.InvalidExecutionExtensionRangeTableRoster;
        return plan;
    }

    pub fn requireCompletePins(self: PinnedStatement, public_initial_rw_root: Digest) !CompletePins {
        const pins = self.complete_pins orelse return error.MissingCompleteBlockPublicPins;
        try pins.expected_job.validate();
        if (!std.meta.eql(pins.initial_rw_anchor, public_initial_rw_root) or
            !std.meta.eql(pins.expected_job.complete.initial_state.rw_memory.bytes, pins.initial_rw_anchor) or
            !std.meta.eql(pins.expected_job.complete.final_state.rw_memory.bytes, pins.initial_rw_anchor))
            return error.InitialRwAnchorMismatch;
        if (!std.meta.eql(pins.expected_job.complete.program.bytes, pins.program_root) or
            pins.expected_job.segment_count != self.seal.execution_instance_count)
            return error.InvalidCompleteBlockPublicJob;
        return pins;
    }

    pub fn firstRoundDigest(self: PinnedStatement, a: std.mem.Allocator) !Digest {
        var entries = std.ArrayList(seal_mod.FirstRoundEntry).empty;
        defer entries.deinit(a);
        for (self.memory_instances, 0..) |item, i|
            try entries.append(a, .{ .family = .memory, .index = @intCast(i), .roots = item.roots });
        for (self.range_table_roots, 0..) |roots, i|
            try entries.append(a, .{ .family = .range_table, .index = @intCast(i), .roots = roots });
        for (self.execution_roots, 0..) |roots, i|
            try entries.append(a, .{ .family = .execution, .index = @intCast(i), .roots = roots });
        for (self.execution_sidecar_roots, 0..) |roots, i|
            try entries.append(a, .{ .family = .execution_sidecar_witness, .index = @intCast(i), .roots = roots });
        if (self.execution_active_counts.len != 0) {
            var execution_plan = try execution_shard.plan(a, self.execution_active_counts);
            defer execution_plan.deinit(a);
            for (self.execution_range_table_roots, 0..) |roots, i|
                try entries.append(a, .{ .family = .execution_range_table, .index = @intCast(i), .roots = roots });
            try entries.append(a, execution_shard.planEntry(&execution_plan));
        }
        if (try self.extensionPlan(a)) |value| {
            var extension_plan = value;
            defer extension_plan.deinit(a);
            try entries.appendSlice(a, self.execution_extension_roots);
            for (self.execution_extension_range_table_roots, 0..) |roots, i|
                try entries.append(a, .{ .family = .execution_extension_range_table, .index = @intCast(i), .roots = roots });
            try entries.append(a, .{ .family = .execution_extension_range_plan, .index = 0, .roots = .{ extension_plan.digest, @splat(0) } });
        }
        var last_family: ?seal_mod.FirstRoundFamily = null;
        var next_index: u32 = 0;
        for (self.provider_roots) |item| {
            if (item.family != .initial_rw and item.family != .initial_program and item.family != .hash)
                return error.InvalidProviderFirstRoundRoster;
            if (last_family) |prior| {
                if (@intFromEnum(item.family) < @intFromEnum(prior)) return error.InvalidProviderFirstRoundRoster;
                if (item.family != prior) next_index = 0;
            }
            if (item.index != next_index) return error.InvalidProviderFirstRoundRoster;
            next_index = try std.math.add(u32, next_index, 1);
            last_family = item.family;
            try entries.append(a, item);
        }
        return seal_mod.digestFirstRoundRoster(entries.items);
    }
};
