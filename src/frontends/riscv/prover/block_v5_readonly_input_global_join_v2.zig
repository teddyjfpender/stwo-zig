//! Scoped detached group closure after genuine source/provider verification.
//! This never grants complete block authority: original program/ROM/table/byte,
//! registers, sorted mutable RAM and recursive coverage remain mandatory.
const std = @import("std");
const core = @import("stwo_core");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Native = @import("block_v5_native_readonly_source_proof_v2.zig");
const Caller = @import("block_v5_caller_readonly_global_proof_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Q = core.fields.qm31.QM31;
const Sum = struct {
    classification: Q = Q.zero(),
    read: Q = Q.zero(),
    source_events: u64 = 0,
    source_readonly: u64 = 0,
    provider_events: u64 = 0,
    provider_readonly: u64 = 0,
};
pub const Limits = struct { max_metadata_bytes: usize = 64 * 1024 * 1024 };
/// Open mutable transition census for the original full global receiver.
/// There is no portable verified-block flag or complete proof constructor.
pub const OpenMutable = struct {
    epoch: Global.Epoch,
    sealed_digest: [32]u8,
    all_rw_events: u64,
    mutable_events: u64,
    readonly_events: u64,
    mutable_sum: Q,
    source_count: u32,
    provider_count: u32,
};
pub const Owned = struct {
    a: std.mem.Allocator,
    authority: *const Roster.Authority,
    sealed: Seal.Sealed,
    sums: []Sum,
    source_seen: []bool,
    provider_seen: []bool,
    source_count: u32 = 0,
    provider_count: u32 = 0,
    mutable_sum: Q = Q.zero(),
    finished: bool = false,
    pub fn init(a: std.mem.Allocator, authority: *const Roster.Authority, sealed: Seal.Sealed, limits: Limits) !Owned {
        try authority.requireEpoch(sealed);
        const bytes = try std.math.add(usize, @sizeOf(Owned), try std.math.add(usize, try std.math.mul(usize, authority.groups().len, @sizeOf(Sum)), try std.math.add(usize, authority.sources().len, authority.providers().len)));
        if (bytes > limits.max_metadata_bytes) return error.GlobalReadonlyJoinResourceLimit;
        const sums = try a.alloc(Sum, authority.groups().len);
        errdefer a.free(sums);
        @memset(sums, .{});
        const source_seen = try a.alloc(bool, authority.sources().len);
        errdefer a.free(source_seen);
        @memset(source_seen, false);
        const provider_seen = try a.alloc(bool, authority.providers().len);
        errdefer a.free(provider_seen);
        @memset(provider_seen, false);
        return .{ .a = a, .authority = authority, .sealed = sealed, .sums = sums, .source_seen = source_seen, .provider_seen = provider_seen };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.provider_seen);
        self.a.free(self.source_seen);
        self.a.free(self.sums);
        self.* = undefined;
    }
    fn requireOpen(self: *const Owned) !void {
        if (self.finished) return error.GlobalReadonlyJoinClosed;
        try self.authority.requireEpoch(self.sealed);
    }
    fn requireSource(self: *const Owned, ordinal: u32, group_id: u32, kind: @import("block_v5_readonly_input_proposal_v1.zig").Kind, identity: [32]u8, epoch: Global.Epoch, sealed_digest: [32]u8, census: Roster.Census) !Roster.SourceRecord {
        try self.requireOpen();
        if (ordinal >= self.source_seen.len or self.source_seen[ordinal]) return error.DuplicateGlobalReadonlySource;
        const expected = try self.authority.source(ordinal);
        try self.authority.requireSource(ordinal, kind, expected.index, group_id, expected.roots, census, identity);
        if (!std.meta.eql(epoch, self.authority.epoch()) or !std.meta.eql(sealed_digest, self.sealed.digest)) return error.StaleGlobalReadonlyJoin;
        return expected;
    }
    fn addSource(self: *Owned, ordinal: u32, source: Roster.SourceRecord, classification: Q, read: Q, mutable: Q) !void {
        for ([_]Q{ classification, read, mutable }) |value| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&value)) return error.InvalidGlobalReadonlyJoinClaim;
        const prior = self.sums[source.group_id];
        const events = try std.math.add(u64, prior.source_events, source.census.all_rw);
        const readonly = try std.math.add(u64, prior.source_readonly, source.census.readonly);
        const expected = self.authority.groups()[source.group_id].census;
        if (events > expected.all_rw or readonly > expected.readonly) return error.InvalidGlobalReadonlyJoinCensus;
        self.sums[source.group_id].classification = prior.classification.add(classification);
        self.sums[source.group_id].read = prior.read.add(read);
        self.sums[source.group_id].source_events = events;
        self.sums[source.group_id].source_readonly = readonly;
        self.mutable_sum = self.mutable_sum.add(mutable);
        self.source_seen[ordinal] = true;
        self.source_count += 1;
    }
    /// Used only by the original fresh native receiver callback: actual_sum and
    /// actual_events are its verified all-RW access receipt, never a file census.
    pub fn native(self: *Owned, verified: Native.OpenProvider, actual_sum: Q, actual_events: u64) !void {
        const expected = try self.requireSource(verified.ordinal, verified.group_id, .native, verified.source_identity, verified.epoch, verified.sealed_digest, verified.census);
        if (verified.index != expected.index or actual_events != expected.census.all_rw or verified.claim.readonly_count != expected.census.readonly or
            !verified.claim.source_sum.add(actual_sum).isZero()) return error.UnclosedGlobalReadonlyNativeSource;
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&actual_sum) or
            !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&verified.claim.source_sum)) return error.InvalidGlobalReadonlyJoinClaim;
        try self.addSource(verified.ordinal, expected, verified.claim.classification_sum, verified.claim.read_sum, verified.claim.mutable_sum);
    }
    /// Typed zero classifier absence can enter only after the original fresh
    /// native receiver proves the same independently planned zero RW census.
    pub fn nativeAbsent(self: *Owned, ordinal: u32, actual_sum: Q, actual_events: u64) !void {
        const expected = try self.authority.source(ordinal);
        if (expected.census.all_rw != 0 or expected.classifier_roots != null or actual_events != 0 or !actual_sum.isZero()) return error.UntrustedGlobalReadonlyAbsence;
        _ = try self.requireSource(ordinal, expected.group_id, .native, try self.authority.sourceIdentity(ordinal), self.authority.epoch(), self.sealed.digest, expected.census);
        try self.addSource(ordinal, expected, Q.zero(), Q.zero(), Q.zero());
    }
    /// V2 Verified extends the original fresh composite receipt; its provider
    /// fields are populated only after successful original AIR/PCS verification.
    pub fn caller(self: *Owned, verified: *const Caller.Verified) !void {
        const request = verified.readonly_provider;
        const census = Roster.Census{ .all_rw = request.events, .mutable = try std.math.sub(u64, request.events, request.readonly_count), .readonly = request.readonly_count };
        const expected = try self.requireSource(request.ordinal, request.group_id, .caller, request.source_identity, request.epoch, request.sealed_digest, census);
        const partition = verified.partition;
        if (request.index != expected.index or partition.all_rw_events != census.all_rw or partition.mutable_events != census.mutable or
            partition.readonly_events != census.readonly or !std.meta.eql(partition.plan_digest, self.authority.epoch().plan_digest) or
            !std.meta.eql(partition.sealed_digest, self.sealed.digest) or !partition.mutable_sum.add(partition.readonly_sum).eql(verified.memory.transition_sum)) return error.UnclosedGlobalReadonlyCallerSource;
        try self.addSource(request.ordinal, expected, request.classification_sum, request.read_sum, partition.mutable_sum);
    }
    /// Consumes only the result of the genuine provider+dedicated range pair.
    /// Exact range scope is checked again before adding group-specific supply.
    pub fn provider(self: *Owned, verified: Provider.OpenSource) !void {
        try self.requireOpen();
        const proof = verified.provider;
        const pin = proof.pin;
        if (pin.shape.index >= self.provider_seen.len or self.provider_seen[pin.shape.index]) return error.DuplicateGlobalReadonlyProvider;
        try self.authority.requireProvider(pin);
        const range_pin = try self.authority.range(pin.range_index);
        try self.authority.requireRange(range_pin);
        if (!std.meta.eql(proof.epoch, self.authority.epoch()) or !std.meta.eql(proof.sealed_digest, self.sealed.digest) or
            !std.meta.eql(verified.range.sealed_digest, self.sealed.digest) or !std.meta.eql(verified.range.shard, range_pin.shard) or
            !std.meta.eql(verified.range.roots, range_pin.roots) or !std.meta.eql(proof.claim.counts, pin.shape.counts) or
            verified.range.claim.count != pin.shape.counts.range_requests) return error.StaleGlobalReadonlyJoin;
        var range_sum = verified.range.claim.sum;
        for (proof.claim.range_sums) |sum| range_sum = range_sum.add(sum);
        if (!range_sum.isZero()) return error.UnclosedGlobalReadonlyProviderRange;
        for ([_]Q{ proof.claim.classification_sum, proof.claim.read_sum, verified.range.claim.sum } ++ proof.claim.range_sums) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidGlobalReadonlyJoinClaim;
        const prior = self.sums[pin.shape.group_id];
        const events = try std.math.add(u64, prior.provider_events, pin.shape.counts.events);
        const readonly = try std.math.add(u64, prior.provider_readonly, pin.shape.counts.readonly);
        const expected = self.authority.groups()[pin.shape.group_id].census;
        if (events > expected.all_rw or readonly > expected.readonly) return error.InvalidGlobalReadonlyJoinCensus;
        self.sums[pin.shape.group_id].classification = prior.classification.add(proof.claim.classification_sum);
        self.sums[pin.shape.group_id].read = prior.read.add(proof.claim.read_sum);
        self.sums[pin.shape.group_id].provider_events = events;
        self.sums[pin.shape.group_id].provider_readonly = readonly;
        self.provider_seen[pin.shape.index] = true;
        self.provider_count += 1;
    }
    pub fn finish(self: *Owned) !OpenMutable {
        try self.requireOpen();
        if (self.source_count != self.source_seen.len or self.provider_count != self.provider_seen.len) return error.IncompleteGlobalReadonlyJoin;
        var census = Roster.Census{ .all_rw = 0, .mutable = 0, .readonly = 0 };
        for (self.authority.groups(), self.sums) |group, sum| {
            if (sum.source_events != group.census.all_rw or sum.provider_events != group.census.all_rw or
                sum.source_readonly != group.census.readonly or sum.provider_readonly != group.census.readonly or
                !sum.classification.isZero() or !sum.read.isZero()) return error.UnclosedGlobalReadonlyGroup;
            census.all_rw = try std.math.add(u64, census.all_rw, group.census.all_rw);
            census.mutable = try std.math.add(u64, census.mutable, group.census.mutable);
            census.readonly = try std.math.add(u64, census.readonly, group.census.readonly);
        }
        self.finished = true;
        return .{ .epoch = self.authority.epoch(), .sealed_digest = self.sealed.digest, .all_rw_events = census.all_rw, .mutable_events = census.mutable, .readonly_events = census.readonly, .mutable_sum = self.mutable_sum, .source_count = self.source_count, .provider_count = self.provider_count };
    }
};
