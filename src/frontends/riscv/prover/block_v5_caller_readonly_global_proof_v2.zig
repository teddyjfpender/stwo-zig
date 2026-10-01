//! Genuine version2 B5IC source fusion. Compact classifier claims must join the
//! separately verified GLOBAL providers/range proof; this is an OPEN source.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_caller_readonly_proof_v1.zig");
const Readonly = @import("block_v5_caller_readonly_protocol_v1.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Caller = @import("block_v5_precompile_protocol_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Q = core.fields.qm31.QM31;
pub const TAG: u32 = 0x42354943; // B5IC; strict VERSION2 grammar
pub const VERSION: u32 = 2;
pub const Slot = struct { claim: Readonly.Claim };
pub const Proof = Original.ProofFor(Slot);
pub const ClaimFrames = Original.ClaimFramesFor(Slot);
/// Fresh compact requests. Provider/source/global joins remain unclosed.
pub const SourceClaims = struct {
    classification_sum: Q,
    read_sum: Q,
    events: u64,
    readonly_count: u64,
    ordinal: u32,
    group_id: u32,
    index: u32,
    source_identity: [32]u8,
    epoch: Global.Epoch,
    sealed_digest: [32]u8,
};
pub const Verified = struct {
    program: @FieldType(Original.Verified, "program"),
    state: @FieldType(Original.Verified, "state"),
    tables: @FieldType(Original.Verified, "tables"),
    memory: @FieldType(Original.Verified, "memory"),
    partition: Original.Partition,
    readonly_provider: SourceClaims,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.memory.deinit(a);
        self.* = undefined;
    }
};
pub const VerifiedCapture = Original.VerifiedCaptureFor(Policy);
pub const Components = Original.Components;
pub const witnessLogs = Original.witnessLogs;
pub const interactionLogs = Original.interactionLogs;
pub const Authority = struct {
    selection: @import("block_v5_readonly_input_selection_v1.zig").Pins,
    plan: Plan.Pins,
    input: []const u8,
    limits: Readonly.Limits,
    /// Genuine independently admitted global owner. It and original policy
    /// slices remain immutable and outlive this synchronous policy/capture use.
    roster: *const Roster.Authority,
    sealed: Seal.Sealed,
    ordinal: u32,
    group_id: u32,
    census: Roster.Census,
    source_identity: [32]u8,
    pub fn init(original_policy: Readonly.Authority, roster: *const Roster.Authority, sealed: Seal.Sealed, ordinal: u32) !Authority {
        try roster.requireEpoch(sealed);
        try roster.requireOriginalPolicy(original_policy);
        const source = try roster.source(ordinal);
        if (source.kind != .caller) return error.UntrustedGlobalCallerSourceKind;
        return .{ .selection = original_policy.selection, .plan = original_policy.plan, .input = original_policy.input, .limits = original_policy.limits, .roster = roster, .sealed = sealed, .ordinal = ordinal, .group_id = source.group_id, .census = source.census, .source_identity = try roster.sourceIdentity(ordinal) };
    }
    pub fn original(self: Authority) Readonly.Authority {
        return .{ .selection = self.selection, .plan = self.plan, .input = self.input, .limits = self.limits };
    }
    pub fn admit(self: Authority, a: std.mem.Allocator) !Roster.BorrowedPlan {
        _ = a;
        try self.roster.requireOriginalPolicy(self.original());
        const admitted = try self.roster.borrowedPlan(self.sealed);
        if (!std.meta.eql(self.plan.expected_digest, admitted.digest)) return error.UntrustedGlobalCallerPlan;
        if (admitted.intervals.len > self.limits.max_intervals) return error.CallerReadonlyResourceLimit;
        const source = try self.roster.source(self.ordinal);
        try self.roster.requireSource(self.ordinal, .caller, source.index, self.group_id, source.roots, self.census, self.source_identity);
        return admitted;
    }
};
pub fn originalAuthority(authority: Authority) Readonly.Authority {
    return authority.original();
}
pub fn firstChannel(binding: Caller.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule, authority: Authority) core.proof_suites.Blake3.Channel {
    // Actual preseal physical commitments retain ORIGINAL first-tree grammar.
    return Original.firstChannel(binding, witness, frame, mode, schedule, authority.original());
}
pub fn mixFirst(channel: anytype, binding: Caller.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule, authority: Authority) void {
    Original.mixFirst(channel, binding, witness, frame, mode, schedule, authority.original());
}
pub fn instanceId(binding: Caller.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule, authority: Authority) ![32]u8 {
    _ = frame;
    _ = mode;
    _ = schedule;
    const source = try authority.roster.source(authority.ordinal);
    try authority.roster.requireSource(authority.ordinal, .caller, binding.execution_index, authority.group_id, .{ binding.first_roots[0], binding.first_roots[1], witness }, authority.census, authority.source_identity);
    if (source.kind != .caller) return error.UntrustedGlobalCallerSourceKind;
    return authority.source_identity;
}
pub fn admit(a: std.mem.Allocator, binding: Caller.CallerBinding, witness: [32]u8, frame: Frame, schedule: *const Schedule, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, authority: Authority) !void {
    if (!std.meta.eql(authority.sealed, sealed)) return error.UntrustedGlobalCallerSeal;
    var plan = try authority.admit(a);
    defer plan.deinit();
    try Original.admit(binding, witness, frame, schedule, sealed, pins, entries, authority.original());
    _ = try instanceId(binding, witness, frame, 1, schedule, authority);
    if (authority.census.all_rw != schedule.rw_events) return error.UntrustedGlobalCallerSourceCensus;
}
pub fn preflight(schedule: *const Schedule, plan: Roster.BorrowedPlan, authority: Authority) !void {
    try Original.preflightCompactCounts(schedule, plan.intervals.len, .{ schedule.program.len, schedule.program.len, schedule.tables.len, schedule.memory.len, schedule.memory.len }, authority.limits);
}
pub fn classification(a: std.mem.Allocator, sealed: Seal.Sealed, plan: Roster.BorrowedPlan, binding: Caller.CallerBinding, witness: [32]u8, frame: Frame, schedule: *const Schedule, authority: Authority) !Readonly.Challenges {
    _ = try instanceId(binding, witness, frame, 1, schedule, authority);
    try authority.roster.requireEpoch(sealed);
    if (!std.meta.eql(plan.digest, authority.roster.epoch().plan_digest)) return error.UntrustedGlobalCallerPlan;
    return Global.forGroup(try Global.draw(a, sealed, authority.roster.epoch()), authority.group_id);
}
pub fn proofChannel(a: std.mem.Allocator, sealed: Seal.Sealed, authority: Authority) !core.proof_suites.Blake3.Channel {
    try authority.roster.requireEpoch(sealed);
    var channel = sealed.sharedChannel();
    _ = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, 3, authority.ordinal, authority.group_id });
    channel.mixRoot(sealed.digest);
    channel.mixRoot(authority.roster.epoch().plan_digest);
    channel.mixRoot(authority.roster.epoch().roster_digest);
    return channel;
}
/// Every compact public claim remains canonical, bounded and exactly scoped.
/// Provider equality is deliberately absent here: it is a separate genuine
/// proof+group closure obligation, never a passed bool or scalar receipt.
pub fn mixClaims(channel: anytype, binding: Caller.CallerBinding, schedule: *const Schedule, claims: anytype, plan: Roster.BorrowedPlan, challenges: *const Readonly.Challenges, authority: Authority) !void {
    _ = challenges;
    try preflight(schedule, plan, authority);
    if (!std.meta.eql(plan.digest, authority.roster.epoch().plan_digest) or claims.readonly_claims.len != schedule.memory.len) return error.InvalidGlobalCallerReadonlyClaims;
    try @import("block_v5_caller_fused_proof_v1.zig").mixClaims(channel, binding, schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
    channel.mixU32s(&.{ TAG, VERSION, 2, authority.ordinal, authority.group_id, @intCast(claims.readonly_claims.len) });
    channel.mixRoot(Global.abiId());
    channel.mixRoot(authority.roster.epoch().plan_digest);
    channel.mixRoot(authority.roster.epoch().roster_digest);
    var readonly_count: u64 = 0;
    var events: u64 = 0;
    for (claims.readonly_claims, claims.memory_claims) |part, source| {
        if (part.claim.readonly_count > source.active_count or source.active_count >= core.fields.m31.Modulus) return error.InvalidGlobalCallerReadonlyCensus;
        for ([_]Q{ part.claim.mutable_sum, part.claim.classification_sum, part.claim.read_sum }) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidGlobalCallerReadonlyClaims;
        readonly_count = try std.math.add(u64, readonly_count, part.claim.readonly_count);
        events = try std.math.add(u64, events, source.active_count);
        channel.mixFelts(&.{ part.claim.mutable_sum, part.claim.classification_sum, part.claim.read_sum });
        channel.mixU64(part.claim.readonly_count);
    }
    if (events != authority.census.all_rw or readonly_count != authority.census.readonly or events - readonly_count != authority.census.mutable) return error.UntrustedGlobalCallerSourceCensus;
}
pub const Policy = struct {
    pub const CAPTURE_DOMAIN = "stwo-zig/block-v5/caller-readonly-global-capture/v2\x00";
    pub const Slot = This.Slot;
    pub const Authority = This.Authority;
    pub const Proof = This.Proof;
    pub const ClaimFrames = This.ClaimFrames;
    pub const Captured = This.VerifiedCapture;
    pub const Verified = This.Verified;
    pub const firstChannel = This.firstChannel;
    pub const instanceId = This.instanceId;
    pub const originalAuthority = This.originalAuthority;
    pub const admit = This.admit;
    pub const preflight = This.preflight;
    pub const classification = This.classification;
    pub const proofChannel = This.proofChannel;
    pub const mixClaims = This.mixClaims;
    /// Called by the one original verifier only AFTER real CompositePCS success.
    /// Taking a manufactured struct is not an alternate verification API.
    pub fn wrapVerified(original: Original.Verified, claims: anytype, authority: @This().Authority) !@This().Verified {
        try authority.roster.requireEpoch(authority.sealed);
        const binding = original.state.binding;
        try authority.roster.requireSource(authority.ordinal, .caller, binding.execution_index, authority.group_id, .{ binding.first_roots[0], binding.first_roots[1], original.memory.witness_root }, authority.census, authority.source_identity);
        var classification_sum = Q.zero();
        var read = Q.zero();
        var count: u64 = 0;
        for (claims.readonly_claims) |part| {
            classification_sum = classification_sum.add(part.claim.classification_sum);
            read = read.add(part.claim.read_sum);
            count = try std.math.add(u64, count, part.claim.readonly_count);
        }
        if (original.partition.all_rw_events != authority.census.all_rw or count != authority.census.readonly or original.partition.readonly_events != count or original.partition.mutable_events != authority.census.mutable) return error.UntrustedGlobalCallerSourceCensus;
        return .{ .program = original.program, .state = original.state, .tables = original.tables, .memory = original.memory, .partition = original.partition, .readonly_provider = .{ .classification_sum = classification_sum, .read_sum = read, .events = original.partition.all_rw_events, .readonly_count = count, .ordinal = authority.ordinal, .group_id = authority.group_id, .index = binding.execution_index, .source_identity = authority.source_identity, .epoch = authority.roster.epoch(), .sealed_digest = authority.sealed.digest } };
    }
    pub fn mixReceiptIdentity(channel: anytype, verified: *const @This().Verified) void {
        const claim = verified.readonly_provider;
        channel.mixU32s(&.{ TAG, VERSION, claim.ordinal, claim.group_id, claim.index });
        channel.mixRoot(claim.source_identity);
        channel.mixRoot(claim.epoch.plan_digest);
        channel.mixRoot(claim.epoch.roster_digest);
        channel.mixRoot(claim.sealed_digest);
        channel.mixFelts(&.{ claim.classification_sum, claim.read_sum });
        channel.mixU64(claim.events);
        channel.mixU64(claim.readonly_count);
    }
    pub const generateWitness = @import("block_v5_caller_readonly_witness_v1.zig").generateOpenSource;
    pub fn emptySlot() This.Slot {
        return .{ .claim = undefined };
    }
    pub fn slotClaim(a: std.mem.Allocator, claim: Readonly.Claim, counters: []const u64) !This.Slot {
        _ = a;
        _ = counters;
        return .{ .claim = claim };
    }
};
const This = @This();
pub fn ForBackend(comptime Backend: type) type {
    return Original.ForProtocol(Backend, Policy);
}
