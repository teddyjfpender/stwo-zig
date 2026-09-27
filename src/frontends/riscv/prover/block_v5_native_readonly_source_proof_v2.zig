//! Genuine original classifier AIR under a versioned group/shared epoch. Fresh
//! verification leaves class/read provider and actual-source joins explicitly
//! open; this family has no per-source counter-array authority.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Original = @import("block_v5_readonly_input_proof_v1.zig");
const Air = @import("block_v5_readonly_input_component_v1.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const TAG: u32 = 0x4235494e; // B5IN, no B5IR-v1 relabel
pub const VERSION: u32 = 2;
pub const Pin = struct {
    ordinal: u32,
    group_id: u32,
    index: u32,
    source_roots: [3][32]u8,
    census: Roster.Census,
    classifier: Original.Pin,
    pub fn fromAuthority(authority: *const Roster.Authority, ordinal: u32, config: core.pcs.PcsConfig, limits: Original.Limits) !Pin {
        const source = try authority.source(ordinal);
        if (source.kind != .native or source.census.all_rw == 0 or source.census.all_rw >= core.fields.m31.Modulus) return error.InvalidNativeReadonlyV2Source;
        return .{ .ordinal = ordinal, .group_id = source.group_id, .index = source.index, .source_roots = source.roots, .census = source.census, .classifier = .{ .plan_digest = authority.epoch().plan_digest, .source_identity = try authority.sourceIdentity(ordinal), .events = @intCast(source.census.all_rw), .row_log = source.row_log, .roots = source.classifier_roots orelse return error.MissingNativeReadonlyV2Classifier, .config = config, .limits = limits } };
    }
    pub fn require(self: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
        try self.classifier.validate();
        _ = entries;
        try authority.requireEpoch(sealed);
        try authority.requireSource(self.ordinal, .native, self.index, self.group_id, self.source_roots, self.census, self.classifier.source_identity);
        const expected = try authority.source(self.ordinal);
        if (!std.meta.eql(expected.classifier_roots.?, self.classifier.roots) or expected.row_log != self.classifier.row_log or
            self.classifier.events != self.census.all_rw or !std.meta.eql(self.classifier.plan_digest, authority.epoch().plan_digest) or
            !std.meta.eql(self.classifier.config, authority.config()) or !std.meta.eql(pins.config, authority.config())) return error.StaleNativeReadonlyV2Classifier;
    }
};
/// Bounded replay trace with no per-source interval counter vector. Requests
/// are proved by the original205 AIR; the one job counter stream belongs to the
/// presealed separate provider. Original trace storage/deinit is reused.
pub const Trace = struct {
    a: std.mem.Allocator,
    original: Original.Trace,
    pub fn deinit(self: *Trace) void {
        self.original.deinit(self.a);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, events: []const @import("../air/block/memory_transition.zig").Transition) !Trace {
        try pin.require(authority, sealed, pins, entries);
        var builder = try @import("block_v5_native_readonly_source_trace_v2.zig").Builder.initBorrowed(a, pin.classifier, authority.intervals(), authority.epoch().plan_digest);
        defer builder.deinit();
        for (events) |event| try builder.append(event, try @import("block_v5_readonly_input_plan_v1.zig").findInterval(authority.intervals(), event.address));
        const owned = try builder.finish();
        return .{ .a = owned.a, .original = owned.original };
    }
};
pub const Proof = struct {
    stark: suite.Proof,
    claim: @import("block_v5_readonly_input_protocol_v1.zig").Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenProvider = struct {
    ordinal: u32,
    group_id: u32,
    index: u32,
    census: Roster.Census,
    claim: @import("block_v5_readonly_input_protocol_v1.zig").Claim,
    source_identity: [32]u8,
    epoch: Global.Epoch,
    sealed_digest: [32]u8,
};
pub fn mixFirst(channel: anytype, pin: Pin) void {
    channel.mixU32s(&.{ TAG, VERSION, pin.ordinal, pin.group_id, pin.index, pin.classifier.events, pin.classifier.row_log });
    channel.mixRoot(Global.abiId());
    channel.mixRoot(pin.classifier.plan_digest);
    channel.mixRoot(pin.classifier.source_identity);
    pin.classifier.config.mixInto(channel);
}
pub fn firstChannel(pin: Pin) suite.Channel {
    var channel = suite.Channel{};
    mixFirst(&channel, pin);
    return channel;
}
/// Preseal witness-only physical header. No challenges are drawn here. After
/// roots enter the authenticated v2 roster, the real proof channel restarts at
/// B5SS/shared54; physical roots do not depend on the header's channel digest.
pub fn physicalFirstChannel(physical: Original.Pin, index: u32) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 0x50485953, index, physical.events, physical.row_log });
    channel.mixRoot(Global.abiId());
    channel.mixRoot(physical.plan_digest);
    channel.mixRoot(physical.source_identity);
    physical.config.mixInto(&channel);
    return channel;
}
pub fn mixPcsSuffix(channel: anytype, pin: Pin, claim: @import("block_v5_readonly_input_protocol_v1.zig").Claim) !void {
    channel.mixU32s(&.{ TAG, VERSION, pin.ordinal, pin.group_id, pin.index });
    channel.mixRoot(pin.classifier.source_identity);
    for (pin.classifier.roots) |root| channel.mixRoot(root);
    for ([_]Q{ claim.source_sum, claim.mutable_sum, claim.classification_sum, claim.read_sum }) |sum| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidNativeReadonlyV2Claim;
        for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
    if (claim.readonly_count != pin.census.readonly) return error.InvalidNativeReadonlyV2Claim;
    channel.mixU64(claim.readonly_count);
}
pub fn pcsChannel(a: std.mem.Allocator, authority: *const Roster.Authority, pin: Pin, sealed: Seal.Sealed, claim: @import("block_v5_readonly_input_protocol_v1.zig").Claim) !suite.Channel {
    try authority.requireEpoch(sealed);
    var channel = sealed.sharedChannel();
    _ = try Global.drawFromChannel(a, &channel, authority.epoch().plan_digest, authority.epoch().roster_digest);
    try mixPcsSuffix(&channel, pin, claim);
    return channel;
}
fn receipt(pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, claim: @import("block_v5_readonly_input_protocol_v1.zig").Claim) OpenProvider {
    return .{ .ordinal = pin.ordinal, .group_id = pin.group_id, .index = pin.index, .census = pin.census, .claim = claim, .source_identity = pin.classifier.source_identity, .epoch = authority.epoch(), .sealed_digest = sealed.digest };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const PCS = @import("block_v5_word_pcs_v1.zig").For(Backend, Air.Spec);
        pub const First = PCS.First;
        pub fn commitPhysical(a: std.mem.Allocator, trace: *const Original.Trace, physical: Original.Pin, index: u32) !First {
            try trace.require(physical);
            return PCS.commit(a, &trace.fixed, &trace.main, physicalFirstChannel(physical, index), physical.config, false);
        }
        pub fn commit(a: std.mem.Allocator, trace: *const Original.Trace, pin: Pin) !First {
            try trace.require(pin.classifier);
            return PCS.commit(a, &trace.fixed, &trace.main, firstChannel(pin), pin.classifier.config, false);
        }
        pub fn prove(a: std.mem.Allocator, first: *First, trace: *const Original.Trace, pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Proof {
            try pin.require(authority, sealed, pins, entries);
            try trace.require(pin.classifier);
            if (!first.owns_scheme or first.scheme.trees.items.len != 2 or !std.meta.eql(first.roots, pin.classifier.roots) or !std.meta.eql(first.scheme.config, pin.classifier.config)) return error.StaleNativeReadonlyV2First;
            const challenges = try Global.forGroup(try Global.draw(a, sealed, authority.epoch()), pin.group_id);
            var generated = try Original.generateInteraction(a, trace, pin.classifier, &challenges);
            defer generated.deinit(a);
            return .{ .claim = generated.claim, .stark = try PCS.prove(a, first, .{ .claim = generated.claim, .challenges = &challenges }, pin.classifier.row_log, &generated.columns, try pcsChannel(a, authority, pin, sealed, generated.claim)) };
        }
        pub const Captured = struct {
            core_capture: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            challenges: Global.Challenges,
            group_challenges: Global.Challenges,
            open: OpenProvider,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.core_capture.deinit(a);
                self.* = undefined;
            }
        };
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, proof: *const Proof, pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Captured {
            try pin.require(authority, sealed, pins, entries);
            const shared = try Global.draw(a, sealed, authority.epoch());
            const challenges = try Global.forGroup(shared, pin.group_id);
            const values = try fixed(a, pin);
            defer a.free(values);
            const captured = try PCS.verifyCaptureBorrowed(a, &proof.stark, .{ .claim = proof.claim, .challenges = &challenges }, pin.classifier.row_log, &.{.{ .log_size = pin.classifier.row_log, .values = values }}, pin.classifier.roots, pin.classifier.config, firstChannel(pin), try pcsChannel(a, authority, pin, sealed, proof.claim));
            return .{ .core_capture = captured.proof, .final_channel = captured.final_channel, .challenges = shared, .group_challenges = challenges, .open = receipt(pin, authority, sealed, proof.claim) };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !OpenProvider {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            try pin.require(authority, sealed, pins, entries);
            const challenges = try Global.forGroup(try Global.draw(a, sealed, authority.epoch()), pin.group_id);
            const values = try fixed(a, pin);
            defer a.free(values);
            const channel = try pcsChannel(a, authority, pin, sealed, proof.claim);
            const result = receipt(pin, authority, sealed, proof.claim);
            owns = false;
            try PCS.verifyOwned(a, proof.stark, .{ .claim = proof.claim, .challenges = &challenges }, pin.classifier.row_log, &.{.{ .log_size = pin.classifier.row_log, .values = values }}, pin.classifier.roots, pin.classifier.config, firstChannel(pin), channel);
            return result;
        }
    };
}
fn fixed(a: std.mem.Allocator, pin: Pin) ![]M {
    const rows: usize = @as(usize, 1) << @intCast(pin.classifier.row_log);
    const values = try a.alloc(M, rows);
    @memset(values, M.zero());
    for (0..pin.classifier.events) |logical| values[@import("../recursion/air/framework_interaction.zig").committedRow(logical, pin.classifier.row_log)] = M.one();
    return values;
}
