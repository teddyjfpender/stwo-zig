//! Real group provider AIR/PCS and dedicated original range16 proof receiver.
//! A paired receipt still leaves all native/caller classifier requests open.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
const Interaction = @import("block_v5_readonly_input_provider_interaction_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Range = @import("block_v5_range16_proof_v1.zig");
const Q = core.fields.qm31.QM31;
pub const TAG: u32 = 0x42354950;
pub const VERSION: u32 = 2;
pub const Pin = Roster.ProviderPin;
pub const Proof = struct {
    stark: suite.Proof,
    claim: Air.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenRange = struct { pin: Pin, claim: Air.Claim, epoch: Global.Epoch, sealed_digest: [32]u8 };
pub const OpenSource = struct { provider: OpenRange, range: Range.OpenReceipt };
pub fn mixFirst(channel: anytype, pin: Pin) void {
    channel.mixU32s(&.{ TAG, VERSION, pin.shape.index, pin.shape.group_id, pin.shape.fragment_count, pin.shape.row_log, pin.range_index });
    channel.mixRoot(Global.abiId());
    channel.mixRoot(pin.plan_digest);
    channel.mixRoot(pin.ordinal_digest);
    channel.mixU64(pin.shape.first_fragment);
    channel.mixU64(pin.shape.counts.events);
    channel.mixU64(pin.shape.counts.readonly);
    channel.mixU64(pin.shape.counts.range_requests);
    pin.config.mixInto(channel);
}
pub fn firstChannel(pin: Pin) suite.Channel {
    var channel = suite.Channel{};
    mixFirst(&channel, pin);
    return channel;
}
pub fn require(a: *const Roster.Authority, pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
    try pin.shape.require();
    _ = entries;
    try a.requireEpoch(sealed);
    try a.requireProvider(pin);
    if (!std.meta.eql(pin.config, a.config()) or !std.meta.eql(pins.config, a.config()) or !std.meta.eql(pin.plan_digest, a.epoch().plan_digest)) return error.StaleReadonlyProviderEpoch;
}
pub fn requireClaim(pin: Pin, claim: Air.Claim) !void {
    if (!std.meta.eql(pin.shape.counts, claim.counts)) return error.InvalidReadonlyProviderClaim;
    for ([_]Q{ claim.classification_sum, claim.read_sum } ++ claim.range_sums) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidReadonlyProviderClaim;
}
pub fn pcsChannel(a: std.mem.Allocator, authority: *const Roster.Authority, pin: Pin, sealed: Seal.Sealed, claim: Air.Claim) !suite.Channel {
    try requireClaim(pin, claim);
    try authority.requireEpoch(sealed);
    var channel = sealed.sharedChannel();
    _ = try Global.drawFromChannel(a, &channel, authority.epoch().plan_digest, authority.epoch().roster_digest);
    try mixPcsSuffix(&channel, pin, claim);
    return channel;
}
pub fn mixPcsSuffix(channel: anytype, pin: Pin, claim: Air.Claim) !void {
    try requireClaim(pin, claim);
    channel.mixU32s(&.{ TAG, VERSION, pin.shape.index, pin.shape.group_id, pin.range_index });
    channel.mixRoot(pin.ordinal_digest);
    for (pin.roots) |root| channel.mixRoot(root);
    for ([_]Q{ claim.classification_sum, claim.read_sum } ++ claim.range_sums) |sum| for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    channel.mixU64(claim.counts.events);
    channel.mixU64(claim.counts.readonly);
    channel.mixU64(claim.counts.range_requests);
}
pub const RangeAdmission = struct {
    authority: *const Roster.Authority,
    pin: Roster.RangePin,
    pub fn require(self: RangeAdmission, shard: @import("block_v5_range16_v1.zig").Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
        _ = entries;
        try self.authority.requireEpoch(sealed);
        try self.authority.requireRange(self.pin);
        if (!std.meta.eql(shard, self.pin.shard) or !std.meta.eql(plan_digest, self.pin.plan_digest) or !std.meta.eql(roots, self.pin.roots) or
            !std.meta.eql(pins.config, self.pin.config) or !std.meta.eql(self.pin.config, self.authority.config())) return error.UntrustedReadonlyProviderRange;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const PCS = @import("block_v5_word_pcs_v1.zig").For(Backend, Air.Spec);
        pub const First = PCS.First;
        pub fn commit(a: std.mem.Allocator, columns: *const Table.Columns, pin: Pin) !First {
            try pin.shape.require();
            if (!std.meta.eql(columns.shape, pin.shape)) return error.UntrustedReadonlyProviderTrace;
            return PCS.commit(a, &columns.fixed.columns, &columns.main, firstChannel(pin), pin.config, false);
        }
        pub fn prove(a: std.mem.Allocator, first: *First, columns: *const Table.Columns, pin: Pin, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Proof {
            try require(authority, pin, sealed, pins, entries);
            if (!first.owns_scheme or first.scheme.trees.items.len != 2 or !std.meta.eql(first.roots, pin.roots) or !std.meta.eql(first.scheme.config, pin.config) or !std.meta.eql(columns.shape, pin.shape)) return error.StaleReadonlyProviderFirst;
            const shared = try Global.draw(a, sealed, authority.epoch());
            const challenges = try Global.forGroup(shared, pin.shape.group_id);
            var generated = try Interaction.generate(a, columns, shared);
            defer generated.deinit();
            return .{ .claim = generated.claim, .stark = try PCS.prove(a, first, .{ .claim = generated.claim, .challenges = &challenges }, pin.shape.row_log, &generated.columns, try pcsChannel(a, authority, pin, sealed, generated.claim)) };
        }
        fn fixed(a: std.mem.Allocator, authority: *const Roster.Authority, pin: Pin, ordinals: []const u32, limits: Table.Limits) !Table.Fixed {
            if (!std.meta.eql(try Table.ordinalDigest(pin.shape, pin.plan_digest, ordinals), pin.ordinal_digest)) return error.UntrustedReadonlyProviderOrdinals;
            return Table.Fixed.init(a, authority.intervals(), ordinals, pin.shape, limits);
        }
        pub const Captured = struct {
            core_capture: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            challenges: Global.Challenges,
            group_challenges: Global.Challenges,
            open: OpenRange,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.core_capture.deinit(a);
                self.* = undefined;
            }
        };
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, pin: Pin, ordinals: []const u32, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Table.Limits) !Captured {
            try require(authority, pin, sealed, pins, entries);
            try requireClaim(pin, received.claim);
            var expected = try fixed(a, authority, pin, ordinals, limits);
            defer expected.deinit();
            const shared = try Global.draw(a, sealed, authority.epoch());
            const challenges = try Global.forGroup(shared, pin.shape.group_id);
            const captured = try PCS.verifyCaptureBorrowed(a, &received.stark, .{ .claim = received.claim, .challenges = &challenges }, pin.shape.row_log, &expected.columns, pin.roots, pin.config, firstChannel(pin), try pcsChannel(a, authority, pin, sealed, received.claim));
            return .{ .core_capture = captured.proof, .final_channel = captured.final_channel, .challenges = shared, .group_challenges = challenges, .open = .{ .pin = pin, .claim = received.claim, .epoch = authority.epoch(), .sealed_digest = sealed.digest } };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, pin: Pin, ordinals: []const u32, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Table.Limits) !OpenRange {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            try require(authority, pin, sealed, pins, entries);
            try requireClaim(pin, proof.claim);
            var expected = try fixed(a, authority, pin, ordinals, limits);
            defer expected.deinit();
            const challenges = try Global.forGroup(try Global.draw(a, sealed, authority.epoch()), pin.shape.group_id);
            const channel = try pcsChannel(a, authority, pin, sealed, proof.claim);
            const result = OpenRange{ .pin = pin, .claim = proof.claim, .epoch = authority.epoch(), .sealed_digest = sealed.digest };
            owns = false;
            try PCS.verifyOwned(a, proof.stark, .{ .claim = proof.claim, .challenges = &challenges }, pin.shape.row_log, &expected.columns, pin.roots, pin.config, firstChannel(pin), channel);
            return result;
        }
        /// Consumes both real original proofs. A caller-provided scalar receipt is
        /// never accepted as the range-provider substitute.
        pub fn verifyPairOwned(a: std.mem.Allocator, received: Proof, range_received: Range.Proof, pin: Pin, ordinals: []const u32, authority: *const Roster.Authority, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Table.Limits) !OpenSource {
            var range_proof = range_received;
            var owns_range = true;
            defer if (owns_range) range_proof.deinit(a);
            const provider = try verifyOwned(a, received, pin, ordinals, authority, sealed, pins, entries, limits);
            const range_pin = try authority.range(pin.range_index);
            if (range_pin.provider_index != pin.shape.index or range_pin.group_id != pin.shape.group_id) return error.UntrustedReadonlyProviderRange;
            owns_range = false;
            const supplied = try Range.ForAdmission(Backend).verifyOwnedWithAdmission(a, range_proof, range_pin.shard, range_pin.plan_digest, range_pin.roots, sealed, pins, entries, RangeAdmission{ .authority = authority, .pin = range_pin });
            var total = Q.zero();
            for (provider.claim.range_sums) |sum| total = total.add(sum);
            if (!total.add(supplied.claim.sum).isZero() or supplied.claim.count != pin.shape.counts.range_requests) return error.UnclosedReadonlyProviderRange;
            return .{ .provider = provider, .range = supplied };
        }
    };
}
