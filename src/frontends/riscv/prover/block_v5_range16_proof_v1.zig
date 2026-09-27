//! Separately planned fixed range16 provider under the common B5SS transcript.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const range = @import("block_v5_range16_v1.zig");
const component = @import("block_v5_range16_component_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const pcs = @import("block_v5_word_pcs_v1.zig");
pub const Proof = struct {
    stark: suite.Proof,
    claim: component.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenReceipt = struct { claim: component.Claim, shard: range.Shard, roots: [2][32]u8, sealed_digest: [32]u8 };
const OriginalAdmission = struct {
    pub fn require(_: OriginalAdmission, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
        return admit(shard, plan_digest, roots, sealed, pins, entries);
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return ForAdmission(Backend);
}
/// Statically selected independent admission; the original range AIR, channels,
/// commitment construction and fresh PCS verifier remain the same body. New
/// families must supply real roster membership, never fabricate memory entries.
pub fn ForAdmission(comptime Backend: type) type {
    return struct {
        const Api = pcs.For(Backend, component.Spec);
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Proof {
            return proveWithAdmission(a, first, counter, shard, plan_digest, sealed, pins, entries, OriginalAdmission{});
        }
        pub fn provePrepared(a: std.mem.Allocator, first: *FirstRound, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, table: *const @import("block_v5_range16_inverse_table_v1.zig").Table) !Proof {
            return provePreparedWithAdmission(a, first, counter, shard, plan_digest, sealed, pins, entries, table, OriginalAdmission{});
        }
        pub fn proveResident(a: std.mem.Allocator, session: anytype, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Proof {
            return proveResidentWithAdmission(a, session, counter, shard, plan_digest, roots, sealed, pins, entries, OriginalAdmission{});
        }
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Captured {
            return verifyCaptureBorrowedWithAdmission(a, received, shard, plan_digest, roots, sealed, pins, entries, OriginalAdmission{});
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !OpenReceipt {
            return verifyOwnedWithAdmission(a, received, shard, plan_digest, roots, sealed, pins, entries, OriginalAdmission{});
        }

        pub const FirstRound = struct {
            pcs_first: Api.First,
            counter_digest: [32]u8,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                self.pcs_first.deinit(a);
                self.* = undefined;
            }
            pub fn roots(self: *const FirstRound) [2][32]u8 {
                return self.pcs_first.roots;
            }
        };
        pub fn commitFirstRound(a: std.mem.Allocator, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, config: core.pcs.PcsConfig, retain: bool) !FirstRound {
            const fixed = try range.valueColumn(a);
            defer a.free(fixed);
            const main = try range.multiplicityColumn(a, counter, shard.request_count);
            defer a.free(main);
            return .{ .pcs_first = try Api.commit(a, &.{.{ .log_size = range.TABLE_LOG, .values = fixed }}, &.{.{ .log_size = range.TABLE_LOG, .values = main }}, firstChannel(shard, plan_digest), config, retain), .counter_digest = counter.digest() };
        }
        pub fn proveWithAdmission(a: std.mem.Allocator, first: *FirstRound, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, authority: anytype) !Proof {
            try authority.require(shard, plan_digest, first.roots(), sealed, pins, entries);
            const challenges = try protocol.Challenges.draw(a, sealed);
            var table = try @import("block_v5_range16_inverse_table_v1.zig").Table.init(a, challenges.range16);
            defer table.deinit();
            return provePreparedWithAdmission(a, first, counter, shard, plan_digest, sealed, pins, entries, &table, authority);
        }
        pub fn provePreparedWithAdmission(a: std.mem.Allocator, first: *FirstRound, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, table: *const @import("block_v5_range16_inverse_table_v1.zig").Table, authority: anytype) !Proof {
            try authority.require(shard, plan_digest, first.roots(), sealed, pins, entries);
            if (!std.meta.eql(counter.digest(), first.counter_digest) or counter.total != shard.request_count) return error.V5Range16ReplayMismatch;
            const challenges = try protocol.Challenges.draw(a, sealed);
            var generated = try component.generatePrepared(a, counter, &challenges, table);
            defer generated.deinit(a);
            var columns: [component.Spec.INTERACTION_COUNT]pcs.Column = undefined;
            for (&columns, generated.columns) |*column, values| column.* = .{ .log_size = range.TABLE_LOG, .values = values };
            const spec = component.Spec{ .claim = generated.claim, .challenges = &challenges };
            return .{ .stark = try Api.prove(a, &first.pcs_first, spec, range.TABLE_LOG, &columns, try proofChannel(a, sealed, shard, plan_digest, generated.claim)), .claim = generated.claim };
        }
        pub fn commitFirstRoundResident(a: std.mem.Allocator, session: anytype, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, config: core.pcs.PcsConfig) !FirstRound {
            if (counter.values.len != range.TABLE_SIZE or counter.total != shard.request_count) return error.V5Range16ReplayMismatch;
            var ingress = try Backend.RamLaneResident.upload(a, counter.values, session.limits.max_resident_bytes);
            defer ingress.deinit();
            var witness = try session.rangeWitness(&ingress);
            defer witness.deinit();
            return .{ .pcs_first = try Api.commitResident(a, session, &witness, range.TABLE_LOG, firstChannel(shard, plan_digest), config, ingress.byte_length), .counter_digest = counter.digest() };
        }
        /// Same sealed inverse table and original PCS owner as the requester.
        /// Only two secure totals cross the CPU transcript boundary.
        pub fn proveResidentWithAdmission(a: std.mem.Allocator, session: anytype, counter: *const range.Counter, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, authority: anytype) !Proof {
            try authority.require(shard, plan_digest, roots, sealed, pins, entries);
            if (counter.values.len != range.TABLE_SIZE or counter.total != shard.request_count) return error.V5Range16ReplayMismatch;
            var observed: u64 = 0;
            for (counter.values) |count_value| {
                if (count_value >= core.fields.m31.Modulus) return error.InvalidV5Range16Counter;
                observed = try std.math.add(u64, observed, count_value);
            }
            if (observed != counter.total) return error.V5Range16ReplayMismatch;
            const Resident = Backend.RamLaneResident;
            var ingress = try Resident.upload(a, counter.values, session.limits.max_resident_bytes);
            defer ingress.deinit();
            try session.noteIngress(ingress.byte_length, true);
            var witness = try session.rangeWitness(&ingress);
            var owns_witness = true;
            defer if (owns_witness) witness.deinit();
            var first = try Api.commitResident(a, session, &witness, range.TABLE_LOG, firstChannel(shard, plan_digest), pins.config, ingress.byte_length);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots, roots)) return error.V5Range16ReplayMismatch;
            const challenges = try protocol.Challenges.draw(a, sealed);
            var program = try @import("block_v5_word_gpu_program_v1.zig").rangeFractions(a, .{ .claim = .{ .sum = core.fields.qm31.QM31.zero(), .count = counter.total }, .challenges = &challenges });
            defer program.deinit();
            const pcs_bytes = try std.math.add(usize, try Resident.retainedBytes(.range_fixed, 16), try Resident.retainedBytes(.range_main, 16));
            const other_live = try std.math.add(usize, pcs_bytes, ingress.byte_length);
            var generated = try session.interaction(a, &program, &witness, other_live);
            var owns_generated = true;
            defer if (owns_generated) generated.deinit();
            if (generated.batches != 2 or generated.claim_count != 2) return error.InvalidV5Range16Claim;
            const totals = try session.readClaims(2, &generated);
            const claim = component.Claim{ .sum = totals[0], .count = try @import("block_v5_ram_lanes_resident_source_v1.zig").count(totals[1]) };
            if (claim.count != counter.total) return error.V5Range16ReplayMismatch;
            const spec = component.Spec{ .claim = claim, .challenges = &challenges };
            const transcript = try proofChannel(a, sealed, shard, plan_digest, claim);
            witness.deinit();
            owns_witness = false;
            owns_generated = false;
            return .{ .stark = try Api.proveResident(a, &first, spec, range.TABLE_LOG, session, generated, other_live, transcript), .claim = claim };
        }
        pub const Captured = struct {
            core_capture: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            receipt: OpenReceipt,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.core_capture.deinit(a);
                self.* = undefined;
            }
        };
        pub fn verifyCaptureBorrowedWithAdmission(a: std.mem.Allocator, received: *const Proof, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, authority: anytype) !Captured {
            try authority.require(shard, plan_digest, roots, sealed, pins, entries);
            if (received.claim.count != shard.request_count or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&received.claim.sum)) return error.InvalidV5Range16Claim;
            const fixed = try range.valueColumn(a);
            defer a.free(fixed);
            const challenges = try protocol.Challenges.draw(a, sealed);
            const spec = component.Spec{ .claim = received.claim, .challenges = &challenges };
            const captured = try Api.verifyCaptureBorrowed(a, &received.stark, spec, range.TABLE_LOG, &.{.{ .log_size = range.TABLE_LOG, .values = fixed }}, roots, pins.config, firstChannel(shard, plan_digest), try proofChannel(a, sealed, shard, plan_digest, received.claim));
            return .{ .core_capture = captured.proof, .final_channel = captured.final_channel, .receipt = .{ .claim = received.claim, .shard = shard, .roots = roots, .sealed_digest = sealed.digest } };
        }
        pub fn verifyOwnedWithAdmission(a: std.mem.Allocator, received: Proof, shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, authority: anytype) !OpenReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            try authority.require(shard, plan_digest, roots, sealed, pins, entries);
            if (proof.claim.count != shard.request_count or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&proof.claim.sum)) return error.InvalidV5Range16Claim;
            const fixed = try range.valueColumn(a);
            defer a.free(fixed);
            const challenges = try protocol.Challenges.draw(a, sealed);
            const spec = component.Spec{ .claim = proof.claim, .challenges = &challenges };
            const result = OpenReceipt{ .claim = proof.claim, .shard = shard, .roots = roots, .sealed_digest = sealed.digest };
            const transcript = try proofChannel(a, sealed, shard, plan_digest, proof.claim);
            owns = false;
            try Api.verifyOwned(a, proof.stark, spec, range.TABLE_LOG, &.{.{ .log_size = range.TABLE_LOG, .values = fixed }}, roots, pins.config, firstChannel(shard, plan_digest), transcript);
            return result;
        }
    };
}
pub fn admit(shard: range.Shard, plan_digest: [32]u8, roots: [2][32]u8, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    if (shard.instance_count == 0 or shard.request_count == 0 or shard.request_count > range.MAX_REQUESTS) return error.InvalidV5Range16Shard;
    try sealed.require(pins, entries);
    for (entries) |entry| if (entry.family == .memory_range and entry.index == shard.index) {
        if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, instanceId(plan_digest, shard.index))) return error.UntrustedV5Range16Shard;
        return;
    };
    return error.MissingV5Range16Shard;
}
pub fn instanceId(plan_digest: [32]u8, index: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/range16-shard/v1\x00");
    hash.update(&protocol.abiId());
    hash.update(&plan_digest);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, index, .little);
    hash.update(&bytes);
    return hash.finalResult();
}
pub fn firstChannel(shard: range.Shard, plan_digest: [32]u8) suite.Channel {
    var channel = suite.Channel{};
    mixShard(&channel, shard, plan_digest);
    return channel;
}
pub fn proofChannel(a: std.mem.Allocator, sealed: seal.Sealed, shard: range.Shard, plan_digest: [32]u8, claim: component.Claim) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try protocol.Challenges.drawFromChannel(a, &channel);
    mixShard(&channel, shard, plan_digest);
    channel.mixU64(claim.count);
    for (claim.sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    return channel;
}
pub fn mixShard(channel: anytype, shard: range.Shard, plan_digest: [32]u8) void {
    channel.mixU32s(&.{ protocol.TAG, protocol.VERSION, range.TABLE_LOG, shard.index, shard.first_instance, shard.instance_count });
    channel.mixU64(shard.request_count);
    channel.mixRoot(plan_digest);
}
