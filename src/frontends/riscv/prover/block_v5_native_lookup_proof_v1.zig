//! Six standalone native lookup providers under the shared B5SS prefix.
//! Each admitted field-safe closure group is independent of execution AIR size.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;
const tables = @import("../air/lookups/tables/mod.zig");
const columns = @import("../recursion/air/blake3_row_columns.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const shared = @import("../recursion/air/universal_provider_relations.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const assembly = @import("block_v5_native_lookup_assembly_v1.zig");
pub const Plan = @import("block_v5_native_lookup_plan_v1.zig").Plan;
const Count = assembly.Count;
const Digest = [32]u8;
pub const Proof = struct {
    stark: suite.Proof,
    claims: [Count]Q,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenReceipt = struct { plan_id: Digest, roots: seal.Roots, sealed_digest: Digest, claims: [Count]Q, total: Q };

fn validateCounters(counters: *const tables.counter.Set) !void {
    for (&counters.counters, 0..) |*counter, index| {
        if (@intFromEnum(counter.kind) != index or counter.values.len != tables.schema.size(counter.kind))
            return error.InvalidBlockV5NativeLookupCounter;
        for (counter.values) |value| if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
    }
}
fn validateBounds(counters: *const tables.counter.Set, plan: Plan) !void {
    try plan.validate();
    for (&counters.counters, plan.max_requests) |*counter, limit| {
        var total: u64 = 0;
        // Access-chain range requests can be negative. Canonical field
        // residues must not be interpreted as unsigned request counts.
        // The independent shape bound counts absolute source requests;
        // cancellation at one tuple can only reduce this centered mass.
        for (counter.values) |value| total = try std.math.add(u64, total, @min(value.v, core.fields.m31.Modulus - value.v));
        if (total > limit) return error.BlockV5NativeLookupDemandExceeded;
    }
}
/// Shared first-round/replay census preflight; no commitment or proof authority.
/// Signed residues retain the original centered absolute request-mass bound.
pub fn validateSourceCounters(counters: *const tables.counter.Set, plan: Plan) !void {
    try validateCounters(counters);
    try validateBounds(counters, plan);
}
fn snapshots(counters: *const tables.counter.Set) [Count]Digest {
    var result: [Count]Digest = undefined;
    for (&counters.counters, &result) |*counter, *digest|
        digest.* = @import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(counter);
    return result;
}
fn fixed(a: std.mem.Allocator, out: *std.ArrayList(Column)) !void {
    for (0..Count) |index| try columns.tablePreprocessed(a, @enumFromInt(index), out);
}
fn free(a: std.mem.Allocator, values: *std.ArrayList(Column)) void {
    for (values.items) |column| a.free(column.values);
    values.deinit(a);
}
pub fn admit(plan: Plan, roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    try sealed.require(pins, entries);
    if (try std.math.add(u32, plan.first_execution, plan.execution_count) > sealed.execution_instance_count)
        return error.InvalidBlockV5LookupExecutionSpan;
    const id = try plan.identity();
    for (entries) |entry| if (entry.family == .native_lookup and entry.index == plan.index) {
        if (!std.meta.eql(entry.instance_id, id) or !std.meta.eql(entry.roots, roots))
            return error.UntrustedBlockV5NativeLookupRoots;
        return;
    };
    return error.MissingBlockV5NativeLookup;
}
pub fn channelFor(a: std.mem.Allocator, plan: Plan, roots: seal.Roots, sealed: seal.Sealed, claims: [Count]Q) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try universal.UniversalRelations.draw(a, &channel);
    channel.mixU32s(&.{ 0x42354c54, 1 }); // B5LT
    channel.mixRoot(try plan.identity());
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    for (claims) |claim| {
        if (!shared.secureIsCanonical(&claim)) return error.InvalidBlockV5NativeLookupClaim;
        channel.mixFelts(&.{claim});
    }
    return channel;
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        /// Typed, independently constructed fixed table basis. Neither the
        /// proof nor its main counters can select these deterministic columns.
        pub const FixedBasis = struct {
            scheme: Scheme,
            root: Digest,
            pub fn init(a: std.mem.Allocator, config: core.pcs.PcsConfig) !FixedBasis {
                try @import("blake3_execution_protocol.zig").validateConfig(config);
                var scheme = try Scheme.init(a, config);
                errdefer scheme.deinit(a);
                scheme.setCoefficientRetentionPolicy(.never);
                var fixed_columns: std.ArrayList(Column) = .empty;
                defer free(a, &fixed_columns);
                try fixed(a, &fixed_columns);
                var channel = suite.Channel{};
                try scheme.commitBorrowedStreaming(a, fixed_columns.items, 8, &channel);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 1) return error.InvalidBlockV5LookupFixedBasis;
                return .{ .scheme = scheme, .root = roots.items[0] };
            }
            pub fn deinit(self: *FixedBasis, a: std.mem.Allocator) void {
                self.scheme.deinit(a);
                self.* = undefined;
            }
        };
        pub const FirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            plan_id: Digest,
            counter_snapshots: [Count]Digest,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
            pub fn entry(self: FirstRound, plan: Plan) !seal.Entry {
                if (!std.meta.eql(self.plan_id, try plan.identity())) return error.UntrustedBlockV5LookupPlan;
                return .{ .family = .native_lookup, .index = plan.index, .instance_id = self.plan_id, .roots = self.roots };
            }
        };
        pub fn commitFirstRound(a: std.mem.Allocator, counters: *const tables.counter.Set, plan: Plan, config: core.pcs.PcsConfig) !FirstRound {
            try validateSourceCounters(counters, plan);
            var basis = try FixedBasis.init(a, config);
            defer basis.deinit(a);
            return commitFirstRoundWithBasis(a, counters, plan, &basis);
        }
        pub fn commitFirstRoundWithBasis(a: std.mem.Allocator, counters: *const tables.counter.Set, plan: Plan, basis: *FixedBasis) !FirstRound {
            try validateSourceCounters(counters, plan);
            const plan_id = try plan.identity();
            var channel = suite.Channel{};
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copyFixed(Backend, a, &basis.scheme, &channel);
            errdefer scheme.deinit(a);
            var main: std.ArrayList(Column) = .empty;
            defer free(a, &main);
            for (&counters.counters) |*counter| {
                const values = try counter.committedColumn(a);
                main.append(a, .{ .log_size = tables.schema.logSize(counter.kind), .values = values }) catch |err| {
                    a.free(values);
                    return err;
                };
            }
            try scheme.commitBorrowedStreaming(a, main.items, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidBlockV5NativeLookupFirstRound;
            if (!std.meta.eql(roots.items[0], basis.root)) return error.UntrustedBlockV5LookupFixedBasis;
            return .{ .scheme = scheme, .roots = roots.items[0..2].*, .plan_id = plan_id, .counter_snapshots = snapshots(counters) };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, counters: *const tables.counter.Set, plan: Plan, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Proof {
            try admit(plan, first.roots, sealed, pins, entries);
            try validateCounters(counters);
            if (!first.owns_scheme or !std.meta.eql(first.plan_id, try plan.identity()) or
                !std.meta.eql(first.scheme.config, pins.config) or
                !std.meta.eql(first.counter_snapshots, snapshots(counters)))
                return error.BlockV5NativeLookupReplayMismatch;
            try validateBounds(counters, plan);
            var relation_channel = sealed.sharedChannel();
            const vm = try universal.UniversalRelations.draw(a, &relation_channel);
            const relations = try shared.SharedProviderRelations.init(&vm);
            var interaction: std.ArrayList(Column) = .empty;
            defer free(a, &interaction);
            var claims: [Count]Q = undefined;
            for (&counters.counters, &claims) |*counter, *claim| {
                var generated = try tables.interaction.generate(a, counter, &relations.native);
                defer generated.deinit(a);
                claim.* = generated.claim;
                for (generated.columns) |values| {
                    const copy = try a.dupe(core.fields.m31.M31, values);
                    interaction.append(a, .{ .log_size = tables.schema.logSize(counter.kind), .values = copy }) catch |err| {
                        a.free(copy);
                        return err;
                    };
                }
            }
            const owner = try assembly.Owner.init(a, relations, claims);
            defer owner.destroy(a);
            var channel = try channelFor(a, plan, first.roots, sealed, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &owner.proverHandles(), &channel, first.scheme), .claims = claims };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !OpenReceipt {
            // Consume the received allocation even if deterministic setup
            // construction fails before the shared verifier takes ownership.
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            var basis = try FixedBasis.init(a, pins.config);
            defer basis.deinit(a);
            owns = false;
            return verifyOwnedWithBasis(a, proof, plan, expected_roots, sealed, pins, entries, &basis);
        }
        pub const Captured = struct {
            proof: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            receipt: OpenReceipt,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.proof.deinit(a);
                self.* = undefined;
            }
        };
        /// Full original table verifier. The capture owns all its storage and
        /// never consumes or retains the borrowed native proof allocation.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Captured {
            var basis = try FixedBasis.init(a, pins.config);
            defer basis.deinit(a);
            return verifyCaptureBorrowedWithBasis(a, received, plan, expected_roots, sealed, pins, entries, &basis);
        }
        pub fn verifyCaptureBorrowedWithBasis(a: std.mem.Allocator, received: *const Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, basis: *const FixedBasis) !Captured {
            var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
            var end: suite.Channel = undefined;
            const receipt = try verifyInternal(false, a, received, plan, expected_roots, sealed, pins, entries, basis, &capture, &end);
            return .{ .proof = capture, .final_channel = end, .receipt = receipt };
        }
        /// Consumes the input on EVERY failure, including deterministic setup.
        pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Captured {
            var proof = received;
            defer proof.deinit(a);
            return verifyCaptureBorrowed(a, &proof, plan, expected_roots, sealed, pins, entries);
        }
        pub fn verifyOwnedWithBasis(a: std.mem.Allocator, received: Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, basis: *const FixedBasis) !OpenReceipt {
            return verifyInternal(true, a, &received, plan, expected_roots, sealed, pins, entries, basis, null, null);
        }
        fn verifyInternal(comptime take: bool, a: std.mem.Allocator, received: *const Proof, plan: Plan, expected_roots: seal.Roots, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, basis: *const FixedBasis, capture: ?*core.verifier.ProofCapture(suite.Hasher), end: ?*suite.Channel) !OpenReceipt {
            var proof = received.*;
            var owns = take;
            defer if (owns) proof.deinit(a);
            try admit(plan, expected_roots, sealed, pins, entries);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected_roots) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config))
                return error.UntrustedBlockV5NativeLookupProof;
            if (!std.meta.eql(basis.scheme.config, pins.config) or !std.meta.eql(basis.root, roots[0]))
                return error.UntrustedBlockV5NativeLookupFixedRoot;
            var relation_channel = sealed.sharedChannel();
            const vm = try universal.UniversalRelations.draw(a, &relation_channel);
            const relations = try shared.SharedProviderRelations.init(&vm);
            const owner = try assembly.Owner.init(a, relations, proof.claims);
            defer owner.destroy(a);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            var temporary = suite.Channel{};
            try verifier.commit(a, roots[0], try assembly.logs(scratch, .fixed), &temporary);
            try verifier.commit(a, roots[1], try assembly.logs(scratch, .main), &temporary);
            var channel = try channelFor(a, plan, expected_roots, sealed, proof.claims);
            try verifier.commit(a, roots[2], try assembly.logs(scratch, .interaction), &channel);
            var total = Q.zero();
            for (proof.claims) |claim| total = total.add(claim);
            const receipt = OpenReceipt{ .plan_id = try plan.identity(), .roots = expected_roots, .sealed_digest = sealed.digest, .claims = proof.claims, .total = total };
            if (take) {
                owns = false;
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &owner.verifierHandles(), &channel, &verifier, proof.stark);
            } else {
                try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &owner.verifierHandles(), &channel, &verifier, &received.stark, capture.?);
            }
            if (end) |output| output.* = channel;
            return receipt;
        }
    };
}
