//! Same-sorted-root final endpoint proof. Public custody is accepted only by
//! the paired receiver after both this quotient and the sorted proof verify.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const memory = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/memory_component_trace.zig");
const sorted = @import("block_memory_shared_instance_proof_v2.zig");
const old = @import("block_memory_proof_v2.zig");
const endpoint = @import("block_v5_rw_endpoint_interaction_v1.zig");
const adapter = @import("block_v5_rw_endpoint_component_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const canonical = @import("../recursion/air/universal_provider_relations.zig");
const Digest = [32]u8;
pub const Proof = struct {
    stark: suite.Proof,
    claim: endpoint.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, false);
}
pub fn ForCompactBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, true);
}
fn ForBackendMode(comptime Backend: type, comptime compact: bool) type {
    return struct {
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Api = if (compact) sorted.ForCompactBackend(Backend) else sorted.ForBackend(Backend);
        const FirstRound = Api.FirstRound;
        const Source = if (compact) trace.CompactTrace else trace.Trace;
        const Component = if (compact) adapter.CompactComponent else adapter.Component;
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, source: *const Source, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, index: u32, roots: [2]Digest) !Proof {
            try admit(compact, sealed, pins, entries, source.claim, index, roots);
            if (!first.owns_scheme or !source.sealed or !std.meta.eql(first.roots, roots)) return error.UntrustedV5EndpointFirstRound;
            const elements = try endpoint.draw(a, sealed);
            var generated = try endpoint.generate(a, source, &elements);
            defer generated.deinit(a);
            var channel = proofChannel(sealed, source.claim, index, generated.claim);
            var columns: [endpoint.COLUMN_COUNT]Column = undefined;
            for (&columns, generated.columns) |*column, values| column.* = .{ .log_size = source.claim.log_size, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
            const component = Component{ .log_size = source.claim.log_size, .claim = generated.claim, .elements = &elements };
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, first.scheme), .claim = generated.claim };
        }
        /// An open projection claim, never complete memory authority. The
        /// final receiver must fresh-verify the sorted proof under these roots.
        pub fn verifyOpenOwned(a: std.mem.Allocator, received: Proof, claim: memory.Claim, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, index: u32, roots: [2]Digest) !endpoint.Claim {
            var proof = received;
            var owns_endpoint = true;
            defer if (owns_endpoint) proof.deinit(a);
            try admit(compact, sealed, pins, entries, claim, index, roots);
            if (!canonical.secureIsCanonical(&proof.claim.sum) or proof.claim.count > claim.total_rows or claim.total_rows >= core.fields.m31.Modulus or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config)) return error.InvalidV5EndpointProof;
            const first_roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (first_roots.len != 4 or !std.meta.eql(first_roots[0..2].*, roots)) return error.UntrustedV5EndpointFirstRound;
            const elements = try endpoint.draw(a, sealed);
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            var channel = suite.Channel{};
            old.mixStatement(&channel, claim, index);
            try verifier.commit(a, roots[0], &([_]u32{claim.log_size} ** trace.fixed_column_count), &channel);
            try verifier.commit(a, roots[1], &([_]u32{claim.log_size} ** Source.stored_main_columns), &channel);
            channel = proofChannel(sealed, claim, index, proof.claim);
            try verifier.commit(a, first_roots[2], &([_]u32{claim.log_size} ** endpoint.COLUMN_COUNT), &channel);
            const component = Component{ .log_size = claim.log_size, .claim = proof.claim, .elements = &elements };
            const result = proof.claim;
            owns_endpoint = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof.stark);
            return result;
        }
    };
}
fn admit(comptime compact: bool, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, claim: memory.Claim, index: u32, roots: [2]Digest) !void {
    try claim.validate();
    try sealed.require(pins, entries);
    if (std.meta.eql(pins.rw_endpoint_plan_digest, @as(Digest, @splat(0)))) return error.MissingV5EndpointPlan;
    for (entries) |entry| if (entry.family == .memory and entry.index == index) {
        if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, if (compact) @import("block_v5_memory_compact_v1.zig").instanceId(claim, index) else @import("block_v5_memory_batch_receiver_v1.zig").memoryInstanceId(claim, index))) return error.UntrustedV5EndpointMemory;
        return;
    };
    return error.MissingV5EndpointMemory;
}
fn proofChannel(sealed: seal.Sealed, claim: memory.Claim, index: u32, endpoints: endpoint.Claim) suite.Channel {
    var channel = sealed.sharedChannel();
    channel.mixU32s(&.{ 0x42354550, 1 });
    old.mixStatement(&channel, claim, index);
    channel.mixU64(endpoints.count);
    for (endpoints.sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    return channel;
}
