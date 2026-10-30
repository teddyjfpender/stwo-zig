//! Request-local immutable verifier compiler. Admission reconstructs the source
//! policy once; cold key setup and live witness evaluation share its exact
//! kernels and geometry. No captures or main witness values are cached.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Statement = @import("../prover/block_v7_multi_union_statement_v1.zig").ForMode(true);
const Composition = @import("air/block_v7_union_composition_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Public = @import("block_v7_union_public_v1.zig");
const Transcript = @import("air/block_v7_union_transcript_v1.zig");
const ClaimsWire = @import("../prover/block_v7_union_claim_wire_v1.zig");
const Shared = @import("air/blake3_execution_composition.zig");
const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    claims: Multi.Claims,
    claim_digest: [32]u8,
    admission: Profile.Owned.Admission,
    composition: Composition.Compiled,
    deep: Deep.Circuit,
    fri: Fri.Circuit,
    arithmetic: Assembly.Arithmetic,
    values: Public.Values,
    fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.values.deinit();
        self.arithmetic.deinit();
        self.fri.deinit();
        self.deep.deinit();
        self.composition.deinit();
        self.admission.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};
pub const Capsule = opaque {
    pub fn derive(a: std.mem.Allocator, statement: *const Statement.Owned, proposed: *const Multi.Claims, limits: Profile.Limits) !*Capsule {
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const encoded = try encodeClaims(a, proposed);
        defer a.free(encoded);
        std.crypto.hash.sha2.Sha256.hash(encoded, &self.claim_digest, .{});
        var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = encoded };
        var remaining: usize = 1 << 18;
        self.claims = try ClaimsWire.decode(Multi.Claims, self.arena.allocator(), &cursor, &remaining);
        if (cursor.position != encoded.len) return error.NonCanonicalUnionClaimSuffix;
        self.admission = try Profile.Owned.deriveAdmitted(a, statement, &self.claims, limits);
        errdefer self.admission.deinit();
        const admitted_profile = self.admission.profile;
        self.composition = try Composition.compileFromComponents(a, admitted_profile, &self.claims, &self.admission.components);
        errdefer self.composition.deinit();
        self.deep = try Deep.build(a, admitted_profile.shape.deepProfile());
        errdefer self.deep.deinit();
        self.fri = try Fri.build(a, admitted_profile.shape.friProfile());
        errdefer self.fri.deinit();
        self.arithmetic = try Assembly.Arithmetic.init(a, .{ self.composition.circuit.graph(), self.deep.graph(), self.fri.graph() });
        errdefer self.arithmetic.deinit();
        var frame = try Transcript.statementFromComponents(a, admitted_profile, &self.admission.components);
        errdefer frame.deinit();
        const public = try Composition.publicValues(a, admitted_profile, &self.admission.components, &self.claims);
        errdefer a.free(public);
        self.values = .{ .allocator = a, .template = admitted_profile.seal, .statement = frame, .public = public, .roots_count = try Transcript.firstInteraction(admitted_profile) };
        try self.values.validate();
        return @ptrCast(self);
    }
    pub fn compiler(self: *const Capsule) *const Owned {
        return @ptrCast(@alignCast(self));
    }
    pub fn profile(self: *const Capsule) *const Profile.Owned {
        return self.compiler().admission.profile;
    }
    pub fn deinit(self: *Capsule) void {
        const self_owned: *Owned = @ptrCast(@alignCast(self));
        self_owned.deinit();
    }
    pub fn requireCapture(self: *const Capsule, a: std.mem.Allocator, capture: *const Multi.VerifiedCapture) !void {
        const encoded = try encodeClaims(a, &capture.claims);
        defer a.free(encoded);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        const p = self.profile();
        if (!std.meta.eql(digest, self.compiler().claim_digest) or !std.meta.eql(capture.closed.statement, p.policy) or !std.meta.eql(capture.closed.epoch, p.statement.input.epoch.digest) or capture.proof.commitments.len != p.trace_count + 1 or !std.meta.eql(capture.proof.commitments[0], p.fixed_root)) return error.UntrustedUnionCompilerCapture;
    }
    pub fn values(self: *const Capsule, a: std.mem.Allocator) !Public.Values {
        const source = self.compiler().values;
        var frame = try source.statement.clone(a);
        errdefer frame.deinit();
        return .{ .allocator = a, .template = source.template, .roots_count = source.roots_count, .statement = frame, .public = try a.dupe(core.fields.qm31.QM31, source.public) };
    }
    pub fn prepareComposition(self: *const Capsule, a: std.mem.Allocator, capture: *const Multi.VerifiedCapture) !Shared.Prepared {
        try self.requireCapture(a, capture);
        const compiled = &self.compiler().composition;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const t = arena.allocator();
        const p = self.profile();
        var draws: std.ArrayList(core.fields.qm31.QM31) = .empty;
        try draws.appendSlice(t, &try @import("air/block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, p.statement.input.epoch));
        for (p.statement.input.callers) |pin| {
            const caller = try @import("../prover/block_v7_caller_active_source_v1.zig").draw(t, p.statement.input.epoch, try pin.require(t, p.statement.input.epoch, p.statement.input.entries));
            try draws.appendSlice(t, &caller.relations.draws());
        }
        const inputs = try t.alloc(core.fields.qm31.QM31, compiled.sources.len);
        for (inputs, compiled.sources) |*out, source| out.* = switch (source) {
            .sample => |index| if (index < capture.proof.sampled_values.len) capture.proof.sampled_values[index] else return error.InvalidUnionCompositionSamples,
            .public_input => |index| if (index < self.compiler().values.public.len) self.compiler().values.public[index] else return error.InvalidUnionCompositionPublicFrame,
            .challenge => |index| if (index < draws.items.len) draws.items[index] else return error.InvalidUnionCompositionChallenge,
            .composition => capture.proof.composition_randomness,
            .oods => capture.proof.oods_seed,
            else => return error.InvalidUnionCompositionSource,
        };
        const original = &compiled.circuit;
        const nodes = try a.dupe(@TypeOf(original.nodes[0]), original.nodes);
        errdefer a.free(nodes);
        const outputs = try a.dupe(u32, original.outputs);
        errdefer a.free(outputs);
        const circuit = @import("air/composition_graph_recorder.zig").Circuit{ .allocator = a, .nodes = nodes, .outputs = outputs, .input_count = original.input_count, .identity_digest = original.identity_digest };
        const values_out = try t.alloc(core.fields.qm31.QM31, nodes.len);
        try circuit.evaluateInto(inputs, values_out);
        var result = Shared.Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs, .sources = try t.dupe(Shared.Source, compiled.sources), .values = values_out, .key_id = p.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
        result.seal = result.identity();
        return result;
    }
};
fn encodeClaims(a: std.mem.Allocator, claims: *const Multi.Claims) ![]u8 {
    var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, 8 << 20);
    defer writer.deinit();
    var remaining: usize = 1 << 18;
    try ClaimsWire.encode(Multi.Claims, &writer, claims.*, &remaining);
    return writer.bytes.toOwnedSlice(a);
}
