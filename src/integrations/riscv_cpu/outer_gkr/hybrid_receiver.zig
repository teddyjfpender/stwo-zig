//! Fresh native receiver for the cyclic-Eq hybrid outer proof. This API is
//! separate from the production M6 wire codec. It never accepts an AIR, class,
//! terminal target, Eq auxiliary or interaction layout supplied by a prover.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const P = @import("profile.zig");
const S = @import("section.zig");
const H = @import("hybrid_air.zig");
const HC = @import("hybrid_component.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
pub const Key = struct {
    allocator: std.mem.Allocator,
    source: *const Outer.prove.Authority,
    class: P.Class,
    instances: []P.Instance,
    artifacts: []H.Artifact,
    identity: [32]u8,
    config: Outer.protocol.PcsConfig,
    /// Source is rebuilt by the receiver's ordinary pinned Authority path, never
    /// decoded from proof material. The source and its PP outlive this key.
    pub fn init(a: std.mem.Allocator, source: *const Outer.prove.Authority, outer_proofs: u64) !Key {
        if (source.bound.components.len != P.N_COMPONENTS) return error.InvalidHybridGeometry;
        for (source.bound.components, source.logs.toArray(), 0..) |component, log, i| {
            if (component.trace_log_size != log or component.evaluation_log_size != log + 1 or !std.mem.eql(u8, component.label, @tagName(@as(P.Component, @enumFromInt(i))))) return error.InvalidHybridGeometry;
        }
        var logs: [P.N_COMPONENTS]u8 = undefined;
        for (&logs, source.logs.toArray()) |*v, log| v.* = std.math.cast(u8, log) orelse return error.InvalidHybridGeometry;
        const instances = try a.alloc(P.Instance, 8);
        errdefer a.free(instances);
        const roster = try P.instancesFor(logs, instances);
        if (roster.len != instances.len) return error.InvalidHybridGeometry;
        const class = P.Class{ .id = 0x4d370002, .name = "source-derived-outer-gkr-v2", .row_logs = logs, .instances = instances, .binding_version = .cyclic_eq_v2 };
        try class.validate();
        try P.requireSecurityWithSource(class, outer_proofs, source.pp.n_outputs);
        const artifacts = try a.alloc(H.Artifact, P.N_COMPONENTS);
        errdefer a.free(artifacts);
        var made: usize = 0;
        errdefer for (artifacts[0..made]) |*artifact| artifact.deinit();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/rv64/hybrid-outer-proof/eq-cyclic-v2\x00");
        hash.update(&source.identity);
        var words: [12 + P.MAX_INSTANCES]u32 = undefined;
        for (try class.header(&words)) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hash.update(&bytes);
        }
        for (artifacts, source.bound.components, 0..) |*artifact, *captured, i| {
            artifact.* = try H.record(a, captured, @enumFromInt(i));
            made += 1;
            hash.update(&artifact.program.identity);
        }
        return .{ .allocator = a, .source = source, .class = class, .instances = instances, .artifacts = artifacts, .identity = hash.finalResult(), .config = Outer.protocol.active().config() };
    }
    pub fn deinit(self: *@This()) void {
        for (self.artifacts) |*artifact| artifact.deinit();
        self.allocator.free(self.artifacts);
        self.allocator.free(self.instances);
        self.* = undefined;
    }
    pub fn begin(self: *const @This(), a: std.mem.Allocator, outputs: []const Outer.protocol.Q) !Outer.protocol.Channel {
        if (outputs.len != self.source.pp.n_outputs) return error.InvalidOm31CircuitOutputCount;
        var channel = Outer.protocol.Channel.init();
        self.config.mixInto(&channel);
        Outer.protocol.mixProfile(&channel);
        const words = try a.alloc(u32, 9 + 4 * outputs.len);
        defer a.free(words);
        for (0..8) |i| words[i] = std.mem.readInt(u32, self.identity[4 * i ..][0..4], .little);
        words[8] = @intCast(outputs.len);
        for (outputs, 0..) |output, i| for (output.toM31Array(), 0..) |coordinate, j| {
            words[9 + 4 * i + j] = coordinate.v;
        };
        channel.mixU32s(words);
        return channel;
    }

    pub fn interLogs(self: *const @This(), a: std.mem.Allocator) ![]u32 {
        const logs = try a.alloc(u32, H.interactionColumns());
        for (0..P.N_COMPONENTS) |i| {
            const kind: P.Component = @enumFromInt(i);
            @memset(logs[H.interactionStart(kind)..][0..H.interactionWidth(kind)], self.class.row_logs[i]);
        }
        return logs;
    }
    /// Only a complete STARK+GKR verification publishes a capture. The section's
    /// class pointer is replaced by this key's independently derived class.
    pub fn verify(self: *const @This(), a: std.mem.Allocator, outputs: []const Outer.protocol.Q, claims: Outer.witness.Claims, section: *const S.Section, proof: *const Outer.protocol.Proof) !Outer.prove.Capture {
        const pcs = &proof.commitment_scheme_proof;
        if (pcs.commitments.items.len != 4 or !std.meta.eql(pcs.config, self.config)) return error.InvalidHybridProof;
        if (!std.mem.eql(u8, &pcs.commitments.items[0], &self.source.fixedRoot())) return error.InvalidHybridFixedRoot;
        var channel = try self.begin(a, outputs);
        const V = core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(Outer.protocol.H, Outer.protocol.MC);
        var receiver = try V.init(a, self.config);
        defer receiver.deinit(a);
        try receiver.commit(a, self.source.fixedRoot(), &self.source.fixed_logs, &channel);
        const main_logs = try self.source.treeLogs(a, 1);
        defer a.free(main_logs);
        try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
        const elements = Outer.prove.draw(&channel);
        const all_claims = claims.toArray();
        for (all_claims, 0..) |claim, i| if (P.gkrBound(@enumFromInt(i)) and !claim.isZero()) return error.InvalidHybridClassicClaim;
        channel.mixFelts(&all_claims);
        const own_section = S.Section{ .class = &self.class, .salt = section.salt, .proof = section.proof };
        var verified = try S.verify(a, &channel, &own_section);
        defer verified.deinit(a);
        var strict = S.StrictChannel{ .inner = channel };
        const challenges = Legacy.drawChallenges(&strict, self.class.instances.len);
        if (strict.rejected) return error.OuterGkrDrawRejected;
        channel = strict.inner;
        try S.requireClosure(&verified, try Outer.witness.lookupSum(outputs, claims, &Outer.witness.Elements.init(elements.z, elements.alpha)));
        const inter_logs = try self.interLogs(a);
        defer a.free(inter_logs);
        try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
        var bound: [P.N_COMPONENTS]HC.Component = undefined;
        var components: [P.N_COMPONENTS]core.air.components.ForField(O).Component = undefined;
        var made: usize = 0;
        defer for (bound[0..made]) |component| a.free(component.parameters);
        for (&bound, &components, self.artifacts, self.source.bound.components, all_claims) |*component, *out, *artifact, *captured, claim| {
            const parameters = try artifact.parameters(a, captured, elements.z, elements.alpha, &self.class, &verified, &challenges, claim);
            component.* = .{ .allocator = a, .source = captured, .artifact = artifact, .fixed_logs = &self.source.fixed_logs, .class = &self.class, .verified = &verified, .parameters = parameters };
            made += 1;
            out.* = component.asVerifierComponent();
        }
        var capture: Outer.prove.Capture = undefined;
        try core.verifier.ForField(O).verifyBorrowedWithProofCapture(Outer.protocol.H, Outer.protocol.MC, a, &components, &channel, &receiver, proof, &capture);
        return capture;
    }
};
