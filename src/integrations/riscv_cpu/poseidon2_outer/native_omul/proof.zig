//! Explicit R6 source-owned six-component CPU STARK, retaining the R5 control.
//! Reference security parameters only; no Ethereum/default/GPU promotion.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const K = @import("authority.zig");
const Mul = @import("component.zig").Component;
const W = @import("witness.zig");
const C = @import("../context.zig");
const P2 = @import("../component.zig").Component;
const Legacy = @import("stwo_circuit_cpu_integration").om31.component.Component;
const O = A.O;
const Q = A.Q;
const M = A.M;
const MC = A.MC;
const H = A.H;
const Channel = MC.Channel;
const Air = Core.air.components.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
pub const Authority = K.Key;
pub const Wire = @import("stwo_proof_wire").ForHasher(O, H);
const MAGIC = "STP26G01";
const HEADER = 8 + 32 + 6 * 8 * 4;
fn begin(a: std.mem.Allocator, key: *const Authority, outputs: []const Q) !Channel {
    if (outputs.len != key.base.n_outputs) return error.InvalidPoseidonOutputCount;
    var channel = Channel.init();
    key.base.profile.config().mixInto(&channel);
    const words = try a.alloc(u32, 9 + 4 * outputs.len);
    defer a.free(words);
    for (0..8) |i| words[i] = std.mem.readInt(u32, key.base.identity[4 * i ..][0..4], .little);
    words[8] = @intCast(outputs.len);
    for (outputs, 0..) |output, i| for (output.toM31Array(), 0..) |v, j| {
        words[9 + 4 * i + j] = v.v;
    };
    channel.mixU32s(words);
    return channel;
}
fn legacy(a: std.mem.Allocator, key: *const Authority, elements: W.Elements, claims: W.Claims, fixed_logs: []const u32) ![4]Legacy {
    var out: [4]Legacy = undefined;
    for (&out, A.OLD_SLOTS, A.NEW_SLOTS) |*component, old, new| {
        component.* = .{ .allocator = a, .captured = &key.base.bound.components[old], .preprocessed_logs = fixed_logs, .z = elements.z, .alpha = elements.powers[1], .claim = claims[new] };
        try component.validate();
    }
    return out;
}
pub fn proveFullStorageControl(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q) ![]u8 {
    return proveRecorded(a, ctx, key, outputs, .none, null, false);
}
pub const Mutation = enum { none, x2, x5, port_extension, range_multiplicity, inter_prefix, claim_balanced, native_result, native_prefix };
pub fn prove(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q) ![]u8 {
    return proveMutation(a, ctx, key, outputs, .none);
}
pub fn proveProfiled(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q, recorder: *Engine.stage_profile.Recorder) ![]u8 {
    return proveRecorded(a, ctx, key, outputs, .none, recorder, true);
}
/// Falsification harness only: successful proofs still pass the same engine
/// self-check and receiver. No receiver accepts a mutation selector.
pub fn proveMutation(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q, mutation: Mutation) ![]u8 {
    return proveRecorded(a, ctx, key, outputs, mutation, null, true);
}
fn proveRecorded(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q, mutation: Mutation, recorder: ?*Engine.stage_profile.Recorder, compact: bool) ![]u8 {
    // A verifier-only authority has deliberately released its witness data.
    // Reject it before witness generation, including monolithic controls.
    if (key.base.fixed_tree == null or key.base.fixed.values.len != K.FIXED_COUNT or key.base.usage.len == 0) return error.PoseidonProverDataNotRetained;
    var main = blk: {
        var span = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.main_generation", "P2 MAIN generation");
        defer span.end();
        break :blk try W.main(a, ctx, key);
    };
    defer main.deinit();
    switch (mutation) {
        .x2, .x5 => {
            const col = A.MAIN_START[3] + @import("../layout.zig").TEMPORARY + @as(usize, @intFromBool(mutation == .x5));
            main.put(col, 0, main.values[col].values[0].add(M.one()));
        },
        .native_result => main.put(K.MAIN_START + 20, 0, main.values[K.MAIN_START + 20].values[0].add(M.one())),
        .range_multiplicity => main.put(A.MAIN_START[4], 0, main.values[A.MAIN_START[4]].values[0].add(M.one())),
        .port_extension => {
            // Change an unrestricted self-yielding guess to a non-base QM31
            // value, keeping its local add equation valid. Only Var-bus
            // agreement with the dedicated P2 base port can reject this.
            const input_id = key.base.fixed.values[A.FIXED_START[3]].values[0];
            var found = false;
            for (0..key.base.rows[1]) |r| if (key.base.fixed.values[8].values[r].v == input_id.v and key.base.fixed.values[2].values[r].v == 1) {
                const side: usize = if (key.base.fixed.values[6].values[r].v == input_id.v and key.base.fixed.values[7].values[r].v == 0) 0 else if (key.base.fixed.values[7].values[r].v == input_id.v and key.base.fixed.values[6].values[r].v == 0) 1 else continue;
                for ([_]usize{ A.MAIN_START[1] + 4 * side + 1, A.MAIN_START[1] + 9 }) |col| main.put(col, r, main.values[col].values[r].add(M.one()));
                found = true;
                break;
            };
            if (!found) return error.PoseidonMutationFixtureMissing;
        },
        else => {},
    }
    var channel = try begin(a, key, outputs);
    var scheme = try A.E.init(a, key.base.profile.config());
    scheme.reuse_bounded_merkle_tail = true;
    if (compact) scheme.setCompactPolynomialStorage(1);
    var owned = true;
    defer if (owned) scheme.deinit(a);
    const control = try @import("../op_profile.zig").monolithicControl();
    var main_commit = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.main_commit", "P2 MAIN commitment");
    defer main_commit.end();
    if (control) {
        try scheme.commit(a, key.base.fixed.values, &channel);
        try scheme.commit(a, main.values, &channel);
    } else {
        // Immutable FIXED was constructed once by independently derived key.
        try scheme.trees.ensureUnusedCapacity(a, 1);
        scheme.trees.appendAssumeCapacity((key.base.fixed_tree orelse return error.PoseidonProverDataNotRetained).retainShared());
        MC.mixRoot(&channel, key.base.fixed_root);
        // Absorb native-height prefixes once rather than flat-rehashing the
        // entire roster at its largest range-table height.
        try scheme.commitBorrowedStreamingWithRecorder(a, main.values, 64, recorder, &channel);
    }
    main_commit.end();
    if (!std.mem.eql(u8, &scheme.trees.items[0].root(), &key.base.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    var interaction = blk: {
        var span = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.interaction_generation", "P2 interaction generation");
        defer span.end();
        break :blk try W.interaction(a, key, main.values, outputs, &elements);
    };
    defer interaction.deinit();
    if (mutation == .claim_balanced) {
        interaction.claims[0] = interaction.claims[0].add(O.one());
        interaction.claims[5] = interaction.claims[5].sub(O.one());
        if (!(try W.closure(outputs, interaction.claims, &elements)).isZero()) return error.InvalidPoseidonMutation;
    }
    if (mutation == .inter_prefix) {
        const col = A.INTER_START[3] + 23 * 8;
        @constCast(interaction.columns[col].values)[5] = interaction.columns[col].values[5].add(M.one());
    }
    if (mutation == .native_prefix) @constCast(interaction.columns[K.INTER_START + 16].values)[5] = interaction.columns[K.INTER_START + 16].values[5].add(M.one());
    channel.mixFelts(&interaction.claims);
    {
        var span = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.interaction_commit", "P2 interaction commitment");
        defer span.end();
        if (control) try scheme.commit(a, interaction.columns, &channel) else try scheme.commitBorrowedStreamingWithRecorder(a, interaction.columns, 64, recorder, &channel);
    }
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const ls = try legacy(a, key, elements, interaction.claims, fixed_logs);
    const p2 = P2{ .key = &key.base, .elements = elements, .claim = interaction.claims[3] };
    const native_mul = Mul{ .key = key, .elements = elements, .claim = interaction.claims[5] };
    const components = [_]PC.ComponentProver{ ls[0].asProverComponent(), ls[1].asProverComponent(), ls[2].asProverComponent(), @import("p2_domain.zig").adapter(&p2), ls[3].asProverComponent(), Mul.Adapter.asProverComponent(&native_mul) };
    owned = false;
    var produced = try A.E.prove(a, &components, &channel, scheme, .{ .recorder = recorder });
    defer produced.deinit(a);
    const body = try Wire.encodeProofBytesBinary(a, produced.proof);
    defer a.free(body);
    const encoded = try a.alloc(u8, HEADER + body.len);
    @memcpy(encoded[0..8], MAGIC);
    @memcpy(encoded[8..40], &key.base.identity);
    for (interaction.claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |v, j| {
        std.mem.writeInt(u32, encoded[40 + 32 * i + 4 * j ..][0..4], v.v, .little);
    };
    @memcpy(encoded[HEADER..], body);
    return encoded;
}
pub const NativeProof = Core.proof.ForField(O).StarkProof(H);
pub const NativeCapture = Core.pcs.ForField(O).verifier.VerifiedProofCapture(H);
pub const Captured = struct {
    proof: NativeProof,
    claims: W.Claims,
    capture: NativeCapture,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.proof.deinit(a);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, key: *const Authority, outputs: []const Q, encoded: []const u8) !void {
    return verifyImpl(a, key, outputs, encoded, null, null, null);
}
/// Captures only after the same full native receiver has admitted source
/// authority, canonical claims, global Var/range closure and the complete PCS.
pub fn verifyCaptured(a: std.mem.Allocator, key: *const Authority, outputs: []const Q, encoded: []const u8) !Captured {
    var out: Captured = undefined;
    try verifyImpl(a, key, outputs, encoded, &out.capture, &out.proof, &out.claims);
    return out;
}
fn verifyImpl(a: std.mem.Allocator, key: *const Authority, outputs: []const Q, encoded: []const u8, capture: ?*NativeCapture, retained: ?*NativeProof, retained_claims: ?*W.Claims) !void {
    if (encoded.len < HEADER or !std.mem.eql(u8, encoded[0..8], MAGIC)) return error.InvalidNativeOmulWire;
    if (!std.mem.eql(u8, encoded[8..40], &key.base.identity)) return error.InvalidNativeOmulAuthority;
    var claims: W.Claims = undefined;
    for (&claims, 0..) |*claim, i| {
        var coordinates: [8]M = undefined;
        for (&coordinates, 0..) |*v, j| {
            const raw = std.mem.readInt(u32, encoded[40 + 32 * i + 4 * j ..][0..4], .little);
            if (raw >= Core.fields.m31.Modulus) return error.NoncanonicalPoseidonClaim;
            v.* = M.fromCanonical(raw);
        }
        claim.* = O.fromM31Array(coordinates);
    }
    var proof = try Wire.decodeProofBytesBinary(a, encoded[HEADER..]);
    var owned = true;
    defer if (owned) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (pcs.commitments.items.len != 4 or pcs.revision_config != null or !std.meta.eql(pcs.config, key.base.profile.config())) return error.InvalidNativeOmulShape;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.base.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    var channel = try begin(a, key, outputs);
    var receiver = try Core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, key.base.profile.config());
    defer receiver.deinit(a);
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, key.base.fixed_root, fixed_logs, &channel);
    try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    if (!(try W.closure(outputs, claims, &elements)).isZero()) return error.PoseidonGlobalLookupSum;
    channel.mixFelts(&claims);
    try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
    const ls = try legacy(a, key, elements, claims, fixed_logs);
    const p2 = P2{ .key = &key.base, .elements = elements, .claim = claims[3] };
    const native_mul = Mul{ .key = key, .elements = elements, .claim = claims[5] };
    const components = [_]Air.Component{ ls[0].asVerifierComponent(), ls[1].asVerifierComponent(), ls[2].asVerifierComponent(), P2.Adapter.asVerifierComponent(&p2), ls[3].asVerifierComponent(), Mul.Adapter.asVerifierComponent(&native_mul) };
    if (capture) |captured| {
        try Core.verifier.ForField(O).verifyBorrowedWithProofCapture(H, MC, a, &components, &channel, &receiver, &proof, captured);
        retained.?.* = proof;
        retained_claims.?.* = claims;
        owned = false;
    } else {
        owned = false;
        try Core.verifier.ForField(O).verify(H, MC, a, &components, &channel, &receiver, proof);
    }
}
