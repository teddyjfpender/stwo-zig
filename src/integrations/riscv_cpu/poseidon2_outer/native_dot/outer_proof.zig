//! Explicit R7 seven-role shared-Var CPU STARK; no R5/R6 acceptance path.
//! Reference security parameters only; no Ethereum/default/GPU promotion.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("../authority.zig");
const K = @import("outer_authority.zig");
const Mul = @import("../native_omul/component.zig").Component;
const W = @import("outer_witness.zig");
const Dot = @import("outer_component.zig").Component;
const DotRow = @import("row.zig");
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
const MAGIC = "STP27D01";
pub const HEADER_BYTES = 8 + 32 + 7 * 8 * 4;
const HEADER = HEADER_BYTES;
fn begin(a: std.mem.Allocator, key: *const Authority, outputs: []const Q) !Channel {
    if (outputs.len != key.core.base.n_outputs) return error.InvalidPoseidonOutputCount;
    var channel = Channel.init();
    key.core.base.profile.config().mixInto(&channel);
    const words = try a.alloc(u32, 9 + 4 * outputs.len);
    defer a.free(words);
    for (0..8) |i| words[i] = std.mem.readInt(u32, key.core.base.identity[4 * i ..][0..4], .little);
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
        component.* = .{ .allocator = a, .captured = &key.core.base.bound.components[old], .preprocessed_logs = fixed_logs, .z = elements.z, .alpha = elements.powers[1], .claim = claims[new] };
        try component.validate();
    }
    return out;
}
pub fn proveFullStorageControl(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q) ![]u8 {
    return proveRecorded(a, ctx, key, outputs, .none, null, false);
}
pub const Mutation = enum { none, x2, x5, port_extension, range_multiplicity, inter_prefix, claim_balanced, native_result, native_prefix, dot_accumulator, dot_weight, dot_scalar, dot_prefix, dot_claim_balanced, dot_reset, dot_empty, omit_dot };
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
    if (!Engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.NativeDotR7BudgetRequired;
    // A verifier-only authority has deliberately released its witness data.
    // Reject it before witness generation, including monolithic controls.
    if (key.core.base.fixed_tree == null or key.core.base.fixed.values.len != K.FIXED_COUNT or key.core.base.usage.len == 0) return error.PoseidonProverDataNotRetained;
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
        .native_result => main.put(K.MUL_MAIN_START + 20, 0, main.values[K.MUL_MAIN_START + 20].values[0].add(M.one())),
        .range_multiplicity => main.put(A.MAIN_START[4], 0, main.values[A.MAIN_START[4]].values[0].add(M.one())),
        .port_extension => {
            // Change an unrestricted self-yielding guess to a non-base QM31
            // value, keeping its local add equation valid. Only Var-bus
            // agreement with the dedicated P2 base port can reject this.
            const input_id = key.core.base.fixed.values[A.FIXED_START[3]].values[0];
            var found = false;
            for (0..key.core.base.rows[1]) |r| if (key.core.base.fixed.values[8].values[r].v == input_id.v and key.core.base.fixed.values[2].values[r].v == 1) {
                const side: usize = if (key.core.base.fixed.values[6].values[r].v == input_id.v and key.core.base.fixed.values[7].values[r].v == 0) 0 else if (key.core.base.fixed.values[7].values[r].v == input_id.v and key.core.base.fixed.values[6].values[r].v == 0) 1 else continue;
                for ([_]usize{ A.MAIN_START[1] + 4 * side + 1, A.MAIN_START[1] + 9 }) |col| main.put(col, r, main.values[col].values[r].add(M.one()));
                found = true;
                break;
            };
            if (!found) return error.PoseidonMutationFixtureMissing;
        },
        .dot_reset => {
            const first = K.physical(0, key.dot_log);
            const row = K.physical(1, key.dot_log);
            // Reset an internal row by subtracting its prior inclusive sum.
            for (0..8) |i| {
                const column = K.MAIN_START + DotRow.ACC + i;
                main.put(column, row, main.values[column].values[row].sub(main.values[column].values[first]));
            }
        },
        .dot_empty => {
            const row = K.physical(key.dot_raw - 1, key.dot_log);
            const column = K.MAIN_START + DotRow.ACC;
            main.put(column, row, main.values[column].values[row].add(M.one()));
        },
        .dot_accumulator, .dot_weight, .dot_scalar, .omit_dot => {
            const column = K.MAIN_START + @as(usize, switch (mutation) {
                .dot_accumulator, .omit_dot => DotRow.ACC,
                .dot_weight => 0,
                .dot_scalar => 8,
                else => unreachable,
            });
            const row = K.physical(1, key.dot_log);
            main.put(column, row, main.values[column].values[row].add(M.one()));
        },
        else => {},
    }
    var channel = try begin(a, key, outputs);
    var scheme = try A.E.init(a, key.core.base.profile.config());
    scheme.reuse_bounded_merkle_tail = true;
    if (compact) scheme.setCompactPolynomialStorage(1);
    var owned = true;
    defer if (owned) scheme.deinit(a);
    const control = try @import("../op_profile.zig").monolithicControl();
    var main_commit = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.main_commit", "P2 MAIN commitment");
    defer main_commit.end();
    if (control) {
        try scheme.commit(a, key.core.base.fixed.values, &channel);
        try scheme.commit(a, main.values, &channel);
    } else {
        // Immutable FIXED was constructed once by independently derived key.
        try scheme.trees.ensureUnusedCapacity(a, 1);
        scheme.trees.appendAssumeCapacity((key.core.base.fixed_tree orelse return error.PoseidonProverDataNotRetained).retainShared());
        MC.mixRoot(&channel, key.core.base.fixed_root);
        // Absorb native-height prefixes once rather than flat-rehashing the
        // entire roster at its largest range-table height.
        try scheme.commitBorrowedStreamingWithRecorder(a, main.values, 64, recorder, &channel);
    }
    main_commit.end();
    if (!std.mem.eql(u8, &scheme.trees.items[0].root(), &key.core.base.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    var interaction = blk: {
        var span = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.interaction_generation", "P2 interaction generation");
        defer span.end();
        break :blk try W.interaction(a, key, main.values, outputs, &elements);
    };
    defer interaction.deinit();
    // The PCS owns coefficient storage after MAIN commitment; interaction
    // generation is the final consumer of these raw evaluations. The explicit
    // full-storage control retains them for differential ownership checks.
    if (compact) {
        main.deinit();
        main = .{ .allocator = a, .values = &.{} };
    }
    if (mutation == .claim_balanced) {
        interaction.claims[0] = interaction.claims[0].add(O.one());
        interaction.claims[5] = interaction.claims[5].sub(O.one());
        if (!(try W.closure(outputs, interaction.claims, &elements)).isZero()) return error.InvalidPoseidonMutation;
    }
    if (mutation == .inter_prefix) {
        const col = A.INTER_START[3] + 23 * 8;
        @constCast(interaction.columns[col].values)[5] = interaction.columns[col].values[5].add(M.one());
    }
    if (mutation == .native_prefix) @constCast(interaction.columns[K.MUL_INTER_START + 16].values)[5] = interaction.columns[K.MUL_INTER_START + 16].values[5].add(M.one());
    if (mutation == .dot_prefix) {
        const column = K.INTER_START + 16;
        const row = K.physical(1, key.dot_log);
        @constCast(interaction.columns[column].values)[row] = interaction.columns[column].values[row].add(M.one());
    }
    if (mutation == .dot_claim_balanced) {
        interaction.claims[0] = interaction.claims[0].add(O.one());
        interaction.claims[6] = interaction.claims[6].sub(O.one());
        if (!(try W.closure(outputs, interaction.claims, &elements)).isZero()) return error.InvalidPoseidonMutation;
    }
    channel.mixFelts(&interaction.claims);
    {
        var span = try Engine.stage_profile.StageScope.begin(recorder, "op_p2.interaction_commit", "P2 interaction commitment");
        defer span.end();
        if (control) try scheme.commit(a, interaction.columns, &channel) else try scheme.commitBorrowedStreamingWithRecorder(a, interaction.columns, 64, recorder, &channel);
    }
    // No component borrows raw INTER evaluations: claims are scalar values and
    // the committed tree retains the polynomials. Keep the deferred owner valid
    // on every later error, without retaining the whole raw witness during FRI.
    if (compact) {
        @import("stwo_circuit_frontend").witness.trace.freeColumns(a, interaction.columns);
        interaction.columns = &.{};
    }
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const ls = try legacy(a, key, elements, interaction.claims, fixed_logs);
    const p2 = P2{ .key = &key.core.base, .elements = elements, .claim = interaction.claims[3] };
    const native_mul = Mul{ .key = &key.core, .elements = elements, .claim = interaction.claims[5] };
    const dot = Dot{ .key = key, .elements = elements, .claim = interaction.claims[6] };
    const components = [_]PC.ComponentProver{ ls[0].asProverComponent(), ls[1].asProverComponent(), ls[2].asProverComponent(), @import("../native_omul/p2_domain.zig").adapter(&p2), ls[3].asProverComponent(), Mul.Adapter.asProverComponent(&native_mul), Dot.Adapter.asProverComponent(&dot) };
    owned = false;
    const selected = if (mutation == .omit_dot) components[0..6] else &components;
    var produced = try A.E.prove(a, selected, &channel, scheme, .{ .recorder = recorder });
    defer produced.deinit(a);
    const body = try Wire.encodeProofBytesBinary(a, produced.proof);
    defer a.free(body);
    const encoded = try a.alloc(u8, HEADER + body.len);
    @memcpy(encoded[0..8], MAGIC);
    @memcpy(encoded[8..40], &key.core.base.identity);
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
    if (encoded.len < HEADER or !std.mem.eql(u8, encoded[0..8], MAGIC)) return error.InvalidNativeDotR7Wire;
    if (!std.mem.eql(u8, encoded[8..40], &key.core.base.identity)) return error.InvalidNativeDotR7Authority;
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
    if (pcs.commitments.items.len != 4 or pcs.revision_config != null or !std.meta.eql(pcs.config, key.core.base.profile.config())) return error.InvalidNativeDotR7Shape;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.core.base.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    var channel = try begin(a, key, outputs);
    var receiver = try Core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, key.core.base.profile.config());
    defer receiver.deinit(a);
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, key.core.base.fixed_root, fixed_logs, &channel);
    try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    if (!(try W.closure(outputs, claims, &elements)).isZero()) return error.PoseidonGlobalLookupSum;
    channel.mixFelts(&claims);
    try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
    const ls = try legacy(a, key, elements, claims, fixed_logs);
    const p2 = P2{ .key = &key.core.base, .elements = elements, .claim = claims[3] };
    const native_mul = Mul{ .key = &key.core, .elements = elements, .claim = claims[5] };
    const dot = Dot{ .key = key, .elements = elements, .claim = claims[6] };
    const components = [_]Air.Component{ ls[0].asVerifierComponent(), ls[1].asVerifierComponent(), ls[2].asVerifierComponent(), P2.Adapter.asVerifierComponent(&p2), ls[3].asVerifierComponent(), Mul.Adapter.asVerifierComponent(&native_mul), Dot.Adapter.asVerifierComponent(&dot) };
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
