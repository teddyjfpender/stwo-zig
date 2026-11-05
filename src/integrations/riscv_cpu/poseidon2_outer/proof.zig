//! Actual source-owned five-component CPU STARK with P2 v2 Merkle AND FS.
//! Reference security parameters only; no Ethereum/default/GPU promotion.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const A = @import("authority.zig");
const W = @import("witness.zig");
const C = @import("context.zig");
const P2 = @import("component.zig").Component;
const Legacy = @import("stwo_circuit_cpu_integration").om31.component.Component;
const O = A.O;
const Q = A.Q;
const M = A.M;
const MC = A.MC;
const H = A.H;
const Channel = MC.Channel;
const Air = Core.air.components.ForField(O);
const PC = Engine.air.component_prover.ForField(O);
pub const Authority = A.Authority;
pub const Wire = @import("stwo_proof_wire").ForHasher(O, H);
const MAGIC = "STP25G02";
const HEADER = 8 + 32 + 5 * 8 * 4;
fn begin(a: std.mem.Allocator, key: *const Authority, outputs: []const Q) !Channel {
    if (outputs.len != key.n_outputs) return error.InvalidPoseidonOutputCount;
    var channel = Channel.init();
    (try A.config()).mixInto(&channel);
    const words = try a.alloc(u32, 9 + 4 * outputs.len);
    defer a.free(words);
    for (0..8) |i| words[i] = std.mem.readInt(u32, key.identity[4 * i ..][0..4], .little);
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
        component.* = .{ .allocator = a, .captured = &key.bound.components[old], .preprocessed_logs = fixed_logs, .z = elements.z, .alpha = elements.powers[1], .claim = claims[new] };
        try component.validate();
    }
    return out;
}
pub const Mutation = enum { none, x2, x5, port_extension, range_multiplicity, inter_prefix, claim_balanced };
pub fn prove(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q) ![]u8 {
    return proveMutation(a, ctx, key, outputs, .none);
}
/// Falsification harness only: successful proofs still pass the same engine
/// self-check and receiver. No receiver accepts a mutation selector.
pub fn proveMutation(a: std.mem.Allocator, ctx: *const C.Context, key: *const Authority, outputs: []const Q, mutation: Mutation) ![]u8 {
    var main = try W.main(a, ctx, key);
    defer main.deinit();
    switch (mutation) {
        .x2, .x5 => {
            const col = A.MAIN_START[3] + @import("layout.zig").TEMPORARY + @as(usize, @intFromBool(mutation == .x5));
            main.put(col, 0, main.values[col].values[0].add(M.one()));
        },
        .range_multiplicity => main.put(A.MAIN_START[4], 0, main.values[A.MAIN_START[4]].values[0].add(M.one())),
        .port_extension => {
            // Change an unrestricted self-yielding guess to a non-base QM31
            // value, keeping its local add equation valid. Only Var-bus
            // agreement with the dedicated P2 base port can reject this.
            const input_id = key.fixed.values[A.FIXED_START[3]].values[0];
            var found = false;
            for (0..key.rows[1]) |r| if (key.fixed.values[8].values[r].v == input_id.v and key.fixed.values[2].values[r].v == 1) {
                const side: usize = if (key.fixed.values[6].values[r].v == input_id.v and key.fixed.values[7].values[r].v == 0) 0 else if (key.fixed.values[7].values[r].v == input_id.v and key.fixed.values[6].values[r].v == 0) 1 else continue;
                for ([_]usize{ A.MAIN_START[1] + 4 * side + 1, A.MAIN_START[1] + 9 }) |col| main.put(col, r, main.values[col].values[r].add(M.one()));
                found = true;
                break;
            };
            if (!found) return error.PoseidonMutationFixtureMissing;
        },
        else => {},
    }
    var channel = try begin(a, key, outputs);
    var scheme = try A.E.init(a, try A.config());
    var owned = true;
    defer if (owned) scheme.deinit(a);
    try scheme.commit(a, key.fixed.values, &channel);
    if (!std.mem.eql(u8, &scheme.trees.items[0].root(), &key.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    try scheme.commit(a, main.values, &channel);
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    var interaction = try W.interaction(a, key, main.values, outputs, &elements);
    defer interaction.deinit();
    if (mutation == .claim_balanced) {
        interaction.claims[0] = interaction.claims[0].add(O.one());
        interaction.claims[3] = interaction.claims[3].sub(O.one());
        if (!(try W.closure(outputs, interaction.claims, &elements)).isZero()) return error.InvalidPoseidonMutation;
    }
    if (mutation == .inter_prefix) {
        const col = A.INTER_START[3] + 23 * 8;
        @constCast(interaction.columns[col].values)[5] = interaction.columns[col].values[5].add(M.one());
    }
    channel.mixFelts(&interaction.claims);
    try scheme.commit(a, interaction.columns, &channel);
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const ls = try legacy(a, key, elements, interaction.claims, fixed_logs);
    const p2 = P2{ .key = key, .elements = elements, .claim = interaction.claims[3] };
    const components = [_]PC.ComponentProver{ ls[0].asProverComponent(), ls[1].asProverComponent(), ls[2].asProverComponent(), P2.Adapter.asProverComponent(&p2), ls[3].asProverComponent() };
    owned = false;
    var produced = try A.E.prove(a, &components, &channel, scheme, .{});
    defer produced.deinit(a);
    const body = try Wire.encodeProofBytesBinary(a, produced.proof);
    defer a.free(body);
    const encoded = try a.alloc(u8, HEADER + body.len);
    @memcpy(encoded[0..8], MAGIC);
    @memcpy(encoded[8..40], &key.identity);
    for (interaction.claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |v, j| {
        std.mem.writeInt(u32, encoded[40 + 32 * i + 4 * j ..][0..4], v.v, .little);
    };
    @memcpy(encoded[HEADER..], body);
    return encoded;
}
pub fn verify(a: std.mem.Allocator, key: *const Authority, outputs: []const Q, encoded: []const u8) !void {
    if (encoded.len < HEADER or !std.mem.eql(u8, encoded[0..8], MAGIC)) return error.InvalidPoseidonFiveWire;
    if (!std.mem.eql(u8, encoded[8..40], &key.identity)) return error.InvalidPoseidonFiveAuthority;
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
    if (pcs.commitments.items.len != 4 or !std.meta.eql(pcs.config, try A.config())) return error.InvalidPoseidonFiveShape;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &key.fixed_root)) return error.UntrustedPoseidonFixedCommitment;
    var channel = try begin(a, key, outputs);
    var receiver = try Core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, try A.config());
    defer receiver.deinit(a);
    const fixed_logs = try key.treeLogs(a, 0);
    defer a.free(fixed_logs);
    const main_logs = try key.treeLogs(a, 1);
    defer a.free(main_logs);
    const inter_logs = try key.treeLogs(a, 2);
    defer a.free(inter_logs);
    try receiver.commit(a, key.fixed_root, fixed_logs, &channel);
    try receiver.commit(a, pcs.commitments.items[1], main_logs, &channel);
    const elements = W.Elements.init(channel.drawSecureFelt(), channel.drawSecureFelt());
    if (!(try W.closure(outputs, claims, &elements)).isZero()) return error.PoseidonGlobalLookupSum;
    channel.mixFelts(&claims);
    try receiver.commit(a, pcs.commitments.items[2], inter_logs, &channel);
    const ls = try legacy(a, key, elements, claims, fixed_logs);
    const p2 = P2{ .key = key, .elements = elements, .claim = claims[3] };
    const components = [_]Air.Component{ ls[0].asVerifierComponent(), ls[1].asVerifierComponent(), ls[2].asVerifierComponent(), P2.Adapter.asVerifierComponent(&p2), ls[3].asVerifierComponent() };
    owned = false;
    try Core.verifier.ForField(O).verify(H, MC, a, &components, &channel, &receiver, proof);
}
pub fn fixture(a: std.mem.Allocator, trace_only: bool) !C.Context {
    var ctx = if (trace_only) try C.Context.initTraceOnly(a, 1) else try C.Context.init(a, 1);
    errdefer ctx.deinit();
    var inputs: [24]C.Var = undefined;
    for (&inputs, 0..) |*v, i| v.* = try ctx.algebra().guess(Q.fromU32Unchecked(@intCast(137 + i * 41), 0, 0, 0));
    const result = try ctx.permute(inputs);
    var second_input = result;
    second_input[0] = result[7];
    second_input[1] = result[7];
    const second = try ctx.permute(second_input);
    const twice = try ctx.algebra().add(second[7], result[7]);
    const product = try ctx.algebra().mul(twice, inputs[3]);
    const raw = if (trace_only) @as(u32, 0) else ctx.base.get(result[2]).toM31Array()[0].v;
    const u32var = try ctx.algebra().newVar(Q.fromU32Unchecked(raw & 65535, raw >> 16, 0, 0));
    try ctx.algebra().m31ToU32Into(result[2], u32var);
    try ctx.setOutputs(&.{product});
    try ctx.finalize();
    return ctx;
}
test "five-roster source authority, cumulative Var bus and range closure prove and fresh verify real P2 v2 STARK" {
    const a = std.testing.allocator;
    var ctx = try fixture(a, false);
    defer ctx.deinit();
    var key = try Authority.init(a, &ctx);
    defer key.deinit();
    const output = ctx.base.get(.{ .idx = 3 });
    const encoded = try prove(a, &ctx, &key, &.{output});
    defer a.free(encoded);
    var source = try fixture(a, true);
    defer source.deinit();
    var receiver_key = try Authority.init(a, &source);
    defer receiver_key.deinit();
    try std.testing.expectEqualSlices(u8, &key.identity, &receiver_key.identity);
    try verify(a, &receiver_key, &.{output}, encoded);
    try std.testing.expectError(error.PoseidonGlobalLookupSum, verify(a, &receiver_key, &.{output.add(Q.one())}, encoded));
    const bad = try a.dupe(u8, encoded);
    defer a.free(bad);
    bad[40] ^= 1;
    try std.testing.expectError(error.PoseidonGlobalLookupSum, verify(a, &receiver_key, &.{output}, bad));
    std.debug.print("\nP2_FIVE_REAL_STARK bytes={} mass={} vars={} rows={any} v2=true fresh_source=true\n", .{ encoded.len, key.gather_mass, key.original_vars, key.rows });
}
