//! Host-only topology census (diagnostic). Never enters a proof, transcript or
//! authority identity. Separates the structural gate graph of a recursive
//! verifier circuit from its interned constant VALUES and its witness-origin
//! shape, so the producer/receiver can see why two nodes have distinct
//! authorities. Callers own any reporting or publication of the returned data.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");

pub const Fingerprint = struct {
    /// All gate lists, outputs and var count. Constants enter only as var ids.
    gates: [32]u8,
    /// Interned constant table, in first-use order (key limbs + var id).
    constants: [32]u8,
    /// Witness-origin kinds and operands (not values).
    origins: [32]u8,
    n_vars: u32,
    n_constants: usize,
    n_origins: usize,
};

fn feed(h: *std.crypto.hash.sha2.Sha256, comptime T: type, items: []const T) void {
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, items.len, .little);
    h.update(&len);
    h.update(std.mem.sliceAsBytes(items));
}

pub fn compute(ctx: *const C.Context) Fingerprint {
    const c = &ctx.circuit;
    var g = std.crypto.hash.sha2.Sha256.init(.{});
    var nv: [4]u8 = undefined;
    std.mem.writeInt(u32, &nv, c.n_vars, .little);
    g.update(&nv);
    feed(&g, circuit.builder.circuit.BinaryGate, c.add.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.sub.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.mul.items);
    feed(&g, circuit.builder.circuit.BinaryGate, c.pointwise_mul.items);
    feed(&g, circuit.builder.circuit.EqGate, c.eq.items);
    feed(&g, circuit.builder.circuit.TripleXorGate, c.triple_xor.items);
    feed(&g, circuit.builder.circuit.M31ToU32Gate, c.m31_to_u32.items);
    feed(&g, circuit.builder.circuit.BlakeGGate, c.blake_g_gate.items);
    feed(&g, u32, c.permutation.ends.items);
    feed(&g, u32, c.permutation.inputs.items);
    feed(&g, u32, c.permutation.outputs.items);
    feed(&g, u32, c.output.items);
    var k = std.crypto.hash.sha2.Sha256.init(.{});
    feed(&k, u128, ctx.constants.keys());
    feed(&k, circuit.builder.Var, ctx.constants.values());
    var o = std.crypto.hash.sha2.Sha256.init(.{});
    var n_origins: usize = 0;
    if (ctx.witness_metadata) |metadata| {
        n_origins = metadata.origins.items.len;
        for (metadata.origins.items) |origin| {
            var buf: [13]u8 = undefined;
            std.mem.writeInt(u32, buf[0..4], origin.out, .little);
            buf[4] = @intFromEnum(origin.kind);
            std.mem.writeInt(u32, buf[5..9], origin.a, .little);
            std.mem.writeInt(u32, buf[9..13], origin.b, .little);
            o.update(&buf);
        }
    }
    return .{ .gates = g.finalResult(), .constants = k.finalResult(), .origins = o.finalResult(), .n_vars = c.n_vars, .n_constants = ctx.constants.count(), .n_origins = n_origins };
}
