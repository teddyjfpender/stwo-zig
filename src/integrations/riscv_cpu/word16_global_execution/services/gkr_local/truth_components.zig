//! Independent geometry for three classic truth roles under one sealed MAIN.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const R = @import("../roster.zig");
const Role = @import("truth_role.zig");
const TF = @import("truth_fractions.zig");
const Manifest = @import("manifest.zig");
/// Pure declaration geometry, also used before any fixed key is constructed.
/// Programs/table policies are receiver-owned; no claim or challenge is needed.
pub fn shapesForDeclaration(d: @import("../wire.zig").TruthDeclaration) ![3]Role.Shape {
    return switch (d.family) {
        .keccak => blk: {
            try A.crypto.keccak.layout.validateGeometry(d.calls, d.first_id, d.logs[0]);
            break :blk .{ .{ .kind = .keccak, .log_size = d.logs[0] }, .{ .kind = .chi, .log_size = 13 }, .{ .kind = .xor5, .log_size = 10 } };
        },
        .add, .double => blk: {
            const kind: A.crypto.secp256k1.program.Kind = if (d.family == .add) .add else .double;
            const program = A.crypto.secp256k1.program.get(kind);
            try A.crypto.secp256k1.layout.validate(.product, program, d.calls, d.first_id, d.logs[0]);
            try A.crypto.secp256k1.layout.validate(.linear, program, d.calls, d.first_id, d.logs[1]);
            const policy = @import("../../secp/roster.zig").TruthSetup.byte_policy;
            break :blk .{ .{ .kind = .product, .log_size = d.logs[0], .byte_policy = policy }, .{ .kind = .linear, .log_size = d.logs[1], .byte_policy = policy }, .{ .kind = .bytes, .log_size = 8 } };
        },
    };
}
pub const Components = struct {
    items: [3]Role.Component,
    pub fn init(truth: R.Truth, local: TF.ChallengesFor(O), shared: Manifest.Shared, claims: []const O) !Components {
        if (claims.len != 5) return error.InvalidWideTruthClaims;
        for (claims) |v| for (v.toM31Array()) |c| {
            if (c.v >= core.fields.m31.Modulus) return error.NoncanonicalWideTruthClaim;
        };
        if (!claims[0].add(claims[1]).add(claims[2]).isZero()) return error.UnclosedWideTruthLocalClaims;
        var out: Components = undefined;
        const descriptor = try shapesForDeclaration(@import("../wire.zig").TruthDeclaration.from(truth));
        if (truth == .keccak and !claims[4].isZero()) return error.NonzeroAbsentWideTruthClaim;
        for (descriptor, &out.items, 0..) |shape, *item, i| {
            const crypto_role = shape.kind == .keccak or shape.kind == .product or shape.kind == .linear;
            item.* = .{ .kind = shape.kind, .log_size = shape.log_size, .calls = if (crypto_role) truth.count() else 0, .first_id = if (crypto_role) truth.first() else 1, .program = if (shape.kind == .product or shape.kind == .linear) A.crypto.secp256k1.program.get(truth.secp.setup.kind) else null, .byte_policy = shape.byte_policy, .local = local, .shared = shared, .claim = claims[i], .global_claim = if (i == 0) claims[3] else if (i == 1 and truth == .secp) claims[4] else O.zero() };
        }
        var offsets: [3]usize = .{ 0, 0, 0 };
        for (&out.items) |*c| {
            c.offsets = offsets;
            c.split = if (truth == .keccak) 2 else 1;
            try c.validate();
            for (c.widths(), 0..) |w, t| offsets[t] += w;
        }
        return out;
    }
    pub fn logs(self: *const Components, a: std.mem.Allocator, tree: usize) ![]u32 {
        var count: usize = 0;
        for (self.items) |c| count += c.widths()[tree];
        const out = try a.alloc(u32, count);
        var at: usize = 0;
        for (self.items) |c| {
            const w = c.widths()[tree];
            @memset(out[at..][0..w], c.log_size);
            at += w;
        }
        return out;
    }
    pub fn provers(self: *const Components) [3]engine.air.component_prover.ForField(O).ComponentProver {
        return .{ self.items[0].asProverComponent(), self.items[1].asProverComponent(), self.items[2].asProverComponent() };
    }
    pub fn verifiers(self: *const Components) [3]core.air.components.ForField(O).Component {
        return .{ self.items[0].asVerifierComponent(), self.items[1].asVerifierComponent(), self.items[2].asVerifierComponent() };
    }
};
