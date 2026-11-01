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
pub const Components = struct {
    items: [3]Role.Component,
    pub fn init(truth: R.Truth, local: TF.ChallengesFor(O), shared: Manifest.Shared, claims: []const O) !Components {
        if (claims.len != 5) return error.InvalidWideTruthClaims;
        for (claims) |v| for (v.toM31Array()) |c| {
            if (c.v >= core.fields.m31.Modulus) return error.NoncanonicalWideTruthClaim;
        };
        if (!claims[0].add(claims[1]).add(claims[2]).isZero()) return error.UnclosedWideTruthLocalClaims;
        var out: Components = undefined;
        switch (truth) {
            .keccak => |t| {
                out.items = .{ .{ .kind = .keccak, .log_size = t.setup.log, .calls = t.calls, .first_id = t.first_id, .local = local, .shared = shared, .claim = claims[0], .global_claim = claims[3] }, .{ .kind = .chi, .log_size = 13, .local = local, .shared = shared, .claim = claims[1] }, .{ .kind = .xor5, .log_size = 10, .local = local, .shared = shared, .claim = claims[2] } };
                if (!claims[4].isZero()) return error.NonzeroAbsentWideTruthClaim;
            },
            .secp => |t| {
                const p = A.crypto.secp256k1.program.get(t.setup.kind);
                const policy = @TypeOf(t.setup.*).byte_policy;
                out.items = .{ .{ .kind = .product, .log_size = t.setup.logs[0], .calls = t.calls, .first_id = t.first_id, .program = p, .byte_policy = policy, .local = local, .shared = shared, .claim = claims[0], .global_claim = claims[3] }, .{ .kind = .linear, .log_size = t.setup.logs[1], .calls = t.calls, .first_id = t.first_id, .program = p, .byte_policy = policy, .local = local, .shared = shared, .claim = claims[1], .global_claim = claims[4] }, .{ .kind = .bytes, .log_size = 8, .local = local, .shared = shared, .claim = claims[2] } };
            },
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
