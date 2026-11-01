//! Concrete bridge and truth component adapters shared by prover and receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const B = S.word16_bridge;
const K = A.crypto.keccak;
const KB = K.word16_bridge;
const T = @import("types.zig");
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Components = @import("../../word16_execution/components.zig").Components;
const Q = G.Q;
pub const Bridges = struct {
    keccak: ?KB.component.Component = null,
    add: ?B.component.Component = null,
    double: ?B.component.Component = null,
    pub fn init(setup: *const R.CpuSetup, calls: [3]u32, first: [3]u32, ch: G.Old.Draw, common: P.Shared, claims: [3]T.ExtraClaims) Bridges {
        var out = Bridges{};
        for (0..3) |k| {
            const family: T.Family = @enumFromInt(k);
            const log = setup.bridges.at(family) orelse continue;
            const offsets = [3]usize{ setup.offset(family, 0), setup.offset(family, 1), setup.offset(family, 2) };
            if (k == 0) {
                out.keccak = .{ .kind = .bridge, .log_size = log, .rows = calls[0], .first_id = first[0], .offsets = offsets, .claims = claims[0].toK(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
            } else {
                const component = B.component.Component{ .kind = @enumFromInt(k), .log_size = log, .rows = calls[k], .first_id = first[k], .offsets = offsets, .claims = claims[k].toSecp(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
                if (k == 1) out.add = component else out.double = component;
            }
        }
        return out;
    }
    fn count(self: *const Bridges) usize {
        return @intFromBool(self.keccak != null) + @as(usize, @intFromBool(self.add != null)) + @intFromBool(self.double != null);
    }
};
pub fn cpuHandles(a: std.mem.Allocator, base: *const Components, bridges: *const Bridges) ![]engine.air.component_prover.ComponentProver {
    const old = try base.provers(a);
    defer a.free(old);
    const out = try a.alloc(engine.air.component_prover.ComponentProver, old.len + bridges.count());
    @memcpy(out[0..old.len], old);
    var at = old.len;
    inline for (.{ "keccak", "add", "double" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asProverComponent();
        at += 1;
    };
    return out;
}
pub fn cpuVerifierHandles(a: std.mem.Allocator, base: *const Components, bridges: *const Bridges) ![]core.air.components.Component {
    const old = try base.verifiers(a);
    defer a.free(old);
    const out = try a.alloc(core.air.components.Component, old.len + bridges.count());
    @memcpy(out[0..old.len], old);
    var at = old.len;
    inline for (.{ "keccak", "add", "double" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asVerifierComponent();
        at += 1;
    };
    return out;
}
// Reuse the existing policy tag; no protocol/version enum or generic AIR type.
const KeccakTruthComponents = union(K.equations.BatchPolicy) {
    triple_v2: [3]K.component.Component,
    quartet_v3: struct { permutation: K.quartet_component.Component, chi: K.component.Component, xor5: K.component.Component },
    fn init(setup: *const @import("../keccak/shared/roster.zig").TruthSetup, first: u32, calls: u32, ch: K.equations.Challenges, claims: [3]Q) KeccakTruthComponents {
        var base = @import("../keccak/shared/execution.zig").truthComponents(setup, first, calls, ch, claims);
        if (setup.policy == .triple_v2) return .{ .triple_v2 = base };
        base[1].offsets.interaction = setup.policy.interactionCount();
        base[2].offsets.interaction = setup.policy.interactionCount() + 4;
        return .{ .quartet_v3 = .{ .permutation = .{ .base = base[0] }, .chi = base[1], .xor5 = base[2] } };
    }
    fn provers(self: *const KeccakTruthComponents) [3]engine.air.component_prover.ComponentProver {
        return switch (self.*) {
            .triple_v2 => |*c| .{ c[0].asProverComponent(), c[1].asProverComponent(), c[2].asProverComponent() },
            .quartet_v3 => |*c| .{ c.permutation.asProverComponent(), c.chi.asProverComponent(), c.xor5.asProverComponent() },
        };
    }
    fn verifiers(self: *const KeccakTruthComponents) [3]core.air.components.Component {
        return switch (self.*) {
            .triple_v2 => |*c| .{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), c[2].asVerifierComponent() },
            .quartet_v3 => |*c| .{ c.permutation.asVerifierComponent(), c.chi.asVerifierComponent(), c.xor5.asVerifierComponent() },
        };
    }
};
pub const TruthComponents = union(enum) {
    keccak: KeccakTruthComponents,
    secp: @import("../secp/execution.zig").TruthComponents,
    pub fn init(truth: R.Truth, ch: P.TruthDraw, claims: [3]Q) !TruthComponents {
        return switch (truth) {
            .keccak => |t| switch (ch) {
                .keccak => |kc| .{ .keccak = KeccakTruthComponents.init(t.setup, t.first_id, t.calls, kc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
            .secp => |t| switch (ch) {
                .secp => |sc| .{ .secp = @import("../secp/execution.zig").TruthComponents.initSpan(t.setup, t.first_id, t.calls, sc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
        };
    }
    pub fn provers(self: *const TruthComponents) [3]engine.air.component_prover.ComponentProver {
        return switch (self.*) {
            .keccak => |*c| c.provers(),
            .secp => |*c| c.provers(),
        };
    }
    pub fn verifiers(self: *const TruthComponents) [3]core.air.components.Component {
        return switch (self.*) {
            .keccak => |*c| c.verifiers(),
            .secp => |*c| c.verifiers(),
        };
    }
};
