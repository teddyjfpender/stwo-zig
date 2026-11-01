//! Concrete bridge and truth component adapters shared by prover and receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const B = S.word16_bridge;
const K = A.crypto.keccak;
const KB = K.word16_bridge;
const BM = A.crypto.bulk_memory;
const KS = A.crypto.keccak_sponge;
pub fn spongeChallenges(ch: G.Old.Draw, common: P.Shared) KS.types.Challenges {
    return .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .and_ = ch.and_, .range16 = ch.memory.range16, .range8 = ch.memory.range8 };
}
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
    sha256: ?B.component.Component = null,
    arith256_mod: ?B.component.Component = null,
    bulk: [3]?BM.component.Component = @splat(null),
    sponge: [2]?KS.component.Component = @splat(null),
    /// Keccak-sponge components share the CPU proof's RAM14, OWNER19, AND and
    /// range challenges and the bundle's Keccak IO11 challenge.
    pub fn withSponge(self: Bridges, setup: *const R.CpuSetup, counts: T.SpongeCounts, ch: G.Old.Draw, common: P.Shared, claims: [2]T.SpongeClaims) Bridges {
        var out = self;
        for (T.sponge_kinds, 0..) |kind, k| {
            const log = setup.bridges.sponge.at(kind) orelse continue;
            out.sponge[k] = .{ .kind = kind, .log_size = log, .rows = counts.rows(kind), .first_id = counts.first_id, .offsets = .{ setup.spongeOffset(kind, 0), setup.spongeOffset(kind, 1), setup.spongeOffset(kind, 2) }, .claims = claims[k], .challenges = spongeChallenges(ch, common) };
        }
        return out;
    }
    /// Bulk-memory components share the CPU proof's RAM14, OWNER19 and U16 challenges.
    pub fn withBulk(self: Bridges, setup: *const R.CpuSetup, counts: T.BulkCounts, ch: G.Old.Draw, claims: [3]T.BulkClaims) Bridges {
        var out = self;
        for (T.bulk_kinds, 0..) |kind, k| {
            const log = setup.bridges.bulk.at(kind) orelse continue;
            out.bulk[k] = .{ .kind = kind, .log_size = log, .rows = counts.rows(kind), .offsets = .{ setup.bulkOffset(kind, 0), setup.bulkOffset(kind, 1), setup.bulkOffset(kind, 2) }, .claims = claims[k], .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .range16 = ch.memory.range16 } };
        }
        return out;
    }
    pub fn init(setup: *const R.CpuSetup, calls: [T.FAMILIES]u32, first: [T.FAMILIES]u32, ch: G.Old.Draw, common: P.Shared, claims: [T.FAMILIES]T.ExtraClaims) Bridges {
        var out = Bridges{};
        for (0..T.FAMILIES) |k| {
            const family: T.Family = @enumFromInt(k);
            const log = setup.bridges.at(family) orelse continue;
            const offsets = [3]usize{ setup.offset(family, 0), setup.offset(family, 1), setup.offset(family, 2) };
            if (k == 0) {
                out.keccak = .{ .kind = .bridge, .log_size = log, .rows = calls[0], .first_id = first[0], .offsets = offsets, .claims = claims[0].toK(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
            } else {
                const component = B.component.Component{ .kind = T.bridgeKind(family), .log_size = log, .rows = calls[k], .first_id = first[k], .offsets = offsets, .claims = claims[k].toSecp(), .challenges = .{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 } };
                switch (family) {
                    .add => out.add = component,
                    .double => out.double = component,
                    .sha256 => out.sha256 = component,
                    .arith256_mod => out.arith256_mod = component,
                    .keccak => unreachable,
                }
            }
        }
        return out;
    }
    fn count(self: *const Bridges) usize {
        var n = @intFromBool(self.keccak != null) + @as(usize, @intFromBool(self.add != null)) + @intFromBool(self.double != null) + @intFromBool(self.sha256 != null) + @intFromBool(self.arith256_mod != null);
        for (self.bulk) |b| n += @intFromBool(b != null);
        for (self.sponge) |b| n += @intFromBool(b != null);
        return n;
    }
};
pub fn cpuHandles(a: std.mem.Allocator, base: *const Components, bridges: *const Bridges) ![]engine.air.component_prover.ComponentProver {
    const old = try base.provers(a);
    defer a.free(old);
    const out = try a.alloc(engine.air.component_prover.ComponentProver, old.len + bridges.count());
    @memcpy(out[0..old.len], old);
    var at = old.len;
    inline for (.{ "keccak", "add", "double", "sha256", "arith256_mod" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asProverComponent();
        at += 1;
    };
    for (&bridges.bulk) |*b| if (b.*) |*c| {
        out[at] = c.asProverComponent();
        at += 1;
    };
    for (&bridges.sponge) |*b| if (b.*) |*c| {
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
    inline for (.{ "keccak", "add", "double", "sha256", "arith256_mod" }) |name| if (@field(bridges, name)) |*c| {
        out[at] = c.asVerifierComponent();
        at += 1;
    };
    for (&bridges.bulk) |*b| if (b.*) |*c| {
        out[at] = c.asVerifierComponent();
        at += 1;
    };
    for (&bridges.sponge) |*b| if (b.*) |*c| {
        out[at] = c.asVerifierComponent();
        at += 1;
    };
    return out;
}
pub const TruthComponents = union(enum) {
    keccak: [3]K.component.Component,
    secp: @import("../secp/execution.zig").TruthComponents,
    sha256: A.crypto.sha256.component.Component,
    arith256_mod: A.crypto.arith256.component.Component,
    pub fn init(truth: R.Truth, ch: P.TruthDraw, claims: [3]Q) !TruthComponents {
        return switch (truth) {
            .keccak => |t| switch (ch) {
                .keccak => |kc| .{ .keccak = @import("../keccak/shared/execution.zig").truthComponents(t.setup, t.first_id, t.calls, kc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
            .secp => |t| switch (ch) {
                .secp => |sc| .{ .secp = @import("../secp/execution.zig").TruthComponents.initSpan(t.setup, t.first_id, t.calls, sc, claims) },
                else => error.InvalidCombinedTruthChallenge,
            },
            .sha256 => |t| switch (ch) {
                .sha256 => |wire_ch| block: {
                    if (!claims[1].isZero() or !claims[2].isZero()) return error.NonzeroAbsentServiceClaim;
                    break :block .{ .sha256 = .{ .log_size = t.setup.log, .public = .{ .calls = t.calls, .first_id = t.first_id }, .claim = claims[0], .wire = wire_ch } };
                },
                else => error.InvalidCombinedTruthChallenge,
            },
            .arith256_mod => |t| switch (ch) {
                .arith256_mod => |ac| block: {
                    if (!claims[1].isZero() or !claims[2].isZero()) return error.NonzeroAbsentServiceClaim;
                    break :block .{ .arith256_mod = .{ .log_size = t.setup.log, .public = .{ .calls = t.calls, .first_id = t.first_id }, .claim = claims[0], .challenges = ac } };
                },
                else => error.InvalidCombinedTruthChallenge,
            },
        };
    }
    pub fn provers(self: *const TruthComponents, out: *[3]engine.air.component_prover.ComponentProver) []engine.air.component_prover.ComponentProver {
        switch (self.*) {
            .keccak => |*c| out.* = .{ c[0].asProverComponent(), c[1].asProverComponent(), c[2].asProverComponent() },
            .secp => |*c| out.* = c.provers(),
            .sha256 => |*c| {
                out[0] = c.asProverComponent();
                return out[0..1];
            },
            .arith256_mod => |*c| {
                out[0] = c.asProverComponent();
                return out[0..1];
            },
        }
        return out;
    }
    pub fn verifiers(self: *const TruthComponents, out: *[3]core.air.components.Component) []core.air.components.Component {
        switch (self.*) {
            .keccak => |*c| out.* = .{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), c[2].asVerifierComponent() },
            .secp => |*c| out.* = c.verifiers(),
            .sha256 => |*c| {
                out[0] = c.asVerifierComponent();
                return out[0..1];
            },
            .arith256_mod => |*c| {
                out[0] = c.asVerifierComponent();
                return out[0..1];
            },
        }
        return out;
    }
};
