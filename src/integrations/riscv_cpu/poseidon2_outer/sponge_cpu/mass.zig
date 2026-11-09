//! Source event bounds for the detached construction. No net cancellation is
//! used: every positive and negative RAM/KIO/Wire event contributes to mass.
//! Source inventory still checks requests, setup geometry and exact coverage.
const std = @import("std");
const core = @import("stwo_core");
const Old = @import("../../word16_global_execution/services/gkr_local/mass_authority.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Manifest = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const G = @import("../sponge_local_gkr/authority.zig").Geometry;
fn checked(mass: Manifest.Mass) !Manifest.Mass {
    inline for (.{ "ram", "kio", "wire" }) |name| if (@field(mass, name) >= core.fields.m31.Modulus) return error.GlobalGkrCharacteristicBound;
    return mass;
}
pub fn cpu(setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan) !Manifest.Mass {
    if (!setup.op_only or setup.bridges.sponge.any()) return error.SpongeCpuRequiresDetachedSetup;
    const extra = try span.mass(setup.bridges);
    return cpuWithTower(request, extra.ram, extra.wire);
}
fn cpuWithTower(request: P.Request, tower_ram: u64, tower_wire: u64) !Manifest.Mass {
    var counts = try Old.cpuCounts(request);
    // The serialized worker, rather than CPU, owns ALL sponge RAM/KIO events.
    counts.sponge = .{ 0, 0 };
    var mass = try (try Old.evaluateCpuCounts(counts)).absolute();
    mass.ram = try std.math.add(u64, mass.ram, tower_ram);
    mass.wire = try std.math.add(u64, mass.wire, tower_wire);
    // frontier.emitRaw/emitWireFor(false): one positive unit OWNER19 transfer.
    mass.wire = try std.math.add(u64, mass.wire, request.sponge.calls);
    return checked(mass);
}
pub fn detached(geometry: G) !Manifest.Mass {
    if (!geometry.detached) return error.SpongeLocalScopeFlavor;
    _ = try geometry.instances();
    const calls: u64 = geometry.calls;
    const perms: u64 = geometry.permutations;
    // descriptor.emitDetachedRaw: four before/after packet words per call.
    // state_word.emitRaw: 25 before/after state words per call.
    // message_word.emitRaw: 18 before/after packet words per permutation.
    const words = try std.math.add(u64, try std.math.mul(u64, calls, 4 + 25), try std.math.mul(u64, perms, 18));
    // state_word: at most25C positive and25C negative events.
    // permutation_lane: at most50P negative events. Fresh suppression can
    // reduce actual mass, never increase it. No positive/negative netting.
    const io = try std.math.mul(u64, try std.math.add(u64, calls, perms), 2 * 25);
    return checked(.{ .ram = try std.math.mul(u64, words, 2), .kio = io, .wire = calls });
}
test "detached manifest mass conserves RAM tightens KIO and counts both frontier Wire signs" {
    var request: P.Request = std.mem.zeroes(P.Request);
    request.base.memory.ls_count = 7;
    request.calls[0] = 2;
    request.sponge = .{ .calls = 3, .perms = 5, .first_id = 3 };
    const old = try (try Old.evaluateCpuCounts(try Old.cpuCounts(request))).absolute();
    const cpu_mass = try cpuWithTower(request, 0, 0);
    const source_mass = try detached(.{ .calls = 3, .permutations = 5, .first_id = 3, .detached = true });
    try std.testing.expectEqual(old.ram, cpu_mass.ram + source_mass.ram);
    try std.testing.expectEqual(old.kio - 50 * @as(u64, request.sponge.calls + request.sponge.perms), cpu_mass.kio + source_mass.kio);
    try std.testing.expectEqual(@as(u64, 50 * (3 + 5)), source_mass.kio);
    try std.testing.expectEqual(old.wire + 2 * request.sponge.calls, cpu_mass.wire + source_mass.wire);
    try std.testing.expectEqual(@as(u64, 3), cpu_mass.wire);
    try std.testing.expectEqual(@as(u64, 3), source_mass.wire);
    try std.testing.expectError(error.SpongeLocalScopeFlavor, detached(.{ .calls = 1, .permutations = 1, .first_id = 1 }));
    try std.testing.expectError(error.SpongeLocalGeometry, detached(.{ .calls = 2, .permutations = 1, .first_id = 1, .detached = true }));
}
