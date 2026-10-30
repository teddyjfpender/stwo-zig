//! Direct-original window proving. A receiver reconstructs the topology from
//! external ELF/checkpoints and canonical metadata, never from a producer key.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const Registry = @import("../riscv_recursion/registry_v1.zig");
const Join = @import("window_join.zig");
const Admission = @import("admission.zig");
const Material = @import("material.zig");
const Statement = @import("statement.zig").Statement;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Times = struct {
    admission_ns: u64 = 0,
    material_ns: u64 = 0,
    key_ns: u64 = 0,
    witness_ns: u64 = 0,
    prove_and_serialize_ns: u64 = 0,
    whole_ns: u64 = 0,
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    statement: Statement,
    times: Times,
    pub fn deinit(v: *Artifact) void {
        v.allocator.free(v.bytes);
        v.* = undefined;
    }
};

pub fn deriveEntry(a: std.mem.Allocator, authority: *const Join.Authority, options: Registry.Options) !Registry.Entry {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const dummy = try arena.allocator().alloc(Material.Owned, authority.sources.len);
    for (dummy, authority.sources) |*value, *source| value.* = try Material.Owned.zeroForTopologyLeaky(arena.allocator(), source.geometry);
    var ctx = try b.Context(b.NoValue).init(a, Join.OUTPUTS);
    defer ctx.deinit();
    _ = try Join.build(b.NoValue, &ctx, authority, dummy);
    return Registry.Entry.deriveFromTopology(a, &ctx, authority.seal, try authority.statement.digest(), options);
}

/// Producers return serialized proof only. Call verifyBytes after releasing
/// all original materials and producer keys to establish fresh receiving.
pub fn produce(a: std.mem.Allocator, metadata: Admission.Metadata, original_bytes: []const []const u8, backend: *const Registry.BackendAuthority, options: Registry.Options) !Artifact {
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var times: Times = .{};
    var authority = try Join.Authority.derive(a, metadata);
    defer authority.deinit();
    times.admission_ns = phase.lap();
    if (original_bytes.len != authority.sources.len) return error.InvalidOriginalWindowRoster;
    const materials = try a.alloc(Material.Owned, original_bytes.len);
    defer a.free(materials);
    var initialized: usize = 0;
    defer for (materials[0..initialized]) |*material| material.deinit();
    for (materials, authority.sources, original_bytes) |*material, *source, bytes| {
        material.* = try Material.Owned.fromBytes(a, source, bytes, .{});
        initialized += 1;
    }
    times.material_ns = phase.lap();
    var entry = try deriveEntry(a, &authority, options);
    defer entry.deinit();
    times.key_ns = phase.lap();
    var ctx = try b.Context(Q).init(a, Join.OUTPUTS);
    var owns_ctx = true;
    defer if (owns_ctx) ctx.deinit();
    _ = try Join.build(Q, &ctx, &authority, materials);
    try Registry.finalizeStrict(Q, &ctx);
    try @import("stwo_circuit_frontend").common.finalize.padToTargets(Q, &ctx, entry.target);
    if (ctx.circuit.n_vars != entry.n_vars or !try ctx.isCircuitValid()) return error.InvalidOriginalWindowWitness;
    times.witness_ns = phase.lap();
    owns_ctx = false;
    const bytes = try Registry.proveFinalized(a, &ctx, &entry, backend, options);
    times.prove_and_serialize_ns = phase.lap();
    times.whole_ns = whole.read();
    return .{ .allocator = a, .bytes = bytes, .statement = authority.statement, .times = times };
}

pub fn verifyBytes(a: std.mem.Allocator, metadata: Admission.Metadata, bytes: []const u8, backend: *const Registry.BackendAuthority, options: Registry.Options) !void {
    var authority = try Join.Authority.derive(a, metadata);
    defer authority.deinit();
    var entry = try deriveEntry(a, &authority, options);
    defer entry.deinit();
    try Registry.verifyWithEntry(a, &entry, bytes, backend);
}
