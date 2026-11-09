//! OP-only two-phase manifest: canonical nine-limb roots and local receipts.
//! Returns pending obligations. No native/recursive execution is admitted here.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = @import("pure_p2_native.zig");
const Profile = @import("op_profile.zig").Profile;
const Old = @import("../word16_global_execution/services/gkr_local/manifest.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(core.fields.om31.OM31).GkrBatchProof;
const O = core.fields.om31.OM31;
pub const MAX_WORKERS = 256;
pub const Claims = Old.Claims;
pub const Shared = Old.Shared;
pub const Relations = Old.Relations;
pub const DOMAIN = [_]u32{ 0x4f504d39, 1, 9 };
pub const Expected = struct {
    kind: Old.Kind,
    ordinal: u32,
    global_relations: Old.Relations,
    mass: Old.Mass,
    statement: [32]u8,
    fixed_identity: [32]u8,
    fixed: N.Digest,
    profile: Profile,
    local_instances: ?[]const Frame.Instance,
};
pub const Local = struct { proof: *const Proof, receipt: N.Digest };
pub const StageOne = struct { main: N.Digest, local: ?Local };
pub const Entry = struct {
    authority: Expected,
    scope: N.Scope,
    local: ?N.Pending,
    // Kept explicit for the existing relation-by-relation closure authority.
    global_relations: Old.Relations,
};
pub const Pending = struct {
    entries: []Entry,
    digest: N.Digest,
    shared: Old.Shared,
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| if (entry.local) |*child| child.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
    /// Must be called for every freshly verified physical worker; this module
    /// cannot infer that callers have discharged any PCS/terminal obligations.
    pub fn checkPhysicalRoots(self: *const @This(), ordinal: usize, fixed: N.Digest, main: N.Digest) !void {
        if (ordinal >= self.entries.len) return error.GlobalGkrManifestOrdinal;
        _ = try core.crypto.poseidon2_m31_sponge.decode(fixed);
        _ = try core.crypto.poseidon2_m31_sponge.decode(main);
        const scope = self.entries[ordinal].scope;
        if (!std.mem.eql(u8, &fixed, &scope.fixed) or !std.mem.eql(u8, &main, &scope.main)) return error.GlobalGkrPhysicalRootMismatch;
    }
    pub fn checkGlobalClosure(self: *const @This(), claims: []const Old.Claims) !void {
        return Old.checkClaimsClosure(self.entries, claims);
    }
};
pub fn validateExpected(expected: []const Expected) !void {
    if (expected.len == 0 or expected.len > MAX_WORKERS) return error.GlobalGkrManifestRoster;
    // Reuse the source-owned exact kind/order/mass/instance validation, without
    // truncating or substituting a nine-limb commitment into a 32-byte root.
    var legacy: [MAX_WORKERS]Old.ExpectedWorker = undefined;
    for (expected, legacy[0..expected.len]) |worker, *target| {
        _ = try core.crypto.poseidon2_m31_sponge.decode(worker.fixed);
        if (worker.profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        target.* = .{ .kind = worker.kind, .ordinal = worker.ordinal, .global_relations = worker.global_relations, .mass = worker.mass, .statement = worker.statement, .fixed = @splat(0), .local_instances = worker.local_instances };
    }
    try Old.validateRoster(legacy[0..expected.len]);
}
/// One typed authority for native and constrained writers. The receipt already
/// binds complete local OOD geometry and terminal marginals, so they are not
/// redundantly expanded here. Only checked/authenticated local receipts belong
/// in this view; deserializing an unverified receipt is never sufficient.
pub fn emit(execution: anytype, entries: anytype, writer: anytype) !void {
    for (DOMAIN) |tag| writer.tag(tag);
    writer.rawDigest(execution);
    writer.integer(entries.len);
    for (entries) |entry| {
        const authority = entry.authority;
        writer.integer(@intFromEnum(authority.kind));
        writer.integer(entry.scope.ordinal);
        writer.integer(@as(u32, @intFromBool(authority.global_relations.ram)) | (@as(u32, @intFromBool(authority.global_relations.kio)) << 1) | (@as(u32, @intFromBool(authority.global_relations.wire)) << 2));
        writer.integer(authority.mass.ram);
        writer.integer(authority.mass.kio);
        writer.integer(authority.mass.wire);
        writer.integer(@intFromEnum(authority.profile));
        writer.rawDigest(authority.fixed_identity);
        writer.rawDigest(entry.scope.statement);
        writer.root(entry.scope.fixed);
        writer.root(entry.scope.main);
        writer.integer(@intFromBool(entry.local != null));
        if (entry.local) |local| writer.root(local.digest);
    }
}
pub fn digest(execution: [32]u8, entries: []const Entry) !N.Digest {
    var writer = N.ReceiptWriter{};
    try emit(execution, entries, &writer);
    return writer.finish();
}
pub fn drawShared(root: N.Digest) !Old.Shared {
    _ = try core.crypto.poseidon2_m31_sponge.decode(root);
    var channel = N.Channel.init();
    channel.mixU32s(&DOMAIN);
    channel.mixRoot(root);
    channel.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallengesFor(O) = undefined;
    ram.offset = channel.drawSecureFelt();
    for (&ram.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x4b494f31, 11 });
    const kio = A.crypto.keccak.equations.IoFor(O).draw(&channel);
    channel.mixU32s(&.{ 0x53574952, 35 });
    return .{ .ram = ram, .kio = kio, .wire = A.crypto.secp256k1.equations.WireFor(O).draw(&channel) };
}
pub fn verifyAndSeal(allocator: std.mem.Allocator, execution: [32]u8, expected: []const Expected, stages: []const StageOne) !Pending {
    try validateExpected(expected);
    if (stages.len != expected.len) return error.GlobalGkrManifestRoster;
    const entries = try allocator.alloc(Entry, expected.len);
    var made: usize = 0;
    errdefer {
        for (entries[0..made]) |*entry| if (entry.local) |*child| child.deinit(allocator);
        allocator.free(entries);
    }
    for (expected, stages, entries) |authority, stage, *entry| {
        _ = try core.crypto.poseidon2_m31_sponge.decode(stage.main);
        const scope = N.Scope{ .statement = authority.statement, .fixed = authority.fixed, .main = stage.main, .ordinal = authority.ordinal };
        if ((authority.local_instances != null) != (stage.local != null)) return error.GlobalGkrManifestRoster;
        entry.* = .{ .authority = authority, .scope = scope, .global_relations = authority.global_relations, .local = if (stage.local) |local| try N.verifyPending(allocator, scope, authority.local_instances.?, local.proof, local.receipt) else null };
        made += 1;
    }
    const root = try digest(execution, entries);
    return .{ .entries = entries, .digest = root, .shared = try drawShared(root) };
}
