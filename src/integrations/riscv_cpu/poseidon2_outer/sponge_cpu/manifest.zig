//! Pending two-phase manifest for the typed detached-sponge construction.
//! Receiver-derived recipes, never producer declarations, populate Expected.
//! This verifies CPU local children before drawing shared challenges. Physical
//! proofs, source inventory/continuity, terminal policy and global closure are
//! separate obligations; production source-suite admission stays closed.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../pure_p2_native.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Global = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Frame = @import("frame.zig");
const Native = @import("native.zig");
const Profile = @import("../pure_p2_worker_protocol.zig").Profile;
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(core.fields.om31.OM31).GkrBatchProof;
pub const Kind = enum(u32) {
    sponge_cpu = 0x53504350,
    detached = 0x53504753,
    keccak = 1,
    secp_add = 2,
    secp_double = 3,
    delegation = 4,
    fn rank(self: Kind) u32 {
        return switch (self) {
            .sponge_cpu => 0,
            .detached => 1,
            .keccak => 2,
            .secp_add => 3,
            .secp_double => 4,
            .delegation => 5,
        };
    }
};
pub const Authority = struct {
    kind: Kind,
    ordinal: u32,
    profile: Profile,
    fixed_identity: [32]u8,
    fixed: [36]u8,
    statement: [32]u8,
    global_relations: Global.Relations,
    mass: Global.Mass,
};
pub const CpuRecipe = struct { epoch: u16, calls: u32, instances: []const Frame.Instance };
pub const Expected = struct { authority: Authority, cpu: ?CpuRecipe = null };
pub const Local = struct { proof: *const Proof, receipt: [36]u8 };
pub const StageOne = struct { main: [36]u8, local: ?Local = null };
pub const Entry = struct {
    authority: Authority,
    scope: Base.Scope,
    local: ?Native.Pending,
    global_relations: Global.Relations,
};
pub const Pending = struct {
    entries: []Entry,
    digest: [36]u8,
    shared: Global.Shared,
    pub fn deinit(self: *Pending, a: std.mem.Allocator) void {
        for (self.entries) |*entry| if (entry.local) |*local| local.deinit(a);
        a.free(self.entries);
        self.* = undefined;
    }
    pub fn checkPhysicalRoots(self: *const Pending, ordinal: usize, fixed: [36]u8, main: [36]u8) !void {
        if (ordinal >= self.entries.len) return error.GlobalGkrManifestOrdinal;
        _ = try core.crypto.poseidon2_m31_sponge.decode(fixed);
        _ = try core.crypto.poseidon2_m31_sponge.decode(main);
        const scope = self.entries[ordinal].scope;
        if (!std.mem.eql(u8, &fixed, &scope.fixed) or !std.mem.eql(u8, &main, &scope.main)) return error.GlobalGkrPhysicalRootMismatch;
    }
    /// Call only with claims from every freshly verified physical worker.
    pub fn checkGlobalClosure(self: *const Pending, claims: []const Global.Claims) !void {
        return Global.checkClaimsClosure(self.entries, claims);
    }
};
pub fn validateExpected(expected: []const Expected) !void {
    if (expected.len < 3 or expected.len > Manifest.MAX_WORKERS or expected[0].authority.kind != .sponge_cpu) return error.DetachedManifestRoster;
    var previous: u32 = 0;
    var detached: usize = 0;
    var keccak: usize = 0;
    var mass = Global.Mass{ .ram = 0, .kio = 0, .wire = 0 };
    const profile = expected[0].authority.profile;
    for (expected, 0..) |entry, ordinal| {
        const source = entry.authority;
        if (source.ordinal != ordinal or source.kind.rank() < previous) return error.GlobalGkrManifestOrdinal;
        previous = source.kind.rank();
        if (source.profile != profile or source.profile == .reference_b2_q24_p0) return error.InvalidOpNativeProfile;
        _ = try core.crypto.poseidon2_m31_sponge.decode(source.fixed);
        const mask = source.global_relations;
        inline for (.{ "ram", "kio", "wire" }) |name| {
            const bound = @field(source.mass, name);
            if (!@field(mask, name) and bound != 0) return error.GlobalGkrRelationMass;
            @field(mass, name) = std.math.add(u64, @field(mass, name), bound) catch return error.GlobalGkrCharacteristicBound;
            if (@field(mass, name) >= core.fields.m31.Modulus) return error.GlobalGkrCharacteristicBound;
        }
        switch (source.kind) {
            .sponge_cpu => {
                if (!mask.ram) return error.GlobalGkrRelationRoster;
                const recipe = entry.cpu orelse return error.MissingGlobalGkrLocalChild;
                if (recipe.epoch != ordinal + 1 or recipe.instances.len < 2 or recipe.instances.len > 256) return error.SpongeCpuGeometry;
                for (recipe.instances[0 .. recipe.instances.len - 1]) |instance| {
                    if (instance != .legacy or instance.legacy.origin == .sponge) return error.SpongeCpuRequiresDetachedSetup;
                    _ = try instance.variables();
                }
                const frontier = recipe.instances[recipe.instances.len - 1];
                if (frontier != .frontier) return error.SpongeCpuFrontierMissing;
                _ = try frontier.variables();
                try @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.serialized.frontier.validatePublic(recipe.calls, frontier.rowLog(), recipe.epoch, source.ordinal);
                // Every active frontier emits one unit OWNER transfer over Wire.
                if (recipe.calls != 0 and (!mask.wire or source.mass.wire < recipe.calls)) return error.GlobalGkrRelationMass;
            },
            .detached => {
                if (entry.cpu != null or !mask.ram or !mask.kio or !mask.wire) return error.GlobalGkrRelationRoster;
                detached += 1;
            },
            .keccak => {
                if (entry.cpu != null or mask.ram or !mask.kio or mask.wire) return error.GlobalGkrRelationRoster;
                keccak += 1;
            },
            .secp_add, .secp_double, .delegation => if (entry.cpu != null or mask.ram or mask.kio or !mask.wire) return error.GlobalGkrRelationRoster,
        }
    }
    if (detached == 0 or keccak == 0) return error.DetachedManifestRoster;
}
pub fn verifyAndSeal(a: std.mem.Allocator, execution: [32]u8, expected: []const Expected, stages: []const StageOne) !Pending {
    try validateExpected(expected);
    if (stages.len != expected.len) return error.GlobalGkrManifestRoster;
    // Reject invalid roots/child presence before any owned artifact allocation.
    for (expected, stages) |source, stage| {
        _ = try core.crypto.poseidon2_m31_sponge.decode(stage.main);
        if ((source.cpu != null) != (stage.local != null)) return error.GlobalGkrManifestRoster;
    }
    const entries = try a.alloc(Entry, expected.len);
    var made: usize = 0;
    errdefer {
        for (entries[0..made]) |*entry| if (entry.local) |*local| local.deinit(a);
        a.free(entries);
    }
    for (expected, stages, entries) |source, stage, *entry| {
        const authority = source.authority;
        const scope = Base.Scope{ .statement = authority.statement, .fixed = authority.fixed, .main = stage.main, .ordinal = authority.ordinal };
        entry.* = .{ .authority = authority, .scope = scope, .global_relations = authority.global_relations, .local = if (source.cpu) |recipe| try Native.verifyPending(a, .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal, .epoch = recipe.epoch, .calls = recipe.calls }, recipe.instances, stage.local.?.proof, stage.local.?.receipt) else null };
        made += 1;
    }
    var writer = Base.ReceiptWriter{};
    try Manifest.emit(execution, entries, &writer);
    const digest = try writer.finish();
    return .{ .entries = entries, .digest = digest, .shared = try Manifest.drawShared(digest) };
}
