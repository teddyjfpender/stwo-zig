//! Independent root-side obligations for the typed detached execution. No
//! native PCS/GKR proof bytes or proposed root key enter this preparation.
//! Every returned frame MUST be authenticated by the physical grouped root.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const I = @import("inventory.zig");
const M = @import("manifest.zig");
const BaseM = @import("../pure_p2_manifest.zig");
const N = @import("../pure_p2_native.zig");
const Fold = @import("../native_omul/fold.zig");
const Parts = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Tower = @import("../pure_p2_op_inventory.zig").MillerDeclaration;
const Leaf = @import("../pure_p2_op_root_receiver.zig").Leaf;
pub const Metadata = struct { execution: [32]u8, manifest: [36]u8, leaves: []const Leaf };
pub const Authority = struct {
    inventory: *const I.Inventory,
    cpus: []const I.Cpu,
    detached: []const I.Detached,
    catalog: []const I.Catalog,
    towers: []const Tower,
    image: *const @import("../../word16_execution/expected_image.zig").Owner,
};
const Entry = struct {
    authority: M.Authority,
    scope: N.Scope,
    local: ?struct { digest: [36]u8 },
    global_relations: BaseM.Relations,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    execution: [32]u8,
    manifest: [36]u8,
    outputs: []Fold.Digest,
    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.outputs);
        self.* = undefined;
    }
    pub fn expectedRoot(self: *const Prepared) !Fold.Digest {
        return Fold.treeDigest(self.allocator, self.outputs);
    }
};
fn canonical(claims: []const O) !void {
    if (claims.len > 4096) return error.OpRootClaimLimit;
    for (claims) |claim| for (claim.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.OpRootNoncanonicalClaim;
}
fn requireSource(actual: M.Authority, ordinal: usize, statement: [32]u8, identity: [32]u8, root: [36]u8) !void {
    if (actual.ordinal != ordinal or !std.mem.eql(u8, &actual.statement, &statement) or !std.mem.eql(u8, &actual.fixed_identity, &identity) or !std.mem.eql(u8, &actual.fixed, &root)) return error.OpRootLeafSourceAuthority;
}
fn appendOutput(a: std.mem.Allocator, words: []u32, output: *Fold.Digest) !void {
    defer a.free(words);
    for (output, try core.crypto.poseidon2_m31_sponge.decode(N.hashWords(words))) |*wire, value| wire.* = core.fields.qm31.QM31.fromBase(value);
}
/// The Inventory has already independently admitted image/genesis/adjacency,
/// exact service coverage, bounded geometry and the source security ledger.
/// Recheck terminal policy here; a previous native verifier is not authority.
pub fn prepare(a: std.mem.Allocator, authority: Authority, metadata: Metadata) !Prepared {
    const inventory = authority.inventory;
    try M.validateExpected(inventory.workers);
    if (authority.cpus.len == 0 or authority.cpus.len != inventory.cpu_count or authority.detached.len != inventory.detached_count or authority.catalog.len != inventory.truth_count or authority.cpus.len + authority.detached.len + authority.catalog.len + authority.towers.len != inventory.workers.len) return error.OpRootLeafCoverage;
    if (!std.mem.eql(u8, &metadata.execution, &inventory.execution)) return error.OpRootExecutionAuthority;
    if (metadata.leaves.len != inventory.workers.len) return error.OpRootLeafCoverage;
    const final = authority.cpus[authority.cpus.len - 1].request;
    _ = try @import("../../word16_global_execution/ethereum/terminal.zig").require(authority.image, final.base.cpu, final.base.memory.terminal);
    const entries = try a.alloc(Entry, inventory.workers.len);
    defer a.free(entries);
    for (metadata.leaves, inventory.workers, entries, 0..) |leaf, source, *entry, ordinal| {
        const local = ordinal < authority.cpus.len + authority.detached.len or if (ordinal < authority.cpus.len + authority.detached.len + authority.catalog.len) authority.catalog[ordinal - authority.cpus.len - authority.detached.len].local_key != null else authority.towers[ordinal - authority.cpus.len - authority.detached.len - authority.catalog.len].local_key != null;
        if (leaf.ordinal != ordinal or (leaf.receipt != null) != local) return error.OpRootLeafOrder;
        _ = try core.crypto.poseidon2_m31_sponge.decode(leaf.main);
        if (leaf.receipt) |receipt| _ = try core.crypto.poseidon2_m31_sponge.decode(receipt);
        try canonical(leaf.claims);
        entry.* = .{ .authority = source.authority, .scope = .{ .ordinal = @intCast(ordinal), .statement = source.authority.statement, .fixed = source.authority.fixed, .main = leaf.main }, .local = if (source.cpu != null) .{ .digest = leaf.receipt.? } else null, .global_relations = source.authority.global_relations };
    }
    var writer = N.ReceiptWriter{};
    try BaseM.emit(inventory.execution, entries, &writer);
    const manifest = try writer.finish();
    if (!std.mem.eql(u8, &manifest, &metadata.manifest)) return error.OpRootManifestAuthority;
    const shared = try BaseM.drawShared(manifest);
    const outputs = try a.alloc(Fold.Digest, metadata.leaves.len);
    errdefer a.free(outputs);
    const global = try a.alloc(BaseM.Claims, metadata.leaves.len);
    defer a.free(global);
    for (authority.cpus, 0..) |cpu, ordinal| {
        try cpu.key.require(cpu.setup);
        const leaf = metadata.leaves[ordinal];
        const expected = @import("worker.zig").Expected{ .ordinal = @intCast(ordinal), .statement = try cpu.key.statement(cpu.setup, cpu.request, inventory.first_ids[ordinal], cpu.span, @intCast(ordinal)) };
        try requireSource(inventory.workers[ordinal].authority, ordinal, expected.statement, cpu.key.identity, cpu.key.root);
        var parts = try Parts.Plan.initForOp(a, cpu.setup);
        defer parts.deinit();
        if (leaf.claims.len != parts.claim_count + 1) return error.SpongeCpuClaims;
        try @import("../pure_p2_cpu_worker.zig").checkPublicClaims(cpu.request, &parts, shared, leaf.claims[0..parts.claim_count]);
        global[ordinal] = try Parts.Set.aggregate(&parts, leaf.claims[0..parts.claim_count]);
        global[ordinal].wire = global[ordinal].wire.add(leaf.claims[parts.claim_count]);
        try appendOutput(a, try @import("statement.zig").expectedWords(a, cpu.setup, cpu.request, cpu.span, inventory.first_ids[ordinal], cpu.key, expected, manifest, leaf.main, leaf.receipt.?, leaf.claims), &outputs[ordinal]);
    }
    for (authority.detached, 0..) |source, j| {
        const ordinal = authority.cpus.len + j;
        const leaf = metadata.leaves[ordinal];
        if (leaf.claims.len != 24) return error.DetachedClaimCount;
        try source.key.require(source.geometry);
        try requireSource(inventory.workers[ordinal].authority, ordinal, try source.key.statementDetached(source.geometry), source.key.identity, source.key.root);
        var claims: [8][3]O = undefined;
        global[ordinal] = .{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
        for (&claims, 0..) |*row, i| {
            @memcpy(row, leaf.claims[3 * i ..][0..3]);
            global[ordinal].ram = global[ordinal].ram.add(row[0]);
            global[ordinal].kio = global[ordinal].kio.add(row[1]);
            global[ordinal].wire = global[ordinal].wire.add(row[2]);
        }
        try @import("../sponge_local_gkr/worker.zig").requireClaims(claims);
        try appendOutput(a, try @import("../sponge_local_gkr/statement.zig").expectedWords(a, source.key, source.geometry, @intCast(ordinal), manifest, leaf.main, leaf.receipt.?, claims), &outputs[ordinal]);
    }
    for (authority.catalog, 0..) |source, j| {
        const ordinal = authority.cpus.len + authority.detached.len + j;
        const leaf = metadata.leaves[ordinal];
        const expected = if (source.local_key) |key| try key.expected(source.truth, @intCast(ordinal)) else try source.key.expected(source.truth, @intCast(ordinal));
        try requireSource(inventory.workers[ordinal].authority, ordinal, expected.statement, expected.fixed_identity, expected.fixed);
        if (source.local_key) |key| {
            if (leaf.claims.len != 2 or (source.truth == .keccak and !leaf.claims[1].isZero())) return error.OpRootLocalTruthClosure;
            global[ordinal] = .{ .ram = O.zero(), .kio = if (source.truth == .keccak) leaf.claims[0] else O.zero(), .wire = if (source.truth == .secp) leaf.claims[0].add(leaf.claims[1]) else O.zero() };
            try appendOutput(a, try @import("../truth_local_gkr/statement.zig").expectedWords(a, key, source.truth, expected, manifest, leaf.main, leaf.receipt.?, leaf.claims[0..2].*), &outputs[ordinal]);
        } else {
            if (source.truth == .keccak or source.truth == .secp) {
                if (leaf.claims.len != 5 or !leaf.claims[0].add(leaf.claims[1]).add(leaf.claims[2]).isZero() or (source.truth == .keccak and !leaf.claims[4].isZero())) return error.OpRootLocalTruthClosure;
                global[ordinal] = try @import("../../word16_global_execution/services/gkr_local/truth_worker.zig").claimsResult(source.truth, leaf.claims);
            } else {
                if (leaf.claims.len != 1) return error.OpRootTruthClaims;
                global[ordinal] = .{ .ram = O.zero(), .kio = O.zero(), .wire = leaf.claims[0] };
            }
            try appendOutput(a, try @import("../pure_p2_truth_statement.zig").expectedWords(a, source.key, source.truth, expected, manifest, leaf.main, leaf.claims), &outputs[ordinal]);
        }
    }
    for (authority.towers, 0..) |source, j| {
        const ordinal = authority.cpus.len + authority.detached.len + authority.catalog.len + j;
        const leaf = metadata.leaves[ordinal];
        const expected = if (source.local_key) |key| try key.expected(source.span, @intCast(ordinal)) else try source.key.expected(source.span, @intCast(ordinal));
        try requireSource(inventory.workers[ordinal].authority, ordinal, expected.statement, expected.fixed_identity, expected.fixed);
        if (source.local_key) |key| {
            if (leaf.claims.len != 2) return error.OpRootLocalMillerClosure;
            global[ordinal] = .{ .ram = O.zero(), .kio = O.zero(), .wire = leaf.claims[0].add(leaf.claims[1]) };
            try appendOutput(a, try @import("../miller_local_gkr/statement.zig").expectedWords(a, key, source.span, expected, manifest, leaf.main, leaf.receipt.?, leaf.claims[0..2].*), &outputs[ordinal]);
        } else {
            if (leaf.claims.len != 4 or !leaf.claims[0].add(leaf.claims[2]).isZero()) return error.OpRootLocalMillerClosure;
            global[ordinal] = .{ .ram = O.zero(), .kio = O.zero(), .wire = leaf.claims[1].add(leaf.claims[3]) };
            try appendOutput(a, try @import("../pure_p2_tower_statement.zig").expectedWords(a, source.key, source.span, expected, manifest, leaf.main, leaf.claims[0..4].*), &outputs[ordinal]);
        }
    }
    try @import("../../word16_global_execution/services/gkr_local/manifest.zig").checkClaimsClosure(entries, global);
    return .{ .allocator = a, .execution = inventory.execution, .manifest = manifest, .outputs = outputs };
}

test "detached root admission refuses empty independent inventory before reading proof metadata" {
    var inventory: I.Inventory = undefined;
    inventory.workers = &.{};
    try std.testing.expectError(error.DetachedManifestRoster, prepare(std.testing.allocator, .{ .inventory = &inventory, .cpus = &.{}, .detached = &.{}, .catalog = &.{}, .towers = &.{}, .image = undefined }, .{ .execution = @splat(0), .manifest = @splat(0), .leaves = &.{} }));
}
