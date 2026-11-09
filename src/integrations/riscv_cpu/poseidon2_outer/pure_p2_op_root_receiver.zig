//! Independent OP root admission and authenticated-frame expectations.
//! Preparing these obligations never accepts an execution. A source-derived
//! physical root verifier must authenticate the COMPLETE ordered output vector.
//! No native PCS or local-GKR proof is reverified on this recursive path.
const std = @import("std");
const core = @import("stwo_core");
const N = @import("pure_p2_native.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Inventory = @import("pure_p2_op_inventory.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Old = @import("../word16_global_execution/services/gkr_local/manifest.zig");
const O = core.fields.om31.OM31;
pub const Digest = [36]u8;
/// All fields originate in receiver policy/program/image and immutable source
/// construction, never from the root bundle or its proposed verifier key.
pub const Output = struct { address: u64, bytes: [43]u8 };
pub const Authority = struct {
    /// Freshly constructed from independently pinned ELF/input/ABI policy.
    image: ?*const @import("../word16_execution/expected_image.zig").Owner = null,
    output: Output,
    profile: @import("op_profile.zig").Profile,
    setups: []const *const R.CpuSetup,
    requests: []const P.Request,
    spans: []const T.OpTowerSpan,
    cpu_keys: []const *const Key,
    truths: []const R.Truth,
    truth_keys: []const *const Truth.Key,
    miller: []const Inventory.MillerDeclaration,
    expected: P.Expected,
};
/// Untrusted sidecar. Claims/receipts become authoritative only when the root
/// proof binds their independently recomputed leaf frame digests.
pub const Leaf = struct { ordinal: u32, main: Digest, receipt: ?Digest, claims: []const O };
pub const Metadata = struct { execution: [32]u8, manifest: Digest, leaves: []const Leaf };
const Entry = struct {
    authority: Manifest.Expected,
    scope: N.Scope,
    local: ?struct { digest: Digest },
    global_relations: Manifest.Relations,
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    inventory: Inventory.Inventory,
    manifest: Digest,
    expected_outputs: []Digest,
    /// Canonical ordered tree; an odd node carries unchanged. Count/order are
    /// fixed by this independently admitted Inventory, never by root metadata.
    pub fn expectedRoot(self: *const Plan, a: std.mem.Allocator) !@import("pure_p2_fold.zig").Digest {
        const Fold = @import("pure_p2_fold.zig");
        const leaves = try a.alloc(Fold.Digest, self.expected_outputs.len);
        defer a.free(leaves);
        for (leaves, self.expected_outputs) |*leaf, encoded| {
            for (leaf, try core.crypto.poseidon2_m31_sponge.decode(encoded)) |*coordinate, value| coordinate.* = core.fields.qm31.QM31.fromBase(value);
        }
        return Fold.treeDigest(a, leaves);
    }
    /// Completes authentication with ONE physical root proof. Topology has no
    /// bundle-key decoder: its leaf authorities are built by concrete source
    /// factories and its fold key is independently derived from those keys.
    /// Neither native child PCS nor local-GKR proofs are reverified here.
    pub fn verifyRoot(self: *const Plan, a: std.mem.Allocator, topology: *const @import("pure_p2_root_topology.zig").Topology, bytes: []const u8) !void {
        if (!std.mem.eql(u8, &topology.execution, &self.inventory.execution) or topology.leaf_count != self.inventory.workers.len or topology.leaf_bindings.len != self.inventory.workers.len) return error.OpRootTopologyCoverage;
        if (topology.profile != self.inventory.workers[0].profile) return error.OpRootTopologyProfile;
        for (topology.leaf_bindings, self.inventory.workers, 0..) |binding, expected, i| {
            const kind: @FieldType(@import("pure_p2_root_topology.zig").Binding, "kind") = if (i < self.inventory.cpu_count) .cpu else if (i < self.inventory.cpu_count + self.inventory.truth_count) .catalog else .miller;
            if (binding.ordinal != i or binding.kind != kind or !std.mem.eql(u8, &binding.native_identity, &expected.fixed_identity)) return error.OpRootLeafSourceAuthority;
        }
        const source_key = topology.key();
        if (source_key.n_outputs != 9 or source_key.profile != topology.profile) return error.OpRootTopologyProfile;
        const expected_root = try self.expectedRoot(a);
        try @import("proof.zig").verify(a, source_key, &expected_root, bytes);
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.expected_outputs);
        self.inventory.deinit();
        self.* = undefined;
    }
};
fn canonical(claims: []const O) !void {
    for (claims) |claim| for (claim.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.OpRootNoncanonicalClaim;
}
fn fillEntries(inventory: *const Inventory.Inventory, leaves: []const Leaf, entries: []Entry) !void {
    if (leaves.len != inventory.workers.len or entries.len != leaves.len) return error.OpRootLeafCoverage;
    for (leaves, inventory.workers, entries, 0..) |leaf, expected, *entry, i| {
        if (leaf.ordinal != i or expected.ordinal != i or (leaf.receipt != null) != (expected.kind == .cpu)) return error.OpRootLeafOrder;
        _ = try core.crypto.poseidon2_m31_sponge.decode(leaf.main);
        if (leaf.receipt) |receipt| _ = try core.crypto.poseidon2_m31_sponge.decode(receipt);
        if (leaf.claims.len > 4096) return error.OpRootClaimLimit;
        try canonical(leaf.claims);
        entry.* = .{ .authority = expected, .scope = .{ .ordinal = expected.ordinal, .statement = expected.statement, .fixed = expected.fixed, .main = leaf.main }, .local = if (leaf.receipt) |receipt| .{ .digest = receipt } else null, .global_relations = expected.global_relations };
    }
}
/// Metadata commitment only; callers still require source admission, public
/// boundary checks, complete recursive authentication and global closure.
pub fn manifestFor(a: std.mem.Allocator, inventory: *const Inventory.Inventory, leaves: []const Leaf) !Digest {
    const entries = try a.alloc(Entry, leaves.len);
    defer a.free(entries);
    try fillEntries(inventory, leaves, entries);
    var writer = N.ReceiptWriter{};
    try Manifest.emit(inventory.execution, entries, &writer);
    return writer.finish();
}
/// Complete source admission (including image/genesis/adjacency/terminal and
/// exact provider coverage), manifest reconstruction and per-relation closure.
/// The returned expected_outputs MUST all be authenticated by the final proof.
/// Native public boundary checks remain explicit here; they are not assumed to
/// follow from a zero sum or from independently valid component proofs.
pub fn prepare(a: std.mem.Allocator, authority: Authority, metadata: Metadata) !Plan {
    return prepareMode(a, authority, metadata, false);
}
/// Explicit closed fixture path. Production always requires the full pinned
/// image terminal policy; this cannot be used by non-test binaries.
pub fn prepareForFixture(a: std.mem.Allocator, authority: Authority, metadata: Metadata) !Plan {
    if (!@import("builtin").is_test) return error.OpRootFixtureOnly;
    return prepareMode(a, authority, metadata, true);
}
fn prepareMode(a: std.mem.Allocator, authority: Authority, metadata: Metadata, allow_fixture: bool) !Plan {
    if (authority.image == null and !allow_fixture) return error.OpRootTerminalPolicyMissing;
    var inventory = try Inventory.Inventory.init(a, authority.profile, authority.setups, authority.requests, authority.spans, authority.cpu_keys, authority.truths, authority.truth_keys, authority.miller, authority.expected);
    errdefer inventory.deinit();
    if (!std.mem.eql(u8, &inventory.execution, &metadata.execution)) return error.OpRootExecutionAuthority;
    if (metadata.leaves.len != inventory.workers.len) return error.OpRootLeafCoverage;
    const final_request = authority.requests[authority.requests.len - 1];
    if (authority.image) |image| {
        if (!std.mem.eql(u8, &image.identity, &authority.expected.admission.image_identity)) return error.OpRootImageAuthority;
        if (authority.output.address != image.symbols.output_data or !std.mem.eql(u8, &authority.output.bytes, &image.expected_output)) return error.OpRootOutputAuthority;
        // This repeats the source-owned terminal policy in the ROOT receiver,
        // independently of any earlier native completion/capture hook.
        _ = try @import("../word16_global_execution/ethereum/terminal.zig").require(image, final_request.base.cpu, final_request.base.memory.terminal);
    }
    try checkOutput(authority.output, final_request.base.memory.terminal);
    const entries = try a.alloc(Entry, metadata.leaves.len);
    defer a.free(entries);
    try fillEntries(&inventory, metadata.leaves, entries);
    // Only receipt commitments are consumed. The local proof is checked in the
    // CPU recursive leaf, and this same receipt is part of its public digest.
    var writer = N.ReceiptWriter{};
    try Manifest.emit(inventory.execution, entries, &writer);
    const manifest = try writer.finish();
    if (!std.mem.eql(u8, &manifest, &metadata.manifest)) return error.OpRootManifestAuthority;
    const shared = try Manifest.drawShared(manifest);
    const outputs = try a.alloc(Digest, metadata.leaves.len);
    errdefer a.free(outputs);
    const global = try a.alloc(Manifest.Claims, metadata.leaves.len);
    defer a.free(global);
    for (authority.setups, authority.requests, authority.spans, authority.cpu_keys, 0..) |setup, request, span, key, i| {
        try key.requireForOp(setup, authority.profile);
        var plan = try Components.Plan.initForOp(a, setup);
        defer plan.deinit();
        const leaf = metadata.leaves[i];
        try CPU.checkPublicClaims(request, &plan, shared, leaf.claims);
        global[i] = try Components.Set.aggregate(&plan, leaf.claims);
        const words = try @import("pure_p2_cpu_statement.zig").expectedWordsForOp(a, setup, request, inventory.first_ids[i], span, inventory.workers[i], manifest, leaf.main, leaf.receipt.?, leaf.claims);
        defer a.free(words);
        outputs[i] = N.hashWords(words);
    }
    for (authority.truths, authority.truth_keys, 0..) |truth, key, j| {
        const i = authority.setups.len + j;
        const leaf = metadata.leaves[i];
        if (truth == .keccak or truth == .secp) {
            if (leaf.claims.len != 5 or !leaf.claims[0].add(leaf.claims[1]).add(leaf.claims[2]).isZero() or (truth == .keccak and !leaf.claims[4].isZero())) return error.OpRootLocalTruthClosure;
            global[i] = try @import("../word16_global_execution/services/gkr_local/truth_worker.zig").claimsResult(truth, leaf.claims);
        } else {
            if (leaf.claims.len != 1) return error.OpRootTruthClaims;
            global[i] = .{ .ram = O.zero(), .kio = O.zero(), .wire = leaf.claims[0] };
        }
        const words = try @import("pure_p2_truth_statement.zig").expectedWords(a, key, truth, inventory.workers[i], manifest, leaf.main, leaf.claims);
        defer a.free(words);
        outputs[i] = N.hashWords(words);
    }
    for (authority.miller, 0..) |item, j| {
        const i = authority.setups.len + authority.truths.len + j;
        const leaf = metadata.leaves[i];
        if (leaf.claims.len != 4 or !leaf.claims[0].add(leaf.claims[2]).isZero()) return error.OpRootLocalMillerClosure;
        global[i] = .{ .ram = O.zero(), .kio = O.zero(), .wire = leaf.claims[1].add(leaf.claims[3]) };
        const words = try @import("pure_p2_tower_statement.zig").expectedWords(a, item.key, item.span, inventory.workers[i], manifest, leaf.main, leaf.claims[0..4].*);
        defer a.free(words);
        outputs[i] = N.hashWords(words);
    }
    try Old.checkClaimsClosure(entries, global);
    return .{ .allocator = a, .inventory = inventory, .manifest = manifest, .expected_outputs = outputs };
}

/// Application output authority is separate from CPU endpoint registers. The
/// source admission has already checked sorted unique public boundary cells.
fn checkOutput(output: Output, terminal: []const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell) !void {
    _ = std.math.add(u64, output.address, output.bytes.len - 1) catch return error.OpRootOutputWrap;
    for (output.bytes, 0..) |expected, index| {
        const address = output.address + @as(u64, @intCast(index));
        const word_address = address & ~@as(u64, 7);
        var lo: usize = 0;
        var hi = terminal.len;
        while (lo < hi) {
            const middle = lo + (hi - lo) / 2;
            if (terminal[middle].address < word_address) lo = middle + 1 else hi = middle;
        }
        if (lo == terminal.len or terminal[lo].address != word_address) return error.OpRootOutputMissing;
        const cell = terminal[lo];
        if (cell.state.rights & 1 == 0) return error.OpRootOutputUnreadable;
        const actual: u8 = @truncate(cell.state.value >> @as(u6, @intCast((address & 7) * 8)));
        if (actual != expected) return error.OpRootOutputMismatch;
    }
}
