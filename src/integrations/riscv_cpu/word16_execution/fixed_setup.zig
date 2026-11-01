//! Explicit-rate immutable M31 fixed keys. No request/witness state or default
//! suite selection. CPU and truth setup keys use the same coefficient seam.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const QChannel = core.channel.blake2s.Blake2sChannel;
const M = core.fields.m31.M31;
const Coefficient = engine.poly.circle.CircleCoefficients;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, H, MC);
pub const Tree = Scheme.CommittedTree;
const Budget = engine.host_budget_allocator.SharedHostBudget;

pub const Profile = struct {
    /// Receiver-owned protocol identity; never copied from a proof bundle.
    protocol: [32]u8,
    log_blowup: u32,
    pub fn validate(self: Profile) !void {
        if (self.log_blowup < 1 or self.log_blowup > 2) return error.UnsupportedFixedSetupRate;
        if (std.mem.allEqual(u8, &self.protocol, 0)) return error.MissingFixedSetupProtocol;
    }
};
fn configuration(profile: Profile) !core.pcs.PcsConfig {
    try profile.validate();
    // Only rate affects this M31 tree. Query/PoW/secure-field/whole-protocol
    // authority remains with the receiver; the protocol identity pins it.
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, profile.log_blowup, 1) };
}
fn coefficientIdentity(coefficients: []const Coefficient, profile: Profile) ![32]u8 {
    try profile.validate();
    if (coefficients.len == 0) return error.EmptyFixedSetup;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-immutable-M31-prefixed-Blake-fixed-setup/v1\x00");
    h.update(&profile.protocol);
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, profile.log_blowup, .little);
    h.update(&word);
    std.mem.writeInt(u64, &word, coefficients.len, .little);
    h.update(&word);
    for (coefficients) |c| {
        if (c.log_size > 28 or c.coeffs.len != @as(usize, 1) << @intCast(c.log_size)) return error.InvalidFixedSetupCoefficientShape;
        std.mem.writeInt(u64, &word, c.log_size, .little);
        h.update(&word);
        for (c.coeffs) |value| {
            // Canonical LE encoding; never hash backing padding or host endian.
            h.update(&value.toBytesLe());
        }
    }
    return h.finalResult();
}
fn coefficientsEqual(a: []const Coefficient, b: []const Coefficient) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.log_size != y.log_size or x.coeffs.len != y.coeffs.len) return false;
        for (x.coeffs, y.coeffs) |xv, yv| if (!xv.eql(yv)) return false;
    }
    return true;
}
fn releaseBudget(context: ?*anyopaque, _: u64) void {
    const budget: *Budget = @ptrCast(@alignCast(context.?));
    budget.destroy();
}

pub const WideFixedKey = struct {
    profile: Profile,
    identity: [32]u8,
    root: [32]u8,
    allocator: std.mem.Allocator,
    tree: Tree,
    fn seal(a: std.mem.Allocator, budget: *Budget, coefficients: []const Coefficient, profile: Profile, id: [32]u8) !WideFixedKey {
        var scheme = try Scheme.init(a, try configuration(profile));
        defer scheme.deinit(a);
        scheme.setStorePolynomialsCoefficients();
        scheme.setCompactPolynomialStorage(1);
        var channel: QChannel = .{};
        // Already interpolated native coefficients: no fixed-row reconstruction
        // or interpolation. Retained copies are made ONCE when this key seals.
        try scheme.commitPolys(a, coefficients, &channel);
        if (scheme.trees.items.len != 1) return error.InvalidFixedSetupTree;
        var tree = scheme.trees.pop().?;
        errdefer tree.deinit(a);
        if (tree.backing_teardown != null) return error.UnexpectedFixedSetupBackingOwner;
        tree.backing_teardown = engine.pcs.BackingTeardownToken.init(budget.retain(), 0, releaseBudget);
        try tree.share(a);
        return .{ .profile = profile, .identity = id, .root = tree.root(), .allocator = a, .tree = tree };
    }
    pub fn require(self: *const WideFixedKey, profile: Profile, id: [32]u8, root: [32]u8) !void {
        try profile.validate();
        if (!std.meta.eql(profile, self.profile) or !std.mem.eql(u8, &id, &self.identity)) return error.FixedSetupIdentityMismatch;
        if (!std.mem.eql(u8, &root, &self.root)) return error.FixedSetupRootMismatch;
    }
    /// Append one shared field-neutral tree to Q or OM PCS. The returned tree
    /// lease retains its own allocator lifetime even after cache/key release.
    pub fn append(self: *const WideFixedKey, a: std.mem.Allocator, scheme: anytype, channel: anytype, profile: Profile, id: [32]u8, root: [32]u8) !void {
        try self.require(profile, id, root);
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or scheme.revision_config != null or scheme.config.fri_config.log_blowup_factor != self.profile.log_blowup or scheme.config.lifting_log_size != null) return error.InvalidWideFixedSetupPhase;
        var lease = self.tree.retainShared();
        errdefer lease.deinit(self.allocator);
        try scheme.appendCommittedTree(a, lease, channel);
    }
    fn deinit(self: *WideFixedKey) void {
        self.tree.deinit(self.allocator);
        self.* = undefined;
    }
};
const Entry = struct { key: WideFixedKey };
const State = struct {
    budget: *Budget,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Thread.Mutex = .{},
    entries: std.ArrayList(*Entry) = .empty,
    hits: u64 = 0,
    seals: u64 = 0,
    fn retain(self: *State) void {
        const old = self.references.fetchAdd(1, .monotonic);
        if (old >= std.math.maxInt(usize) / 2) @panic("too many fixed setup leases");
    }
    fn release(self: *State) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const budget = self.budget;
        const a = budget.allocator();
        for (self.entries.items) |entry| {
            entry.key.deinit();
            a.destroy(entry);
        }
        self.entries.deinit(a);
        a.destroy(self);
        budget.destroy();
    }
};
pub const Lease = struct {
    state: *State,
    key: *const WideFixedKey,
    pub fn retain(self: *const Lease) Lease {
        self.state.retain();
        return self.*;
    }
    pub fn deinit(self: *Lease) void {
        self.state.release();
        self.* = undefined;
    }
};
pub const Snapshot = struct { limit_bytes: usize, live_bytes: usize, peak_bytes: usize, keys: usize, hits: u64, seals: u64, refused: bool };
pub const Cache = struct {
    state: *State,
    /// Includes cache/control metadata and sealing scratch, not RSS. No global
    /// cache or eviction. A finite hard cap applies during construction too.
    pub fn init(a: std.mem.Allocator, maximum_bytes: usize) !Cache {
        if (maximum_bytes <= @sizeOf(Budget)) return error.InvalidFixedSetupBudget;
        const budget = try Budget.createRetainingParent(a, maximum_bytes - @sizeOf(Budget));
        errdefer budget.destroy();
        const state = try budget.allocator().create(State);
        state.* = .{ .budget = budget };
        return .{ .state = state };
    }
    pub fn deinit(self: *Cache) void {
        self.state.release();
        self.* = undefined;
    }
    pub fn snapshot(self: *const Cache) Snapshot {
        const state = self.state;
        state.mutex.lock();
        defer state.mutex.unlock();
        const b = state.budget.snapshot();
        return .{ .limit_bytes = b.limit + @sizeOf(Budget), .live_bytes = b.live_bytes + @sizeOf(Budget), .peak_bytes = b.peak_live_bytes + @sizeOf(Budget), .keys = state.entries.items.len, .hits = state.hits, .seals = state.seals, .refused = b.exceeded };
    }
    pub fn acquireCoefficients(self: *const Cache, coefficients: []const Coefficient, profile: Profile) !Lease {
        const id = try coefficientIdentity(coefficients, profile);
        const state = self.state;
        state.mutex.lock();
        defer state.mutex.unlock();
        for (state.entries.items) |entry| if (std.mem.eql(u8, &id, &entry.key.identity)) {
            // Independently supplied equivalent setup is accepted only after
            // checking actual ordered native coefficients, not a producer ID.
            if (!std.meta.eql(profile, entry.key.profile) or !coefficientsEqual(coefficients, entry.key.tree.coefficients orelse return error.MissingFixedSetupCoefficients)) return error.FixedSetupDigestCollision;
            state.hits += 1;
            state.retain();
            return .{ .state = state, .key = &entry.key };
        };
        const a = state.budget.allocator();
        try state.entries.ensureUnusedCapacity(a, 1);
        const entry = try a.create(Entry);
        errdefer a.destroy(entry);
        entry.* = .{ .key = try WideFixedKey.seal(a, state.budget, coefficients, profile, id) };
        state.entries.appendAssumeCapacity(entry);
        state.seals += 1;
        state.retain();
        return .{ .state = state, .key = &entry.key };
    }
    /// CPU: cache.acquireFromKey(&setup.key, profile).
    /// Truth: cache.acquireFromKey(truth.key(), profile).
    /// The source key remains live until this synchronous call returns.
    pub fn acquireFromKey(self: *const Cache, source: anytype, profile: Profile) !Lease {
        try source.suite.validate();
        const coefficients = source.tree.coefficients orelse return error.MissingFixedSetupCoefficients;
        if (coefficients.len != source.tree.columns.len) return error.InvalidFixedSetupCoefficientShape;
        const source_blowup = source.suite.config().fri_config.log_blowup_factor;
        for (coefficients, source.tree.columns) |c, column| if (c.log_size > 28 or c.log_size + source_blowup != column.log_size) return error.InvalidFixedSetupCoefficientShape;
        return self.acquireCoefficients(coefficients, profile);
    }
};
