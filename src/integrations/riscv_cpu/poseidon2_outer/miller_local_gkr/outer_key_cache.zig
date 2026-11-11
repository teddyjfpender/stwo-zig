//! Opt-in, Miller-only immutable R6 source keys. No process-global state and no
//! proposed outer VK is accepted. Requests retain separate statements/spans.
//! Cache operations are externally serialized; const leases may be read while
//! live. Destruction refuses every live lease; the explicit production barrier
//! may retire prover data only after all proving capabilities are released.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Native = @import("worker.zig");
const Full = @import("statement.zig");
const View = @import("leaf_test.zig").View;
const Template = @import("../pure_p2_gkr_template.zig");
const Skeleton = @import("../pure_p2_trace_skeleton.zig");
const Authority = @import("../native_omul/authority.zig").Key;
const Manifest = @import("../pure_p2_manifest.zig");
const Scope = @import("../native_omul/scope.zig");
const Retire = @import("../native_omul/verifier_key.zig");
const P = @import("../pure_p2_native.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Phase = enum { proving, verification };
const Entry = struct { fingerprint: [32]u8, authority: Authority };
const State = struct {
    budget: *Budget,
    entries: std.ArrayList(*Entry) = .empty,
    max_entries: usize,
    phase: Phase,
    leases: usize = 0,
    proving_leases: usize = 0,
    hits: usize = 0,
    misses: usize = 0,
};
/// Fingerprint includes source-owned immutable authority, never a claimed outer
/// key. Only validated coefficient lengths are advice; dimensions are source.
/// Calls, first_id, ordinal, statement and transcripts are public request data
/// and intentionally excluded. The built source uses canonical span1/first1;
/// source equations constrain the actual request words inside every proof.
pub fn fingerprint(key: *const Native.Key, span: Native.Span, lengths: []const u8) ![32]u8 {
    const geometry = try key.geometry(span);
    const instances = try geometry.instances();
    try Template.validateFor(&instances, lengths);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("OP_MILLER_R6_SOURCE_KEY_CACHE_V1\x00");
    h.update(&key.identity);
    h.update(&key.base.root);
    h.update(&key.base.profile.identity());
    // Freeze concrete source expression/compiler authority in this binary.
    inline for (.{ @embedFile("statement.zig"), @embedFile("child.zig"), @embedFile("projection.zig"), @embedFile("leaf_test.zig"), @embedFile("../native_omul/authority.zig"), @embedFile("../native_omul/row.zig") }) |source| h.update(source);
    var word: [4]u8 = undefined;
    for ([_]u32{ geometry.frontier_log, geometry.arithmetic_log, @intCast(lengths.len) }) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        h.update(&word);
    }
    h.update(lengths);
    return h.finalResult();
}
fn build(a: std.mem.Allocator, key: *const Native.Key, lengths: []const u8) !Authority {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const span = Native.Span{ .calls = 1, .first_id = 1 };
    const geometry = try key.geometry(span);
    const instances = try geometry.instances();
    try Template.validateFor(&instances, lengths);
    const shape = try Full.geometry(scratch, key, span);
    const values = try Skeleton.init(scratch, &shape);
    var proof = try Template.skeletonFor(scratch, &instances, lengths);
    const root = P.hashWords(&.{});
    const source = View{ .key = key, .span = span, .expected = try key.expected(span, 0), .manifest = root, .main = root, .receipt = root, .claims = @splat(V.common.O.zero()), .local = &proof, .shape = &shape, .values = &values };
    var scope = Scope.begin();
    defer scope.deinit();
    var trace = try source.build(a, true);
    defer trace.deinit();
    return Authority.init(a, &trace, key.base.profile);
}
pub const Lease = struct {
    state: *State,
    entry: *const Entry,
    span: Native.Span,
    expected: Manifest.Expected,
    proving: bool,
    live: bool = true,
    pub fn key(self: *const Lease) !*const Authority {
        if (!self.live) return error.MillerOuterCacheLeaseReleased;
        return &self.entry.authority;
    }
    pub fn proverKey(self: *const Lease) !*const Authority {
        try self.requireProving();
        return self.key();
    }
    pub fn requireView(self: *const Lease, source: View) !void {
        if (!self.live) return error.MillerOuterCacheLeaseReleased;
        try Native.validateExpected(source.key, source.span, source.expected);
        if (!std.meta.eql(self.span, source.span) or !std.meta.eql(self.expected, source.expected)) return error.MillerOuterCacheRequestMismatch;
        var arena = std.heap.ArenaAllocator.init(self.state.budget.allocator());
        defer arena.deinit();
        const instances = try (try source.key.geometry(source.span)).instances();
        const lengths = try Template.fromProofFor(arena.allocator(), &instances, source.local);
        if (!std.mem.eql(u8, &self.entry.fingerprint, &try fingerprint(source.key, source.span, lengths))) return error.MillerOuterCacheClassMismatch;
        if (source.values.cap_log != 0) return error.OpRootLeafCapVariant;
    }
    pub fn requireProving(self: *const Lease) !void {
        if (!self.live) return error.MillerOuterCacheLeaseReleased;
        if (!self.proving or self.state.phase != .proving) return error.MillerOuterCacheProvingClosed;
    }
    /// Keep immutable verifier metadata alive for folds, but irrevocably end
    /// this leaf's use of the shared class's large proving buffers.
    pub fn releaseProving(self: *Lease) !void {
        try self.requireProving();
        std.debug.assert(self.state.proving_leases != 0);
        self.state.proving_leases -= 1;
        self.proving = false;
    }
    pub fn release(self: *Lease) !void {
        if (!self.live) return error.MillerOuterCacheLeaseReleased;
        std.debug.assert(self.state.leases > 0);
        if (self.proving) {
            std.debug.assert(self.state.proving_leases != 0);
            self.state.proving_leases -= 1;
        }
        self.state.leases -= 1;
        self.live = false;
    }
};
pub const Snapshot = struct { bytes: Budget.Snapshot, classes: usize, leases: usize, proving_leases: usize, hits: usize, misses: usize, phase: Phase };
pub const Cache = struct {
    state: *State,
    pub fn init(a: std.mem.Allocator, byte_limit: usize, max_entries: usize) !Cache {
        return initMode(a, byte_limit, max_entries, .proving);
    }
    /// A fresh final receiver builds its own cache; it never imports a producer
    /// cache or key. Prover storage retires immediately after independent build.
    pub fn initForVerification(a: std.mem.Allocator, byte_limit: usize, max_entries: usize) !Cache {
        return initMode(a, byte_limit, max_entries, .verification);
    }
    fn initMode(a: std.mem.Allocator, byte_limit: usize, max_entries: usize, phase: Phase) !Cache {
        if (byte_limit == 0 or max_entries == 0 or max_entries > 256) return error.InvalidMillerOuterCacheLimits;
        const budget = try Budget.createRetainingParent(a, byte_limit);
        errdefer budget.destroy();
        const state = try budget.allocator().create(State);
        state.* = .{ .budget = budget, .max_entries = max_entries, .phase = phase };
        return .{ .state = state };
    }
    pub fn snapshot(self: *const Cache) Snapshot {
        const s = self.state;
        return .{ .bytes = s.budget.snapshot(), .classes = s.entries.items.len, .leases = s.leases, .proving_leases = s.proving_leases, .hits = s.hits, .misses = s.misses, .phase = s.phase };
    }
    pub fn acquireForProving(self: *Cache, key: *const Native.Key, span: Native.Span, ordinal: u32, lengths: []const u8) !Lease {
        if (self.state.phase != .proving) return error.MillerOuterCacheProvingClosed;
        return self.acquire(key, span, ordinal, lengths, true);
    }
    pub fn acquireForVerification(self: *Cache, key: *const Native.Key, span: Native.Span, ordinal: u32, lengths: []const u8) !Lease {
        return self.acquire(key, span, ordinal, lengths, false);
    }
    fn acquire(self: *Cache, key: *const Native.Key, span: Native.Span, ordinal: u32, lengths: []const u8, proving: bool) !Lease {
        const id = try fingerprint(key, span, lengths);
        const expected = try key.expected(span, ordinal);
        const s = self.state;
        var found: ?*Entry = null;
        for (s.entries.items) |entry| if (std.mem.eql(u8, &entry.fingerprint, &id)) {
            found = entry;
            break;
        };
        if (found == null) {
            if (s.entries.items.len >= s.max_entries) return error.MillerOuterCacheEntryLimit;
            const a = s.budget.allocator();
            try s.entries.ensureUnusedCapacity(a, 1);
            const entry = try a.create(Entry);
            errdefer a.destroy(entry);
            entry.* = .{ .fingerprint = id, .authority = try build(a, key, lengths) };
            if (s.phase == .verification) Retire.retireProverData(&entry.authority);
            s.entries.appendAssumeCapacity(entry);
            s.misses += 1;
            found = entry;
        } else s.hits += 1;
        const next_leases = try std.math.add(usize, s.leases, 1);
        const next_proving = if (proving) try std.math.add(usize, s.proving_leases, 1) else s.proving_leases;
        s.leases = next_leases;
        s.proving_leases = next_proving;
        return .{ .state = s, .entry = found.?, .span = span, .expected = expected, .proving = proving };
    }
    /// Explicit end-of-proving barrier. A lease can no longer accidentally
    /// retire a shared class while another leaf still needs its prover data.
    pub fn finishProving(self: *Cache) !void {
        const s = self.state;
        if (s.leases != 0) return error.MillerOuterCacheLiveLeases;
        return self.finishProvingWithVerificationLeases();
    }
    /// Session barrier after every leaf has relinquished its proving use.
    /// Read-only leases still pin the immutable key through topology/folding.
    /// The historical finishProving() API retains its stricter refusal rule.
    pub fn finishProvingWithVerificationLeases(self: *Cache) !void {
        const s = self.state;
        if (s.proving_leases != 0) return error.MillerOuterCacheLiveProvingLeases;
        if (s.phase == .verification) return;
        for (s.entries.items) |entry| Retire.retireProverData(&entry.authority);
        s.phase = .verification;
    }
    pub fn deinit(self: *Cache) !void {
        const s = self.state;
        if (s.leases != 0) return error.MillerOuterCacheLiveLeases;
        const budget = s.budget;
        const a = budget.allocator();
        for (s.entries.items) |entry| {
            entry.authority.deinit();
            a.destroy(entry);
        }
        s.entries.deinit(a);
        a.destroy(s);
        budget.destroy();
        self.* = undefined;
    }
};
