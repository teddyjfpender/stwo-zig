//! Ordered beta2 fixed authority derived from receiver-owned CPU/truth setup.
//! A cache lease, not producer metadata, owns each immutable key lifetime.
const std = @import("std");
const W = @import("worker_protocol.zig");
const F = @import("fixed_authority.zig");
const R = @import("../roster.zig");
const SourceKey = @import("../../keccak/shared/key.zig").Key;
/// Only the resident session's OWNED, frozen source keys may enter this cache.
/// Pointer provenance restricts reuse to that same owner; independently rebuilt
/// keys still undergo complete coefficient validation, even with an equal root.
/// Entries and retained leases use the resident key owner's hard byte budget.
pub const ValidatedCatalogue = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    const Entry = struct { source: *const SourceKey, binding: F.Binding };
    pub fn clear(self: *ValidatedCatalogue) void {
        for (self.entries.items) |*entry| entry.binding.deinit();
        self.entries.clearAndFree(self.allocator);
    }
    pub fn deinit(self: *ValidatedCatalogue) void {
        self.clear();
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }
    fn acquire(self: *ValidatedCatalogue, cache: *const F.Fixed.Cache, source: *const SourceKey, config: W.PcsConfig) !Acquired {
        for (self.entries.items) |*entry| {
            if (entry.source != source or entry.binding.profile != W.candidateProfile(config) or entry.binding.lease.key.descriptor.log_blowup != config.fri_config.log_blowup_factor) continue;
            try entry.binding.require(source, config);
            return .{ .binding = entry.binding.retain(), .validated = false };
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const binding = try F.Binding.acquire(cache, source, config);
        self.entries.appendAssumeCapacity(.{ .source = source, .binding = binding });
        return .{ .binding = binding.retain(), .validated = true };
    }
};
pub const Set = struct {
    allocator: std.mem.Allocator,
    config: W.PcsConfig,
    cpu_count: usize,
    bindings: []F.Binding,
    source_validations: usize,
    source_coefficient_cells: usize,
    pub fn init(a: std.mem.Allocator, cache: *const F.Fixed.Cache, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig) !Set {
        return initPolicy(a, cache, setups, truths, config, null);
    }
    pub fn initWithValidatedCatalogue(a: std.mem.Allocator, cache: *const F.Fixed.Cache, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig, catalogue: *ValidatedCatalogue) !Set {
        return initPolicy(a, cache, setups, truths, config, catalogue);
    }
    fn initPolicy(a: std.mem.Allocator, cache: *const F.Fixed.Cache, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig, catalogue: ?*ValidatedCatalogue) !Set {
        try W.validateCandidateConfig(config);
        const count = try std.math.add(usize, setups.len, truths.len);
        if (setups.len == 0 or count > 256) return error.WideBeta2FixedInventoryMismatch;
        const bindings = try a.alloc(F.Binding, count);
        errdefer a.free(bindings);
        var initialized: usize = 0;
        var validations: usize = 0;
        var cells: usize = 0;
        errdefer for (bindings[0..initialized]) |*binding| binding.deinit();
        for (setups, 0..) |setup, i| {
            const acquired = if (catalogue) |owner| try owner.acquire(cache, &setup.key, config) else try acquireUnique(bindings[0..initialized], cache, &setup.key, config);
            bindings[i] = acquired.binding;
            initialized += 1;
            validations += @intFromBool(acquired.validated);
            if (acquired.validated) cells = try std.math.add(usize, cells, acquired.binding.source_coefficient_cells);
        }
        for (truths, 0..) |truth, i| {
            const acquired = if (catalogue) |owner| try owner.acquire(cache, truth.key(), config) else try acquireUnique(bindings[0..initialized], cache, truth.key(), config);
            bindings[setups.len + i] = acquired.binding;
            initialized += 1;
            validations += @intFromBool(acquired.validated);
            if (acquired.validated) cells = try std.math.add(usize, cells, acquired.binding.source_coefficient_cells);
        }
        return .{ .allocator = a, .config = config, .cpu_count = setups.len, .bindings = bindings, .source_validations = validations, .source_coefficient_cells = cells };
    }
    pub fn deinit(self: *Set) void {
        for (self.bindings) |*binding| binding.deinit();
        self.allocator.free(self.bindings);
        self.* = undefined;
    }
    pub fn require(self: *const Set, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig) !void {
        try W.validateCandidateConfig(config);
        if (!std.meta.eql(self.config, config) or self.cpu_count != setups.len or self.bindings.len != try std.math.add(usize, setups.len, truths.len)) return error.WideBeta2FixedInventoryMismatch;
        for (setups, self.bindings[0..setups.len]) |setup, *binding| try binding.require(&setup.key, config);
        for (truths, self.bindings[setups.len..]) |truth, *binding| try binding.require(truth.key(), config);
    }
    pub fn at(self: *const Set, index: usize) *const F.Binding {
        return &self.bindings[index];
    }
    /// Bind the complete receiver-ordered immutable context to execution scope.
    pub fn executionIdentity(self: *const Set, base: [32]u8) [32]u8 {
        var ch = W.Channel.init();
        W.digest(&ch, base);
        var tag: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(F.PROFILE, &tag, .{});
        W.digest(&ch, tag);
        // Non-legacy named profiles bind their identity (proven keeps bytes).
        if (W.candidateProfile(self.config)) |p| if (p.conjectured()) W.digest(&ch, W.Candidate.profileIdentity(p));
        ch.mixU64(self.cpu_count);
        ch.mixU64(self.bindings.len);
        for (self.bindings, 0..) |binding, ordinal| {
            ch.mixU64(ordinal);
            W.digest(&ch, binding.fixed_identity);
            W.digest(&ch, binding.root());
        }
        return ch.digestBytes();
    }
};

const Acquired = struct { binding: F.Binding, validated: bool };
fn acquireUnique(existing: []const F.Binding, cache: *const F.Fixed.Cache, source: anytype, config: W.PcsConfig) !Acquired {
    // A trusted original sealed Merkle root/suite/count is the immutable source
    // authority, not its pointer. Equivalent independently rebuilt source keys
    // can reuse the same validated candidate lease within this ordered set.
    for (existing) |*binding| if (binding.matchesSource(source)) {
        try binding.require(source, config);
        return .{ .binding = binding.retain(), .validated = false };
    };
    return .{ .binding = try F.Binding.acquire(cache, source, config), .validated = true };
}
