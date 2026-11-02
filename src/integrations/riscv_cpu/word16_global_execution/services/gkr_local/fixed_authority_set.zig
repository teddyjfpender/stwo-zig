//! Ordered beta2 fixed authority derived from receiver-owned CPU/truth setup.
//! A cache lease, not producer metadata, owns each immutable key lifetime.
const std = @import("std");
const W = @import("worker_protocol.zig");
const F = @import("fixed_authority.zig");
const R = @import("../roster.zig");
pub const Set = struct {
    allocator: std.mem.Allocator,
    config: W.PcsConfig,
    cpu_count: usize,
    bindings: []F.Binding,
    source_validations: usize,
    source_coefficient_cells: usize,
    pub fn init(a: std.mem.Allocator, cache: *const F.Fixed.Cache, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig) !Set {
        try W.validateBeta2Config(config);
        const count = try std.math.add(usize, setups.len, truths.len);
        if (setups.len == 0 or count > 256) return error.WideBeta2FixedInventoryMismatch;
        const bindings = try a.alloc(F.Binding, count);
        errdefer a.free(bindings);
        var initialized: usize = 0;
        var validations: usize = 0;
        var cells: usize = 0;
        errdefer for (bindings[0..initialized]) |*binding| binding.deinit();
        for (setups, 0..) |setup, i| {
            const acquired = try acquireUnique(bindings[0..initialized], cache, &setup.key, config);
            bindings[i] = acquired.binding;
            initialized += 1;
            validations += @intFromBool(acquired.validated);
            if (acquired.validated) cells = try std.math.add(usize, cells, acquired.binding.source_coefficient_cells);
        }
        for (truths, 0..) |truth, i| {
            const acquired = try acquireUnique(bindings[0..initialized], cache, truth.key(), config);
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
        try W.validateBeta2Config(config);
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
