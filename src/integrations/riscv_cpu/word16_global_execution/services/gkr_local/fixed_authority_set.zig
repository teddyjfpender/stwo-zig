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
    pub fn init(a: std.mem.Allocator, cache: *const F.Fixed.Cache, setups: []const *const R.CpuSetup, truths: []const R.Truth, config: W.PcsConfig) !Set {
        try W.validateBeta2Config(config);
        const count = try std.math.add(usize, setups.len, truths.len);
        if (setups.len == 0 or count > 256) return error.WideBeta2FixedInventoryMismatch;
        const bindings = try a.alloc(F.Binding, count);
        errdefer a.free(bindings);
        var initialized: usize = 0;
        errdefer for (bindings[0..initialized]) |*binding| binding.deinit();
        for (setups, 0..) |setup, i| {
            bindings[i] = try F.Binding.acquire(cache, &setup.key, config);
            initialized += 1;
        }
        for (truths, 0..) |truth, i| {
            bindings[setups.len + i] = try F.Binding.acquire(cache, truth.key(), config);
            initialized += 1;
        }
        return .{ .allocator = a, .config = config, .cpu_count = setups.len, .bindings = bindings };
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
            W.digest(&ch, binding.lease.key.identity);
            W.digest(&ch, binding.root());
        }
        return ch.digestBytes();
    }
};
