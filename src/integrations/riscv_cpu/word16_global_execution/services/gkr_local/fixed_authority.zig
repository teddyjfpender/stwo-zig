//! Receiver-derived immutable beta2 authority. No producer root/profile selects
//! a key. This engineering profile is not a whole-protocol security certificate.
const std = @import("std");
const W = @import("worker_protocol.zig");
pub const Fixed = @import("../../../word16_execution/fixed_setup.zig");
pub const PROFILE = "rv64-OM-localGKR-classicTruth-beta2-engineering/v1\x00";
pub const Binding = struct {
    lease: Fixed.Lease,
    pub fn acquire(cache: *const Fixed.Cache, source: anytype, config: W.PcsConfig) !Binding {
        try W.validateBeta2Config(config);
        return .{ .lease = try cache.acquireFromKey(source, .{ .log_blowup = 2 }) };
    }
    pub fn retain(self: *const Binding) Binding {
        return .{ .lease = self.lease.retain() };
    }
    pub fn deinit(self: *Binding) void {
        self.lease.deinit();
        self.* = undefined;
    }
    pub fn root(self: *const Binding) [32]u8 {
        return self.lease.key.root;
    }
    pub fn require(self: *const Binding, source: anytype, config: W.PcsConfig) !void {
        try W.validateBeta2Config(config);
        if (self.lease.key.descriptor.log_blowup != 2) return error.WideBeta2FixedDescriptorMismatch;
        try self.lease.key.requireSource(source);
    }
    pub fn statement(self: *const Binding, base: [32]u8) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update(PROFILE);
        h.update(&base);
        h.update(&self.lease.key.identity);
        h.update(&self.lease.key.root);
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn begin(self: *const Binding, config: W.PcsConfig, expected: @import("manifest.zig").ExpectedWorker) W.Channel {
        var ch = W.begin(config, expected);
        var tag: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(PROFILE, &tag, .{});
        W.digest(&ch, tag);
        W.digest(&ch, self.lease.key.identity);
        W.digest(&ch, self.lease.key.root);
        return ch;
    }
    pub fn append(self: *const Binding, a: std.mem.Allocator, source: anytype, expected: [32]u8, scheme: *W.Scheme, ch: *W.Channel) !void {
        try self.require(source, scheme.config);
        try self.lease.key.append(a, scheme, ch, .{ .log_blowup = 2 }, self.lease.key.identity, expected, scheme.config);
    }
};
