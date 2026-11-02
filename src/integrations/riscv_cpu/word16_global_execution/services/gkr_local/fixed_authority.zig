//! Receiver-derived immutable beta2 authority. No producer root/profile selects
//! a key. This engineering profile is not a whole-protocol security certificate.
const std = @import("std");
const W = @import("worker_protocol.zig");
pub const Fixed = @import("../../../word16_execution/fixed_setup.zig");
const SourceKey = @import("../../keccak/shared/key.zig").Key;
pub const PROFILE = "rv64-OM-localGKR-classicTruth-beta2-engineering/v1\x00";
pub const Binding = struct {
    lease: Fixed.Lease,
    source_root: [32]u8,
    source_suite: SourceKey.Suite,
    source_columns: usize,
    fixed_identity: [32]u8,
    fixed_root: [32]u8,
    source_coefficient_cells: usize,
    /// Receiver-selected named profile (exact config match at acquire).
    /// null: legacy beta2 structural family (bytes as before named profiles).
    profile: ?W.Candidate.Profile,
    pub fn acquire(cache: *const Fixed.Cache, source: anytype, config: W.PcsConfig) !Binding {
        try W.validateCandidateConfig(config);
        const profile = W.candidateProfile(config);
        if (!std.mem.eql(u8, &source.root, &source.tree.root())) return error.FixedSetupIdentityMismatch;
        var lease = try cache.acquireFromKey(source, .{ .log_blowup = config.fri_config.log_blowup_factor });
        errdefer lease.deinit();
        var cells: usize = 0;
        for (lease.key.tree.coefficients orelse return error.MissingFixedSetupCoefficients) |column| cells = try std.math.add(usize, cells, column.coeffs.len);
        return .{ .lease = lease, .source_root = source.root, .source_suite = source.suite, .source_columns = source.tree.columns.len, .fixed_identity = lease.key.identity, .fixed_root = lease.key.root, .source_coefficient_cells = cells, .profile = profile };
    }
    pub fn retain(self: *const Binding) Binding {
        var out = self.*;
        out.lease = self.lease.retain();
        return out;
    }
    pub fn deinit(self: *Binding) void {
        self.lease.deinit();
        self.* = undefined;
    }
    pub fn root(self: *const Binding) [32]u8 {
        return self.fixed_root;
    }
    /// Constant-size checks against a previously validated, sealed trusted
    /// source. This does NOT detect body mutation with an unchanged root. The
    /// cached candidate coefficients are independently owned and immutable;
    /// source setup must remain frozen. Producer bytes never supply this key.
    pub fn matchesSource(self: *const Binding, source: *const SourceKey) bool {
        return self.source_suite.eql(source.suite) and self.source_columns == source.tree.columns.len and
            std.mem.eql(u8, &self.source_root, &source.root) and std.mem.eql(u8, &self.source_root, &source.tree.root());
    }
    pub fn require(self: *const Binding, source: *const SourceKey, config: W.PcsConfig) !void {
        try W.validateCandidateConfig(config);
        if (W.candidateProfile(config) != self.profile) return error.WideCandidateProfileMismatch;
        try source.suite.validate();
        if (!self.matchesSource(source)) return error.FixedSetupIdentityMismatch;
        try self.lease.key.require(.{ .log_blowup = config.fri_config.log_blowup_factor }, self.fixed_identity, self.fixed_root);
    }
    /// Explicit full coefficient revalidation for a reconstructed/modified
    /// source; not repeated by worker lifecycle operations.
    pub fn revalidateSource(self: *const Binding, source: *const SourceKey, config: W.PcsConfig) !void {
        try self.require(source, config);
        try self.lease.key.requireSource(source);
    }
    pub fn statement(self: *const Binding, base: [32]u8) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update(PROFILE);
        h.update(&base);
        h.update(&self.fixed_identity);
        h.update(&self.fixed_root);
        // Named non-legacy profiles bind their identity; the proven profile
        // keeps its historical statement bytes (old bundles still verify).
        if (self.profile) |p| if (p.conjectured()) h.update(&W.Candidate.profileIdentity(p));
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn begin(self: *const Binding, config: W.PcsConfig, expected: @import("manifest.zig").ExpectedWorker) W.Channel {
        var ch = W.begin(config, expected);
        var tag: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(PROFILE, &tag, .{});
        W.digest(&ch, tag);
        W.digest(&ch, self.fixed_identity);
        W.digest(&ch, self.fixed_root);
        if (self.profile) |p| if (p.conjectured()) W.digest(&ch, W.Candidate.profileIdentity(p));
        return ch;
    }
    pub fn append(self: *const Binding, a: std.mem.Allocator, source: anytype, expected: [32]u8, scheme: *W.Scheme, ch: *W.Channel) !void {
        try self.require(source, scheme.config);
        try self.lease.key.append(a, scheme, ch, .{ .log_blowup = scheme.config.fri_config.log_blowup_factor }, self.fixed_identity, expected, scheme.config);
    }
};
