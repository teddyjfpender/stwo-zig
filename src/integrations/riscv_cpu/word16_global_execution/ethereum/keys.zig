//! Request-independent setup cache scoped to one independently loaded image.
//! Geometry selects cost, never software identity or statement authority.
const std = @import("std");
const R = @import("../services/roster.zig");
const W = @import("../services/wire.zig");
const K = @import("../keccak/shared/roster.zig");
const S = @import("../secp/roster.zig");
const H = @import("../sha256/roster.zig");
const Ar = @import("../arith256/roster.zig");
const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
const ImmutableCaches = @import("../../word16_execution/setup.zig").ImmutableCaches;
const NativeCache = @import("../../word16_execution/fixed_native_cache.zig");
const Image = @import("../../word16_execution/expected_image.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    cpus: []*const R.CpuSetup,
    truths: []R.Truth,
    cpu_owners: std.ArrayList(*R.CpuSetup) = .{},
    keccak_owners: std.ArrayList(*K.TruthSetup) = .{},
    secp_owners: std.ArrayList(*S.TruthSetup) = .{},
    sha256_owners: std.ArrayList(*H.TruthSetup) = .{},
    arith256_owners: std.ArrayList(*Ar.TruthSetup) = .{},
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, false, Suite.production(), .{});
    }
    pub fn initRetiring(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, true, Suite.production(), .{});
    }
    pub fn initWithSuite(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite) !Owner {
        return initPolicy(a, image, cpu, truth, retire, suite, .{});
    }
    pub fn initWithNativeCache(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, cache: *const NativeCache.Cache) !Owner {
        return initWithSuiteAndNativeCache(a, image, cpu, truth, false, Suite.production(), cache);
    }
    pub fn initRetiringWithNativeCache(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, cache: *const NativeCache.Cache) !Owner {
        return initWithSuiteAndNativeCache(a, image, cpu, truth, true, Suite.production(), cache);
    }
    pub fn initWithSuiteAndNativeCache(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite, cache: *const NativeCache.Cache) !Owner {
        return initWithSuiteAndCaches(a, image, cpu, truth, retire, suite, .{ .native = cache });
    }
    pub fn initWithSuiteAndCaches(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite, caches: ImmutableCaches) !Owner {
        return initPolicy(a, image, cpu, truth, retire, suite, caches);
    }
    fn initPolicy(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite, caches: ImmutableCaches) !Owner {
        try suite.validate();
        const cpus = try a.alloc(*const R.CpuSetup, cpu.len);
        const truths = a.alloc(R.Truth, truth.len) catch |err| {
            a.free(cpus);
            return err;
        };
        var self = Owner{ .allocator = a, .cpus = cpus, .truths = truths };
        errdefer self.deinit();
        for (cpu, cpus) |d, *out| {
            var found: ?*const R.CpuSetup = null;
            for (self.cpu_owners.items) |s| if (std.meta.eql(s.materials.geometry, d.geometry) and std.meta.eql(s.bridges, d.bridges)) {
                found = s;
                break;
            };
            if (found) |s| {
                out.* = s;
                continue;
            }
            try self.cpu_owners.ensureUnusedCapacity(a, 1);
            const s = try a.create(R.CpuSetup);
            errdefer a.destroy(s);
            s.* = try R.CpuSetup.initWithAuthorityAndSuiteAndCaches(a, &image.authority, d.geometry, d.bridges, suite, caches);
            errdefer s.deinit();
            if (retire) try s.releaseFixedWitness();
            self.cpu_owners.appendAssumeCapacity(s);
            out.* = s;
        }
        for (truth, truths) |d, *out| switch (d.family) {
            .keccak => {
                var found: ?*const K.TruthSetup = null;
                for (self.keccak_owners.items) |s| if (s.log == d.logs[0]) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.keccak_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(K.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try K.TruthSetup.initWithSuite(a, d.logs[0], suite);
                    self.keccak_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .keccak = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
            .add, .double => {
                const kind: @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1.program.Kind = if (d.family == .add) .add else .double;
                var found: ?*const S.TruthSetup = null;
                for (self.secp_owners.items) |s| if (s.kind == kind and std.meta.eql(s.logs, d.logs)) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.secp_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(S.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try S.TruthSetup.initWithSuite(a, kind, d.logs, suite);
                    self.secp_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .secp = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
            .sha256 => {
                if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                var found: ?*const H.TruthSetup = null;
                for (self.sha256_owners.items) |s| if (s.log == d.logs[0]) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.sha256_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(H.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try H.TruthSetup.initWithSuite(a, d.logs[0], suite);
                    self.sha256_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .sha256 = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
            .arith256_mod => {
                if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                var found: ?*const Ar.TruthSetup = null;
                for (self.arith256_owners.items) |s| if (s.log == d.logs[0]) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.arith256_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(Ar.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try Ar.TruthSetup.initWithSuite(a, d.logs[0], suite);
                    self.arith256_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .arith256_mod = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
        };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        for (self.cpu_owners.items) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.keccak_owners.items) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.secp_owners.items) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.sha256_owners.items) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.sha256_owners.deinit(a);
        for (self.arith256_owners.items) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.arith256_owners.deinit(a);
        self.cpu_owners.deinit(a);
        self.keccak_owners.deinit(a);
        self.secp_owners.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        self.* = undefined;
    }
};
