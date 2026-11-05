//! Request-independent setup cache scoped to one independently loaded image.
//! Geometry selects cost, never software identity or statement authority.
const std = @import("std");
const R = @import("../services/roster.zig");
const W = @import("../services/wire.zig");
const K = @import("../keccak/shared/roster.zig");
const S = @import("../secp/roster.zig");
const H = @import("../sha256/roster.zig");
const Ar = @import("../arith256/roster.zig");
const Cv = @import("../curves/roster.zig");
const SR = @import("../secp/row_roster.zig");
const Types = @import("../services/types.zig");
const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
const ImmutableCaches = @import("../../word16_execution/setup.zig").ImmutableCaches;
const NativeCache = @import("../../word16_execution/fixed_native_cache.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const owner_fields = .{ "cpu_owners", "keccak_owners", "secp_owners", "sha256_owners", "arith256_owners", "curve_owners", "secp_row_owners" };
pub const SetupCache = @import("setup_cache.zig");
pub const Owner = struct {
    /// Shared immutable prefixes remain owned by the sequential resident session.
    borrowed_prefix: [7]usize = @splat(0),
    allocator: std.mem.Allocator,
    cpus: []*const R.CpuSetup,
    truths: []R.Truth,
    cpu_owners: std.ArrayList(*R.CpuSetup) = .{},
    keccak_owners: std.ArrayList(*K.TruthSetup) = .{},
    secp_owners: std.ArrayList(*S.TruthSetup) = .{},
    sha256_owners: std.ArrayList(*H.TruthSetup) = .{},
    arith256_owners: std.ArrayList(*Ar.TruthSetup) = .{},
    /// Curve/field truth keys depend only on (op, log).
    curve_owners: std.ArrayList(*Cv.TruthSetup) = .{},
    /// secp row truth keys depend only on (kind, log).
    secp_row_owners: std.ArrayList(*SR.TruthSetup) = .{},
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, false, Suite.production(), .{}, null);
    }
    pub fn initRetiring(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, true, Suite.production(), .{}, null);
    }
    pub fn initWithSuite(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite) !Owner {
        return initPolicy(a, image, cpu, truth, retire, suite, .{}, null);
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
        return initPolicy(a, image, cpu, truth, retire, suite, caches, null);
    }
    /// The caller independently binds shared to the authenticated program and
    /// suite, serializes requests, and keeps its allocator alive through teardown.
    pub fn initWithSharedCache(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, suite: Suite, caches: ImmutableCaches, shared: *Owner) !Owner {
        return initPolicy(a, image, cpu, truth, true, suite, caches, shared);
    }
    /// Candidate-route setup borrowed from a receiver-owned resident/persisted
    /// cache (`setup_cache.zig`). Components are owned by `cache`, which must
    /// outlive this owner, `caches` and every lease derived from them.
    pub fn initResident(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite, caches: ImmutableCaches, cache: *SetupCache.Cache) !Owner {
        try suite.validate();
        const cpus = try a.alloc(*const R.CpuSetup, cpu.len);
        const truths = a.alloc(R.Truth, truth.len) catch |err| {
            a.free(cpus);
            return err;
        };
        var self = Owner{ .allocator = a, .cpus = cpus, .truths = truths };
        errdefer self.deinit();
        const Builders = struct {
            const Cpu = struct {
                a: std.mem.Allocator,
                image: *const Image.Owner,
                d: W.CpuDeclaration,
                suite: Suite,
                caches: ImmutableCaches,
                retire: bool,
                pub fn build(b: @This()) !R.CpuSetup {
                    var s = try R.CpuSetup.initWithAuthorityAndSuiteAndCaches(b.a, &b.image.authority, b.d.geometry, b.d.bridges, b.suite, b.caches);
                    errdefer s.deinit();
                    if (b.retire) try s.releaseFixedWitness();
                    // Resident components outlive this request's Image (a
                    // session-owned cache serves later blocks): take custody
                    // of the raw ROM arrays, exactly as the session key cache
                    // does. Copies only; no setup value changes.
                    try s.materials.program.retainRawAuthority();
                    return s;
                }
            };
            const Keccak = struct {
                a: std.mem.Allocator,
                log: u32,
                suite: Suite,
                policy: K.TruthSetup.Policy,
                pub fn build(b: @This()) !K.TruthSetup {
                    return K.TruthSetup.initPolicy(b.a, b.log, b.suite, b.policy);
                }
            };
            const SecpRow = struct {
                a: std.mem.Allocator,
                kind: SR.Kind,
                log: u32,
                suite: Suite,
                pub fn build(b: @This()) !SR.TruthSetup {
                    return SR.TruthSetup.initWithSuite(b.a, b.kind, b.log, b.suite);
                }
            };
            const Secp = struct {
                a: std.mem.Allocator,
                kind: @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1.program.Kind,
                logs: @FieldType(W.TruthDeclaration, "logs"),
                suite: Suite,
                pub fn build(b: @This()) !S.TruthSetup {
                    return S.TruthSetup.initWithSuite(b.a, b.kind, b.logs, b.suite);
                }
            };
            const Sha = struct {
                a: std.mem.Allocator,
                log: u32,
                suite: Suite,
                pub fn build(b: @This()) !H.TruthSetup {
                    return H.TruthSetup.initWithSuite(b.a, b.log, b.suite);
                }
            };
            const Arith = struct {
                a: std.mem.Allocator,
                log: u32,
                suite: Suite,
                pub fn build(b: @This()) !Ar.TruthSetup {
                    return Ar.TruthSetup.initWithSuite(b.a, b.log, b.suite);
                }
            };
            const Curve = struct {
                a: std.mem.Allocator,
                op: @FieldType(Cv.TruthSetup, "op"),
                log: u32,
                suite: Suite,
                pub fn build(b: @This()) !Cv.TruthSetup {
                    return Cv.TruthSetup.initWithSuite(b.a, b.op, b.log, b.suite);
                }
            };
        };
        const Jobs = struct {
            a: std.mem.Allocator,
            image: *const Image.Owner,
            cpu: []const W.CpuDeclaration,
            truth: []const W.TruthDeclaration,
            cpus: []*const R.CpuSetup,
            truths: []R.Truth,
            suite: Suite,
            suite_id: [32]u8,
            caches: ImmutableCaches,
            retire: bool,
            cache: *SetupCache.Cache,
            order: []const usize,
            fn run(j: *const @This(), slot: usize) anyerror!void {
                const index = j.order[slot];
                const al = j.a;
                const st = j.suite;
                const sid = j.suite_id;
                const c = j.cache;
                if (index < j.cpu.len) {
                    const d = j.cpu[index];
                    j.cpus[index] = try c.obtain(R.CpuSetup, "cpu", .{ .suite = sid, .retire = j.retire, .geometry = d.geometry, .bridges = d.bridges }, true, Builders.Cpu{ .a = al, .image = j.image, .d = d, .suite = st, .caches = j.caches, .retire = j.retire });
                    return;
                }
                const d = j.truth[index - j.cpu.len];
                const out = &j.truths[index - j.cpu.len];
                switch (d.family) {
                    .keccak => {
                        const policy = try @import("../services/wire.zig").keccakPolicy(d.logs[1]);
                        const s = try c.obtain(K.TruthSetup, "keccak", .{ .suite = sid, .log = d.logs[0], .policy = policy }, false, Builders.Keccak{ .a = al, .log = d.logs[0], .suite = st, .policy = policy });
                        out.* = .{ .keccak = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    },
                    .add, .double => if (W.isSecpRow(d)) {
                        const kind: SR.Kind = if (d.family == .add) .add else .double;
                        const s = try c.obtain(SR.TruthSetup, "secp_row", .{ .suite = sid, .kind = kind, .log = d.logs[0] }, false, Builders.SecpRow{ .a = al, .kind = kind, .log = d.logs[0], .suite = st });
                        out.* = .{ .secp_row = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    } else {
                        const kind: @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1.program.Kind = if (d.family == .add) .add else .double;
                        const s = try c.obtain(S.TruthSetup, "secp", .{ .suite = sid, .kind = kind, .logs = d.logs }, false, Builders.Secp{ .a = al, .kind = kind, .logs = d.logs, .suite = st });
                        out.* = .{ .secp = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    },
                    .sha256 => {
                        if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                        const s = try c.obtain(H.TruthSetup, "sha256", .{ .suite = sid, .log = d.logs[0] }, false, Builders.Sha{ .a = al, .log = d.logs[0], .suite = st });
                        out.* = .{ .sha256 = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    },
                    .arith256_mod => {
                        if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                        const s = try c.obtain(Ar.TruthSetup, "arith256_mod", .{ .suite = sid, .log = d.logs[0] }, false, Builders.Arith{ .a = al, .log = d.logs[0], .suite = st });
                        out.* = .{ .arith256_mod = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    },
                    .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont, .bls12_381_g1_add, .bls12_381_g1_double => {
                        if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                        const op = Types.curveOp(d.family).?;
                        const s = try c.obtain(Cv.TruthSetup, "curve", .{ .suite = sid, .op = op, .log = d.logs[0] }, false, Builders.Curve{ .a = al, .op = op, .log = d.logs[0], .suite = st });
                        out.* = .{ .curve = .{ .setup = s, .first_id = d.first_id, .calls = d.calls } };
                    },
                }
            }
        };
        const order = try classBuildOrder(a, cpu, truth, cache.unique_classes_first);
        defer a.free(order);
        const jobs = Jobs{ .order = order, .a = a, .image = image, .cpu = cpu, .truth = truth, .cpus = cpus, .truths = truths, .suite = suite, .suite_id = try suite.identity(), .caches = caches, .retire = retire, .cache = cache };
        // Independent pure components; the cache serializes equal keys.
        try SetupCache.Cache.parallel(cpu.len + truth.len, cache.max_build_threads, &jobs, Jobs.run);
        return self;
    }
    fn initPolicy(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool, suite: Suite, caches: ImmutableCaches, shared: ?*Owner) !Owner {
        try suite.validate();
        const cpus = try a.alloc(*const R.CpuSetup, cpu.len);
        const truths = a.alloc(R.Truth, truth.len) catch |err| {
            a.free(cpus);
            return err;
        };
        var self = Owner{ .allocator = a, .cpus = cpus, .truths = truths };
        errdefer self.deinit();
        if (shared) |cached| inline for (owner_fields, 0..) |name, index| {
            try @field(self, name).appendSlice(a, @field(cached, name).items);
            self.borrowed_prefix[index] = @field(self, name).items.len;
        };
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
                // logs[1] selects the Keccak lookup profile (wire.keccakPolicy).
                const policy = try @import("../services/wire.zig").keccakPolicy(d.logs[1]);
                var found: ?*const K.TruthSetup = null;
                for (self.keccak_owners.items) |s| if (s.log == d.logs[0] and s.policy == policy) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.keccak_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(K.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try K.TruthSetup.initPolicy(a, d.logs[0], suite, policy);
                    self.keccak_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .keccak = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
            .add, .double => if (W.isSecpRow(d)) {
                const kind: SR.Kind = if (d.family == .add) .add else .double;
                var found: ?*const SR.TruthSetup = null;
                for (self.secp_row_owners.items) |s| if (s.kind == kind and s.log == d.logs[0]) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.secp_row_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(SR.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try SR.TruthSetup.initWithSuite(a, kind, d.logs[0], suite);
                    self.secp_row_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .secp_row = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            } else {
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
            .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont, .bls12_381_g1_add, .bls12_381_g1_double => {
                if (d.logs[1] != 0) return error.InvalidServicesTruthGeometry;
                const op = Types.curveOp(d.family).?;
                var found: ?*const Cv.TruthSetup = null;
                for (self.curve_owners.items) |s| if (s.op == op and s.log == d.logs[0]) {
                    found = s;
                    break;
                };
                if (found == null) {
                    try self.curve_owners.ensureUnusedCapacity(a, 1);
                    const s = try a.create(Cv.TruthSetup);
                    errdefer a.destroy(s);
                    s.* = try Cv.TruthSetup.initWithSuite(a, op, d.logs[0], suite);
                    self.curve_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .curve = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
            },
        };
        if (shared) |cached| {
            // New session-owned keys outlive this request's Image. Decoded
            // metadata is already leased; the raw ROM arrays also need custody.
            // All copies use the SAME bounded key allocator and finish before
            // transferring any owner into the persistent cache.
            for (self.cpu_owners.items[self.borrowed_prefix[0]..]) |setup| try setup.materials.program.retainRawAuthority();
            // Reserve every list before transferring any newly constructed owner.
            // Failure leaves both original cache and request cleanup ownership intact.
            inline for (owner_fields, 0..) |name, index| {
                const count = @field(self, name).items.len - self.borrowed_prefix[index];
                try @field(cached, name).ensureUnusedCapacity(a, count);
            }
            inline for (owner_fields, 0..) |name, index| {
                const list = &@field(self, name);
                @field(cached, name).appendSliceAssumeCapacity(list.items[self.borrowed_prefix[index]..]);
                self.borrowed_prefix[index] = list.items.len;
            }
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        for (self.cpu_owners.items[self.borrowed_prefix[0]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.keccak_owners.items[self.borrowed_prefix[1]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.secp_owners.items[self.borrowed_prefix[2]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        for (self.sha256_owners.items[self.borrowed_prefix[3]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.sha256_owners.deinit(a);
        for (self.arith256_owners.items[self.borrowed_prefix[4]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.arith256_owners.deinit(a);
        for (self.curve_owners.items[self.borrowed_prefix[5]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.curve_owners.deinit(a);
        for (self.secp_row_owners.items[self.borrowed_prefix[6]..]) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.secp_row_owners.deinit(a);
        self.cpu_owners.deinit(a);
        self.keccak_owners.deinit(a);
        self.secp_owners.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        self.* = undefined;
    }
};

/// Source-owned scheduling only: distinct cache keys precede duplicate callers,
/// so waiting for an equal class cannot occupy a worker before another unique
/// class is dispatched. Writes still target the original roster ordinal.
fn classBuildOrder(a: std.mem.Allocator, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, unique_first: bool) ![]usize {
    const n = try std.math.add(usize, cpu.len, truths.len);
    const order = try a.alloc(usize, n);
    if (!unique_first) {
        for (order, 0..) |*out, i| out.* = i;
        return order;
    }
    const duplicate = a.alloc(bool, n) catch |err| {
        a.free(order);
        return err;
    };
    defer a.free(duplicate);
    @memset(duplicate, false);
    for (0..n) |i| {
        for (0..i) |j| {
            const equal = if (i < cpu.len and j < cpu.len)
                std.meta.eql(cpu[i].geometry, cpu[j].geometry) and std.meta.eql(cpu[i].bridges, cpu[j].bridges)
            else if (i >= cpu.len and j >= cpu.len)
                truths[i - cpu.len].family == truths[j - cpu.len].family and std.meta.eql(truths[i - cpu.len].logs, truths[j - cpu.len].logs)
            else
                false;
            if (equal) {
                duplicate[i] = true;
                break;
            }
        }
    }
    var at: usize = 0;
    for ([_]bool{ false, true }) |want_duplicate| for (duplicate, 0..) |d, i| if (d == want_duplicate) {
        order[at] = i;
        at += 1;
    };
    return order;
}

test "class-first setup dispatch preserves ordinals and distinguishes authoritative parameters" {
    const a = std.testing.allocator;
    var cpu = [_]W.CpuDeclaration{.{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }} ** 5;
    cpu[3].bridges.ls_dword = 6;
    const truths = [_]W.TruthDeclaration{
        .{ .family = .keccak, .logs = .{ 6, 0 }, .first_id = 1, .calls = 2 },
        .{ .family = .keccak, .logs = .{ 6, 0 }, .first_id = 3, .calls = 4 },
        .{ .family = .keccak, .logs = .{ 6, 1 }, .first_id = 7, .calls = 5 },
        .{ .family = .sha256, .logs = .{ 6, 0 }, .first_id = 1, .calls = 1 },
    };
    const order = try classBuildOrder(a, &cpu, &truths, true);
    defer a.free(order);
    try std.testing.expectEqualSlices(usize, &.{ 0, 3, 5, 7, 8, 1, 2, 4, 6 }, order);
    const serial = try classBuildOrder(a, &cpu, &truths, false);
    defer a.free(serial);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8 }, serial);
}
