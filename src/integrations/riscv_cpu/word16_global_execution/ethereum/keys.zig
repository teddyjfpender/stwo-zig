//! Request-independent setup cache scoped to one independently loaded image.
//! Geometry selects cost, never software identity or statement authority.
const std = @import("std");
const R = @import("../services/roster.zig");
const W = @import("../services/wire.zig");
const K = @import("../keccak/shared/roster.zig");
const S = @import("../secp/roster.zig");
const Image = @import("../../word16_execution/expected_image.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    cpus: []*const R.CpuSetup,
    truths: []R.Truth,
    cpu_owners: std.ArrayList(*R.CpuSetup) = .{},
    keccak_owners: std.ArrayList(*K.TruthSetup) = .{},
    secp_owners: std.ArrayList(*S.TruthSetup) = .{},
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, false);
    }
    pub fn initRetiring(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration) !Owner {
        return initPolicy(a, image, cpu, truth, true);
    }
    fn initPolicy(a: std.mem.Allocator, image: *const Image.Owner, cpu: []const W.CpuDeclaration, truth: []const W.TruthDeclaration, retire: bool) !Owner {
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
            s.* = try R.CpuSetup.initWithAuthority(a, &image.authority, d.geometry, d.bridges);
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
                    s.* = try K.TruthSetup.init(a, d.logs[0]);
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
                    s.* = try S.TruthSetup.init(a, kind, d.logs);
                    self.secp_owners.appendAssumeCapacity(s);
                    found = s;
                }
                out.* = .{ .secp = .{ .setup = found.?, .first_id = d.first_id, .calls = d.calls } };
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
        self.cpu_owners.deinit(a);
        self.keccak_owners.deinit(a);
        self.secp_owners.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        self.* = undefined;
    }
};
