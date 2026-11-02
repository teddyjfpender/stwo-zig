//! Small full-execution fixture: two CPU shards and K/ADD/DOUBLE truths. Setup
//! authority is independently reconstructible; no legacy-Q proofs are produced.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const F = @import("../fixture.zig");
const R = @import("../roster.zig");
const KR = @import("../../keccak/shared/roster.zig");
const SR = @import("../../secp/roster.zig");
const C = @import("coordinator.zig");
const W = @import("worker_protocol.zig");
pub fn config() !W.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(W.O).FriConfig.init(0, 1, 12) };
}
pub const Keys = struct {
    allocator: std.mem.Allocator,
    cpus: [2]*R.CpuSetup,
    keccak: *KR.TruthSetup,
    add: *SR.TruthSetup,
    double: *SR.TruthSetup,
    pub fn pointers(self: *const Keys) [2]*const R.CpuSetup {
        return .{ self.cpus[0], self.cpus[1] };
    }
    pub fn truths(self: *const Keys) [3]R.Truth {
        return .{ .{ .keccak = .{ .setup = self.keccak, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = self.add, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = self.double, .first_id = 1, .calls = 1 } } };
    }
    pub fn init(a: std.mem.Allocator) !Keys {
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, .{ .cpu_log = 5 }, .{ .keccak = 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, .{ .cpu_log = 5 }, .{ .add = 5, .double = 5 });
        errdefer s1.deinit();
        const k = try a.create(KR.TruthSetup);
        errdefer a.destroy(k);
        k.* = try KR.TruthSetup.init(a, 5);
        errdefer k.deinit();
        const add = try a.create(SR.TruthSetup);
        errdefer a.destroy(add);
        add.* = try SR.TruthSetup.init(a, .add, .{ try A.crypto.secp256k1.layout.logSize(.product, A.crypto.secp256k1.program.get(.add), 1), try A.crypto.secp256k1.layout.logSize(.linear, A.crypto.secp256k1.program.get(.add), 1) });
        errdefer add.deinit();
        const double = try a.create(SR.TruthSetup);
        errdefer a.destroy(double);
        double.* = try SR.TruthSetup.init(a, .double, .{ try A.crypto.secp256k1.layout.logSize(.product, A.crypto.secp256k1.program.get(.double), 1), try A.crypto.secp256k1.layout.logSize(.linear, A.crypto.secp256k1.program.get(.double), 1) });
        return .{ .allocator = a, .cpus = .{ s0, s1 }, .keccak = k, .add = add, .double = double };
    }
    pub fn deinit(self: *Keys) void {
        const a = self.allocator;
        self.keccak.deinit();
        a.destroy(self.keccak);
        self.add.deinit();
        a.destroy(self.add);
        self.double.deinit();
        a.destroy(self.double);
        for (self.cpus) |s| {
            s.deinit();
            a.destroy(s);
        }
        self.* = undefined;
    }
};
pub const Case = struct {
    allocator: std.mem.Allocator,
    keys: Keys,
    bundle: C.Bundle,
    pub fn init(a: std.mem.Allocator) !Case {
        return initWithOptions(a, .{ .gkr_budget = 2 << 30 });
    }
    pub fn initWithOptions(a: std.mem.Allocator, options: C.Options) !Case {
        var captured = try F.Captured.init(a);
        defer captured.deinit();
        var keys = try Keys.init(a);
        errdefer keys.deinit();
        const bundle = try C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, F.expectedFor(captured.program.identity), try config(), options);
        return .{ .allocator = a, .keys = keys, .bundle = bundle };
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.keys.deinit();
        self.* = undefined;
    }
    pub fn verify(self: *const Case, a: std.mem.Allocator) !@import("execution.zig").Verified {
        return self.bundle.verify(a, &self.keys.pointers(), &self.keys.truths(), F.expectedFor(self.keys.cpus[0].materials.program.identity), try config());
    }
};
