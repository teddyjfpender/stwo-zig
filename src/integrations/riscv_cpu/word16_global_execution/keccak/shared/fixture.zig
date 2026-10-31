//! Both service protocols consume the same captured advice fixture.
const std = @import("std");
const F = @import("../fixture.zig");
const R = @import("roster.zig");
const E = @import("execution.zig");
const P = @import("protocol.zig");
pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    truth: *R.TruthSetup,
    bundle: E.Bundle,
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn expected(self: *const Case) P.Expected {
        return F.Case.expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.truth.deinit();
        self.allocator.destroy(self.truth);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub fn init(a: std.mem.Allocator, mutation: F.Case.Mutation) !Case {
        var c = try F.Captured.init(a);
        defer c.deinit();
        c.mutate(mutation);
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[0].geometry(), 5);
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[1].geometry(), 5);
        errdefer s1.deinit();
        const truth = try a.create(R.TruthSetup);
        errdefer a.destroy(truth);
        truth.* = try R.TruthSetup.init(a, 5);
        errdefer truth.deinit();
        const bundle = try E.produce(a, &.{ s0, s1 }, truth, &.{ &c.native[0], &c.native[1] }, &c.advice, F.Case.expectedFor(c.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .truth = truth, .bundle = bundle };
    }
};

/// Four actual proofs: two CPU shards and two separately bounded truth workers.
pub const BoundedCase = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    truths: [2]*R.TruthSetup,
    bundle: E.BoundedBundle,
    pub fn keys(self: *const BoundedCase) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn roster(self: *const BoundedCase) [2]P.Truth {
        return .{ .{ .setup = self.truths[0], .first_id = 1, .calls = 1 }, .{ .setup = self.truths[1], .first_id = 2, .calls = 1 } };
    }
    pub fn expected(self: *const BoundedCase) P.Expected {
        return F.Case.expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn deinit(self: *BoundedCase) void {
        self.bundle.deinit(self.allocator);
        for (self.truths) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub fn init(a: std.mem.Allocator, mutation: F.Case.Mutation) !BoundedCase {
        var c = try F.Captured.init(a);
        defer c.deinit();
        c.mutate(mutation);
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[0].geometry(), 5);
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[1].geometry(), 5);
        errdefer s1.deinit();
        const t0 = try a.create(R.TruthSetup);
        errdefer a.destroy(t0);
        t0.* = try R.TruthSetup.init(a, 5);
        errdefer t0.deinit();
        const t1 = try a.create(R.TruthSetup);
        errdefer a.destroy(t1);
        t1.* = try R.TruthSetup.init(a, 5);
        errdefer t1.deinit();
        const bundle = try E.produceBounded(a, &.{ s0, s1 }, &.{ .{ .setup = t0, .first_id = 1, .calls = 1 }, .{ .setup = t1, .first_id = 2, .calls = 1 } }, &.{ &c.native[0], &c.native[1] }, &c.advice, F.Case.expectedFor(c.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .truths = .{ t0, t1 }, .bundle = bundle };
    }
};
