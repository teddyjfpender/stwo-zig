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
