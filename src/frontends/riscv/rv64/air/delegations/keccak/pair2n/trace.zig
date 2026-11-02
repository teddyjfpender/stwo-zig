//! One permutation witness via the unchanged row filler; two extra enable columns.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Base = @import("../trace.zig");
const K = @import("../layout.zig");
const E = @import("../equations.zig");
const L = @import("layout.zig");
const physical = @import("../../../witness.zig").physical;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    base: Base.Trace,
    main: []M,
    interaction: []M = &.{},
    pub fn init(a: std.mem.Allocator, inputs: []const Base.State, first: u32, log: u32) !Trace {
        try K.validateGeometry(inputs.len, first, log);
        const n = @as(usize, 1) << @intCast(log);
        const main = try a.alloc(M, L.MAIN * n);
        errdefer a.free(main);
        var base = try Base.Trace.initWithMainBuffer(a, inputs, first, log, main[0 .. K.MAIN * n]);
        errdefer base.deinit();
        var m: [K.MAIN]M = @splat(M.zero());
        for (0..n) |logical| {
            const p = physical(logical, log);
            m[K.ACTIVE_A] = base.main[K.ACTIVE_A * n + p];
            m[K.ACTIVE_B] = base.main[K.ACTIVE_B * n + p];
            var f: [K.FIXED]M = undefined;
            for (&f, 0..) |*v, c| v.* = base.fixed[c * n + p];
            const state = m[0..K.STATE];
            const row = E.RowFor(M){ .main = &m, .fixed = &f, .state_minus_two = state, .state_minus_one = state, .state_plus_one = state, .state_plus_two = state };
            main[L.ROUND_ENABLE * n + p] = E.roundActiveFor(M, row);
            main[L.IO_ENABLE * n + p] = E.ioActiveFor(M, row);
        }
        return .{ .allocator = a, .base = base, .main = main };
    }
    pub fn deinit(self: *Trace) void {
        self.base.deinit();
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Trace) void {
        self.allocator.free(self.main);
        self.main = &.{};
        self.base.main = &.{};
    }
};
