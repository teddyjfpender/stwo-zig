const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Authority = @import("mass_authority.zig");
/// Native fixture check of actual raw query weights, not field claim sums.
pub const Counter = struct {
    totals: Authority.Globals = .{},
    pub fn emit(self: *@This(), relation: anytype, _: anytype, weight: M) void {
        self.observe(@tagName(relation), weight);
    }
    pub fn emitIo(self: *@This(), _: [11]M, weight: M) void {
        self.observe("kio", weight);
    }
    pub fn emitWire(self: *@This(), _: [35]M, weight: M) void {
        self.observe("wire", weight);
    }
    fn observe(self: *@This(), name: []const u8, weight: M) void {
        const std = @import("std");
        inline for (.{ "ram", "kio", "wire" }) |field| if (std.mem.eql(u8, name, field)) {
            const target = &@field(self.totals, field);
            if (weight.v > core.fields.m31.Modulus / 2) target.negative += core.fields.m31.Modulus - weight.v else target.positive += weight.v;
            return;
        };
        unreachable;
    }
};
