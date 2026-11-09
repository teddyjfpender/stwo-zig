//! Shared owned/borrowed evaluation preparation for the closed R7 native chips.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const PC = Engine.air.component_prover.ForField(Core.fields.om31.OM31);
const Canonic = Core.poly.circle.canonic.CanonicCoset;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    polys: []Engine.air.component_trace.Poly,
    owned: []bool,
    pub fn init(a: std.mem.Allocator, trace: *const PC.Trace, log_: u32, widths: [3]usize, offsets: [3]usize) !Prepared {
        const count = widths[0] + widths[1] + widths[2];
        const polys = try a.alloc(Engine.air.component_trace.Poly, count);
        errdefer a.free(polys);
        const owned = try a.alloc(bool, count);
        errdefer a.free(owned);
        @memset(owned, false);
        var made: usize = 0;
        errdefer for (polys[0..made], owned[0..made]) |poly, take| if (take) a.free(@constCast(poly.values));
        const domain = Canonic.new(log_).circleDomain();
        for (widths, offsets, 0..) |width, start, tree| {
            if (tree >= trace.polys.items.len or start + width > trace.polys.items[tree].len) return error.NativeDotPhysicalTrace;
            for (trace.polys.items[tree][start..][0..width]) |poly| {
                try poly.validate();
                if (poly.device != null) return error.DeviceColumnRequiresBackend;
                if (poly.log_size == log_ and poly.values.len != 0) {
                    polys[made] = poly;
                } else {
                    const coefficients = poly.coefficients orelse return error.NativeDotCoefficientsRequired;
                    if (coefficients.logSize() > log_) return error.NativeDotPhysicalDegree;
                    const evaluation = try coefficients.evaluate(a, domain);
                    polys[made] = .{ .log_size = log_, .values = evaluation.values };
                    owned[made] = true;
                }
                made += 1;
            }
        }
        return .{ .allocator = a, .polys = polys, .owned = owned };
    }
    pub fn deinit(self: *Prepared) void {
        for (self.polys, self.owned) |poly, take| if (take) self.allocator.free(@constCast(poly.values));
        self.allocator.free(self.owned);
        self.allocator.free(self.polys);
        self.* = undefined;
    }
};
