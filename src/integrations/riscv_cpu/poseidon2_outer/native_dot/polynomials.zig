//! Shared owned/borrowed evaluation preparation for the closed R7 native chips.
//! Independent FFT columns use the existing bounded proof pool only with its
//! thread-safe numerical budget allocator. No expanded values survive deinit.
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
        return initMode(a, trace, log_, widths, offsets, true);
    }
    pub fn initSerialForTest(a: std.mem.Allocator, trace: *const PC.Trace, log_: u32, widths: [3]usize, offsets: [3]usize) !Prepared {
        if (!@import("builtin").is_test) return error.NativeDotPreparationTestOnly;
        return initMode(a, trace, log_, widths, offsets, false);
    }
    fn initMode(a: std.mem.Allocator, trace: *const PC.Trace, log_: u32, widths: [3]usize, offsets: [3]usize, parallel: bool) !Prepared {
        const first = std.math.add(usize, widths[0], widths[1]) catch return error.NativeDotPhysicalTrace;
        const count = std.math.add(usize, first, widths[2]) catch return error.NativeDotPhysicalTrace;
        const polys = try a.alloc(Engine.air.component_trace.Poly, count);
        errdefer a.free(polys);
        const owned = try a.alloc(bool, count);
        errdefer a.free(owned);
        @memset(owned, false);
        var made: usize = 0;
        errdefer for (polys[0..made], owned[0..made]) |poly, take| if (take) a.free(@constCast(poly.values));
        // Validate immutable descriptors before publishing any helper work.
        for (widths, offsets, 0..) |width, start, tree| {
            if (tree >= trace.polys.items.len or start > trace.polys.items[tree].len or width > trace.polys.items[tree].len - start) return error.NativeDotPhysicalTrace;
            for (trace.polys.items[tree][start..][0..width]) |poly| {
                try poly.validate();
                if (poly.device != null) return error.DeviceColumnRequiresBackend;
                if (poly.log_size != log_ or poly.values.len == 0) {
                    const coefficients = poly.coefficients orelse return error.NativeDotCoefficientsRequired;
                    if (coefficients.logSize() > log_) return error.NativeDotPhysicalDegree;
                }
                polys[made] = poly;
                made += 1;
            }
        }
        var out = Prepared{ .allocator = a, .polys = polys, .owned = owned };
        const columns = Columns{ .prepared = &out, .log = log_ };
        // Arbitrary caller arenas are not assumed to permit concurrent allocs.
        if (parallel and Engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) {
            try @import("domain_tiles.zig").run(Columns, &columns, count, 1);
        } else try columns.runRange(0, count);
        return out;
    }
    const Columns = struct {
        prepared: *Prepared,
        log: u32,
        pub fn runRange(self: *const @This(), first: usize, end: usize) !void {
            if (first == end) return;
            const p = self.prepared;
            const domain = Canonic.new(self.log).circleDomain();
            for (first..end) |index| {
                const source = p.polys[index];
                if (source.log_size == self.log and source.values.len != 0) continue;
                const evaluation = try source.coefficients.?.evaluate(p.allocator, domain);
                p.polys[index] = .{ .log_size = self.log, .values = evaluation.values };
                p.owned[index] = true;
            }
        }
    };
    pub fn deinit(self: *Prepared) void {
        for (self.polys, self.owned) |poly, take| if (take) self.allocator.free(@constCast(poly.values));
        self.allocator.free(self.owned);
        self.allocator.free(self.polys);
        self.* = undefined;
    }
};
