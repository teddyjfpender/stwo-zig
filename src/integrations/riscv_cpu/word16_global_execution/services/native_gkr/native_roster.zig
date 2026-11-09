//! Receiver-owned physical roster and spans for the native-GKR format.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const V2 = @import("v2.zig");
const R = @import("roster.zig");
const CPU = @import("cpu_component.zig");
const Legacy = @import("../gkr_local/cpu_components.zig");
const Setup = @import("../roster.zig").CpuSetup;
const Wire = @import("../wire.zig");
const Catalog = @import("../gkr_local/truth_catalog.zig");
pub const Span = struct { fixed_offset: usize, main_offset: usize, inter_offset: usize, fixed: usize, main: usize, constraints: usize, degree: u8, split: u8, max_main_samples: u8 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    roster: R.Roster,
    spans: []Span,
    pub fn deinit(self: *Plan) void {
        self.roster.deinit();
        self.allocator.free(self.spans);
        self.* = undefined;
    }
};
pub fn cpu(a: std.mem.Allocator, setup: *const Setup) !Plan {
    var old = try Legacy.Plan.init(a, setup);
    defer old.deinit();
    const specs = try a.alloc(R.ComponentSpec, old.slots.len);
    defer a.free(specs);
    const spans = try a.alloc(Span, old.slots.len);
    errdefer a.free(spans);
    for (old.slots, specs, spans, 0..) |slot, *spec, *span, index| {
        const descriptor = CPU.Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = setup.materials.geometry.cpu_compact_decode };
        const shape = try CPU.Authority.shape(descriptor);
        spec.* = .{ .origin = CPU.Authority.Source.Frame.originWords(slot.origin), .row_log = slot.log, .terms = try CPU.terms(descriptor) };
        span.* = .{ .fixed_offset = slot.fixed_offset, .main_offset = slot.main_offset, .inter_offset = 16 * index, .fixed = shape.fixed, .main = shape.main, .constraints = shape.constraints + 3, .degree = 3, .split = 1, .max_main_samples = 2 };
    }
    return .{ .allocator = a, .roster = try V2.derive(a, specs), .spans = spans };
}
pub fn truth(a: std.mem.Allocator, d: Wire.TruthDeclaration) !Plan {
    if (d.family == .keccak) {
        const K = A.crypto.keccak;
        const policy = try @import("../gkr_local/truth_profile.zig").fromDeclaration(d);
        if (policy != .throughput_r27_v1 and policy != .triple_v2) return error.NativeGkrTruthPolicy;
        const specs = [_]R.ComponentSpec{
            .{ .origin = .{ 16 + @intFromEnum(d.family), 0 }, .row_log = d.logs[0], .terms = .{ @intCast(policy.lookups()), 0, @intCast(policy.ioLookups()), 0 } },
            .{ .origin = .{ 16 + @intFromEnum(d.family), 1 }, .row_log = policy.tableLog(.chi), .terms = .{ 1, 0, 0, 0 } },
            .{ .origin = .{ 16 + @intFromEnum(d.family), 2 }, .row_log = policy.tableLog(.xor5), .terms = .{ 1, 0, 0, 0 } },
        };
        const spans = try a.alloc(Span, 3);
        errdefer a.free(spans);
        spans[0] = .{ .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .fixed = K.layout.FIXED, .main = K.layout.MAIN, .constraints = K.layout.DIRECT + 3, .degree = 5, .split = 2, .max_main_samples = 5 };
        spans[1] = .{ .fixed_offset = K.layout.FIXED, .main_offset = K.layout.MAIN, .inter_offset = 16, .fixed = 7, .main = 1, .constraints = 3, .degree = 3, .split = 2, .max_main_samples = 1 };
        spans[2] = .{ .fixed_offset = K.layout.FIXED + 7, .main_offset = K.layout.MAIN + 1, .inter_offset = 32, .fixed = 7, .main = 1, .constraints = 3, .degree = 3, .split = 2, .max_main_samples = 1 };
        return .{ .allocator = a, .roster = try V2.derive(a, &specs), .spans = spans };
    }
    if (d.logs[1] != 0) return error.NativeGkrLegacyTruthUnsupported;
    const descriptor = try Catalog.descriptorForDeclaration(d);
    const queries = try Catalog.lookupCountsForDeclaration(d);
    const specs = [_]R.ComponentSpec{.{ .origin = .{ 16 + @intFromEnum(d.family), 0 }, .row_log = d.logs[0], .terms = .{ @intCast(if (queries.byte_queries_per_row == 0) 0 else queries.byte_queries_per_row + 1), 0, 0, @intCast(queries.wire_fractions_per_row) } }};
    const spans = try a.alloc(Span, 1);
    errdefer a.free(spans);
    spans[0] = .{ .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .fixed = descriptor.shape.fixed, .main = descriptor.shape.main, .constraints = descriptor.shape.constraints - descriptor.shape.byte_batches - descriptor.shape.wire_batches + 3, .degree = @intCast(descriptor.shape.degree), .split = if (descriptor.shape.degree > 3) 2 else 1, .max_main_samples = 2 };
    return .{ .allocator = a, .roster = try V2.derive(a, &specs), .spans = spans };
}

test "native receiver roster retains original r27 and wire-only fractions" {
    const a = std.testing.allocator;
    var sha = try truth(a, .{ .family = .sha256, .first_id = 1, .calls = 1, .logs = .{ 10, 0 } });
    defer sha.deinit();
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 4 }, sha.roster.components[0].terms);
    try std.testing.expectEqual(@as(usize, 1), sha.roster.instances.len);
    try std.testing.expectEqual(@as(usize, 16), R.BINDING_BASE_COLUMNS);
}
