//! Canonical geometry contract for experimental compact range providers.
//! Identity is meaningful only when pinned by the caller's admitted statement;
//! a digest supplied with an untrusted witness is never an admission authority.
const std = @import("std");
const core = @import("stwo_core");
const schema = @import("../../air/lookups/tables/schema.zig");
const provider = @import("compact_range_provider.zig");
pub const kinds = [_]schema.Kind{ .range_check_20, .range_check_8_11, .range_check_8_8_4 };
pub const VERSION: u32 = 1;
pub const MIN_LOG: u32 = 4;
pub const Shape = struct {
    n_rows: u32,
    log_size: u32,
    pub fn canonical(kind: schema.Kind, count: usize) !Shape {
        _ = try kindIndex(kind);
        if (count > schema.size(kind)) return error.InvalidCompactRangeGeometry;
        return .{ .n_rows = @intCast(count), .log_size = @max(MIN_LOG, std.math.log2_int_ceil(usize, @max(1, count))) };
    }
    pub fn validate(self: Shape, kind: schema.Kind) !void {
        if (!std.meta.eql(self, try canonical(kind, self.n_rows))) return error.InvalidCompactRangeGeometry;
    }
    pub fn paddedRows(self: Shape, kind: schema.Kind) !u64 {
        try self.validate(kind);
        return @as(u64, 1) << @intCast(self.log_size);
    }
};
pub fn kindIndex(kind: schema.Kind) !usize {
    return switch (kind) {
        .range_check_20 => 0,
        .range_check_8_11 => 1,
        .range_check_8_8_4 => 2,
        else => error.UnsupportedCompactRangeKind,
    };
}
pub const Plan = struct {
    shapes: [kinds.len]Shape,
    pub fn canonical(counts: [kinds.len]usize) !Plan {
        var self: Plan = undefined;
        for (kinds, counts, &self.shapes) |kind, count, *shape| shape.* = try Shape.canonical(kind, count);
        return self;
    }
    pub fn validate(self: Plan) !void {
        for (kinds, self.shapes) |kind, shape| try shape.validate(kind);
    }
    /// Bind version, relation kind, exact real/padded geometry and typed AIR
    /// identities, rather than hashing only witness buffer sizes.
    pub fn identity(self: Plan) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.Blake3.init(.{});
        h.update("stwo.riscv.compact-range.geometry.v1");
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, VERSION, .little);
        h.update(&bytes);
        inline for (kinds, 0..) |kind, i| {
            const Air = provider.Provider(kind);
            for ([_]u32{ @intFromEnum(kind), self.shapes[i].n_rows, self.shapes[i].log_size, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT }) |value| {
                std.mem.writeInt(u32, &bytes, value, .little);
                h.update(&bytes);
            }
            h.update(&Air.SEMANTIC_DIGEST);
        }
        var digest: [32]u8 = undefined;
        h.final(&digest);
        return digest;
    }
    /// Every padded row contributes one byte request, including zero padding.
    /// Original signed multiplicities do not scale this additional request.
    pub fn additionalByteTerms(self: Plan) !u64 {
        var total: u64 = 0;
        for (kinds, self.shapes) |kind, shape| total = try std.math.add(u64, total, try shape.paddedRows(kind));
        return total;
    }
    pub fn extendByteBound(self: Plan, base: u64) !u64 {
        const bound = try std.math.add(u64, base, try self.additionalByteTerms());
        if (bound >= core.fields.m31.Modulus) return error.CoefficientBoundExceeded;
        return bound;
    }
    pub fn admit(self: Plan, expected: [32]u8) !void {
        if (!std.mem.eql(u8, &(try self.identity()), &expected)) return error.UntrustedCompactRangeGeometry;
    }
};
