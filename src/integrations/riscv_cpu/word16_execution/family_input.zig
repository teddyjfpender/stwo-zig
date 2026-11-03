//! Compact family inputs at the capture/device boundary. These are native
//! execution facts and multiplicities, never padded field-column witnesses.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air.word16_v1;
pub const Kind = enum(u32) { alu = 0, binary = 1, shift = 2, zbb = 3 };
pub const Fact = extern struct {
    op: u32,
    multiplicity: u32,
    a: u64,
    b: u64,
    c: u64,
};
comptime {
    if (@sizeOf(Fact) != 32 or @offsetOf(Fact, "a") != 8 or @offsetOf(Fact, "c") != 24) @compileError("native family fact ABI changed");
}
pub const Batch = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    log: u32,
    function_mass: u32,
    facts: []Fact,
    fn allocate(a: std.mem.Allocator, kind: Kind, count: usize, weights: ?[]const u32, log: u32) !Batch {
        if (log < 5 or log > 26 or count > @as(usize, 1) << @intCast(log)) return error.InvalidDeviceFamilyGeometry;
        if (weights) |w| if (w.len != count) return error.InvalidDeviceFamilyWeights;
        var mass: u64 = if (weights == null) count else 0;
        if (weights) |w| for (w) |value| {
            if (value >= core.fields.m31.Modulus) return error.InvalidDeviceFamilyWeights;
            mass = try std.math.add(u64, mass, value);
            if (mass >= core.fields.m31.Modulus) return error.DeviceFamilyMultiplicityMassExceeded;
        };
        if (mass >= core.fields.m31.Modulus) return error.DeviceFamilyMultiplicityMassExceeded;
        const facts = try a.alloc(Fact, count);
        for (facts, 0..) |*f, i| f.multiplicity = if (weights) |w| w[i] else 1;
        return .{ .allocator = a, .kind = kind, .log = log, .function_mass = @intCast(mass), .facts = facts };
    }
    pub fn alu(a: std.mem.Allocator, facts: []const A.alu_experiment.source.Fact, weights: ?[]const u32, log: u32) !Batch {
        const batch = try allocate(a, .alu, facts.len, weights, log);
        for (facts, batch.facts) |f, *out| {
            out.op = @intFromEnum(f.op);
            out.a = f.a;
            out.b = f.b;
            out.c = f.c;
        }
        return batch;
    }
    pub fn binary(a: std.mem.Allocator, facts: []const A.binary_source.Fact, weights: ?[]const u32, log: u32) !Batch {
        const batch = try allocate(a, .binary, facts.len, weights, log);
        for (facts, batch.facts) |f, *out| {
            out.op = @intFromEnum(f.op);
            out.a = f.a;
            out.b = f.b;
            out.c = f.c;
        }
        return batch;
    }
    pub fn shift(a: std.mem.Allocator, facts: []const A.shift_word_packed_experiment.source.Fact, weights: ?[]const u32, log: u32) !Batch {
        const batch = try allocate(a, .shift, facts.len, weights, log);
        for (facts, batch.facts) |f, *out| {
            out.op = @intFromEnum(f.op);
            out.a = f.a;
            out.b = f.b;
            out.c = f.c;
        }
        return batch;
    }
    pub fn zbb(a: std.mem.Allocator, facts: []const A.binary_zbb_source.Fact, weights: ?[]const u32, log: u32) !Batch {
        const batch = try allocate(a, .zbb, facts.len, weights, log);
        for (facts, batch.facts) |f, *out| {
            out.op = @intFromEnum(f.op);
            out.a = f.a;
            out.b = f.b;
            out.c = f.c;
        }
        return batch;
    }
    pub fn words(self: *const Batch) []const u32 {
        return std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(self.facts));
    }
    pub fn deinit(self: *Batch) void {
        self.allocator.free(self.facts);
        self.* = undefined;
    }
};

test "device family witness compact inputs own exact unpadded weighted facts" {
    var batch = try Batch.alu(std.testing.allocator, &.{.{ .op = .add, .a = 0xffffffffffffffff, .b = 1, .c = 0 }}, &.{3}, 22);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 32), std.mem.sliceAsBytes(batch.facts).len);
    try std.testing.expectEqual(@as(u32, 3), batch.function_mass);
    try std.testing.expectEqualSlices(u32, &.{ 0, 3, 0xffffffff, 0xffffffff, 1, 0, 0, 0 }, batch.words());
    try std.testing.expectError(error.InvalidDeviceFamilyWeights, Batch.alu(std.testing.allocator, &.{}, &.{1}, 5));
    try std.testing.expectError(error.DeviceFamilyMultiplicityMassExceeded, Batch.alu(std.testing.allocator, &.{ .{ .op = .add, .a = 0, .b = 0, .c = 0 }, .{ .op = .add, .a = 0, .b = 0, .c = 0 } }, &.{ core.fields.m31.Modulus - 1, 1 }, 5));
}
