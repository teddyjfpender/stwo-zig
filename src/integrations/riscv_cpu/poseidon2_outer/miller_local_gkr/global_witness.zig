//! One bounded Wire35 prefix per independently sized Miller component.
//! All local BYTE/U15/SSA work belongs to the separate GKR child.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.bn254_tower.narrow;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const Witness = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    data: []M,
    claim: O,
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};
pub fn generate(comptime role: N.source.Role, a: std.mem.Allocator, source: *const N.trace.SourceForField(role, O), challenges: N.equations.ChallengesFor(O), limit: usize) !Witness {
    if (source.advice_retired) return error.TowerAdviceRetired;
    const rows = source.size();
    const bytes = try std.math.mul(usize, rows, 8 * @sizeOf(M));
    if (try std.math.add(usize, bytes, 3 * 256 * @sizeOf(O)) > limit) return error.MillerGlobalWitnessBudget;
    const data = try a.alloc(M, bytes / @sizeOf(M));
    errdefer a.free(data);
    const scratch = try a.alloc(O, @as(usize, 3) * @min(rows, 256));
    defer a.free(scratch);
    var total = O.zero();
    var start: usize = 0;
    while (start < rows) : (start += 256) {
        const count: usize = @min(256, rows - start);
        const n = scratch[0..count];
        const d = scratch[count .. 2 * count];
        const inv = scratch[2 * count .. 3 * count];
        for (0..count) |offset| {
            try source.fractionsAt(start + offset, challenges, .wire, 0, n[offset..][0..1], d[offset..][0..1]);
            // Preserve the original producer's zero-weight pole behavior.
            if (n[offset].isZero()) d[offset] = O.one();
        }
        for (d) |dd| for (dd.toM31Array()) |coordinate| std.debug.assert(coordinate.v < core.fields.m31.Modulus);
        try core.fields.batchInverseInPlace(O, d, inv);
        for (n, inv, 0..) |nn, inverse, offset| {
            total = total.add(nn.mul(inverse));
            const physical = A.witness.physical(start + offset, source.log_size);
            for (total.toM31Array(), 0..) |value, c| {
                std.debug.assert(value.v < core.fields.m31.Modulus);
                data[c * rows + physical] = value;
            }
        }
    }
    for (total.toM31Array(), 0..) |value, c| for (data[c * rows ..][0..rows]) |*cell| {
        std.debug.assert(cell.v < core.fields.m31.Modulus);
        cell.* = cell.sub(value);
    };
    return .{ .allocator = a, .log_size = source.log_size, .data = data, .claim = total };
}
test "Miller local GKR global Wire prefix exactly matches classic authority" {
    const a = std.testing.allocator;
    const input = [_]N.trace.Input{@splat(1)};
    var source = try N.trace.SourceForField(.arithmetic, O).initWithoutFixed(a, &input, 9, 15);
    defer source.deinit();
    var channel = @import("native.zig").Channel.init();
    var ch = @import("native.zig").draw(&channel);
    ch.wire = A.crypto.curves.equations.WireFor(O).draw(&channel);
    try std.testing.expectError(error.MillerGlobalWitnessBudget, generate(.arithmetic, a, &source, ch, 1));
    var global = try generate(.arithmetic, a, &source, ch, 2 << 20);
    defer global.deinit();
    const old = try source.generateInteraction(ch);
    try std.testing.expect(old.wire.eql(global.claim));
    const begin = source.size() * @TypeOf(source).L.WIRE_FIRST;
    try std.testing.expectEqualSlices(M, source.interaction[begin..][0..global.data.len], global.data);
}
