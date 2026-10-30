//! Extends the existing endpoint R16 provider with exactly three cells for
//! each fixed active LS row. Byte-pair demand remains endpoint-only.
const std = @import("std");
const core = @import("stwo_core");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Profile = @import("block_v8_native_endpoint_profile_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
pub const Owned = struct {
    /// byte_counter is borrowed; only range16 is owned by this view.
    provider: Range.Owned,
    pub fn deinit(self: *Owned) void {
        self.provider.range16.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, shape: *const Shape, base: *const Range.Owned, main: []const Column) !Owned {
    const logs = try @import("block_v8_ram_clock_v3_stage.zig").mainLogs(a, shape);
    defer a.free(logs);
    if (logs.len != main.len) return error.InvalidDirectRamClockColumns;
    const extra = try Profile.gapRequests(shape, .direct_ram_clock_v3);
    const total = try std.math.add(u32, base.counts.range16, extra);
    if (total >= core.fields.m31.Modulus) return error.DirectRamClockRangeCountExceedsField;
    var matrix = try T.Matrix.init(a, 16, 3, 1 << 20);
    errdefer matrix.deinit();
    @memcpy(matrix.storage, base.range16.storage);
    var group: usize = 0;
    const start = main.len - 3 * Halt.count(shape);
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        for (0..desc.n_rows) |logical| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, desc.log_size), desc.log_size);
            for (main[start + 3 * group ..][0..3]) |column| {
                const value = column.values[physical].v;
                if (value >= 65536) return error.InvalidDirectRamClockRange16;
                const count = matrix.get(2, value);
                if (count.v >= core.fields.m31.Modulus - 1) return error.DirectRamClockRangeCountExceedsField;
                matrix.set(2, value, count.add(M.one()));
            }
        }
        group += 1;
    };
    var provider = base.*;
    provider.range16 = matrix;
    provider.counts.range16 = total;
    return .{ .provider = provider };
}
