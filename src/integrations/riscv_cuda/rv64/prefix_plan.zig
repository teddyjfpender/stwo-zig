//! Geometry of the resident eight-coordinate, logical-coset prefix scan.
//! No numerical arrays or allocations are owned by this immutable plan.
pub const Plan = struct {
    rows: u32,
    levels: u32,
    scratch_words: usize,
    pub fn init(row_log: u32) !Plan {
        if (row_log == 0 or row_log > 22) return error.InvalidGeometry;
        const rows = @as(u32, 1) << @intCast(row_log);
        var n = rows;
        var words: usize = 0;
        var levels: u32 = 0;
        while (n > 1) {
            n = (n + 127) / 128;
            words += @as(usize, n) * 8;
            levels += 1;
        }
        return .{ .rows = rows, .levels = levels, .scratch_words = words };
    }
    pub fn dispatches(self: Plan, center: bool) u64 {
        return 2 * @as(u64, self.levels) + @intFromBool(self.levels == 1 and center);
    }
};
