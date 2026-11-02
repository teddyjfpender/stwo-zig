//! Native touched-cell witness only. Receiver statements carry no private RAM
//! ledger; a same-PCS authenticated CellTable must close these state effects.
const S = @import("rv64_full_statement.zig");
pub const Boundary = struct {
    cells: []const S.Cell,
    memory_clocks: []const u32,
    pub fn native(self: Boundary, public: S.Statement) !S.Statement {
        if (public.cells.len != 0 or public.memory_clocks.len != 0 or self.cells.len != self.memory_clocks.len) return error.InvalidRv64PrivateBoundary;
        var result = public;
        result.cells = self.cells;
        result.memory_clocks = self.memory_clocks;
        return result;
    }
};
