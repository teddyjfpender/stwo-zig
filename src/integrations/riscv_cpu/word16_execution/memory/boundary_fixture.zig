//! Test-only hostile prover support. Rebuilds MAIN and retained metadata from
//! typed cells while deliberately bypassing constructor order/alignment checks.
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.memory.load_store_v2;
const Ram = A.memory.closed_ram;
pub fn rewrite(source: *B.boundary_source.Source, cells: []const Ram.types.Cell) void {
    const n = source.size();
    for (0..n) |logical| {
        const row = B.native.boundaryRow(cells, logical);
        const pos = Ram.trace.physical(logical, source.log_size);
        for (row, 0..) |value, column| source.main[column * n + pos] = value;
        for (Ram.layout.B_U16[0..10], 0..) |column, i| source.metadata[logical].range16[i] = @intCast(row[column].v);
        source.metadata[logical].high = @intCast(row[11].v);
        source.metadata[logical].flags = @intCast(row[0].v | row[12].v << 1 | row[13].v << 2);
    }
}
