//! Receiver recomputation from the independently authorized complete cell list.
//! Canonical tuple projection is the same original native boundary authority;
//! no host-declared polynomial evaluation stands in for this comparison.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
pub fn claim(cells: []const A.memory.closed_ram.types.Cell, initial: bool, ch: A.memory.closed_ram.types.RamChallengesFor(O)) !O {
    var denominators: [4096]O = undefined;
    var inverses: [4096]O = undefined;
    var out = O.zero();
    var start: usize = 0;
    while (start < cells.len) : (start += 4096) {
        const count = @min(@as(usize, 4096), cells.len - start);
        for (0..count) |i| {
            const row = A.memory.load_store_v2.native.boundaryRow(cells, start + i);
            const tuple = A.memory.closed_ram.equations.ramTuple(M, if (initial) .initial else .terminal, &row, false);
            var d = ch.offset;
            for (ch.coefficients, tuple) |coefficient, value| d = d.sub(coefficient.mulM31(value));
            denominators[i] = d;
        }
        try core.fields.batchInverseInPlace(O, denominators[0..count], inverses[0..count]);
        for (inverses[0..count]) |inverse| out = if (initial) out.sub(inverse) else out.add(inverse);
    }
    return out;
}
