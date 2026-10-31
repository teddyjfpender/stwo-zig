//! Retained pre-dictionary native interaction recipe; tests only.
const core = @import("stwo_core");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = K.layout;
const E = K.equations;
const T = K.trace;
const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical;
const store = K.interaction.store;
pub fn generate(trace: *T.Trace, ch: E.Challenges) !Q {
    if (trace.interaction.len != 0) return error.KeccakInteractionAlreadyGenerated;
    try trace.validateMetadata();
    const n = trace.size();
    const data = try trace.allocator.alloc(M, L.INTERACTION * n);
    errdefer trace.allocator.free(data);
    var sum = Q.zero();
    for (0..n) |logical| {
        const r = physical(logical, trace.log_size);
        var fixed: [L.FIXED]Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
        const base_main = try trace.metadataRow(logical);
        const base_next = try trace.metadataRow((logical + 1) % n);
        var main: [L.MAIN]Q = undefined;
        var next: [L.STATE]Q = undefined;
        for (&main, base_main) |*v, b| v.* = Q.fromBase(b);
        for (&next, base_next[0..L.STATE]) |*v, b| v.* = Q.fromBase(b);
        const row = E.Row{ .fixed = &fixed, .main = &main, .state_minus_two = &next, .state_minus_one = &next, .state_plus_one = &next, .state_plus_two = &next };
        const coefficient = E.roundActive(row).neg();
        for (0..L.LOOKUPS / 3) |batch| {
            for (0..3) |i| {
                const inverse = try E.lookupDenominator(row, ch, 3 * batch + i).inv();
                sum = sum.add(coefficient.mul(inverse));
            }
            store(data, n, r, batch, sum);
        }
        for (0..L.IO_BATCHES) |local| {
            for (0..3) |i| if (3 * local + i < L.IO_LANES) {
                sum = sum.add(E.ioActive(row).mul(try ch.io.denominator(&E.ioTuple(row, 3 * local + i)).inv()));
            };
            store(data, n, r, L.LOOKUPS / 3 + local, sum);
        }
    }
    trace.interaction = data;
    return sum;
}
