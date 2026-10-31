//! Bounded batched inversion from48-byte native projection metadata. Clock
//! range inverses are shared with the small typed range tables, not recomputed
//! for every CPU query. There is no full-row QM31 advice matrix or ISA replay.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const L = @import("layout.zig");
const P = @import("public.zig");
const Lookup = @import("lookup.zig");
const Eq = @import("equations.zig");
const Source = @import("trace.zig").Source;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK = 4096;
fn affine(offset: Q, coefficients: []const Q, tuple: []const M) Q {
    var result = offset;
    for (coefficients, tuple) |coefficient, value| result = result.sub(coefficient.mulM31(value));
    return result;
}
fn store(output: []M, n: usize, position: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| output[(column + i) * n + position] = coordinate;
}
pub fn generate(source: *Source, challenges: Lookup.Challenges, range16: []const Q, range8: []const Q) !P.Claims {
    if (source.interaction.len != 0 or source.metadata.len != source.public.steps or range16.len != 65536 or range8.len != 256) return error.InvalidWord16CpuPhase;
    try source.public.validate(source.log_size);
    const a = source.allocator;
    const n = source.size();
    const output = try a.alloc(M, n * L.inter.COUNT);
    errdefer a.free(output);
    const denominators = try a.alloc(Q, 8 * CHUNK);
    defer a.free(denominators);
    const scratch = try a.alloc(Q, 10 * CHUNK);
    defer a.free(scratch);
    var sums: [5]Q = @splat(Q.zero());
    var start: usize = 0;
    while (start < n) : (start += CHUNK) {
        const count = @min(CHUNK, n - start);
        for (0..count) |j| {
            const logical = start + j;
            const main = source.rowValues(logical);
            const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical == n - 1)) };
            const row = denominators[8 * j ..][0..8];
            for (0..3) |slot| {
                const before = Eq.registerTuple(M, &fixed, &main, slot, false);
                const after = Eq.registerTuple(M, &fixed, &main, slot, true);
                row[2 * slot] = affine(challenges.register.offset, &challenges.register.coefficients, &before);
                row[2 * slot + 1] = affine(challenges.register.offset, &challenges.register.coefficients, &after);
                scratch[5 * j + slot] = row[2 * slot].mul(row[2 * slot + 1]);
            }
            row[6] = affine(challenges.function.offset, &challenges.function.coefficients, &Eq.functionTuple(M, &main));
            const rom_tuple = Eq.romTupleProfile(M, source.program.profile, &main);
            row[7] = affine(challenges.rom.offset, &challenges.rom.coefficients, rom_tuple[0..16]);
            if (source.program.profile == .alu_binary_v2) row[7] = affine(row[7], &challenges.rom.control_coefficients, rom_tuple[16..]);
            scratch[5 * j + 3] = row[6];
            scratch[5 * j + 4] = row[7];
        }
        const inverse = scratch[5 * CHUNK ..][0 .. 5 * count];
        try core.fields.batchInverseInPlace(Q, scratch[0 .. 5 * count], inverse);
        for (0..count) |j| {
            const logical = start + j;
            const pos = L.physical(logical, source.log_size);
            const main = source.rowValues(logical);
            const row = denominators[8 * j ..][0..8];
            const inv = inverse[5 * j ..][0..5];
            var registers = Q.zero();
            for (0..3) |slot| {
                store(output, n, pos, L.inter.register_inverses + 4 * slot, inv[slot]);
                registers = registers.add(row[2 * slot + 1].sub(row[2 * slot]).mul(inv[slot]).mulM31(main[L.main.enabled + slot]));
            }
            sums[0] = sums[0].add(registers);
            store(output, n, pos, L.inter.register_sum, sums[0]);
            store(output, n, pos, L.inter.function_inverse, inv[3]);
            sums[1] = sums[1].add(inv[3].mulM31(main[L.main.active]));
            store(output, n, pos, L.inter.function_sum, sums[1]);
            store(output, n, pos, L.inter.rom_inverse, inv[4]);
            sums[2] = sums[2].add(inv[4].mulM31(main[L.main.active]));
            store(output, n, pos, L.inter.rom_sum, sums[2]);
            const low = [_]Q{ range16[main[L.main.gap16].v], range16[main[L.main.gap16 + 1].v], range16[main[L.main.gap16 + 2].v] };
            const high = [_]Q{ range8[main[L.main.gap8].v], range8[main[L.main.gap8 + 1].v], range8[main[L.main.gap8 + 2].v] };
            store(output, n, pos, L.inter.range16_inverses, low[0].mul(low[1]));
            store(output, n, pos, L.inter.range16_inverses + 4, low[2]);
            sums[3] = sums[3].add(low[0]).add(low[1]).add(low[2]);
            store(output, n, pos, L.inter.range16_sum, sums[3]);
            store(output, n, pos, L.inter.range8_inverses, high[0].mul(high[1]));
            store(output, n, pos, L.inter.range8_inverses + 4, high[2]);
            sums[4] = sums[4].add(high[0]).add(high[1]).add(high[2]);
            store(output, n, pos, L.inter.range8_sum, sums[4]);
        }
    }
    const prefixes = [_]usize{ L.inter.register_sum, L.inter.function_sum, L.inter.rom_sum, L.inter.range16_sum, L.inter.range8_sum };
    for (prefixes, sums) |column, claim| {
        for (claim.toM31Array(), 0..) |coordinate, i| for (0..n) |row| {
            const index = (column + i) * n + row;
            output[index] = output[index].sub(coordinate);
        };
    }
    source.interaction = output;
    return .{ .register = sums[0], .function = sums[1], .rom = sums[2], .range16 = sums[3], .range8 = sums[4] };
}
