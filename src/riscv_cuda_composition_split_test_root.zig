const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Circle = engine.poly.circle;
const Split = @import("backends/cuda/runtime/stages/composition_split.zig");

test {
    std.testing.refAllDecls(Split);
}

// Scalar simulation of the native final-stage compact scatter. The reference
// uses the original CPU interpolation and recursive SecureCirclePoly splitting.
// This qualifies algebra/order only; native CUDA execution is a separate gate.
test "q3 composition split compact B2N algebra matches original interpolation and recursive chunks" {
    const a = std.testing.allocator;
    for ([_]u32{ 4, 5, 8, 13 }) |log| {
        const n = @as(usize, 1) << @intCast(log);
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        const input = try a.alloc(M, 4 * n);
        defer a.free(input);
        var rng = std.Random.DefaultPrng.init(0x51337 + log);
        for (input) |*v| v.* = M.fromU64(rng.random().int(u64));
        // Include zero and boundary values in every coordinate.
        for (0..4) |c| {
            input[c * n] = M.zero();
            input[c * n + 1] = M.fromCanonical(0x7ffffffe);
        }
        var original: Circle.SecureCirclePoly = undefined;
        var initialized: usize = 0;
        defer for (original.polys[0..initialized]) |*p| p.deinit(a);
        for (0..4) |c| {
            const eval = try Circle.CircleEvaluation.init(domain, input[c * n ..][0..n]);
            original.polys[c] = try Circle.poly.interpolateFromEvaluation(a, eval);
            initialized += 1;
        }
        const work = try a.dupe(M, input);
        defer a.free(work);
        for (0..4) |c| try scalarB2n(work[c * n ..][0..n], log, tw.itwiddles);
        for ([_]u32{ 1, 2, 3 }) |depth| {
            var chunks = try original.splitIntoChunks(a, depth);
            defer chunks.deinit(a);
            const chunk_n = n >> @intCast(depth);
            const compact = try a.alloc(M, 4 * n);
            defer a.free(compact);
            // Exact final kernel address: (coordinate + chunk*4)*chunk_rows+row.
            for (0..4) |c| for (0..n) |i| {
                compact[(c + (i / chunk_n) * 4) * chunk_n + i % chunk_n] = work[c * n + i];
            };
            for (chunks.chunks, 0..) |chunk, k| for (chunk.polys, 0..) |poly, c| {
                try std.testing.expectEqualSlices(M, poly.coefficients(), compact[(k * 4 + c) * chunk_n ..][0..chunk_n]);
            };
        }
    }
}

fn scalarB2n(values: []M, log: u32, tw: []const M) !void {
    const half = values.len / 2;
    var layer_size = half;
    var layer_offset: usize = 0;
    var stage: u32 = 1;
    const scale = try M.fromU64(values.len).inv();
    while (stage <= log) : (stage += 1) {
        const stride = @as(usize, 1) << @intCast(stage - 1);
        for (0..half) |pair| {
            const butterfly = pair >> @intCast(stage - 1);
            const left = (pair & (stride - 1)) + butterfly * 2 * stride;
            const right = left + stride;
            const w = if (stage == 1) switch (butterfly & 3) {
                0 => tw[2 * (butterfly >> 2) + 1],
                1 => tw[2 * (butterfly >> 2) + 1].neg(),
                2 => tw[2 * (butterfly >> 2)].neg(),
                else => tw[2 * (butterfly >> 2)],
            } else tw[layer_offset + butterfly];
            const x = values[left];
            const y = values[right];
            values[left] = x.add(y);
            values[right] = x.sub(y).mul(w);
            if (stage == log) {
                values[left] = values[left].mul(scale);
                values[right] = values[right].mul(scale);
            }
        }
        if (stage >= 2 and stage != log) {
            layer_size >>= 1;
            layer_offset += layer_size;
        }
    }
}
