//! Native truth rational fractions, emitted through the same device projection
//! backend as CPU global relations. Two physical groups remain two claims;
//! this module never relabels either group as RAM or draws a challenge.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const CPU = @import("stwo_riscv_cpu_integration");
const K = A.crypto.keccak;
const T = @import("truth_codegen.zig");
const X = @import("symbolic_external.zig");
const C = @import("composition_codegen.zig");
const G = @import("global_codegen.zig");
const F = X.Lane;
pub const Artifact = struct {
    a: std.mem.Allocator,
    program: C.Program,
    parameter_slots: []u32,
    groups: [2]u32,
    pub fn deinit(self: *@This()) void {
        self.program.deinit();
        self.a.free(self.parameter_slots);
        self.* = undefined;
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    parameters: T.Role.Component.ParametersFor(F),
    roots: std.ArrayList(u32) = .empty,
    denominators: [3]F = @splat(F.one()),
    weights: [3]F = @splat(F.zero()),
    fill: usize = 0,
    packing: usize,
    fn flush(self: *@This()) !void {
        const values = CPU.rv64_gkr_truth_products(F, self.denominators, self.weights, self.packing);
        try self.roots.appendSlice(self.a, &.{ values.n.id, values.d.id });
        self.denominators = @splat(F.one());
        self.weights = @splat(F.zero());
        self.fill = 0;
    }
    fn append(self: *@This(), denominator: F, weight: F) !void {
        self.denominators[self.fill] = denominator;
        self.weights[self.fill] = weight;
        self.fill += 1;
        if (self.fill == self.packing) try self.flush();
    }
};
/// id0=throughput-r27 permutation, id1=chi multiplicities, id2=xor5.
pub fn record(a: std.mem.Allocator, id: u32) !Artifact {
    if ((id >= 3 and id < 7) or (id >= 10 and id < 15)) return switch (id) {
        3 => recordV3(a, T.V3Catalog.Sha(), id),
        4 => recordV3(a, T.V3Catalog.Arith(), id),
        5 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add), id),
        6 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double), id),
        10 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_add), id),
        11 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_double), id),
        12 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_fp2_mul), id),
        13 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bls12_381_fp2_mul), id),
        14 => recordV3(a, T.V3Catalog.Curve(A.crypto.curves.spec.Op.arith384_mont), id),
        else => error.UnsupportedTruthInteractionRole,
    };
    if (id >= 10) return error.UnsupportedTruthInteractionRole;
    const local_id: u32 = if (id < 3) id else id - 7;
    const policy: K.equations.BatchPolicy = if (id < 3) .throughput_r27_v1 else .triple_v2;
    var recording = X.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const params = T.symbolicParameters();
    var collector = Collector{ .a = a, .parameters = params, .packing = if (local_id == 0) 3 else 1 };
    defer collector.roots.deinit(a);
    if (local_id == 0) {
        var fixed: [K.layout.FIXED]F = undefined;
        for (&fixed, 0..) |*v, i| v.* = F.input(0, i, 0);
        var main: [K.layout.MAIN]F = undefined;
        for (&main, 0..) |*v, i| v.* = F.input(1, i, 0);
        var previous: [K.layout.STATE]F = undefined;
        var next: [K.layout.STATE]F = undefined;
        for (&previous, &next, 0..) |*p, *n, i| {
            p.* = F.input(1, i, -1);
            n.* = F.input(1, i, 1);
        }
        const empty: [K.layout.STATE]F = @splat(F.zero());
        const row = K.equations.RowFor(F){ .fixed = &fixed, .main = &main, .previous_header = &@as([3]F, @splat(F.zero())), .state_minus_two = &empty, .state_minus_one = &previous, .state_plus_one = &next, .state_plus_two = &empty };
        const weight = K.equations.roundActiveFor(F, row).neg();
        for (0..policy.lookups()) |event| {
            const tuple = if (policy == .throughput_r27_v1) K.equations.throughputTupleFor(F, main[0..K.layout.STATE], main[K.layout.STATE..K.layout.ACTIVE_A], &next, fixed[2..26], event) else K.equations.lookupTupleFor(F, row, event);
            const d = params.local.denominatorFor(F, if (event < policy.chiLookups()) .chi else .xor5, tuple);
            try collector.append(d, weight);
        }
        if (collector.fill != 0) try collector.flush();
        const local: u32 = @intCast(collector.roots.items.len / 2);
        for (0..if (policy == .throughput_r27_v1) 2 * K.layout.IO_LANES else K.layout.IO_LANES) |entry| {
            const tuple = if (policy == .throughput_r27_v1) K.equations.ioTupleR27For(F, row, entry) else K.equations.ioTupleFor(F, row, entry);
            const d = A.evaluation.denominatorFor(F, params.kio.offset, &params.kio.coefficients, &tuple, true);
            const n = if (policy == .throughput_r27_v1) K.equations.ioActiveR27For(F, row, entry) else K.equations.ioActiveFor(F, row);
            try collector.roots.appendSlice(a, &.{ n.id, d.id });
        }
        return finish(a, &recording, collector.roots.items, id, .{ local, if (policy == .throughput_r27_v1) 50 else 25 });
    }
    var tuple: [6]F = undefined;
    for (&tuple, 0..) |*v, i| v.* = F.input(0, i, 0);
    try collector.append(params.local.denominatorFor(F, if (local_id == 1) .chi else .xor5, tuple), F.input(1, 0, 0));
    return finish(a, &recording, collector.roots.items, id, .{ 1, 0 });
}
fn recordV3(a: std.mem.Allocator, comptime Type: type, id: u32) !Artifact {
    var recording = X.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const params = T.symbolicParameters();
    var collector = Collector{ .a = a, .parameters = params, .packing = Type.batch };
    defer collector.roots.deinit(a);
    const View = struct {
        pub fn fixed(_: *const @This(), c: usize) F {
            return F.input(0, c, 0);
        }
        pub fn main(_: *const @This(), c: usize) F {
            return F.input(1, c, 0);
        }
        pub fn previousActive(_: *const @This()) F {
            return F.input(1, 0, -1);
        }
    };
    const view = View{};
    if (comptime Type.bytes != 0) {
        for (0..Type.byte_batches * Type.batch) |i| {
            const n = if (i < Type.bytes) F.one() else if (i == Type.bytes) view.main(Type.L.MULT).neg() else F.zero();
            const d = if (i < Type.bytes) params.local.polynomial.sub(Type.Eq.byteQuery(F, &view, i)) else if (i == Type.bytes) params.local.polynomial.sub(view.fixed(A.crypto.curves.layout.BYTE)) else F.one();
            try collector.append(d, n);
        }
    }
    const byte_batches: u32 = @intCast(collector.roots.items.len / 2);
    for (0..Type.wire_batches * Type.batch) |i| {
        if (i >= Type.wires) {
            try collector.append(F.one(), F.zero());
            continue;
        }
        const tuple = if (comptime Type == T.V3Catalog.Sha() or Type == T.V3Catalog.Arith()) Type.Eq.tuple(F, &view, params.span, @intCast(i)) else Type.Eq.tuple(F, &view, params.span, i);
        const positive = if (comptime Type == T.V3Catalog.Sha() or Type == T.V3Catalog.Arith()) i == Type.L.OUTPUT_WIRE else i >= Type.L.COORDS;
        const active = view.main(Type.L.ACTIVE);
        const d = A.evaluation.denominatorFor(F, params.wire.offset, &params.wire.coefficients, &tuple, true);
        try collector.append(d, if (positive) active else active.neg());
    }
    if (collector.fill != 0) return error.UnfinishedTruthRationalBatch;
    const groups: [2]u32 = if (byte_batches == 0) .{ @intCast(Type.wire_batches), 0 } else .{ byte_batches, @intCast(Type.wire_batches) };
    return finish(a, &recording, collector.roots.items, id, groups);
}
fn finish(a: std.mem.Allocator, recording: *X.Recording, roots: []const u32, id: u32, groups: [2]u32) !Artifact {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/cuda/native-truth-rational-groups/v1");
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, id, .little);
    hash.update(&word);
    var program = try recording.builder.finish(hash.finalResult(), roots);
    errdefer program.deinit();
    const slots = try a.alloc(u32, program.parameters.len);
    errdefer a.free(slots);
    for (slots, program.parameters) |*slot, value| {
        const c = value.toM31Array();
        for (c[1..]) |v| if (!v.isZero()) return error.InvalidTruthParameter;
        if (c[0].v == 0 or c[0].v > T.slots.count) return error.InvalidTruthParameter;
        slot.* = c[0].v - 1;
    }
    return .{ .a = a, .program = program, .parameter_slots = slots, .groups = groups };
}
pub fn emit(a: std.mem.Allocator, w: anytype, artifact: *const Artifact, kernel_name: []const u8) !void {
    // Storage lens only: these field names in the shared emitter select the
    // prefix gap, never a relation/challenge/manifest classification.
    const view = G.Artifact{ .a = artifact.a, .descriptor = undefined, .program = artifact.program, .parameter_slots = artifact.parameter_slots, .ram_pairs = artifact.groups[0], .other_pairs = artifact.groups[1] };
    return G.emitContiguous(a, w, &view, kernel_name);
}
test "truth rational projection keeps native triple and strict IO groups" {
    const a = std.testing.allocator;
    for (0..15) |id| {
        var artifact = try record(a, @intCast(id));
        defer artifact.deinit();
        try artifact.program.validate();
        const first = [15]u32{ 143, 1, 1, 2, @intCast(T.V3Catalog.Arith().byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add).byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double).byte_batches), 640, 1, 1, @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_add).byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_double).byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_fp2_mul).byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bls12_381_fp2_mul).byte_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.arith384_mont).byte_batches) };
        const second = [15]u32{ 50, 0, 0, 0, @intCast(T.V3Catalog.Arith().wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add).wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double).wire_batches), 25, 0, 0, @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_add).wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_double).wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_fp2_mul).wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.bls12_381_fp2_mul).wire_batches), @intCast(T.V3Catalog.Curve(A.crypto.curves.spec.Op.arith384_mont).wire_batches) };
        try std.testing.expectEqual(first[id], artifact.groups[0]);
        try std.testing.expectEqual(second[id], artifact.groups[1]);
        try std.testing.expectEqual(@as(usize, 2) * (artifact.groups[0] + artifact.groups[1]), artifact.program.roots.len);
        for (artifact.program.inputs) |input| {
            try std.testing.expect(input.tree < 2);
            try std.testing.expect(input.offset >= -1 and input.offset <= 1);
        }
    }
}

pub fn name(a: std.mem.Allocator, id: u32) ![]u8 {
    if (id > 14) return error.UnsupportedTruthInteractionRole;
    return std.fmt.allocPrint(a, "stwo_rv64_truth_projection_{}", .{id});
}
pub fn roleWidths(id: u32) ![2]usize {
    return switch (id) {
        0, 7 => .{ 32, 1923 },
        1, 2, 8, 9 => .{ 7, 1 },
        3 => .{ T.V3Catalog.Sha().fixed, T.V3Catalog.Sha().L.MAIN },
        4 => .{ T.V3Catalog.Arith().fixed, T.V3Catalog.Arith().L.MAIN },
        5 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add).L.MAIN },
        6 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double).L.MAIN },
        10 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_add).L.MAIN },
        11 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_g1_double).L.MAIN },
        12 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bn254_fp2_mul).L.MAIN },
        13 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.Op.bls12_381_fp2_mul).L.MAIN },
        14 => .{ 4, T.V3Catalog.Curve(A.crypto.curves.spec.Op.arith384_mont).L.MAIN },
        else => error.UnsupportedTruthInteractionRole,
    };
}
pub fn writeAot(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    for (0..15) |id| {
        var artifact = try record(a, @intCast(id));
        defer artifact.deinit();
        const symbol = try name(a, @intCast(id));
        defer a.free(symbol);
        const kernel = try std.fmt.allocPrint(a, "{s}_kernel", .{symbol});
        defer a.free(kernel);
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        const w = text.writer(a);
        try emit(a, w, &artifact, kernel);
        const widths = try roleWidths(@intCast(id));
        const pairs = artifact.groups[0] + artifact.groups[1];
        const width = 8 * (pairs + 1 + @as(u32, @intFromBool(artifact.groups[1] != 0)));
        try w.writeAll("\n#include \"rv64/custody.cuh\"\n");
        try w.print(
            \\extern "C" __attribute__((visibility("default"))) int {s}(void*ctx,uint32_t lane,const uint32_t*fixed,const uint32_t*main,const uint32_t*parameters,uint32_t*n,uint32_t*d,uint32_t*status,uint32_t log){{
            \\if(log<5||log>22)return int(cudaErrorInvalidValue);const uint64_t rows=1ull<<log;Custody c(ctx,lane);
            \\if(!c.range(fixed,rows*{}ull,false)||!c.range(main,rows*{}ull,false)||!c.range(parameters,{}ull,false)||!c.range(n,rows*{}ull,true)||!c.range(d,rows*{}ull,true)||!c.range(status,1,true))return c.status;
            \\{s}<<<dim3((rows+127)/128,{}u),128,0,c.stream>>>(fixed,main,nullptr,parameters,n,d,rows,uint32_t(rows),status);return int(cudaPeekAtLastError());}}
            \\
        , .{ symbol, widths[0], widths[1], artifact.parameter_slots.len * 8, pairs * 8, width, kernel, pairs });
        const filename = try std.fmt.allocPrint(a, "{s}.cu", .{symbol});
        defer a.free(filename);
        try dir.writeFile(.{ .sub_path = filename, .data = text.items });
    }
}
