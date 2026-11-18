//! Native 2n-domain interpreter for the validated octic circuit AIR.
//! FIXED/MAIN and base arithmetic stay in M31. validateLens guarantees that
//! INTER coordinates only flow directly into aligned secure packs. OODS uses
//! the scalar program because its inputs can span the whole extension.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const E = @import("program.zig");
const G = @import("geometry.zig");
const M = P.M;
const Trace = prover.air.component_prover.ForField(P.O).Trace;
const fields = core.fields.m31;
const V = fields.PackedM31;
const simd = core.fields.packed_om31;
const Oct = simd.PackedOM31;
const ReadColumn = struct {
    values: []const M,
    shift: u5,
    offset: i32,
    fn load(c: ReadColumn, r: usize, trace_log: u32, eval_log: u32, active: usize) V {
        if (active == fields.PACK_WIDTH and c.shift == 0 and c.offset == 0) return fields.loadPacked(c.values[r..].ptr);
        var v: V = undefined;
        inline for (0..fields.PACK_WIDTH) |lane| {
            const position = r + @min(lane, active - 1);
            const index = if (c.offset == 0) position else core.utils.offsetBitReversedCircleDomainIndex(position, trace_log, eval_log, c.offset);
            v[lane] = c.values[(((index >> 1) >> c.shift) << 1) | (index & 1)].v;
        }
        return v;
    }
};

const Reads = struct { low: ReadColumn, high: ?ReadColumn };
// A base-only operand scales eight coordinates independently. Resolve its
// provenance once per program so every SIMD pack can use the cheaper product.
const Multiply = enum { full, left_base, right_base };
const PartPlan = struct {
    projections: []const Projection,
    reads: []const Reads,
    multiply: []const Multiply,
    base_roots: []const bool,
};
// A common lookup denominator is bias + p0*x + p1*y + p2*z. Its inputs
// are base-field lanes. Four canonical products fit in u64 before reduction.
const Projection = struct {
    first: usize,
    dst: u16,
    slots: [3]u32,
    coeffs: [8][4]V,

    fn evaluate(self: *const Projection, low: []const V) Oct {
        const v = [4]V{ low[self.slots[0]], low[self.slots[1]], low[self.slots[2]], @splat(1) };
        var coords: [8]V = undefined;
        inline for (0..8) |k| coords[k] = fields.dot4Packed(v, self.coeffs[k]);
        return simd.fromCoordinates(coords);
    }
};
const projection_len = 15;
fn projections(a: std.mem.Allocator, p: E.Program, params: []const P.O, zero: []const bool, high: []const bool) ![]const Projection {
    const ops = p.ext_insts;
    if (ops.len < projection_len) return &.{};
    const uses = try a.alloc(usize, ops.len);
    defer a.free(uses);
    @memset(uses, 0);
    for (ops, 0..) |op, i| {
        if (op.dst != i) return &.{};
        switch (op.op) {
            .mul, .add, .sub => {
                uses[op.a] += 1;
                uses[op.b] += 1;
            },
            .neg => uses[op.a] += 1,
            else => {},
        }
    }
    for (p.constraint_roots) |root| uses[root] += 1;
    var matches: std.ArrayList(Projection) = .empty;
    const expected = [_]C.eval_program.ExtOpcode{ .param, .secure_col, .mul, .constant, .add, .param, .secure_col, .mul, .add, .param, .secure_col, .mul, .add, .param, .sub };
    var i: usize = 0;
    while (i + projection_len <= ops.len) : (i += 1) {
        const input = ops[i..][0..projection_len];
        for (input, expected) |op, code| {
            if (op.op != code) break;
        } else {
            if (!std.mem.allEqual(usize, uses[i..][0 .. projection_len - 1], 1)) continue;
            const cs = input[3];
            var result = Projection{ .first = i, .dst = input[14].dst, .slots = undefined, .coeffs = undefined };
            for ([_]usize{ 0, 5, 9 }, 0..) |j, term| {
                const load = input[j + 1];
                const mul = input[j + 2];
                if (high[load.a] or !zero[load.b] or !zero[load.c] or !zero[load.d] or mul.a != i + j or mul.b != i + j + 1) break;
                result.slots[term] = load.a;
                for (params[input[j].a].toM31Array(), 0..) |x, k| result.coeffs[k][term] = @splat(x.v);
            } else {
                if (input[4].a != cs.dst or input[4].b != i + 2 or input[8].a != i + 4 or input[8].b != i + 7 or
                    input[12].a != i + 8 or input[12].b != i + 11 or input[14].a != i + 12 or input[14].b != i + 13) continue;
                const bias = E.embed(P.Q.fromU32Unchecked(cs.a, cs.b, cs.c, cs.d)).sub(params[input[13].a]);
                for (bias.toM31Array(), 0..) |x, k| result.coeffs[k][3] = @splat(x.v);
                try matches.append(a, result);
                i += projection_len - 1;
            }
        }
    }
    return matches.toOwnedSlice(a);
}

fn planPart(a: std.mem.Allocator, program: E.Program, reads: []const Reads, params: []const P.O) !PartPlan {
    const zero = try a.alloc(bool, program.header.max_base_regs);
    defer a.free(zero);
    const high = try a.alloc(bool, zero.len);
    defer a.free(high);
    for (program.base_insts) |i| {
        zero[i.dst] = i.op == .constant and i.a == 0;
        high[i.dst] = (i.op == .trace_col or i.op == .preprocessed_col) and i.interaction == 2;
    }
    const base = try a.alloc(bool, program.header.max_ext_regs);
    defer a.free(base);
    const multiply = try a.alloc(Multiply, program.ext_insts.len);
    for (program.ext_insts, multiply) |i, *mode| {
        mode.* = .full;
        base[i.dst] = switch (i.op) {
            .secure_col => !high[i.a] and zero[i.b] and zero[i.c] and zero[i.d],
            .constant => i.b == 0 and i.c == 0 and i.d == 0,
            .param => false,
            .neg => base[i.a],
            .add, .sub => base[i.a] and base[i.b],
            .mul => blk: {
                mode.* = if (base[i.a]) .left_base else if (base[i.b]) .right_base else .full;
                break :blk base[i.a] and base[i.b];
            },
        };
    }
    const roots = try a.alloc(bool, program.constraint_roots.len);
    for (program.constraint_roots, roots) |idx, *is_base| is_base.* = base[idx];
    return .{ .projections = try projections(a, program, params, zero, high), .reads = reads, .multiply = multiply, .base_roots = roots };
}
pub const Registers = struct { low: []V, high: []V, extension: []Oct };
pub const Plan = struct {
    component: *const C.composition_bundle.Component,
    parts: []const PartPlan,
    parameters: []const Oct,
    weights: []const Oct,
    base_count: usize,
    extension_count: usize,
    /// The caller's component arena owns the projection and the worker banks.
    pub fn init(a: std.mem.Allocator, owner: *const C.composition_bundle.Component, trace: *const Trace, shadow: ?[3][]?[]M, parameters: []const P.O, weights: []const P.O) !Plan {
        const parts = try a.alloc(PartPlan, owner.parts.len);
        var base_count: usize = 0;
        var extension_count: usize = 0;
        for (owner.parts, parts) |part, *dest| {
            const program = part.program;
            if (program.header.n_base_params != 0 or program.header.n_ext_params != parameters.len) return error.InvalidOm31Parameters;
            base_count = @max(base_count, program.header.max_base_regs);
            extension_count = @max(extension_count, program.header.max_ext_regs);
            const reads = try a.alloc(Reads, program.base_insts.len);
            for (program.base_insts, reads) |inst, *read| switch (inst.op) {
                .trace_col, .preprocessed_col => {
                    const inter = inst.interaction == 2;
                    const col = if (inter) try std.math.add(u32, try std.math.mul(u32, inst.a / 4, 8), inst.a % 4) else inst.a;
                    read.* = .{
                        .low = try project(owner, trace, shadow, inst.interaction, col, inst.imm),
                        .high = if (inter) try project(owner, trace, shadow, 2, try std.math.add(u32, col, 4), inst.imm) else null,
                    };
                },
                else => {},
            };
            dest.* = try planPart(a, program, reads, parameters);
        }
        return .{ .component = owner, .parts = parts, .base_count = base_count, .extension_count = extension_count, .parameters = try broadcast(a, parameters), .weights = try broadcast(a, weights) };
    }
    fn broadcast(a: std.mem.Allocator, values: []const P.O) ![]Oct {
        const result = try a.alloc(Oct, values.len);
        for (values, result) |v, *r| r.* = simd.splat(v);
        return result;
    }
    pub fn registers(self: Plan, a: std.mem.Allocator) !Registers {
        return .{ .low = try a.alloc(V, self.base_count), .high = try a.alloc(V, self.base_count), .extension = try a.alloc(Oct, self.extension_count) };
    }
    fn project(owner: *const C.composition_bundle.Component, trace: *const Trace, shadow_values: ?[3][]?[]M, tree: u8, col: u32, offset: i32) !ReadColumn {
        if (tree > 2 or tree >= trace.polys.items.len) return error.MissingOm31Trace;

        const index = if (tree == 0) blk: {
            if (col >= owner.preprocessed_indices.len) return error.MissingOm31Trace;
            break :blk owner.preprocessed_indices[col];
        } else try std.math.add(usize, (try G.span(owner.*, tree)).start, col);
        if (index >= trace.polys.items[tree].len) return error.MissingOm31Trace;
        var poly = trace.polys.items[tree][index];
        if (shadow_values) |shadow| if (shadow[tree][index]) |vals| {
            poly = .{ .values = vals, .log_size = std.math.log2_int(usize, vals.len) };
        };
        try poly.validate();
        if (poly.device != null or poly.values.len == 0 or poly.log_size > owner.evaluation_log_size) return error.Om31CircuitRequiresHostLde;
        return .{ .values = poly.values, .offset = offset, .shift = @intCast(owner.evaluation_log_size - poly.log_size) };
    }
    pub fn evaluate(self: Plan, bank: Registers, r: usize, active: usize) !Oct {
        const owner = self.component;
        const lo = bank.low;
        const hi = bank.high;
        const ext = bank.extension;
        var value = simd.splat(P.O.zero());
        for (owner.parts, self.parts) |part, plan| {
            const p = part.program;
            for (p.base_insts, plan.reads) |i, read| {
                hi[i.dst] = @splat(0);
                lo[i.dst] = switch (i.op) {
                    .trace_col, .preprocessed_col => blk: {
                        if (read.high) |high| hi[i.dst] = high.load(r, owner.trace_log_size, owner.evaluation_log_size, active);
                        break :blk read.low.load(r, owner.trace_log_size, owner.evaluation_log_size, active);
                    },
                    .param => return error.InvalidOm31Parameters,
                    .constant => @splat(i.a),
                    .add => fields.addPacked(lo[i.a], lo[i.b]),
                    .sub => fields.subPacked(lo[i.a], lo[i.b]),
                    .mul => fields.mulPacked(lo[i.a], lo[i.b]),
                    .neg => fields.negPacked(lo[i.a]),
                    .inv => blk: {
                        var res: V = undefined;
                        inline for (0..fields.PACK_WIDTH) |k| res[k] = (try M.fromCanonical(lo[i.a][k]).inv()).v;
                        break :blk res;
                    },
                };
            }
            var cursor: usize = 0;
            var upcoming = plan.projections;
            while (cursor < p.ext_insts.len) {
                if (upcoming.len != 0 and upcoming[0].first == cursor) {
                    ext[upcoming[0].dst] = upcoming[0].evaluate(lo);
                    cursor += projection_len;
                    upcoming = upcoming[1..];
                    continue;
                }
                const i = p.ext_insts[cursor];
                const mode = plan.multiply[cursor];
                cursor += 1;
                ext[i.dst] = switch (i.op) {
                    .secure_col => simd.fromCoordinates(.{ lo[i.a], lo[i.b], lo[i.c], lo[i.d], hi[i.a], hi[i.b], hi[i.c], hi[i.d] }),
                    .constant => simd.splat(E.embed(P.Q.fromU32Unchecked(i.a, i.b, i.c, i.d))),
                    .param => self.parameters[i.a],
                    .add => ext[i.a].add(ext[i.b]),
                    .sub => ext[i.a].sub(ext[i.b]),
                    .mul => switch (mode) {
                        .left_base => ext[i.b].mulBase(ext[i.a].c0.c0.a),
                        .right_base => ext[i.a].mulBase(ext[i.b].c0.c0.a),
                        .full => simd.mul(ext[i.a], ext[i.b]),
                    },
                    .neg => ext[i.a].neg(),
                };
            }
            for (p.constraint_roots, plan.base_roots, 0..) |idx, is_base, i| {
                const weight = self.weights[owner.n_constraints - 1 - part.rc_base - i];
                value = value.add(if (is_base) weight.mulBase(ext[idx].c0.c0.a) else simd.mul(ext[idx], weight));
            }
        }
        return value;
    }
};

test "packed domain reads preserve lifted offsets and uneven worker tails" {
    const a = std.testing.allocator;
    const width = fields.PACK_WIDTH;
    const values = try a.alloc(M, 64);
    defer a.free(values);
    for (values, 0..) |*v, i| v.* = M.fromU64(i * 19);
    for ([_]u32{ 4, 5, 6 }) |log| {
        const column: prover.air.component_trace.Poly = .{ .log_size = log, .values = values[0 .. @as(usize, 1) << @intCast(log)] };
        for ([_]i32{ -1, 0, 1 }) |offset| for ([_]usize{ 1, width }) |active| {
            const read = ReadColumn{ .values = column.values, .shift = @intCast(6 - log), .offset = offset };
            const start = 64 - active;
            const pack = read.load(start, 5, 6, active);
            for (0..width) |k| {
                const index = core.utils.offsetBitReversedCircleDomainIndex(start + @min(k, active - 1), 5, 6, offset);
                try std.testing.expectEqual((try column.valueAtLiftingPosition(6, index)).v, pack[k]);
            }
        };
    }
}

test "packed octic product plan preserves high coordinates and register overwrite order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const B = C.eval_program.BaseInst;
    const X = C.eval_program.ExtInst;
    var source = [_]B{
        .{ .op = .trace_col, .interaction = 2, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 0, .b = 0, .imm = 0 },
    };
    var ext = [_]X{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 1, .c = 1, .d = 1 },
        .{ .op = .constant, .dst = 1, .a = 13, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 2, .a = 1, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 0, .a = 0, .b = 1, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 1, .a = 0, .b = 2, .c = 0, .d = 0 },
    };
    var roots = [_]u32{ 0, 1, 2 };
    const program = E.Program{ .allocator = a, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 3, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 3, .max_base_regs = 2, .max_ext_regs = 3, .domain_log_size = 5 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = &source, .ext_insts = &ext, .constraint_roots = &roots };
    const inter = try planPart(a, program, &.{}, &.{});
    try std.testing.expectEqualSlices(Multiply, &.{ .left_base, .right_base, .full }, inter.multiply[2..]);
    try std.testing.expectEqualSlices(bool, &.{ false, false, false }, inter.base_roots);
    source[0].interaction = 1;
    const main = try planPart(a, program, &.{}, &.{});
    try std.testing.expectEqualSlices(bool, &.{ true, true, true }, main.base_roots);
}

test "linear lookup projections equal scalar octic evaluation and preserve shared intermediates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bytes = try std.fs.cwd().readFileAlloc(a, @import("../air.zig").bundle_path, 64 << 20);
    var bundle = try @import("../air.zig").parse(a, bytes);
    defer bundle.deinit();
    var total: usize = 0;
    for (bundle.components) |component| for (component.parts) |part| {
        var p = part.program;
        const zero = try a.alloc(bool, p.header.max_base_regs);
        const high = try a.alloc(bool, zero.len);
        const low = try a.alloc(V, zero.len);
        for (p.base_insts) |i| {
            zero[i.dst] = i.op == .constant and i.a == 0;
            high[i.dst] = (i.op == .trace_col or i.op == .preprocessed_col) and i.interaction == 2;
            inline for (0..fields.PACK_WIDTH) |lane| low[i.dst][lane] = M.fromU64((@as(u64, 1) << 30) + @as(u64, i.dst) * 31 + lane).v;
        }
        const params = try a.alloc(P.O, p.header.n_ext_params);
        for (params, 0..) |*v, i| {
            var coords: [8]M = undefined;
            for (&coords, 0..) |*x, j| x.* = M.fromU64((1 << 31) - 2 - i * 37 - j);
            v.* = P.O.fromM31Array(coords);
        }
        const found = try projections(a, p, params, zero, high);
        total += found.len;
        for (found) |item| {
            const ops = p.ext_insts[item.first..][0..projection_len];
            const c = ops[3];
            const value = item.evaluate(low);
            for (0..fields.PACK_WIDTH) |lane| {
                var expected = E.embed(P.Q.fromU32Unchecked(c.a, c.b, c.c, c.d)).sub(params[ops[13].a]);
                for ([_]usize{ 0, 5, 9 }) |j| expected = expected.add(params[ops[j].a].mulM31(M.fromCanonical(low[ops[j + 1].a][lane])));
                try std.testing.expectEqual(expected, simd.lane(value, lane));
            }
        }
        if (found.len != 0) {
            const roots = try a.alloc(u32, p.constraint_roots.len + 1);
            @memcpy(roots[0..p.constraint_roots.len], p.constraint_roots);
            roots[roots.len - 1] = @intCast(found[0].first);
            p.constraint_roots = roots;
            const after = try projections(a, p, params, zero, high);
            try std.testing.expectEqual(found.len - 1, after.len);
        }
    };
    try std.testing.expect(total > 0);
}
