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
pub const Registers = struct { low: []V, high: []V, extension: []Oct };
pub const Plan = struct {
    component: *const C.composition_bundle.Component,
    reads: []const []const Reads,
    parameters: []const Oct,
    weights: []const Oct,
    base_count: usize,
    extension_count: usize,
    /// The caller's component arena owns the projection and the worker banks.
    pub fn init(a: std.mem.Allocator, owner: *const C.composition_bundle.Component, trace: *const Trace, shadow: ?[3][]?[]M, parameters: []const P.O, weights: []const P.O) !Plan {
        const parts = try a.alloc([]const Reads, owner.parts.len);
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
            dest.* = reads;
        }
        return .{ .component = owner, .reads = parts, .base_count = base_count, .extension_count = extension_count, .parameters = try broadcast(a, parameters), .weights = try broadcast(a, weights) };
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
        for (owner.parts, self.reads) |part, reads| {
            const p = part.program;
            for (p.base_insts, reads) |i, read| {
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
            for (p.ext_insts) |i| ext[i.dst] = switch (i.op) {
                .secure_col => simd.fromCoordinates(.{ lo[i.a], lo[i.b], lo[i.c], lo[i.d], hi[i.a], hi[i.b], hi[i.c], hi[i.d] }),
                .constant => simd.splat(E.embed(P.Q.fromU32Unchecked(i.a, i.b, i.c, i.d))),
                .param => self.parameters[i.a],
                .add => ext[i.a].add(ext[i.b]),
                .sub => ext[i.a].sub(ext[i.b]),
                .mul => simd.mul(ext[i.a], ext[i.b]),
                .neg => ext[i.a].neg(),
            };
            for (p.constraint_roots, 0..) |idx, i| value = value.add(simd.mul(ext[idx], self.weights[owner.n_constraints - 1 - part.rc_base - i]));
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
