//! Base-field SIMD interpretation of the pinned circuit AIR on its domain.
//! OODS uses program.zig's scalar octic lens. INTER coordinates are never
//! treated as base arithmetic: the validated lens maps each quartic pack to
//! its eight physical coordinates before reconstructing the packed OM31 value.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("program.zig");
const Shapes = @import("stwo_cairo_frontend").codegen.field_shapes;
const P = @import("protocol.zig");
const M = core.fields.m31;
pub const Packed = core.fields.packed_om31;
pub const F = Packed.PackedOM31;
pub const WIDTH = M.PACK_WIDTH;
pub const Reader = struct {
    context: *const anyopaque,
    get: *const fn (*const anyopaque, u8, u32, i32) anyerror!M.PackedM31,
};
const Inter = struct { column: u32, offset: i32 };
const ExtensionOp = enum { ordinary, zero, copy_a, copy_b, scale_a, scale_b };

pub const Scratch = struct {
    allocator: std.mem.Allocator,
    base: []M.PackedM31,
    extension: []F,
    inter: []?Inter,
    operations: []ExtensionOp,
    root_kinds: []Shapes.Kind,

    pub fn init(a: std.mem.Allocator, p: E.Program) !Scratch {
        try E.validateLens(a, p);
        const base = try a.alloc(M.PackedM31, p.header.max_base_regs);
        errdefer a.free(base);
        const extension = try a.alloc(F, p.header.max_ext_regs);
        errdefer a.free(extension);
        const inter = try a.alloc(?Inter, p.ext_insts.len);
        errdefer a.free(inter);
        const operations = try a.alloc(ExtensionOp, p.ext_insts.len);
        errdefer a.free(operations);
        const root_kinds = try a.alloc(Shapes.Kind, p.constraint_roots.len);
        errdefer a.free(root_kinds);
        @memset(inter, null);
        const direct = try a.alloc(?Inter, base.len);
        defer a.free(direct);
        @memset(direct, null);
        for (p.base_insts) |i| direct[i.dst] = switch (i.op) {
            .trace_col, .preprocessed_col => if (i.interaction == 2) .{ .column = i.a, .offset = i.imm } else null,
            else => null,
        };
        for (p.ext_insts, inter) |i, *input| {
            if (i.op != .secure_col) continue;
            if (direct[i.a]) |source| input.* = .{
                .column = try std.math.mul(u32, source.column / 4, 8),
                .offset = source.offset,
            };
        }
        // These facts depend only on authenticated instructions, never on a
        // witness or a random challenge. INTER packs remain full octic values.
        var facts = try Shapes.Facts.init(a, p);
        defer facts.deinit(a);
        for (p.base_insts) |i| facts.base[i.dst] = facts.baseValue(i);
        for (p.ext_insts, operations) |i, *operation| {
            const kind = facts.extensionKind(i);
            operation.* = if (kind == .zero) .zero else switch (i.op) {
                .add, .sub => if (facts.extended[i.b] == .zero) .copy_a else if (i.op == .add and facts.extended[i.a] == .zero) .copy_b else .ordinary,
                .mul => if (facts.extended[i.a] == .one) .copy_b else if (facts.extended[i.b] == .one) .copy_a else if (facts.extended[i.a] != .secure) .scale_a else if (facts.extended[i.b] != .secure) .scale_b else .ordinary,
                else => .ordinary,
            };
            facts.extended[i.dst] = kind;
        }
        for (root_kinds, p.constraint_roots) |*kind, index| kind.* = facts.extended[index];
        return .{ .allocator = a, .base = base, .extension = extension, .inter = inter, .operations = operations, .root_kinds = root_kinds };
    }

    pub fn deinit(self: *Scratch) void {
        self.allocator.free(self.base);
        self.allocator.free(self.extension);
        self.allocator.free(self.inter);
        self.allocator.free(self.operations);
        self.allocator.free(self.root_kinds);
        self.* = undefined;
    }

    fn inverse(value: M.PackedM31) !M.PackedM31 {
        var out: M.PackedM31 = undefined;
        inline for (0..WIDTH) |lane| out[lane] = (try P.M.fromCanonical(value[lane]).inv()).v;
        return out;
    }

    pub fn evaluateInto(self: *Scratch, p: E.Program, reader: Reader, parameters: []const F, roots: []F) !void {
        if (p.header.n_base_params != 0 or p.header.n_ext_params != parameters.len or roots.len != p.constraint_roots.len or self.base.len < p.header.max_base_regs or self.extension.len < p.header.max_ext_regs or self.inter.len != p.ext_insts.len) return error.InvalidOm31Parameters;
        const base = self.base;
        const ext = self.extension;
        for (p.base_insts) |i| base[i.dst] = switch (i.op) {
            // INTER is read by the secure_col instruction below. validateLens
            // forbids using these registers in ordinary base arithmetic.
            .trace_col, .preprocessed_col => if (i.interaction == 2) @splat(0) else try reader.get(reader.context, i.interaction, i.a, i.imm),
            .param => return error.InvalidOm31Parameters,
            .constant => M.splatPacked(P.M.fromCanonical(i.a)),
            .add => M.addPacked(base[i.a], base[i.b]),
            .sub => M.subPacked(base[i.a], base[i.b]),
            .mul => M.mulPacked(base[i.a], base[i.b]),
            .neg => M.subPacked(@splat(0), base[i.a]),
            .inv => try inverse(base[i.a]),
        };
        for (p.ext_insts, self.inter, self.operations) |i, inter, operation| ext[i.dst] = switch (operation) {
            .zero => Packed.splat(P.O.zero()),
            .copy_a => ext[i.a],
            .copy_b => ext[i.b],
            .scale_a => ext[i.b].mulBase(ext[i.a].c0.c0.a),
            .scale_b => ext[i.a].mulBase(ext[i.b].c0.c0.a),
            .ordinary => switch (i.op) {
                .secure_col => blk: {
                    var coordinates: [8]M.PackedM31 = undefined;
                    if (inter) |input| {
                        inline for (0..8) |j| coordinates[j] = try reader.get(reader.context, 2, input.column + @as(u32, j), input.offset);
                    } else {
                        coordinates = .{ base[i.a], base[i.b], base[i.c], base[i.d], @splat(0), @splat(0), @splat(0), @splat(0) };
                    }
                    break :blk Packed.fromCoordinates(coordinates);
                },
                .param => parameters[i.a],
                .constant => Packed.splat(E.embed(P.Q.fromU32Unchecked(i.a, i.b, i.c, i.d))),
                .add => ext[i.a].add(ext[i.b]),
                .sub => ext[i.a].sub(ext[i.b]),
                .mul => Packed.mul(ext[i.a], ext[i.b]),
                .neg => ext[i.a].neg(),
            },
        };
        for (roots, p.constraint_roots) |*out, index| out.* = ext[index];
    }
};
