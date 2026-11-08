const std = @import("std");
const core = @import("stwo_core");
const E = @import("program.zig");
const D = @import("domain_program.zig");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
const a = std.testing.allocator;

const Rows = struct {
    first: usize,
    fn value(row: usize, tree: u8, col: u32, offset: i32) P.M {
        return P.M.fromU64(13 + @as(u64, @intCast(row)) * 271 + @as(u64, tree) * 1777 + @as(u64, col) * 191 + @as(u32, @bitCast(offset)));
    }
    fn scalar(raw: *const anyopaque, tree: u8, col: u32, offset: i32) !P.O {
        const self: *const Rows = @ptrCast(@alignCast(raw));
        return P.O.fromBase(value(self.first, tree, col, offset));
    }
    fn readPack(raw: *const anyopaque, tree: u8, col: u32, offset: i32) !core.fields.m31.PackedM31 {
        const self: *const Rows = @ptrCast(@alignCast(raw));
        var out: core.fields.m31.PackedM31 = undefined;
        inline for (0..D.WIDTH) |lane| out[lane] = value(self.first + lane, tree, col, offset).v;
        return out;
    }
};

test "OM31 SIMD domain preserves every pinned AIR root and both interaction halves" {
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Air.parse(a, bytes);
    defer bundle.deinit();
    var parts: usize = 0;
    for (bundle.components) |*component| {
        const parameters = try a.alloc(P.O, component.ext_sources.len);
        defer a.free(parameters);
        const packed_parameters = try a.alloc(D.F, parameters.len);
        defer a.free(packed_parameters);
        for (parameters, packed_parameters, 0..) |*out, *pack_value, i| {
            var coordinates: [8]P.M = undefined;
            for (&coordinates, 0..) |*c, j| c.* = P.M.fromU64(19 + i * 177 + j * 61);
            out.* = P.O.fromM31Array(coordinates);
            pack_value.* = D.Packed.splat(out.*);
        }
        for (component.parts) |part| {
            var scratch = try D.Scratch.init(a, part.program);
            defer scratch.deinit();
            const roots = try a.alloc(D.F, part.program.constraint_roots.len);
            defer a.free(roots);
            for (0..4) |tile| {
                var read = Rows{ .first = tile * D.WIDTH };
                try scratch.evaluateInto(part.program, .{ .context = &read, .get = Rows.readPack }, packed_parameters, roots);
                for (0..D.WIDTH) |lane| {
                    read.first = tile * D.WIDTH + lane;
                    const scalar = try E.evaluate(a, part.program, .{ .context = &read, .get = Rows.scalar }, parameters);
                    defer a.free(scalar);
                    for (roots, scalar) |pack_value, want| try std.testing.expect(D.Packed.lane(pack_value, lane).eql(want));
                }
            }
            parts += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 11), bundle.components.len);
    try std.testing.expect(parts >= 11);
}

test "OM31 SIMD domain rejects arithmetic on interaction coordinates" {
    const C = @import("stwo_cairo_frontend").witness.eval_program;
    var base = [_]C.BaseInst{
        .{ .op = .trace_col, .interaction = 2, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .neg, .interaction = 0, .dst = 1, .a = 0, .b = 0, .imm = 0 },
    };
    var ext = [_]C.ExtInst{.{ .op = .secure_col, .dst = 0, .a = 1, .b = 1, .c = 1, .d = 1 }};
    var roots = [_]u32{0};
    const program = E.Program{ .allocator = a, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 3, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 2, .max_ext_regs = 1, .domain_log_size = 5 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = &base, .ext_insts = &ext, .constraint_roots = &roots };
    try std.testing.expectError(error.UnsupportedOm31InteractionArithmetic, D.Scratch.init(a, program));
}
