//! One instruction/basis authority for native OM31 and its two-QM31 circuit lane.
//! External callers must check their lane's latched builder error before any
//! graph is accepted; this interpreter never turns that failure into authority.
const std = @import("std");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const Q = P.Q;
const M = P.M;
pub const Program = C.eval_program.Program;
pub fn ForLane(comptime F: type) type {
    if (F != P.O and (!@hasDecl(F, "rv64_extension_degree") or F.rv64_extension_degree != 8)) @compileError("OM31 circuit interpreter requires the concrete octic field/lane");
    return struct {
        fn basis() F {
            return F.fromM31Array(.{ M.zero(), M.zero(), M.zero(), M.zero(), M.one(), M.zero(), M.zero(), M.zero() });
        }
        fn inverse(value: F) !F {
            if (@typeInfo(@TypeOf(value.inv())) == .error_union) return try value.inv();
            return value.inv();
        }
        pub const Reader = struct {
            context: *const anyopaque,
            get: *const fn (*const anyopaque, u8, u32, i32) anyerror!F,
            pub fn read(self: @This(), tree: u8, logical: u32, offset: i32) !F {
                if (tree != 2) return self.get(self.context, tree, logical, offset);
                const low = try std.math.add(u32, try std.math.mul(u32, logical / 4, 8), logical % 4);
                return (try self.get(self.context, 2, low, offset)).add(basis().mul(try self.get(self.context, 2, try std.math.add(u32, low, 4), offset)));
            }
        };
        pub fn embed(value: Q) F {
            const c = value.toM31Array();
            return F.fromM31Array(.{ c[0], c[1], c[2], c[3], M.zero(), M.zero(), M.zero(), M.zero() });
        }
        pub fn pack4(values: [4]F) F {
            return F.fromPartialEvals(.{ values[0], values[1], values[2], values[3], F.zero(), F.zero(), F.zero(), F.zero() });
        }
        pub const Scratch = struct {
            allocator: std.mem.Allocator,
            base: []F,
            extension: []F,
            pub fn init(a: std.mem.Allocator, p: Program) !Scratch {
                const base = try a.alloc(F, p.header.max_base_regs);
                errdefer a.free(base);
                return .{ .allocator = a, .base = base, .extension = try a.alloc(F, p.header.max_ext_regs) };
            }
            pub fn deinit(self: *@This()) void {
                self.allocator.free(self.base);
                self.allocator.free(self.extension);
                self.* = undefined;
            }
            /// Domain workers reuse one register bank and root buffer for an entire
            /// row tile. No witness planes, parameter arrays or masks are rebuilt here.
            pub fn evaluateInto(self: *Scratch, p: Program, reader: Reader, parameters: []const F, roots: []F) !void {
                if (p.header.n_base_params != 0 or p.header.n_ext_params != parameters.len or roots.len != p.constraint_roots.len or self.base.len < p.header.max_base_regs or self.extension.len < p.header.max_ext_regs) return error.InvalidOm31Parameters;
                const base = self.base;
                const ext = self.extension;
                for (p.base_insts) |i| base[i.dst] = switch (i.op) {
                    .trace_col, .preprocessed_col => try reader.read(i.interaction, i.a, i.imm),
                    .param => return error.InvalidOm31Parameters,
                    .constant => F.fromBase(M.fromCanonical(i.a)),
                    .add => base[i.a].add(base[i.b]),
                    .sub => base[i.a].sub(base[i.b]),
                    .mul => base[i.a].mul(base[i.b]),
                    .neg => base[i.a].neg(),
                    .inv => try inverse(base[i.a]),
                };
                for (p.ext_insts) |i| ext[i.dst] = switch (i.op) {
                    .secure_col => pack4(.{ base[i.a], base[i.b], base[i.c], base[i.d] }),
                    .param => parameters[i.a],
                    .constant => embed(Q.fromU32Unchecked(i.a, i.b, i.c, i.d)),
                    .add => ext[i.a].add(ext[i.b]),
                    .sub => ext[i.a].sub(ext[i.b]),
                    .mul => ext[i.a].mul(ext[i.b]),
                    .neg => ext[i.a].neg(),
                };
                for (roots, p.constraint_roots) |*out, index| out.* = ext[index];
            }
        };
        /// Convenience for isolated OODS evaluation; DOMAIN callers retain Scratch.
        pub fn evaluate(a: std.mem.Allocator, p: Program, reader: Reader, parameters: []const F) ![]F {
            var scratch = try Scratch.init(a, p);
            defer scratch.deinit();
            const roots = try a.alloc(F, p.constraint_roots.len);
            errdefer a.free(roots);
            try scratch.evaluateInto(p, reader, parameters, roots);
            return roots;
        }

        fn power(x: F, n: u32) F {
            var out = F.one();
            var base = x;
            var exponent = n;
            while (exponent != 0) : (exponent >>= 1) {
                if (exponent & 1 != 0) out = out.mul(base);
                base = base.square();
            }
            return out;
        }
        /// Original ExtSource meanings, widened without changing Q4 constants.
        pub fn extensionParameters(a: std.mem.Allocator, c: *const C.composition_bundle.Component, z: F, alpha: F, claim: F) ![]F {
            const out = try a.alloc(F, c.ext_sources.len);
            errdefer a.free(out);
            const scale = try M.fromCanonical(@as(u32, 1) << @intCast(c.trace_log_size)).inv();
            for (out, c.ext_sources) |*v, source| v.* = switch (source) {
                .constant => |w| embed(Q.fromU32Unchecked(w[0], w[1], w[2], w[3])),
                .lookup_z => z,
                .lookup_alpha_power => |n| power(alpha, n),
                .lookup_alpha_power_scaled => |x| power(alpha, x.power).mulM31(M.fromCanonical(x.scale)),
                .claimed_sum_scaled => claim.mulM31(scale),
            };
            return out;
        }
    };
}
