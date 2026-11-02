//! Recording lane: runs an RV64 component's own generic `emitFor` once over
//! symbolic values and records every lane operation into a
//! `secure_polynomial_program_v2` DAG.
//!
//! Unlike an external (circuit) lane, a symbolic lane keeps the component's
//! native constant family (`Const`, QM31 or OM31): the component is the very
//! instance the prover runs, with its Q-typed claims, challenges and publics.
//! Those constants enter the DAG as invocation parameters (`splatFor`), while
//! literal integers (`qFor`) become constants. Every mask read is an input.
//! Recording is cold, single-threaded per builder and never used in proving.
const std = @import("std");
const core = @import("stwo_core");
const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v2;
const M = core.fields.m31.M31;

pub fn isSymbolic(comptime F: type) bool {
    return @typeInfo(F) == .@"struct" and @hasDecl(F, "rv64_symbolic_lane") and F.rv64_symbolic_lane;
}

pub fn SymbolicLane(comptime C: type) type {
    return struct {
        const Self = @This();
        pub const rv64_symbolic_lane = true;
        pub const Const = C;
        pub const Builder = ir.BuilderFor(C);
        pub const DEGREE = ir.degreeOf(C);
        id: u32,

        /// The recorder this thread writes into; set by `Recording.begin`.
        pub threadlocal var active: ?*Builder = null;
        inline fn b() *Builder {
            return active orelse @panic("symbolic RV64 lane used outside a recording");
        }
        /// Node ids `Recording.init` reserves for the literals 0 and 1, so
        /// comptime-known lane zeros/ones (struct field defaults, container
        /// constants in generic emitters) need no active builder.
        pub const ZERO_ID: u32 = 0;
        pub const ONE_ID: u32 = 1;
        pub fn zero() Self {
            if (@inComptime()) return .{ .id = ZERO_ID };
            return .{ .id = b().constant(C.zero()) };
        }
        pub fn one() Self {
            if (@inComptime()) return .{ .id = ONE_ID };
            return .{ .id = b().constant(C.one()) };
        }
        pub fn fromU32(x: u32) Self {
            return .{ .id = b().constant(C.fromBase(M.fromCanonical(x))) };
        }
        pub fn fromCanonical(x: u32) Self {
            return fromU32(x);
        }
        pub fn fromBase(m: M) Self {
            return .{ .id = b().constant(C.fromBase(m)) };
        }
        /// Literal secure constant (fixed protocol constant, never an FS draw).
        pub fn literal(c: C) Self {
            return .{ .id = b().constant(c) };
        }
        /// Typed public / challenge / claim value: an invocation parameter.
        pub fn fromConst(c: C) Self {
            return .{ .id = b().parameter(c) };
        }
        pub fn splat(c: C) Self {
            return fromConst(c);
        }
        pub fn input(tree: u8, column: usize, offset: i8) Self {
            return .{ .id = b().input(.{ .tree = tree, .column = @intCast(column), .offset = offset }) };
        }
        pub fn fromPartialEvals(c: [DEGREE]Self) Self {
            var out = c[0];
            for (1..DEGREE) |i| {
                var unit: [DEGREE]C = @splat(C.zero());
                unit[i] = C.one();
                out = out.add(c[i].mul(literal(C.fromPartialEvals(unit))));
            }
            return out;
        }
        pub fn add(x: Self, y: Self) Self {
            return .{ .id = b().add(x.id, y.id) };
        }
        pub fn sub(x: Self, y: Self) Self {
            return .{ .id = b().sub(x.id, y.id) };
        }
        pub fn mul(x: Self, y: Self) Self {
            return .{ .id = b().mul(x.id, y.id) };
        }
        pub fn mulBase(x: Self, y: Self) Self {
            return x.mul(y);
        }
        pub fn neg(x: Self) Self {
            return .{ .id = b().neg(x.id) };
        }
        pub fn square(x: Self) Self {
            return x.mul(x);
        }
        pub fn double(x: Self) Self {
            return x.add(x);
        }
    };
}

/// RAII-style scope binding a builder to the current thread's lane.
pub fn Recording(comptime C: type) type {
    const Lane = SymbolicLane(C);
    return struct {
        builder: Lane.Builder,
        previous: ?*Lane.Builder = null,
        pub fn init(a: std.mem.Allocator) @This() {
            var builder = Lane.Builder.init(a);
            // Reserve ZERO_ID/ONE_ID (an allocation failure is latched in
            // `builder.failure` and surfaces from `finish`).
            const zero_id = builder.constant(C.zero());
            const one_id = builder.constant(C.one());
            std.debug.assert(builder.failure != null or (zero_id == Lane.ZERO_ID and one_id == Lane.ONE_ID));
            return .{ .builder = builder };
        }
        pub fn begin(self: *@This()) void {
            self.previous = Lane.active;
            Lane.active = &self.builder;
        }
        pub fn end(self: *@This()) void {
            Lane.active = self.previous;
        }
        pub fn deinit(self: *@This()) void {
            self.builder.deinit();
        }
    };
}
