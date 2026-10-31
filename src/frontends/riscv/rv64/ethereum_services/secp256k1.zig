//! Concrete RCB projective programs matching k256 0.13.4's homogeneous XYZ.
//! Constants and topology are immutable setup; raw input words are reduced once.
const std = @import("std");
pub const MODULUS: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
pub const Kind = enum(u8) { add = 1, double = 2 };
pub const Ref = union(enum) { wire: u8, small: u8, modulus };
pub const Operation = struct { kind: enum { multiply, add, subtract, reduce_once }, lhs: Ref, rhs: Ref, result: u8 };
pub const MAX_OPS = 64;
pub const MAX_WIRES = 80;
pub const Program = struct {
    kind: Kind,
    inputs: u8,
    operations: [MAX_OPS]Operation = undefined,
    length: u8 = 0,
    wires: u8,
    uses: [MAX_WIRES]u8 = @splat(0),
    outputs: [3]u8 = undefined,
    pub fn rows(self: *const Program, product: bool) usize {
        var count: usize = 0;
        for (self.operations[0..self.length]) |op| if ((op.kind == .multiply) == product) {
            count += 1;
        };
        return count;
    }
    pub fn operation(self: *const Program, product: bool, index: usize) Operation {
        var found: usize = 0;
        for (self.operations[0..self.length]) |op| {
            if ((op.kind == .multiply) != product) continue;
            if (found == index) return op;
            found += 1;
        }
        unreachable;
    }
    fn append(self: *Program, kind: @FieldType(Operation, "kind"), lhs: Ref, rhs: Ref) Ref {
        const wire = self.wires;
        self.wires += 1;
        self.operations[self.length] = .{ .kind = kind, .lhs = lhs, .rhs = rhs, .result = wire };
        self.length += 1;
        for ([_]Ref{ lhs, rhs }) |r| switch (r) {
            .wire => |w| self.uses[w] += 1,
            else => {},
        };
        return .{ .wire = wire };
    }
    fn mul(self: *Program, a: Ref, b: Ref) Ref {
        return self.append(.multiply, a, b);
    }
    fn plus(self: *Program, a: Ref, b: Ref) Ref {
        return self.append(.add, a, b);
    }
    fn minus(self: *Program, a: Ref, b: Ref) Ref {
        return self.append(.subtract, a, b);
    }
};
pub const add = build(.add);
pub const double = build(.double);
pub fn get(kind: Kind) *const Program {
    return switch (kind) {
        .add => &add,
        .double => &double,
    };
}
fn build(kind: Kind) Program {
    @setEvalBranchQuota(10000);
    const count: u8 = if (kind == .add) 6 else 3;
    var p = Program{ .kind = kind, .inputs = count, .wires = count };
    var input: [6]Ref = undefined;
    for (0..count) |i| input[i] = p.append(.reduce_once, .{ .wire = @intCast(i) }, .modulus);
    const x = input[0];
    const y = input[1];
    const z = input[2];
    var output: [3]Ref = undefined;
    if (kind == .add) {
        const xx = p.mul(x, input[3]);
        const yy = p.mul(y, input[4]);
        const zz = p.mul(z, input[5]);
        const xy = p.minus(p.minus(p.mul(p.plus(x, y), p.plus(input[3], input[4])), xx), yy);
        const yz = p.minus(p.minus(p.mul(p.plus(y, z), p.plus(input[4], input[5])), yy), zz);
        const xz = p.minus(p.minus(p.mul(p.plus(x, z), p.plus(input[3], input[5])), xx), zz);
        const bzz3 = p.mul(zz, .{ .small = 21 });
        const ym = p.minus(yy, bzz3);
        const yp = p.plus(yy, bzz3);
        const byz3 = p.mul(yz, .{ .small = 21 });
        const xx3 = p.mul(xx, .{ .small = 3 });
        const bxx9 = p.mul(xx, .{ .small = 63 });
        output = .{ p.minus(p.mul(xy, ym), p.mul(byz3, xz)), p.plus(p.mul(yp, ym), p.mul(bxx9, xz)), p.plus(p.mul(yz, yp), p.mul(xx3, xy)) };
    } else {
        const yy = p.mul(y, y);
        const zz = p.mul(z, z);
        const xy2 = p.mul(p.mul(x, y), .{ .small = 2 });
        const bzz3 = p.mul(zz, .{ .small = 21 });
        const bzz9 = p.mul(zz, .{ .small = 63 });
        const ym = p.minus(yy, bzz9);
        const yp = p.plus(yy, bzz3);
        const t = p.mul(p.mul(yy, zz), .{ .small = 168 });
        output = .{ p.mul(xy2, ym), p.plus(p.mul(ym, yp), t), p.mul(p.mul(p.mul(yy, y), z), .{ .small = 8 }) };
    }
    for (output, 0..) |r, i| {
        p.outputs[i] = r.wire;
        p.uses[r.wire] += 1;
    }
    return p;
}
pub const Values = [MAX_WIRES]u256;
pub fn execute(program: *const Program, inputs: []const u256) !Values {
    if (inputs.len != program.inputs) return error.InvalidProjectiveInputCount;
    var values: Values = @splat(0);
    @memcpy(values[0..inputs.len], inputs);
    const modulus = MODULUS;
    for (program.operations[0..program.length]) |op| {
        const a = resolve(op.lhs, &values);
        const b = resolve(op.rhs, &values);
        values[op.result] = switch (op.kind) {
            .multiply => @intCast(@as(u512, a) * b % modulus),
            .add => @intCast((@as(u512, a) + b) % modulus),
            .subtract => if (a >= b) a - b else modulus - (b - a),
            .reduce_once => if (a >= modulus) a - modulus else a,
        };
    }
    return values;
}
pub fn resolve(ref: Ref, values: *const Values) u256 {
    return switch (ref) {
        .wire => |i| values[i],
        .small => |i| i,
        .modulus => MODULUS,
    };
}
pub fn bytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .little);
    return out;
}
