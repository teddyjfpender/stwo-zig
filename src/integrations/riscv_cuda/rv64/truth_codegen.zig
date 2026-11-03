//! Record existing truth equation authority with named runtime parameter wires.
//! The last-anchor polynomial is a public auxiliary, never a committed column.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
pub const Role = @import("stwo_riscv_cpu_integration").rv64_gkr_truth_role;
const X = @import("symbolic_external.zig");
const F = X.Lane;
const C = @import("composition_codegen.zig");
const O = core.fields.om31.OM31;
pub const slots = struct {
    pub const span = 0;
    pub const polynomial = 3;
    pub const offsets = 4;
    pub const coefficients = 7;
    pub const kio = 25;
    pub const wire = kio + 1 + A.crypto.keccak.layout.IO_ARITY;
    pub const claim = wire + 1 + A.crypto.secp256k1.layout.WIRE_ARITY;
    pub const global_claim = claim + 1;
    pub const count = global_claim + 1;
};
pub fn symbolicParameters() Role.Component.ParametersFor(F) {
    var p: Role.Component.ParametersFor(F) = undefined;
    p.span = .{ .calls = F.parameter(0), .first_id = F.parameter(1), .nonempty = F.parameter(2) };
    p.local.polynomial = F.parameter(slots.polynomial);
    for (&p.local.offsets, 0..) |*v, i| v.* = F.parameter(slots.offsets + @as(u32, @intCast(i)));
    for (&p.local.coefficients, 0..) |*row, i| for (row, 0..) |*v, j| {
        v.* = F.parameter(slots.coefficients + @as(u32, @intCast(6 * i + j)));
    };
    p.kio.offset = F.parameter(slots.kio);
    for (&p.kio.coefficients, 0..) |*v, i| v.* = F.parameter(slots.kio + 1 + @as(u32, @intCast(i)));
    p.wire.offset = F.parameter(slots.wire);
    for (&p.wire.coefficients, 0..) |*v, i| v.* = F.parameter(slots.wire + 1 + @as(u32, @intCast(i)));
    p.claim = F.parameter(slots.claim);
    p.global_claim = F.parameter(slots.global_claim);
    return p;
}
pub fn nativeMetadata(component: *const Role.Component) [slots.count]O {
    var values: [slots.count]O = @splat(O.zero());
    const M = core.fields.m31.M31;
    values[0] = O.fromBase(M.fromCanonical(component.calls));
    values[1] = O.fromBase(M.fromCanonical(component.first_id));
    values[2] = if (component.calls == 0) O.zero() else O.one();
    values[slots.polynomial] = component.local.polynomial;
    @memcpy(values[slots.offsets..][0..3], &component.local.offsets);
    for (component.local.coefficients, 0..) |row, i| @memcpy(values[slots.coefficients + 6 * i ..][0..6], &row);
    values[slots.kio] = component.shared.kio.offset;
    @memcpy(values[slots.kio + 1 ..][0..component.shared.kio.coefficients.len], &component.shared.kio.coefficients);
    values[slots.wire] = component.shared.wire.offset;
    @memcpy(values[slots.wire + 1 ..][0..component.shared.wire.coefficients.len], &component.shared.wire.coefficients);
    values[slots.claim] = component.claim;
    values[slots.global_claim] = component.global_claim;
    return values;
}
pub const Artifact = struct {
    a: std.mem.Allocator,
    program: C.Program,
    parameter_slots: []u32,
    last_anchor_column: usize,
    pub fn deinit(self: *@This()) void {
        self.program.deinit();
        self.a.free(self.parameter_slots);
        self.* = undefined;
    }
};
pub fn record(a: std.mem.Allocator, component: *const Role.Component) !Artifact {
    const shape = component.shape();
    const width = shape.widths();
    var recording = X.Recording.init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const Sample = struct {
        anchor: usize,
        pub fn get(_: @This(), tree: usize, column: usize, offset: i32) !F {
            return F.input(@intCast(tree), column, @intCast(offset));
        }
        pub fn last(self: @This()) !F {
            return F.input(2, self.anchor, 0);
        }
    };
    const values = try a.alloc(F, shape.nConstraints());
    defer a.free(values);
    const workspace = try a.create(Role.Component.Workspace(F));
    defer a.destroy(workspace);
    var sink = E.SinkFor(F){ .values = values };
    try component.emitWithParameters(F, Sample{ .anchor = width[2] }, &sink, workspace, symbolicParameters());
    if (sink.count != values.len) return error.WrongTruthConstraintCount;
    const roots = try a.alloc(u32, values.len);
    defer a.free(roots);
    for (roots, values) |*r, v| r.* = v.id;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/cuda/native-truth-equations/v1");
    for ([_]u32{ @intFromEnum(shape.kind), @intFromEnum(shape.keccak_policy), @intFromEnum(shape.byte_policy), if (component.program) |p| @intFromEnum(p.kind) else std.math.maxInt(u32) }) |tag| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, tag, .little);
        hash.update(&bytes);
    }
    var program = try recording.builder.finish(hash.finalResult(), roots);
    errdefer program.deinit();
    const map = try a.alloc(u32, program.parameters.len);
    errdefer a.free(map);
    for (program.parameters, map) |p, *slot| {
        const coordinates = p.toM31Array();
        for (coordinates[1..]) |v| if (!v.isZero()) return error.InvalidTruthParameter;
        if (coordinates[0].v == 0 or coordinates[0].v > slots.count) return error.InvalidTruthParameter;
        slot.* = coordinates[0].v - 1;
    }
    return .{ .a = a, .program = program, .parameter_slots = map, .last_anchor_column = width[2] };
}

test "classic truth records the existing equation authority with bounded mask geometry" {
    const a = std.testing.allocator;
    for (std.enums.values(Role.Kind)) |kind| {
        var component = Role.Component{
            .kind = kind,
            .log_size = 5,
            .program = if (kind == .product or kind == .linear) A.crypto.secp256k1.program.get(.add) else null,
            .byte_policy = .canonical_inputs,
            .local = std.mem.zeroes(@FieldType(Role.Component, "local")),
            .shared = std.mem.zeroes(@FieldType(Role.Component, "shared")),
            .claim = O.zero(),
        };
        const Dense = struct {
            fn value(seed: usize) O {
                var words: [8]core.fields.m31.M31 = undefined;
                for (&words, 0..) |*v, i| v.* = core.fields.m31.M31.fromCanonical(@intCast((seed * 73 + i * 151 + 1) % core.fields.m31.Modulus));
                return O.fromM31Array(words);
            }
            pub fn get(_: @This(), tree: usize, column: usize, offset: i32) !O {
                return value(1 + tree * 100000 + column * 11 + @as(usize, @intCast(offset + 2)));
            }
            pub fn last(_: @This()) !O {
                return value(999999);
            }
        };
        component.calls = 3;
        component.first_id = 2;
        component.local.polynomial = Dense.value(1);
        for (&component.local.offsets, 0..) |*v, i| v.* = Dense.value(i + 2);
        for (&component.local.coefficients, 0..) |*row, i| for (row, 0..) |*v, j| {
            v.* = Dense.value(50 + i * 6 + j);
        };
        inline for (.{ "ram", "kio", "wire" }) |name| {
            @field(component.shared, name).offset = Dense.value(77);
            for (&@field(component.shared, name).coefficients, 0..) |*v, i| v.* = Dense.value(99 + i);
        }
        component.claim = Dense.value(110);
        component.global_claim = Dense.value(111);
        var artifact = try record(a, &component);
        defer artifact.deinit();
        try artifact.program.validate();
        try std.testing.expectEqual(component.nConstraints(), artifact.program.roots.len);
        const degrees = try artifact.program.degrees(a);
        defer a.free(degrees);
        for (artifact.program.roots) |root| try std.testing.expect(degrees[root] <= component.shape().maxDegree());
        const params = nativeMetadata(&component);
        for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
        const inputs = try a.alloc(O, artifact.program.inputs.len);
        defer a.free(inputs);
        for (inputs, artifact.program.inputs) |*v, input| v.* = if (input.tree == 2 and input.column == artifact.last_anchor_column) try Dense.last(.{}) else try Dense.get(.{}, input.tree, input.column, input.offset);
        const actual = try artifact.program.evaluate(a, inputs);
        defer a.free(actual);
        const expected = try a.alloc(O, component.nConstraints());
        defer a.free(expected);
        var native_sink = E.SinkFor(O){ .values = expected };
        const native_workspace = try a.create(Role.Component.Workspace(O));
        defer a.destroy(native_workspace);
        try component.emitForWithWorkspace(O, Dense{}, &native_sink, native_workspace);
        try std.testing.expectEqual(expected.len, native_sink.count);
        for (expected, actual) |x, y| try std.testing.expect(x.eql(y));
        const widths = component.widths();
        for (artifact.program.inputs) |input| {
            try std.testing.expect(input.tree < 3);
            const is_anchor = input.tree == 2 and input.column == artifact.last_anchor_column;
            if (is_anchor) {
                try std.testing.expectEqual(@as(i8, 0), input.offset);
            } else {
                try std.testing.expect(input.column < widths[input.tree]);
                try std.testing.expect(std.mem.indexOfScalar(i32, component.shifts(input.tree, input.column), input.offset) != null);
            }
        }
    }
}
