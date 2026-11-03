//! Cold native authority fixtures reused by the joined DOMAIN CUDA qualifier.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const T = @import("truth_codegen.zig");
const C = @import("composition_codegen.zig");
const IO = @import("fixture_io.zig");
const Oracle = @import("joined_fixture_support.zig");
const Field = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const count = 10;
pub const Record = struct { artifact: T.Artifact, widths: [3]usize, classic: ?T.Role.Component };
pub fn record(a: std.mem.Allocator, id: u32) !Record {
    if (id < 3 or (id >= 7 and id < 10)) {
        const kind = ([3]T.Role.Kind{ .keccak, .chi, .xor5 })[if (id < 3) id else id - 7];
        const c = T.Role.Component{ .kind = kind, .log_size = 5, .keccak_policy = if (id < 3) .throughput_r27_v1 else .triple_v2, .local = std.mem.zeroes(@FieldType(T.Role.Component, "local")), .shared = std.mem.zeroes(@FieldType(T.Role.Component, "shared")), .claim = Field.zero(), .split = 2 };
        var widths = c.widths();
        widths[2] += 1;
        return .{ .artifact = try T.record(a, &c), .widths = widths, .classic = c };
    }
    switch (id) {
        3 => return v3(a, T.V3Catalog.Sha(), id),
        4 => return v3(a, T.V3Catalog.Arith(), id),
        5 => return v3(a, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add), id),
        6 => return v3(a, T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double), id),
        else => return error.InvalidTruthKernel,
    }
}
fn v3(a: std.mem.Allocator, comptime Type: type, id: u32) !Record {
    const family: T.V3Catalog.Family = if (Type == T.V3Catalog.Sha()) .sha256 else if (Type == T.V3Catalog.Arith()) .arith256_mod else if (id == 5) .add else .double;
    return .{ .artifact = try T.recordV3Type(a, Type, @intFromEnum(family)), .widths = .{ Type.fixed, Type.L.MAIN, (Type.byte_batches + Type.wire_batches) * 8 }, .classic = null };
}
const Samples = struct {
    trees: [3][]M,
    rows: usize,
    trace_log: u32,
    eval_log: u32,
    at: usize,
    last_column: usize,
    pub fn get(self: @This(), tree: usize, column: usize, shift: i32) !Field {
        const row = core.utils.offsetBitReversedCircleDomainIndex(self.at, self.trace_log, self.eval_log, shift);
        return Field.fromBase(self.trees[tree][column * self.rows + row]);
    }
    pub fn last(self: @This()) !Field {
        return self.get(2, self.last_column, 0);
    }
};
fn nativeV3(comptime Type: type, samples: Samples, params: *const [T.slots.count]Field, sink: *E.SinkFor(Field)) !void {
    const View = struct {
        s: Samples,
        pub fn fixed(v: *const @This(), c: usize) Field {
            return v.s.get(0, c, 0) catch unreachable;
        }
        pub fn main(v: *const @This(), c: usize) Field {
            return v.s.get(1, c, 0) catch unreachable;
        }
        pub fn previousActive(v: *const @This()) Field {
            return v.s.get(1, 0, -1) catch unreachable;
        }
        pub fn interaction(v: *const @This(), c: usize) Field {
            return v.s.get(2, c, 0) catch unreachable;
        }
        pub fn previousInteraction(v: *const @This(), c: usize) Field {
            return v.s.get(2, c, -1) catch unreachable;
        }
    };
    const view = View{ .s = samples };
    var wire: A.crypto.sha256.equations.WireFor(Field) = undefined;
    wire.offset = params[T.slots.wire];
    for (&wire.coefficients, 0..) |*v, i| v.* = params[T.slots.wire + 1 + i];
    const span = E.CallSpanFor(Field){ .calls = 3, .first_id = 2 };
    Type.Eq.emitMain(Field, &view, span, sink);
    if (Type.bytes == 0) Type.Eq.emitInteraction(Field, &view, span, params[T.slots.claim], wire, sink) else Type.Eq.emitInteraction(Field, &view, span, params[T.slots.claim], .{ .bytes = params[T.slots.polynomial], .wire = wire }, sink);
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32) !void {
    var item = try record(a, id);
    defer item.artifact.deinit();
    const artifact = &item.artifact;
    const trace_log: u32 = 5;
    const eval_log: u32 = 7;
    const rows: usize = 1 << eval_log;
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    const name = try std.fmt.allocPrint(a, "rv64_truth_domain_{}", .{id});
    defer a.free(name);
    try C.emitGrouped(a, source.writer(a), &artifact.program, name, 32);
    const source_name = try std.fmt.allocPrint(a, "case-{}-domain.cu", .{id});
    defer a.free(source_name);
    try dir.writeFile(.{ .sub_path = source_name, .data = source.items });
    var random = std.Random.DefaultPrng.init(0x971432 + id);
    var params: [T.slots.count]Field = undefined;
    for (&params) |*v| v.* = Oracle.random(random.random());
    params[0] = Field.fromBase(M.fromCanonical(3));
    params[1] = Field.fromBase(M.fromCanonical(2));
    params[2] = Field.one();
    for (artifact.program.parameters, artifact.parameter_slots) |*v, slot| v.* = params[slot];
    var trees: [3][]M = undefined;
    var allocated: usize = 0;
    defer for (trees[0..allocated]) |tree| a.free(tree);
    for (&trees, item.widths) |*tree, width| {
        tree.* = try a.alloc(M, width * rows);
        allocated += 1;
        for (tree.*) |*v| v.* = M.fromCanonical(random.random().uintLessThan(u32, core.fields.m31.Modulus));
    }
    const powers = try a.alloc(Field, artifact.program.roots.len);
    defer a.free(powers);
    var power = Field.one();
    const alpha = Oracle.random(random.random());
    for (powers) |*v| {
        v.* = power;
        power = power.mul(alpha);
    }
    const denominators = try A.geometry.denominatorInverses(a, trace_log, eval_log);
    defer a.free(denominators);
    var initial: [rows]Field = undefined;
    var expected: [rows]Field = undefined;
    const native_values = try a.alloc(Field, artifact.program.roots.len);
    defer a.free(native_values);
    const inputs = try a.alloc(Field, artifact.program.inputs.len);
    defer a.free(inputs);
    const workspace = try a.create(T.Role.Component.Workspace(Field));
    defer a.destroy(workspace);
    for (0..rows) |row| {
        const sample = Samples{ .trees = trees, .rows = rows, .trace_log = trace_log, .eval_log = eval_log, .at = row, .last_column = artifact.last_anchor_column };
        var sink = E.SinkFor(Field){ .values = native_values };
        if (item.classic) |*c| {
            var p: T.Role.Component.ParametersFor(Field) = undefined;
            p.span = .{ .calls = 3, .first_id = 2 };
            p.local.polynomial = params[T.slots.polynomial];
            @memcpy(&p.local.offsets, params[T.slots.offsets..][0..3]);
            for (&p.local.coefficients, 0..) |*coeff, i| @memcpy(coeff, params[T.slots.coefficients + 6 * i ..][0..6]);
            p.kio.offset = params[T.slots.kio];
            for (&p.kio.coefficients, 0..) |*v, i| v.* = params[T.slots.kio + 1 + i];
            p.wire.offset = params[T.slots.wire];
            for (&p.wire.coefficients, 0..) |*v, i| v.* = params[T.slots.wire + 1 + i];
            p.claim = params[T.slots.claim];
            p.global_claim = params[T.slots.global_claim];
            try c.emitWithParameters(Field, sample, &sink, workspace, p);
        } else switch (id) {
            3 => try nativeV3(T.V3Catalog.Sha(), sample, &params, &sink),
            4 => try nativeV3(T.V3Catalog.Arith(), sample, &params, &sink),
            5 => try nativeV3(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.add), sample, &params, &sink),
            6 => try nativeV3(T.V3Catalog.Curve(A.crypto.curves.spec.SecpKind.double), sample, &params, &sink),
            else => return error.InvalidTruthKernel,
        }
        if (sink.count != native_values.len) return error.WrongTruthConstraintCount;
        for (inputs, artifact.program.inputs) |*v, input| v.* = try sample.get(input.tree, input.column, input.offset);
        const actual = try artifact.program.evaluate(a, inputs);
        defer a.free(actual);
        var folded = Field.zero();
        for (native_values, actual, 0..) |v, ir, i| {
            if (!v.eql(ir)) return error.NativeTruthFixtureMismatch;
            folded = folded.add(v.mul(powers[powers.len - 1 - i]));
        }
        initial[row] = Oracle.random(random.random());
        expected[row] = initial[row].add(folded.mulM31(denominators[row >> trace_log]));
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564350, 1, trace_log, eval_log, @intCast(item.widths[0]), @intCast(item.widths[1]), @intCast(item.widths[2]), @intCast(artifact.program.inputs.len), @intCast(artifact.program.parameters.len), @intCast(powers.len), @intCast(artifact.program.nodes.len), id });
    for (trees) |tree| for (tree) |v| try IO.words(w, &.{v.v});
    for (artifact.program.inputs) |input| {
        const offset = @as(u64, input.column) * rows;
        try IO.words(w, &.{ @truncate(offset), @truncate(offset >> 32) });
    }
    try IO.felts(w, artifact.program.parameters);
    try IO.felts(w, powers);
    for (denominators) |v| try IO.words(w, &.{v.v});
    for (0..8) |coordinate| for (initial) |v| try IO.words(w, &.{v.toM31Array()[coordinate].v});
    for (0..8) |coordinate| for (expected) |v| try IO.words(w, &.{v.toM31Array()[coordinate].v});
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
    std.debug.print("TRUTH DOMAIN id={} main={} inter={} roots={}\n", .{ id, item.widths[1], item.widths[2], artifact.program.roots.len });
}
