//! Walk each operation once and write both final matrices directly. Only one
//! bounded wire-value scratch is live; no retained product/linear/wide caller tape.
const std = @import("std");
const Storage = @import("../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const L = @import("layout.zig");
const P = L.P;
const T = @import("trace.zig");
const BCall = @import("bridge/trace.zig").Call;
const Format = @import("bridge/equations.zig").PacketFormat;
pub const MainBuffers = struct { product: []M, linear: []M };
pub const FixedColumns = struct { product: []const M, linear: []const M };
const physical = @import("../../witness.zig").physical;
pub const Batch = struct {
    product: T.Trace,
    linear: T.Trace,
    pub fn init(a: std.mem.Allocator, program: *const P.Program, inputs: []const T.Input, first_id: u32) !Batch {
        return initWithLogs(a, program, inputs, first_id, try L.logSize(.product, program, inputs.len), try L.logSize(.linear, program, inputs.len));
    }
    pub fn initWithLogs(a: std.mem.Allocator, program: *const P.Program, inputs: []const T.Input, first_id: u32, plog: u32, llog: u32) !Batch {
        return build(a, a, program, .{ .coordinates = inputs }, first_id, plog, llog, null, null);
    }
    pub fn initFromPackets(a: std.mem.Allocator, program: *const P.Program, calls: []const BCall, first_id: u32, format: Format, plog: u32, llog: u32, fixed: ?FixedColumns) !Batch {
        return build(a, a, program, .{ .packets = .{ .calls = calls, .format = format } }, first_id, plog, llog, fixed, null);
    }
    pub fn initFromPacketsWithMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, program: *const P.Program, calls: []const BCall, first_id: u32, format: Format, plog: u32, llog: u32, fixed: ?FixedColumns) !Batch {
        return build(a, main_allocator, program, .{ .packets = .{ .calls = calls, .format = format } }, first_id, plog, llog, fixed, null);
    }
    pub fn initFromPacketsWithMainBuffers(a: std.mem.Allocator, program: *const P.Program, calls: []const BCall, first_id: u32, format: Format, plog: u32, llog: u32, fixed: ?FixedColumns, main: MainBuffers) !Batch {
        return build(a, a, program, .{ .packets = .{ .calls = calls, .format = format } }, first_id, plog, llog, fixed, main);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, program: *const P.Program, inputs: []const T.Input, first_id: u32, plog: u32, llog: u32, main: MainBuffers) !Batch {
        return build(a, a, program, .{ .coordinates = inputs }, first_id, plog, llog, null, main);
    }
    fn build(a: std.mem.Allocator, main_allocator: std.mem.Allocator, program: *const P.Program, inputs: InputSource, first_id: u32, plog: u32, llog: u32, fixed: ?FixedColumns, main: ?MainBuffers) !Batch {
        _ = try L.admitRoster(&.{ .{ .kind = .product, .program = program, .calls = inputs.len(), .first_id = first_id, .log = plog }, .{ .kind = .linear, .program = program, .calls = inputs.len(), .first_id = first_id, .log = llog } }, &.{});
        if (fixed) |f| {
            if (f.product.len != L.FIXED * (@as(usize, 1) << @intCast(plog)) or f.linear.len != L.FIXED * (@as(usize, 1) << @intCast(llog))) return error.InvalidSecpFixedShape;
        }
        if (main) |buffers| {
            const slices = [_]Storage.Slice{ .{ .values = buffers.product, .cells = L.main(.product) * (@as(usize, 1) << @intCast(plog)) }, .{ .values = buffers.linear, .cells = L.main(.linear) * (@as(usize, 1) << @intCast(llog)) } };
            try Storage.validate(&slices);
            try Storage.exclude(&slices, inputs.inputBytes());
            if (fixed) |f| {
                try Storage.exclude(&slices, std.mem.sliceAsBytes(f.product));
                try Storage.exclude(&slices, std.mem.sliceAsBytes(f.linear));
            }
        }
        var product = try empty(a, if (main) |m| .{ .borrowed = m.product } else .{ .owned = main_allocator }, .product, program, inputs.len(), first_id, plog, if (fixed) |f| f.product else null);
        errdefer product.deinit();
        var linear = try empty(a, if (main) |m| .{ .borrowed = m.linear } else .{ .owned = main_allocator }, .linear, program, inputs.len(), first_id, llog, if (fixed) |f| f.linear else null);
        errdefer linear.deinit();
        for (0..inputs.len()) |call| {
            const input = inputs.at(call, program.inputs);
            var values: P.Values = @splat(0);
            @memcpy(values[0..program.inputs], input.coordinates[0..program.inputs]);
            var pi: usize = 0;
            var li: usize = 0;
            for (program.operations[0..program.length]) |op| {
                const lhs = P.resolve(op.lhs, &values);
                const rhs = P.resolve(op.rhs, &values);
                const modulus = P.field.base_modulus.integer();
                if (op.kind == .multiply) {
                    const witness = try P.field.create(P.bytes(lhs), P.bytes(rhs), P.field.base_modulus);
                    values[op.result] = std.mem.readInt(u256, &witness.result, .little);
                    const row = L.mul.rowFromWitness(&witness);
                    writeRow(&product, &row, call, pi);
                    pi += 1;
                } else {
                    const result: u256 = switch (op.kind) {
                        .add => @intCast((@as(u512, lhs) + rhs) % modulus),
                        .subtract => if (lhs >= rhs) lhs - rhs else modulus - (rhs - lhs),
                        .reduce_once => if (lhs >= modulus) lhs - modulus else lhs,
                        .multiply => unreachable,
                    };
                    values[op.result] = result;
                    const record = P.affine.LinearRecord{ .kind = switch (op.kind) {
                        .add => .add,
                        .subtract => .subtract,
                        .reduce_once => .reduce_once,
                        .multiply => unreachable,
                    }, .modulus = .base, .lhs = P.bytes(lhs), .rhs = P.bytes(rhs), .result = P.bytes(result) };
                    const row = try L.linear.rowFromRecord(&record);
                    writeRow(&linear, &row, call, li);
                    li += 1;
                }
            }
        }
        for ([_]*T.Trace{ &product, &linear }) |trace| {
            const padding = trace.size() - inputs.len() * program.rows(trace.kind == .product);
            trace.byte_counts[0] += padding * L.byteCount(trace.kind);
        }
        return .{ .product = product, .linear = linear };
    }
    pub fn deinit(self: *Batch) void {
        self.linear.deinit();
        self.product.deinit();
        self.* = undefined;
    }
};
fn empty(a: std.mem.Allocator, storage: Storage.Buffer, kind: L.Kind, program: *const P.Program, calls: usize, first_id: u32, log: u32, borrowed: ?[]const M) !T.Trace {
    try L.validate(kind, program, calls, first_id, log);
    try storage.validate(L.main(kind) * (@as(usize, 1) << @intCast(log)));
    const fixed = if (borrowed) |data| data else try T.fixedColumns(a, kind, program, log);
    errdefer if (borrowed == null) a.free(fixed);
    if (fixed.len != L.FIXED * (@as(usize, 1) << @intCast(log))) return error.InvalidSecpFixedShape;
    const lookup_bytes = try a.alloc(u8, calls * program.rows(kind == .product) * L.byteCount(kind));
    errdefer a.free(lookup_bytes);
    const main = try storage.acquire(L.main(kind) * (@as(usize, 1) << @intCast(log)));
    @memset(main, M.zero());
    return .{ .allocator = a, .kind = kind, .program = program, .calls = @intCast(calls), .first_id = first_id, .log_size = log, .fixed = fixed, .owns_fixed = borrowed == null, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .lookup_bytes = lookup_bytes };
}
fn writeRow(trace: *T.Trace, row: []const M, call: usize, opindex: usize) void {
    const n = trace.size();
    const r = physical(call * trace.program.rows(trace.kind == .product) + opindex, trace.log_size);
    for (row, 0..) |v, c| trace.main[c * n + r] = v;
    T.captureLookupBytes(trace.kind, trace.lookup_bytes[(call * trace.program.rows(trace.kind == .product) + opindex) * L.byteCount(trace.kind) ..][0..L.byteCount(trace.kind)], row);
    trace.main[L.base(trace.kind) * n + r] = M.fromCanonical(@intCast(@as(u64, trace.first_id) + call));
    for (0..L.byteCount(trace.kind)) |i| trace.byte_counts[row[T.byteColumn(trace.kind, i)].v] += 1;
}

const InputSource = union(enum) {
    coordinates: []const T.Input,
    packets: struct { calls: []const BCall, format: Format },
    fn inputBytes(self: InputSource) []const u8 {
        return switch (self) {
            .coordinates => |v| std.mem.sliceAsBytes(v),
            .packets => |v| std.mem.sliceAsBytes(v.calls),
        };
    }
    fn len(self: InputSource) usize {
        return switch (self) {
            .coordinates => |v| v.len,
            .packets => |v| v.calls.len,
        };
    }
    fn at(self: InputSource, index: usize, count: usize) T.Input {
        return switch (self) {
            .coordinates => |v| v[index],
            .packets => |v| blk: {
                var input = T.Input{ .coordinates = @splat(0) };
                for (input.coordinates[0..count], 0..) |*coordinate, i| {
                    var bytes: [32]u8 = undefined;
                    for (0..4) |lane| std.mem.writeInt(u64, bytes[8 * lane ..][0..8], v.calls[index].before[4 * i + lane], .little);
                    coordinate.* = if (v.format == .big_endian_bytes_v1) std.mem.readInt(u256, &bytes, .big) else std.mem.readInt(u256, &bytes, .little);
                }
                break :blk input;
            },
        };
    }
};
