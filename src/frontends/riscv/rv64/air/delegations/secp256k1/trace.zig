//! Column-major modular witnesses. No retained wide caller or group point tape.
const std = @import("std");
const Storage = @import("../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const P = L.P;
const E = @import("equations.zig");
const physical = @import("../../witness.zig").physical;
pub const Input = struct { coordinates: [6]u256 };
pub const Trace = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    program: *const P.Program,
    calls: u32,
    first_id: u32,
    log_size: u32,
    fixed: []const M,
    owns_fixed: bool = true,
    main: []M,
    main_allocator: ?std.mem.Allocator = null,
    owns_main: bool = true,
    lookup_bytes: []u8 = &.{},
    interaction: []M = &.{},
    byte_counts: [256]u64 = @splat(0),
    pub fn init(a: std.mem.Allocator, kind: L.Kind, program: *const P.Program, inputs: []const Input, first_id: u32) !Trace {
        return initWithLog(a, kind, program, inputs, first_id, try L.logSize(kind, program, inputs.len));
    }
    pub fn initWithLog(a: std.mem.Allocator, kind: L.Kind, program: *const P.Program, inputs: []const Input, first_id: u32, log: u32) !Trace {
        return initWithLogAndMainAllocator(a, a, kind, program, inputs, first_id, log);
    }
    pub fn initWithLogAndMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, kind: L.Kind, program: *const P.Program, inputs: []const Input, first_id: u32, log: u32) !Trace {
        return build(a, .{ .owned = main_allocator }, kind, program, inputs, first_id, log);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, kind: L.Kind, program: *const P.Program, inputs: []const Input, first_id: u32, log: u32, main: []M) !Trace {
        return build(a, .{ .borrowed = main }, kind, program, inputs, first_id, log);
    }
    fn build(a: std.mem.Allocator, storage: Storage.Buffer, kind: L.Kind, program: *const P.Program, inputs: []const Input, first_id: u32, log: u32) !Trace {
        try L.validate(kind, program, inputs.len, first_id, log);
        const n = @as(usize, 1) << @intCast(log);
        const width = L.main(kind);
        try storage.validate(width * n);
        if (storage == .borrowed) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = width * n }}, std.mem.sliceAsBytes(inputs));
        const fixed = try fixedColumns(a, kind, program, log);
        errdefer a.free(fixed);
        const lookup_bytes = try a.alloc(u8, inputs.len * program.rows(kind == .product) * L.byteCount(kind));
        errdefer a.free(lookup_bytes);
        const main = try storage.acquire(width * n);
        errdefer storage.release(main);
        @memset(main, M.zero());
        for (inputs, 0..) |input, call| {
            const values = try P.execute(program, input.coordinates[0..program.inputs]);
            for (0..program.rows(kind == .product)) |opindex| {
                const op = program.operation(kind == .product, opindex);
                const r = physical(call * program.rows(kind == .product) + opindex, log);
                const lhs = P.bytes(P.resolve(op.lhs, &values));
                const rhs = P.bytes(P.resolve(op.rhs, &values));
                const result = P.bytes(values[op.result]);
                if (kind == .product) {
                    const witness = try P.field.create(lhs, rhs, P.field.base_modulus);
                    const row = L.mul.rowFromWitness(&witness);
                    for (row, 0..) |v, c| main[c * n + r] = v;
                    captureLookupBytes(kind, lookup_bytes[(call * program.rows(kind == .product) + opindex) * L.byteCount(kind) ..][0..L.byteCount(kind)], &row);
                } else {
                    const record = P.affine.LinearRecord{ .kind = switch (op.kind) {
                        .add => .add,
                        .subtract => .subtract,
                        .reduce_once => .reduce_once,
                        .multiply => unreachable,
                    }, .modulus = .base, .lhs = lhs, .rhs = rhs, .result = result };
                    const row = try L.linear.rowFromRecord(&record);
                    for (row, 0..) |v, c| main[c * n + r] = v;
                    captureLookupBytes(kind, lookup_bytes[(call * program.rows(kind == .product) + opindex) * L.byteCount(kind) ..][0..L.byteCount(kind)], &row);
                }
                main[L.base(kind) * n + r] = M.fromCanonical(@intCast(@as(u64, first_id) + call));
            }
        }
        var out = Trace{ .allocator = a, .kind = kind, .program = program, .calls = @intCast(inputs.len), .first_id = first_id, .log_size = log, .fixed = fixed, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .lookup_bytes = lookup_bytes };
        for (0..n) |r| for (0..L.byteCount(kind)) |i| {
            const c = byteColumn(kind, i);
            const value = main[c * n + r].v;
            if (value > 255) return error.InvalidSecpByte;
            out.byte_counts[value] += 1;
        };
        return out;
    }
    pub fn deinit(self: *Trace) void {
        if (self.owns_fixed) self.allocator.free(self.fixed);
        if (self.owns_main and self.main.len != 0) (self.main_allocator orelse self.allocator).free(self.main);
        self.allocator.free(self.lookup_bytes);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn size(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn validateMetadata(self: *const Trace) !void {
        try L.validate(self.kind, self.program, self.calls, self.first_id, self.log_size);
        if (self.lookup_bytes.len != @as(usize, self.calls) * self.program.rows(self.kind == .product) * L.byteCount(self.kind) or self.fixed.len != L.FIXED * self.size()) return error.InvalidSecpLookupMetadata;
    }
    pub fn metadataRow(self: *const Trace, logical: usize, out: []Q) !void {
        if (out.len != L.main(self.kind)) return error.InvalidSecpLookupMetadata;
        @memset(out, Q.zero());
        const per = self.program.rows(self.kind == .product);
        if (logical >= @as(usize, self.calls) * per) return;
        const count = L.byteCount(self.kind);
        if (self.lookup_bytes.len < (logical + 1) * count) return error.InvalidSecpLookupMetadata;
        for (self.lookup_bytes[logical * count ..][0..count], 0..) |v, i| out[byteColumn(self.kind, i)] = Q.fromBase(M.fromCanonical(v));
        out[0] = Q.one();
        out[L.base(self.kind)] = Q.fromBase(M.fromCanonical(@intCast(@as(usize, self.first_id) + logical / per)));
    }
    pub fn takeMain(self: *Trace) ![]M {
        if (!self.owns_main) return error.BorrowedCryptoMain;
        try self.validateMetadata();
        if (self.main.len != L.main(self.kind) * self.size()) return error.InvalidSecpSourcePhase;
        const values = self.main;
        self.main = &.{};
        return values;
    }
    pub fn releaseMain(self: *Trace) !void {
        try self.validateMetadata();
        if (self.main.len != L.main(self.kind) * self.size()) return error.InvalidCryptoMainPhase;
        if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
        self.main = &.{};
    }
    pub fn generateInteraction(self: *Trace, ch: E.Challenges) !Q {
        if (self.interaction.len != 0) return error.SecpInteractionAlreadyGenerated;
        try self.validateMetadata();
        const n = self.size();
        const batches = L.batches(self.kind);
        const data = try self.allocator.alloc(M, 4 * batches * n);
        errdefer self.allocator.free(data);
        const main = try self.allocator.alloc(Q, L.main(self.kind));
        defer self.allocator.free(main);
        var sum = Q.zero();
        for (0..n) |logical| {
            const r = physical(logical, self.log_size);
            var f: [L.FIXED]Q = undefined;
            for (&f, 0..) |*v, c| v.* = Q.fromBase(self.fixed[c * n + r]);
            try self.metadataRow(logical, main);
            const row = E.Row{ .fixed = &f, .main = main };
            for (0..batches) |batch| {
                if (batch + 1 == batches) {
                    for (0..3) |event| sum = sum.add(E.wireCoefficient(row, event).mul(try ch.wire.denominator(&E.wireTuple(self.kind, self.program, row, event)).inv()));
                } else {
                    for (0..3) |j| {
                        const index = 3 * batch + j;
                        if (index < L.byteCount(self.kind)) sum = sum.add(try ch.bytes.sub(E.byte(self.kind, main, index)).inv());
                    }
                }
                for (sum.toM31Array(), 0..) |v, c| data[(4 * batch + c) * n + r] = v;
            }
        }
        self.interaction = data;
        return sum;
    }
};
pub fn byteColumn(kind: L.Kind, index: usize) usize {
    return if (kind == .product) L.mul.Layout.first_byte + index else if (index < 96) L.linear.Layout.lhs + index else L.linear.Layout.canonical_sum + index - 96;
}
pub fn fixedColumns(a: std.mem.Allocator, kind: L.Kind, program: *const P.Program, log: u32) ![]M {
    if (log < 5 or log > 22) return error.InvalidSecpGeometry;
    const n = @as(usize, 1) << @intCast(log);
    const per = program.rows(kind == .product);
    const data = try a.alloc(M, L.FIXED * n);
    @memset(data, M.zero());
    for (0..n) |logical| {
        const r = physical(logical, log);
        const phase = logical % per;
        const op = program.operation(kind == .product, phase);
        data[L.FIRST * n + r] = M.fromCanonical(@intFromBool(logical == 0));
        data[L.PHASE_FIRST * n + r] = M.fromCanonical(@intFromBool(phase == 0));
        data[L.COMPLETE * n + r] = M.fromCanonical(@intFromBool(logical < n / per * per));
        data[L.CALL_INDEX * n + r] = M.fromCanonical(@intCast(logical / per));
        data[L.OP_INDEX * n + r] = M.fromCanonical(@intCast(phase));
        data[L.LHS_ID * n + r] = M.fromCanonical(op.lhs.wire);
        data[L.LHS_WIRE * n + r] = M.one();
        switch (op.rhs) {
            .wire => |w| {
                data[L.RHS_ID * n + r] = M.fromCanonical(w);
                data[L.RHS_WIRE * n + r] = M.one();
            },
            .small => |v| data[L.RHS_SMALL * n + r] = M.fromCanonical(v),
            .modulus => {},
        }
        data[L.RESULT_ID * n + r] = M.fromCanonical(op.result);
        data[L.USES * n + r] = M.fromCanonical(program.uses[op.result]);
        data[L.ADD * n + r] = M.fromCanonical(@intFromBool(op.kind == .add));
        data[L.SUB * n + r] = M.fromCanonical(@intFromBool(op.kind == .subtract));
        data[L.REDUCE * n + r] = M.fromCanonical(@intFromBool(op.kind == .reduce_once));
    }
    return data;
}

pub fn captureLookupBytes(kind: L.Kind, out: []u8, row: []const M) void {
    for (out, 0..) |*v, i| v.* = @intCast(row[byteColumn(kind, i)].v);
}
