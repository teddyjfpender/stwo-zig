//! Cold symbolic registry extracted from the ORIGINAL physical relation DAG.
//! This is a routing plan, never a proof receipt. Conditional emitters remain
//! symbolic; no private weight or coordinate is selected on the host.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Program = @import("resident_parent_program_v1.zig");
const Storage = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Binding = @import("../../frontends/riscv/recursion/air/universal_relation_binding.zig");
const Types = @import("stwo_prover_engine").air.component_prover;
const Route = @import("resident_parent_value_routes_v1.zig");
pub const Op = enum(u32) { constant, main, add, sub, mul, neg };
pub const Expr = extern struct { op: u32, value: u32 = 0, lhs: u32 = 0, rhs: u32 = 0 };
pub const Candidate = extern struct { endpoint: u64, cohort: u32, row: u32, weight: u32, coordinates: [4]u32 };
pub const Consumer = extern struct { main_word: u32, limb: u32, endpoint: u64, cohort: u32, row: u32, weight: u32 };
pub const Argument = struct {
    /// One scalar or four little-endian bytes consumed by the original writer.
    is_packed: bool,
    coordinates: [4]?Consumer = @splat(null),
};
pub const Endpoint = extern struct { key: u64, first: u32, count: u32 };
pub const Unresolved = extern struct { cohort: u32, row: u32, event: u32, reason: u32 };
pub const Limits = struct { max_rows: usize = 1 << 22, max_expressions: usize = 1 << 25, max_candidates: usize = 1 << 23, max_consumers: usize = 1 << 25, max_bytes: usize = 2 << 30 };
pub const Plan = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    program_id: [32]u8,
    expressions: []Expr,
    candidates: []Candidate,
    endpoints: []Endpoint,
    consumers: []Consumer,
    unresolved: []Unresolved,
    main_words: usize,
    pub fn init(backing: std.mem.Allocator, program: *const Program.Owned, fixed: Storage.FixedTuple(false), limits: Limits) !Plan {
        if (limits.max_rows == 0 or limits.max_bytes == 0) return error.ResidentRegistryResourceLimit;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var builder = Builder{ .a = a, .limits = limits };
        defer builder.map.deinit(a);
        const p = program.view();
        var main_first: usize = 0;
        var rows: usize = 0;
        inline for (Storage.Airs, 0..) |Air, cohort| {
            const c = p.cohorts[cohort];
            const count = @as(usize, 1) << @intCast(c.trace_log);
            if (fixed[cohort].len > count) return error.InvalidResidentRegistryRows;
            rows = try std.math.add(usize, rows, fixed[cohort].len);
            if (rows > limits.max_rows) return error.ResidentRegistryResourceLimit;
            if (cohort != 16 and fixed[cohort].len != 0) {
                var definition = if (@hasDecl(Air, "Location")) try Air.build(backing, .generated) else try Air.build(backing);
                defer definition.deinit();
                const binding = try Binding.Binding(Air).authenticate(&definition);
                const pr = &p.programs[cohort];
                if (pr.entries.len != binding.events.len or !std.mem.eql(u8, &pr.semantic_digest, &Air.SEMANTIC_DIGEST)) return error.InvalidResidentRegistryProgram;
                const needed = try backing.alloc(bool, pr.lookup_nodes.len);
                defer backing.free(needed);
                @memset(needed, false);
                for (binding.events, pr.entries) |event, e| {
                    if (@intFromEnum(event.domain) != e.domain or event.arity != e.arity) return error.InvalidResidentRegistryProgram;
                    if (e.domain == 13) {
                        if (e.arity != 6) return error.InvalidResidentRegistryProgram;
                        needed[e.numerator] = true;
                        for (e.values[0..6]) |v| needed[v] = true;
                    }
                }
                var rev = needed.len;
                while (rev != 0) {
                    rev -= 1;
                    if (!needed[rev]) continue;
                    const n = pr.lookup_nodes[rev];
                    switch (n.op) {
                        .constant, .column => {},
                        .neg => needed[n.lhs] = true,
                        .add, .sub, .mul => {
                            needed[n.lhs] = true;
                            needed[n.rhs] = true;
                        },
                    }
                }
                const values = try backing.alloc(u32, pr.lookup_nodes.len);
                defer backing.free(values);
                for (fixed[cohort], 0..) |row, row_index| {
                    for (row) |word| if (word.v >= core.fields.m31.Modulus) return error.InvalidResidentRegistryFixed;
                    const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row_index, c.trace_log), c.trace_log);
                    // These two original AIRs duplicate immutable circuit metadata in MAIN.
                    // Their original canonical writer, fixed-tail roundtrip and AIR identity
                    // determine precisely these columns; numeric operands stay symbolic.
                    const known_main: Air.Row = if (comptime cohort == 4 or cohort == 5) blk: {
                        const Writers = @import("resident_parent_direct_writers_v1.zig");
                        var pp: [row.len]u32 = undefined;
                        for (row, &pp) |m, *v| v.* = m.v;
                        var neutral: [Writers.dynamicCount(cohort)]u32 = @splat(0);
                        if (cohort == 4) neutral[0] = 1;
                        break :blk Writers.row(cohort, &pp, &neutral) catch |err| {
                            std.debug.print("RESIDENT_REGISTRY_FIXED_FAILURE cohort={d} row={d} pp={any}\n", .{ cohort, row_index, pp });
                            return err;
                        };
                    } else undefined;
                    for (pr.lookup_nodes, 0..) |n, i| {
                        if (!needed[i]) continue;
                        values[i] = switch (n.op) {
                            .constant => try builder.constant(n.value),
                            .column => switch (pr.inputs[n.value]) {
                                .profile_parameter => |parameter| try builder.constant(row[Air.PREPROCESSED_COLUMN_COUNT + parameter].v),
                                .trace_column => |column| switch (column.tree_index) {
                                    0 => try builder.constant(row[column.column_index].v),
                                    1 => if ((cohort == 4 and (column.column_index == 0 or column.column_index >= 9)) or (cohort == 5 and (column.column_index < 8 or column.column_index == 20))) try builder.constant(known_main[column.column_index].v) else try builder.main(try std.math.add(usize, main_first, try std.math.add(usize, try std.math.mul(usize, column.column_index, count), physical))),
                                    else => return error.InvalidResidentRegistryProgram,
                                },
                            },
                            .neg => try builder.operation(.neg, values[n.lhs], 0),
                            .add => try builder.operation(.add, values[n.lhs], values[n.rhs]),
                            .sub => try builder.operation(.sub, values[n.lhs], values[n.rhs]),
                            .mul => try builder.operation(.mul, values[n.lhs], values[n.rhs]),
                        };
                    }
                    for (binding.events, pr.entries, 0..) |event, e, ordinal| {
                        if (e.domain != 13) continue;
                        const weight = values[e.numerator];
                        if (event.role == .emit) if (builder.constantValue(weight)) |w| {
                            if (w == 0) continue;
                        };
                        const circuit = builder.constantValue(values[e.values[0]]);
                        const wire = builder.constantValue(values[e.values[1]]);
                        if (circuit == null or wire == null) {
                            try builder.unresolved.append(a, .{ .cohort = cohort, .row = @intCast(row_index), .event = @intCast(ordinal), .reason = 1 });
                            continue;
                        }
                        const key = (@as(u64, circuit.?) << 32) | wire.?;
                        switch (event.role) {
                            .emit => {
                                if (builder.candidates.items.len >= limits.max_candidates) return error.ResidentRegistryResourceLimit;
                                var coords: [4]u32 = undefined;
                                for (&coords, e.values[2..6]) |*out, root| out.* = values[root];
                                try builder.candidates.append(a, .{ .endpoint = key, .cohort = cohort, .row = @intCast(row_index), .weight = weight, .coordinates = coords });
                            },
                            .consume, .request => for (e.values[2..6], 0..) |root, limb| {
                                const expr = builder.expressions.items[values[root]];
                                if (expr.op == @intFromEnum(Op.main)) {
                                    if (builder.consumers.items.len >= limits.max_consumers) return error.ResidentRegistryResourceLimit;
                                    try builder.consumers.append(a, .{ .main_word = expr.value, .limb = @intCast(limb), .endpoint = key, .cohort = cohort, .row = @intCast(row_index), .weight = weight });
                                } else if (expr.op != @intFromEnum(Op.constant)) {
                                    try builder.unresolved.append(a, .{ .cohort = cohort, .row = @intCast(row_index), .event = @intCast(ordinal), .reason = 2 });
                                }
                            },
                        }
                    }
                    try builder.requireBudget();
                }
            }
            main_first = try std.math.add(usize, main_first, try std.math.mul(usize, count, c.columns[1]));
        }
        if (main_first > std.math.maxInt(u32)) return error.ResidentRegistryResourceLimit;
        std.mem.sort(Candidate, builder.candidates.items, {}, struct {
            fn less(_: void, l: Candidate, r: Candidate) bool {
                return l.endpoint < r.endpoint;
            }
        }.less);
        var endpoints: std.ArrayList(Endpoint) = .empty;
        var cursor: usize = 0;
        while (cursor < builder.candidates.items.len) {
            const first = cursor;
            const key = builder.candidates.items[cursor].endpoint;
            while (cursor < builder.candidates.items.len and builder.candidates.items[cursor].endpoint == key) cursor += 1;
            try endpoints.append(a, .{ .key = key, .first = @intCast(first), .count = @intCast(cursor - first) });
        }
        std.mem.sort(Consumer, builder.consumers.items, {}, struct {
            fn less(_: void, l: Consumer, r: Consumer) bool {
                if (l.main_word != r.main_word) return l.main_word < r.main_word;
                if (l.endpoint != r.endpoint) return l.endpoint < r.endpoint;
                return l.limb < r.limb;
            }
        }.less);
        return .{ .a = backing, .arena = arena, .program_id = p.identity, .expressions = try builder.expressions.toOwnedSlice(a), .candidates = try builder.candidates.toOwnedSlice(a), .endpoints = try endpoints.toOwnedSlice(a), .consumers = try builder.consumers.toOwnedSlice(a), .unresolved = try builder.unresolved.toOwnedSlice(a), .main_words = main_first };
    }
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn endpoint(self: *const Plan, key: u64) ?Endpoint {
        var lo: usize = 0;
        var hi = self.endpoints.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.endpoints[mid].key < key) lo = mid + 1 else hi = mid;
        }
        return if (lo < self.endpoints.len and self.endpoints[lo].key == key) self.endpoints[lo] else null;
    }
    pub fn consumer(self: *const Plan, main_word: u32) !?Consumer {
        var lo: usize = 0;
        var hi = self.consumers.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.consumers[mid].main_word < main_word) lo = mid + 1 else hi = mid;
        }
        if (lo == self.consumers.len or self.consumers[lo].main_word != main_word) return null;
        const result = self.consumers[lo];
        var next = lo + 1;
        while (next < self.consumers.len and self.consumers[next].main_word == main_word) : (next += 1) if (self.consumers[next].endpoint != result.endpoint or self.consumers[next].limb != result.limb) return error.AmbiguousResidentWireConsumer;
        return result;
    }

    /// Finite original writer input ABI. The scalar/packed distinction is only
    /// serialization: every coordinate comes from an authenticated consume event.
    /// Free private words and arithmetic graph rows deliberately have no route.
    pub fn directArguments(self: *const Plan, program: *const Program.Owned, comptime cohort: usize, row: u32) ![@import("resident_parent_direct_writers_v1.zig").dynamicCount(cohort)]Argument {
        if (!std.mem.eql(u8, &self.program_id, &program.view().identity)) return error.UntrustedResidentRegistryProgram;
        const n = comptime @import("resident_parent_direct_writers_v1.zig").dynamicCount(cohort);
        var columns: [n]u32 = undefined;
        var packed_args: [n]bool = @splat(false);
        switch (cohort) {
            6 => {
                for (&columns, 0..) |*v, i| v.* = @intCast(8 * i);
                @memset(&packed_args, true);
            },
            7, 10, 11 => for (&columns, 0..) |*v, i| {
                v.* = @intCast(i);
            },
            8 => {
                columns[0] = 0;
                packed_args[0] = true;
            },
            12 => columns[0] = 0,
            13 => {
                columns = .{ 0, 1, 5 };
                packed_args = .{ false, true, true };
            },
            14 => {
                columns[0] = 0;
                columns[1] = 1;
                for (2..10) |i| columns[i] = @intCast(i + 2);
            },
            15 => {
                columns = .{ 1, 5, 0 };
                packed_args = .{ true, true, false };
            },
            17 => {
                columns = .{ 0, 4 };
                packed_args = .{ true, false };
            },
            else => return error.ResidentWriterRequiresExternalBinding,
        }
        const p = program.view();
        const c = p.cohorts[cohort];
        const count = @as(usize, 1) << @intCast(c.trace_log);
        if (row >= count) return error.InvalidResidentRegistryRows;
        var first: usize = 0;
        for (p.cohorts[0..cohort]) |prior| first = try std.math.add(usize, first, try std.math.mul(usize, prior.columns[1], @as(usize, 1) << @intCast(prior.trace_log)));
        const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, c.trace_log), c.trace_log);
        var result: [n]Argument = undefined;
        for (&result, columns, packed_args) |*arg, column, is_packed| {
            arg.* = .{ .is_packed = is_packed };
            const limbs: usize = if (is_packed) 4 else 1;
            for (0..limbs) |limb| {
                const index = try std.math.add(usize, first, try std.math.add(usize, try std.math.mul(usize, column + limb, count), physical));
                arg.coordinates[limb] = (try self.consumer(std.math.cast(u32, index) orelse return error.ResidentRegistryResourceLimit)) orelse return error.MissingResidentWireConsumer;
            }
        }
        return result;
    }
    /// Safe static fast path. Conditional/multiple producers require the device
    /// resolver. A zero weight never supplies a value, even if its bytes agree.
    pub fn staticSource(self: *const Plan, key: u64, limb: u2, phase: u32) !?Route.Source {
        const e = self.endpoint(key) orelse return null;
        if (e.count != 1) return null;
        const candidate = self.candidates[e.first];
        const weight = self.expressions[candidate.weight];
        if (weight.op != @intFromEnum(Op.constant) or weight.value == 0) return null;
        const value = self.expressions[candidate.coordinates[limb]];
        return switch (@as(Op, @enumFromInt(value.op))) {
            .constant => Route.Source.constant(value.value),
            .main => Route.Source.mainWord(value.value, phase),
            else => null,
        };
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    limits: Limits,
    expressions: std.ArrayList(Expr) = .empty,
    map: std.AutoHashMapUnmanaged(Expr, u32) = .{},
    candidates: std.ArrayList(Candidate) = .empty,
    consumers: std.ArrayList(Consumer) = .empty,
    unresolved: std.ArrayList(Unresolved) = .empty,
    fn intern(self: *Builder, e: Expr) !u32 {
        if (self.map.get(e)) |i| return i;
        if (self.expressions.items.len >= self.limits.max_expressions or self.expressions.items.len >= std.math.maxInt(u32)) return error.ResidentRegistryResourceLimit;
        const index: u32 = @intCast(self.expressions.items.len);
        try self.expressions.append(self.a, e);
        try self.map.put(self.a, e, index);
        return index;
    }
    fn constant(self: *Builder, value: u32) !u32 {
        if (value >= core.fields.m31.Modulus) return error.InvalidResidentRegistryFixed;
        return self.intern(.{ .op = @intFromEnum(Op.constant), .value = value });
    }
    fn main(self: *Builder, value: usize) !u32 {
        return self.intern(.{ .op = @intFromEnum(Op.main), .value = std.math.cast(u32, value) orelse return error.ResidentRegistryResourceLimit });
    }
    fn constantValue(self: *const Builder, id: u32) ?u32 {
        const e = self.expressions.items[id];
        return if (e.op == @intFromEnum(Op.constant)) e.value else null;
    }
    fn operation(self: *Builder, op: Op, lhs: u32, rhs: u32) !u32 {
        const l = self.constantValue(lhs);
        const r = if (op == .neg) @as(?u32, 0) else self.constantValue(rhs);
        if (l != null and r != null) {
            const a = M.fromCanonical(l.?);
            const b = M.fromCanonical(r.?);
            return self.constant((switch (op) {
                .add => a.add(b),
                .sub => a.sub(b),
                .mul => a.mul(b),
                .neg => a.neg(),
                else => return error.InvalidResidentRegistryExpression,
            }).v);
        }
        if (op == .mul) {
            if (l == 0 or r == 0) return self.constant(0);
            if (l == 1) return rhs;
            if (r == 1) return lhs;
        }
        if (op == .add) {
            if (l == 0) return rhs;
            if (r == 0) return lhs;
        }
        if (op == .sub and r == 0) return lhs;
        return self.intern(.{ .op = @intFromEnum(op), .lhs = lhs, .rhs = if (op == .neg) 0 else rhs });
    }
    fn requireBudget(self: *const Builder) !void {
        var bytes: usize = 0;
        inline for (.{ self.expressions.items, self.candidates.items, self.consumers.items, self.unresolved.items }) |items| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, items.len, @sizeOf(std.meta.Child(@TypeOf(items)))));
        if (bytes > self.limits.max_bytes) return error.ResidentRegistryResourceLimit;
    }
};
test "resident wire registry derives canonical G consumers from fixed boundary identity" {
    const a = std.testing.allocator;
    const p = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (Storage.Airs, 0..) |_, i| fixed[i] = &.{};
    const G = Storage.Airs[0];
    const Boundary = Storage.Airs[2];
    var grow = [_]Storage.FixedRow(G){Storage.compactFixed(G, try G.fixedRow(.{ .circuit = 7, .input = .{ 10, 11, 12, 13, 14, 15 }, .output = .{ 20, 21, 22, 23 }, .uses = .{ 1, 1, 1, 1 } }))};
    var brow = [_]Storage.FixedRow(Boundary){Storage.compactFixed(Boundary, try Boundary.logicalRow(7, 10, M.one(), 0x12345678))};
    fixed[0] = &grow;
    fixed[2] = &brow;
    var registry = try Plan.init(a, p, fixed, .{});
    defer registry.deinit();
    const key = (@as(u64, 7) << 32) | 10;
    const consumer0 = (try registry.consumer(0)).?;
    try std.testing.expectEqual(key, consumer0.endpoint);
    try std.testing.expectEqual(@as(u32, 0), consumer0.limb);
    const source = (try registry.staticSource(key, 0, 3)).?;
    try std.testing.expectEqual(@intFromEnum(Route.Kind.main_word), source.kind);
    try std.testing.expectEqual(@as(u32, (82 + 12) * 4), source.index);
    try std.testing.expectEqual(@as(u32, 3), source.ready_phase);
    try std.testing.expectEqual(@as(usize, 0), registry.unresolved.len);
    // Changed fixed wire identity changes the cold route; it cannot retain a
    // stale producer under the original endpoint. Device fixed root is authority.
    brow[0][2] = M.fromCanonical(99);
    var changed = try Plan.init(a, p, fixed, .{});
    defer changed.deinit();
    try std.testing.expectEqual(@as(?Route.Source, null), try changed.staticSource(key, 0, 3));
    try std.testing.expectError(error.ResidentRegistryResourceLimit, Plan.init(a, p, fixed, .{ .max_expressions = 1 }));
}

test "resident wire registry keeps retry weights symbolic and binds readonly input coordinates" {
    const a = std.testing.allocator;
    const p = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (Storage.Airs, 0..) |_, i| fixed[i] = &.{};
    const Readonly = Storage.Airs[17];
    const Challenge = Storage.Airs[6];
    var r = [_]Storage.FixedRow(Readonly){Storage.compactFixed(Readonly, try Readonly.fixedRow(.{ .index = .{ .circuit = 7, .wire = 10 }, .value = .{ .circuit = 7, .wire = 20 }, .table = 99 }))};
    fixed[17] = &r;
    var c = [_]Storage.FixedRow(Challenge){Storage.compactFixed(Challenge, try Challenge.fixedRow(.{ .source_circuit = 9, .source_first = 0, .destination_circuit = 10, .destination_first = 20, .uses = @splat(1), .status_wire = 100, .status_uses = 1 }))};
    fixed[6] = &c;
    var registry = try Plan.init(a, p, fixed, .{});
    defer registry.deinit();
    const args = try registry.directArguments(p, 17, 0);
    try std.testing.expect(args[0].is_packed);
    try std.testing.expect(!args[1].is_packed);
    for (args[0].coordinates, 0..) |coordinate, i| {
        try std.testing.expectEqual((@as(u64, 7) << 32) | 10, coordinate.?.endpoint);
        try std.testing.expectEqual(i, coordinate.?.limb);
    }
    try std.testing.expectEqual((@as(u64, 7) << 32) | 20, args[1].coordinates[0].?.endpoint);
    const draws = try registry.directArguments(p, 6, 0);
    for (draws, 0..) |arg, i| {
        try std.testing.expect(arg.is_packed);
        for (arg.coordinates, 0..) |coordinate, j| {
            try std.testing.expectEqual((@as(u64, 9) << 32) | i, coordinate.?.endpoint);
            try std.testing.expectEqual(j, coordinate.?.limb);
        }
    }
    const key = (@as(u64, 10) << 32) | 20;
    const e = registry.endpoint(key).?;
    try std.testing.expectEqual(@as(u32, 1), e.count);
    const candidate = registry.candidates[e.first];
    try std.testing.expectEqual(@intFromEnum(Op.main), registry.expressions[candidate.weight].op);
    try std.testing.expectEqual(@as(?Route.Source, null), try registry.staticSource(key, 0, 1));
    // Dynamic readonly address is retained as an explicitly unresolved emitter;
    // the root's authenticated sort task owns it. Static input consumers survive.
    try std.testing.expectEqual(@as(usize, 1), registry.unresolved.len);
    try std.testing.expectEqual(@as(u32, 17), registry.unresolved[0].cohort);
    inline for (.{ 7, 8, 10, 11, 12, 13, 14, 15 }) |i| try std.testing.expectError(error.MissingResidentWireConsumer, registry.directArguments(p, i, 0));
    try std.testing.expectError(error.ResidentWriterRequiresExternalBinding, registry.directArguments(p, 9, 0));
}
