//! Bounded cold routing for device-produced direct parent witnesses.
//! Sources describe raw request offsets or resident device values, never
//! CPU-computed witness columns. Device execution must honor the explicit
//! phase ordering; a plan alone confers no child-verification authority.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Program = @import("resident_parent_program_v1.zig");
pub const COHORTS = [_]u32{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
pub const MAX_DYNAMIC_WORDS: usize = 40;
pub const Kind = enum(u32) { constant, raw_u32_le, resident_word, packed_bytes4, extract_bit, arithmetic_word, main_word, hash_word, packed_main4, hash_byte, raw_byte, readonly_word, resident_byte };
pub const Source = extern struct {
    kind: u32,
    index: u32,
    aux: u32 = 0,
    ready_phase: u32 = 0,
    pub fn constant(value: u32) Source {
        return .{ .kind = @intFromEnum(Kind.constant), .index = value };
    }
    pub fn raw(offset: u32) Source {
        return .{ .kind = @intFromEnum(Kind.raw_u32_le), .index = offset };
    }
    pub fn resident(word: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.resident_word), .index = word, .ready_phase = phase };
    }
    pub fn arithmetic(word: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.arithmetic_word), .index = word, .ready_phase = phase };
    }
    pub fn mainWord(word: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.main_word), .index = word, .ready_phase = phase };
    }
    pub fn hashWord(word: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.hash_word), .index = word, .ready_phase = phase };
    }
    pub fn residentByte(word: u32, byte: u2, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.resident_byte), .index = word, .aux = byte, .ready_phase = phase };
    }
    pub fn readonlyWord(word: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.readonly_word), .index = word, .ready_phase = phase };
    }
    pub fn mainPacked(first: u32, stride: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.packed_main4), .index = first, .aux = stride, .ready_phase = phase };
    }
    pub fn packedBytes(first: u32, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.packed_bytes4), .index = first, .ready_phase = phase };
    }
    pub fn bit(word: u32, ordinal: u5, phase: u32) Source {
        return .{ .kind = @intFromEnum(Kind.extract_bit), .index = word, .aux = ordinal, .ready_phase = phase };
    }
};
pub const Call = extern struct {
    cohort: u32,
    logical_row: u32,
    trace_log: u32,
    fixed_first: u32,
    source_first: u32,
    source_count: u32,
    phase: u32,
    reserved: u32 = 0,
    /// Offset within the proof-owned main tree, in base-field words.
    destination_first: u64,
};
pub const Limits = struct {
    max_calls: usize = 1 << 20,
    max_fixed_words: usize = 1 << 26,
    max_sources: usize = 1 << 25,
    max_device_bytes: usize = 8 << 30,
};
pub const Bounds = struct { raw_bytes: usize, resident_words: usize, main_words: usize, arithmetic_words: usize = 0, hash_words: usize = 0, readonly_words: usize = 0 };
pub const Data = struct {
    calls: []const Call,
    fixed: []const u32,
    sources: []const Source,
    /// Stable phase/cohort groups. A GPU scheduler must not run a phase
    /// before its explicitly declared resident source producers finish.
    groups: []const Group,
    bounds: Bounds,
    metadata_bytes: usize,
    identity: [32]u8,
};
pub const Group = extern struct { first: u32, count: u32, phase: u32, cohort: u32 };
const Owned = struct { a: std.mem.Allocator, arena: std.heap.ArenaAllocator, data: Data };
pub const Plan = opaque {
    pub fn view(self: *const Plan) *const Data {
        const p: *const Owned = @ptrCast(@alignCast(self));
        return &p.data;
    }
    pub fn deinit(self: *Plan) void {
        const p: *Owned = @ptrCast(@alignCast(self));
        const a = p.a;
        p.arena.deinit();
        a.destroy(p);
    }
};
pub const Builder = struct {
    a: std.mem.Allocator,
    program: *const Program.Owned,
    bounds: Bounds,
    limits: Limits,
    calls: std.ArrayList(Call) = .empty,
    fixed: std.ArrayList(u32) = .empty,
    sources: std.ArrayList(Source) = .empty,
    destinations: std.AutoHashMapUnmanaged(u64, void) = .{},

    pub fn init(a: std.mem.Allocator, program: *const Program.Owned, bounds: Bounds, limits: Limits) !Builder {
        if (bounds.raw_bytes == 0 or bounds.raw_bytes > std.math.maxInt(u32) or
            bounds.resident_words > std.math.maxInt(u32) or bounds.main_words == 0 or
            limits.max_calls == 0 or limits.max_sources == 0 or limits.max_device_bytes == 0)
            return error.InvalidResidentValueRouteBounds;
        try program.view().admission.validate();
        return .{ .a = a, .program = program, .bounds = bounds, .limits = limits };
    }
    pub fn deinit(self: *Builder) void {
        self.calls.deinit(self.a);
        self.fixed.deinit(self.a);
        self.sources.deinit(self.a);
        self.destinations.deinit(self.a);
        self.* = undefined;
    }

    pub fn mainOffset(self: *const Builder, comptime cohort: usize) !usize {
        var result: usize = 0;
        for (self.program.view().cohorts[0..cohort]) |prior|
            result = try std.math.add(usize, result, try std.math.mul(usize, prior.columns[1], @as(usize, 1) << @intCast(prior.trace_log)));
        return result;
    }

    /// Original fixed fusion schedules already name each graph node. Bind
    /// directly to its GPU output; no CPU evaluation or wide matrix is needed.
    pub fn appendArithmetic(self: *Builder, arithmetic: *const @import("resident_parent_arithmetic_plan_v1.zig").Plan, fixed: Storage.FixedTuple(false), phase: u32) !void {
        if (arithmetic.graphs.len != 3 or arithmetic.graph_ids.len != 3 or self.bounds.arithmetic_words != arithmetic.value_words)
            return error.InvalidResidentArithmeticRoute;
        for (arithmetic.graph_ids, self.program.view().admission.key.context.graph_ids) |actual, expected|
            if (!std.mem.eql(u8, &actual, &expected)) return error.UntrustedResidentArithmeticRoute;
        inline for (.{ 3, 4, 5, 18, 19 }) |cohort| {
            for (fixed[cohort], 0..) |row, index| {
                var pp: [row.len]u32 = undefined;
                for (row, &pp) |value, *out| out.* = value.v;
                _ = try @import("resident_parent_direct_writers_v1.zig").fixedRow(cohort, &pp);
                const circuit = pp[1];
                const graph = try graphForCircuit(arithmetic, circuit);
                var refs: [dynamicWordCount(cohort)]Source = undefined;
                switch (cohort) {
                    3 => {
                        try graphRefs(graph, pp[3], refs[0..4], phase);
                        try graphRefs(graph, pp[4], refs[4..8], phase);
                        if (pp[7] == 0) @memset(refs[8..12], Source.constant(0)) else try graphRefs(graph, pp[5], refs[8..12], phase);
                    },
                    4 => try graphRefs(graph, pp[3], &refs, phase),
                    5 => {
                        try graphRefs(graph, pp[6], refs[0..4], phase);
                        if (pp[3] == 0 and pp[4] == 0) @memset(refs[4..8], Source.constant(0)) else try graphRefs(graph, pp[7], refs[4..8], phase);
                    },
                    18 => {
                        try graphRefs(graph, pp[2], refs[0..4], phase);
                        for (0..4) |j| {
                            try graphRefs(graph, pp[3 + j], refs[4 + 4 * j ..][0..4], phase);
                            try graphRefs(graph, pp[7 + j], refs[20 + 4 * j ..][0..4], phase);
                        }
                        try graphRefs(graph, pp[11], refs[36..40], phase);
                    },
                    19 => {
                        try graphRefs(graph, pp[2], refs[0..4], phase);
                        for (0..4) |j| {
                            var query: [4]Source = undefined;
                            try graphRefs(graph, pp[3 + j], &query, phase);
                            refs[4 + j] = query[0];
                            try graphRefs(graph, pp[7 + j], refs[8 + 4 * j ..][0..4], phase);
                        }
                        try graphRefs(graph, pp[11], refs[24..28], phase);
                    },
                    else => unreachable,
                }
                try self.append(cohort, @intCast(index), row, &refs, phase, try self.mainOffset(cohort));
            }
        }
    }

    /// Scalar providers and public anchors in the original arithmetic graph
    /// namespaces read those same completed GPU nodes. Other namespaces are
    /// intentionally left for raw/hash routing and remain required by finish.
    pub fn appendGraphPorts(self: *Builder, arithmetic: *const @import("resident_parent_arithmetic_plan_v1.zig").Plan, fixed: Storage.FixedTuple(false), phase: u32) !void {
        if (arithmetic.graphs.len != 3 or arithmetic.graph_ids.len != 3 or self.bounds.arithmetic_words != arithmetic.value_words)
            return error.InvalidResidentArithmeticRoute;
        for (arithmetic.graph_ids, self.program.view().admission.key.context.graph_ids) |actual, expected|
            if (!std.mem.eql(u8, &actual, &expected)) return error.UntrustedResidentArithmeticRoute;
        inline for (.{ 2, 12 }) |cohort| for (fixed[cohort], 0..) |row, index| {
            const circuit = row[if (cohort == 2) 1 else 0].v;
            if (circuit < 1500 or circuit > 1504 or circuit & 1 != 0) continue;
            const node = row[if (cohort == 2) 2 else 1].v;
            var refs: [4]Source = undefined;
            try graphRefs(try graphForCircuit(arithmetic, circuit), node, &refs, phase);
            try self.append(cohort, @intCast(index), row, refs[0..dynamicWordCount(cohort)], phase, try self.mainOffset(cohort));
        };
    }

    /// Fixed tails must originate from the independently derived original
    /// roster. Their numeric identity is checked by the GPU fixed commitment;
    /// these bounds cannot nominate or replace that expected root.
    pub fn append(self: *Builder, comptime cohort: usize, row: u32, fixed: Storage.FixedRow(Storage.Airs[cohort]), sources: []const Source, phase: u32, destination: u64) !void {
        comptime {
            var supported = false;
            for (COHORTS) |c| if (c == cohort) {
                supported = true;
            };
            if (!supported) @compileError("direct row is owned by the hash/arithmetic device producer");
        }
        const Air = Storage.Airs[cohort];
        const p = self.program.view();
        const log = p.cohorts[cohort].trace_log;
        if (sources.len != dynamicWordCount(cohort) or sources.len > MAX_DYNAMIC_WORDS or log > 27 or
            row >= @as(u32, 1) << @intCast(log)) return error.InvalidResidentValueRoute;
        const words = try std.math.mul(usize, Air.PHYSICAL_MAIN_COLUMN_COUNT, @as(usize, 1) << @intCast(log));
        if (destination > self.bounds.main_words or words > self.bounds.main_words - destination)
            return error.ResidentValueRouteDestinationLimit;
        const expected_destination = try self.mainOffset(cohort);
        if (destination != expected_destination) return error.ResidentValueRouteDestinationLimit;
        const new_calls = try std.math.add(usize, self.calls.items.len, 1);
        const new_fixed = try std.math.add(usize, self.fixed.items.len, fixed.len);
        const new_sources = try std.math.add(usize, self.sources.items.len, sources.len);
        if (new_calls > self.limits.max_calls or new_calls > std.math.maxInt(u32) or
            new_fixed > self.limits.max_fixed_words or new_fixed > std.math.maxInt(u32) or
            new_sources > self.limits.max_sources or new_sources > std.math.maxInt(u32))
            return error.ResidentValueRouteResourceLimit;
        for (fixed) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidResidentFixedValue;
        for (sources) |source| try validateSource(source, self.bounds, phase);
        const destination_key = (@as(u64, cohort) << 32) | row;
        if (self.destinations.contains(destination_key)) return error.DuplicateResidentValueRoute;
        if (try metadataBytes(new_calls, new_fixed, new_sources, new_calls) > self.limits.max_device_bytes)
            return error.ResidentValueRouteResourceLimit;
        // Every fallible allocation precedes publication of this row.
        try self.calls.ensureUnusedCapacity(self.a, 1);
        try self.fixed.ensureUnusedCapacity(self.a, fixed.len);
        try self.sources.ensureUnusedCapacity(self.a, sources.len);
        try self.destinations.ensureUnusedCapacity(self.a, 1);
        const call = Call{ .cohort = cohort, .logical_row = row, .trace_log = log, .fixed_first = @intCast(self.fixed.items.len), .source_first = @intCast(self.sources.items.len), .source_count = @intCast(sources.len), .phase = phase, .destination_first = destination };
        for (fixed) |value| self.fixed.appendAssumeCapacity(value.v);
        self.sources.appendSliceAssumeCapacity(sources);
        self.calls.appendAssumeCapacity(call);
        self.destinations.putAssumeCapacityNoClobber(destination_key, {});
    }

    /// Every original direct row must have a route. Missing witnesses cannot
    /// silently become zero rows or be supplied by a CPU fallback.
    pub fn finish(self: *Builder, expected_counts: [Storage.Airs.len]usize) !*Plan {
        var seen: [Storage.Airs.len]usize = @splat(0);
        for (self.calls.items) |call| {
            if (call.logical_row >= expected_counts[call.cohort]) return error.MissingResidentValueRoute;
            seen[call.cohort] += 1;
        }
        for (COHORTS) |c| if (seen[c] != expected_counts[c]) return error.MissingResidentValueRoute;
        const owned = try self.a.create(Owned);
        errdefer self.a.destroy(owned);
        var arena = std.heap.ArenaAllocator.init(self.a);
        errdefer arena.deinit();
        const a = arena.allocator();
        const calls = try a.dupe(Call, self.calls.items);
        std.mem.sort(Call, calls, {}, struct {
            fn less(_: void, left: Call, right: Call) bool {
                if (left.phase != right.phase) return left.phase < right.phase;
                if (left.cohort != right.cohort) return left.cohort < right.cohort;
                return left.logical_row < right.logical_row;
            }
        }.less);
        var groups: std.ArrayList(Group) = .empty;
        for (calls, 0..) |call, i| {
            if (groups.items.len == 0 or groups.items[groups.items.len - 1].phase != call.phase or
                groups.items[groups.items.len - 1].cohort != call.cohort)
                try groups.append(a, .{ .first = @intCast(i), .count = 1, .phase = call.phase, .cohort = call.cohort })
            else
                groups.items[groups.items.len - 1].count += 1;
        }
        const fixed = try a.dupe(u32, self.fixed.items);
        const sources = try a.dupe(Source, self.sources.items);
        const group_slice = try groups.toOwnedSlice(a);
        const bytes = try metadataBytes(calls.len, fixed.len, sources.len, group_slice.len);
        if (bytes > self.limits.max_device_bytes) return error.ResidentValueRouteResourceLimit;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/resident-parent/value-routes/v1\x00");
        hash.update(&self.program.view().identity);
        // Explicit words avoid hashing ABI padding and machine endianness.
        inline for (std.meta.fields(Bounds)) |field| mix(&hash, @intCast(@field(self.bounds, field.name)));
        for (calls) |call| inline for (std.meta.fields(Call)) |field| mix(&hash, @intCast(@field(call, field.name)));
        for (fixed) |value| mix(&hash, value);
        for (sources) |source| inline for (std.meta.fields(Source)) |field| mix(&hash, @field(source, field.name));
        owned.* = .{ .a = self.a, .arena = arena, .data = .{ .calls = calls, .fixed = fixed, .sources = sources, .groups = group_slice, .bounds = self.bounds, .metadata_bytes = bytes, .identity = hash.finalResult() } };
        return @ptrCast(owned);
    }
};

pub fn dynamicWordCount(comptime cohort: usize) usize {
    return @import("resident_parent_direct_writers_v1.zig").dynamicWordCount(cohort);
}
pub fn validateSource(source: Source, bounds: Bounds, phase: u32) !void {
    const kind = std.meta.intToEnum(Kind, source.kind) catch return error.InvalidResidentValueSource;
    if (source.ready_phase > phase) return error.UnreadyResidentValueSource;
    switch (kind) {
        .constant => if (source.aux != 0 or source.ready_phase != 0) return error.InvalidResidentValueSource,
        .raw_u32_le => if (source.aux != 0 or source.ready_phase != 0 or source.index > bounds.raw_bytes or bounds.raw_bytes - source.index < 4) return error.InvalidResidentValueSource,
        .resident_word => if (source.aux != 0 or source.index >= bounds.resident_words) return error.InvalidResidentValueSource,
        .packed_bytes4 => if (source.aux != 0 or source.index > bounds.resident_words or bounds.resident_words - source.index < 4) return error.InvalidResidentValueSource,
        .extract_bit => if (source.aux >= 32 or source.index >= bounds.resident_words) return error.InvalidResidentValueSource,
        .arithmetic_word => if (source.aux != 0 or source.index >= bounds.arithmetic_words) return error.InvalidResidentValueSource,
        .main_word => if (source.aux != 0 or source.index >= bounds.main_words) return error.InvalidResidentValueSource,
        .hash_word => if (source.aux != 0 or source.index >= bounds.hash_words) return error.InvalidResidentValueSource,
        .packed_main4 => {
            const end = try std.math.add(usize, source.index, try std.math.mul(usize, source.aux, 3));
            if (source.aux == 0 or end >= bounds.main_words) return error.InvalidResidentValueSource;
        },
        .hash_byte => if (source.aux >= 4 or source.index >= bounds.hash_words) return error.InvalidResidentValueSource,
        .raw_byte => if (source.aux != 0 or source.ready_phase != 0 or source.index >= bounds.raw_bytes) return error.InvalidResidentValueSource,
        .resident_byte => if (source.aux >= 4 or source.index >= bounds.resident_words) return error.InvalidResidentValueSource,
        .readonly_word => if (source.aux != 0 or source.index >= bounds.readonly_words) return error.InvalidResidentValueSource,
    }
}
fn mix(hash: anytype, value: u64) void {
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, value, .little);
    hash.update(&word);
}
fn metadataBytes(calls: usize, fixed: usize, sources: usize, groups: usize) !usize {
    var result: usize = 0;
    inline for (.{ Call, u32, Source, Group }, .{ calls, fixed, sources, groups }) |T, count|
        result = try std.math.add(usize, result, try std.math.mul(usize, @sizeOf(T), count));
    return result;
}
fn graphForCircuit(plan: *const @import("resident_parent_arithmetic_plan_v1.zig").Plan, circuit: u32) !@import("resident_parent_arithmetic_plan_v1.zig").Graph {
    if (circuit < 1500 or circuit > 1504 or circuit & 1 != 0) return error.InvalidResidentArithmeticCircuit;
    return plan.graphs[(circuit - 1500) / 2];
}
fn graphRefs(graph: @import("resident_parent_arithmetic_plan_v1.zig").Graph, node: u32, out: []Source, phase: u32) !void {
    if (node >= graph.node_count or out.len != 4) return error.InvalidResidentArithmeticNode;
    const first = try std.math.add(u32, graph.value_word_base, try std.math.mul(u32, node, 4));
    for (out, 0..) |*ref, limb| ref.* = Source.arithmetic(first + @as(u32, @intCast(limb)), phase);
}

test "resident value routes reject unavailable phases and all source overruns" {
    const bounds = Bounds{ .raw_bytes = 7, .resident_words = 5, .main_words = 32 };
    try validateSource(Source.raw(3), bounds, 0);
    try validateSource(Source.packedBytes(1, 2), bounds, 2);
    try std.testing.expectError(error.InvalidResidentValueSource, validateSource(Source.raw(4), bounds, 0));
    try std.testing.expectError(error.InvalidResidentValueSource, validateSource(Source.packedBytes(2, 0), bounds, 0));
    try std.testing.expectError(error.InvalidResidentValueSource, validateSource(Source.resident(5, 0), bounds, 0));
    try std.testing.expectError(error.UnreadyResidentValueSource, validateSource(Source.resident(0, 3), bounds, 2));
    try std.testing.expectError(error.InvalidResidentValueSource, validateSource(.{ .kind = 999, .index = 0 }, bounds, 0));
}

test "resident value routes bind the exact original destination and require complete coverage" {
    const a = std.testing.allocator;
    const p = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var main_words: usize = 0;
    var destination: usize = 0;
    for (p.view().cohorts, 0..) |cohort, index| {
        const n = @as(usize, cohort.columns[1]) << @intCast(cohort.trace_log);
        if (index < 2) destination += n;
        main_words += n;
    }
    var builder = try Builder.init(a, p, .{ .raw_bytes = 4, .resident_words = 4, .main_words = main_words }, .{});
    defer builder.deinit();
    const Boundary = Storage.Airs[2];
    const row = try Boundary.logicalCoordinates(1, 2, core.fields.m31.M31.one(), @splat(core.fields.m31.M31.zero()));
    const fixed = Storage.compactFixed(Boundary, row);
    const refs = [_]Source{ Source.raw(0), Source.constant(0), Source.constant(0), Source.constant(0) };
    try std.testing.expectError(error.ResidentValueRouteDestinationLimit, builder.append(2, 0, fixed, &refs, 0, destination + 1));
    try builder.append(2, 0, fixed, &refs, 0, destination);
    try std.testing.expectError(error.DuplicateResidentValueRoute, builder.append(2, 0, fixed, &refs, 0, destination));
    var counts: [Storage.Airs.len]usize = @splat(0);
    counts[2] = 2;
    try std.testing.expectError(error.MissingResidentValueRoute, builder.finish(counts));
    counts[2] = 1;
    const plan = try builder.finish(counts);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.view().calls.len);
    try std.testing.expectEqual(@as(usize, 1), plan.view().groups.len);
    try std.testing.expectEqual(destination, plan.view().calls[0].destination_first);
}

test "resident arithmetic row routes use authenticated graph outputs and literal inactive operands" {
    const a = std.testing.allocator;
    const Arithmetic = @import("resident_parent_arithmetic_plan_v1.zig");
    const Original = Arithmetic.Original;
    const nodes = [_]Original.Node{ .{ .op = .input }, .{ .op = .{ .constant = .{ 1, 0, 0, 0 } } }, .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .sub = .{ .lhs = 2, .rhs = 2 } } } };
    const outputs = [_]u32{3};
    const graph = try Original.CircuitGraph.authenticate(&nodes, &outputs, Original.computeGraphDigest(&nodes, &outputs));
    var arithmetic = try Arithmetic.Plan.init(a, &.{ graph, graph, graph }, .{});
    defer arithmetic.deinit();
    var admission = try Program.fixtureAdmission();
    admission.key.context.graph_ids = .{ graph.identity_digest, graph.identity_digest, graph.identity_digest };
    admission.expected_id = try admission.key.identity();
    const program = try Program.Owned.derive(a, admission, .{});
    defer program.deinit();
    var main_words: usize = 0;
    for (program.view().cohorts) |cohort| main_words += @as(usize, cohort.columns[1]) << @intCast(cohort.trace_log);
    var builder = try Builder.init(a, program, .{ .raw_bytes = 4, .resident_words = 0, .main_words = main_words, .arithmetic_words = arithmetic.value_words }, .{});
    defer builder.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    var multiply = [_]Storage.FixedRow(Storage.Airs[3]){try Storage.Airs[3].fixedRow(.{ .circuit = 1500, .output = 2, .lhs = 0, .rhs = 1, .uses = 1 })};
    fixed[3] = &multiply;
    try builder.appendArithmetic(&arithmetic, fixed, 4);
    try std.testing.expectEqual(@as(usize, 12), builder.sources.items.len);
    for (builder.sources.items[0..8]) |source| {
        try std.testing.expectEqual(@intFromEnum(Kind.arithmetic_word), source.kind);
        try std.testing.expectEqual(@as(u32, 4), source.ready_phase);
    }
    for (builder.sources.items[8..12]) |source| try std.testing.expectEqualDeep(Source.constant(0), source);
    var bad = arithmetic;
    var bad_ids = arithmetic.graph_ids[0..3].*;
    bad_ids[0][0] ^= 1;
    bad.graph_ids = &bad_ids;
    try std.testing.expectError(error.UntrustedResidentArithmeticRoute, builder.appendArithmetic(&bad, fixed, 4));
}
