//! Native witness for the Zbb BINARY truth provider (binary_zbb.zig).
//! It produces an ordinary `binary_source.Source`: the packed metadata
//! (FUNCTION payload, eight byte-AND indices, multiplicity) is chip-agnostic,
//! so the SAME interaction generator, AND dictionary and prefix kernel serve
//! both chips. Only the MAIN row formatter differs (31 local + multiplicity).
//! Facts are validated against the independent reference semantics before any
//! row is written; this is a witness builder, not an acceptance authority.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Z = @import("binary_zbb.zig");
const P = @import("binary_lookup.zig");
const S = @import("binary_source.zig");
const Tables = @import("../providers/tables.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
pub const MAIN = P.zbb.MAIN;
pub const INTERACTION = P.zbb.INTERACTION;
comptime {
    std.debug.assert(INTERACTION == S.INTERACTION);
}
pub const Fact = struct { op: Z.Op, a: u64, b: u64, c: u64 };

/// Exact reference check: result and the ROM-pinned B of unary ops.
pub fn validFact(fact: Fact) bool {
    return @intFromEnum(fact.op) < Z.OPS and fact.b == Z.canonicalB(fact.op, fact.b) and fact.c == Z.result(fact.op, fact.a, fact.b);
}

fn toM(value: E.Q) M {
    return value.tryIntoM31() catch unreachable; // witness rows are base-field
}

/// Weighted facts (multiplicity per distinct fact); null weights = all one.
pub fn initWeighted(a: std.mem.Allocator, facts: []const Fact, weights: ?[]const u32, log: u32) !S.Source {
    const mass = try S.massForLog(log);
    const n: usize = @intCast(mass.fact_capacity);
    if (facts.len > n) return error.BinaryZbbCapacityExceeded;
    var function_mass: u64 = facts.len;
    if (weights) |w| {
        if (w.len != facts.len) return error.InvalidBinaryZbbWeights;
        function_mass = 0;
        for (w) |weight| {
            if (weight >= core.fields.m31.Modulus) return error.InvalidBinaryZbbWeights;
            function_mass = try std.math.add(u64, function_mass, weight);
            if (function_mass >= core.fields.m31.Modulus) return error.BinaryZbbMultiplicityMassExceeded;
        }
    }
    for (facts) |fact| if (!validFact(fact)) return error.InvalidBinaryZbbFact;
    const fixed = try S.fixedForLog(a, log);
    errdefer a.free(fixed);
    const counts = try a.alloc(u64, 65536);
    errdefer a.free(counts);
    @memset(counts, 0);
    const metadata = try a.alloc(S.Metadata, n);
    errdefer a.free(metadata);
    const main = try a.alloc(M, MAIN * n);
    errdefer a.free(main);
    for (0..n) |i| {
        const p = physical(i, log);
        const weight: u32 = if (i < facts.len) (if (weights) |w| w[i] else 1) else 0;
        var row: Z.RowFor(E.Q) = undefined;
        if (i < facts.len) {
            row = Z.witness(facts[i].op, facts[i].a, facts[i].b);
        } else {
            // Inactive padding: every byte zero, payload zero (binary_zbb.zig item 6).
            row = .{ .payload = @splat(E.Q.zero()), .active = E.Q.zero(), .selectors = @splat(E.Q.zero()), .a = @splat(E.Q.zero()), .b = @splat(E.Q.zero()), .ab = @splat(E.Q.zero()) };
        }
        const values = P.rowToColumnsOf(Z, E.Q, row);
        for (values, 0..) |v, c| main[c * n + p] = toM(v);
        main[Z.LOCAL_MAIN * n + p] = M.fromCanonical(weight);
        metadata[i].multiplicity_words = .{ @truncate(weight), @truncate(weight >> 16) };
        for (row.payload, 0..) |v, c| metadata[i].payload[c] = @intCast(toM(v).v);
        for (0..8) |j| {
            const index = try Tables.Kind.byte_and.rowIndex(.{ toM(row.a[j]).v, toM(row.b[j]).v, toM(row.ab[j]).v, 0, 0, 0 });
            metadata[i].and_indices[j] = @intCast(index);
            counts[index] += 1;
        }
    }
    return .{ .allocator = a, .log_size = log, .fact_count = facts.len, .function_mass = @intCast(function_mass), .fixed = fixed, .main = main, .owns_main = true, .and_counts = counts, .metadata = metadata };
}

/// Exact-tuple grouping (deduplication with multiplicities) of CPU facts.
pub const Weighted = struct {
    allocator: std.mem.Allocator,
    facts: []Fact,
    weights: []u32,
    pub fn deinit(self: *Weighted) void {
        self.allocator.free(self.facts);
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
pub fn collect(a: std.mem.Allocator, input: []const Fact) !Weighted {
    if (input.len >= core.fields.m31.Modulus) return error.BinaryZbbMultiplicityMassExceeded;
    var map: std.AutoHashMapUnmanaged(Fact, usize) = .empty;
    defer map.deinit(a);
    var facts: std.ArrayList(Fact) = .empty;
    defer facts.deinit(a);
    var weights: std.ArrayList(u32) = .empty;
    defer weights.deinit(a);
    for (input) |fact| {
        // Grouping only (like binary_dedup): truth is checked by initWeighted.
        if (@intFromEnum(fact.op) >= Z.OPS) return error.InvalidBinaryZbbFact;
        const entry = try map.getOrPut(a, fact);
        if (entry.found_existing) {
            weights.items[entry.value_ptr.*] += 1;
            continue;
        }
        entry.value_ptr.* = facts.items.len;
        try facts.append(a, fact);
        try weights.append(a, 1);
    }
    const fs = try facts.toOwnedSlice(a);
    errdefer a.free(fs);
    return .{ .allocator = a, .facts = fs, .weights = try weights.toOwnedSlice(a) };
}
