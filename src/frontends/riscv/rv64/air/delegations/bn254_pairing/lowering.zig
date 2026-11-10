//! Immutable source lowering, never decoded from prover metadata.
//! Every old writer maps to a fresh canonical final MAC stage/hint writer.
const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
pub const N = @import("../bn254_mac12/normalize.zig");
const Literal = @import("literal_fold.zig");
pub const Mac = @import("../bn254_mac12/source.zig");
pub const Hint = struct { writer: u32, source_writer: u32, kind: S.Hint, denominator: u32 };
pub const Event = struct { kind: enum { arithmetic, hint }, index: usize };
pub const FRONTIER_ROWS = S.INITIAL + S.ASSERTIONS;
pub const Program = struct {
    allocator: std.mem.Allocator,
    stages: []N.Stage,
    hints: []Hint,
    events: []Event,
    source_to_new: []u32,
    assertions: []S.Assertion,
    fanout: []u32,
    value_count: u32,
    pub fn init(a: std.mem.Allocator) !Program {
        var stage_count: usize = 0;
        for (W.ROM.nodes) |node| if (node.kind != .hint) {
            const expression = S.expression(node);
            var terms: [145]N.Term = undefined;
            for (expression.terms[0..expression.len], terms[0..expression.len]) |term, *out| out.* = .{ .a = term.a, .b = term.b, .coefficient = term.coefficient };
            const folded = try Literal.apply(terms[0..expression.len], S.literalId(0), S.literalId(1));
            stage_count += (try N.count(folded.terms[0..folded.len])).rows;
        };
        const stages = try a.alloc(N.Stage, stage_count);
        errdefer a.free(stages);
        const hints = try a.alloc(Hint, S.HINTS);
        errdefer a.free(hints);
        const events = try a.alloc(Event, stage_count + S.HINTS);
        errdefer a.free(events);
        const mapping = try a.alloc(u32, S.VALUES);
        errdefer a.free(mapping);
        const assertions = try a.alloc(S.Assertion, S.ASSERTIONS);
        errdefer a.free(assertions);
        const value_count = S.INITIAL + stage_count + S.HINTS;
        if (value_count >= 2147483647) return error.PairingLoweredIdBound;
        const fanout = try a.alloc(u32, value_count);
        errdefer a.free(fanout);
        @memset(fanout, 0);
        for (mapping[0..S.INITIAL], 0..) |*id, i| id.* = @intCast(i);
        var next: u32 = S.INITIAL;
        var arithmetic_at: usize = 0;
        var hint_at: usize = 0;
        var event_at: usize = 0;
        for (W.ROM.nodes) |node| {
            if (node.kind == .hint) {
                const denominator = if (node.hint == .inverse) mapping[node.hint_denominator] else S.NONE;
                hints[hint_at] = .{ .writer = next, .source_writer = node.writer, .kind = node.hint, .denominator = denominator };
                events[event_at] = .{ .kind = .hint, .index = hint_at };
                mapping[node.writer] = next;
                hint_at += 1;
                event_at += 1;
                next += 1;
                continue;
            }
            const expression = S.expression(node);
            var terms: [145]N.Term = undefined;
            for (expression.terms[0..expression.len], terms[0..expression.len]) |term, *out| {
                if (term.a >= node.writer or (term.b != null and term.b.? >= node.writer)) return error.PairingSourceNotTopological;
                out.* = .{ .a = mapping[term.a], .b = if (term.b) |b| mapping[b] else null, .coefficient = term.coefficient };
            }
            const folded = try Literal.apply(terms[0..expression.len], S.literalId(0), S.literalId(1));
            var plan = try N.lower(a, folded.terms[0..folded.len], &next, S.literalId(0), S.literalId(1));
            defer plan.deinit();
            for (plan.stages) |stage| {
                stages[arithmetic_at] = stage;
                events[event_at] = .{ .kind = .arithmetic, .index = arithmetic_at };
                for (stage.input) |id| {
                    if (id >= stage.writer) return error.PairingLoweredSourceCycle;
                    fanout[id] = std.math.add(u32, fanout[id], 1) catch return error.PairingLoweredMassBound;
                }
                arithmetic_at += 1;
                event_at += 1;
            }
            mapping[node.writer] = plan.output();
        }
        for (W.ROM.assertions, assertions) |obligation, *out| {
            out.* = .{ .id = mapping[obligation.id], .value = obligation.value };
            fanout[out.id] = std.math.add(u32, fanout[out.id], 1) catch return error.PairingLoweredMassBound;
        }
        var mass: u64 = 0;
        for (fanout) |n| {
            if (n >= 2147483647) return error.PairingLoweredMassBound;
            mass += n;
        }
        if (mass >= 2147483647) return error.PairingLoweredMassBound;
        std.debug.assert(next == value_count and arithmetic_at == stage_count and hint_at == S.HINTS and event_at == events.len);
        return .{ .allocator = a, .stages = stages, .hints = hints, .events = events, .source_to_new = mapping, .assertions = assertions, .fanout = fanout, .value_count = next };
    }
    pub fn deinit(p: *Program) void {
        const a = p.allocator;
        a.free(p.stages);
        a.free(p.hints);
        a.free(p.events);
        a.free(p.source_to_new);
        a.free(p.assertions);
        a.free(p.fanout);
        p.* = undefined;
    }
    pub fn fixed(p: *const Program, index: usize) !Mac.Fixed {
        const stage = p.stages[index];
        return Mac.fixed(true, stage.coefficients, stage.input, stage.writer, p.fanout[stage.writer]);
    }
    pub fn frontierId(p: *const Program, row: usize) u32 {
        return if (row < S.INITIAL) @intCast(row) else p.assertions[row - S.INITIAL].id;
    }
    pub fn frontierWeight(p: *const Program, row: usize) i32 {
        return if (row < S.INITIAL) @intCast(p.fanout[row]) else -1;
    }
    pub fn frontierExpected(p: *const Program, row: usize, expected_initial: *const [S.INITIAL]u256) u256 {
        return if (row < S.INITIAL) expected_initial[row] else p.assertions[row - S.INITIAL].value;
    }
};

/// New physical-candidate identity. The qualified logical source identity stays
/// unchanged; a later proof must additionally bind this exact lowering authority.
pub fn sourceDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("complete-finite-pairing-canonical-mac12-lowering/v1");
    h.update(&@import("mod.zig").sourceDigest());
    h.update(@embedFile("lowering.zig"));
    h.update(@embedFile("literal_fold.zig"));
    h.update(@embedFile("normalized_witness.zig"));
    h.update(@embedFile("../bn254_mac12/normalize.zig"));
    h.update(@embedFile("../bn254_mac12/source.zig"));
    h.update(@embedFile("../bn254_mac12/bounds.zig"));
    h.update(@embedFile("../bn254_mac12/witness.zig"));
    h.update(@embedFile("../bn254_mac12/canonical_word16.zig"));
    return h.finalResult();
}
