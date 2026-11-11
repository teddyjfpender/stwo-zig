//! Retains canonical values only. Full carry/range rows are materialized on demand.
const std = @import("std");
const S = @import("spec.zig");
const Source = @import("witness.zig");
const L = @import("lowering.zig");
pub const Mac = @import("../bn254_mac12/source.zig");
pub const MW = @import("../bn254_mac12/witness.zig");
pub const HW = @import("../bn254_hint/witness.zig");
pub const Witness = struct {
    allocator: std.mem.Allocator,
    initial: [S.INITIAL]u256,
    values: []u256,
    pub fn init(a: std.mem.Allocator, p: *const L.Program, source: *const Source.Witness) !Witness {
        const values = try a.alloc(u256, p.value_count);
        errdefer a.free(values);
        @memcpy(values[0..S.INITIAL], &source.initial);
        for (p.events) |event| switch (event.kind) {
            .hint => {
                const hint = p.hints[event.index];
                const value = source.values[hint.source_writer];
                if (value >= S.B.BN254_P) return error.NonCanonicalNormalizedHint;
                values[hint.writer] = value;
            },
            .arithmetic => {
                const stage = p.stages[event.index];
                var input: MW.Inputs = undefined;
                for (stage.input, &input) |id, *value| value.* = values[id];
                values[stage.writer] = @intCast(@mod(MW.expression(&input, stage.coefficients), @as(i1024, S.B.BN254_P)));
            },
        };
        for (p.source_to_new, source.values) |id, expected| if (values[id] != expected) return error.NormalizedSourceOutputMismatch;
        return .{ .allocator = a, .initial = source.initial, .values = values };
    }
    pub fn deinit(w: *Witness) void {
        w.allocator.free(w.values);
        w.* = undefined;
    }
    pub fn row(w: *const Witness, p: *const L.Program, index: usize) !Mac.Row {
        return w.rowMode(false, p, index);
    }
    pub fn rowReferenceForTesting(w: *const Witness, p: *const L.Program, index: usize) !Mac.Row {
        if (!@import("builtin").is_test) @compileError("test-only reference row encoder");
        return w.rowMode(true, p, index);
    }
    fn rowMode(w: *const Witness, comptime reference: bool, p: *const L.Program, index: usize) !Mac.Row {
        const stage = p.stages[index];
        var input: MW.Inputs = undefined;
        for (stage.input, &input) |id, *value| value.* = w.values[id];
        const out = if (reference) try MW.fillReferenceForTesting(&input, stage.coefficients) else try MW.fillKnownCanonical(&input, stage.coefficients, w.values[stage.writer]);
        if (MW.read(&out, Mac.OUTPUT, 32) != w.values[stage.writer]) return error.NormalizedSourceOutputMismatch;
        return out;
    }
    pub fn hintRow(w: *const Witness, p: *const L.Program, index: usize) !@import("../bn254_hint/source.zig").Row {
        return HW.fill(w.values[p.hints[index].writer]);
    }
    pub fn satisfied(w: *const Witness, p: *const L.Program) bool {
        if (!std.mem.eql(u256, w.values[0..S.INITIAL], &w.initial)) return false;
        for (p.stages) |stage| {
            var input: MW.Inputs = undefined;
            for (stage.input, &input) |id, *value| {
                if (w.values[id] >= S.B.BN254_P) return false;
                value.* = w.values[id];
            }
            if (w.values[stage.writer] >= S.B.BN254_P or @mod(MW.expression(&input, stage.coefficients), @as(i1024, S.B.BN254_P)) != w.values[stage.writer]) return false;
        }
        for (p.hints) |hint| if (w.values[hint.writer] >= S.B.BN254_P) return false;
        for (p.assertions) |obligation| if (w.values[obligation.id] != obligation.value) return false;
        return true;
    }
};
