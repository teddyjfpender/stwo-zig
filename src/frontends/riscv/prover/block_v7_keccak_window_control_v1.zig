//! Same-column control projection for independently selected Keccak windows.
//! One original Keccak AIR must constrain each referenced caller row. The
//! fixed owner selector must also be used by the original global-RAM bridge.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Memory = @import("block_v7_memory_relations_v1.zig");
const Trace = @import("block_v7_memory_trace_v1.zig");
const Source = @import("block_v7_keccak_window_source_v1.zig");
const Relations = @import("../air/guest_precompile/keccakf_relations.zig").Relations;
pub fn For(comptime local_zero: bool) type {
    return struct {
        const Self = @This();
        const S = Source.For(local_zero);
        pub const FIXED_COUNT = 1;
        pub const MAIN_COUNT = S.caller_width;
        pub const PLANES = S.control_planes;
        pub const INTERACTION_COUNT = 4 * PLANES;
        pub const CONSTRAINT_COUNT = PLANES;
        // The fixed owner multiplies the original x0 caller numerator.
        // Do not silently reuse the original unselected degree-3 bound.
        pub const DEGREE = 4;
        pub const EXPANSION_BITS = 2;
        pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
        pub const Component = @import("block_v7_shared_word_projection_v1.zig").ForOwnedFixed(Self);
        relations: *const Relations,
        sums: [PLANES]Q,
        pub fn terms(self: Self, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q) ![PLANES]Memory.Term(Q) {
            return S.control(fixed[0], &main, self.relations);
        }
        pub fn termsAt(self: Self, source: Trace.Matrix, logical: usize) ![PLANES]Memory.Term(Q) {
            var main: [MAIN_COUNT]Q = undefined;
            for (&main, 0..) |*value, i| value.* = Q.fromBase(source.get(i, logical));
            return self.terms(.{Q.fromBase(source.get(MAIN_COUNT, logical))}, main);
        }
        pub const Domain = struct {
            spec: Self,
            normalized: [PLANES]Q,
            pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
                _ = previous_main;
                _ = size;
                return Memory.interactionConstraints(Q, PLANES, try self.spec.terms(fixed, main), current, previous, self.normalized);
            }
            pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]Memory.P, main: [MAIN_COUNT]Memory.P, previous_main: [MAIN_COUNT]Memory.P, current: [INTERACTION_COUNT]Memory.P, previous: [INTERACTION_COUNT]Memory.P) [CONSTRAINT_COUNT]Memory.P {
                const lanes = core.fields.m31.PACK_WIDTH;
                var results: [CONSTRAINT_COUNT][lanes]Q = undefined;
                for (0..lanes) |lane| {
                    var f: [FIXED_COUNT]Q = undefined;
                    var m: [MAIN_COUNT]Q = undefined;
                    var pm: [MAIN_COUNT]Q = undefined;
                    var c: [INTERACTION_COUNT]Q = undefined;
                    var p: [INTERACTION_COUNT]Q = undefined;
                    for (&f, fixed) |*out, value| out.* = value.lane(lane);
                    for (&m, main) |*out, value| out.* = value.lane(lane);
                    for (&pm, previous_main) |*out, value| out.* = value.lane(lane);
                    for (&c, current) |*out, value| out.* = value.lane(lane);
                    for (&p, previous) |*out, value| out.* = value.lane(lane);
                    const equations = self.evaluate(f, m, pm, c, p, 0) catch unreachable;
                    for (&results, equations) |*out, value| out[lane] = value;
                }
                var out: [CONSTRAINT_COUNT]Memory.P = undefined;
                for (&out, results) |*value, values| value.* = Memory.P.fromLanes(values);
                return out;
            }
        };
        pub fn prepareDomain(self: Self, size: u32) !Domain {
            return .{ .spec = self, .normalized = try Memory.normalize(PLANES, self.sums, size) };
        }
        pub fn evaluate(self: Self, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            return (try self.prepareDomain(size)).evaluate(fixed, main, previous_main, current, previous, size);
        }
    };
}

test "Keccak control projection declares only new owner and interaction columns" {
    const std = @import("std");
    const a = std.testing.allocator;
    const S = For(true);
    const relations = Relations.dummy();
    const component = try S.Component.init(.{ .relations = &relations, .sums = @splat(Q.zero()) }, 5, .{ 9, 100, 200 });
    var logs = try component.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 1), logs.items[0].len);
    try std.testing.expectEqual(@as(usize, 0), logs.items[1].len);
    try std.testing.expectEqual(@as(usize, 12), logs.items[2].len);
    const fixed = try component.preprocessedColumnIndices(a);
    defer a.free(fixed);
    try std.testing.expectEqualSlices(usize, &.{9}, fixed);
    const prover = component.asProverComponent();
    const verifier = component.asVerifierComponent();
    try std.testing.expectEqual(@as(u32, 2), prover.compositionLogSplit());
    try std.testing.expectEqual(prover.nConstraints(), verifier.nConstraints());
}
