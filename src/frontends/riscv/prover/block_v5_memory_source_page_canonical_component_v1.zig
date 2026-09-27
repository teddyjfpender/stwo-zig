//! Canonical zero/Boolean closure of ORIGINAL PAGE source cells. The graph
//! omits these zero cells for efficiency; that omission is sound only when
//! this exact component uses the same original committed main tree.
//! Fixed kinds are independently reconstructed from the sealed page roster.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Old = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
pub const CANONICAL_FIXED_COUNT: usize = 5;
pub fn rawFixed(descriptor: ?Raw.Descriptor) [CANONICAL_FIXED_COUNT]M {
    var out: [CANONICAL_FIXED_COUNT]M = @splat(M.zero());
    const d = descriptor orelse return out;
    out[0] = M.one();
    const field: usize = switch (d) {
        .sha => 1,
        .record => |record| switch (record.stream) {
            .input_words, .rw_words => 2,
            .first_touches => 3,
            .endpoints => 4,
            .public_input => unreachable,
        },
    };
    out[field] = M.one();
    return out;
}
pub fn foldFixed(descriptor: ?Eq.Descriptor) ![CANONICAL_FIXED_COUNT]M {
    var out: [CANONICAL_FIXED_COUNT]M = @splat(M.zero());
    const d = descriptor orelse return out;
    try d.validate();
    out[0] = M.one();
    out[
        switch (d.kind) {
            .leaf => @as(usize, 1),
            .branch => 2,
            .empty => 3,
            .root => 4,
        }
    ] = M.one();
    return out;
}
pub fn ForKind(comptime kind: Semantic.Kind) type {
    return struct {
        const Self = @This();
        pub const MAIN_COUNT: usize = if (kind == .raw) Old.BIT_COUNT else Eq.BIT_COUNT;
        pub const CONSTRAINT_COUNT: usize = 2 * MAIN_COUNT;
        pub fn Algebra(comptime S: type) type {
            return struct {
                pub fn constraints(fixed: [CANONICAL_FIXED_COUNT]S, main: [Self.MAIN_COUNT]S) [Self.CONSTRAINT_COUNT]S {
                    var out: [Self.CONSTRAINT_COUNT]S = undefined;
                    for (main, 0..) |value, column| {
                        var allowed = S.zero();
                        if (kind == .raw) {
                            if (column < 768) allowed = allowed.add(fixed[1]);
                            if (column >= 768 and column < 832) allowed = allowed.add(fixed[2]).add(fixed[3]).add(fixed[4]);
                            if (column >= 832 and column < 864) allowed = allowed.add(fixed[3]);
                            if (column >= 864 and column < 896) allowed = allowed.add(fixed[2]).add(fixed[4]);
                            if (column >= 896 and column < 960) allowed = allowed.add(fixed[4]);
                        } else {
                            if (column < 832 or column >= 1856) allowed = allowed.add(fixed[1]);
                            if (column < 32 or (column >= 320 and column < 1856)) allowed = allowed.add(fixed[2]);
                            if (column < 32 or (column >= 320 and column < 832)) allowed = allowed.add(fixed[3]).add(fixed[4]);
                        }
                        out[2 * column] = value.mul(value.sub(S.one()));
                        out[2 * column + 1] = value.mul(S.one().sub(allowed));
                    }
                    return out;
                }
            };
        }
        pub const Spec = struct {
            pub const FIXED_COUNT = 5;
            pub const MAIN_COUNT = Self.MAIN_COUNT;
            pub const INTERACTION_COUNT = 0;
            pub const CONSTRAINT_COUNT = Self.CONSTRAINT_COUNT;
            pub const PREVIOUS_MAIN_MASK: [Self.MAIN_COUNT]bool = @splat(false);
            pub const DEGREE: u32 = 2;
            pub const EXPANSION_BITS: u32 = 2;
            rows: u32,
            pub const Domain = struct {
                size: u32,
                pub fn evaluate(self: Domain, fixed: [CANONICAL_FIXED_COUNT]Q, main: [Self.MAIN_COUNT]Q, _: [Self.MAIN_COUNT]Q, _: [0]Q, _: [0]Q, size: u32) ![Self.CONSTRAINT_COUNT]Q {
                    if (self.size != size) return error.InvalidSourcePageCanonicalGeometry;
                    return Self.Algebra(Q).constraints(fixed, main);
                }
                pub fn evaluatePacked(_: *const Domain, fixed: [CANONICAL_FIXED_COUNT]P, main: [Self.MAIN_COUNT]P, _: [Self.MAIN_COUNT]P, _: [0]P, _: [0]P) [Self.CONSTRAINT_COUNT]P {
                    return Self.Algebra(P).constraints(fixed, main);
                }
            };
            pub fn prepareDomain(self: Spec, rows: u32) !Domain {
                if (rows != self.rows or rows == 0) return error.InvalidSourcePageCanonicalGeometry;
                return .{ .size = rows };
            }
            pub fn evaluate(self: Spec, fixed: [CANONICAL_FIXED_COUNT]Q, main: [Self.MAIN_COUNT]Q, previous: [Self.MAIN_COUNT]Q, current: [0]Q, previous_interaction: [0]Q, rows: u32) ![Self.CONSTRAINT_COUNT]Q {
                return (try self.prepareDomain(rows)).evaluate(fixed, main, previous, current, previous_interaction, rows);
            }
        };
        pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
    };
}
