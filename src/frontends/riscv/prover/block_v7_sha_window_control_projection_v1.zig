//! Relation-only projection of an authenticated complete SHA caller recipe.
//! The complete caller must be proved on these SAME columns. This does not
//! replace its constraints or relax typed machine-address validation.
const std = @import("std");
const core = @import("stwo_core");
const Caller = @import("../air/guest_precompile/sha256_global_wire_caller_v1.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig").Binding(Caller);
const Relations = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const Memory = @import("block_v7_memory_relations_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Owner = struct {
    plan: Binding.Plan,
    selected: [7]u8,
    pub fn init(a: std.mem.Allocator) !Owner {
        var definition = try Caller.build(a);
        defer definition.deinit();
        const plan = try Binding.authenticate(&definition);
        var selected: [7]u8 = undefined;
        var at: usize = 0;
        inline for (.{ .program_access, .registers_state, .memory_access }, .{ 1, 2, 4 }) |domain, expected| {
            const start = at;
            for (plan.events) |event| {
                if (event.domain != domain) continue;
                if (domain == .memory_access) {
                    var space: ?u32 = null;
                    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
                        if (node.destination != event.value_slots[0]) continue;
                        space = switch (node.op) {
                            .constant => |value| value,
                            else => null,
                        };
                    }
                    if (space == null or space.? > 1) return error.UntrustedShaRegisterSelection;
                    if (space.? != 0) continue;
                }
                if (at == selected.len) return error.UntrustedShaControlSelection;
                selected[at] = event.ordinal;
                at += 1;
            }
            if (at - start != expected) return error.UntrustedShaControlSelection;
        }
        for ([_][]const u8{ selected[0..1], selected[1..3], selected[3..5], selected[5..7] }) |pair| {
            if (try @import("block_v5_precompile_lookup_source_v1.zig").projectedDegree(Caller, &plan, pair) > Spec.DEGREE) return error.UnsupportedShaControlDegree;
        }
        return .{ .plan = plan, .selected = selected };
    }
};
pub const Spec = struct {
    pub const FIXED_COUNT = Caller.PREPROCESSED_COLUMN_COUNT;
    pub const MAIN_COUNT = Caller.PHYSICAL_MAIN_COLUMN_COUNT;
    pub const PLANES = 4;
    pub const INTERACTION_COUNT = 16;
    pub const CONSTRAINT_COUNT = 4;
    pub const DEGREE = 3;
    pub const EXPANSION_BITS = 1;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
    owner: *const Owner,
    relations: *const Relations,
    wire_offset: Q,
    sums: [PLANES]Q,
    pub fn terms(self: Spec, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q) ![PLANES]Memory.Term(Q) {
        var row: [Caller.LOGICAL_INPUT_COUNT]Q = undefined;
        @memcpy(row[0..MAIN_COUNT], &main);
        row[MAIN_COUNT] = fixed[0];
        row[Caller.LOGICAL_INPUT_COUNT - 1] = self.wire_offset;
        var visitor = Visitor{ .owner = self.owner, .relations = self.relations };
        try self.owner.plan.visitPreparedEntriesFor(Q, row, &visitor);
        if (visitor.found != 7) return error.InvalidShaControlProjection;
        return visitor.out;
    }
    pub const Domain = struct {
        spec: Spec,
        normalized: [PLANES]Q,
        // Small projection domains use scalar lanes of the authenticated plan.
        // No independently transcribed packed tuple algebra is introduced.
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
        pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            _ = previous_main;
            _ = size;
            return Memory.interactionConstraints(Q, PLANES, try self.spec.terms(fixed, main), current, previous, self.normalized);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        return .{ .spec = self, .normalized = try Memory.normalize(PLANES, self.sums, size) };
    }
    pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, main, previous_main, current, previous, size);
    }
    pub fn termsAt(self: Spec, source: @import("block_v7_memory_trace_v1.zig").Matrix, logical: usize) ![PLANES]Memory.Term(Q) {
        var main: [MAIN_COUNT]Q = undefined;
        for (&main, 0..) |*value, i| value.* = Q.fromBase(source.get(i, logical));
        return self.terms(.{Q.fromBase(source.get(MAIN_COUNT, logical))}, main);
    }
};
const Visitor = struct {
    owner: *const Owner,
    relations: *const Relations,
    found: usize = 0,
    out: [4]Memory.Term(Q) = @splat(.{}),
    pub fn accepts(_: *@This(), schema: @import("../air/lang/types.zig").RelationSchemaId) bool {
        const R = @import("../air/lang/relation.zig");
        return schema == R.id(.program_access) or schema == R.id(.registers_state) or schema == R.id(.memory_access);
    }
    pub fn visit(self: *@This(), ordinal: u8, domain: @import("../air/lang/relation.zig").Domain, numerator: Q, values: []const Q) !void {
        for (self.owner.selected, 0..) |wanted, i| if (ordinal == wanted) {
            const plane = if (i == 0) 0 else 1 + (i - 1) / 2;
            const denominator = try self.relations.get(domain).combineSecure(values);
            if (i == 0 or i % 2 == 1) {
                self.out[plane].wl = numerator;
                self.out[plane].left = denominator;
            } else {
                self.out[plane].wr = numerator;
                self.out[plane].right = denominator;
            }
            self.found += 1;
        };
    }
};
/// These three independently closed buses remain distinct in public metadata.
pub fn totals(sums: [4]Q) [3]Q {
    return .{ sums[0], sums[1], sums[2].add(sums[3]) };
}

test "SHA control projection authenticates complete original event selection" {
    const owner = try Owner.init(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &Caller.SEMANTIC_DIGEST, &owner.plan.semantic_digest);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 8, 9, 16, 17 }, &owner.selected);
}
