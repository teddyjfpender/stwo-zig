//! Fixed-only ORIGINAL nested public coordinate unpacking. The same four
//! leading DAG inputs, scalar weights and pack schedules as attachTerms;
//! coordinates remain MAIN/public inputs and never enter fixed metadata.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Storage = @import("blake3_parent_row_storage.zig");
const Fixed = @import("block_v5_recursive_fixed_port_rows_v1.zig").ForSlots(.{ 12, 11 });
const Scalar = @import("scalar_wire_source.zig");
const Pack = @import("qm31_pack_wire.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const Term = @import("../block_v5_open_child_frames_v2.zig").Term;
pub const CIRCUIT = @import("block_v5_open_parent_packed_sources_v2.zig").CIRCUIT;
pub const Limits = struct { max_terms: usize = 16 << 20 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    rows: Fixed,
    nodes: [][4]u32,
    graph_identity: [32]u8,
    term_recipe: [32]u8,
    pub const complete_fixed_setup = false;
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, composition: anytype, terms: []const Term, limits: Limits) !Owned {
        if (limits.max_terms == 0 or terms.len > limits.max_terms or terms.len > std.math.maxInt(u32) / 4) return error.RequesterPackedFixedResourceLimit;
        try composition.circuit.validate();
        if (composition.sources.len != composition.circuit.input_count) return error.InvalidV5NestedPackedSource;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const nodes = try a.alloc([4]u32, terms.len);
        errdefer a.free(nodes);
        const seen = try a.alloc([4]bool, terms.len);
        defer a.free(seen);
        @memset(seen, @splat(false));
        const scalar_count = try std.math.mul(usize, terms.len, 4);
        for (composition.sources, 0..) |source, node| switch (source) {
            .packed_public_input => |index| {
                if (index >= scalar_count or seen[index / 4][index % 4]) return error.InvalidV5NestedPackedSource;
                seen[index / 4][index % 4] = true;
                nodes[index / 4][index % 4] = std.math.cast(u32, node) orelse return error.RequesterPackedFixedResourceLimit;
            },
            .public_input => return error.UnexpectedScopedChildSpanInput,
            else => {},
        };
        const scratch = try a.alloc(u32, composition.circuit.nodes.len);
        defer a.free(scratch);
        const uses = try Lower.computeUseCountsInto(composition.circuit.graph(), scratch);
        var rows = try Fixed.init(a, .{ scalar_count, terms.len });
        errdefer rows.deinit();
        for (terms, nodes, seen, 0..) |term, tuple, found, index| {
            // Same independent source bounds used by the original public bus.
            if (term.circuit >= core.fields.m31.Modulus or term.wire >= core.fields.m31.Modulus or term.uses == 0 or term.uses >= core.fields.m31.Modulus) return error.InvalidV5NestedPackedSource;
            for (term.coordinates) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.InvalidV5NestedPackedSource;
            for (found) |present| if (!present) return error.MissingV5NestedPackedSource;
            for (tuple) |node| {
                const weight = try std.math.add(u32, uses[node], 1);
                if (weight >= core.fields.m31.Modulus) return error.RequesterPackedFixedResourceLimit;
                try rows.appendLogicalFixed(12, try Scalar.logicalRow(1500, node, weight, M.zero()));
            }
            try rows.appendLogicalFixed(11, try Pack.fixedRow(.{ .source_circuit = 1500, .source_nodes = tuple, .destination_circuit = CIRCUIT, .destination_wire = std.math.cast(u32, index) orelse return error.RequesterPackedFixedResourceLimit }));
        }
        try rows.finish();
        return .{ .allocator = a, .lease = lease, .rows = rows, .nodes = nodes, .graph_identity = composition.circuit.identity_digest, .term_recipe = recipe(terms) };
    }
    /// Pure original primitive parity, never a successful verifier token.
    pub fn validateAgainst(self: *const Owned, composition: anytype, terms: []const Term, limits: Limits) !void {
        var expected = try Owned.init(self.allocator, composition, terms, limits);
        defer expected.deinit();
        if (!std.meta.eql(self.graph_identity, expected.graph_identity) or !std.meta.eql(self.term_recipe, expected.term_recipe) or self.nodes.len != expected.nodes.len) return error.UntrustedRequesterPackedFixedSource;
        for (self.nodes, expected.nodes) |actual, independent| if (!std.meta.eql(actual, independent)) return error.UntrustedRequesterPackedFixedSource;
        inline for (.{ 12, 11 }) |slot| {
            const actual = try self.rows.metadata(slot);
            const independent = try expected.rows.metadata(slot);
            if (actual.len != independent.len) return error.UntrustedRequesterPackedFixedSource;
            for (actual, independent) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPackedFixedSource;
        }
    }
    pub fn requireComplete(_: *const Owned) error{MissingRequesterFixedFamilyPorts}!void {
        return error.MissingRequesterFixedFamilyPorts;
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.lease;
        self.rows.deinit();
        self.allocator.free(self.nodes);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
fn recipe(terms: []const Term) [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x52515046, 1, CIRCUIT, @intCast(terms.len) });
    for (terms) |term| channel.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
    return channel.digestBytes();
}
pub fn scalarRows(self: *const Owned) ![]const Storage.FixedRow(Storage.Airs[12]) {
    return self.rows.metadata(12);
}
pub fn packRows(self: *const Owned) ![]const Storage.FixedRow(Storage.Airs[11]) {
    return self.rows.metadata(11);
}
