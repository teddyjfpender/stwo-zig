//! Literal original-coordinate/equation fixtures. No child proof is fabricated,
//! cryptographically admitted, generated, or accepted by these tests.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Raw = @import("../recursion/air/block_v5_global_join_source_values_v1.zig");
const S = @import("../recursion/block_v5_global_join_semantic_plan_v1.zig");
const F = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Lookup = @import("block_v5_native_lookup_plan_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const byte_kind = @intFromEnum(Schema.Kind.range_check_8_8);
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn encodeCell(word: u32) [4]M {
    var out: [4]M = undefined;
    for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    return out;
}
const Decoder = struct {
    claims: [1]Q,
    words: [5]u32,
    frames: [2]F.Frame,
    cells: [9][4]M,
    views: [2]Raw.View,
    fn init(self: *@This()) void {
        self.claims = .{Q.fromM31Array(.{ M.fromCanonical(0x7eff1234), M.fromCanonical(0x018080ff), M.fromCanonical(0x7ffffffd), M.fromCanonical(0x10203040) })};
        self.refresh();
    }
    fn refresh(self: *@This()) void {
        const limbs = self.claims[0].toM31Array();
        self.words = .{ limbs[2].v, 999, limbs[0].v, limbs[3].v, limbs[1].v };
        for (self.words, self.cells[0..5]) |word, *cell| cell.* = encodeCell(word);
        for (limbs, self.cells[5..]) |word, *cell| cell.* = encodeCell(word.v);
        self.frames = .{ .{ .first = 0, .operation = .{ .words = &self.words } }, .{ .first = 5, .operation = .{ .felts = &self.claims } } };
        self.views = @splat(.{ .frames = &self.frames, .cells = &self.cells });
    }
    fn fields() [2]Raw.Field {
        return .{ .{ .child = 0, .form = .{ .words = .{ .{ .frame = 0, .word = 2 }, .{ .frame = 0, .word = 4 }, .{ .frame = 0, .word = 0 }, .{ .frame = 0, .word = 3 } } } }, .{ .child = 1, .form = .{ .felt = .{ .frame = 1, .index = 0 } } } };
    }
};
const Equal = struct {
    pub fn record(_: @This(), _: std.mem.Allocator, builder: *R.Builder, claims: []const R.Scalar) !void {
        if (claims.len != 2) return error.InvalidTestConstraintCount;
        const difference = claims[0].sub(claims[1]);
        if (builder.failure) |err| return err;
        try builder.constrainZero(difference);
    }
};
test "global semantic mapping: four original word limbs and felt cells have identical extension value" {
    var fixture: Decoder = undefined;
    fixture.init();
    const fields = Decoder.fields();
    const left = try Raw.read(&fixture.views, fields[0]);
    const right = try Raw.read(&fixture.views, fields[1]);
    try std.testing.expect(left.value.eql(fixture.claims[0]) and left.value.eql(right.value));
    for (left.sources, left.inputs, 0..) |source, input, index| {
        try std.testing.expectEqual(@as(u32, 0), source.child);
        try std.testing.expectEqual(@as(u2, @intCast(index % 4)), source.part);
        try std.testing.expect(input.eql(Q.fromBase(fixture.cells[source.cell][source.part])));
    }
    for (right.sources) |source| try std.testing.expectEqual(@as(u32, 1), source.child);
    var recorded = try Raw.record(std.testing.allocator, &fixture.views, &fields, Equal{}, 8 << 20);
    defer recorded.deinit();
    try std.testing.expectEqual(@as(usize, 32), recorded.inputs.len);
    try std.testing.expectEqual(@as(usize, 32), recorded.sources.len);
}
test "global semantic mapping: malformed limbs bytes and unrelated zero coordinates fail closed" {
    var fixture: Decoder = undefined;
    fixture.init();
    const fields = Decoder.fields();
    fixture.words[2] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalGlobalJoinSource, Raw.read(&fixture.views, fields[0]));
    fixture.refresh();
    fixture.cells[2][3] = fixture.cells[2][3].add(M.one());
    try std.testing.expectError(error.MutatedGlobalJoinSource, Raw.read(&fixture.views, fields[0]));
    fixture.refresh();
    var bad = fields[0];
    bad.form.words[0].frame = 1;
    try std.testing.expectError(error.InvalidGlobalJoinSource, Raw.read(&fixture.views, bad));
    bad = fields[1];
    bad.form.felt.index = 1;
    try std.testing.expectError(error.InvalidGlobalJoinSource, Raw.read(&fixture.views, bad));
    bad = fields[0];
    bad.child = 2;
    try std.testing.expectError(error.InvalidGlobalJoinSource, Raw.read(&fixture.views, bad));
    fixture.words[2] = 0;
    fixture.cells[2] = encodeCell(0);
    // It is an authentic changed word, but is not the original expected claim.
    try std.testing.expectError(error.UnsatisfiedCircuit, Raw.record(std.testing.allocator, &fixture.views, &fields, Equal{}, 8 << 20));
    try std.testing.expectError(error.GlobalJoinResourceLimit, Raw.record(std.testing.allocator, &fixture.views, &fields, Equal{}, 0));
}
fn decoderConstruction(a: std.mem.Allocator) !void {
    var fixture: Decoder = undefined;
    fixture.init();
    const fields = Decoder.fields();
    var recorded = try Raw.record(a, &fixture.views, &fields, Equal{}, 8 << 20);
    defer recorded.deinit();
}
test "global semantic mapping: decoder equation construction preserves original allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decoderConstruction, .{});
}
const count = 12;
const Inventory = struct {
    claims: [count]Q,
    cells: [4 * count][4]M,
    frames: [1]F.Frame,
    views: [1]Raw.View,
    exports: [count]S.Export,
    fields: [count]Raw.Field,
    groups: [1]Lookup.Plan,
    obligations: [1]S.Obligation,
    seals: [1][32]u8,
    derived: S.Derived,
    fn init(self: *@This(), a: std.mem.Allocator) !void {
        const budget = try Budget.create(a, 8 << 20);
        self.claims = .{ q(3), q(3).neg(), q(17), q(17).neg(), q(11), q(11).neg(), q(7), q(7).neg(), q(101), q(103), q(107), q(109) };
        const roles: [count]S.Role = .{ .native_compensation, .native_state, .table_request, .table_provider, .byte_request, .table_provider, .transition_request, .ram_transition, .native_open, .program_provider, .ram_initial, .caller_open };
        for (&self.exports, &self.fields, roles, 0..) |*entry, *field, role, index| {
            field.* = .{ .child = 0, .form = .{ .felt = .{ .frame = 0, .index = @intCast(index) } } };
            entry.* = .{ .role = role, .owner = 0, .slot = @intCast(index), .coordinate = if (index == 5) byte_kind else 0, .field = field.* };
        }
        self.groups = .{.{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) }};
        self.obligations = .{.{ .kind = .complete_source_proof, .index = 0, .identity = @splat(1), .count = 1 }};
        self.seals = @splat(@splat(2));
        self.derived = .{ .budget = budget, .arena = std.heap.ArenaAllocator.init(budget.allocator()), .exports = &self.exports, .obligations = &self.obligations, .groups = &self.groups, .execution_count = 1, .coverage = @splat(3), .child_seals = &self.seals, .limits = .{}, .seal = undefined };
        self.refresh();
        self.reseal();
    }
    fn refresh(self: *@This()) void {
        for (self.claims, 0..) |claim, index| {
            for (claim.toM31Array(), self.cells[4 * index ..][0..4]) |word, *cell| cell.* = encodeCell(word.v);
        }
        self.frames = .{.{ .first = 0, .operation = .{ .felts = &self.claims } }};
        self.views = .{.{ .frames = &self.frames, .cells = &self.cells }};
    }
    fn reseal(self: *@This()) void {
        self.derived.seal = self.derived.identity();
    }
    fn record(self: *@This(), a: std.mem.Allocator) !Raw.Prepared {
        return S.testing.recordSubset(a, &self.views, &self.fields, &self.derived, 16 << 20);
    }
};
test "global semantic mapping: exact exported subset binds original scope and remains open" {
    var fixture: Inventory = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.derived.deinit();
    var recorded = try fixture.record(std.testing.allocator);
    defer recorded.deinit();
    for (recorded.sources, recorded.inputs) |source, input| try std.testing.expect(input.eql(Q.fromBase(fixture.cells[source.cell][source.part])));
    try std.testing.expect(!S.Derived.complete_block_authority);
    try std.testing.expectError(error.MissingAuthenticatedGlobalJoinObligations, fixture.derived.requireComplete());
    fixture.derived.obligations = &.{};
    fixture.reseal();
    try std.testing.expectError(error.GlobalJoinCompleteAuthorityUnavailable, fixture.derived.requireComplete());
}
test "global semantic mapping: each execution group kind and byte partition closes separately" {
    var fixture: Inventory = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.derived.deinit();
    fixture.exports[1].owner = 1;
    fixture.derived.execution_count = 2;
    fixture.reseal();
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    fixture.exports[1].owner = 0;
    fixture.derived.execution_count = 1;
    fixture.exports[3].coordinate = 1;
    fixture.reseal();
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    fixture.exports[3].coordinate = 0;
    fixture.exports[3].owner = 1;
    fixture.reseal();
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    fixture.exports[3].owner = 0;
    fixture.reseal();
    fixture.claims[4] = fixture.claims[4].add(Q.one());
    fixture.refresh();
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
}
test "global semantic mapping: every semantic mapping and obligation mutation invalidates derivation" {
    var fixture: Inventory = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.derived.deinit();
    const original = fixture.exports[0];
    fixture.exports[0].role = .ram_link;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.derived.validateIntegrity());
    fixture.exports[0] = original;
    fixture.exports[0].slot += 1;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.derived.validateIntegrity());
    fixture.exports[0] = original;
    fixture.exports[0].field.form.felt.index += 1;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.record(std.testing.allocator));
    fixture.exports[0] = original;
    fixture.obligations[0].count += 1;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.derived.requireComplete());
    fixture.obligations[0].count -= 1;
    fixture.groups[0].first_execution += 1;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.derived.validateIntegrity());
    fixture.groups[0].first_execution -= 1;
    fixture.seals[0][0] ^= 1;
    try std.testing.expectError(error.MutatedGlobalJoinSemanticPlan, fixture.derived.validateIntegrity());
    fixture.seals[0][0] ^= 1;
    try fixture.derived.validateIntegrity();
}
fn subsetConstruction(a: std.mem.Allocator) !void {
    var fixture: Inventory = undefined;
    try fixture.init(a);
    defer fixture.derived.deinit();
    var recorded = try fixture.record(a);
    defer recorded.deinit();
}
test "global semantic mapping: derived subset allocation failures release both bounded owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, subsetConstruction, .{});
}

test "global semantic mapping: re-sealing arbitrary selectors does not match independently derived recipe" {
    var expected: Inventory = undefined;
    try expected.init(std.testing.allocator);
    defer expected.derived.deinit();
    var received: Inventory = undefined;
    try received.init(std.testing.allocator);
    defer received.derived.deinit();
    try S.testing.requireIndependentDerivation(&received.derived, &expected.derived);
    received.exports[0].field.form.felt.index = 8;
    received.reseal();
    try received.derived.validateIntegrity();
    try std.testing.expectError(error.UntrustedGlobalJoinSemanticPlan, S.testing.requireIndependentDerivation(&received.derived, &expected.derived));
    received.exports[0] = expected.exports[0];
    received.derived.obligations = &.{};
    received.reseal();
    try std.testing.expectError(error.UntrustedGlobalJoinSemanticPlan, S.testing.requireIndependentDerivation(&received.derived, &expected.derived));
}
// Deliberately invalid key/seal metadata, for ordinal layout selection only.
// It must never enter a positive child-verifier or parent admission path.
fn metadataChild(a: std.mem.Allocator, frames: []const F.Frame, cells: []const [4]M) F.Child {
    const B = @import("../recursion/blake3_execution_parent_protocol.zig");
    return .{
        .arena = std.heap.ArenaAllocator.init(a),
        .physical = .{ .kind = .native_fused, .subtype = .capacity_fused_v1, .index = 0, .logical = .{ 0, 1 }, .logical_count = 2, .instance_id = @splat(0), .roots = @splat(@splat(0)) },
        .recipe = .custody_v2,
        .source_seal = @splat(1),
        .key = .{ .context = .{ .child_key_id = @splat(0), .child_config = B.PCS_CONFIG, .graph_ids = @splat(@splat(0)), .transcript_plan_id = @splat(0) }, .log_sizes = @splat(1), .preprocessed_root = @splat(0) },
        .expected_id = @splat(0),
        .public_input_digest = @splat(0),
        .claim_frame = @splat(0),
        .frames = frames,
        .cells = cells,
        .terms = &.{},
        .span = null,
        .link = null,
        .seal = @splat(0),
    };
}
test "global semantic mapping: identical zero payloads cannot change normative slot ordinal" {
    const values = [_]Q{ Q.zero(), Q.zero() };
    const frames = [_]F.Frame{
        .{ .first = 0, .operation = .{ .felts = &values } }, // original PCS config invocation
        .{ .first = 8, .operation = .{ .felts = &values } }, // actual typed statement claims
        .{ .first = 16, .operation = .{ .felts = &values } }, // quotient public-input vector
    };
    const cells: [24][4]M = @splat(@splat(M.zero()));
    var child = metadataChild(std.testing.allocator, &frames, &cells);
    defer child.deinit();
    try std.testing.expectError(error.InvalidHeterogeneousChild, child.validate());
    try std.testing.expectEqual(@as(u32, 1), try S.testing.ordinalFeltFrame(&child, 1, 2));
    try std.testing.expectError(error.UntrustedGlobalJoinTypedLayout, S.testing.ordinalFeltFrame(&child, 1, 1));
    try std.testing.expectError(error.UntrustedGlobalJoinTypedLayout, S.testing.ordinalFeltFrame(&child, 3, null));
}
