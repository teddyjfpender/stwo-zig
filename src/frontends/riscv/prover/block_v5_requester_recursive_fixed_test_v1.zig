//! Nonproving original packed-row/compiler checks, no fake capture or key.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Packed = @import("../recursion/air/block_v5_requester_recursive_packed_fixed_v1.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Sources = @import("../recursion/air/blake3_execution_composition.zig").Source;
const Scalar = @import("../recursion/air/scalar_wire_source.zig");
const Pack = @import("../recursion/air/qm31_pack_wire.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Term = @import("../recursion/block_v5_open_child_frames_v2.zig").Term;
const Requester = @import("../recursion/block_v5_requester_recursive_shape_admission_v1.zig");
const Public = @import("../recursion/block_v5_requester_public_recursive_shape_admission_v1.zig");
const Fixture = struct {
    circuit: R.Circuit,
    sources: [4]Sources = .{ .{ .packed_public_input = 0 }, .{ .packed_public_input = 1 }, .{ .packed_public_input = 2 }, .{ .packed_public_input = 3 } },
    terms: [1]Term = .{.{ .circuit = 11, .wire = 7, .uses = 3, .negative = true, .coordinates = .{ M.one(), M.fromCanonical(6), M.fromCanonical(2), M.fromCanonical(4) } }},
    fn init(a: std.mem.Allocator) !Fixture {
        var builder = R.Builder.init(a);
        defer builder.deinit();
        var symbols: [4]R.Scalar = undefined;
        for (&symbols) |*symbol| symbol.* = (try builder.input()).value;
        try builder.activate();
        defer if (builder.active) builder.deactivate();
        try builder.constrainZero(symbols[0].mul(symbols[1]).sub(symbols[2].add(symbols[3])));
        builder.deactivate();
        return .{ .circuit = try builder.finish() };
    }
    fn composition(self: *const Fixture) struct { circuit: R.Circuit, sources: []const Sources } {
        return .{ .circuit = self.circuit, .sources = &self.sources };
    }
};
test "requester fixed ports: exact original scalar weights and four-coordinate pack schedules" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    var fixed = try Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{});
    defer fixed.deinit();
    const counts = try std.testing.allocator.alloc(u32, fixture.circuit.nodes.len);
    defer std.testing.allocator.free(counts);
    const uses = try Lower.computeUseCountsInto(fixture.circuit.graph(), counts);
    const rows = try fixed.rows.metadata(12);
    for (rows, 0..) |actual, node| {
        const expected = Storage.compactFixed(Storage.Airs[12], try Scalar.logicalRow(1500, @intCast(node), uses[node] + 1, fixture.terms[0].coordinates[node]));
        try std.testing.expectEqualDeep(expected, actual);
    }
    const packs = try fixed.rows.metadata(11);
    const expected_pack = Storage.compactFixed(Storage.Airs[11], try Pack.logicalRow(.{ .source_circuit = 1500, .source_nodes = .{ 0, 1, 2, 3 }, .destination_circuit = Packed.CIRCUIT, .destination_wire = 0 }, core.fields.qm31.QM31.fromM31Array(fixture.terms[0].coordinates)));
    try std.testing.expectEqualDeep(expected_pack, packs[0]);
    try fixed.validateAgainst(fixture.composition(), &fixture.terms, .{});
}
test "requester fixed ports: duplicate missing excess and unsupported span inputs reject" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    fixture.sources[1] = .{ .packed_public_input = 0 };
    try std.testing.expectError(error.InvalidV5NestedPackedSource, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
    fixture.sources[1] = .{ .sample = 0 };
    try std.testing.expectError(error.MissingV5NestedPackedSource, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
    fixture.sources[1] = .{ .packed_public_input = 4 };
    try std.testing.expectError(error.InvalidV5NestedPackedSource, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
    fixture.sources[1] = .{ .public_input = 0 };
    try std.testing.expectError(error.UnexpectedScopedChildSpanInput, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
}
test "requester fixed ports: independent term caps and canonical coordinate bounds fail closed" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    try std.testing.expectError(error.RequesterPackedFixedResourceLimit, Packed.Owned.init(std.testing.failing_allocator, fixture.composition(), &fixture.terms, .{ .max_terms = 0 }));
    fixture.terms[0].uses = 0;
    try std.testing.expectError(error.InvalidV5NestedPackedSource, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
    fixture.terms[0].uses = 1;
    // Raw corrupt field, without violating a canonical constructor contract.
    fixture.terms[0].coordinates[0].v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidV5NestedPackedSource, Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{}));
}
test "requester fixed ports: changed tuple assignments do not enter fixed rows but changed routing rejects" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    var fixed = try Packed.Owned.init(std.testing.allocator, fixture.composition(), &fixture.terms, .{});
    defer fixed.deinit();
    fixture.terms[0].coordinates = @splat(M.fromCanonical(8));
    try fixed.validateAgainst(fixture.composition(), &fixture.terms, .{});
    fixture.terms[0].negative = false;
    try std.testing.expectError(error.UntrustedRequesterPackedFixedSource, fixed.validateAgainst(fixture.composition(), &fixture.terms, .{}));
    fixture.terms[0].negative = true;
    const rows = @constCast(try fixed.rows.metadata(12));
    rows[0][0] = rows[0][0].add(M.one());
    try std.testing.expectError(error.UntrustedRequesterPackedFixedSource, fixed.validateAgainst(fixture.composition(), &fixture.terms, .{}));
    try std.testing.expectError(error.MissingRequesterFixedFamilyPorts, fixed.requireComplete());
}
fn allocation(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var fixed = try Packed.Owned.init(a, fixture.composition(), &fixture.terms, .{});
    defer fixed.deinit();
    try std.testing.expectEqual(@as(usize, 4), (try fixed.rows.metadata(12)).len);
    try std.testing.expectEqual(@as(usize, 1), (try fixed.rows.metadata(11)).len);
}
test "requester fixed ports: upstream original graph outside injected allocation and all port failures release" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    try allocation(std.testing.allocator, &fixture);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocation, .{&fixture});
}
test "requester fixed ports: setup-only admissions cannot satisfy live verifier authority methods" {
    inline for (.{ Requester.Admission, Public.Admission }) |Admission| {
        try std.testing.expect(Admission.fixed_setup_only);
        try std.testing.expect(!@hasDecl(Admission, "admitRoot"));
        try std.testing.expect(!@hasDecl(Admission, "mixClaims"));
        try std.testing.expect(!@hasDecl(Admission, "validateClaimsForRelations"));
        try std.testing.expect(!@hasField(Admission, "expected_id"));
    }
    try std.testing.expect(!Packed.Owned.complete_fixed_setup);
    try std.testing.expect(!Packed.Owned.complete_block_authority);
}
test "requester fixed ports: original child supplier collector preserves byte reads and negative packed consumption" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    const T = @import("../recursion/air/blake3_transcript_witness.zig");
    const roots = [_]T.RootReads{.{ .operation = 0, .source = .{ .circuit = Requester.PUBLIC_CIRCUIT, .first_wire = 7 }, .uses = .{ 2, 0, 1, 0, 0, 0, 0, 0 } }};
    const payloads = [_]T.PayloadReads{.{ .operation = 1, .source = .{ .circuit = Requester.PUBLIC_CIRCUIT, .first_wire = 20 }, .uses = &.{ 0, 3 } }};
    const fixed = .{ .root_reads = &roots, .payload_reads = &payloads };
    const collect = @import("../recursion/air/block_v5_recursive_fixed_child_suppliers_v1.zig").collect;
    const wires = try collect(std.testing.allocator, fixed, fixture.composition(), fixture.terms.len, 3, Requester.PUBLIC_CIRCUIT);
    defer std.testing.allocator.free(wires);
    try std.testing.expectEqual(@as(usize, 4), wires.len);
    try std.testing.expectEqual(@as(u32, 7), wires[0].coordinate);
    try std.testing.expectEqual(@as(u32, 2), wires[0].uses);
    try std.testing.expectEqual(@as(u32, 9), wires[1].coordinate);
    try std.testing.expectEqual(@as(u32, 21), wires[2].coordinate);
    try std.testing.expectEqual(@as(u32, 3), wires[2].uses);
    try std.testing.expect(wires[3].kind == .child_term and wires[3].negative);
    try std.testing.expectEqual(@as(u32, 1), wires[3].uses);
    try std.testing.expectEqual(@as(u32, 0), wires[3].coordinate);
    for (wires) |wire| try std.testing.expectEqual(@as(u32, 3), wire.child);
    try std.testing.expectError(error.InvalidRecursiveFixedChildCount, collect(std.testing.failing_allocator, fixed, fixture.composition(), 1, 4, Requester.PUBLIC_CIRCUIT));
}
test "requester fixed ports: nested fixed allocations retain creator budget until final free" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.circuit.deinit();
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(std.testing.allocator, 1 << 20);
    var live = true;
    defer if (live) budget.destroy();
    var fixed = try Packed.Owned.init(budget.allocator(), fixture.composition(), &fixture.terms, .{});
    defer fixed.deinit();
    budget.destroy();
    live = false;
    try std.testing.expectEqual(@as(usize, 4), (try fixed.rows.metadata(12)).len);
    try fixed.validateAgainst(fixture.composition(), &fixture.terms, .{});
}
test "requester fixed ports: setup recorder admits 67 and 4096 roots with exact original no-offset grammar" {
    const Sink = @import("../recursion/air/blake3_fixed_operation_recorder_v1.zig");
    const Frames = @import("../recursion/air/block_v5_recursive_statement_frames_v1.zig");
    const NativeRecorder = @import("../recursion/air/blake3_native_recorder.zig");
    for ([_]usize{ 67, 4096 }) |count| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var sink = Sink.Recorder{ .a = arena.allocator(), .limits = .{} };
        var original = Frames.Builder{ .allocator = arena.allocator(), .track_root_offsets = false };
        defer original.deinit();
        original.mixU32s(&.{ 7, 11 });
        for (0..count) |index| {
            original.mixRoot(@splat(@truncate(index)));
            // PUBLIC21 actually interleaves felt frames and later raw words.
            // All felt source coordinates still begin after ALL raw words.
            original.mixFelts(&.{core.fields.qm31.QM31.one()});
            original.mixU32s(&.{ @intCast(index), 13 });
        }
        original.mixFelts(&.{core.fields.qm31.QM31.one()});
        try original.check();
        const frame = Frames.Statement{ .allocator = arena.allocator(), .words = original.data.items, .felts = original.fields.items, .first = original.steps.items, .claims = &.{}, .sealed_offset = 0, .roots_offset = @splat(0) };
        try frame.recordAt(&sink, frame.first, Public.PUBLIC_CIRCUIT);
        try std.testing.expectEqual(count, original.root_count);
        try std.testing.expectEqual(frame.first.len, sink.operations.items.len);
        for (sink.operations.items, frame.first) |operation, step| switch (step) {
            .words => |span| {
                try std.testing.expect(operation == .routed_words);
                try std.testing.expectEqual(span.first, operation.routed_words.source.first_wire);
                try std.testing.expectEqual(Public.PUBLIC_CIRCUIT, operation.routed_words.source.circuit);
            },
            .root => |first| {
                try std.testing.expect(operation == .routed_root);
                try std.testing.expectEqual(first, operation.routed_root.source.first_wire);
                try std.testing.expectEqual(Public.PUBLIC_CIRCUIT, operation.routed_root.source.circuit);
                try std.testing.expectEqual(@as([32]u8, @splat(0)), operation.routed_root.value);
            },
            .felts => |span| {
                try std.testing.expect(operation == .routed_felts);
                try std.testing.expectEqual(@as(u32, @intCast(frame.words.len + 4 * span.first)), operation.routed_felts.source.first_wire);
                try std.testing.expectEqual(Public.PUBLIC_CIRCUIT, operation.routed_felts.source.circuit);
                for (operation.routed_felts.values) |value| try std.testing.expect(value.isZero());
            },
            .integer => return error.UnexpectedIntegerFixture,
        };
        try std.testing.expectEqual(frame.words.len + 4 * frame.felts.len, sink.routed_words);
        const first_felt = sink.operations.items[2];
        const later_words = sink.operations.items[3];
        try std.testing.expect(first_felt.routed_felts.source.first_wire > later_words.routed_words.source.first_wire);
        var live = NativeRecorder.Recorder{ .a = arena.allocator() };
        try frame.recordAt(&live, frame.first, Public.PUBLIC_CIRCUIT);
        var expected = core.channel.blake3.Channel{};
        try frame.replay(&expected, frame.first);
        try std.testing.expectEqualDeep(expected.digestBytes(), live.native.digestBytes());
    }
}
