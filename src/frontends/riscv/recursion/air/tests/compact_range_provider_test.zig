const std = @import("std");
const core = @import("stwo_core");
const provider = @import("../compact_range_provider.zig");
const schema = @import("../../../air/lookups/tables/schema.zig");
const M = core.fields.m31.M31;
const kinds = .{ schema.Kind.range_check_20, schema.Kind.range_check_8_11, schema.Kind.range_check_8_8_4 };
test "compact range provider semantic identities" {
    var valid = true;
    inline for (kinds) |kind| {
        const Air = provider.Provider(kind);
        const digest = try Air.computeSemanticDigest(std.testing.allocator);
        if (!std.mem.eql(u8, &digest, &Air.SEMANTIC_DIGEST)) {
            std.debug.print("COMPACT_RANGE_{s}={s}\n", .{ @tagName(kind), std.fmt.bytesToHex(digest, .lower) });
            valid = false;
        }
    }
    try std.testing.expect(valid);
}
test "compact range provider constraints signed relations and adversarial limbs" {
    const a = std.testing.allocator;
    inline for (kinds) |kind| {
        const Air = provider.Provider(kind);
        var d = try Air.build(a);
        defer d.deinit();
        const binding = try @import("../universal_relation_binding.zig").Binding(Air).authenticate(&d);
        const direct = try @import("../direct_constraint_program.zig").authenticate(&d.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        var exported = try @import("../framework_polynomial_export_v1.zig").exportLocalPrepared(Air, a, &direct, &binding);
        defer exported.deinit();
        for ([_]usize{ 0, 1, 255, 256, schema.size(kind) - 1 }) |index| {
            const tuple = try schema.tupleAt(kind, index);
            for ([_]M{ M.zero(), M.one(), M.one().neg(), M.fromCanonical(12345) }) |multiplicity| {
                const row = try Air.logicalRow(tuple.slice(), multiplicity);
                try std.testing.expect(try satisfied(&d.arena, &row));
                const entries = binding.preparedEntries(row);
                try std.testing.expectEqualStrings(@tagName(schema.domain(kind)), @tagName(entries[0].domain));
                try std.testing.expectEqual(multiplicity.neg(), try entries[0].numerator.tryIntoM31());
                for (entries[0].values[0..tuple.len], tuple.slice()) |actual, expected| try std.testing.expectEqual(expected, try actual.tryIntoM31());
                _ = try schema.indexSecure(.range_check_8_8, entries[1].values[0..2]);
                try std.testing.expectEqual(M.one().neg(), try entries[1].numerator.tryIntoM31());
                for (0..Air.high_bits) |bit| {
                    var bad = row;
                    bad[Air.bit_start + bit] = M.fromCanonical(2);
                    try std.testing.expect(!try satisfied(&d.arena, &bad));
                }
                var bad = row;
                bad[if (kind == .range_check_20) 0 else if (kind == .range_check_8_11) 1 else 2] = bad[if (kind == .range_check_20) 0 else if (kind == .range_check_8_11) 1 else 2].add(M.one());
                try std.testing.expect(!try satisfied(&d.arena, &bad));
            }
        }
        const padded: Air.Row = @splat(M.zero());
        try std.testing.expect(try satisfied(&d.arena, &padded));
        const padding_entries = binding.preparedEntries(padded);
        try std.testing.expect(padding_entries[0].numerator.isZero());
        try std.testing.expectEqual(M.one().neg(), try padding_entries[1].numerator.tryIntoM31());
        var invalid = (try schema.tupleAt(kind, schema.size(kind) - 1));
        invalid.values[0] = M.fromCanonical(if (kind == .range_check_20) 1 << 20 else 256);
        try std.testing.expectError(error.ValueOutOfRange, Air.logicalRow(invalid.slice(), M.one()));
        // Direct equations alone must not be mistaken for byte membership.
        var forged = padded;
        forged[if (kind == .range_check_20) 1 else 0] = M.fromCanonical(256);
        if (kind == .range_check_20) forged[0] = M.fromCanonical(256);
        try std.testing.expect(try satisfied(&d.arena, &forged));
        const forged_entries = binding.preparedEntries(forged);
        try std.testing.expectError(error.ValueOutOfRange, schema.indexSecure(.range_check_8_8, forged_entries[1].values[0..2]));
    }
}
fn satisfied(arena: *const @import("../../../air/lang/ir.zig").Arena, row: []const M) !bool {
    const a = std.testing.allocator;
    const values = try @import("../test_support.zig").evaluateArena(a, arena, row);
    defer a.free(values);
    for (arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/types.zig").idIndex(constraint.root)].isZero()) return false;
    return true;
}

test "compact range provider direct final layout and padding byte census" {
    const a = std.testing.allocator;
    inline for (kinds) |kind| {
        const Air = provider.Provider(kind);
        var counter = try @import("../../../air/lookups/tables/counter.zig").Counter.init(a, kind);
        defer counter.deinit(a);
        counter.values[1] = M.one();
        counter.values[257] = M.one().neg();
        counter.values[counter.values.len - 1] = M.fromCanonical(42);
        var witness = try @import("../compact_range_witness.zig").Owner(kind).init(a, &counter);
        defer witness.deinit();
        try std.testing.expectEqual(@as(usize, 3), witness.n_rows);
        try std.testing.expectEqual(@as(u32, 4), witness.log_size);
        var d = try Air.build(a);
        defer d.deinit();
        const binding = try @import("../universal_relation_binding.zig").Binding(Air).authenticate(&d);
        var expected = try @import("../../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
        defer expected.deinit(a);
        for (0..16) |logical| {
            const dst = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, 4), 4);
            var row: Air.Row = undefined;
            for (&row, witness.columns) |*value, column| value.* = column[dst];
            try std.testing.expect(try satisfied(&d.arena, &row));
            const entries = binding.preparedEntries(row);
            const index = try schema.indexSecure(.range_check_8_8, entries[1].values[0..2]);
            expected.values[index] = expected.values[index].add(try entries[1].numerator.tryIntoM31());
            if (logical < 3) {
                const source = ([_]usize{ 1, 257, schema.size(kind) - 1 })[logical];
                const tuple = try schema.tupleAt(kind, source);
                try std.testing.expectEqualSlices(M, tuple.slice(), row[0..Air.tuple_len]);
                try std.testing.expectEqual(counter.values[source], row[Air.multiplicity_index]);
            } else try std.testing.expectEqualSlices(M, &@as(Air.Row, @splat(M.zero())), &row);
        }
        try std.testing.expectEqualSlices(M, expected.values, witness.byte_counts);
        @memset(counter.values, M.zero());
        var empty = try @import("../compact_range_witness.zig").Owner(kind).init(a, &counter);
        defer empty.deinit();
        try std.testing.expectEqual(@as(usize, 0), empty.n_rows);
        try std.testing.expectEqual(M.fromCanonical(16).neg(), empty.byte_counts[0]);
        try std.testing.expectEqualSlices(M, &@as([16]M, @splat(M.zero())), empty.columns[Air.multiplicity_index]);
    }
}

test "compact range provider allocation failures release owned buffers" {
    inline for (kinds) |kind| {
        const Harness = struct {
            fn run(a: std.mem.Allocator) !void {
                var counter = try @import("../../../air/lookups/tables/counter.zig").Counter.init(a, kind);
                defer counter.deinit(a);
                counter.values[0] = M.one();
                var witness = try @import("../compact_range_witness.zig").Owner(kind).init(a, &counter);
                defer witness.deinit();
                try std.testing.expectEqual(M.one(), counter.values[0]);
            }
        };
        try std.testing.checkAllAllocationFailures(std.testing.allocator, Harness.run, .{});
    }
}

test "compact range provider canonical geometry identity and term admission" {
    const geometry = @import("../compact_range_geometry.zig");
    const plan = try geometry.Plan.canonical(.{ 557, 27, 13 });
    try std.testing.expectEqual(@as(u32, 10), plan.shapes[0].log_size);
    try std.testing.expectEqual(@as(u32, 5), plan.shapes[1].log_size);
    try std.testing.expectEqual(@as(u32, 4), plan.shapes[2].log_size);
    try std.testing.expectEqual(@as(u64, 1072), try plan.additionalByteTerms());
    try std.testing.expectEqual(@as(u64, 1172), try plan.extendByteBound(100));
    const identity = try plan.identity();
    try plan.admit(identity);
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, plan.admit(@splat(0)));
    var changed = plan;
    changed.shapes[0].n_rows += 1;
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, changed.admit(identity));
    changed = plan;
    changed.shapes[0].log_size += 1;
    try std.testing.expectError(error.InvalidCompactRangeGeometry, changed.identity());
    changed = plan;
    changed.shapes[0].log_size = 32;
    try std.testing.expectError(error.InvalidCompactRangeGeometry, changed.additionalByteTerms());
    try std.testing.expectError(error.CoefficientBoundExceeded, plan.extendByteBound(core.fields.m31.Modulus - 1072));
    try std.testing.expectError(error.Overflow, plan.extendByteBound(std.math.maxInt(u64)));
    try std.testing.expectError(error.UnsupportedCompactRangeKind, geometry.Shape.canonical(.bitwise, 1));
    for (geometry.kinds) |kind| {
        try std.testing.expectError(error.InvalidCompactRangeGeometry, geometry.Shape.canonical(kind, schema.size(kind) + 1));
        for ([_]usize{ 0, 1, 16, 17, schema.size(kind) }) |count| {
            const shape = try geometry.Shape.canonical(kind, count);
            try shape.validate(kind);
            try std.testing.expect(try shape.paddedRows(kind) >= count);
        }
    }
}

test "compact range provider admitted roster binds prover verifier and witness geometry" {
    const a = std.testing.allocator;
    const geometry = @import("../compact_range_geometry.zig");
    const roster = @import("../compact_range_roster.zig");
    const plan = try geometry.Plan.canonical(.{ 1, 1, 1 });
    const id = try plan.identity();
    const manifest = try roster.admittedManifest(plan, id, .{ .columns = .{ 3, 5, 7, 11 }, .claimed_sum_index = 2 });
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, roster.admittedManifest(plan, @splat(0), .{}));
    try std.testing.expectError(error.Overflow, roster.admittedManifest(plan, id, .{ .columns = .{ 0, std.math.maxInt(u32), 0, 0 } }));
    const large = try roster.admittedManifest(plan, id, .{ .claimed_sum_index = 255 });
    try std.testing.expectEqual(@as(u32, 257), (try large.placement(@enumFromInt(2))).claimed_sum_index);
    try std.testing.expectError(error.Overflow, roster.admittedManifest(plan, id, .{ .claimed_sum_index = std.math.maxInt(u32) }));
    var relations = @import("../universal_challenges.zig").UniversalRelations.dummy();
    inline for (roster.Roster.Airs, 0..) |Air, i| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const binding = try @import("../universal_relation_binding.zig").Binding(Air).authenticate(&definition);
        var component = try roster.Roster.Component(Air).init(&definition, binding, &manifest, @enumFromInt(i), plan.shapes[i].log_size, .{}, &relations, core.fields.qm31.QM31.zero());
        const prover = component.asProverComponent();
        const verifier = component.asVerifierComponent();
        try std.testing.expectEqual(prover.maxConstraintLogDegreeBound(), verifier.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT, verifier.nConstraints());
        try std.testing.expectError(error.InvalidProofShape, roster.Roster.Component(Air).init(&definition, binding, &manifest, @enumFromInt(i), plan.shapes[i].log_size + 1, .{}, &relations, core.fields.qm31.QM31.zero()));
        var counter = try @import("../../../air/lookups/tables/counter.zig").Counter.init(a, geometry.kinds[i]);
        defer counter.deinit(a);
        counter.values[1] = M.one();
        const Owner = @import("../compact_range_witness.zig").Owner(geometry.kinds[i]);
        var witness = try Owner.initAdmitted(a, &counter, plan, id);
        defer witness.deinit();
        try std.testing.expectError(error.UntrustedCompactRangeGeometry, Owner.initAdmitted(a, &counter, plan, @splat(0)));
        counter.values[2] = M.one();
        try std.testing.expectError(error.CompactRangeWitnessGeometryMismatch, Owner.initAdmitted(a, &counter, plan, id));
    }
}

test "compact range provider persistent interaction closes original tables including padding" {
    const a = std.testing.allocator;
    const Counter = @import("../../../air/lookups/tables/counter.zig").Counter;
    const interactions = @import("../../../air/lookups/tables/interaction.zig");
    const geometry = @import("../compact_range_geometry.zig");
    const plan = try geometry.Plan.canonical(.{ 3, 3, 3 });
    const id = try plan.identity();
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x4352414e, 1 });
    const relations = try @import("../universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const native = try @import("../universal_provider_relations.zig").SharedProviderRelations.init(&relations);
    inline for (geometry.kinds) |kind| {
        var source = try Counter.init(a, kind);
        defer source.deinit(a);
        source.values[0] = M.one();
        source.values[257] = M.fromCanonical(7).neg();
        source.values[source.values.len - 1] = M.fromCanonical(123);
        var witness = try @import("../compact_range_witness.zig").Owner(kind).initAdmitted(a, &source, plan, id);
        defer witness.deinit();
        const Prepared = @import("../compact_range_interaction.zig").Prepared(kind);
        const prepared = try Prepared.init(a, plan, id);
        defer prepared.deinit();
        var first = try prepared.generate(&witness, &relations);
        defer first.deinit(a);
        var second = try prepared.generate(&witness, &relations);
        defer second.deinit(a);
        try std.testing.expectEqual(first.claimed_sum, second.claimed_sum);
        for (first.columns, second.columns) |lhs, rhs| try std.testing.expectEqualSlices(M, lhs, rhs);
        const bytes = Counter{ .kind = .range_check_8_8, .values = witness.byte_counts };
        var byte_interaction = try interactions.generate(a, &bytes, &native.native);
        defer byte_interaction.deinit(a);
        var original = try interactions.generate(a, &source, &native.native);
        defer original.deinit(a);
        try std.testing.expect(first.claimed_sum.add(byte_interaction.claim).sub(original.claim).isZero());
        // Omitting even a zero-padding request breaks global relation closure.
        witness.byte_counts[0] = witness.byte_counts[0].add(M.one());
        var missing = try interactions.generate(a, &bytes, &native.native);
        defer missing.deinit(a);
        try std.testing.expect(!first.claimed_sum.add(missing.claim).sub(original.claim).isZero());
        witness.n_rows += 1;
        try std.testing.expectError(error.CompactRangeWitnessGeometryMismatch, prepared.generate(&witness, &relations));
        try std.testing.expectError(error.UntrustedCompactRangeGeometry, Prepared.init(a, plan, @splat(0)));
    }
}
