//! Independent fraction oracle for wider LogUp batches, including remainder batches.
const std = @import("std");
const core = @import("stwo_core");
const g = @import("blake3_g_call.zig");
const compiler = @import("relation_interaction.zig");
const universal = @import("universal_challenges.zig");
const QM31 = core.fields.qm31.QM31;
test "wide batches preserve every mixed-domain fraction and reject forged plans" {
    var definition = try g.build(std.testing.allocator);
    defer definition.deinit();
    const row = try g.logicalRow(.{ .circuit = 13, .input = .{1,2,3,4,5,6}, .output = .{7,8,9,10}, .uses = .{1,2,3,4} }, .{0xffffffff,1234567,0,99,0xabcdef01,333});
    const relations = universal.UniversalRelations.dummy();
    inline for (.{1,2,3,4}) |batch_size| {
        const R = compiler.Runtime(g.LOGICAL_INPUT_COUNT,g.RELATION_EVENT_COUNT,batch_size);
        const plan = try R.authenticate(&definition.arena,g.SEMANTIC_DIGEST,definition.events);
        const entries = plan.preparedEntries(row);
        var expected = QM31.zero();
        for (entries) |entry| expected = expected.add(entry.numerator.mul(try (try entry.denominator(&relations)).inv()));
        const pairs = try plan.preparedRowPairs(row,&relations);
        var secure: R.SecureRow = undefined;
        for (row,&secure) |value,*slot| slot.* = QM31.fromBase(value);
        try std.testing.expectEqualDeep(pairs,try plan.preparedSecureRowPairs(secure,&relations));
        var actual = QM31.zero();
        for (pairs) |pair| actual = actual.add(pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1)).mul(try pair.d1.mul(pair.d2).inv()));
        try std.testing.expectEqualDeep(expected,actual);
        const audit = try plan.auditPreparedDomainSums(std.testing.allocator,&.{row},&relations,expected);
        try std.testing.expectEqualDeep(expected,audit.total);
        var forged = plan;
        forged.batches[0].third = if (batch_size >= 3) null else 2;
        try std.testing.expectError(error.EventPlanMismatch,forged.validateAgainst(&definition.arena,g.SEMANTIC_DIGEST,definition.events));
    }
}
