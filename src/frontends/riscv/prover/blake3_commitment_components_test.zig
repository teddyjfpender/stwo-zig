const std = @import("std");
const core = @import("stwo_core");
const components = @import("blake3_commitment_components.zig");
const program = @import("../recursion/air/blake3_program_word.zig");
const table = @import("../recursion/air/blake3_public_program.zig");
const binding = @import("../recursion/air/universal_relation_binding.zig");
const lang = @import("../air/lang/mod.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const plans = @import("blake3_commitment_plan.zig");
const codec = @import("blake3_commitment_plan_codec.zig");

test "BLAKE3 Span public program pins typed identity" {
    const digest = try table.computeSemanticDigest(std.testing.allocator);
    if (!std.mem.eql(u8, &digest, &table.SEMANTIC_DIGEST)) std.debug.print("PUBLIC_PROGRAM_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqual(table.SEMANTIC_DIGEST, digest);
    var definition = try table.build(std.testing.allocator);
    defer definition.deinit();
    const authenticated = try binding.Binding(table).authenticate(&definition);
    try authenticated.validateAgainst(&definition.arena, table.SEMANTIC_DIGEST, definition.events);
    const row = try table.fixedRow(0x1000, 7, .{ 12, 1, 0, 0x7ffffffe });
    const entries = authenticated.preparedEntries(row);
    try std.testing.expectEqual(lang.relation.id(.program_access), entries[0].schema);
    try std.testing.expectEqual(@as(u32, 7), (try entries[0].numerator.tryIntoM31()).toU32());
    const expected = [_]u32{ 0x1000, 12, 1, 0, 0x7ffffffe };
    for (entries[0].values[0..5], expected) |value, word| try std.testing.expectEqual(word, (try value.tryIntoM31()).toU32());
    const padding: table.Row = @splat(core.fields.m31.M31.zero());
    try std.testing.expect(authenticated.preparedEntries(padding)[0].numerator.isZero());
    try std.testing.expectError(error.NonCanonicalProgramField, table.fixedRow(0, 1, .{ 0, 0, 0, 0x7fffffff }));
}

test "BLAKE3 Span public program authenticates complete ROM and emits no hash rows" {
    const a = std.testing.allocator;
    const leaves = [_]tree.Leaf{
        .{ .index = 0x1000, .value = 12 }, .{ .index = 0x1001, .value = 1 },
        .{ .index = 0x1002, .value = 0 },  .{ .index = 0x1003, .value = 0x7ffffffe },
    };
    const hasher = tree.TreeHasher.init(.program);
    const statement = program.Statement{ .namespace = 100, .address = 0x1000, .multiplicity = 7, .root = try hasher.root(&leaves) };
    const empty = tree.TreeHasher.init(.memory).defaults[0];
    var plan = try plans.Plan.init(a, .{ statement.root, empty, empty }, &.{}, &.{statement}, &leaves);
    defer plan.deinit();
    const admitted = try plans.Admission.init(&plan, try plan.identity());
    var sink = Sink{};
    try components.emitTrusted(a, admitted, &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.program_rows);
    try std.testing.expectEqual(@as(usize, 0), sink.other_rows);
    try std.testing.expectEqualDeep(try table.fixedRow(0x1000, 7, .{ 12, 1, 0, 0x7ffffffe }), sink.row.?);
    const bytes = try codec.encode(a, &plan, admitted.expected_id, .{});
    defer a.free(bytes);
    var decoded = try codec.decode(a, bytes, admitted.expected_id, .{});
    defer decoded.deinit();
    try std.testing.expectEqualDeep(plan.program_leaves, decoded.program_leaves);
    try std.testing.expectEqual(admitted.expected_id, try decoded.identity());
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, bytes[8..12], .little));
    // Reject the previous schedule-only format, never reinterpret it as public ROM.
    std.mem.writeInt(u32, bytes[8..12], 2, .little);
    try std.testing.expectError(error.InvalidCommitmentPlanVersion, codec.decode(a, bytes, admitted.expected_id, .{}));
    std.mem.writeInt(u32, bytes[8..12], 4, .little);
    // Corrupt a canonical decoded value without changing the embedded authority.
    bytes[codec.HEADER_BYTES + 12] ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, codec.decode(a, bytes, admitted.expected_id, .{}));
    bytes[codec.HEADER_BYTES + 12] ^= 1;
    plan.program_leaves[0].value ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, admitted.validate());
    // Even a self-consistent replacement ROM/root must not rebind a pinned plan.
    plan.roots[0] = try hasher.root(plan.program_leaves);
    plan.programs[0].root = plan.roots[0];
    try std.testing.expectError(error.UntrustedCommitmentPlan, admitted.validate());
    plan.program_leaves[0].value ^= 1;
    plan.roots[0] = statement.root;
    plan.programs[0].root = statement.root;
    plan.programs[0].multiplicity += 1;
    try std.testing.expectError(error.UntrustedCommitmentPlan, admitted.validate());
    plan.programs[0].multiplicity -= 1;
    try admitted.validate();
    try std.testing.expectError(error.InvalidProgramPreprocessing, plans.Plan.init(a, plan.roots, &.{}, &.{statement}, leaves[0..3]));
    // Explicit zero leaves cannot be relabeled as a different decoded address.
    plan.program_leaves[2].index = 0x1003;
    try std.testing.expectError(error.UnsortedOrDuplicateByte, admitted.validate());
}
const Sink = struct {
    program_rows: usize = 0,
    other_rows: usize = 0,
    row: ?table.Row = null,
    pub fn append(self: *Sink, comptime Air: type, rows: []const Air.Row) !void {
        if (Air == table) {
            self.program_rows += rows.len;
            if (rows.len != 0) self.row = rows[0];
        } else self.other_rows += rows.len;
    }
};
