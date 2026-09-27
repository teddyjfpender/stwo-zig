const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const binding = @import("universal_relation_binding.zig");
const direct = @import("direct_constraint_program.zig");
const exporter = @import("framework_polynomial_export_v1.zig");
const framework = @import("framework_interaction.zig");
const universal = @import("universal_challenges.zig");
const table_schema = @import("../../air/lookups/tables/schema.zig");
const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
test "BLAKE3 boundary pins semantics and exports committed framework programs" {
    const hash = try boundary.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &boundary.SEMANTIC_DIGEST, &hash);
    inline for (.{ g, xor, boundary }) |Air| {
        var definition = try Air.build(std.testing.allocator);
        defer definition.deinit();
        const relation_plan = try binding.Binding(Air).authenticate(&definition);
        const program = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        var exported = try exporter.exportLocalPrepared(Air, std.testing.allocator, &program, &relation_plan);
        defer exported.deinit();
        if (Air.DIRECT_CONSTRAINT_COUNT == 0) {
            const saved = exported.direct.nodes;
            defer exported.direct.nodes = saved;
            exported.direct.nodes = exported.lookup_nodes[0..1];
            try std.testing.expectError(error.InvalidFrameworkPolynomialProgram, exported.validate(&.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT }));
        }
    }
    var definition = try boundary.build(std.testing.allocator);
    defer definition.deinit();
    var row = try boundary.logicalRow(991, 5, M31.one(), 0xabcdef01);
    for (0..4) |byte| {
        row[byte] = row[byte].add(M31.one());
        const values = try @import("test_support.zig").evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        var rejected = false;
        for (definition.arena.constraintsView()) |constraint| rejected = rejected or !values[lang.types.idIndex(constraint.root)].isZero();
        try std.testing.expect(rejected);
        row[byte] = row[byte].sub(M31.one());
    }
}
test "BLAKE3 padded framework and production table interaction claims close" {
    const allocator = std.testing.allocator;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42334350, 1 });
    const relations = try universal.UniversalRelations.draw(allocator, &channel);
    const providers = try @import("universal_provider_relations.zig").SharedProviderRelations.init(&relations);
    const prepared = try @import("blake3_compression_witness.zig").prepare(991, core.crypto.blake3_compression.IV, @splat(0x12345678), 0, 64, 11);
    const plan = @import("blake3_compression_plan.zig").canonical();
    var rows: [48]boundary.Row = undefined;
    for (prepared.initial, 0..) |word, i| rows[i] = try boundary.logicalRow(991, @intCast(i), M31.fromCanonical(plan.uses[i]), word);
    for (prepared.output, plan.output, 0..) |word, id, i| rows[32 + i] = try boundary.logicalRow(991, id, M31.one().neg(), word);
    var bitwise = try Counter.init(allocator, .bitwise);
    defer bitwise.deinit(allocator);
    var bytes = try Counter.init(allocator, .range_check_8_8);
    defer bytes.deinit(allocator);
    var total = try generate(g, &prepared.g_rows, 6, &relations, &bitwise, &bytes);
    total = total.add(try generate(xor, &prepared.xor_rows, 4, &relations, &bitwise, &bytes));
    const boundary_claim = try generate(boundary, &rows, 6, &relations, &bitwise, &bytes);
    total = total.add(boundary_claim);
    const interactions = @import("../../air/lookups/tables/interaction.zig");
    var bitwise_interaction = try interactions.generate(allocator, &bitwise, &providers.native);
    defer bitwise_interaction.deinit(allocator);
    var bytes_interaction = try interactions.generate(allocator, &bytes, &providers.native);
    defer bytes_interaction.deinit(allocator);
    total = total.add(bitwise_interaction.claim).add(bytes_interaction.claim);
    try std.testing.expect(total.isZero());
    // Omit a real zero-padding table request and regenerate production columns.
    bytes.values[0] = bytes.values[0].add(M31.one());
    var omitted = try interactions.generate(allocator, &bytes, &providers.native);
    defer omitted.deinit(allocator);
    try std.testing.expect(!total.add(omitted.claim.sub(bytes_interaction.claim)).isZero());
    // A consistent but false public output changes the wire boundary claim.
    rows[32] = try boundary.logicalRow(991, plan.output[0], M31.one().neg(), prepared.output[0] ^ 1);
    const changed = try generate(boundary, &rows, 6, &relations, &bitwise, &bytes);
    try std.testing.expect(!total.add(changed.sub(boundary_claim)).isZero());
}
fn generate(comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, log: u32, relations: *const universal.UniversalRelations, bitwise: *Counter, bytes: *Counter) !QM31 {
    const allocator = std.testing.allocator;
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const Runtime = binding.Binding(Air).Runtime;
    const plan = try binding.Binding(Air).authenticate(&definition);
    const size = @as(usize, 1) << @intCast(log);
    const padded = try allocator.alloc([Air.LOGICAL_INPUT_COUNT]M31, size);
    defer allocator.free(padded);
    @memset(padded, @splat(M31.zero()));
    @memcpy(padded[0..rows.len], rows);
    // G padding retains constant-weight range/bitwise requests. Explicit rows
    // ensure the framework evaluates the same AIR as the committed trace.
    var trace = try framework.Runtime(Runtime).generatePrepared(allocator, &plan, padded, log, relations);
    defer trace.deinit(allocator);
    for (padded) |row| {
        for (plan.preparedEntries(row)) |entry| {
            const counter = if (entry.schema == lang.relation.id(.bitwise)) bitwise else if (entry.schema == lang.relation.id(.range_check_8_8)) bytes else continue;
            try counter.registerRaw(entry.numerator, entry.values[0..entry.arity]);
        }
    }
    return trace.claimed_sum;
}
