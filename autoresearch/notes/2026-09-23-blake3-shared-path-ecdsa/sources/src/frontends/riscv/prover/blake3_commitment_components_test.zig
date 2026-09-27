const std = @import("std");
const core = @import("stwo_core");
const components = @import("blake3_commitment_components.zig");
const program = @import("../recursion/air/blake3_program_word.zig");
const boundary = @import("../recursion/air/blake3_program_boundary.zig");
const binding = @import("../recursion/air/universal_relation_binding.zig");
const lang = @import("../air/lang/mod.zig");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
const M = core.fields.m31.M31;
const Hash = core.vcs.blake3_hash.Blake3Hasher;

test "BLAKE3 Span program boundary pins typed identity" {
    const digest = try boundary.computeSemanticDigest(std.testing.allocator);
    if (!std.mem.eql(u8, &digest, &boundary.SEMANTIC_DIGEST)) std.debug.print("PROGRAM_BOUNDARY_DIGEST={s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    try std.testing.expectEqual(boundary.SEMANTIC_DIGEST, digest);
    var definition = try boundary.build(std.testing.allocator);
    defer definition.deinit();
    const Runtime = @import("../recursion/air/relation_interaction.zig").Runtime(boundary.LOGICAL_INPUT_COUNT, boundary.RELATION_EVENT_COUNT, boundary.LOOKUP_BATCH_SIZE);
    try std.testing.expectError(error.InvalidInputGeometry, Runtime.authenticate(&definition.arena, boundary.SEMANTIC_DIGEST, definition.events));
    const authenticated = try binding.Binding(boundary).authenticate(&definition);
    try authenticated.validateAgainst(&definition.arena, boundary.SEMANTIC_DIGEST, definition.events);
}

test "BLAKE3 Span program components close canonical fields through hash paths" {
    const a = std.testing.allocator;
    const leaves = [_]tree.Leaf{ .{ .index = 0x1000, .value = 12 }, .{ .index = 0x1001, .value = 1 }, .{ .index = 0x1003, .value = 0x7ffffffe } };
    const hasher = tree.TreeHasher.init(.program);
    const statement = program.Statement{ .namespace = 100, .address = 0x1000, .multiplicity = 7, .root = try hasher.root(&leaves) };
    var observed = Sink.init(a, true);
    defer observed.deinit();
    try emitProgram(a, statement, &leaves, false, &observed);
    try std.testing.expect(observed.closed());
    try std.testing.expectEqual(@as(u32, 7), observed.program_multiplicity.toU32());
    var expected = Sink.init(a, false);
    defer expected.deinit();
    const empty_memory = tree.TreeHasher.init(.memory).defaults[0];
    var admitted_plan = try @import("blake3_commitment_plan.zig").Plan.init(a, .{ statement.root, empty_memory, empty_memory }, &.{}, &.{statement});
    defer admitted_plan.deinit();
    const admitted = try @import("blake3_commitment_plan.zig").Admission.init(&admitted_plan, try admitted_plan.identity());
    try components.emitTrusted(a, admitted, &expected);
    const codec = @import("blake3_commitment_plan_codec.zig");
    const serialized = try codec.encode(a, &admitted_plan, admitted.expected_id, .{});
    defer a.free(serialized);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, serialized[8..12], .little));
    std.mem.writeInt(u32, serialized[8..12], 1, .little);
    try std.testing.expectError(error.InvalidCommitmentPlanVersion, codec.decode(a, serialized, admitted.expected_id, .{}));
    inline for (components.Airs, 0..) |_, i| {
        try std.testing.expectEqual(observed.counts[i], expected.counts[i]);
        try std.testing.expectEqual(observed.fixed[i].finalize(), expected.fixed[i].finalize());
    }
    var forged = Sink.init(a, true);
    defer forged.deinit();
    try emitProgram(a, statement, &leaves, true, &forged);
    try std.testing.expect(!forged.closed());
    var wrong = statement;
    wrong.root.bytes[0] ^= 1;
    var invalid = Sink.init(a, false);
    defer invalid.deinit();
    try std.testing.expectError(error.SharedPathRootMismatch, emitProgram(a, wrong, &leaves, false, &invalid));
    var frontier = Sink.init(a, true);
    defer frontier.deinit();
    frontier.corrupt_frontier = true;
    try emitProgram(a, statement, &leaves, false, &frontier);
    try std.testing.expect(!frontier.closed());
    try std.testing.expectError(error.NonCanonicalProgramField, boundary.logicalRow(statement.schedule(), .{ 0, 0, 0, 0x7fffffff }));
}

fn emitProgram(a: std.mem.Allocator, statement: program.Statement, leaves: []const tree.Leaf, forge: bool, sink: anytype) !void {
    const shared = @import("blake3_shared_path_emit.zig");
    var values: [4]u32 = undefined;
    var inputs: [4]shared.Input = undefined;
    for (&values, &inputs, 0..) |*value, *input, i| {
        const address = statement.address + @as(u32, @intCast(i));
        value.* = shared.valueAt(leaves, address);
        input.* = .{ .address = address, .caller = .{ .circuit = statement.namespace + 2, .wire = @intCast(i) } };
    }
    var row = try boundary.logicalRow(statement.schedule(), values);
    const coordinates = core.fields.qm31.QM31.fromM31Array(row[0..4].*);
    if (forge) row[3] = M.zero();
    try sink.append(boundary, &.{row});
    const packing = @import("../recursion/air/qm31_pack_wire.zig");
    const encoding = @import("../recursion/air/blake3_field_bytes.zig");
    try sink.append(packing, &.{try packing.logicalRow(statement.packSchedule(), coordinates)});
    try sink.append(encoding, &.{try encoding.logicalRow(statement.encodingSchedule(), coordinates)});
    _ = try shared.emit(a, &inputs, statement.namespace + program.CIRCUIT_COUNT, .program, statement.root, leaves, sink);
}

const Sink = struct {
    a: std.mem.Allocator,
    inspect: bool,
    corrupt_frontier: bool = false,
    fixed: [components.Airs.len]Hash,
    counts: [components.Airs.len]usize = @splat(0),
    wires: std.AutoHashMap([6]u32, M),
    program_multiplicity: M = M.zero(),
    fn init(a: std.mem.Allocator, inspect: bool) Sink {
        var result = Sink{ .a = a, .inspect = inspect, .fixed = undefined, .wires = std.AutoHashMap([6]u32, M).init(a) };
        for (&result.fixed) |*hash| hash.* = Hash.init();
        return result;
    }
    fn deinit(self: *Sink) void {
        self.wires.deinit();
    }
    pub fn append(self: *Sink, comptime Air: type, rows: []const Air.Row) !void {
        const index = comptime blk: {
            for (components.Airs, 0..) |Candidate, i| if (Air == Candidate) break :blk i;
            @compileError("unregistered commitment component");
        };
        self.counts[index] += rows.len;
        for (rows) |row| for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |field| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, field.toU32(), .little);
            self.fixed[index].update(&bytes);
        };
        if (!self.inspect) return;
        var definition = try Air.build(self.a);
        defer definition.deinit();
        const plan = try binding.Binding(Air).authenticate(&definition);
        for (rows) |original| {
            var row = original;
            if (Air == @import("../recursion/air/blake3_private_word.zig") and self.corrupt_frontier) row[0] = row[0].add(M.one());
            for (plan.preparedEntries(row)) |entry| {
                if (entry.schema == lang.relation.id(.program_access)) self.program_multiplicity = self.program_multiplicity.add(try entry.numerator.tryIntoM31());
                if (entry.schema != lang.relation.id(.recursion_wire)) continue;
                var key: [6]u32 = undefined;
                for (&key, entry.values[0..6]) |*value, coordinate| value.* = (try coordinate.tryIntoM31()).toU32();
                const slot = try self.wires.getOrPut(key);
                if (!slot.found_existing) slot.value_ptr.* = M.zero();
                slot.value_ptr.* = slot.value_ptr.*.add(try entry.numerator.tryIntoM31());
            }
        }
    }
    fn closed(self: *Sink) bool {
        var values = self.wires.valueIterator();
        while (values.next()) |value| if (!value.isZero()) return false;
        return true;
    }
};
