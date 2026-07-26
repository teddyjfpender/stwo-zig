const std = @import("std");
const adapter = @import("cairo_frontend").adapter;

const fixture_path = "vectors/cairo/official/all_opcodes.prover_input.json";
const summary_path = "vectors/cairo/official/all_opcodes.input_summary.json";
const builtins_fixture_path = "vectors/cairo/official/all_builtins.prover_input.json";
const builtins_summary_path = "vectors/cairo/official/all_builtins.input_summary.json";

test "official Cairo input: pinned all-opcodes vector is admitted exactly" {
    const fixture = try readFixture(std.testing.allocator);
    defer std.testing.allocator.free(fixture);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(fixture, &digest, .{});
    try std.testing.expectEqualSlices(u8, &.{
        0x7f, 0x94, 0xbd, 0x5d, 0xcf, 0x32, 0xe7, 0xdd,
        0x69, 0xa8, 0xa4, 0x7f, 0x42, 0xd4, 0x18, 0x30,
        0xb4, 0xfd, 0xd3, 0xb7, 0x58, 0x46, 0xef, 0x9f,
        0x76, 0x94, 0xf3, 0x16, 0x41, 0x17, 0xfc, 0xd6,
    }, &digest);

    var input = try adapter.official_input.readFile(
        std.testing.allocator,
        fixture_path,
    );
    defer input.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 1), input.state_transitions.initial_state.pc.toU32());
    try std.testing.expectEqual(@as(u32, 1343), input.state_transitions.initial_state.ap.toU32());
    try std.testing.expectEqual(@as(u32, 5), input.state_transitions.final_state.pc.toU32());
    try std.testing.expectEqual(@as(usize, 1498), input.state_transitions.casm_states_by_opcode.totalCount());
    try std.testing.expectEqual(@as(usize, 778), input.pc_count);
    try std.testing.expectEqual(@as(usize, 2779), input.memory.address_to_id.len);
    try std.testing.expectEqual(@as(usize, 19), input.memory.f252_values.len);
    try std.testing.expectEqual(@as(usize, 430), input.memory.small_values.len);
    try std.testing.expectEqual(@as(usize, 1366), input.public_memory_addresses.len);
    try std.testing.expectEqual(
        @as(usize, 2),
        input.state_transitions.casm_states_by_opcode.getConst(.blake_compress_opcode).len,
    );
    try std.testing.expectEqual(
        @as(?adapter.MemorySegmentAddresses, .{ .begin_addr = 2529, .stop_ptr = 2531 }),
        input.builtin_segments.output,
    );
    for (input.public_segment_context) |present| try std.testing.expect(present);

    try expectRustSummary(&input, digest, summary_path);
}

test "official Cairo input: all builtin segment and resource semantics match Rust" {
    const fixture = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        builtins_fixture_path,
        2 * 1024 * 1024,
    );
    defer std.testing.allocator.free(fixture);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(fixture, &digest, .{});
    const expected_digest = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings(
        "d7e902c3b8584a79b466ef0c384208ad95ea75340f0b0590ea0ba765c54acac1",
        &expected_digest,
    );

    var input = try adapter.official_input.readFile(
        std.testing.allocator,
        builtins_fixture_path,
    );
    defer input.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 9157), input.state_transitions.casm_states_by_opcode.totalCount());
    try std.testing.expectEqual(@as(usize, 272), input.pc_count);
    try std.testing.expectEqual(@as(usize, 9811), input.memory.address_to_id.len);
    try std.testing.expectEqual(@as(usize, 50), input.memory.f252_values.len);
    try std.testing.expectEqual(@as(usize, 1345), input.memory.small_values.len);
    inline for (@typeInfo(adapter.BuiltinSegments).@"struct".fields) |field| {
        try std.testing.expect(@field(input.builtin_segments, field.name) != null);
    }
    try expectRustSummary(&input, digest, builtins_summary_path);
}

test "official Cairo input: schema and semantic mutations fail closed" {
    const fixture = try readFixture(std.testing.allocator);
    defer std.testing.allocator.free(fixture);
    try expectMutationError(
        fixture,
        "\"pc_count\": 778",
        "\"pc_count\": 777",
        error.InvalidPcCount,
    );
    try expectMutationError(
        fixture,
        "\"pc\": 1,\n      \"ap\": 1343",
        "\"pc\": 536870912,\n      \"ap\": 1343",
        error.StateAddressOutOfRange,
    );
    try expectMutationError(
        fixture,
        "\"address_to_id\": [\n      1073741823,",
        "\"address_to_id\": [\n      2147483648,",
        error.InvalidMemoryTag,
    );
    try expectMutationError(
        fixture,
        "\"small_values\": [\n      290341444919459839,",
        "\"small_values\": [\n      4722366482869645213696,",
        error.InvalidSmallValue,
    );
    try expectMutationError(
        fixture,
        \\[
        \\        4294967293,
        \\        4294967295,
        \\        4294967295,
        \\        4294967295,
        \\        4294967295,
        \\        4294967295,
        \\        16,
        \\        134217728
        \\      ],
    ,
        \\[
        \\        1,
        \\        0,
        \\        0,
        \\        0,
        \\        0,
        \\        0,
        \\        17,
        \\        134217728
        \\      ],
    ,
        error.F252ValueNotCanonical,
    );
    try expectMutationError(
        fixture,
        "\"pc_count\": 778",
        "\"pc_count\": 778,\n  \"schema_version\": 2",
        error.UnknownField,
    );
    try std.testing.expectError(
        error.InputTooLarge,
        adapter.official_input.readFileWithLimits(
            std.testing.allocator,
            fixture_path,
            .{ .max_file_bytes = fixture.len - 1 },
        ),
    );
    const trailing = try std.mem.concat(std.testing.allocator, u8, &.{ fixture, "false" });
    defer std.testing.allocator.free(trailing);
    try expectRejected(trailing);
}

fn expectRejected(encoded: []const u8) !void {
    if (adapter.official_input.parseSlice(std.testing.allocator, encoded, .{})) |admitted| {
        var input = admitted;
        input.deinit(std.testing.allocator);
        return error.TestUnexpectedResult;
    } else |_| {}
}

fn expectMutationError(
    fixture: []const u8,
    needle: []const u8,
    replacement: []const u8,
    expected: anyerror,
) !void {
    const mutated = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        fixture,
        needle,
        replacement,
    );
    defer std.testing.allocator.free(mutated);
    try std.testing.expect(mutated.len != fixture.len or !std.mem.eql(u8, mutated, fixture));
    try std.testing.expectError(
        expected,
        adapter.official_input.parseSlice(std.testing.allocator, mutated, .{}),
    );
}

fn readFixture(allocator: std.mem.Allocator) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, fixture_path, 1024 * 1024);
}

fn expectRustSummary(
    input: *const adapter.ProverInput,
    input_sha256: adapter.official_input.summary.Digest,
    expected_path: []const u8,
) !void {
    const encoded = try std.fs.cwd().readFileAlloc(std.testing.allocator, expected_path, 64 * 1024);
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(
        "stwo_cairo_official_input_summary_v1",
        root.get("schema").?.string,
    );

    const actual = adapter.official_input.summary.fromInput(input, input_sha256);
    try expectDigest(root.get("input_sha256").?, actual.input_sha256);
    try expectState(root.get("initial_state").?, actual.initial_state);
    try expectState(root.get("final_state").?, actual.final_state);

    const expected_opcodes = root.get("opcode_states").?.object;
    const expected_resource_opcodes = root
        .get("execution_resources").?.object
        .get("opcodes_instance_counter").?.object;
    inline for (@typeInfo(adapter.opcodes.OpcodeTag).@"enum".fields) |field| {
        const tag: adapter.opcodes.OpcodeTag = @enumFromInt(field.value);
        const digest = actual.opcode_states.get(tag);
        const expected = expected_opcodes.get(field.name).?.object;
        try expectNumber(usize, expected.get("count").?, digest.count);
        try expectDigest(expected.get("sha256_le").?, digest.sha256_le);
        try expectNumber(
            usize,
            expected_resource_opcodes.get(field.name).?,
            actual.execution_resources.opcode_counts[field.value],
        );
    }

    const expected_memory = root.get("memory").?.object;
    try expectNumber(u128, expected_memory.get("small_max").?, actual.memory.small_max);
    try expectNumber(
        u32,
        expected_memory.get("log_small_value_capacity").?,
        actual.memory.log_small_value_capacity,
    );
    try expectTable(expected_memory.get("address_to_id").?, actual.memory.address_to_id);
    try expectTable(expected_memory.get("f252_values").?, actual.memory.f252_values);
    try expectTable(expected_memory.get("small_values").?, actual.memory.small_values);
    try expectNumber(usize, root.get("pc_count").?, actual.pc_count);
    try expectTable(root.get("public_memory_addresses").?, actual.public_memory_addresses);
    try expectSegments(root.get("builtin_segments").?, actual.builtin_segments);
    try expectContext(root.get("public_segment_context").?, actual.public_segment_context);
    try expectResources(root.get("execution_resources").?, actual.execution_resources);
}

fn expectState(expected: std.json.Value, actual: [3]u32) !void {
    for (expected.array.items, actual) |value, word| try expectNumber(u32, value, word);
}

fn expectTable(
    expected_value: std.json.Value,
    actual: adapter.official_input.summary.TableDigest,
) !void {
    const expected = expected_value.object;
    try expectNumber(usize, expected.get("count").?, actual.count);
    try expectDigest(expected.get("sha256_le").?, actual.sha256_le);
}

fn expectDigest(
    expected: std.json.Value,
    actual: adapter.official_input.summary.Digest,
) !void {
    const encoded = std.fmt.bytesToHex(actual, .lower);
    try std.testing.expectEqualStrings(expected.string, &encoded);
}

fn expectNumber(comptime T: type, expected: std.json.Value, actual: T) !void {
    const parsed: T = switch (expected) {
        .integer => |value| std.math.cast(T, value) orelse return error.TestExpectedEqual,
        .number_string => |value| try std.fmt.parseInt(T, value, 10),
        else => return error.TestExpectedEqual,
    };
    try std.testing.expectEqual(parsed, actual);
}

fn expectSegments(expected_value: std.json.Value, actual: adapter.BuiltinSegments) !void {
    const expected = expected_value.object;
    inline for (@typeInfo(adapter.BuiltinSegments).@"struct".fields) |field| {
        const expected_segment = expected.get(field.name).?;
        if (@field(actual, field.name)) |segment| {
            try expectNumber(usize, expected_segment.object.get("begin_addr").?, segment.begin_addr);
            try expectNumber(usize, expected_segment.object.get("stop_ptr").?, segment.stop_ptr);
        } else {
            try std.testing.expectEqual(std.json.Value.null, expected_segment);
        }
    }
}

fn expectContext(expected: std.json.Value, actual: adapter.PublicSegmentContext) !void {
    for (expected.array.items, actual) |value, present| {
        try std.testing.expectEqual(present, value.bool);
    }
}

fn expectResources(
    expected_value: std.json.Value,
    actual: adapter.official_input.summary.ExecutionResources,
) !void {
    const expected = expected_value.object;
    const memory = expected.get("memory_tables_sizes").?.object;
    try expectNumber(usize, memory.get("memory_address_to_id").?, actual.memory_address_to_id);
    try expectNumber(usize, memory.get("memory_id_to_big").?, actual.memory_id_to_big);
    try expectNumber(usize, memory.get("memory_id_to_small").?, actual.memory_id_to_small);
    try expectNumber(usize, expected.get("verify_instruction").?, actual.verify_instruction);

    const builtins = expected.get("builtin_instance_counter").?.object;
    inline for (@typeInfo(adapter.official_input.summary.BuiltinCounts).@"struct".fields) |field| {
        try expectNumber(
            usize,
            builtins.get(field.name).?,
            @field(actual.builtin_counts, field.name),
        );
    }
}
