//! Diagnostic validation and restoration of Cairo transcript bootstrap fixtures.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;

const Error = error{
    DuplicateBinding,
    InvalidBindingSize,
    InvalidSchedule,
    MissingBinding,
    TranscriptBootstrapCommitmentMismatch,
    TranscriptBootstrapStatementMismatch,
};

fn purpose(entry: std.json.Value) ![]const u8 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("purpose") orelse return Error.InvalidSchedule;
    if (value != .string) return Error.InvalidSchedule;
    return value.string;
}

fn logicalId(entry: std.json.Value) !u32 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("id") orelse return Error.InvalidSchedule;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32))
        return Error.InvalidSchedule;
    return @intCast(value.integer);
}

fn ordinal(entry: std.json.Value) !u32 {
    if (entry != .object) return Error.InvalidSchedule;
    const value = entry.object.get("ordinal") orelse return 0;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32))
        return Error.InvalidSchedule;
    return @intCast(value.integer);
}

fn oneOrdinal(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    name: []const u8,
    wanted_ordinal: u32,
) !arena_plan.Binding {
    var found: ?arena_plan.Binding = null;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), name) or try ordinal(entry) != wanted_ordinal)
            continue;
        if (found != null) return Error.DuplicateBinding;
        found = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
    }
    return found orelse Error.MissingBinding;
}

const transcript_bootstrap_statement_ordinals = [_]u32{ 1, 2, 10, 11, 12, 13, 14, 15, 16 };
const transcript_bootstrap_commitment_ordinals = [_]u32{ 3, 20 };
const transcript_bootstrap_ordinals = [_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 };

const TranscriptBootstrapFixture = struct {
    allocator: std.mem.Allocator,
    encoded: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn read(allocator: std.mem.Allocator, path: []const u8) !TranscriptBootstrapFixture {
        const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
        errdefer allocator.free(encoded);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
        errdefer parsed.deinit();
        if (parsed.value != .object) return Error.InvalidSchedule;
        const inputs_value = parsed.value.object.get("inputs") orelse return Error.InvalidSchedule;
        if (inputs_value != .object) return Error.InvalidSchedule;
        return .{ .allocator = allocator, .encoded = encoded, .parsed = parsed };
    }

    fn deinit(self: *TranscriptBootstrapFixture) void {
        self.parsed.deinit();
        self.allocator.free(self.encoded);
        self.* = undefined;
    }

    fn inputs(self: TranscriptBootstrapFixture) std.json.Value {
        return self.parsed.value.object.get("inputs").?;
    }
};

pub const TranscriptBootstrapValidationOptions = struct {
    /// Tree roots become meaningful only after the corresponding commitment
    /// has written them into transcript ordinals 3 and 20.
    validate_commitment_roots: bool = false,
};

fn transcriptBootstrapFixtureWords(inputs: std.json.Value, ordinal_value: u32) ![]const std.json.Value {
    var key_storage: [16]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_storage, "{d}", .{ordinal_value});
    const words_value = inputs.object.get(key) orelse return Error.InvalidSchedule;
    if (words_value != .array) return Error.InvalidSchedule;
    return words_value.array.items;
}

fn transcriptBootstrapBindingWords(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    inputs: std.json.Value,
    ordinal_value: u32,
) !struct { fixture: []const std.json.Value, arena: []u32 } {
    const fixture_words = try transcriptBootstrapFixtureWords(inputs, ordinal_value);
    const binding = try oneOrdinal(schedule, plan, "TranscriptInput", ordinal_value);
    if (binding.size_bytes != fixture_words.len * @sizeOf(u32)) return Error.InvalidBindingSize;
    const bytes = try resident_arena.bytes(binding);
    const aligned: []align(4) u8 = @alignCast(bytes);
    return .{ .fixture = fixture_words, .arena = std.mem.bytesAsSlice(u32, aligned) };
}

fn transcriptBootstrapExpectedWord(word_value: std.json.Value) !u32 {
    if (word_value != .integer or word_value.integer < 0 or word_value.integer > std.math.maxInt(u32))
        return Error.InvalidSchedule;
    return @intCast(word_value.integer);
}

fn validateTranscriptBootstrapOrdinal(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    inputs: std.json.Value,
    ordinal_value: u32,
    commitment_root: bool,
) !void {
    const words = try transcriptBootstrapBindingWords(resident_arena, schedule, plan, inputs, ordinal_value);
    for (words.fixture, words.arena, 0..) |word_value, actual, word_index| {
        const expected = try transcriptBootstrapExpectedWord(word_value);
        if (actual == expected) continue;
        std.debug.print(
            "transcript bootstrap {s} mismatch ordinal={} word={} expected={} actual={}\n",
            .{ if (commitment_root) "commitment" else "statement", ordinal_value, word_index, expected, actual },
        );
        return if (commitment_root)
            Error.TranscriptBootstrapCommitmentMismatch
        else
            Error.TranscriptBootstrapStatementMismatch;
    }
}

/// Compares statement bootstrap inputs in the arena with a diagnostic fixture
/// without copying fixture data into proof state. Commitment-root comparison is
/// explicitly deferred until the caller has produced both roots.
pub fn validateTranscriptBootstrap(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    path: []const u8,
    options: TranscriptBootstrapValidationOptions,
) !void {
    var fixture = try TranscriptBootstrapFixture.read(allocator, path);
    defer fixture.deinit();
    const inputs = fixture.inputs();
    for (transcript_bootstrap_statement_ordinals) |ordinal_value|
        try validateTranscriptBootstrapOrdinal(resident_arena, schedule, plan, inputs, ordinal_value, false);
    if (options.validate_commitment_roots) {
        for (transcript_bootstrap_commitment_ordinals) |ordinal_value|
            try validateTranscriptBootstrapOrdinal(resident_arena, schedule, plan, inputs, ordinal_value, true);
    }
}

/// Loads the canonical statement inputs used before the base commitment from
/// a reference transcript artifact. Tree roots are validated against the
/// commitments already present in the arena; all other bootstrap inputs are
/// copied verbatim for transcript-parity bring-up.
pub fn restoreTranscriptBootstrap(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    path: []const u8,
) !void {
    var fixture = try TranscriptBootstrapFixture.read(allocator, path);
    defer fixture.deinit();
    const inputs = fixture.inputs();
    for (transcript_bootstrap_ordinals) |ordinal_value| {
        if (ordinal_value == 3 or ordinal_value == 20) {
            validateTranscriptBootstrapOrdinal(resident_arena, schedule, plan, inputs, ordinal_value, true) catch |err| switch (err) {
                Error.TranscriptBootstrapCommitmentMismatch => return Error.InvalidSchedule,
                else => return err,
            };
        } else {
            const words = try transcriptBootstrapBindingWords(resident_arena, schedule, plan, inputs, ordinal_value);
            for (words.fixture, words.arena) |word_value, *destination|
                destination.* = try transcriptBootstrapExpectedWord(word_value);
        }
    }
}

const transcript_bootstrap_test_schedule =
    \\[
    \\  {"purpose":"TranscriptInput","ordinal":1,"id":1},
    \\  {"purpose":"TranscriptInput","ordinal":2,"id":2},
    \\  {"purpose":"TranscriptInput","ordinal":3,"id":3},
    \\  {"purpose":"TranscriptInput","ordinal":10,"id":10},
    \\  {"purpose":"TranscriptInput","ordinal":11,"id":11},
    \\  {"purpose":"TranscriptInput","ordinal":12,"id":12},
    \\  {"purpose":"TranscriptInput","ordinal":13,"id":13},
    \\  {"purpose":"TranscriptInput","ordinal":14,"id":14},
    \\  {"purpose":"TranscriptInput","ordinal":15,"id":15},
    \\  {"purpose":"TranscriptInput","ordinal":16,"id":16},
    \\  {"purpose":"TranscriptInput","ordinal":20,"id":20}
    \\]
;

const transcript_bootstrap_test_fixture =
    \\{"inputs":{
    \\  "1":[101],"2":[102],"3":[103],
    \\  "10":[110],"11":[111],"12":[112],"13":[113],
    \\  "14":[114],"15":[115],"16":[116],"20":[120]
    \\}}
;

fn transcriptBootstrapTestBindings(bindings: *[transcript_bootstrap_ordinals.len]arena_plan.Binding) void {
    for (transcript_bootstrap_ordinals, bindings, 0..) |ordinal_value, *binding, index| {
        binding.* = .{
            .logical_id = ordinal_value,
            .slot = @intCast(index),
            .offset_bytes = index * @sizeOf(u32),
            .size_bytes = @sizeOf(u32),
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        };
    }
}

fn transcriptBootstrapTestArena(words: *[transcript_bootstrap_ordinals.len]u32) arena_plan.ResidentArena {
    return .{ .buffer = .{
        .handle = @ptrCast(words),
        .contents = @ptrCast(words),
        .byte_length = @sizeOf(@TypeOf(words.*)),
    } };
}

test "Cairo transcript bootstrap validator is non-mutating and root-aware" {
    const allocator = std.testing.allocator;
    var parsed_schedule = try std.json.parseFromSlice(std.json.Value, allocator, transcript_bootstrap_test_schedule, .{});
    defer parsed_schedule.deinit();
    var bindings: [transcript_bootstrap_ordinals.len]arena_plan.Binding = undefined;
    transcriptBootstrapTestBindings(&bindings);
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = allocator,
        .bindings = &bindings,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = @sizeOf([transcript_bootstrap_ordinals.len]u32),
        .peak_live_bytes = @sizeOf([transcript_bootstrap_ordinals.len]u32),
        .plan_hash = 0,
    };
    var words = [_]u32{ 101, 102, 0, 110, 111, 112, 113, 114, 115, 116, 0 };
    var resident_arena = transcriptBootstrapTestArena(&words);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("transcript.json", .{});
    try file.writeAll(transcript_bootstrap_test_fixture);
    file.close();
    const path = try temporary.dir.realpathAlloc(allocator, "transcript.json");
    defer allocator.free(path);

    const before_statement_validation = words;
    try validateTranscriptBootstrap(
        allocator,
        &resident_arena,
        parsed_schedule.value.array.items,
        plan,
        path,
        .{},
    );
    try std.testing.expectEqualSlices(u32, &before_statement_validation, &words);
    try std.testing.expectError(
        Error.TranscriptBootstrapCommitmentMismatch,
        validateTranscriptBootstrap(
            allocator,
            &resident_arena,
            parsed_schedule.value.array.items,
            plan,
            path,
            .{ .validate_commitment_roots = true },
        ),
    );
    try std.testing.expectEqualSlices(u32, &before_statement_validation, &words);

    words[2] = 103;
    words[10] = 120;
    const before_root_validation = words;
    try validateTranscriptBootstrap(
        allocator,
        &resident_arena,
        parsed_schedule.value.array.items,
        plan,
        path,
        .{ .validate_commitment_roots = true },
    );
    try std.testing.expectEqualSlices(u32, &before_root_validation, &words);

    words[5] = 999;
    const before_mismatch = words;
    try std.testing.expectError(
        Error.TranscriptBootstrapStatementMismatch,
        validateTranscriptBootstrap(
            allocator,
            &resident_arena,
            parsed_schedule.value.array.items,
            plan,
            path,
            .{},
        ),
    );
    try std.testing.expectEqualSlices(u32, &before_mismatch, &words);
}

test "Cairo transcript bootstrap restore preserves diagnostic fallback order" {
    const allocator = std.testing.allocator;
    var parsed_schedule = try std.json.parseFromSlice(std.json.Value, allocator, transcript_bootstrap_test_schedule, .{});
    defer parsed_schedule.deinit();
    var bindings: [transcript_bootstrap_ordinals.len]arena_plan.Binding = undefined;
    transcriptBootstrapTestBindings(&bindings);
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = allocator,
        .bindings = &bindings,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = @sizeOf([transcript_bootstrap_ordinals.len]u32),
        .peak_live_bytes = @sizeOf([transcript_bootstrap_ordinals.len]u32),
        .plan_hash = 0,
    };
    var words = [_]u32{0} ** transcript_bootstrap_ordinals.len;
    words[2] = 103;
    words[10] = 120;
    var resident_arena = transcriptBootstrapTestArena(&words);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("transcript.json", .{});
    try file.writeAll(transcript_bootstrap_test_fixture);
    file.close();
    const path = try temporary.dir.realpathAlloc(allocator, "transcript.json");
    defer allocator.free(path);

    try restoreTranscriptBootstrap(
        allocator,
        &resident_arena,
        parsed_schedule.value.array.items,
        plan,
        path,
    );
    try std.testing.expectEqualSlices(
        u32,
        &[_]u32{ 101, 102, 103, 110, 111, 112, 113, 114, 115, 116, 120 },
        &words,
    );

    words = [_]u32{0} ** transcript_bootstrap_ordinals.len;
    words[10] = 120;
    try std.testing.expectError(
        Error.InvalidSchedule,
        restoreTranscriptBootstrap(
            allocator,
            &resident_arena,
            parsed_schedule.value.array.items,
            plan,
            path,
        ),
    );
    try std.testing.expectEqual(@as(u32, 101), words[0]);
    try std.testing.expectEqual(@as(u32, 102), words[1]);
    try std.testing.expectEqual(@as(u32, 0), words[3]);
}
