const std = @import("std");
const statement_bootstrap = @import("../../frontends/cairo/statement_bootstrap.zig");
const adapter = @import("../../frontends/cairo/adapter/mod.zig");
const claim_registry = @import("../../frontends/cairo/air/official_claim_registry.zig");
const memory_mod = @import("../../frontends/cairo/common/memory.zig");
const composition_bundle = @import("../../frontends/cairo/witness/composition_bundle.zig");
const M31 = @import("stwo_core").fields.m31.M31;

const ORDINALS = statement_bootstrap.ORDINALS;
const Error = statement_bootstrap.Error;
const StatementBootstrapInput = statement_bootstrap.StatementBootstrapInput;
const CanonicalClaimComponent = statement_bootstrap.CanonicalClaimComponent;
const compact_statement_magic = statement_bootstrap.compact_statement_magic;
const compact_statement_version = statement_bootstrap.compact_statement_version;
const compact_statement_header_bytes = statement_bootstrap.compact_statement_header_bytes;
const deriveFlatClaimGeometryFromCanonical = statement_bootstrap.deriveFlatClaimGeometryFromCanonical;
const initFromCompositionSchedule = statement_bootstrap.initFromCompositionSchedule;
const encodeCompactStatementV1 = statement_bootstrap.encodeCompactStatementV1;
const encodeCompactStatementFromFlatClaimV1 = statement_bootstrap.encodeCompactStatementFromFlatClaimV1;
const deriveFlatClaimGeometry = statement_bootstrap.deriveFlatClaimGeometry;
const init = statement_bootstrap.init;

test {
    std.testing.refAllDecls(statement_bootstrap);
}
fn syntheticInput(allocator: std.mem.Allocator) !adapter.ProverInput {
    const address_count = 23;
    const address_to_id = try allocator.alloc(memory_mod.EncodedMemoryValueId, address_count);
    errdefer allocator.free(address_to_id);
    const small_values = try allocator.alloc(u128, address_count);
    errdefer allocator.free(small_values);
    const f252_values = try allocator.alloc(memory_mod.F252, 0);
    errdefer allocator.free(f252_values);
    for (address_to_id, 0..) |*encoded, index| encoded.* = .small(@intCast(index));
    @memset(small_values, 0);
    small_values[1] = 11;
    small_values[2] = 12;
    small_values[3] = 5;
    small_values[5] = 20;
    small_values[7] = 22;
    small_values[20] = 123;
    small_values[21] = 456;

    return .{
        .state_transitions = .{
            .initial_state = .{
                .pc = M31.fromCanonical(1),
                .ap = M31.fromCanonical(5),
                .fp = M31.fromCanonical(5),
            },
            .final_state = .{
                .pc = M31.fromCanonical(9),
                .ap = M31.fromCanonical(8),
                .fp = M31.fromCanonical(5),
            },
            .casm_states_by_opcode = adapter.opcodes.CasmStatesByOpcode.init(allocator),
        },
        .memory = .{
            .config = .{},
            .address_to_id = address_to_id,
            .f252_values = f252_values,
            .small_values = small_values,
        },
        .pc_count = 0,
        .public_memory_addresses = try allocator.alloc(u32, 0),
        .builtin_segments = .{},
        .public_segment_context = .{
            true,  false, false, false, false, false,
            false, false, false, false, false,
        },
    };
}

fn claimComponent(label: []const u8, instance: u32, trace_log_size: u32) composition_bundle.Component {
    return .{
        .label = @constCast(label),
        .instance = instance,
        .trace_log_size = trace_log_size,
        .evaluation_log_size = trace_log_size,
        .n_constraints = 1,
        .random_coefficient_offset = 0,
        .trace_spans = undefined,
        .preprocessed_indices = undefined,
        .denominator_inverses = undefined,
        .ext_sources = undefined,
        .parts = undefined,
    };
}

fn claimBundle(components: []composition_bundle.Component) composition_bundle.Bundle {
    return .{
        .allocator = undefined,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = 31,
        .plan_hash = 1,
        .components = components,
    };
}

test "statement bootstrap derives flat claim order from shuffled schedule" {
    var components = [_]composition_bundle.Component{
        claimComponent("memory_id_to_small", 0, 20),
        claimComponent("memory_id_to_big", 1, 19),
        claimComponent("range_check_8", 0, 8),
        claimComponent("add_opcode", 0, 7),
        claimComponent("memory_id_to_big", 0, 18),
    };
    var bundle = claimBundle(&components);
    var flat = try deriveFlatClaimGeometry(std.testing.allocator, &bundle);
    defer flat.deinit();

    try std.testing.expectEqual(@as(usize, 83), flat.component_enable_bits.len);
    try std.testing.expect(flat.component_enable_bits[0]);
    try std.testing.expect(flat.component_enable_bits[49]);
    try std.testing.expect(flat.component_enable_bits[50]);
    try std.testing.expect(flat.component_enable_bits[65]);
    try std.testing.expect(flat.component_enable_bits[67]);
    try std.testing.expectEqualSlices(u32, &.{ 7, 18, 19, 20, 8 }, flat.component_log_sizes);
}

test "statement bootstrap imports canonical Fib25k claim geometry" {
    const components = [_]CanonicalClaimComponent{
        .{ .name = "memory_id_to_small", .log_size = 16 },
        .{ .name = "range_check_9_9" },
        .{ .name = "add_opcode", .log_size = 15 },
        .{ .name = "verify_bitwise_xor_9" },
        .{ .name = "add_opcode_small", .log_size = 16 },
        .{ .name = "add_ap_opcode", .log_size = 4 },
        .{ .name = "assert_eq_opcode", .log_size = 15 },
        .{ .name = "assert_eq_opcode_imm", .log_size = 4 },
        .{ .name = "call_opcode_rel_imm", .log_size = 15 },
        .{ .name = "jnz_opcode_non_taken", .log_size = 4 },
        .{ .name = "jnz_opcode_taken", .log_size = 15 },
        .{ .name = "ret_opcode", .log_size = 15 },
        .{ .name = "verify_instruction", .log_size = 5 },
        .{ .name = "memory_address_to_id", .log_size = 14 },
        .{ .name = "memory_id_to_big", .log_size = 15 },
        .{ .name = "range_check_6" },
        .{ .name = "range_check_8" },
        .{ .name = "range_check_11" },
        .{ .name = "range_check_12" },
        .{ .name = "range_check_18" },
        .{ .name = "range_check_20" },
        .{ .name = "range_check_4_3" },
        .{ .name = "range_check_4_4" },
        .{ .name = "range_check_7_2_5" },
        .{ .name = "range_check_3_6_6_3" },
        .{ .name = "range_check_4_4_4_4" },
        .{ .name = "range_check_3_3_3_3_3" },
        .{ .name = "verify_bitwise_xor_4" },
        .{ .name = "verify_bitwise_xor_7" },
        .{ .name = "verify_bitwise_xor_8" },
    };
    var flat = try deriveFlatClaimGeometryFromCanonical(std.testing.allocator, &components);
    defer flat.deinit();

    try std.testing.expectEqual(@as(usize, 83), flat.component_enable_bits.len);
    try std.testing.expectEqual(@as(usize, 30), std.mem.count(
        bool,
        flat.component_enable_bits,
        &.{true},
    ));
    try std.testing.expect(!flat.component_enable_bits[7]);
    try std.testing.expect(flat.component_enable_bits[8]);
    try std.testing.expect(flat.component_enable_bits[49]);
    try std.testing.expect(!flat.component_enable_bits[50]);
    try std.testing.expectEqualSlices(u32, &.{
        15, 16, 4,  15, 4,  15, 4,  15, 15, 5,
        14, 15, 16, 6,  8,  11, 12, 18, 20, 7,
        8,  18, 14, 18, 16, 15, 8,  14, 16, 18,
    }, flat.component_log_sizes);
}

test "statement bootstrap rejects noncanonical imported claim geometry" {
    const missing_dynamic_log = [_]CanonicalClaimComponent{.{ .name = "add_opcode" }};
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        deriveFlatClaimGeometryFromCanonical(std.testing.allocator, &missing_dynamic_log),
    );

    const wrong_fixed_log = [_]CanonicalClaimComponent{
        .{ .name = "range_check_8", .log_size = 7 },
    };
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        deriveFlatClaimGeometryFromCanonical(std.testing.allocator, &wrong_fixed_log),
    );

    const memory_gap = [_]CanonicalClaimComponent{
        .{ .name = "memory_id_to_big", .instance = 1, .log_size = 15 },
    };
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        deriveFlatClaimGeometryFromCanonical(std.testing.allocator, &memory_gap),
    );
}

test "statement bootstrap rejects ambiguous claim schedules" {
    var duplicate_components = [_]composition_bundle.Component{
        claimComponent("add_opcode", 0, 7),
        claimComponent("add_opcode", 0, 7),
    };
    var duplicate_bundle = claimBundle(&duplicate_components);
    try std.testing.expectError(
        Error.DuplicateClaimComponent,
        deriveFlatClaimGeometry(std.testing.allocator, &duplicate_bundle),
    );

    var gap_components = [_]composition_bundle.Component{
        claimComponent("memory_id_to_big", 1, 19),
    };
    var gap_bundle = claimBundle(&gap_components);
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        deriveFlatClaimGeometry(std.testing.allocator, &gap_bundle),
    );

    var unknown_components = [_]composition_bundle.Component{
        claimComponent("not_a_cairo_claim", 0, 7),
    };
    var unknown_bundle = claimBundle(&unknown_components);
    try std.testing.expectError(
        Error.UnknownClaimComponent,
        deriveFlatClaimGeometry(std.testing.allocator, &unknown_bundle),
    );
}

test "self-derived statement populates transcript recipe inputs without fixtures" {
    const RecordingRecipe = struct {
        const max_words = 128;

        expected_lengths: [ORDINALS.len]usize,
        lengths: [ORDINALS.len]usize = .{0} ** ORDINALS.len,
        storage: [ORDINALS.len][max_words]u32 = .{.{0} ** max_words} ** ORDINALS.len,

        pub fn loadInputWords(self: *@This(), ordinal: u32, input_words: []const u32) !void {
            const index = for (ORDINALS, 0..) |candidate, candidate_index| {
                if (candidate == ordinal) break candidate_index;
            } else return error.MissingRecipe;
            if (input_words.len != self.expected_lengths[index] or input_words.len > max_words)
                return error.BindingSizeMismatch;
            @memcpy(self.storage[index][0..input_words.len], input_words);
            self.lengths[index] = input_words.len;
        }

        fn words(self: *const @This(), ordinal: u32) ?[]const u32 {
            for (ORDINALS, 0..) |candidate, index| {
                if (candidate == ordinal) return self.storage[index][0..self.lengths[index]];
            }
            return null;
        }
    };

    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    var components = [_]composition_bundle.Component{
        claimComponent("memory_id_to_small", 0, 20),
        claimComponent("add_opcode", 0, 7),
        claimComponent("memory_id_to_big", 0, 18),
    };
    var composition = claimBundle(&components);
    var bootstrap = try initFromCompositionSchedule(allocator, .{
        .channel_salt = 7,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .n_queries = 70,
            .log_last_layer_degree_bound = 0,
            .fold_step = 3,
        },
        .composition = &composition,
        .prover_input = &prover_input,
    });
    defer bootstrap.deinit();

    var lengths: [ORDINALS.len]usize = undefined;
    for (ORDINALS, &lengths) |ordinal, *length| length.* = bootstrap.words(ordinal).?.len;
    var recipe = RecordingRecipe{ .expected_lengths = lengths };
    try bootstrap.populateTranscriptRecipeInputs(&recipe);
    for (ORDINALS) |ordinal| {
        try std.testing.expectEqualSlices(u32, bootstrap.words(ordinal).?, recipe.words(ordinal).?);
    }
}

test "compact statement v1 serializes the transcript's authoritative public data" {
    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    var components = [_]composition_bundle.Component{
        claimComponent("memory_id_to_small", 0, 20),
        claimComponent("add_opcode", 0, 7),
        claimComponent("memory_id_to_big", 0, 18),
    };
    var composition = claimBundle(&components);
    const encoded = try encodeCompactStatementV1(allocator, &composition, &prover_input);
    defer allocator.free(encoded);
    var flat = try deriveFlatClaimGeometry(allocator, &composition);
    defer flat.deinit();
    const runtime_encoded = try encodeCompactStatementFromFlatClaimV1(allocator, .{
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
    }, &prover_input);
    defer allocator.free(runtime_encoded);
    try std.testing.expectEqualSlices(u8, encoded, runtime_encoded);

    try std.testing.expectEqualSlices(u8, &compact_statement_magic, encoded[0..8]);
    try std.testing.expectEqual(compact_statement_version, std.mem.readInt(u16, encoded[8..10], .little));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, encoded[16..20], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[48..52], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[52..56], .little));
    try std.testing.expectEqual(@as(u32, 83), std.mem.readInt(u32, encoded[56..60], .little));
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, encoded[60..64], .little));
    try std.testing.expectEqual(@as(usize, 788), encoded.len);

    const first_segment = compact_statement_header_bytes;
    for ([_]u32{ 1, 5, 20, 7, 22 }, 0..) |expected, index| {
        const offset = first_segment + index * 4;
        try std.testing.expectEqual(expected, std.mem.readInt(u32, encoded[offset..][0..4], .little));
    }
    const first_program = compact_statement_header_bytes + adapter.N_PUBLIC_SEGMENTS * 5 * 4;
    for ([_]u32{ 1, 11, 0, 0, 0, 0, 0, 0, 0 }, 0..) |expected, index| {
        const offset = first_program + index * 4;
        try std.testing.expectEqual(expected, std.mem.readInt(u32, encoded[offset..][0..4], .little));
    }
}

test "compact statement v1 rejects noncanonical runtime flat geometry" {
    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    var enable_bits = [_]bool{false} ** claim_registry.enable_slot_count;
    enable_bits[67] = true;
    const wrong_fixed_log = [_]u32{7};
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        encodeCompactStatementFromFlatClaimV1(allocator, .{
            .component_enable_bits = &enable_bits,
            .component_log_sizes = &wrong_fixed_log,
        }, &prover_input),
    );

    var memory_gap = [_]bool{false} ** claim_registry.enable_slot_count;
    memory_gap[50] = true;
    const memory_log = [_]u32{15};
    try std.testing.expectError(
        Error.InvalidClaimGeometry,
        encodeCompactStatementFromFlatClaimV1(allocator, .{
            .component_enable_bits = &memory_gap,
            .component_log_sizes = &memory_log,
        }, &prover_input),
    );
}

test "compact statement v1 matches an independently encoded SN2 statement" {
    const allocator = std.testing.allocator;
    const expected_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_COMPACT_STATEMENT",
    ) catch return error.SkipZigTest;
    defer allocator.free(expected_path);
    const expected = try std.fs.cwd().readFileAlloc(allocator, expected_path, 16 * 1024 * 1024);
    defer allocator.free(expected);
    var prover_input = try adapter.adapted_input.readFile(
        allocator,
        "/private/tmp/SN_PIE_2.generic.stwzcpi",
    );
    defer prover_input.deinit(allocator);
    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();
    const actual = try encodeCompactStatementV1(allocator, &composition, &prover_input);
    defer allocator.free(actual);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "statement bootstrap derives canonical shapes and roots" {
    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    const enable = [_]bool{ true, false, true };
    const logs = [_]u32{ 4, 5 };
    var bootstrap = try init(allocator, .{
        .channel_salt = 7,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .n_queries = 70,
            .log_last_layer_degree_bound = 0,
            .fold_step = 3,
        },
        .component_enable_bits = &enable,
        .component_log_sizes = &logs,
        .prover_input = &prover_input,
    });
    defer bootstrap.deinit();

    try std.testing.expectEqualSlices(u32, &.{ 7, 0, 0, 0 }, bootstrap.ordinal_1);
    try std.testing.expectEqualSlices(u32, &.{ 3, 0, 0, 0 }, bootstrap.ordinal_10);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 1, 0 }, bootstrap.ordinal_11);
    try std.testing.expectEqualSlices(u32, &.{ 4, 5, 0, 0 }, bootstrap.ordinal_12);
    try std.testing.expectEqualSlices(u32, &.{ 2, 0, 0, 0 }, bootstrap.ordinal_13);
    try std.testing.expectEqual(@as(usize, 56), bootstrap.ordinal_14.len);
    try std.testing.expectEqualSlices(u32, &.{ 1, 5, 5, 9, 8, 5 }, bootstrap.ordinal_14[0..6]);
    try std.testing.expectEqualSlices(u32, &.{ 5, 20, 7, 22 }, bootstrap.ordinal_14[6..10]);
    try std.testing.expectEqualSlices(u32, &.{ 3, 4, 20, 21, 1, 2 }, bootstrap.ordinal_14[50..56]);
    try std.testing.expectEqual(@as(usize, 8), bootstrap.ordinal_15.len);
    try std.testing.expectEqual(@as(usize, 8), bootstrap.ordinal_16.len);
    try std.testing.expect(bootstrap.words(3) == null);
}

test "statement bootstrap roots and public IDs respond to memory mutation" {
    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    const enable = [_]bool{true};
    const logs = [_]u32{4};
    const statement = StatementBootstrapInput{
        .channel_salt = 0,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .n_queries = 70,
            .log_last_layer_degree_bound = 0,
            .fold_step = 3,
        },
        .component_enable_bits = &enable,
        .component_log_sizes = &logs,
        .prover_input = &prover_input,
    };
    var before = try init(allocator, statement);
    defer before.deinit();

    prover_input.memory.small_values[20] += 1;
    var output_mutated = try init(allocator, statement);
    defer output_mutated.deinit();
    try std.testing.expect(!std.mem.eql(u32, before.ordinal_15, output_mutated.ordinal_15));
    try std.testing.expectEqualSlices(u32, before.ordinal_16, output_mutated.ordinal_16);

    prover_input.memory.address_to_id[20] = .small(22);
    var id_mutated = try init(allocator, statement);
    defer id_mutated.deinit();
    try std.testing.expect(!std.mem.eql(u32, output_mutated.ordinal_14, id_mutated.ordinal_14));
}

test "statement bootstrap rejects malformed public memory shape" {
    const allocator = std.testing.allocator;
    var prover_input = try syntheticInput(allocator);
    defer prover_input.deinit(allocator);
    const enable = [_]bool{true};
    const logs = [_]u32{4};
    const statement = StatementBootstrapInput{
        .channel_salt = 0,
        .pcs = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .n_queries = 70,
            .log_last_layer_degree_bound = 0,
            .fold_step = 3,
        },
        .component_enable_bits = &enable,
        .component_log_sizes = &logs,
        .prover_input = &prover_input,
    };

    prover_input.public_segment_context[0] = false;
    try std.testing.expectError(Error.InvalidPublicSegmentContext, init(allocator, statement));
    prover_input.public_segment_context[0] = true;
    prover_input.memory.small_values[3] = 6;
    try std.testing.expectError(Error.InvalidSafeCall, init(allocator, statement));
}

fn jsonWords(allocator: std.mem.Allocator, inputs: std.json.ObjectMap, ordinal: u32) ![]u32 {
    var key_buffer: [8]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buffer, "{}", .{ordinal});
    const value = inputs.get(key) orelse return error.MissingOrdinal;
    const array = switch (value) {
        .array => |items| items,
        else => return error.InvalidOrdinalWords,
    };
    const result = try allocator.alloc(u32, array.items.len);
    errdefer allocator.free(result);
    for (array.items, result) |item, *word| {
        const integer = switch (item) {
            .integer => |number| number,
            else => return error.InvalidOrdinalWords,
        };
        word.* = std.math.cast(u32, integer) orelse return error.InvalidOrdinalWords;
    }
    return result;
}

test "statement bootstrap matches actual SN PIE 1 through 4 fixtures" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(allocator, "STWO_ZIG_TEST_SN_PIE_STATEMENT_FIXTURES") catch
        return error.SkipZigTest;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;

    for (1..5) |pie_number| {
        var fixture_path_buffer: [128]u8 = undefined;
        const fixture_path = try std.fmt.bufPrint(
            &fixture_path_buffer,
            "/private/tmp/SN_PIE_{}.fold3.reference.transcript-inputs.json",
            .{pie_number},
        );
        const encoded = try std.fs.cwd().readFileAlloc(allocator, fixture_path, 16 * 1024 * 1024);
        defer allocator.free(encoded);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
        defer parsed.deinit();
        const inputs_value = parsed.value.object.get("inputs") orelse return error.MissingInputs;
        const inputs = switch (inputs_value) {
            .object => |object| object,
            else => return error.InvalidInputs,
        };

        var adapted_path_buffer: [96]u8 = undefined;
        const adapted_path = try std.fmt.bufPrint(
            &adapted_path_buffer,
            "/private/tmp/SN_PIE_{}.generic.stwzcpi",
            .{pie_number},
        );
        var prover_input = try adapter.adapted_input.readFile(allocator, adapted_path);
        defer prover_input.deinit(allocator);

        var composition_path_buffer: [96]u8 = undefined;
        const composition_path = if (pie_number == 2)
            "vectors/cairo/sn_pie_2_composition.bin"
        else
            try std.fmt.bufPrint(
                &composition_path_buffer,
                "/private/tmp/SN_PIE_{}.composition.bin",
                .{pie_number},
            );
        var composition = try composition_bundle.Bundle.readFile(allocator, composition_path);
        defer composition.deinit();

        var bootstrap = try initFromCompositionSchedule(allocator, .{
            .channel_salt = 0,
            .pcs = .{
                .pow_bits = 26,
                .log_blowup_factor = 1,
                .n_queries = 70,
                .log_last_layer_degree_bound = 0,
                .fold_step = 3,
            },
            .composition = &composition,
            .prover_input = &prover_input,
        });
        defer bootstrap.deinit();

        for (ORDINALS) |ordinal| {
            const expected = try jsonWords(allocator, inputs, ordinal);
            defer allocator.free(expected);
            try std.testing.expectEqualSlices(u32, expected, bootstrap.words(ordinal).?);
        }
    }
}
