const std = @import("std");
const core = @import("stwo_core");
const writer = @import("block_v5_memory_source_writer_v1.zig");
const sparse = @import("block_v5_sparse_state_stream_v1.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const spool = @import("../air/block/memory_spool.zig");
const transition = @import("../air/block/memory_transition.zig");
const replay = @import("block_memory_replay.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const reg = @import("block_v5_register_endpoints_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const layout = @import("../runner/memory_state.zig").MemoryLayout{
    .program_base = 0x1000,
    .program_end = 0x2000,
    .data_base = 0x2000,
    .data_end = 0x5000,
    .stack_bottom = 0x8000,
    .stack_top = 0x9000,
    .io_base = 0x6000,
    .io_end = 0x7000,
    .input_base = 0x6000,
    .input_end = 0x6100,
    .output_len_addr = 0x6200,
    .output_data_addr = 0x6204,
    .output_base = 0x6200,
    .output_end = 0x7000,
};
const public_input = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a };
const words = [_]replay.InitialWord{
    .{ .address = 0x1000, .value = 0x13, .source = .program_root },
    .{ .address = 0x2000, .value = 7, .source = .rw_root },
    .{ .address = 0x2004, .value = 11, .source = .rw_root },
    .{ .address = 0x6000, .value = 0x78563412, .source = .public_input },
    .{ .address = 0x8000, .value = 17, .source = .rw_root },
};
const initial_leaves = [_]tree.Leaf{
    .{ .index = 0x2000 / 4, .value = 7 },
    .{ .index = 0x2004 / 4, .value = 11 },
    .{ .index = 0x6000 / 4, .value = 0x78563412 },
    .{ .index = 0x6004 / 4, .value = 0x9a },
    .{ .index = 0x8000 / 4, .value = 17 },
};
const Source = struct {
    sorted: *spool.Spool,
    wrong_before: bool = false,
    fn open(ctx: *anyopaque) anyerror!transition.Reader {
        const self: *Source = @ptrCast(@alignCast(ctx));
        return .{ .sorted = try self.sorted.reopenSorted(), .initial = .{ .context = self, .load = load } };
    }
    fn load(ctx: *anyopaque, space: u1, address: u32) anyerror!u32 {
        const self: *Source = @ptrCast(@alignCast(ctx));
        if (space == 0 and address == 1) return if (self.wrong_before) 6 else 5;
        for (words) |word| if (word.address == address) return word.value;
        return if (address == 0x6004) 0x9a else 0;
    }
    fn interface(self: *Source) writer.SortedSource {
        return .{ .context = self, .open = open };
    }
};
fn input() !writer.Input {
    const hasher = tree.TreeHasher.init(.memory);
    var final_leaves: [604]tree.Leaf = undefined;
    final_leaves[0] = .{ .index = 0x2004 / 4, .value = 11 };
    for (0..600) |index| final_leaves[index + 1] = .{ .index = (0x3000 + 4 * @as(u32, @intCast(index))) / 4, .value = @intCast(index + 1) };
    final_leaves[601] = .{ .index = 0x6000 / 4, .value = 44 };
    final_leaves[602] = .{ .index = 0x6004 / 4, .value = 0x9a };
    final_leaves[603] = .{ .index = 0x8000 / 4, .value = 17 };
    var first: [32]u32 = @splat(0);
    first[1] = 5;
    first[2] = 99;
    var last = first;
    last[1] = 13;
    return .{ .layout = layout, .initial_words = &words, .public_input = &public_input, .initial_registers = first, .expected_final_registers = last, .expected_initial_rw_root = (try hasher.root(&initial_leaves)).bytes, .expected_final_rw_root = (try hasher.root(&final_leaves)).bytes, .expected_total_events = 604, .caps = .{ .max_initial_words = 10, .max_events = 700, .max_first_touches = 700, .max_file_bytes = 20_000 } };
}

test "RW-only source writer preserves untouched full image with zero RAM events" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var stream = try spool.Spool.init(std.testing.allocator, temporary.dir, 8);
    defer stream.deinit();
    var empty = try stream.finishEmpty();
    empty.deinit();
    var source = Source{ .sorted = &stream };
    var pins = try input();
    pins.register_custody_mode = 1;
    pins.register_window_plan_digest = @splat(17);
    pins.expected_total_events = 0;
    pins.expected_final_rw_root = pins.expected_initial_rw_root;
    var result = try writer.write(temporary.dir, pins, source.interface());
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 0), result.event_count);
    try std.testing.expectEqual(@as(u64, 0), result.initial_pins.first_touches.records);
    try std.testing.expectEqual(@as(u64, 0), result.endpoint_file_pin.records);
    try std.testing.expectEqualSlices(u8, &pins.expected_initial_rw_root, &result.final_rw_root);
    try std.testing.expectEqualSlices(u8, &pins.register_window_plan_digest, &(try result.registerPlanDigest()));
    // The old sorted-register placeholder is never a mode1 receipt.
    try std.testing.expectEqual(@as(u32, 0), result.register_pins.first_touch_mask);
    try std.testing.expectEqualSlices(u32, &pins.initial_registers, &result.register_pins.final_registers);
}

test "RW-only source writer rejects register stream and independently wrong roots" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var stream = try spool.Spool.init(std.testing.allocator, temporary.dir, 8);
    defer stream.deinit();
    try stream.append(.{ .space = 0, .address = 1, .clock = 3, .value = 13 });
    var sorted = try stream.finish();
    sorted.deinit();
    var source = Source{ .sorted = &stream };
    var pins = try input();
    pins.register_custody_mode = 1;
    pins.register_window_plan_digest = @splat(17);
    pins.expected_total_events = 1;
    pins.expected_final_rw_root = pins.expected_initial_rw_root;
    try std.testing.expectError(error.MixedV5RegisterCustody, writer.write(temporary.dir, pins, source.interface()));
    pins.expected_initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5WriterInitialRoot, writer.write(temporary.dir, pins, source.interface()));
    pins.expected_initial_rw_root[0] ^= 1;
    // Use a separate truly empty replay so final-root failure is not hidden
    // by the earlier space/census guard.
    var empty_dir = std.testing.tmpDir(.{});
    defer empty_dir.cleanup();
    var empty_stream = try spool.Spool.init(std.testing.allocator, empty_dir.dir, 8);
    defer empty_stream.deinit();
    var empty = try empty_stream.finishEmpty();
    empty.deinit();
    source.sorted = &empty_stream;
    pins.expected_total_events = 0;
    pins.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5WriterFinalRoot, writer.write(empty_dir.dir, pins, source.interface()));
    pins.expected_final_rw_root[0] ^= 1;
    pins.register_window_plan_digest = @splat(0);
    try std.testing.expectError(error.MissingV5RegisterWindowPlan, writer.write(empty_dir.dir, pins, source.interface()));
}
fn append(sorted: *spool.Spool) !void {
    // Deliberately unsorted append order exercises the real spool sorter.
    try sorted.append(.{ .space = 1, .address = 0x6000, .clock = (@as(u64, 1) << 48) + 4001, .value = 44 });
    for (0..600) |index| try sorted.append(.{ .space = 1, .address = 0x3000 + 4 * @as(u32, @intCast(index)), .clock = (@as(u64, 1) << 48) + 4 * index + 1, .value = @intCast(index + 1) });
    try sorted.append(.{ .space = 0, .address = 1, .clock = 2, .value = 13 });
    try sorted.append(.{ .space = 1, .address = 0x2000, .clock = 3, .value = 0 });
    try sorted.append(.{ .space = 0, .address = 1, .clock = 1, .value = 9 });
    var reader = try sorted.finish();
    reader.deinit();
}
fn assertRemoved(dir: std.fs.Dir) !void {
    for (writer.filenames) |name| try std.testing.expectError(error.FileNotFound, dir.openFile(name, .{}));
}

test "block-v5 production source writer preserves full state beyond 256 events with overlapping RW ranges" {
    const a = std.testing.allocator;
    var spool_dir = std.testing.tmpDir(.{});
    defer spool_dir.cleanup();
    var sorted = try spool.Spool.init(a, spool_dir.dir, 16);
    defer sorted.deinit();
    try append(&sorted);
    var source = Source{ .sorted = &sorted };
    var supplied = try input();
    // Canonical ELF IO extends one control byte across output_end into the
    // adjacent stack. Both ranges retain exactly the same RW-root authority.
    supplied.layout.output_end = supplied.layout.stack_bottom;
    supplied.layout.io_end = supplied.layout.output_end + 1;
    _ = try writer.validateInitial(supplied);
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var result = try writer.write(dir.dir, supplied, source.interface());
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 604), result.event_count);
    try std.testing.expectEqual(@as(u64, 2), result.initial_pins.input_words.records);
    try std.testing.expectEqual(@as(u64, 3), result.initial_pins.rw_words.records);
    try std.testing.expectEqual(@as(u64, 603), result.initial_pins.first_touches.records);
    try std.testing.expectEqual(@as(u64, 602), result.endpoint_file_pin.records);
    try std.testing.expectEqual(@as(u32, 2), result.register_pins.first_touch_mask);
    try std.testing.expectEqual(@as(u64, 2), result.register_pins.final_clocks[1]);
    try std.testing.expectEqual(@as(u64, 15_099), result.file_bytes);
    try std.testing.expectEqualDeep(supplied.expected_initial_rw_root, result.initial_pins.initial_rw_root);
    try std.testing.expectEqualDeep(supplied.expected_final_rw_root, result.final_rw_root);
    // Existing production checkers consume the exact pinned bytes. They return
    // public sums only; no sorted proof or complete authority is fabricated.
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |family| counts[@intFromEnum(family) - 1] = 1;
    const endpoint_pins = result.endpointPins(@splat(5));
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(6), .memory_plan_digest = @splat(5), .initial_source_plan_digest = try result.initial_pins.digest(), .expected_final_rw_root = result.final_rw_root, .rw_endpoint_plan_digest = try endpoint_pins.digest(), .register_endpoint_plan_digest = try result.register_pins.digest(), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
    };
    const sealed = try seal.seal(pins, &entries);
    const first = try @import("block_v5_initial_source_receiver_v1.zig").check(a, result.initial_pins, &public_input, result.files().initial, pins, &entries, sealed);
    const final = try endpoints.check(a, endpoint_pins, &public_input, result.files(), pins, &entries, sealed);
    const register = try reg.check(a, result.register_pins, result.initial_pins, result.files().initial.first_touches, sealed, pins, &entries);
    try std.testing.expectEqual(@as(u64, 603), first.first_touch_count);
    try std.testing.expectEqual(@as(u64, 602), final.count);
    try std.testing.expectEqual(@as(u64, 1), final.input_endpoints);
    try std.testing.expectEqual(@as(u64, 1), register.count);
    const bytes = try initial.readPinned(a, result.files().endpoints, result.endpoint_file_pin, 16);
    defer a.free(bytes);
    var expected = bytes[0];
    expected ^= 1;
    try result.files().endpoints.pwriteAll(&.{expected}, 0);
    try std.testing.expectError(error.UntrustedV5InitialSourceBytes, endpoints.check(a, endpoint_pins, &public_input, result.files(), pins, &entries, sealed));
}

test "block-v5 production source writer rejects roots caps first values and changed registers" {
    const a = std.testing.allocator;
    var spool_dir = std.testing.tmpDir(.{});
    defer spool_dir.cleanup();
    var sorted = try spool.Spool.init(a, spool_dir.dir, 16);
    defer sorted.deinit();
    try append(&sorted);
    var source = Source{ .sorted = &sorted };
    const supplied = try input();
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var wrong = supplied;
    wrong.expected_initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5WriterInitialRoot, writer.write(dir.dir, wrong, source.interface()));
    try assertRemoved(dir.dir);
    wrong = supplied;
    wrong.expected_final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5WriterFinalRoot, writer.write(dir.dir, wrong, source.interface()));
    try assertRemoved(dir.dir);
    wrong = supplied;
    wrong.caps.max_file_bytes = 20;
    try std.testing.expectError(error.V5SourceFileCapExceeded, writer.write(dir.dir, wrong, source.interface()));
    try assertRemoved(dir.dir);
    wrong = supplied;
    wrong.caps.max_workspace_bytes = writer.WORKSPACE_BOUND_BYTES - 1;
    try std.testing.expectError(error.V5SourceFileCapExceeded, writer.write(dir.dir, wrong, source.interface()));
    source.wrong_before = true;
    try std.testing.expectError(error.InvalidV5WriterFirstTouch, writer.write(dir.dir, supplied, source.interface()));
    try assertRemoved(dir.dir);
    source.wrong_before = false;
    wrong = supplied;
    wrong.expected_final_registers[2] += 1;
    try std.testing.expectError(error.UntouchedV5RegisterEndpointChanged, writer.write(dir.dir, wrong, source.interface()));
    try assertRemoved(dir.dir);
    wrong = supplied;
    wrong.expected_total_events -= 1;
    try std.testing.expectError(error.InvalidV5WriterEventCensus, writer.write(dir.dir, wrong, source.interface()));
    try assertRemoved(dir.dir);
}

test "block-v5 streaming sparse roots reuse canonical topology and reject malformed streams" {
    const Cursor = struct {
        leaves: []const tree.Leaf,
        at: usize = 0,
        fail_at: ?usize = null,
        pub fn next(self: *@This()) !?tree.Leaf {
            if (self.fail_at != null and self.at == self.fail_at.?) return error.InjectedSparseReadFailure;
            if (self.at == self.leaves.len) return null;
            defer self.at += 1;
            return self.leaves[self.at];
        }
    };
    var cursor = Cursor{ .leaves = &initial_leaves };
    const hasher = tree.TreeHasher.init(.memory);
    try std.testing.expectEqualDeep(try hasher.root(&initial_leaves), try sparse.root(&cursor, initial_leaves.len));
    cursor = .{ .leaves = &initial_leaves, .fail_at = 2 };
    try std.testing.expectError(error.InjectedSparseReadFailure, sparse.root(&cursor, initial_leaves.len));
    cursor = .{ .leaves = &initial_leaves };
    try std.testing.expectError(error.InvalidV5SparseStateStream, sparse.root(&cursor, 2));
    const duplicated = [_]tree.Leaf{ initial_leaves[0], initial_leaves[0] };
    cursor = .{ .leaves = &duplicated };
    try std.testing.expectError(error.InvalidV5SparseStateStream, sparse.root(&cursor, 2));
}
