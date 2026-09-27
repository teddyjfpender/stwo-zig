const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const sources = @import("block_v5_initial_sources_v1.zig");
const source_receiver = @import("block_v5_initial_source_receiver_v1.zig");
const receiver = @import("block_v5_initial_memory_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard = @import("block_memory_range_shard_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const transition = @import("../air/block/memory_transition.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");

pub const layout = @import("../runner/memory_state.zig").MemoryLayout{
    .program_base = 0x1000,
    .program_end = 0x2000,
    .data_base = 0x2000,
    .data_end = 0x4000,
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
pub const input = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
pub const input_value: u32 = 0x78563412;
pub const initial = [_]transition.Transition{
    .{ .space = 0, .address = 1, .clock = 1, .before = 7, .after = 8 },
    .{ .space = 1, .address = 0x2000, .clock = 2, .before = 9, .after = 10 },
    .{ .space = 1, .address = 0x2004, .clock = 3, .before = 0, .after = 1 },
    .{ .space = 1, .address = 0x6000, .clock = 4, .before = input_value, .after = input_value + 1 },
};

pub fn recordWord(address: u32, value: u32) [8]u8 {
    var result: [8]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], address, .little);
    std.mem.writeInt(u32, result[4..8], value, .little);
    return result;
}
pub fn recordTouch(space: u8, address: u32, value: u32) [9]u8 {
    var result: [9]u8 = undefined;
    result[0] = space;
    std.mem.writeInt(u32, result[1..5], address, .little);
    std.mem.writeInt(u32, result[5..9], value, .little);
    return result;
}
pub fn writeFile(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(name, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
}
pub const OpenFiles = struct {
    files: sources.Files,
    pub fn open(dir: std.fs.Dir) !OpenFiles {
        const input_file = try dir.openFile("input.bin", .{});
        errdefer input_file.close();
        const rw_file = try dir.openFile("rw.bin", .{});
        errdefer rw_file.close();
        const touches_file = try dir.openFile("touches.bin", .{});
        return .{ .files = .{ .input_words = input_file, .rw_words = rw_file, .first_touches = touches_file } };
    }
    pub fn deinit(self: *OpenFiles) void {
        self.files.input_words.close();
        self.files.rw_words.close();
        self.files.first_touches.close();
    }
};
pub fn sourcePins(input_bytes: []const u8, rw_bytes: []const u8, touch_bytes: []const u8) !sources.Pins {
    const leaves = [_]tree.Leaf{
        .{ .index = try tree.memoryIndex(0x2000), .value = 9 },
        .{ .index = try tree.memoryIndex(0x6000), .value = input_value },
    };
    const hasher = tree.TreeHasher.init(.memory);
    var registers: [32]u32 = @splat(0);
    registers[1] = 7;
    return .{
        .layout = layout,
        .initial_rw_root = (try hasher.root(&leaves)).bytes,
        .initial_registers = registers,
        .public_input_sha256 = sources.sha256(&input),
        .public_input_len = input.len,
        .input_words = .{ .sha256 = sources.sha256(input_bytes), .records = @intCast(input_bytes.len / 8) },
        .rw_words = .{ .sha256 = sources.sha256(rw_bytes), .records = @intCast(rw_bytes.len / 8) },
        .first_touches = .{ .sha256 = sources.sha256(touch_bytes), .records = @intCast(touch_bytes.len / 9) },
    };
}
pub fn sealPins(source_pins: sources.Pins, config: core.pcs.PcsConfig) !v5.Pins {
    var counts: [v5.family_count]u32 = @splat(0);
    inline for ([_]v5.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .memory_range }) |family|
        counts[@intFromEnum(family) - 1] = 1;
    return .{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .native_template_id = @splat(3),
        .program_root = @splat(4),
        .program_plan_digest = @splat(5),
        .memory_plan_digest = @splat(6),
        .initial_source_plan_digest = try source_pins.digest(),
        .config = config,
        .counts = counts,
    };
}
fn entriesFor(memory_roots: [2][32]u8, table_roots: [2][32]u8, range_digest: [32]u8) [6]v5.Entry {
    return .{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(20), .roots = memory_roots },
        .{ .family = .memory_range, .index = 0, .instance_id = range_digest, .roots = table_roots },
    };
}

test "block-v5 initial source files, layout and seal mutation reject before challenge" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input_record = recordWord(0x6000, input_value);
    const rw_record = recordWord(0x2000, 9);
    const touches = [_][9]u8{
        recordTouch(0, 1, 7),      recordTouch(1, 0x2000, 9),
        recordTouch(1, 0x2004, 0), recordTouch(1, 0x6000, input_value),
    };
    const touch_bytes = std.mem.sliceAsBytes(&touches);
    try writeFile(tmp.dir, "input.bin", &input_record);
    try writeFile(tmp.dir, "rw.bin", &rw_record);
    try writeFile(tmp.dir, "touches.bin", touch_bytes);
    var files = try OpenFiles.open(tmp.dir);
    defer files.deinit();
    const pins = try sourcePins(&input_record, &rw_record, touch_bytes);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const v5_pins = try sealPins(pins, config);
    const entries = entriesFor(.{ @splat(21), @splat(22) }, .{ @splat(23), @splat(24) }, @splat(25));
    const sealed = try v5.seal(v5_pins, &entries);
    const claim = try source_receiver.check(a, pins, &input, files.files, v5_pins, &entries, sealed);
    try std.testing.expectEqual(@as(u64, 4), claim.first_touch_count);
    try std.testing.expectEqual(@as(u64, 1), claim.input_touches);
    try std.testing.expectEqual(@as(u64, 2), claim.rw_touches);

    var wrong_layout = pins;
    wrong_layout.layout.program_end = 0x2100;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, wrong_layout.digest());
    var wrong_plan = v5_pins;
    wrong_plan.initial_source_plan_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5InitialSourcePlan, source_receiver.check(a, pins, &input, files.files, wrong_plan, &entries, sealed));
    const wrong_input = [_]u8{ 0, 0, 0, 0 };
    try std.testing.expectError(error.UntrustedV5PublicInput, source_receiver.check(a, pins, &wrong_input, files.files, v5_pins, &entries, sealed));

    var reordered = touches;
    const swap = reordered[1];
    reordered[1] = reordered[2];
    reordered[2] = swap;
    try writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&reordered));
    var changed = try OpenFiles.open(tmp.dir);
    defer changed.deinit();
    var reordered_pins = pins;
    reordered_pins.first_touches.sha256 = sources.sha256(std.mem.sliceAsBytes(&reordered));
    const reordered_v5 = try sealPins(reordered_pins, config);
    const reordered_seal = try v5.seal(reordered_v5, &entries);
    try std.testing.expectError(error.DuplicateOrUnsortedV5FirstTouch, source_receiver.check(a, reordered_pins, &input, changed.files, reordered_v5, &entries, reordered_seal));
    try std.testing.expectError(error.UntrustedV5InitialSourceBytes, source_receiver.check(a, pins, &input, changed.files, v5_pins, &entries, sealed));

    var bad_root = pins;
    bad_root.initial_rw_root[0] ^= 1;
    const bad_root_v5 = try sealPins(bad_root, config);
    const bad_root_seal = try v5.seal(bad_root_v5, &entries);
    try writeFile(tmp.dir, "touches.bin", touch_bytes);
    try std.testing.expectError(error.InvalidV5InitialRwRoot, source_receiver.check(a, bad_root, &input, files.files, bad_root_v5, &entries, bad_root_seal));

    var duplicated = touches;
    duplicated[2] = duplicated[1];
    try writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&duplicated));
    var duplicate_pins = pins;
    duplicate_pins.first_touches.sha256 = sources.sha256(std.mem.sliceAsBytes(&duplicated));
    const duplicate_v5 = try sealPins(duplicate_pins, config);
    const duplicate_seal = try v5.seal(duplicate_v5, &entries);
    try std.testing.expectError(error.DuplicateOrUnsortedV5FirstTouch, source_receiver.check(a, duplicate_pins, &input, files.files, duplicate_v5, &entries, duplicate_seal));

    var program_touch = touches;
    program_touch[1] = recordTouch(1, 0x1000, 9);
    try writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&program_touch));
    var program_pins = pins;
    program_pins.first_touches.sha256 = sources.sha256(std.mem.sliceAsBytes(&program_touch));
    const program_v5 = try sealPins(program_pins, config);
    const program_seal = try v5.seal(program_v5, &entries);
    try std.testing.expectError(error.ProgramTouchRequiresVerifiedRomReceipt, source_receiver.check(a, program_pins, &input, files.files, program_v5, &entries, program_seal));
}

test "block-v5 initial source closes freshly verified sorted memory and range proof" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input_record = recordWord(0x6000, input_value);
    const rw_record = recordWord(0x2000, 9);
    const touches = [_][9]u8{
        recordTouch(0, 1, 7),      recordTouch(1, 0x2000, 9),
        recordTouch(1, 0x2004, 0), recordTouch(1, 0x6000, input_value),
    };
    const touch_bytes = std.mem.sliceAsBytes(&touches);
    try writeFile(tmp.dir, "input.bin", &input_record);
    try writeFile(tmp.dir, "rw.bin", &rw_record);
    try writeFile(tmp.dir, "touches.bin", touch_bytes);
    var files = try OpenFiles.open(tmp.dir);
    defer files.deinit();
    const pins = try sourcePins(&input_record, &rw_record, touch_bytes);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = initial.len, .first = initial[0], .last = initial[initial.len - 1] }, initial.len, 8, null);
    var trace = try trace_mod.Trace.init(a, claim);
    defer trace.deinit();
    for (initial) |event| try trace.append(event);
    try trace.seal();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var memory_first = try instance.ForBackend(Cpu).commitFirstRound(a, &trace, &counter, 0, config);
    defer memory_first.deinit(a);
    var range_plan = try shard.plan(a, &.{claim}, initial.len);
    defer range_plan.deinit(a);
    var table_first = try table.ForBackend(Cpu).commitFirstRound(a, &counter, range_plan.shards[0], config);
    defer table_first.deinit(a);
    const entries = entriesFor(memory_first.roots, table_first.roots, range_plan.digest);
    const v5_pins = try sealPins(pins, config);
    const sealed = try v5.seal(v5_pins, &entries);
    const adapter = receiver.MemorySeal{ .source = sealed, .memory_instance_count = 1, .range_shard_digest = range_plan.digest };
    var memory_proof = try instance.ForBackend(Cpu).prove(a, &memory_first, &trace, adapter, 0, memory_first.roots);
    var table_proof = try table.ForBackend(Cpu).prove(a, &table_first, &counter, range_plan.shards[0], adapter, table_first.roots);
    const accepted = try receiver.verifyOne(Cpu, a, .{
        .sources = pins,
        .v5_pins = v5_pins,
        .expected_seal_digest = sealed.digest,
        .first_round = &entries,
        .memory_claim = claim,
        .expected_memory_roots = memory_first.roots,
        .expected_table_roots = table_first.roots,
    }, .{ .memory_proof = &memory_proof, .table_proof = &table_proof, .public_input = &input, .files = files.files }, sealed);
    try std.testing.expectEqual(@as(u64, 4), accepted.event_count);
    try std.testing.expectEqual(@as(u64, 4), accepted.first_touch_count);
    try std.testing.expectEqualDeep(sealed.digest, (try v5.seal(v5_pins, &entries)).digest);
}
