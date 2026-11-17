//! Owned custody, borrowing, canonical wire and snapshot regression cases.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const witness_codes = @import("witness_codes.zig");

const runner = frontend.runner;
const Snapshot = runner.memory_state.Snapshot;

const authority_owner = @import("authority.zig");
const Identity = authority_owner.Identity;
const InputFile = authority_owner.InputFile;
const Options = authority_owner.Options;
const digestWithNewline = authority_owner.digestWithNewline;
const capture_owner = @import("capture.zig");
const Call = capture_owner.Call;
const readGuestBytes = capture_owner.readGuestBytes;
const observation_owner = @import("observation.zig");
const callWire = observation_owner.callWire;
const witnessCodeWire = observation_owner.witnessCodeWire;

test "options require every exact custody input" {
    const args = [_][]const u8{
        "--cargo-lock",                "a", "--elf",             "b", "--execution-journal",       "c",
        "--function-value-evidence",   "d", "--input",           "e", "--nm-map",                  "f",
        "--observer-semantics-source", "g", "--observer-source", "h", "--observer-witness-source", "i",
        "--pc-observation",            "j", "--revm-source",     "j", "--segment-count",           "31",
    };
    const options = try Options.parse(&args);
    try std.testing.expectEqual(@as(u32, 31), options.segment_count);
}

test "input identity borrows digest storage from its owner" {
    var bytes = [_]u8{0x42};
    var path = [_]u8{ '/', 'x' };
    var input = InputFile{
        .bytes = &bytes,
        .path = &path,
        .sha256 = [_]u8{0x11} ** 32,
        .sha256_hex = [_]u8{'1'} ** 64,
    };
    const identity = input.identity();
    try std.testing.expectEqual(
        @intFromPtr(input.sha256_hex[0..].ptr),
        @intFromPtr(identity.sha256.ptr),
    );
    try std.testing.expectEqualStrings(&input.sha256_hex, identity.sha256);
}

test "call wire borrows digest and opcode storage from retained call" {
    var opcode_positions = [_]u32{ 0, 2 };
    var call = Call{
        .analysis = .{
            .bitmap_bytes = 1,
            .eof_immediate_padding = 1,
            .jumpdest_count = 0,
            .opcode_positions = &opcode_positions,
            .push_count = 1,
            .push_overflow = 0,
            .total_padding = 1,
        },
        .authority = .{
            .bytes_struct_pointer = 1,
            .entry_clock = 2,
            .entry_segment_index = 3,
            .length = 4,
            .length_clock = 5,
            .observation_segment_index = 6,
            .pointer_clock = 7,
            .source_pointer = 8,
            .witness_code_index = 9,
        },
        .source_bytes_sha256 = [_]u8{0x11} ** 32,
        .source_bytes_sha256_hex = [_]u8{'1'} ** 64,
    };
    const wire = callWire(&call, 0, 2);
    try std.testing.expectEqual(
        @intFromPtr(call.source_bytes_sha256_hex[0..].ptr),
        @intFromPtr(wire.source_bytes_sha256.ptr),
    );
    try std.testing.expectEqual(
        @intFromPtr(call.analysis.opcode_positions.ptr),
        @intFromPtr(wire.opcode_positions.ptr),
    );
}

test "witness code wire borrows its retained hex allocation" {
    const bytes = [_]u8{0x00};
    var code = witness_codes.Code{
        .bytes = &bytes,
        .classification = .legacy,
        .sha256 = [_]u8{0x22} ** 32,
    };
    var sha256_hex = [_]u8{'2'} ** 64;
    const wire = witnessCodeWire(&code, true, 7, &sha256_hex);
    try std.testing.expectEqual(
        @intFromPtr(sha256_hex[0..].ptr),
        @intFromPtr(wire.sha256.ptr),
    );
    try std.testing.expectEqualStrings(&sha256_hex, wire.sha256);
}

test "canonical sealed identity wire reopens to its unsigned bytes" {
    const Unsigned = struct {
        elf: Identity,
        input: Identity,
    };
    const Sealed = struct {
        content_sha256: []const u8,
        elf: Identity,
        input: Identity,
    };
    var bytes = [_]u8{0x42};
    var path = [_]u8{ '/', 'x' };
    var input_file = InputFile{
        .bytes = &bytes,
        .path = &path,
        .sha256 = [_]u8{0x11} ** 32,
        .sha256_hex = [_]u8{'1'} ** 64,
    };
    const unsigned = Unsigned{
        .elf = input_file.identity(),
        .input = input_file.identity(),
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        unsigned,
        .{},
    );
    defer std.testing.allocator.free(unsigned_json);
    const content_digest = digestWithNewline(unsigned_json);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed_json = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        Sealed{
            .content_sha256 = &content_hex,
            .elf = unsigned.elf,
            .input = unsigned.input,
        },
        .{},
    );
    defer std.testing.allocator.free(sealed_json);
    const field = ",\"elf\":";
    const marker = std.mem.indexOf(u8, sealed_json, field) orelse
        return error.MissingSyntheticElfIdentity;
    const reopened = try std.testing.allocator.alloc(
        u8,
        1 + sealed_json[marker + 1 ..].len,
    );
    defer std.testing.allocator.free(reopened);
    reopened[0] = '{';
    @memcpy(reopened[1..], sealed_json[marker + 1 ..]);
    try std.testing.expectEqualStrings(unsigned_json, reopened);
    try std.testing.expectEqualSlices(
        u8,
        &content_digest,
        &digestWithNewline(reopened),
    );
}

test "snapshot reader handles unaligned exact bytes" {
    var words = [_]runner.memory_state.WordState{
        .{ .addr = 0x2000, .initial_word = 0, .final_word = 0x44332211, .final_clock = 1 },
        .{ .addr = 0x2004, .initial_word = 0, .final_word = 0x88776655, .final_clock = 1 },
    };
    const snapshot = Snapshot{
        .layout = .{
            .program_base = 0,
            .program_end = 0,
            .data_base = 0x2000,
            .data_end = 0x3000,
            .stack_bottom = 0,
            .stack_top = 0,
            .io_base = 0,
            .io_end = 0,
            .input_base = 0,
            .input_end = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_base = 0,
            .output_end = 0,
        },
        .segment_role = .single(),
        .words = &words,
    };
    const bytes = try readGuestBytes(std.testing.allocator, snapshot, 0x2002, 4);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x33, 0x44, 0x55, 0x66 }, bytes);
}
