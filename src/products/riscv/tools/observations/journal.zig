//! Shared V3 prefix-journal ownership for bounded RISC-V observations.
//! Callers retain their CLI admission, execution, output and teardown policy.
//! Segment count is admitted by each command before this parser is called.
const std = @import("std");
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";

pub const ExpectedSegment = struct {
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    core_trace_rows: usize,
};

pub const JournalAuthority = struct {
    segment_step_budget: usize,
    first_global_cycle: u64,
    sampled_cycles: u64,
    retired_instructions: u64,
    segments: []ExpectedSegment,

    pub fn parse(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        elf_sha256: [32]u8,
        input_sha256: [32]u8,
        segment_count: u32,
    ) !JournalAuthority {
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        const header_line = lines.next() orelse return error.InvalidJournal;
        if (header_line.len == 0) return error.InvalidJournal;
        var header = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            header_line,
            .{},
        );
        defer header.deinit();
        const payload = try objectField(header.value, "payload");
        if (!std.mem.eql(u8, try stringField(payload, "schema"), "stwo.riscv.segmented-execution-header.v3") or
            !std.mem.eql(u8, try stringField(payload, "profile"), profile_name) or
            !std.mem.eql(u8, try stringField(payload, "clock_frame"), clock_frame))
        {
            return error.InvalidJournal;
        }
        const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
        const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
        if (!std.mem.eql(u8, try stringField(payload, "elf_sha256"), &elf_hex) or
            !std.mem.eql(u8, try stringField(payload, "input_sha256"), &input_hex))
        {
            return error.JournalInputMismatch;
        }
        const budget = try unsignedField(payload, "segment_step_budget");
        if (budget == 0 or budget > std.math.maxInt(u32))
            return error.InvalidJournal;
        const segments = try allocator.alloc(ExpectedSegment, segment_count);
        errdefer allocator.free(segments);
        var sampled_cycles: u64 = 0;
        var retired: u64 = 0;
        for (segments, 0..) |*out, index| {
            const line = lines.next() orelse return error.InvalidJournal;
            if (line.len == 0) return error.InvalidJournal;
            var parsed = try std.json.parseFromSlice(
                std.json.Value,
                allocator,
                line,
                .{},
            );
            defer parsed.deinit();
            const segment = try objectField(parsed.value, "payload");
            if (!std.mem.eql(u8, try stringField(segment, "schema"), "stwo.riscv.segmented-execution-segment.v3")) {
                return error.InvalidJournal;
            }
            const segment_index = try unsignedField(segment, "segment_index");
            const first_cycle = try unsignedField(segment, "global_first_cycle");
            const cycles = try unsignedField(segment, "cycle_count");
            const core_rows = try unsignedField(segment, "core_trace_rows");
            if (segment_index != index or cycles == 0 or core_rows == 0 or
                segment_index > std.math.maxInt(u32) or
                cycles > std.math.maxInt(u32) or
                core_rows > std.math.maxInt(usize))
            {
                return error.InvalidJournal;
            }
            out.* = .{
                .segment_index = @intCast(segment_index),
                .global_first_cycle = first_cycle,
                .cycle_count = @intCast(cycles),
                .core_trace_rows = @intCast(core_rows),
            };
            sampled_cycles = std.math.add(u64, sampled_cycles, cycles) catch
                return error.InvalidJournal;
            retired = std.math.add(u64, retired, core_rows) catch
                return error.InvalidJournal;
        }
        return .{
            .segment_step_budget = @intCast(budget),
            .first_global_cycle = segments[0].global_first_cycle,
            .sampled_cycles = sampled_cycles,
            .retired_instructions = retired,
            .segments = segments,
        };
    }

    pub fn deinit(self: *JournalAuthority, allocator: std.mem.Allocator) void {
        allocator.free(self.segments);
        self.* = undefined;
    }
};

fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidJournal;
    return value.object.get(name) orelse error.InvalidJournal;
}

fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = try objectField(value, name);
    if (field != .string) return error.InvalidJournal;
    return field.string;
}

fn unsignedField(value: std.json.Value, name: []const u8) !u64 {
    const field = try objectField(value, name);
    return switch (field) {
        .integer => |number| std.math.cast(u64, number) orelse
            error.InvalidJournal,
        else => error.InvalidJournal,
    };
}

pub fn readPathAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(allocator, maximum_bytes);
}

pub fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
