//! Bounded custody admission, immutable observation pins and sealed journal validation.
const std = @import("std");

pub const schema = "stwo.riscv.analyze-legacy-semantic-observation.v1";
pub const status = "captured-diagnostic-only";
pub const claim_boundary = "exact-revm42-execution-observation-not-air-or-proof";
pub const profile_name = "rv32im-zkvm-ethereum-v1";
pub const clock_frame = "leaf_local";
pub const revm_bytecode_version = "42.0.0";
pub const revm_git_revision = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c";
pub const revm_source_sha256 = "cf26e05a027549b772a04ff4f2ad7bcd03eaaa5dbd42d53f03830050504671d4";
pub const cargo_lock_sha256 = "17b841e66b7017edd621877bcbbd76ad50242d648e6dd49667d6e05dc3c46ce9";
pub const expected_call_count: u32 = 115;
pub const expected_length_sum: u64 = 1_328_485;
pub const expected_symbol_rows: u64 = 6_846_967;
pub const symbol_end_exclusive: u32 = 0x000bd9e8;
pub const maximum_input_bytes: usize = 64 << 20;
pub const maximum_elf_bytes: usize = 64 << 20;
pub const maximum_executable_bytes: usize = 64 << 20;
pub const maximum_journal_bytes: usize = 64 << 20;
pub const maximum_source_bytes: usize = 4 << 20;
pub const maximum_evidence_bytes: usize = 16 << 20;
pub const maximum_sample_segments: u32 = 64;

pub const function_authority = FunctionAuthority{
    .entry_instruction_word = 0xfc010113,
    .entry_pc = 0x000bd490,
    .length_imm = 8,
    .length_instruction_word = 0x0085a903,
    .length_pc = 0x000bd4c4,
    .length_rd = 18,
    .length_rs1 = 11,
    .revm_bytecode_version = revm_bytecode_version,
    .revm_git_revision = revm_git_revision,
    .source_pointer_imm = 4,
    .source_pointer_instruction_word = 0x0044aa83,
    .source_pointer_pc = 0x000bd5c4,
    .source_pointer_rd = 21,
    .source_pointer_rs1 = 9,
    .symbol = "revm_bytecode::legacy::analysis::analyze_legacy",
    .symbol_end_exclusive = symbol_end_exclusive,
    .symbol_rows = expected_symbol_rows,
};

pub const Options = struct {
    cargo_lock: []const u8,
    elf: []const u8,
    execution_journal: []const u8,
    function_value_evidence: []const u8,
    input: []const u8,
    nm_map: []const u8,
    observer_semantics_source: []const u8,
    observer_source: []const u8,
    observer_witness_source: []const u8,
    pc_observation: []const u8,
    revm_source: []const u8,
    segment_count: u32,

    pub fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 24) return error.InvalidArguments;
        var cargo_lock: ?[]const u8 = null;
        var elf: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var function_value_evidence: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var nm_map: ?[]const u8 = null;
        var observer_semantics_source: ?[]const u8 = null;
        var observer_source: ?[]const u8 = null;
        var observer_witness_source: ?[]const u8 = null;
        var pc_observation: ?[]const u8 = null;
        var revm_source: ?[]const u8 = null;
        var segment_count: ?u32 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (std.mem.eql(u8, name, "--cargo-lock")) {
                if (cargo_lock != null) return error.DuplicateArgument;
                cargo_lock = value;
            } else if (std.mem.eql(u8, name, "--elf")) {
                if (elf != null) return error.DuplicateArgument;
                elf = value;
            } else if (std.mem.eql(u8, name, "--execution-journal")) {
                if (journal != null) return error.DuplicateArgument;
                journal = value;
            } else if (std.mem.eql(u8, name, "--function-value-evidence")) {
                if (function_value_evidence != null) return error.DuplicateArgument;
                function_value_evidence = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                if (input != null) return error.DuplicateArgument;
                input = value;
            } else if (std.mem.eql(u8, name, "--nm-map")) {
                if (nm_map != null) return error.DuplicateArgument;
                nm_map = value;
            } else if (std.mem.eql(u8, name, "--observer-semantics-source")) {
                if (observer_semantics_source != null) return error.DuplicateArgument;
                observer_semantics_source = value;
            } else if (std.mem.eql(u8, name, "--observer-source")) {
                if (observer_source != null) return error.DuplicateArgument;
                observer_source = value;
            } else if (std.mem.eql(u8, name, "--observer-witness-source")) {
                if (observer_witness_source != null) return error.DuplicateArgument;
                observer_witness_source = value;
            } else if (std.mem.eql(u8, name, "--pc-observation")) {
                if (pc_observation != null) return error.DuplicateArgument;
                pc_observation = value;
            } else if (std.mem.eql(u8, name, "--revm-source")) {
                if (revm_source != null) return error.DuplicateArgument;
                revm_source = value;
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (segment_count != null) return error.DuplicateArgument;
                segment_count = try std.fmt.parseInt(u32, value, 10);
            } else return error.InvalidArguments;
        }
        const count = segment_count orelse return error.InvalidArguments;
        if (count == 0 or count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        return .{
            .cargo_lock = cargo_lock orelse return error.InvalidArguments,
            .elf = elf orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .function_value_evidence = function_value_evidence orelse
                return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .nm_map = nm_map orelse return error.InvalidArguments,
            .observer_semantics_source = observer_semantics_source orelse
                return error.InvalidArguments,
            .observer_source = observer_source orelse return error.InvalidArguments,
            .observer_witness_source = observer_witness_source orelse
                return error.InvalidArguments,
            .pc_observation = pc_observation orelse return error.InvalidArguments,
            .revm_source = revm_source orelse return error.InvalidArguments,
            .segment_count = count,
        };
    }
};

pub const InputFile = struct {
    bytes: []u8,
    path: []u8,
    sha256: [32]u8,
    sha256_hex: [64]u8,

    pub fn open(
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum: usize,
    ) !InputFile {
        const canonical = try std.fs.realpathAlloc(allocator, path);
        errdefer allocator.free(canonical);
        const file = try std.fs.openFileAbsolute(canonical, .{});
        defer file.close();
        const metadata = try file.stat();
        if (metadata.kind != .file or metadata.size > maximum)
            return error.InvalidInputFile;
        const bytes = try file.readToEndAlloc(allocator, maximum);
        errdefer allocator.free(bytes);
        const sha256 = digest(bytes);
        return .{
            .bytes = bytes,
            .path = canonical,
            .sha256 = sha256,
            .sha256_hex = std.fmt.bytesToHex(sha256, .lower),
        };
    }

    pub fn deinit(self: *InputFile, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.path);
        self.* = undefined;
    }

    pub fn identity(self: *const InputFile) Identity {
        return .{
            .bytes = self.bytes.len,
            .path = self.path,
            .sha256 = &self.sha256_hex,
        };
    }
};

pub const ExpectedSegment = struct {
    core_trace_rows: usize,
    cycle_count: u32,
    global_first_cycle: u64,
    segment_index: u32,
};

pub const JournalAuthority = struct {
    first_global_cycle: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    segment_step_budget: usize,
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
        var header = try std.json.parseFromSlice(std.json.Value, allocator, header_line, .{});
        defer header.deinit();
        const payload = try objectField(header.value, "payload");
        if (!std.mem.eql(u8, try stringField(payload, "schema"), "stwo.riscv.segmented-execution-header.v3") or
            !std.mem.eql(u8, try stringField(payload, "profile"), profile_name) or
            !std.mem.eql(u8, try stringField(payload, "clock_frame"), clock_frame) or
            !(try boolField(payload, "strict_completion")) or
            !std.mem.eql(u8, try stringField(payload, "trace_retention"), "segment-owned"))
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
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
            defer parsed.deinit();
            const segment = try objectField(parsed.value, "payload");
            if (!std.mem.eql(u8, try stringField(segment, "schema"), "stwo.riscv.segmented-execution-segment.v3"))
                return error.InvalidJournal;
            const segment_index = try unsignedField(segment, "segment_index");
            const first_cycle = try unsignedField(segment, "global_first_cycle");
            const cycles = try unsignedField(segment, "cycle_count");
            const core_rows = try unsignedField(segment, "core_trace_rows");
            if (segment_index != index or cycles == 0 or core_rows == 0 or
                segment_index > std.math.maxInt(u32) or cycles > std.math.maxInt(u32) or
                core_rows > std.math.maxInt(usize))
            {
                return error.InvalidJournal;
            }
            out.* = .{
                .core_trace_rows = @intCast(core_rows),
                .cycle_count = @intCast(cycles),
                .global_first_cycle = first_cycle,
                .segment_index = @intCast(segment_index),
            };
            sampled_cycles = std.math.add(u64, sampled_cycles, cycles) catch
                return error.InvalidJournal;
            retired = std.math.add(u64, retired, core_rows) catch
                return error.InvalidJournal;
        }
        const summary_line = lines.next() orelse return error.InvalidJournal;
        var summary_parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            summary_line,
            .{},
        );
        defer summary_parsed.deinit();
        const summary = try objectField(summary_parsed.value, "payload");
        if (!std.mem.eql(u8, try stringField(summary, "schema"), "stwo.riscv.segmented-execution-summary.v3") or
            !std.mem.eql(u8, try stringField(summary, "clock_frame"), clock_frame) or
            !(try boolField(summary, "completed")) or
            try unsignedField(summary, "segment_count") != segment_count or
            try unsignedField(summary, "total_cycles") != sampled_cycles or
            try unsignedField(summary, "total_core_trace_rows") != retired)
        {
            return error.InvalidJournal;
        }
        while (lines.next()) |trailing| {
            if (trailing.len != 0) return error.InvalidJournal;
        }
        return .{
            .first_global_cycle = segments[0].global_first_cycle,
            .retired_instructions = retired,
            .sampled_cycles = sampled_cycles,
            .segment_step_budget = @intCast(budget),
            .segments = segments,
        };
    }

    pub fn deinit(self: *JournalAuthority, allocator: std.mem.Allocator) void {
        allocator.free(self.segments);
        self.* = undefined;
    }
};

pub const FunctionAuthority = struct {
    entry_instruction_word: u32,
    entry_pc: u32,
    length_imm: i32,
    length_instruction_word: u32,
    length_pc: u32,
    length_rd: u5,
    length_rs1: u5,
    revm_bytecode_version: []const u8,
    revm_git_revision: []const u8,
    source_pointer_imm: i32,
    source_pointer_instruction_word: u32,
    source_pointer_pc: u32,
    source_pointer_rd: u5,
    source_pointer_rs1: u5,
    symbol: []const u8,
    symbol_end_exclusive: u32,
    symbol_rows: u64,
};

pub const Identity = struct {
    bytes: usize,
    path: []const u8,
    sha256: []const u8,
};

pub fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidJournal;
    return value.object.get(name) orelse error.InvalidJournal;
}

pub fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const field = try objectField(value, name);
    if (field != .string) return error.InvalidJournal;
    return field.string;
}

pub fn unsignedField(value: std.json.Value, name: []const u8) !u64 {
    const field = try objectField(value, name);
    return switch (field) {
        .integer => |number| std.math.cast(u64, number) orelse error.InvalidJournal,
        else => error.InvalidJournal,
    };
}

pub fn boolField(value: std.json.Value, name: []const u8) !bool {
    const field = try objectField(value, name);
    if (field != .bool) return error.InvalidJournal;
    return field.bool;
}

pub fn validateNmAuthority(bytes: []const u8) !void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var found = false;
    while (lines.next()) |line| {
        if (line.len < 12) continue;
        var fields = std.mem.splitScalar(u8, line, ' ');
        const address_text = fields.next() orelse continue;
        const kind = fields.next() orelse continue;
        const name = fields.rest();
        if (address_text.len != 8 or kind.len != 1 or
            (kind[0] != 't' and kind[0] != 'T'))
        {
            continue;
        }
        const address = std.fmt.parseInt(u32, address_text, 16) catch continue;
        if (!found) {
            if (address == function_authority.entry_pc and
                std.mem.eql(u8, name, function_authority.symbol))
            {
                found = true;
            }
            continue;
        }
        if (address == function_authority.entry_pc) continue;
        if (address != function_authority.symbol_end_exclusive)
            return error.NmSymbolIntervalMismatch;
        return;
    }
    return error.NmSymbolIntervalMismatch;
}

pub fn digest(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

pub fn digestWithNewline(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    hasher.update("\n");
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}
