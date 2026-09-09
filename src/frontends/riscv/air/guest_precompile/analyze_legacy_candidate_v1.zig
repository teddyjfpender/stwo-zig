//! Non-production authority for a typed Revm-42 `analyze_legacy` candidate.
//!
//! This contract authenticates only legacy bytecode calls. Empty bytecode and
//! EIP-7702 delegation bytecode remain on Revm's committed `Bytecode::new_raw`
//! path. The original and padded `Bytes` construction also remains ordinary
//! committed RV32 software; this candidate covers only opcode scanning,
//! jump-table bits, and terminal padding quantities.

const std = @import("std");

pub const production_active = false;
pub const opcode_allocated = false;
pub const proof_opcode_allocated = false;
pub const dispatch_active = false;
pub const stark_component_ready = false;
pub const source_memory_relation_ready = false;
pub const output_memory_relation_ready = false;

pub const schema = "stwo.riscv.analyze-legacy-air-candidate.v1";
pub const revm_git_revision = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c";
pub const revm_bytecode_version = "42.0.0";
pub const revm_source_sha256_hex =
    "cf26e05a027549b772a04ff4f2ad7bcd03eaaa5dbd42d53f03830050504671d4";
pub const function_symbol = "revm_bytecode::legacy::analysis::analyze_legacy";
pub const function_entry_pc: u32 = 0x000b_d490;
pub const function_end_exclusive: u32 = 0x000b_d9e8;

pub const jumpdest_opcode: u8 = 0x5b;
pub const push1_opcode: u8 = 0x60;
pub const push32_opcode: u8 = 0x7f;
pub const stop_opcode: u8 = 0x00;
pub const dupn_opcode: u8 = 0xe6;
pub const eip7702_prefix = [2]u8{ 0xef, 0x01 };
pub const guest_address_limit: u32 = @as(u32, 1) << 30;
pub const maximum_source_length: u32 = guest_address_limit - 33;

pub const retained_call_count: u32 = 115;
pub const retained_scan_rows: u64 = 796_670;
pub const retained_bitmap_bytes: u64 = 166_105;
pub const retained_bitmap_word_rows: u64 = 41_558;
pub const retained_jumpdest_count: u64 = 41_026;
pub const retained_push_count: u64 = 207_786;
pub const retained_legacy_source_bytes: u64 = 1_328_485;
pub const retained_observation_content_sha256_hex =
    "bc940a0512316dfa291fe0704150f80daf848b4848436404757ab5dd27d47006";

pub const Error = error{
    EmptyBytecodeUsesNewRaw,
    Eip7702BytecodeUsesNewRaw,
    InvalidCallDescriptor,
    InvalidSourceIdentity,
    SourceAddressOverflow,
    SourceTooLarge,
};

pub const Classification = enum {
    legacy,
    empty_new_raw,
    eip7702_new_raw,
};

pub const SummaryV1 = struct {
    bitmap_bytes: u32,
    eof_immediate_padding: u32,
    jumpdest_count: u32,
    push_count: u32,
    push_overflow: u32,
    scan_iterations: u32,
    total_padding: u32,
};

pub const DescriptorV1 = struct {
    call_index: u32,
    source_pointer: u32,
    source_length: u32,
    source_sha256: [32]u8,
    summary: SummaryV1,

    pub fn init(
        call_index: u32,
        source_pointer: u32,
        source: []const u8,
    ) Error!DescriptorV1 {
        try requireLegacy(source);
        if (source.len > maximum_source_length) return error.SourceTooLarge;
        const length: u32 = @intCast(source.len);
        _ = std.math.add(u32, source_pointer, length) catch
            return error.SourceAddressOverflow;
        if (source_pointer + length > guest_address_limit)
            return error.SourceAddressOverflow;
        var source_sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &source_sha256, .{});
        return .{
            .call_index = call_index,
            .source_pointer = source_pointer,
            .source_length = length,
            .source_sha256 = source_sha256,
            .summary = try analyzeLegacy(source),
        };
    }

    pub fn validate(self: DescriptorV1, source: []const u8) Error!void {
        const expected = try init(self.call_index, self.source_pointer, source);
        if (!std.meta.eql(self, expected)) return error.InvalidCallDescriptor;
    }

    pub fn bitmapWordRows(self: DescriptorV1) u32 {
        return (self.source_length + 31) / 32;
    }
};

/// Observation-side caller authority. It does not allocate a custom opcode:
/// the committed RV32 function entry and its authenticated pointer/length are
/// retained while the normal software call remains the execution authority.
pub const CallerV1 = struct {
    entry_clock: u32,
    entry_pc: u32,
    bytes_struct_pointer: u32,
    descriptor: DescriptorV1,

    pub fn validate(self: CallerV1, source: []const u8) Error!void {
        if (self.entry_clock == 0 or
            self.entry_pc != function_entry_pc or
            self.bytes_struct_pointer >= guest_address_limit)
        {
            return error.InvalidCallDescriptor;
        }
        try self.descriptor.validate(source);
    }
};

pub const RetainedProjectionV1 = struct {
    call_count: u32,
    scan_rows: u64,
    bitmap_bytes: u64,
    bitmap_word_rows: u64,
    jumpdest_count: u64,
    push_count: u64,
    legacy_source_bytes: u64,
    semantic_observation_content_sha256_hex: []const u8,
    production: bool,
    proof_claim: ?u64,
    end_to_end_claim: ?u64,

    pub fn validate(self: RetainedProjectionV1) Error!void {
        if (self.call_count != retained_call_count or
            self.scan_rows != retained_scan_rows or
            self.bitmap_bytes != retained_bitmap_bytes or
            self.bitmap_word_rows != retained_bitmap_word_rows or
            self.jumpdest_count != retained_jumpdest_count or
            self.push_count != retained_push_count or
            self.legacy_source_bytes != retained_legacy_source_bytes or
            !std.mem.eql(
                u8,
                self.semantic_observation_content_sha256_hex,
                retained_observation_content_sha256_hex,
            ) or
            self.production or
            self.proof_claim != null or
            self.end_to_end_claim != null)
        {
            return error.InvalidCallDescriptor;
        }
    }
};

pub const retained_projection = RetainedProjectionV1{
    .call_count = retained_call_count,
    .scan_rows = retained_scan_rows,
    .bitmap_bytes = retained_bitmap_bytes,
    .bitmap_word_rows = retained_bitmap_word_rows,
    .jumpdest_count = retained_jumpdest_count,
    .push_count = retained_push_count,
    .legacy_source_bytes = retained_legacy_source_bytes,
    .semantic_observation_content_sha256_hex = retained_observation_content_sha256_hex,
    .production = false,
    .proof_claim = null,
    .end_to_end_claim = null,
};

pub fn classify(source: []const u8) Classification {
    if (source.len == 0) return .empty_new_raw;
    if (source.len >= eip7702_prefix.len and
        std.mem.eql(u8, source[0..eip7702_prefix.len], &eip7702_prefix))
    {
        return .eip7702_new_raw;
    }
    return .legacy;
}

pub fn requireLegacy(source: []const u8) Error!void {
    switch (classify(source)) {
        .legacy => {},
        .empty_new_raw => return error.EmptyBytecodeUsesNewRaw,
        .eip7702_new_raw => return error.Eip7702BytecodeUsesNewRaw,
    }
}

/// Exact scalar model of Revm bytecode 42.0.0. This constructs no output
/// `Bytes`; it only derives the quantities later authenticated by the AIR.
pub fn analyzeLegacy(source: []const u8) Error!SummaryV1 {
    try requireLegacy(source);
    if (source.len > maximum_source_length) return error.SourceTooLarge;
    var cursor: usize = 0;
    var previous: u8 = 0;
    var last: u8 = 0;
    var scans: u32 = 0;
    var pushes: u32 = 0;
    var jumpdests: u32 = 0;
    while (cursor < source.len) {
        scans += 1;
        previous = last;
        last = source[cursor];
        if (last == jumpdest_opcode) {
            jumpdests += 1;
            cursor += 1;
        } else {
            const push_offset = last -% push1_opcode;
            if (push_offset < 32) {
                pushes += 1;
                cursor += @as(usize, push_offset) + 2;
            } else {
                cursor += 1;
            }
        }
    }
    const overflow: u32 = @intCast(cursor - source.len);
    const eof_padding: u32 = if (last == stop_opcode)
        @intFromBool(isEofImmediate(previous))
    else
        1 + @as(u32, @intFromBool(isEofImmediate(last)));
    return .{
        .bitmap_bytes = @intCast((source.len + 7) / 8),
        .eof_immediate_padding = eof_padding,
        .jumpdest_count = jumpdests,
        .push_count = pushes,
        .push_overflow = overflow,
        .scan_iterations = scans,
        .total_padding = overflow + eof_padding,
    };
}

pub fn verifierProgramIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.analyze-legacy-air-candidate.v1\x00");
    hash.update(revm_git_revision);
    hash.update(revm_bytecode_version);
    hash.update(revm_source_sha256_hex);
    hash.update(function_symbol);
    hash.update(&u32Bytes(function_entry_pc));
    hash.update(&u32Bytes(function_end_exclusive));
    hash.update(&u32Bytes(guest_address_limit));
    hash.update(&u32Bytes(maximum_source_length));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

pub fn isEofImmediate(opcode: u8) bool {
    return opcode -% dupn_opcode < 3;
}

fn u32Bytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

comptime {
    if (production_active or
        opcode_allocated or
        proof_opcode_allocated or
        dispatch_active or
        stark_component_ready or
        source_memory_relation_ready or
        output_memory_relation_ready or
        retained_call_count != 115 or
        retained_scan_rows != 796_670 or
        retained_bitmap_bytes != 166_105 or
        retained_bitmap_word_rows != 41_558)
    {
        @compileError("analyze_legacy candidate authority drifted");
    }
}
