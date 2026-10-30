//! Opt-in execution-only hotspot census of an independently pinned real
//! continuation. It grants no proof authority and reports no proving time.
const std = @import("std");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Runner = @import("../../runner/mod.zig");
fn env(name: [:0]const u8) ![:0]const u8 {
    return std.posix.getenv(name) orelse error.MissingPcCensusInput;
}
fn pin(name: [:0]const u8) ![32]u8 {
    const text = try env(name);
    if (text.len != 64) return error.InvalidPcCensusDigest;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, text);
    return digest;
}
fn read(a: std.mem.Allocator, path: [:0]const u8, max: usize) ![]u8 {
    return std.fs.cwd().readFileAlloc(a, try env(path), max);
}
const Count = struct { pc: u32, instruction_word: u32, opcode: @import("../../runner/decode.zig").Opcode, count: u64 = 0 };
test "pinned real continuation execution-only PC census" {
    if (std.posix.getenv("STWO_B8_PC_CENSUS_ELF") == null) return error.SkipZigTest;
    const a = std.testing.allocator;
    const elf = try read(a, "STWO_B8_PC_CENSUS_ELF", 32 << 20);
    defer a.free(elf);
    const elf_pin = try pin("STWO_B8_PC_CENSUS_ELF_SHA256");
    if (!std.meta.eql(Capture.sha(elf), elf_pin)) return error.UntrustedPcCensusElf;
    const bytes = try read(a, "STWO_B8_PC_CENSUS_INCOMING", 256 << 20);
    defer a.free(bytes);
    const incoming_pin = try pin("STWO_B8_PC_CENSUS_INCOMING_SHA256");
    const outgoing_pin = try pin("STWO_B8_PC_CENSUS_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    const cycles = try std.fmt.parseInt(u32, try env("STWO_B8_PC_CENSUS_CYCLES"), 10);
    const skip = try std.fmt.parseInt(u64, try env("STWO_B8_PC_CENSUS_SKIP"), 10);
    if (cycles == 0 or cycles > 1 << 23) return error.InvalidPcCensusWindow;
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .input = &.{}, .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    defer session.deinit();
    const addresses = try a.alloc(u32, incoming.words.len);
    defer a.free(addresses);
    for (incoming.words, addresses) |word, *address| address.* = word.address;
    for (try session.memory.canonicalAlignedWordAddresses()) |address| session.memory.writeU32AssumePrepared(address, 0);
    try session.memory.prepareAlignedWordWrites(addresses);
    for (incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
    session.cpu = incoming.cpu;
    var segment = try session.startSegment(cycles);
    defer segment.deinit();
    if (segment.base.cycle_count != cycles) return error.PcCensusWindowMismatch;
    var outgoing = try Capture.snapshot(a, session.cpu, &session.memory, .{});
    defer outgoing.deinit(a);
    if (!std.meta.eql(outgoing.identity(), outgoing_pin)) return error.PcCensusWindowMismatch;
    var counts = std.AutoHashMap(u32, Count).init(a);
    defer counts.deinit();
    for (segment.base.execution_trace.rows.items) |row| {
        const slot = try counts.getOrPut(row.pc);
        if (!slot.found_existing) slot.value_ptr.* = .{ .pc = row.pc, .instruction_word = row.inst_word, .opcode = row.opcode };
        if (slot.value_ptr.instruction_word != row.inst_word or slot.value_ptr.opcode != row.opcode) return error.PcCensusInstructionMismatch;
        slot.value_ptr.count += 1;
    }
    const rows = try a.alloc(Count, counts.count());
    defer a.free(rows);
    var iterator = counts.valueIterator();
    var index: usize = 0;
    while (iterator.next()) |value| : (index += 1) rows[index] = value.*;
    std.mem.sort(Count, rows, {}, struct {
        fn less(_: void, left: Count, right: Count) bool {
            return if (left.count != right.count) left.count > right.count else left.pc < right.pc;
        }
    }.less);
    var total: u64 = 0;
    for (rows) |row| total += row.count;
    if (total != segment.base.execution_trace.rows.items.len) return error.PcCensusCountMismatch;
    const result = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-real-window-pc-census-v1", .scope = "execution-only declared window; no skipped prefix or proof", .elf_sha256 = std.fmt.bytesToHex(elf_pin, .lower), .incoming_sha256 = std.fmt.bytesToHex(incoming_pin, .lower), .outgoing_sha256 = std.fmt.bytesToHex(outgoing_pin, .lower), .skip_cycles = skip, .cycles = cycles, .core_rows = total, .keccak_calls = segment.extension.keccakf_calls.records().len, .recovery_calls = segment.extension.signer_recovery_calls.records().len, .pcs = rows }, .{ .whitespace = .indent_2 });
    defer a.free(result);
    const output = try env("STWO_B8_PC_CENSUS_OUTPUT");
    const file = try std.fs.cwd().createFileZ(output, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(result);
}
