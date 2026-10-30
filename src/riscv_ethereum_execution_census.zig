//! Bounded full-guest execution census for measured proof-work scheduling.
//! It creates no STARK and grants no execution or recursion proof authority.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Runner = @import("frontends/riscv/runner/mod.zig");
const Trace = Runner.trace;

fn number(comptime T: type, name: [:0]const u8, fallback: T) !T {
    return if (std.posix.getenv(name)) |value| try std.fmt.parseInt(T, value, 10) else fallback;
}
fn sha(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn writeJson(a: std.mem.Allocator, file: std.fs.File, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(bytes);
    try file.writeAll(bytes);
    try file.writeAll("\n");
}
const Counts = struct {
    cycles: u64 = 0,
    core_rows: u64 = 0,
    register_accesses: u64 = 0,
    ram_accesses: u64 = 0,
    unique_ram_keys_segment: u64 = 0,
    new_ram_keys_4m_cohort: u64 = 0,
    new_ram_keys_8m_cohort: u64 = 0,
    new_ram_keys_whole: u64 = 0,
    elf_readonly_candidate_accesses: u64 = 0,
    input_candidate_accesses: u64 = 0,
    stack_accesses: u64 = 0,
    other_ram_accesses: u64 = 0,
    elf_readonly_store_rows: u64 = 0,
    input_store_rows: u64 = 0,
    register_gap_rows: u64 = 0,
    ram_gap_rows: u64 = 0,
    keccak_calls: u64 = 0,
    recovery_calls: u64 = 0,
    sha_calls: u64 = 0,
    families: [Trace.N_FAMILIES]u64 = @splat(0),
    execution_ns: u64 = 0,
    census_ns: u64 = 0,
    cleanup_ns: u64 = 0,

    fn add(self: *Counts, next: Counts) void {
        inline for (std.meta.fields(Counts)) |field| {
            if (comptime std.mem.eql(u8, field.name, "families")) {
                for (&self.families, next.families) |*target, source| target.* += source;
            } else @field(self, field.name) += @field(next, field.name);
        }
    }
};
const PcCount = struct {
    pc: u32,
    instruction_word: u32,
    opcode: Runner.decode.Opcode,
    count: u64 = 0,
};
// Diagnostic candidates only. ELF flags are not current machine write
// permissions; a future proof route must prove exact disjoint classification
// and reject writes before removing any event from the RAM argument.
const ElfRanges = struct {
    elf: []const u8,
    offset: usize,
    count: usize,
    fn init(elf: []const u8) !ElfRanges {
        if (elf.len < 52) return error.InvalidCensusElf;
        const offset = std.mem.readInt(u32, elf[28..32], .little);
        const stride = std.mem.readInt(u16, elf[42..44], .little);
        const count = std.mem.readInt(u16, elf[44..46], .little);
        if (stride != 32 or offset > elf.len or count > (elf.len - offset) / 32) return error.InvalidCensusElf;
        return .{ .elf = elf, .offset = offset, .count = count };
    }
    fn readonlyWord(self: ElfRanges, address: u32) bool {
        const start: u64 = address & ~@as(u32, 3);
        const end = start + 4;
        var found = false;
        for (0..self.count) |index| {
            const ph = self.elf[self.offset + 32 * index ..][0..32];
            if (std.mem.readInt(u32, ph[0..4], .little) != 1) continue;
            const lo: u64 = std.mem.readInt(u32, ph[8..12], .little);
            const hi = lo + std.mem.readInt(u32, ph[20..24], .little);
            if (hi > (@as(u64, 1) << 32)) return false;
            const writable = std.mem.readInt(u32, ph[24..28], .little) & 2 != 0;
            if (writable and start < hi and lo < end) return false;
            if (!writable and lo <= start and end <= hi) found = true;
        }
        return found;
    }
};
fn inWordRange(address: u32, start: u32, end: u64) bool {
    const word: u64 = address & ~@as(u32, 3);
    return start <= word and word + 4 <= end;
}
test "bounded retained Ethereum execution census without proving" {
    const elf_path = std.posix.getenv("STWO_V7_CENSUS_ELF") orelse return error.MissingCensusElf;
    const input_path = std.posix.getenv("STWO_V7_CENSUS_INPUT") orelse return error.MissingCensusInput;
    const output_path = std.posix.getenv("STWO_V7_CENSUS_OUTPUT") orelse return error.MissingCensusOutput;
    const expected_elf = std.posix.getenv("STWO_V7_CENSUS_ELF_SHA256") orelse return error.MissingCensusElfPin;
    const expected_input = std.posix.getenv("STWO_V7_CENSUS_INPUT_SHA256") orelse return error.MissingCensusInputPin;
    const expected_output = std.posix.getenv("STWO_V7_CENSUS_OUTPUT_SHA256") orelse return error.MissingCensusOutputPin;
    const segment_cycles = try number(u32, "STWO_V7_CENSUS_SEGMENT_CYCLES", 1 << 19);
    const max_cycles = try number(u64, "STWO_V7_CENSUS_MAX_CYCLES", 200_000_000);
    if (segment_cycles == 0 or segment_cycles > 1 << 20 or max_cycles == 0 or (1 << 22) % segment_cycles != 0) return error.InvalidCensusPolicy;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 8 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, 32 << 20);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, input_path, 4 << 20);
    defer a.free(input);
    if (!std.mem.eql(u8, expected_elf, &std.fmt.bytesToHex(sha(elf), .lower)) or
        !std.mem.eql(u8, expected_input, &std.fmt.bytesToHex(sha(input), .lower))) return error.UntrustedCensusInput;
    var directory = try std.fs.cwd().openDir(output_path, .{});
    defer directory.close();
    const Checkpoints = @import("frontends/riscv/prover/block_v8_execution_checkpoint_writer_v1.zig");
    var checkpoints: ?Checkpoints.Owned = null;
    defer if (checkpoints) |*writer| writer.deinit();
    if (std.posix.getenv("STWO_B8_CENSUS_CHECKPOINT_PLAN")) |plan_path| {
        const plan_bytes = try std.fs.cwd().readFileAlloc(a, plan_path, 128 << 10);
        defer a.free(plan_bytes);
        checkpoints = try Checkpoints.Owned.init(a, directory, plan_bytes, try number(u64, "STWO_V7_CENSUS_EXPECTED_CYCLES", 0));
    }
    const records = try directory.createFile("segments.jsonl", .{ .exclusive = true });
    defer records.close();
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{
        .input = input,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .stop_on_halt_flag = true,
        .require_current_output_accesses = false,
    });
    defer session.deinit();
    if (checkpoints) |*writer| try writer.captureIfBoundary(0, session.cpu, &session.memory);
    const elf_ranges = try ElfRanges.init(elf);
    const input_end: u64 = @as(u64, session.elf_info.input_start) + input.len;
    const setup_ns = phase.lap();
    var continuation: ?Runner.ContinuationToken = null;
    var ram_segment = std.AutoHashMap(u32, void).init(a);
    defer ram_segment.deinit();
    var ram_4m = std.AutoHashMap(u32, void).init(a);
    defer ram_4m.deinit();
    var ram_8m = std.AutoHashMap(u32, void).init(a);
    defer ram_8m.deinit();
    var ram_whole = std.AutoHashMap(u32, void).init(a);
    defer ram_whole.deinit();
    const pc_census_enabled = std.posix.getenv("STWO_V8_CENSUS_INCLUDE_PC") != null;
    var pcs = std.AutoHashMap(u32, PcCount).init(a);
    defer pcs.deinit();
    var total: Counts = .{};
    var segments: u32 = 0;
    var terminal: ?Runner.CompletionReason = null;
    var output_sha256: ?[64]u8 = null;
    while (terminal == null) {
        if (total.cycles >= max_cycles) return error.CensusCycleLimit;
        const proposed = @min(segment_cycles, max_cycles - total.cycles);
        const n: usize = @intCast(if (checkpoints) |*writer| try writer.chunkCycles(total.cycles, proposed) else proposed);
        var segment = if (continuation) |token| try session.resumeSegment(token, n) else try session.startSegment(n);
        var segment_live = true;
        defer if (segment_live) segment.deinit();
        var count = Counts{ .execution_ns = phase.lap() };
        if (segment.base.segment_index != segments or segment.base.global_first_cycle != total.cycles + 1 or
            segment.base.clock_frame != .leaf_local or segment.base.cycle_count > n)
            return error.InvalidCensusContinuation;
        count.cycles = segment.base.cycle_count;
        count.core_rows = segment.base.execution_trace.rows.items.len;
        count.register_gap_rows = segment.base.state_chain_tracker.clock_updates_reg.items.len;
        count.ram_gap_rows = segment.base.state_chain_tracker.clock_updates_mem.items.len;
        // Baseline maps are deliberately released/transferred by the runner.
        // Count this diagnostic from the actual published access stream.
        ram_segment.clearRetainingCapacity();
        if (total.cycles % (1 << 22) == 0) ram_4m.clearRetainingCapacity();
        if (total.cycles % (1 << 23) == 0) ram_8m.clearRetainingCapacity();
        for (segment.base.state_chain_tracker.accesses.items) |access| {
            if (access.addr_space == 0) {
                count.register_accesses += 1;
            } else {
                count.ram_accesses += 1;
                try ram_segment.put(access.addr, {});
                if (!(try ram_4m.getOrPut(access.addr)).found_existing) count.new_ram_keys_4m_cohort += 1;
                if (!(try ram_8m.getOrPut(access.addr)).found_existing) count.new_ram_keys_8m_cohort += 1;
                if (!(try ram_whole.getOrPut(access.addr)).found_existing) count.new_ram_keys_whole += 1;
                if (elf_ranges.readonlyWord(access.addr)) {
                    count.elf_readonly_candidate_accesses += 1;
                } else if (inWordRange(access.addr, session.elf_info.input_start, input_end)) {
                    count.input_candidate_accesses += 1;
                } else if (inWordRange(access.addr, session.elf_info.memory_layout.stack_bottom, session.elf_info.memory_layout.stack_top)) {
                    count.stack_accesses += 1;
                } else count.other_ram_accesses += 1;
            }
        }
        count.unique_ram_keys_segment = ram_segment.count();
        if ((count.ram_accesses == 0) != (count.unique_ram_keys_segment == 0) or count.unique_ram_keys_segment > count.ram_accesses) return error.CensusClassificationMismatch;
        for (segment.base.execution_trace.rows.items) |row| {
            count.families[@intFromEnum(try Trace.proofOpcodeFamily(row.opcode))] += 1;
            if (pc_census_enabled) {
                const slot = try pcs.getOrPut(row.pc);
                if (!slot.found_existing) slot.value_ptr.* = .{ .pc = row.pc, .instruction_word = row.inst_word, .opcode = row.opcode };
                if (slot.value_ptr.instruction_word != row.inst_word or slot.value_ptr.opcode != row.opcode) return error.CensusPcInstructionMismatch;
                slot.value_ptr.count += 1;
            }
            if (row.is_store) {
                if (elf_ranges.readonlyWord(row.mem_addr)) count.elf_readonly_store_rows += 1;
                if (inWordRange(row.mem_addr, session.elf_info.input_start, input_end)) count.input_store_rows += 1;
            }
        }
        if (count.ram_accesses != count.elf_readonly_candidate_accesses + count.input_candidate_accesses + count.stack_accesses + count.other_ram_accesses) return error.CensusClassificationMismatch;
        count.keccak_calls = segment.extension.keccakf_calls.records().len;
        count.recovery_calls = segment.extension.signer_recovery_calls.records().len;
        count.sha_calls = segment.extension.sha_calls.records().len;
        continuation = segment.base.continuation;
        terminal = segment.base.completion_reason;
        const entry_pc = segment.base.entry_cpu.pc;
        const exit_pc = segment.base.exit_cpu.pc;
        if (terminal) |reason| {
            if (reason != .halt_flag or continuation != null or segment.base.output_len != 43)
                return error.UnexpectedCensusCompletion;
            const output = segment.base.output orelse return error.MissingCensusGuestOutput;
            output_sha256 = std.fmt.bytesToHex(sha(output), .lower);
            if (!std.mem.eql(u8, expected_output, &output_sha256.?)) return error.UnexpectedCensusOutput;
            const file = try directory.createFile("output.bin", .{ .exclusive = true });
            defer file.close();
            try file.writeAll(output);
        } else if (continuation == null or count.cycles != n) return error.InvalidCensusContinuation;
        if (checkpoints) |*writer| try writer.captureIfBoundary(total.cycles + count.cycles, session.cpu, &session.memory);
        count.census_ns = phase.lap();
        segment.deinit();
        segment_live = false;
        count.cleanup_ns = phase.lap();
        try writeJson(a, records, .{
            .index = segments,
            .first_cycle = total.cycles + 1,
            .entry_pc = entry_pc,
            .exit_pc = exit_pc,
            .terminal = terminal,
            .counts = count,
            .tracked_live_bytes = budget.snapshot().live_bytes,
            .tracked_cumulative_peak_bytes = budget.snapshot().peak_live_bytes,
        });
        total.add(count);
        segments += 1;
        _ = phase.lap(); // File serialization is outside execution/census phases.
    }
    const expected_cycles = try number(u64, "STWO_V7_CENSUS_EXPECTED_CYCLES", 0);
    if (checkpoints) |*writer| try writer.finish(total.cycles);
    if (expected_cycles != 0 and total.cycles != expected_cycles) return error.CensusCycleMismatch;
    if (pc_census_enabled) {
        const pc_rows = try a.alloc(PcCount, pcs.count());
        defer a.free(pc_rows);
        var iterator = pcs.valueIterator();
        var at: usize = 0;
        while (iterator.next()) |value| : (at += 1) pc_rows[at] = value.*;
        std.mem.sort(PcCount, pc_rows, {}, struct {
            fn less(_: void, left: PcCount, right: PcCount) bool {
                return if (left.count != right.count) left.count > right.count else left.pc < right.pc;
            }
        }.less);
        var pc_total: u64 = 0;
        for (pc_rows) |row| pc_total += row.count;
        if (pc_total != total.core_rows) return error.CensusPcCountMismatch;
        const file = try directory.createFile("pcs.json", .{ .exclusive = true });
        defer file.close();
        try writeJson(a, file, .{ .schema = "stwo-b8-full-execution-pc-census-v1", .scope = "full_guest_execution_census_without_proving", .proof_verified = false, .elf_sha256 = std.fmt.bytesToHex(sha(elf), .lower), .input_sha256 = std.fmt.bytesToHex(sha(input), .lower), .output_sha256 = output_sha256, .cycles = total.cycles, .core_rows = total.core_rows, .external_retirements = total.cycles - total.core_rows, .pcs = pc_rows });
    }
    const summary = try directory.createFile("summary.json", .{ .exclusive = true });
    defer summary.close();
    try writeJson(a, summary, .{
        .schema = "stwo-retained-ethereum-bounded-execution-census-v2",
        .scope = "full_guest_execution_census_without_proving",
        .proof_verified = false,
        .elf_sha256 = std.fmt.bytesToHex(sha(elf), .lower),
        .input_sha256 = std.fmt.bytesToHex(sha(input), .lower),
        .output_sha256 = output_sha256,
        .expected_cycles = if (expected_cycles == 0) null else @as(?u64, expected_cycles),
        .segment_cycles = segment_cycles,
        .segments = segments,
        .setup_ns = setup_ns,
        .whole_ns = whole.read(),
        .counts = total,
        .family_names = comptime std.meta.fieldNames(Trace.OpcodeFamily),
        .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
        .host_byte_limit = 8 << 30,
        .pc_census_enabled = pc_census_enabled,
    });
    std.debug.print("ETHEREUM_EXECUTION_CENSUS cycles={d} segments={d} keccak={d} recovery={d} proof_verified=false\n", .{ total.cycles, segments, total.keccak_calls, total.recovery_calls });
}
