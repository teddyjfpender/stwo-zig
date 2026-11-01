//! Bounded software Ethereum execution census. Never establishes a proof.
const std = @import("std");
const rv = @import("mod.zig");
const contract = @import("ethereum_contract.zig");
const services = @import("service_session.zig");
const ethereum = @import("ethereum_services/session.zig");
const access = @import("access_census.zig");
const frequent = @import("frequent_operations.zig");
const candidate = @import("ethereum_services/candidate_services.zig");
/// `ethereum_services_v3_candidate` = admitted v2 services plus execution-only
/// candidate services (candidate_services.zig). Never proof-relevant: it is
/// rejected with compact capture, RAM-boundary capture and access census.
/// `ethereum_services_v3` is ADMITTED (v2 + SHA-256 compression 0x0003_0010)
/// and supports compact capture for the prover.
const Profile = enum { software, keccak_service_v1, ethereum_services_v1, ethereum_services_v2, ethereum_services_v3_candidate, ethereum_services_v3 };
const A = std.heap.smp_allocator;
const OPCODE_NAMES = blk: {
    const fields = @typeInfo(rv.decode.Opcode).@"enum".fields;
    if (fields.len != access.OPCODE_COUNT) @compileError("execution census opcode schema needs qualification");
    var result: [fields.len][]const u8 = undefined;
    for (fields, 0..) |field, i| result[i] = field.name;
    break :blk result;
};
const Config = struct {
    elf: []const u8,
    input: []const u8,
    elf_sha256: []const u8,
    input_sha256: []const u8,
    expected_output: []const u8,
    symbols: contract.Symbols,
    max_steps: u64 = 100000000,
    cache_entries: usize = 1024,
    pc_profile: ?PcRange = null,
    execution_profile: Profile = .software,
    census_batch_steps: ?u32 = null,
    compact_capture_batch_steps: ?u32 = null,
    capture_ram_boundaries: bool = false,
    frequent_operation_limit: ?usize = null,
};
const PcRange = struct { start: u64, end: u64 };
const PcProfile = struct { start: u64, end: u64, counts: []u64, outside: u64 = 0 };
const Status = enum { completed, step_limit, trap };
const CaptureStats = struct {
    batches: u64 = 0,
    instructions: u64 = 0,
    ram_words: u64 = 0,
    service_calls: u64 = 0,
    secp_add_calls: u64 = 0,
    secp_double_calls: u64 = 0,
    sha256_calls: u64 = 0,
    peak_retained_bytes: usize = 0,
    step_bytes: usize = @sizeOf(rv.compact_tape.Step),
    legacy_retirement_bytes: usize = @sizeOf(rv.machine.Retirement),
    // Diagnostic capture releases each batch; it does not establish continuity.
    authenticated_continuation: bool = false,
    fn account(self: *CaptureStats, tape: *const rv.compact_tape.Tape) void {
        if (tape.len == 0) return;
        self.batches += 1;
        self.instructions += tape.len;
        self.ram_words += tape.memory_before.items.len;
        self.service_calls += tape.serviceCount();
        self.sha256_calls += tape.sha256_calls.items.len;
        for (tape.secp_calls.items) |call| {
            if (call.kind == .add) self.secp_add_calls += 1 else self.secp_double_calls += 1;
        }
        self.peak_retained_bytes = @max(self.peak_retained_bytes, tape.retainedBytes());
    }
};
const BoundaryStats = struct {
    batches: u64 = 0,
    instructions: u64 = 0,
    touched_cells: u64 = 0,
    peak_cells: u32 = 0,
    cell_bytes: usize = @sizeOf(rv.boundary_capture.Cell),
    authenticated_continuation: bool = false,
    fn account(self: *BoundaryStats, capture: *const rv.boundary_capture.Capture) void {
        if (capture.steps == 0) return;
        self.batches += 1;
        self.instructions += capture.steps;
        self.touched_cells += capture.cells.count();
        self.peak_cells = @max(self.peak_cells, capture.cells.count());
    }
};
const Report = struct {
    schema: []const u8 = "rv64-ethereum-execution-v0",
    proof_supported: bool = false,
    trace_retained: bool = false,
    execution_profile: Profile = .software,
    keccak_calls: u64 = 0,
    secp_add_calls: u64 = 0,
    secp_double_calls: u64 = 0,
    sha256_calls: u64 = 0,
    bulk_memcpy_calls: u64 = 0,
    bulk_memset_calls: u64 = 0,
    bulk_memcpy_bytes: u64 = 0,
    bulk_memset_bytes: u64 = 0,
    /// memcpy with a source not 8-aligned (unaligned body rows).
    bulk_memcpy_unaligned_calls: u64 = 0,
    bulk_memcpy_unaligned_bytes: u64 = 0,
    bulk_memcmp_calls: u64 = 0,
    /// 8 x examined word pairs (the proof's compare rows).
    bulk_memcmp_bytes: u64 = 0,
    service_ram_word_transitions: u64 = 0,
    status: Status,
    verified_output: bool = false,
    stop_error: ?[]const u8 = null,
    pc: u64,
    final_registers: [32]u64 = @splat(0),
    stopped_instruction: ?u32 = null,
    instructions: u64,
    opcode_counts: [@typeInfo(rv.decode.Opcode).@"enum".fields.len]u64,
    opcode_names: [OPCODE_NAMES.len][]const u8 = OPCODE_NAMES,
    loads: u64,
    stores: u64,
    allocated_pages: usize,
    setup_ns: u64,
    execution_ns: u64,
    elf_sha256: [64]u8,
    input_sha256: [64]u8,
    output: ?[contract.OUTPUT_BYTES * 2]u8 = null,
    pc_profile: ?PcProfile = null,
    access_census_batch_steps: ?u32 = null,
    access_census_chunk_bytes: [access.CHUNK_BYTES.len]u32 = access.CHUNK_BYTES,
    access_batches: []access.Stats = &.{},
    compact_capture: ?CaptureStats = null,
    ram_boundary_capture: ?BoundaryStats = null,
    frequent_operations: ?frequent.Summary = null,
    candidate_service_calls: ?candidate.Counts = null,
};
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(A);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedEthereumExecutionConfig;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    const parsed = try std.json.parseFromSlice(Config, a, raw, .{});
    const c = parsed.value;
    if (c.max_steps == 0 or c.max_steps > 10000000000) return error.InvalidExecutionBudget;
    if (c.expected_output.len != contract.OUTPUT_BYTES * 2) return error.InvalidExpectedOutput;
    var expected: [contract.OUTPUT_BYTES]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, c.expected_output);
    const bytes = try std.fs.cwd().readFileAlloc(a, c.elf, 32 * 1024 * 1024);
    const input = try std.fs.cwd().readFileAlloc(a, c.input, contract.INPUT_CAPACITY_MAX - 4);
    const elf_hash = try checkedHash(bytes, c.elf_sha256);
    const input_hash = try checkedHash(input, c.input_sha256);
    var report = try run(c, bytes, input, expected);
    defer if (report.pc_profile) |profile| A.free(profile.counts);
    defer A.free(report.access_batches);
    defer if (report.frequent_operations) |value| A.free(value.top);
    report.elf_sha256 = elf_hash;
    report.input_sha256 = input_hash;
    const encoded = try std.json.Stringify.valueAlloc(a, report, .{});
    try std.fs.File.stdout().writeAll(encoded);
    try std.fs.File.stdout().writeAll("\n");
}
fn checkedHash(bytes: []const u8, expected: []const u8) ![64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const actual = std.fmt.bytesToHex(hash, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.ArtifactDigestMismatch;
    return actual;
}
fn profileStep(session: *ethereum.Session, execution: Profile, event: *ethereum.Event) ethereum.Error!?rv.machine.Retirement {
    return switch (execution) {
        .software => try session.keccak.base.step(),
        .keccak_service_v1 => blk: {
            var call: services.Call = undefined;
            const row = try session.keccak.step(&call);
            if (row == null) event.* = .{ .keccak = call };
            break :blk row;
        },
        .ethereum_services_v1, .ethereum_services_v2, .ethereum_services_v3_candidate, .ethereum_services_v3 => session.step(event),
    };
}
fn run(c: Config, bytes: []const u8, input: []const u8, expected: [contract.OUTPUT_BYTES]u8) !Report {
    if (c.pc_profile) |range| if (range.end <= range.start or range.start & 3 != 0 or range.end & 3 != 0 or range.end - range.start > 8 * 1024 * 1024) return error.InvalidPcProfileRange;
    const is_candidate = c.execution_profile == .ethereum_services_v3_candidate;
    if (is_candidate and (c.compact_capture_batch_steps != null or c.census_batch_steps != null or c.capture_ram_boundaries)) return error.CandidateProfileIsExecutionOnly;
    var setup_timer = try std.time.Timer.start();
    var loaded = try contract.load(A, c.symbols, bytes, input);
    defer loaded.deinit();
    const memory = &loaded.memory;
    var service_session = try ethereum.Session.initWithProfile(A, rv.machine.Cpu.init(loaded.info.entry, c.symbols.stack_top), memory, .{ .max_retirements = c.max_steps, .cache_entries = c.cache_entries }, switch (c.execution_profile) {
        .ethereum_services_v3 => .ethereum_services_v3,
        .ethereum_services_v2, .ethereum_services_v3_candidate => .ethereum_services_v2,
        else => .ethereum_services_v1,
    });
    const session = &service_session.keccak.base;
    defer service_session.deinit();
    var census: ?access.Census = if (c.census_batch_steps) |steps| try access.Census.init(A, steps) else null;
    defer if (census) |*value| value.deinit();
    var frequent_census: ?frequent.Census = if (c.frequent_operation_limit) |limit| try frequent.Census.init(A, limit) else null;
    defer if (frequent_census) |*value| value.deinit();
    const execution_profile: rv.execution_profile.Profile = switch (c.execution_profile) {
        .software => .rv64im,
        .keccak_service_v1 => .keccak_service_v1,
        .ethereum_services_v1 => .ethereum_services_v1,
        .ethereum_services_v2 => .ethereum_services_v2,
        // Unreachable with a tape (rejected above); never reaches the prover.
        .ethereum_services_v3_candidate => .ethereum_services_v2,
        .ethereum_services_v3 => .ethereum_services_v3,
    };
    var tape: ?rv.compact_tape.Tape = if (c.compact_capture_batch_steps) |steps| try rv.compact_tape.Tape.init(A, steps, session.cpu.pc, 0, execution_profile) else null;
    defer if (tape) |*value| value.deinit();
    if (c.capture_ram_boundaries and c.compact_capture_batch_steps == null) return error.ExpectedBoundaryBatchSteps;
    var boundaries: ?rv.boundary_capture.Capture = if (c.capture_ram_boundaries) try rv.boundary_capture.Capture.init(A, 0, c.compact_capture_batch_steps.?, 1 << 24) else null;
    defer if (boundaries) |*value| value.deinit();
    var report = Report{ .status = .step_limit, .pc = loaded.info.entry, .instructions = 0, .opcode_counts = @splat(0), .loads = 0, .stores = 0, .allocated_pages = 0, .setup_ns = setup_timer.read(), .execution_ns = 0, .elf_sha256 = undefined, .input_sha256 = undefined };
    report.execution_profile = c.execution_profile;
    report.access_census_batch_steps = c.census_batch_steps;
    if (is_candidate) report.candidate_service_calls = .{};
    if (tape != null) report.compact_capture = .{};
    if (boundaries != null) report.ram_boundary_capture = .{};
    if (c.pc_profile) |range| {
        const counts = try A.alloc(u64, @intCast((range.end - range.start) / 4));
        @memset(counts, 0);
        report.pc_profile = .{ .start = range.start, .end = range.end, .counts = counts };
    }
    errdefer if (report.pc_profile) |profile| A.free(profile.counts);
    var timer = try std.time.Timer.start();
    while (true) {
        if (tape) |*value| if (value.len == value.storage.len) {
            report.compact_capture.?.account(value);
            value.clearRetainingCapacity();
            if (boundaries) |*boundary| {
                report.ram_boundary_capture.?.account(boundary);
                try boundary.clearRetainingCapacity();
            }
        };
        var event: ethereum.Event = undefined;
        const optional_row = profileStep(&service_session, c.execution_profile, &event) catch |first| {
            const err = if (is_candidate and first == error.UnsupportedService) blk: {
                // Admitted services declined the tag; the CPU/memory are unchanged.
                if (candidate.step(A, &session.cpu, memory, &report.candidate_service_calls.?)) |_| {
                    report.opcode_counts[@intFromEnum(rv.decode.Opcode.ECALL)] += 1;
                    if (report.pc_profile) |*profile| {
                        const pc = session.cpu.pc -% 4;
                        if (pc >= profile.start and pc < profile.end) profile.counts[@intCast((pc - profile.start) / 4)] += 1 else profile.outside += 1;
                    }
                    continue;
                } else |second| break :blk second;
            } else first;
            report.status = if (err == error.StepLimit) .step_limit else .trap;
            report.stop_error = @errorName(err);
            report.stopped_instruction = if (memory.load(session.cpu.pc, 4)) |word| @intCast(word) else |_| null;
            break;
        };
        if (optional_row == null) {
            if (tape) |*value| try value.appendEvent(event);
            if (boundaries) |*value| try value.appendEvent(event, memory);
            const retirement = event.retirement();
            switch (event) {
                .keccak => |call| {
                    report.keccak_calls += 1;
                    report.service_ram_word_transitions += 25;
                    if (census) |*value| for (call.before, call.after, 0..) |before, after, i| try value.observe(call.pointer + 8 * i, before, after, true);
                },
                .secp => |call| {
                    if (call.kind == .add) report.secp_add_calls += 1 else report.secp_double_calls += 1;
                    report.service_ram_word_transitions += call.wordCount();
                    if (census) |*value| for (call.before[0..call.wordCount()], call.after[0..call.wordCount()], 0..) |before, after, i| try value.observe(call.pointer + 8 * i, before, after, i < 12);
                },
                .sha256 => |call| {
                    report.sha256_calls += 1;
                    report.service_ram_word_transitions += call.before.len;
                    if (census) |*value| for (call.before, call.after, 0..) |before, after, i| try value.observe(call.pointer + 8 * i, before, after, i < 4);
                },
                .bulk => |e| {
                    const kind = ethereum.bulk_memory.kindOf(e.call.tag).?;
                    const words = e.packet.len / 8;
                    switch (kind) {
                        .memcpy => if (e.packet.word1 & 7 == 0) {
                            report.bulk_memcpy_calls += 1;
                            report.bulk_memcpy_bytes += e.packet.len;
                        } else {
                            report.bulk_memcpy_unaligned_calls += 1;
                            report.bulk_memcpy_unaligned_bytes += e.packet.len;
                        },
                        .memset => {
                            report.bulk_memset_calls += 1;
                            report.bulk_memset_bytes += e.packet.len;
                        },
                        .memcmp => {
                            report.bulk_memcmp_calls += 1;
                            // Proof rows are the examined word pairs, not len.
                            report.bulk_memcmp_bytes += 8 * e.packet.examined;
                        },
                    }
                    const source = ethereum.bulk_memory.sourceWords(e.packet.word1, e.packet.len);
                    report.service_ram_word_transitions += switch (kind) {
                        .memcpy => 3 + words + source.count,
                        .memset => 3 + words,
                        .memcmp => 4 + 2 * e.packet.examined,
                    };
                    if (census) |*value| {
                        for (0..3) |k| {
                            const w = memory.backing.load(e.call.pointer + 8 * k, 8).value;
                            try value.observe(e.call.pointer + 8 * k, w, w, false);
                        }
                        switch (kind) {
                            .memcmp => {
                                try value.observe(e.call.pointer + 24, e.dst_before[0], memory.backing.load(e.call.pointer + 24, 8).value, true);
                                for (0..e.packet.examined) |j| for ([_]u64{ e.packet.dst, e.packet.word1 }) |base| {
                                    const w = memory.backing.load(base + 8 * j, 8).value;
                                    try value.observe(base + 8 * j, w, w, false);
                                };
                            },
                            .memcpy, .memset => {
                                if (kind == .memcpy) for (0..source.count) |j| {
                                    const w = memory.backing.load(source.base + 8 * j, 8).value;
                                    try value.observe(source.base + 8 * j, w, w, false);
                                };
                                for (e.dst_before, 0..) |before, j| try value.observe(e.packet.dst + 8 * j, before, memory.backing.load(e.packet.dst + 8 * j, 8).value, true);
                            },
                        }
                    }
                },
            }
            report.opcode_counts[@intFromEnum(rv.decode.Opcode.ECALL)] += 1;
            if (report.pc_profile) |*profile| {
                const pc = retirement.pc.toInt();
                if (pc >= profile.start and pc < profile.end) profile.counts[@intCast((pc - profile.start) / 4)] += 1 else profile.outside += 1;
            }
            if (census) |*value| switch (event) {
                // Bulk memory is counted as a plain ECALL retirement.
                .bulk => try value.retireOpcode(@intFromEnum(rv.decode.Opcode.ECALL)),
                .keccak => try value.retireService(.keccak),
                .secp => |call| try value.retireService(if (call.kind == .add) .secp_add else .secp_double),
                .sha256 => try value.retireService(.sha256),
            };
            continue;
        }
        const row = optional_row.?;
        if (tape) |*value| try value.append(row);
        if (boundaries) |*value| try value.append(row, memory);
        report.opcode_counts[@intFromEnum(row.opcode)] += 1;
        if (frequent_census) |*value| try value.retire(row);
        if (report.pc_profile) |*profile| {
            const pc = row.pc.toInt();
            if (pc >= profile.start and pc < profile.end) profile.counts[@intCast((pc - profile.start) / 4)] += 1 else profile.outside += 1;
        }
        if (row.memory) |effect| {
            if (effect.write) report.stores += 1 else report.loads += 1;
            const address = effect.address.toInt();
            if (census) |*value| {
                try value.observe(address, effect.before_word.toInt(), effect.after_word.toInt(), effect.write);
                try value.retireOpcode(@intFromEnum(row.opcode));
            }
            if (effect.write and address <= c.symbols.halt_flag + 3 and try rv.memory.endAddress(address, effect.width) >= c.symbols.halt_flag) {
                const flag = try memory.load(c.symbols.halt_flag, 4);
                if (flag == 0) continue;
                if (flag != 1) return error.InvalidEthereumCompletion;
                if (try memory.load(c.symbols.output_len, 4) != contract.OUTPUT_BYTES) return error.InvalidEthereumOutputLength;
                var output: [contract.OUTPUT_BYTES]u8 = undefined;
                for (&output, 0..) |*byte, i| byte.* = @intCast(try memory.load(c.symbols.output_data + i, 1));
                if (!std.mem.eql(u8, &output, &expected)) return error.EthereumOutputMismatch;
                report.output = std.fmt.bytesToHex(output, .lower);
                report.verified_output = true;
                report.status = .completed;
                break;
            }
        } else if (census) |*value| try value.retireOpcode(@intFromEnum(row.opcode));
    }
    report.execution_ns = timer.read();
    report.instructions = session.cpu.retired;
    report.pc = session.cpu.pc;
    report.final_registers = session.cpu.regs;
    report.allocated_pages = memory.pageCount();
    if (census) |*value| report.access_batches = try value.finish();
    if (frequent_census) |*value| report.frequent_operations = try value.summary(A, 256);
    if (tape) |*value| report.compact_capture.?.account(value);
    if (boundaries) |*value| report.ram_boundary_capture.?.account(value);
    return report;
}
test {
    _ = candidate;
}
