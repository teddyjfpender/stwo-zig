//! First pinned Pokémon checkpoint replay against the SameBoy callback oracle.
//!
//! The proof prefix is exactly 2^12 machine rows. A bounded lookahead through
//! the next instruction callback binds any trailing HALT span without changing
//! the prefix boundary that will be proved.

const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const sameboy_checkpoint = @import("checkpoint/sameboy.zig");
const oracle = @import("sameboy_instruction_trace.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");

const ROM_PATH = "pokered_rogue_e2e.gbc";
const ROM_SHA256 =
    "ebc21f5a683278aeb690a4cbad9576e33ee42fbe271d44e103047576d4108327";
const CHECKPOINT_PATH =
    "build/traces/battle-seed-1/boundary-000000.s1";
const CHECKPOINT_SHA256 =
    "c4d99e64d7a08e1828af6bdc0d9e5f930bd7315f137eb1f8d518cd5a9c9f31ea";
const TRACE_PATH = "build/traces/battle-seed-1/instructions.bin";
const TRACE_SHA256 =
    "58c4462e9370163a9714f3a9d9195fa8735b2496e04c1b5b6abf81760feec59d";
const TRACE_SIZE: usize = 182_452_224;
const TRACE_RECORDS: usize = 6_291_456;
const PREFIX_ROWS: usize = 1 << 12;
const MAX_LOOKAHEAD_ROWS: usize = 1 << 15;
const EXPECTED_PREFIX_INSTRUCTIONS: usize = 929;
const EXPECTED_PREFIX_MCYCLES: u64 = 5_211;
const EXPECTED_LOOKAHEAD_ROWS: usize = 10_239;
const EXPECTED_ORACLE_RECORDS: usize = 930;
const INITIAL_MCYCLE: u32 = 13_312_966;
const FIRST_CALLBACK_MCYCLE: u32 = INITIAL_MCYCLE;
/// PE-AGI applies frame 760 before capture; START remains pressed.
const INITIAL_PRESSED: u8 = runner.joypad.Key.start.mask();

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: zig run src/frontends/sm83/sameboy_replay_gate.zig -- " ++
                "/path/to/PE-AGI/v1\n",
            .{},
        );
        return error.InvalidArguments;
    }

    var directory = std.fs.cwd().openDir(arguments[1], .{}) catch |err| {
        std.debug.print(
            "SM83 SameBoy replay: missing pinned corpus root {s}: {s}\n",
            .{ arguments[1], @errorName(err) },
        );
        return error.MissingPinnedReplayCorpus;
    };
    defer directory.close();

    const rom = try readPinned(
        allocator,
        &directory,
        ROM_PATH,
        cartridge.header.ROM_SIZE,
        ROM_SHA256,
    );
    defer allocator.free(rom);
    if (rom.len != cartridge.header.ROM_SIZE)
        return error.InvalidRomSize;

    const checkpoint_bytes = try readPinned(
        allocator,
        &directory,
        CHECKPOINT_PATH,
        sameboy_checkpoint.CHECKPOINT_SIZE,
        CHECKPOINT_SHA256,
    );
    defer allocator.free(checkpoint_bytes);
    if (checkpoint_bytes.len != sameboy_checkpoint.CHECKPOINT_SIZE)
        return error.InvalidCheckpointSize;

    const trace_bytes = try readPinned(
        allocator,
        &directory,
        TRACE_PATH,
        TRACE_SIZE,
        TRACE_SHA256,
    );
    defer allocator.free(trace_bytes);
    if (trace_bytes.len != TRACE_SIZE)
        return error.InvalidTraceSize;
    const trace = try oracle.Trace.init(trace_bytes);
    if (trace.count() != TRACE_RECORDS)
        return error.InvalidTraceRecordCount;
    try trace.validateAll();
    if (try (try trace.record(0)).callbackMcycle() != FIRST_CALLBACK_MCYCLE)
        return error.InvalidInitialClock;

    var checkpoint = try sameboy_checkpoint.import(
        allocator,
        checkpoint_bytes,
        rom,
    );
    defer checkpoint.deinit();
    const restored_timer = try checkpoint.toTimer();
    var joypad = try checkpoint.toJoypad(INITIAL_PRESSED);
    var ppu = try checkpoint.toPpuMmio();
    const dma = try checkpoint.toDma(INITIAL_MCYCLE);
    if (dma.phase != .idle) return error.ActiveInitialDmaUnsupported;

    const loaded_cartridge = try cartridge.Cartridge.init(rom);
    var memory = runner.cartridge_memory.Memory.init(
        loaded_cartridge,
        checkpoint.sram,
        checkpoint.system,
        checkpoint.mapper,
        checkpoint.data_bus,
    );
    try memory.attachJoypad(&joypad);
    defer memory.detachJoypad();
    try memory.attachPpu(&ppu);
    defer memory.detachPpu();
    var scheduler = try machine.CartridgeMachine.restore(
        &memory,
        checkpoint.cpu,
        restored_timer,
        checkpoint.halt_bug,
    );

    var comparator = oracle.Comparator{
        .trace = trace,
        .initial_boundary_mcycle = INITIAL_MCYCLE,
    };
    var prefix_mcycles: u64 = 0;
    var prefix_instructions: usize = 0;
    for (0..PREFIX_ROWS) |row| {
        const result = scheduler.step() catch |err| {
            printDivergence(row, comparator.next_record, err);
            return err;
        };
        if (!result.hasCanonicalShape()) {
            printDivergence(
                row,
                comparator.next_record,
                error.NonCanonicalMachineRow,
            );
            return error.NonCanonicalMachineRow;
        }
        comparator.observe(result) catch |err| {
            printDivergence(row, comparator.next_record, err);
            return err;
        };
        prefix_mcycles += result.m_cycles;
        prefix_instructions += @intFromBool(result.event == .instruction);
    }

    const consumed_at_boundary = comparator.next_record;
    var lookahead_rows: usize = 0;
    while (comparator.next_record == consumed_at_boundary and
        lookahead_rows < MAX_LOOKAHEAD_ROWS)
    {
        const result = scheduler.step() catch |err| {
            printDivergence(
                PREFIX_ROWS + lookahead_rows,
                comparator.next_record,
                err,
            );
            return err;
        };
        if (!result.hasCanonicalShape())
            return error.NonCanonicalMachineRow;
        comparator.observe(result) catch |err| {
            printDivergence(
                PREFIX_ROWS + lookahead_rows,
                comparator.next_record,
                err,
            );
            const expected = try trace.record(comparator.next_record);
            const expected_mcycle = try expected.callbackMcycle();
            std.debug.print(
                "SM83 SameBoy replay: prefix_instructions={d} " ++
                    "prefix_mcycles={d} lookahead_rows={d} " ++
                    "actual_callback_delta={d} " ++
                    "expected_callback_delta={d}\n",
                .{
                    prefix_instructions,
                    prefix_mcycles,
                    lookahead_rows,
                    comparator.elapsed_since_callback,
                    expected_mcycle -
                        comparator.previous_callback_mcycle.?,
                },
            );
            return err;
        };
        lookahead_rows += 1;
    }
    if (comparator.next_record == consumed_at_boundary)
        return error.LookaheadExhausted;
    if (comparator.next_record != consumed_at_boundary + 1)
        return error.InstructionCountMismatch;
    if (prefix_instructions != EXPECTED_PREFIX_INSTRUCTIONS or
        prefix_mcycles != EXPECTED_PREFIX_MCYCLES or
        lookahead_rows != EXPECTED_LOOKAHEAD_ROWS or
        comparator.next_record != EXPECTED_ORACLE_RECORDS)
    {
        return error.InvalidPositiveCount;
    }

    std.debug.print(
        "SM83 SameBoy replay: PASS prefix_rows={d} " ++
            "prefix_instructions={d} prefix_mcycles={d} " ++
            "lookahead_rows={d} oracle_records={d}\n",
        .{
            PREFIX_ROWS,
            prefix_instructions,
            prefix_mcycles,
            lookahead_rows,
            comparator.next_record,
        },
    );
}

fn readPinned(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    path: []const u8,
    maximum_size: usize,
    expected_sha256: []const u8,
) ![]u8 {
    const bytes = directory.readFileAlloc(
        allocator,
        path,
        maximum_size,
    ) catch |err| {
        std.debug.print(
            "SM83 SameBoy replay: missing pinned artifact {s}: {s}\n",
            .{ path, @errorName(err) },
        );
        return error.MissingPinnedReplayCorpus;
    };
    errdefer allocator.free(bytes);
    try validateDigest(bytes, expected_sha256);
    return bytes;
}

fn validateDigest(bytes: []const u8, expected_hex: []const u8) !void {
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    if (!std.mem.eql(u8, &actual, &expected))
        return error.ContentDigestMismatch;
}

fn printDivergence(
    machine_row: usize,
    oracle_record: usize,
    err: anyerror,
) void {
    std.debug.print(
        "SM83 SameBoy replay: DIVERGENCE machine_row={d} " ++
            "oracle_record={d} error={s}\n",
        .{ machine_row, oracle_record, @errorName(err) },
    );
}

test "replay constants pin a power-of-two prefix and complete corpus" {
    try std.testing.expect(std.math.isPowerOfTwo(PREFIX_ROWS));
    try std.testing.expectEqual(TRACE_SIZE / oracle.RECORD_SIZE, TRACE_RECORDS);
    try std.testing.expectEqual(INITIAL_MCYCLE, FIRST_CALLBACK_MCYCLE);
    try std.testing.expect(MAX_LOOKAHEAD_ROWS > PREFIX_ROWS);
    try std.testing.expectEqual(
        EXPECTED_PREFIX_INSTRUCTIONS + 1,
        EXPECTED_ORACLE_RECORDS,
    );
}
