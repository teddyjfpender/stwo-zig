//! Parameterizable release-shape guest ELF: a caller-supplied instruction body
//! wrapped in the fixed prologue and epilogue the release ABI requires.
//!
//! Adversarial AIR tests need a *committed* row of one opcode family, which
//! means an ELF that retires that opcode and can be proven. Every such test
//! needs the same wrapper — the release ABI symbols `elf_loader.validateReleaseAbi`
//! looks up, a public-input read, a published output word, and a halt-flag
//! store — and differs only in the instructions under test. This module owns the
//! wrapper so a family test owns nothing but its opcode stream.
//!
//! # Why the input length is fixed at one word
//!
//! The memory-access bus closes a public-input word only when the guest touches
//! it. `PublicData.io_entries.input_words` is derived from the whole input, and
//! `public_logup.memoryAccessSum` emits every one of those words at clock zero;
//! `memory_state.WordState.includeFinal` emits the matching consume only when
//! `final_clock > 0`, i.e. only when some instruction accessed the word. A guest
//! handed more public input than it reads therefore *proves* and then fails
//! verification with `LogupSumNonZero` — a global-cancellation failure with no
//! relation to whatever the test was probing.
//!
//! So the declared input region here is exactly one word wide and `INPUT` is
//! exactly that word: `runner.runWithInput` rejects a longer input with
//! `error.InputTooLarge` before any proof is attempted, and the prologue's
//! single `LW` closes the one word that exists. The invariant is structural
//! rather than remembered.
//!
//! # Register discipline for the body
//!
//! The epilogue needs `x1 = __halt_flag` and clobbers `x2`. A body must not
//! write `x1`; `x2` is free because the epilogue reloads it. `x4` and `x5` hold
//! the input pointer and the loaded input word and are free to clobber.
//!
//! A body that transfers control must land back in the straight-line stream:
//! `bodyPc` gives the address of every body instruction, so a `JALR` test
//! computes its own target from `bodyPc(index + 1)`. `bodyClock` and `bodyRow`
//! assume each body instruction retires exactly once, which is what a
//! straight-line body does.

const std = @import("std");
const sail_oracle = @import("stwo_riscv_frontend").runner.sail_oracle;

pub const CODE_VADDR: u32 = 0x0001_0000;
const INPUT_START: u32 = 0x0018_0000;
/// One word: see the input-length discussion above.
const INPUT_END: u32 = INPUT_START + 4;
const HALT_FLAG: u32 = 0x0010_0000;
const OUTPUT_LEN: u32 = 0x0010_0004;
const OUTPUT_DATA: u32 = 0x0010_0008;
const STACK_BOTTOM: u32 = 0x001F_FC00;
const STACK_TOP: u32 = 0x0020_0000;
const GLOBAL_POINTER: u32 = 0x0020_0800;
const OUTPUT_END: u32 = STACK_BOTTOM;

/// The public input every guest built here consumes, exactly one word wide.
pub const INPUT = [_]u8{ 1, 2, 3, 4 };

/// The runner-initialized data memory of every guest built here, as the Sail
/// oracle's seed image: exactly the input word at the declared input region.
/// Code is not data to these guests — no body may load from the text segment,
/// because Sail over RVFI-DII executes injected words without an ELF image —
/// so the input word is the whole image. Derived from the same constants the
/// wrapper assembles with, never from an executed trace.
pub fn initialMemory() [1]sail_oracle.MemoryWord {
    return .{.{
        .address = INPUT_START,
        .value = std.mem.readInt(u32, INPUT[0..4], .little),
    }};
}

/// `LUI x1, __halt_flag`, `LUI x4, __input_start`, `LW x5, 0(x4)`.
const PROLOGUE = [_]u32{
    0x0010_00B7,
    0x0018_0237,
    0x0002_2283,
};

/// Instructions before the caller's body, so `bodyPc(0)` is the body's entry.
pub const PROLOGUE_LEN: usize = PROLOGUE.len;

/// `ADDI x2, x0, 4`, `SW x2, 4(x1)`, `SW xN, 8(x1)`, `ADDI x2, x0, 1`,
/// `SW x2, 0(x1)`: publish `output_len = 4`, publish one output word, then set
/// the halt flag before the next fetch.
pub const EPILOGUE_LEN: usize = 5;

/// Proof-bearing completion emitted after the public-output stores.
///
/// The committed-forgery fleet keeps the release ABI's halt flag by default.
/// Recursion V1 deliberately admits only the canonical unretired self-loop,
/// so its real-proof fixture selects `.self_loop` without maintaining a
/// second ELF assembler or changing the guest's trace geometry.
pub const Completion = enum {
    halt_flag,
    self_loop,
};

/// What to assemble around a caller's instruction stream.
pub const Spec = struct {
    /// The instructions under test, retired between prologue and epilogue.
    body: []const u32,
    /// Register whose value the epilogue publishes as public output word 0.
    /// Publishing is not what binds a forged row — `public_logup` emits all 32
    /// final register values regardless — but it keeps the retired result in
    /// the statement where a reader can see it.
    publish: u5 = 10,
    completion: Completion = .halt_flag,
};

/// Total instructions of `spec`, i.e. the retired step count of a
/// straight-line body.
pub fn instructionCount(spec: Spec) usize {
    return PROLOGUE_LEN + spec.body.len + EPILOGUE_LEN;
}

/// Step budget for `runner.runWithInput`: the retired count plus slack, so a
/// body that loops fails on its own completion assertion rather than silently
/// hitting the step cap.
pub fn maxSteps(spec: Spec) usize {
    return instructionCount(spec) + 16;
}

/// Program counter of body instruction `index`.
pub fn bodyPc(index: usize) u32 {
    return CODE_VADDR + @as(u32, @intCast((PROLOGUE_LEN + index) * 4));
}

/// One-based execution clock stamped on body instruction `index`. The runner
/// stamps every access of step `n` with clock `n + 1`.
pub fn bodyClock(index: usize) u32 {
    return @intCast(PROLOGUE_LEN + index + 1);
}

/// Index of body instruction `index` in `RunResult.execution_trace.rows`.
pub fn bodyRow(index: usize) usize {
    return PROLOGUE_LEN + index;
}

const Symbol = struct {
    name: []const u8,
    value: u32,
};

const SYMBOL_NAMES = [_][]const u8{
    "__text_start",
    "__text_len",
    "__data_start",
    "__data_len",
    "__global_pointer$",
    "__stack_bottom",
    "__stack_top",
    "__input_start",
    "__input_end",
    "__halt_flag",
    "__output_len",
    "__output_data",
    "__output_end",
};

fn symbolValues(text_len: u32) [SYMBOL_NAMES.len]u32 {
    return .{
        CODE_VADDR,
        text_len,
        STACK_TOP,
        0,
        GLOBAL_POINTER,
        STACK_BOTTOM,
        STACK_TOP,
        INPUT_START,
        INPUT_END,
        HALT_FLAG,
        OUTPUT_LEN,
        OUTPUT_DATA,
        OUTPUT_END,
    };
}

const ELF_HEADER_SIZE: usize = 52;
const PROGRAM_HEADER_SIZE: usize = 32;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_ENTRY_SIZE: usize = 16;
const SECTION_COUNT: usize = 4;
const SHSTRTAB = "\x00.symtab\x00.strtab\x00.shstrtab\x00";
const STRTAB_SIZE: usize = blk: {
    var size: usize = 1;
    for (SYMBOL_NAMES) |name| size += name.len + 1;
    break :blk size;
};

/// Assemble the guest. The caller owns the returned bytes.
pub fn build(allocator: std.mem.Allocator, spec: Spec) ![]u8 {
    const count = instructionCount(spec);
    const code_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
    const code_size = count * @sizeOf(u32);
    const symtab_offset = code_offset + code_size;
    const symtab_size = (SYMBOL_NAMES.len + 1) * SYMBOL_ENTRY_SIZE;
    const strtab_offset = symtab_offset + symtab_size;
    const shstrtab_offset = strtab_offset + STRTAB_SIZE;
    const section_headers_offset = shstrtab_offset + SHSTRTAB.len;
    const elf_size = section_headers_offset + SECTION_COUNT * SECTION_HEADER_SIZE;

    const elf = try allocator.alloc(u8, elf_size);
    errdefer allocator.free(elf);
    @memset(elf, 0);

    elf[0..4].* = .{ 0x7F, 'E', 'L', 'F' };
    elf[4] = 1; // ELFCLASS32
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    writeU16(elf, 16, 2); // ET_EXEC
    writeU16(elf, 18, 0xF3); // EM_RISCV
    writeU32(elf, 20, 1);
    writeU32(elf, 24, CODE_VADDR);
    writeU32(elf, 28, ELF_HEADER_SIZE);
    writeU32(elf, 32, section_headers_offset);
    writeU16(elf, 40, ELF_HEADER_SIZE);
    writeU16(elf, 42, PROGRAM_HEADER_SIZE);
    writeU16(elf, 44, 1);
    writeU16(elf, 46, SECTION_HEADER_SIZE);
    writeU16(elf, 48, SECTION_COUNT);
    writeU16(elf, 50, 3); // .shstrtab section index

    writeU32(elf, ELF_HEADER_SIZE, 1); // PT_LOAD
    writeU32(elf, ELF_HEADER_SIZE + 4, code_offset);
    writeU32(elf, ELF_HEADER_SIZE + 8, CODE_VADDR);
    writeU32(elf, ELF_HEADER_SIZE + 16, code_size);
    writeU32(elf, ELF_HEADER_SIZE + 20, code_size);

    var cursor = code_offset;
    for (PROLOGUE) |instruction| {
        writeU32(elf, cursor, instruction);
        cursor += @sizeOf(u32);
    }
    for (spec.body) |instruction| {
        writeU32(elf, cursor, instruction);
        cursor += @sizeOf(u32);
    }
    for (epilogue(spec.publish, spec.completion)) |instruction| {
        writeU32(elf, cursor, instruction);
        cursor += @sizeOf(u32);
    }
    std.debug.assert(cursor == symtab_offset);

    const values = symbolValues(@intCast(code_size));
    var string_offset: u32 = 1;
    var string_cursor = strtab_offset + 1;
    for (SYMBOL_NAMES, values, 0..) |name, value, index| {
        const symbol_offset = symtab_offset + (index + 1) * SYMBOL_ENTRY_SIZE;
        writeU32(elf, symbol_offset, string_offset);
        writeU32(elf, symbol_offset + 4, value);
        elf[symbol_offset + 12] = 0x10; // STB_GLOBAL
        writeU16(elf, symbol_offset + 14, 0xFFF1); // SHN_ABS

        @memcpy(elf[string_cursor .. string_cursor + name.len], name);
        string_cursor += name.len + 1;
        string_offset += @intCast(name.len + 1);
    }
    @memcpy(elf[shstrtab_offset .. shstrtab_offset + SHSTRTAB.len], SHSTRTAB);

    writeSectionHeader(elf, section_headers_offset, 0, 0, 0, 0, 0, 0);
    writeSectionHeader(
        elf,
        section_headers_offset + SECTION_HEADER_SIZE,
        1,
        2,
        symtab_offset,
        symtab_size,
        2,
        SYMBOL_ENTRY_SIZE,
    );
    writeSectionHeader(
        elf,
        section_headers_offset + 2 * SECTION_HEADER_SIZE,
        9,
        3,
        strtab_offset,
        STRTAB_SIZE,
        0,
        0,
    );
    writeSectionHeader(
        elf,
        section_headers_offset + 3 * SECTION_HEADER_SIZE,
        17,
        3,
        shstrtab_offset,
        SHSTRTAB.len,
        0,
        0,
    );

    return elf;
}

/// `SW x{register}, 8(x1)`, assembled rather than tabulated so the publish
/// register stays a parameter of one instruction instead of a table of 32.
fn storePublishedWord(register: u5) u32 {
    const imm: u32 = 8;
    return (@as(u32, register) << 20) | (1 << 15) | (2 << 12) | (imm << 7) | 0x23;
}

fn epilogue(publish: u5, completion: Completion) [EPILOGUE_LEN]u32 {
    return .{
        0x0040_0113, // ADDI x2, x0, 4
        0x0020_A223, // SW x2, 4(x1): publish output_len = 4
        storePublishedWord(publish),
        0x0010_0113, // ADDI x2, x0, 1
        switch (completion) {
            .halt_flag => 0x0020_A023, // SW x2, 0(x1): halt before the next fetch
            .self_loop => 0x0000_006f, // JAL x0, 0: observed, never retired
        },
    };
}

fn writeSectionHeader(
    elf: []u8,
    offset: usize,
    name: u32,
    section_type: u32,
    file_offset: usize,
    size: usize,
    link: u32,
    entry_size: usize,
) void {
    writeU32(elf, offset, name);
    writeU32(elf, offset + 4, section_type);
    writeU32(elf, offset + 16, file_offset);
    writeU32(elf, offset + 20, size);
    writeU32(elf, offset + 24, link);
    writeU32(elf, offset + 28, @as(u32, if (section_type == 2) 1 else 0));
    writeU32(elf, offset + 32, 1);
    writeU32(elf, offset + 36, entry_size);
}

fn writeU16(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(value), .little);
}

fn writeU32(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], @intCast(value), .little);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const elf_loader = @import("stwo_riscv_frontend").runner.elf_loader;
const runner = @import("stwo_riscv_frontend").runner;

/// `ADDI x10, x0, 7`: a one-instruction body for the wrapper's own tests.
const ADDI_X10_7: u32 = 0x0070_0513;

// Runtime: milliseconds. One nine-instruction run.
test "guest elf fixture: the wrapper satisfies the release ABI and halts on the flag" {
    const allocator = std.testing.allocator;
    const spec = Spec{ .body = &.{ADDI_X10_7} };
    const elf = try build(allocator, spec);
    defer allocator.free(elf);
    try elf_loader.validateReleaseAbi(elf);

    var run = try runner.runWithInput(allocator, elf, &INPUT, maxSteps(spec));
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.halt_flag, run.completion_reason);
    try std.testing.expectEqual(instructionCount(spec), run.step_count);
    try std.testing.expectEqual(@as(u32, 7), run.final_regs[10]);

    // The published word is the register the spec names, so a caller can read
    // the retired result out of the statement.
    try std.testing.expectEqual(@as(u32, 4), run.output_len);
    try std.testing.expect(run.output != null);
    try std.testing.expectEqual(
        @as(u32, 7),
        std.mem.readInt(u32, run.output.?[0..4], .little),
    );

    // The body's own row is where `bodyPc`/`bodyClock` say it is.
    const row = run.execution_trace.rows.items[bodyRow(0)];
    try std.testing.expectEqual(bodyPc(0), row.pc);
    try std.testing.expectEqual(bodyClock(0), row.clk);
}

// Runtime: milliseconds.
test "guest elf fixture: an input wider than the declared region is refused" {
    // The refusal is the load-bearing half of the input invariant: an input the
    // prologue does not read would emit an unconsumed public memory-access
    // term and fail global LogUp cancellation after proving succeeded.
    const allocator = std.testing.allocator;
    const spec = Spec{ .body = &.{ADDI_X10_7} };
    const elf = try build(allocator, spec);
    defer allocator.free(elf);
    const too_wide = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(
        error.InputTooLarge,
        runner.runWithInput(allocator, elf, &too_wide, maxSteps(spec)),
    );
}
