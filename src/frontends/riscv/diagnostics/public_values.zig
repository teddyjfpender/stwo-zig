//! Proof-independent public-value derivation for oracle comparison.
//!
//! This boundary executes no prover admission logic. It derives the statement
//! from an already completed execution and the same program/RW sparse-tree
//! builders consumed by the production prover.
//!
//! The production adapter first owns public I/O and then the prover constructs
//! these trees while assembling committed infrastructure. Calling a shared
//! full-statement helper there would either construct both trees twice or make
//! this diagnostic depend on proof admission. Directly importing the production
//! tree builders keeps the shared derivation exact without either coupling.

const std = @import("std");
const public_data = @import("../air/public_data.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_table = @import("../air/program/table.zig");
const authority = @import("../isa/authority.zig");
const runner = @import("../runner/mod.zig");
const witness_layout = @import("../witness_layout.zig");

pub const SCHEMA = "riscv-public-values-diagnostic-v1";
pub const DERIVATION = "execution_and_committed_tree_builders_without_proof_admission";

pub const OwnedPublicData = struct {
    data: public_data.PublicData,
    input_words: []u32,
    output_words: []public_data.OutputWord,

    pub fn deinit(self: *OwnedPublicData, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

/// Derive the exact pinned-oracle public statement without asking whether its
/// opcode families are currently admitted to production proving.
pub fn derive(
    allocator: std.mem.Allocator,
    run_result: *const runner.RunResult,
) !OwnedPublicData {
    const input_words = try public_data.packInputWords(allocator, run_result.input);
    errdefer allocator.free(input_words);

    const output_words = try allocator.alloc(public_data.OutputWord, run_result.output_words.len);
    errdefer allocator.free(output_words);
    for (run_result.output_words, output_words) |source, *destination| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }

    var memory = try memory_boundary.build(allocator, run_result.rw_memory.words);
    defer memory.deinit(allocator);
    try memory.validate(allocator);

    const fetches = try allocator.alloc(program_table.Fetch, run_result.execution_trace.rows.items.len);
    defer allocator.free(fetches);
    for (run_result.execution_trace.rows.items, fetches) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    var program = try program_commitment.build(
        allocator,
        fetches,
        run_result.rw_memory.program_words,
    );
    defer program.deinit(allocator);

    const data = public_data.PublicData{
        .initial_pc = run_result.initial_pc,
        .final_pc = run_result.final_pc,
        .clock = std.math.cast(u32, run_result.step_count) orelse return error.ClockOverflow,
        .initial_regs = run_result.initial_regs,
        .final_regs = run_result.final_regs,
        .reg_last_clock = run_result.state_chain_tracker.reg_last_clk,
        .program_root = program.tree.root,
        .initial_rw_root = if (memory.initial_tree) |tree| tree.root else null,
        .final_rw_root = if (memory.final_tree) |tree| tree.root else null,
        .completion = try public_data.completionFromRun(run_result),
        .io_entries = .{
            .input_start = run_result.input_start,
            .input_len = std.math.cast(u32, run_result.input.len) orelse
                return error.InputLengthOverflow,
            .input_words = input_words,
            .output_len = run_result.output_len,
            .output_len_addr = run_result.output_len_addr,
            .output_data_addr = run_result.output_data_addr,
            .output_words = output_words,
        },
    };
    try data.validate();

    return .{
        .data = data,
        .input_words = input_words,
        .output_words = output_words,
    };
}

const ProvenanceWire = struct {
    implementation_commit: []const u8,
    implementation_dirty: bool,
    oracle_commit: []const u8,
    witness_layout_sha256: []const u8,
};

const SourceWire = struct {
    elf_sha256: []const u8,
    input_sha256: []const u8,
};

const DiagnosticWire = struct {
    schema: []const u8,
    derivation: []const u8,
    provenance: ProvenanceWire,
    source: SourceWire,
    public_data: public_data.PublicData,
};

/// Encode a self-identifying diagnostic result. Oracle and witness-layout pins
/// are sourced from the live implementation rather than accepted from a caller.
pub fn encode(
    allocator: std.mem.Allocator,
    data: public_data.PublicData,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    elf_bytes: []const u8,
    input_bytes: []const u8,
) ![]u8 {
    var elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &elf_digest, .{});
    var input_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input_bytes, &input_digest, .{});
    const elf_hex = std.fmt.bytesToHex(elf_digest, .lower);
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const layout_hex = std.fmt.bytesToHex(witness_layout.digest(), .lower);

    return std.json.Stringify.valueAlloc(allocator, DiagnosticWire{
        .schema = SCHEMA,
        .derivation = DERIVATION,
        .provenance = .{
            .implementation_commit = implementation_commit,
            .implementation_dirty = implementation_dirty,
            .oracle_commit = authority.sail_revision,
            .witness_layout_sha256 = &layout_hex,
        },
        .source = .{
            .elf_sha256 = &elf_hex,
            .input_sha256 = &input_hex,
        },
        .public_data = data,
    }, .{});
}

test "public-value diagnostic schema binds provenance and nonempty IO shape" {
    const input_words = [_]u32{0x0403_0201};
    const output_words = [_]public_data.OutputWord{.{
        .addr = 0x20,
        .value = 0,
        .clock = 7,
    }};
    const data = public_data.PublicData{
        .initial_pc = 0x1000,
        .final_pc = 0x1020,
        .clock = 7,
        .initial_regs = [_]u32{0} ** 32,
        .final_regs = [_]u32{0} ** 32,
        .reg_last_clock = [_]u32{0} ** 32,
        .program_root = 11,
        .initial_rw_root = 22,
        .final_rw_root = 33,
        .completion = public_data.Completion.canonicalSelfLoop(0x1020),
        .io_entries = .{
            .input_start = 0x10,
            .input_len = 4,
            .input_words = &input_words,
            .output_len = 0,
            .output_len_addr = 0x20,
            .output_data_addr = 0x24,
            .output_words = &output_words,
        },
    };
    const encoded = try encode(
        std.testing.allocator,
        data,
        "0123456789012345678901234567890123456789",
        true,
        "elf",
        "\x01\x02\x03\x04",
    );
    defer std.testing.allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    try std.testing.expectEqual(@as(usize, 5), root.count());
    try std.testing.expectEqualStrings(SCHEMA, root.get("schema").?.string);
    try std.testing.expectEqualStrings(DERIVATION, root.get("derivation").?.string);
    const provenance = root.get("provenance").?.object;
    try std.testing.expectEqual(@as(usize, 4), provenance.count());
    try std.testing.expect(provenance.get("implementation_dirty").?.bool);
    try std.testing.expectEqualStrings(
        authority.sail_revision,
        provenance.get("oracle_commit").?.string,
    );
    const io = root.get("public_data").?.object.get("io_entries").?.object;
    try std.testing.expectEqual(@as(usize, 1), io.get("input_words").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 1), io.get("output_words").?.array.items.len);
}
