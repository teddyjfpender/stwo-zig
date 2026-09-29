//! Host inputs of the circuit-recursion leaf statement.
//!
//! The in-circuit `CairoStatement::new` (design §5.3) takes the serialized
//! auxiliary data as plain M31 words, the program as 28-limb felts, the output
//! as a Blake2s digest and the 83 `enabled_bits`. This module derives each of
//! them from the Cairo lane's existing statement code instead of re-walking
//! memory, and fails closed wherever upstream would panic or silently diverge.
//! The circuit frontend never imports it (design §2.2); leaf orchestration
//! and test roots do.
//!
//! Upstream (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230):
//! `crates/cairo_verifier/src/statement.rs` (`serialize_aux_data`,
//! `AUX_DATA_FIXED_LEN`, `claims_to_mix`), `crates/cairo_verifier/src/verify.rs`
//! (`output_hash_from_output_cells`), `crates/cairo_verifier/src/utils.rs`
//! (`load_program`) and `crates/leaf_prover/src/prove_leaf.rs`
//! (`leaf_verifier_components`). `vectors/circuit/r6/cairo_statement.json`
//! pins every function here.

const std = @import("std");
const core = @import("stwo_core");
const layout = @import("stwo_core").cairo_air_layout;
const adapter = @import("../adapter/mod.zig");
const claim_registry = @import("../air/official_claim_registry.zig");
const Felt252 = @import("../common/felt252.zig").Felt252;
const public_data = @import("public_data.zig");

const M31 = core.fields.m31.M31;
const Blake2sHasher = core.vcs.blake2_hash.Blake2sHasher;

pub const n_segments = adapter.N_PUBLIC_SEGMENTS;
pub const n_outputs = 2;
pub const n_words_per_output_cell = 4;
pub const memory_values_limbs = 28;
/// `2 * STATE_LEN + 2 * PUB_MEMORY_VALUE_M31_LEN * N_SEGMENTS + N_SAFE_CALL_IDS + N_OUTPUTS`.
pub const aux_data_fixed_len = 2 * 3 + 2 * 2 * n_segments + 2 + n_outputs;
pub const ProgramFelt = [memory_values_limbs]M31;

comptime {
    std.debug.assert(aux_data_fixed_len == 54);
    std.debug.assert(n_outputs * n_words_per_output_cell == 8);
}

pub const Error = error{
    /// `serialize_aux_data` drops absent segments while the circuit expects
    /// eleven; the two layouts agree only when every segment is present.
    AbsentPublicSegment,
    /// The leaf circuit requires exactly `n_outputs` output cells.
    OutputCellCount,
    /// An output cell does not fit in 128 bits.
    OutputCellTooWide,
    InvalidAuxDataLength,
    InvalidClaimWord,
    InvalidProgramJson,
    InvalidFeltHex,
    SlotCountMismatch,
};

// ---------------------------------------------------------------------------
// Auxiliary data

/// `serialize_aux_data` from the public claim words the Cairo lane already
/// derives (`public_data.derive(...).public_claim[0..public_claim_word_count]`,
/// which is `PublicData::pack_into_u32s().0`): with all segments present it is
/// that prefix followed by the component log sizes.
pub fn serializeAuxDataFromPublicClaim(
    allocator: std.mem.Allocator,
    public_claim: []const u32,
    segments_present: [n_segments]bool,
    output_len: usize,
    program_len: usize,
    component_log_sizes: []const u32,
) (Error || std.mem.Allocator.Error)![]u32 {
    for (segments_present) |present| if (!present) return Error.AbsentPublicSegment;
    if (output_len != n_outputs) return Error.OutputCellCount;
    if (public_claim.len != aux_data_fixed_len + program_len) return Error.InvalidAuxDataLength;
    const words = try allocator.alloc(u32, public_claim.len + component_log_sizes.len);
    errdefer allocator.free(words);
    @memcpy(words[0..public_claim.len], public_claim);
    @memcpy(words[public_claim.len..], component_log_sizes);
    for (words) |word| public_data.validateClaimWord(word) catch return Error.InvalidClaimWord;
    return words;
}

/// `serialize_aux_data(flat_claim)` for a Cairo execution, with the flat
/// claim's log sizes (`statement_bootstrap.OwnedFlatClaimGeometry`).
pub fn serializeAuxData(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    component_log_sizes: []const u32,
) (Error || public_data.Error || std.mem.Allocator.Error)![]u32 {
    const segments = try public_data.extractPublicSegments(input);
    var present: [n_segments]bool = undefined;
    for (segments, &present) |segment, *flag| flag.* = segment != null;
    const statement = try public_data.derive(allocator, input);
    defer allocator.free(statement.public_claim);
    return serializeAuxDataFromPublicClaim(
        allocator,
        statement.public_claim[0..statement.public_claim_word_count],
        present,
        statement.output_len,
        statement.program_len,
        component_log_sizes,
    );
}

// ---------------------------------------------------------------------------
// Output hash

/// `output_hash_from_output_cells`: the low `n_words_per_output_cell` words of
/// each output cell, little-endian, form the Blake2s digest the leaf exposes.
pub fn outputHashFromOutputCells(cells: []const [8]u32) Error![8]u32 {
    if (cells.len != n_outputs) return Error.OutputCellCount;
    var digest: [8]u32 = undefined;
    for (cells, 0..) |cell, index| {
        for (cell[n_words_per_output_cell..]) |word| if (word != 0) return Error.OutputCellTooWide;
        @memcpy(digest[index * n_words_per_output_cell ..][0..n_words_per_output_cell], cell[0..n_words_per_output_cell]);
    }
    return digest;
}

// ---------------------------------------------------------------------------
// Program

/// `load_program`'s felt parsing: `0x` hex, left-padded to 64 digits, split
/// into eight LE u32 words, not reduced modulo P. Values wider than 256 bits
/// and non-hex digits are rejected (upstream panics or misreads them).
pub fn parseFeltHex(text: []const u8) Error![8]u32 {
    if (!std.mem.startsWith(u8, text, "0x")) return Error.InvalidFeltHex;
    const digits = text[2..];
    if (digits.len > 64) return Error.InvalidFeltHex;
    var words = [_]u32{0} ** 8;
    for (digits, 0..) |digit, index| {
        const nibble = std.fmt.charToDigit(digit, 16) catch return Error.InvalidFeltHex;
        const bit = (digits.len - 1 - index) * 4;
        words[bit / 32] |= @as(u32, nibble) << @intCast(bit % 32);
    }
    return words;
}

/// The program felts of a compiled Cairo program's `data` array, as
/// `Felt252::get_limbs` (`prove_leaf.rs::program_felts`) and `load_program`
/// produce them. Caller owns the result.
pub fn programFeltsFromCompiledJson(
    allocator: std.mem.Allocator,
    json_bytes: []const u8,
) (Error || std.mem.Allocator.Error)![]ProgramFelt {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return Error.InvalidProgramJson,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return Error.InvalidProgramJson;
    const data = parsed.value.object.get("data") orelse return Error.InvalidProgramJson;
    if (data != .array) return Error.InvalidProgramJson;
    const felts = try allocator.alloc(ProgramFelt, data.array.items.len);
    errdefer allocator.free(felts);
    for (data.array.items, felts) |item, *felt| {
        if (item != .string) return Error.InvalidProgramJson;
        felt.* = Felt252.fromU32x8(try parseFeltHex(item.string)).limbs9();
    }
    return felts;
}

/// `claims_to_mix`'s program hash: Blake2s over `pack_into_qm31s` of the flat
/// limbs as LE u32 words. Every felt has 28 limbs, so the packing never pads.
pub fn programHash(program: []const ProgramFelt) [8]u32 {
    comptime std.debug.assert(memory_values_limbs % 4 == 0);
    // One Blake2s over LE(words), streamed per felt: `Blake2sHasher.hashU32s`
    // of the flat limbs without materializing them.
    var hasher = Blake2sHasher.init();
    for (program) |felt| {
        var bytes: [memory_values_limbs * 4]u8 = undefined;
        for (felt, 0..) |limb, index| std.mem.writeInt(u32, bytes[index * 4 ..][0..4], limb.v, .little);
        hasher.update(&bytes);
    }
    return digestWords(hasher.finalize());
}

fn digestWords(digest: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    return words;
}

// ---------------------------------------------------------------------------
// Components

/// Upstream `all_components()` name of registry slot `slot`: the sixteen
/// `memory_id_to_big` instances render as `memory_id_to_big`,
/// `memory_id_to_big_1`, ..., `memory_id_to_big_15`.
pub fn slotName(slot: usize, buffer: *[64]u8) []const u8 {
    const entry = claim_registry.enable_slots[slot];
    const field_name = claim_registry.claim_fields[entry.claim_field_index].name;
    if (entry.field_slot_index == 0) return field_name;
    return std.fmt.bufPrint(buffer, "{s}_{}", .{ field_name, entry.field_slot_index }) catch unreachable;
}

/// `leaf_verifier_components(disabled_components(variant)).enabled_bits` in
/// the registry's 83-slot order. Returns the number of enabled components.
pub fn leafEnabledBits(
    variant: layout.Variant,
    out: *[claim_registry.enable_slot_count]bool,
) layout.Error!usize {
    var buffers: [claim_registry.enable_slot_count][64]u8 = undefined;
    var names: [claim_registry.enable_slot_count][]const u8 = undefined;
    for (&names, &buffers, 0..) |*name, *buffer, slot| name.* = slotName(slot, buffer);
    return layout.leafEnabledBits(variant, &names, out);
}

test "aux data fails closed on absent segments, wrong output counts and lengths" {
    const allocator = std.testing.allocator;
    const claim = [_]u32{0} ** (aux_data_fixed_len + 1);
    var present = [_]bool{true} ** n_segments;
    const words = try serializeAuxDataFromPublicClaim(allocator, &claim, present, 2, 1, &.{ 5, 6 });
    defer allocator.free(words);
    try std.testing.expectEqual(@as(usize, aux_data_fixed_len + 3), words.len);
    try std.testing.expectEqualSlices(u32, &.{ 5, 6 }, words[aux_data_fixed_len + 1 ..]);
    try std.testing.expectError(Error.OutputCellCount, serializeAuxDataFromPublicClaim(allocator, &claim, present, 3, 1, &.{}));
    try std.testing.expectError(Error.InvalidAuxDataLength, serializeAuxDataFromPublicClaim(allocator, &claim, present, 2, 2, &.{}));
    try std.testing.expectError(Error.InvalidClaimWord, serializeAuxDataFromPublicClaim(allocator, &claim, present, 2, 1, &.{0x7fff_ffff}));
    present[6] = false;
    try std.testing.expectError(Error.AbsentPublicSegment, serializeAuxDataFromPublicClaim(allocator, &claim, present, 2, 1, &.{}));
}

test "output hash takes the low four words of two 128-bit cells" {
    const cells = [_][8]u32{ .{ 1, 2, 3, 4, 0, 0, 0, 0 }, .{ 5, 6, 7, 8, 0, 0, 0, 0 } };
    try std.testing.expectEqual([8]u32{ 1, 2, 3, 4, 5, 6, 7, 8 }, try outputHashFromOutputCells(&cells));
    try std.testing.expectError(Error.OutputCellCount, outputHashFromOutputCells(cells[0..1]));
    const wide = [_][8]u32{ .{ 1, 2, 3, 4, 0, 0, 0, 0 }, .{ 5, 6, 7, 8, 9, 0, 0, 0 } };
    try std.testing.expectError(Error.OutputCellTooWide, outputHashFromOutputCells(&wide));
}

test "felt hex parsing zero-pads like load_program and rejects malformed values" {
    try std.testing.expectEqual([8]u32{ 0x12345678, 0x9, 0, 0, 0, 0, 0, 0 }, try parseFeltHex("0x912345678"));
    try std.testing.expectEqual([8]u32{0} ** 8, try parseFeltHex("0x"));
    try std.testing.expectEqual([8]u32{ 0, 0, 0, 0, 0, 0, 0, 0x0800_0000 }, try parseFeltHex("0x800000000000000000000000000000000000000000000000000000000000000"));
    try std.testing.expectError(Error.InvalidFeltHex, parseFeltHex("12"));
    try std.testing.expectError(Error.InvalidFeltHex, parseFeltHex("0xg1"));
    try std.testing.expectError(Error.InvalidFeltHex, parseFeltHex("0x" ++ "1" ** 65));
}
