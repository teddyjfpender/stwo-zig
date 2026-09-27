//! Original native private supplier ports. Public statement/equation suppliers
//! and initial key/MAIN roots are deliberately external, closed by the genuine
//! independently derived native public schedule. No witness or value is built.
const std = @import("std");
const Word = @import("block_v5_word_recursive_fixed_v1.zig");
const Transcript = @import("block_v5_word_recursive_fixed_transcript_v1.zig");
const Original = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig");
pub fn ForFamily(comptime family: @import("air/block_v5_word_recursive_shape_composition_v1.zig").Family) type {
    const Native = Word.ForFamily(family);
    const TypedTranscript = Transcript.ForFamily(family);
    const Admission = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    return struct {
        pub const Owned = Original.Owned;
        pub const complete_family_setup = false;
        pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, transcript: *const TypedTranscript.Owned) !*Owned {
            try native.validateAgainst(admitted, expected);
            try transcript.validateAgainst(admitted, expected, native.shape);
            const sources = try Owned.compileNativeWord(a, native.shape, &native.composition, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            errdefer sources.deinit();
            try native.validateAgainst(admitted, expected);
            try transcript.validateAgainst(admitted, expected, native.shape);
            return sources;
        }
        pub fn validateAgainst(sources: *const Owned, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, transcript: *const TypedTranscript.Owned) !void {
            const original = try derive(sources.allocator, native, admitted, expected, transcript);
            defer original.deinit();
            inline for (.{ "challenges", "claims", "samples", "terminal", "payload_bytes", "roots" }) |name| {
                inline for (.{ 12, 11, 10, 2, 9 }) |slot| {
                    const actual = try @field(sources, name).metadata(slot);
                    const expected_rows = try @field(original, name).metadata(slot);
                    if (actual.len != expected_rows.len) return error.UntrustedWordFixedPrivateSources;
                    for (actual, expected_rows) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedWordFixedPrivateSources;
                }
            }
        }
    };
}
