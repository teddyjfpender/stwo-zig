//! Typed original PAGE private suppliers. Public sums/count bytes and first
//! eight roots have no private producers. No witness/capture/value is built.
const std = @import("std");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const NativeModule = @import("block_v5_memory_source_page_recursive_fixed_v1.zig");
const TranscriptModule = @import("block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Profiles = @import("block_v5_native_fixed_pcs_profile_v1.zig");
const Original = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Native = NativeModule.ForKind(kind);
    const Transcript = TranscriptModule.ForKind(kind);
    const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Profile = Profiles.ForPage(kind);
    return struct {
        pub const Owned = Original.Owned;
        pub const complete_family_setup = false;
        pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, transcript: *const Transcript.Owned) !*Owned {
            var profile = try Profile.derive(native, admitted, expected, public_claims);
            try transcript.validateAgainst(admitted, expected, native, public_claims);
            const sources = try Owned.compileNativePage(a, &profile, &native.composition, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            errdefer sources.deinit();
            try profile.validate();
            try transcript.validateAgainst(admitted, expected, native, public_claims);
            return sources;
        }
        pub fn validateAgainst(sources: *const Owned, native: *const Native.Owned, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, transcript: *const Transcript.Owned) !void {
            const original = try derive(sources.allocator, native, admitted, expected, public_claims, transcript);
            defer original.deinit();
            inline for (.{ "challenges", "claims", "samples", "terminal", "payload_bytes", "roots" }) |name| {
                inline for (.{ 12, 11, 10, 2, 9 }) |slot| {
                    const actual = try @field(sources, name).metadata(slot);
                    const expected_rows = try @field(original, name).metadata(slot);
                    if (actual.len != expected_rows.len) return error.UntrustedPageFixedPrivateSources;
                    for (actual, expected_rows) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedPrivateSources;
                }
            }
        }
    };
}
