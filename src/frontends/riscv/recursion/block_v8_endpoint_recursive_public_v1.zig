//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Exact public operands for one joined original verifier. Values alone confer
        // no proof authority. Parent verification must close their complete wire sum
        // and independently check the original execution/global public statement.
        const std = @import("std");
        const core = @import("stwo_core");
        const Whole = Adapter.Original;
        const Profile = Adapter.Profile;
        const Transcript = Adapter.Transcript;
        const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
        const P = struct {
            pub const Admission = struct {
                pub const Prepared = Profile.Owned;
            };
            pub const Statement = struct {
                pub const PUBLIC_CIRCUIT = Transcript.PUBLIC_CIRCUIT;
                pub const Statement = Frames.Statement;
            };
            pub const IDENTITY_TAG: u32 = Adapter.IDENTITY_TAG;
            pub const SCHEDULE_TAG: u32 = Adapter.SCHEDULE_TAG;
            pub fn rootWordOffset(frame: *const Frames.Statement, roots: usize, tree: usize) !u32 {
                const words = try std.math.mul(usize, roots, 8);
                if (tree >= roots or words > frame.words.len) return error.InvalidEndpointPublicRoots;
                return std.math.cast(u32, frame.words.len - words + 8 * tree) orelse error.InvalidEndpointPublicRoots;
            }
        };
        pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamilyWithBoundedRoots(P);
        pub const Wire = API.Wire;
        pub const Values = API.Values;
        pub const supply = API.supply;
        pub const scheduleDigest = API.scheduleDigest;
        pub fn reconstruct(a: std.mem.Allocator, profile: *const Profile.Owned) !Values {
            try profile.validate();
            var frame = try Transcript.statement(a, profile);
            errdefer frame.deinit();
            const public = try Adapter.Composition.publicValues(a, profile);
            errdefer a.free(public);
            const values = Values{ .allocator = a, .template = profile.seal, .statement = frame, .public = public, .roots_count = Adapter.firstRoots(profile) };
            try values.validate();
            return values;
        }
        pub fn collect(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, composition: *const @import("air/blake3_execution_composition.zig").Prepared, transcript: *const @import("air/blake3_native_transcript.zig").Planned, values: Values, max_wires: usize) ![]Wire {
            try values.validate();
            if (!std.meta.eql(values.template, profile.seal) or values.roots_count != Adapter.firstRoots(profile) or capture.proof.commitments.len != profile.shape.columns.len or capture.proof.trace_paths.len != capture.proof.commitments.len) return error.InvalidEndpointPublicRoots;
            const reads = try a.alloc(u32, values.roots_count);
            defer a.free(reads);
            for (reads, 0..) |*count, tree| {
                const offset = try P.rootWordOffset(&values.statement, values.roots_count, tree);
                if (!std.meta.eql(try values.statement.digest(offset), capture.proof.commitments[tree])) return error.UntrustedEndpointFirstRoot;
                count.* = std.math.cast(u32, capture.proof.trace_paths[tree].positions.len) orelse return error.InvalidEndpointPublicRoots;
            }
            for (composition.sources, composition.inputs) |source, value| if (source == .public_input) {
                if (source.public_input >= values.public.len or !value.eql(values.public[source.public_input])) return error.UntrustedEndpointPublicOperand;
            };
            return API.collectFixedSchedulePerTree(a, &transcript.plan, composition, values.statement.words.len, values.public.len, reads, max_wires);
        }
    };
}
