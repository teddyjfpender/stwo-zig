//! Reconstructed actual v7 caller public operands. Never a standalone receipt.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const Admission = Policy.Admission;
        const Profile = @import("../prover/blake3_ethereum_sha_profile.zig");
        const Fused = @import("../prover/block_v5_caller_fused_proof_v1.zig");
        const Statement = Policy.Statement;
        const Definition = struct {
            pub const Admission = Policy.Admission;
            pub const Statement = Policy.Statement;
            pub const IDENTITY_TAG: u32 = Policy.identity_tag;
            pub const SCHEDULE_TAG: u32 = Policy.schedule_tag;
        };
        pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(Definition);
        pub const Values = API.Values;
        pub const Wire = API.Wire;
        pub const supply = API.supply;
        pub const scheduleDigest = API.scheduleDigest;
        pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, claims: *const Fused.ClaimFrames) ![]Q {
            try arithmetic.validate(&admitted.arithmetic.statement);
            const fused = try @import("air/block_v5_caller_fused_composition_v1.zig").publicInputsForSchedule(a, &admitted.relations.schedule, admitted.relations.frame, claims.*);
            defer a.free(fused);
            var values: std.ArrayList(Q) = .empty;
            defer values.deinit(a);
            for (arithmetic.componentClaims()) |view| {
                try values.appendSlice(a, view.detailed);
                if (view.has_batch_frame) try values.append(a, view.total);
            }
            try values.append(a, arithmetic.componentSum());
            try values.appendSlice(a, fused);
            if (values.items.len > admitted.limits.max_claims) return error.V7CallerResourceLimit;
            return values.toOwnedSlice(a);
        }
        pub fn reconstruct(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, claims: *const Fused.ClaimFrames) !Values {
            try admitted.validate();
            var statement = try Statement.init(a, admitted, arithmetic, claims);
            errdefer statement.deinit();
            const public = try publicInputs(a, admitted, arithmetic, claims);
            errdefer a.free(public);
            const result = Values{ .allocator = a, .template = admitted.template_id, .statement = statement, .public = public, .roots_count = 3 };
            try result.validate();
            return result;
        }
        pub fn requireSameFrame(got: Values, expected: Values) !void {
            try got.validate();
            try expected.validate();
            if (!std.meta.eql(got.template, expected.template) or got.roots_count != expected.roots_count or
                !std.meta.eql(got.statement.roots_offset, expected.statement.roots_offset) or got.statement.sealed_offset != expected.statement.sealed_offset or
                !std.mem.eql(u32, got.statement.words, expected.statement.words) or got.statement.felts.len != expected.statement.felts.len or got.public.len != expected.public.len or
                got.statement.first.len != expected.statement.first.len or got.statement.claims.len != expected.statement.claims.len) return error.UntrustedV7CallerPublicFrame;
            for (got.statement.felts, expected.statement.felts) |x, y| if (!x.eql(y)) return error.UntrustedV7CallerPublicFrame;
            for (got.public, expected.public) |x, y| if (!x.eql(y)) return error.UntrustedV7CallerPublicFrame;
            for (got.statement.first, expected.statement.first) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedV7CallerPublicFrame;
            for (got.statement.claims, expected.statement.claims) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedV7CallerPublicFrame;
        }
    };
}
