//! Exact five-range shared Poseidon caller witness for the V3 leaf wrapper.
//!
//! The first range belongs to the admitted 39-row cohort. The remaining
//! ranges are metadata, link, native ProgramV2 and outer provider hashes.
//! This assembles one row-34 call slice and checks its pinned geometry; it
//! does not commit that row or admit a V3 wrapper proof.

const std = @import("std");
const core = @import("stwo_core");
const fields_mod = @import("segment_leaf_wrapper_field_witness_v3.zig");
const hash_mod = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const link_program = @import("ethereum_leaf_link_program_v1.zig");
const global_mod = @import("segment_leaf_local_authority_v3.zig");
const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
const roster = @import("air/segment_leaf_wrapper_roster_v3.zig");
const verified = @import("segment_verified_artifact_v2.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Call = poseidon_air.Call;
pub const RANGE_COUNT: usize = 5;

pub const Range = struct {
    start: usize,
    len: usize,

    pub fn end(self: Range) !usize {
        return std.math.add(usize, self.start, self.len);
    }
};

pub const BundleV3 = struct {
    allocator: std.mem.Allocator,
    fields: fields_mod.BundleV3,
    metadata_hash: hash_mod.HashV1,
    link_hash: hash_mod.HashV1,
    ranges: [RANGE_COUNT]Range,
    calls: []Call,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: anytype,
        global: *const global_mod.MetadataV3,
        verified_link: *const link_mod.VerifiedLinkV3,
        outer_capture: *const verified.OuterProofCapture,
        publication: *const verified.Publication,
        recursive_witness: *const verified.RecursiveWitnessV1,
        cohort: anytype,
        program: *const link_program.ProgramV1,
    ) !BundleV3 {
        try cohort.validate();
        const base_manifest = cohort.manifest();
        const base_calls = try cohort.core.completePoseidonCalls();
        if (base_calls.len == 0) return error.IncompleteV3PoseidonCallRoster;
        try prepared.validate();
        try verified.preflight(outer_capture, publication, recursive_witness, base_manifest);
        try verified_link.validateAgainst(
            global,
            &prepared.capture.public_data.data,
            &prepared.capture.receipt,
        );
        try program.validate();

        var fields = try fields_mod.BundleV3.init(
            allocator,
            prepared,
            outer_capture,
            publication,
            recursive_witness,
            base_manifest,
        );
        errdefer fields.deinit();
        const metadata_words = try global.identityWords();
        const link_words = try verified_link.identityWords();
        var metadata_hash = try hash_mod.HashV1.init(
            allocator,
            &metadata_words,
            global_mod.METADATA_ID_DOMAIN,
            source_air.METADATA_SCOPE,
            source_air.METADATA_DIGEST_KIND,
            link_program.METADATA_HASH_STEP_BASE,
            try global.identity(),
        );
        errdefer metadata_hash.deinit();
        var link_hash = try hash_mod.HashV1.init(
            allocator,
            &link_words,
            link_mod.IDENTITY_DOMAIN,
            source_air.LINK_SCOPE,
            source_air.LINK_DIGEST_KIND,
            link_program.LINK_HASH_STEP_BASE,
            verified_link.identity,
        );
        errdefer link_hash.deinit();
        if (metadata_hash.calls.len != link_program.METADATA_HASH_ROW_COUNT or
            link_hash.calls.len != link_program.LINK_HASH_ROW_COUNT or
            !sliceMetaEqual(@TypeOf(metadata_hash.preprocessed[0]), metadata_hash.preprocessed, program.metadata_hash.rows) or
            !sliceMetaEqual(@TypeOf(link_hash.preprocessed[0]), link_hash.preprocessed, program.link_hash.rows))
            return error.InvalidV3LeafHashSchedule;

        const parts = .{
            base_calls,                       metadata_hash.calls,        link_hash.calls,
            fields.native.program_hash.calls, fields.provider.hash.calls,
        };
        var ranges: [RANGE_COUNT]Range = undefined;
        var total: usize = 0;
        inline for (parts, 0..) |part, index| {
            ranges[index] = .{ .start = total, .len = part.len };
            total = try std.math.add(usize, total, part.len);
        }
        if (total >= core.fields.m31.Modulus) return error.IncompleteV3PoseidonCallRoster;
        const calls = try allocator.alloc(Call, total);
        errdefer allocator.free(calls);
        inline for (parts, 0..) |part, index|
            @memcpy(calls[ranges[index].start..][0..part.len], part);
        return .{
            .allocator = allocator,
            .fields = fields,
            .metadata_hash = metadata_hash,
            .link_hash = link_hash,
            .ranges = ranges,
            .calls = calls,
        };
    }

    pub fn deinit(self: *BundleV3) void {
        self.allocator.free(self.calls);
        self.link_hash.deinit();
        self.metadata_hash.deinit();
        self.fields.deinit();
        self.* = undefined;
    }

    pub fn shape(self: *const BundleV3) roster.Shape {
        return .{
            .program_words = self.fields.native.program.words.len,
            .provider_words = self.fields.provider.authority.words.len,
            .base_poseidon_calls = self.ranges[0].len,
        };
    }

    /// Rechecks all five ranges against source-owned calls and one complete
    /// 49-row plan. No caller-supplied count can turn this into proof evidence.
    pub fn validateForPlan(self: *const BundleV3, plan: *const roster.Plan, cohort: anytype) !void {
        try plan.validate();
        const base_calls = try cohort.core.completePoseidonCalls();
        if (!std.meta.eql(self.shape(), plan.shape) or
            self.calls.len != plan.poseidon_calls.total or
            self.ranges[0].len != plan.poseidon_calls.base or
            self.ranges[1].len != plan.poseidon_calls.metadata or
            self.ranges[2].len != plan.poseidon_calls.link or
            self.ranges[3].len != plan.poseidon_calls.program or
            self.ranges[4].len != plan.poseidon_calls.provider or
            self.ranges[0].len != base_calls.len)
            return error.IncompleteV3PoseidonCallRoster;
        const parts = .{
            base_calls,                            self.metadata_hash.calls,        self.link_hash.calls,
            self.fields.native.program_hash.calls, self.fields.provider.hash.calls,
        };
        var at: usize = 0;
        inline for (parts, 0..) |part, index| {
            if (self.ranges[index].start != at or self.ranges[index].len != part.len)
                return error.V3PoseidonCallRosterMismatch;
            for (part) |call| {
                if (!std.meta.eql(call, self.calls[at]))
                    return error.V3PoseidonCallRosterMismatch;
                at += 1;
            }
        }
        if (at != self.calls.len or
            at > (@as(usize, 1) << @intCast(plan.placements[34].?.geometry.log_size)))
            return error.V3PoseidonCallRosterMismatch;
    }
};

fn sliceMetaEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}
