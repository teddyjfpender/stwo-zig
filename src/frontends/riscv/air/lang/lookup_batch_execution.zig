//! Allocation-free row execution for a compiler-selected LogUp batch plan.
//!
//! Plan construction is a cold, fallible operation over the authenticated
//! typed program. The retained owner contains one bounded batch slice and the
//! exact degree facts used to select it. `rowPair` performs no allocation and
//! never reorders entries; it is the differential execution seam needed before
//! a selected layout may replace compatibility batching in a versioned proof.

const std = @import("std");
const stwo_core = @import("stwo_core");
const planner = @import("lookup_batch_planner.zig");
const protocol_degree = @import("protocol_degree.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const static_registry = @import("static_profile_registry.zig");
const production_entry = @import("../lookups/entry.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");

const QM31 = stwo_core.fields.qm31.QM31;

pub const NATIVE_V1_AMBIENT_CONSTRAINT_DEGREE: protocol_degree.Degree = 3;
pub const NATIVE_V1_MAXIMUM_INTERACTION_DEGREE: protocol_degree.Degree = 5;
pub const AUTHORITY_DIGEST_DOMAIN =
    "stwo-zig/typed-air/lookup-batch-authority/v1\x00";
pub const EXPECTED_NATIVE_V1_AUTHORITY_DIGEST_HEX = [_][]const u8{
    "b05aaaf15df58bd807d1125dc05b97758598d8ed7fe3695b59cea578fa671cbc",
    "fcc190ace1d304fcd912213b1b412a68d7427a09a6cd3b386416cbcc311ff222",
    "2f00e333f86136bd594841597880ba6bb09341a19cd9e7d147568befe5b25d5c",
    "f4ae53c93d867cbad8f76cd565ee7d3418201f1e01da15be1eb3edc4962bbb56",
    "81c42f2302924772f07f90be3c63eb319f4f2590acf380dc2010a8d885534cef",
    "c2061cbc783769066ac838e698799c256ad10daab7e30fdaba61c228ec221107",
    "49a4982b6ef7fc3855f66fc8702b87d065005642c1cd0caa2f7505fab8c0f493",
    "411c72762dfaa3020cb25db5f895738be81e4bda25db5aba7d8e4e5b8f42f294",
    "369caf92e180695e4986cc5bb05686e2360b2481ea7369f362b2360569a5e4f8",
    "d9572429a7899612e852bfa33fc983bc8e517048bcc7fc17342b11b79b1eb0e9",
    "62244164c29d4830b3265fd00566cff30ada140f4c0d6f3dc78b6fd249fdeb0e",
    "4ad4e6243a52dae1a5fa23ec6aaa26f979ab3a01fb0317e0d5c64df3de4ec230",
    "249c49d154cebf3e0e55738208cd7b13511139937264730d2df4852d049b9bb2",
    "d8ba57a810bfd758c52281e6918c01e4e0a1a62e40578c76f036b88b1991270a",
    "096cc698691fcc263ae893823e1ec199b07c1fb8b7255b90b5045fbd49f74eea",
    "5dccf510068b523f51bc5bfd77a7ea012ea980a651835a3c222fa716f5277db1",
    "5819c9c1582ba9d2af20af29bb1f3d2637a4cfc1650edafec1787eca793a548c",
};
pub const EXPECTED_NATIVE_V1_PLAN_DIGEST_HEX = [_][]const u8{
    "b4cd91e80e9fa82a167c4d4d6f66fd40b76eab9d7a62965fc947a74c32f2bfe8",
    "f5e87b5108995a107af0e1a69adb8b79062f50b43cda71c00893397c902fbc64",
    "f8767bd258db6447d79957872c258ed5a40f0208bae7659f76da6d606932fde6",
    "15e76e2660117874e65a6d6c504dcae8f1dd5016d6defacd53f91de494a6fc6c",
    "cc497668eb35c17cbda4e87f31b14a52e88860d5724268fe1ef945df25f6286d",
    "f25ecc1b3f1c3d022821f0ceee7d16d757856eaf7990e43692068343c371c34e",
    "4099a47c2026659e46a0e860873e0fd0e5eaf48b7dbaf805b088e60004c9a25c",
    "7d2e6c0e46a507355e0396a1821a920f1b6ef5564aff1fbaaac6fb678126d465",
    "00ceccf93a338a52ae22c22b78ed80e5bc7a0f704c97c2758ebfcdb136ba5669",
    "259a2fff44300e17d6f70c9a69c888e7d128fcfe090d61d04fffc2c3bb9195d2",
    "7c4dd5ff50249940d1569ce4caa2bdd241b33390974a9dc2b2415e5ae683491e",
    "87a71a7115d1de0eca7e8c2b93e5fd963ae3023c7ed5c4184a297742c2ca6b0c",
    "ddaf97575f7a7948849d1737a87ea1fc107e71e9f377b55fe590d9471493bf94",
    "9b96a967bfc76fe1c63fe0fcd1bcb66ece7fbc98dea227815ba9b23b9392879f",
    "c618b7f69fbe50c7ff2c8bae59a35eb347a62e3f24bc019ae7aa70a05181e8a8",
    "48d3f29da4e5f1e221227380fad487704270bbbec858b223bb994ee19b207d4a",
    "80c9186add61ae57e27e1e79efc90f3f3d5bb3a48920f54709e9121916468617",
};

pub const Error = planner.Error || production_entry.Error || error{
    InvalidAuthorityDigest,
    InvalidBatchIndex,
    InvalidEntryCount,
    InvalidPlanDigest,
    InvalidPlanFamily,
};

/// Fixed compiler output consumed by proving and verification setup. The
/// current shadow path discovers this value from the typed program; production
/// activation will generate it beside the physical manifest so runtime setup
/// never needs to rebuild a symbolic arena.
pub const FamilyAuthority = struct {
    family: trace.OpcodeFamily,
    program_digest: planner.Digest,
    event_count: u32,
    events: [production_entry.MAX_ENTRIES]planner.Event = undefined,

    pub fn discover(
        allocator: std.mem.Allocator,
        family: trace.OpcodeFamily,
    ) !FamilyAuthority {
        var imported = try shadow_program.buildProduction(
            allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        var analysis = try protocol_degree.analyze(
            allocator,
            &imported,
            10,
        );
        defer analysis.deinit();
        if (analysis.lookups.len > production_entry.MAX_ENTRIES or
            analysis.lookups.len != opcode_entries.entryCount(family))
        {
            return error.InvalidPlanFamily;
        }

        var result = FamilyAuthority{
            .family = family,
            .program_digest = undefined,
            .event_count = @intCast(analysis.lookups.len),
        };
        for (analysis.lookups, result.events[0..analysis.lookups.len]) |
            lookup,
            *event,
        | {
            event.* = .{
                .ordinal = lookup.index,
                .numerator_degree = lookup.numerator,
                .denominator_degree = lookup.denominator,
            };
        }
        result.program_digest = static_registry.DESCRIPTORS[
            @intFromEnum(family)
        ].semantic_program_digest;
        try result.validate();
        return result;
    }

    pub fn validate(self: *const FamilyAuthority) Error!void {
        const family_index: usize = @intFromEnum(self.family);
        if (family_index >= static_registry.DESCRIPTORS.len)
            return error.InvalidPlanFamily;
        if (self.event_count != opcode_entries.entryCount(self.family) or
            self.event_count > production_entry.MAX_ENTRIES)
        {
            return error.InvalidPlanFamily;
        }
        const descriptor = static_registry.DESCRIPTORS[family_index];
        if (@intFromEnum(descriptor.family) != @intFromEnum(self.family) or
            !std.mem.eql(
                u8,
                &descriptor.semantic_program_digest,
                &self.program_digest,
            ))
        {
            return error.InvalidPlanFamily;
        }
        const actual_hex = std.fmt.bytesToHex(self.digest(), .lower);
        if (!std.mem.eql(
            u8,
            &actual_hex,
            EXPECTED_NATIVE_V1_AUTHORITY_DIGEST_HEX[family_index],
        )) return error.InvalidAuthorityDigest;
        // `select` performs canonical ordinal/degree validation. The separate
        // authority digest pins the complete ordered degree schedule before
        // this value can become a generated production artifact.
    }

    pub fn digest(self: *const FamilyAuthority) planner.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(AUTHORITY_DIGEST_DOMAIN);
        hashInteger(&hash, u8, @intFromEnum(self.family));
        hash.update(&self.program_digest);
        hashInteger(&hash, u32, self.event_count);
        for (self.events[0..self.event_count]) |event| {
            hashInteger(&hash, u32, event.ordinal);
            hashInteger(&hash, u32, event.numerator_degree);
            hashInteger(&hash, u32, event.denominator_degree);
        }
        return hash.finalResult();
    }
};

/// Cold owner for one family. Temporary compiler arenas and degree reports are
/// released before return; only the selected batches remain allocated.
pub const FamilyPlan = struct {
    family: trace.OpcodeFamily,
    events: [production_entry.MAX_ENTRIES]planner.Event = undefined,
    selection: planner.Plan,
    expected_plan_digest_hex: ?[]const u8 = null,

    pub fn initNativeV1(
        allocator: std.mem.Allocator,
        family: trace.OpcodeFamily,
    ) !FamilyPlan {
        const authority = try FamilyAuthority.discover(allocator, family);
        return initNativeAuthority(allocator, authority);
    }

    /// Failure-atomic V1 constructor over generated compiler authority. Both
    /// the ordered degree schedule and resulting selected plan are pinned.
    pub fn initNativeAuthority(
        allocator: std.mem.Allocator,
        authority: FamilyAuthority,
    ) !FamilyPlan {
        try authority.validate();
        return initAuthorityInternal(
            allocator,
            authority,
            NATIVE_V1_AMBIENT_CONSTRAINT_DEGREE,
            .{
                .maximum_interaction_degree = NATIVE_V1_MAXIMUM_INTERACTION_DEGREE,
            },
            EXPECTED_NATIVE_V1_PLAN_DIGEST_HEX[
                @intFromEnum(authority.family)
            ],
        );
    }

    pub fn init(
        allocator: std.mem.Allocator,
        family: trace.OpcodeFamily,
        ambient_constraint_degree: protocol_degree.Degree,
        policy: planner.PolicyV1,
    ) !FamilyPlan {
        const authority = try FamilyAuthority.discover(allocator, family);
        return initAuthority(
            allocator,
            authority,
            ambient_constraint_degree,
            policy,
        );
    }

    /// Failure-atomic runtime constructor over fixed compiler output. This is
    /// the production-shaped seam and contains no symbolic arena operations.
    pub fn initAuthority(
        allocator: std.mem.Allocator,
        authority: FamilyAuthority,
        ambient_constraint_degree: protocol_degree.Degree,
        policy: planner.PolicyV1,
    ) !FamilyPlan {
        return initAuthorityInternal(
            allocator,
            authority,
            ambient_constraint_degree,
            policy,
            null,
        );
    }

    fn initAuthorityInternal(
        allocator: std.mem.Allocator,
        authority: FamilyAuthority,
        ambient_constraint_degree: protocol_degree.Degree,
        policy: planner.PolicyV1,
        expected_plan_digest_hex: ?[]const u8,
    ) !FamilyPlan {
        try authority.validate();
        var result = FamilyPlan{
            .family = authority.family,
            .selection = undefined,
            .expected_plan_digest_hex = expected_plan_digest_hex,
        };
        @memcpy(
            result.events[0..authority.event_count],
            authority.events[0..authority.event_count],
        );
        result.selection = try planner.select(
            allocator,
            authority.program_digest,
            ambient_constraint_degree,
            result.events[0..authority.event_count],
            policy,
        );
        errdefer result.selection.deinit();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *FamilyPlan) void {
        self.selection.deinit();
        self.* = undefined;
    }

    /// Allocation-free integrity check for the retained selection. Semantic
    /// identity was derived from `family` during construction; callers accept
    /// plans by reconstructing them, not by decoding this host struct.
    pub fn validate(self: *const FamilyPlan) Error!void {
        if (self.selection.event_count != opcode_entries.entryCount(self.family))
            return error.InvalidPlanFamily;
        try self.selection.validate(
            self.events[0..self.selection.event_count],
        );
        if (self.expected_plan_digest_hex) |expected| {
            const actual = std.fmt.bytesToHex(
                self.selection.plan_digest,
                .lower,
            );
            if (!std.mem.eql(u8, &actual, expected))
                return error.InvalidPlanDigest;
        }
    }

    pub fn batchCount(self: *const FamilyPlan) usize {
        return self.selection.batches.len;
    }

    /// Reconstruct one selected row pair from the production entry list. This
    /// is suitable for a hot row loop after the caller has validated the plan
    /// once at setup.
    pub fn rowPair(
        self: *const FamilyPlan,
        list: *const production_entry.List,
        batch_index: usize,
        relations: *const relations_mod.Relations,
    ) Error!logup.RowPair {
        if (list.len != self.selection.event_count)
            return error.InvalidEntryCount;
        if (batch_index >= self.selection.batches.len)
            return error.InvalidBatchIndex;
        return rowPairFromBatch(
            list,
            self.selection.batches[batch_index],
            relations,
        );
    }
};

/// Stateless primitive kept public for focused algebra and collision tests.
/// A production caller normally uses `FamilyPlan.rowPair`, which first binds
/// the list to the selected family event count.
pub fn rowPairFromBatch(
    list: *const production_entry.List,
    batch: planner.Batch,
    relations: *const relations_mod.Relations,
) Error!logup.RowPair {
    return rowPairFromRange(
        list,
        batch.first_event,
        batch.event_count,
        relations,
    );
}

/// Lean physical-manifest execution seam. Degree certificates stay in the
/// authenticated cold artifact; the row loop needs only the contiguous range.
pub fn rowPairFromRange(
    list: *const production_entry.List,
    first_event: u32,
    event_count: u8,
    relations: *const relations_mod.Relations,
) Error!logup.RowPair {
    if (event_count == 0 or
        event_count > planner.MAXIMUM_BATCH_SIZE or
        first_event >= list.len)
    {
        return error.InvalidBatch;
    }
    const first_index: usize = first_event;
    const end = std.math.add(
        usize,
        first_index,
        event_count,
    ) catch return error.CountOverflow;
    if (end > list.len) return error.InvalidBatch;

    const first = &list.entries[first_index];
    if (event_count == 1) {
        return logup.RowPair.single(
            first.numerator,
            try first.denominator(relations),
        );
    }
    const second = &list.entries[first_index + 1];
    return .{
        .n1 = first.numerator,
        .d1 = try first.denominator(relations),
        .n2 = second.numerator,
        .d2 = try second.denominator(relations),
    };
}

pub fn pairTerm(pair: logup.RowPair) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn hashInteger(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
