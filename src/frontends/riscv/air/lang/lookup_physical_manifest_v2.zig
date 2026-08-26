//! Versioned physical authority for degree-selected opcode lookups.
//!
//! V1 remains the default proof layout. This append-only V2 artifact pins the
//! complete seventeen-family cohort, including typed-component identity,
//! polynomial authority, selected singleton/pair ranges, claim placement, and
//! physical tree offsets. Production setup consumes only this fixed record;
//! rebuilding a symbolic program or running the planner is an audit operation.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const composition = @import("opcode_composition_manifest.zig");
const selected = @import("lookup_batch_execution.zig");
const lowering = @import("lookup_polynomial_program_v2.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const statement_mod = @import("../statement.zig");

const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 2;
pub const STATEMENT_FORMAT_VERSION: u16 = 1;
pub const FAMILY_COUNT: usize = composition.FAMILY_COUNT;
pub const MAX_BATCHES_PER_FAMILY: usize = composition.MAX_LOOKUP_BATCHES;
pub const EXPECTED_TOTAL_LOOKUP_ENTRIES: u32 = 242;
pub const EXPECTED_TOTAL_BATCHES: u32 = 137;
pub const EXPECTED_TOTAL_INTERACTION_COLUMNS: u32 = 548;
pub const EXPECTED_TOTAL_MAIN_COLUMNS: u32 = 644;
pub const EXPECTED_TOTAL_PREPROCESSED_COLUMNS: u32 = 34;
pub const EXPECTED_TOTAL_ADAPTERS: u32 = 34;
pub const IDENTITY_DOMAIN =
    "stwo-zig/riscv/lookup-physical-manifest/v2\x00";
pub const STATEMENT_IDENTITY_DOMAIN =
    "stwo-zig/riscv/lookup-physical-statement/v2\x00";
pub const ACTIVATION_IDENTITY_DOMAIN =
    "stwo-zig/riscv/lookup-physical-activation/v2\x00";
pub const TRANSCRIPT_TAG: u32 = 0x4c56_3201; // "LV2" + revision 1.

pub const Digest = [32]u8;
pub const Family = composition.Family;
pub const Authority = prover_component.LookupPolynomialAuthorityV2;
pub const Batch = prover_component.LookupPolynomialBatchV2;

pub const Error = error{
    CountOverflow,
    InvalidActivationIdentity,
    InvalidAdapterPlacement,
    InvalidAuthority,
    InvalidBatchGeometry,
    InvalidClaimGeometry,
    InvalidFamilyOrder,
    InvalidMainGeometry,
    InvalidManifestIdentity,
    InvalidManifestVersion,
    InvalidPreprocessedPlacement,
    InvalidStatementGeometry,
    InvalidStatementIdentity,
};

pub const FixedBatches = struct {
    len: u8,
    values: [MAX_BATCHES_PER_FAMILY]Batch,

    pub fn active(self: *const FixedBatches) []const Batch {
        return self.values[0..self.len];
    }
};

/// One family in canonical transcript order. Every offset describes the
/// one-shard native cohort; an admitted sharded statement derives its own
/// offsets from the same per-family widths.
pub const FamilyEntry = struct {
    family: Family,
    composition_index: u8,
    semantic_adapter_index: u8,
    lookup_adapter_index: u8,
    is_first_column: u32,
    is_active_column: u32,
    main_column_offset: u32,
    main_column_count: u32,
    interaction_column_offset: u32,
    interaction_column_count: u32,
    detailed_claim_offset: u32,
    detailed_claim_count: u32,
    typed_authority_identity: Digest,
    lookup_authority: Authority,
    batches: FixedBatches,

    pub fn activeBatches(self: *const FamilyEntry) []const Batch {
        return self.batches.active();
    }
};

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    family_count: u16 = FAMILY_COUNT,
    total_lookup_entries: u32 = EXPECTED_TOTAL_LOOKUP_ENTRIES,
    total_batches: u32 = EXPECTED_TOTAL_BATCHES,
    total_interaction_columns: u32 = EXPECTED_TOTAL_INTERACTION_COLUMNS,
    total_main_columns: u32 = EXPECTED_TOTAL_MAIN_COLUMNS,
    total_preprocessed_columns: u32 =
        EXPECTED_TOTAL_PREPROCESSED_COLUMNS,
    total_adapters: u32 = EXPECTED_TOTAL_ADAPTERS,
    entries: [FAMILY_COUNT]FamilyEntry,
    identity: Digest,

    /// Allocation-free production constructor. All expensive typed-program
    /// discovery and plan selection has already been compiled into `PINNED`.
    pub fn native() Manifest {
        var result = Manifest{
            .entries = nativeEntries(),
            .identity = .{0} ** 32,
        };
        result.identity = result.identityDigest();
        return result;
    }

    pub fn entryForFamily(self: *const Manifest, family: Family) *const FamilyEntry {
        return &self.entries[composition.compositionIndex(family)];
    }

    pub fn validate(self: *const Manifest) (Error || prover_component.LookupPolynomialProgramV2Error)!void {
        if (self.format_version != FORMAT_VERSION or
            self.family_count != FAMILY_COUNT)
        {
            return error.InvalidManifestVersion;
        }
        if (self.total_lookup_entries != EXPECTED_TOTAL_LOOKUP_ENTRIES or
            self.total_batches != EXPECTED_TOTAL_BATCHES or
            self.total_interaction_columns !=
                EXPECTED_TOTAL_INTERACTION_COLUMNS or
            self.total_main_columns != EXPECTED_TOTAL_MAIN_COLUMNS or
            self.total_preprocessed_columns !=
                EXPECTED_TOTAL_PREPROCESSED_COLUMNS or
            self.total_adapters != EXPECTED_TOTAL_ADAPTERS)
        {
            return error.InvalidManifestIdentity;
        }

        var main_offset: u32 = 0;
        var interaction_offset: u32 = 0;
        var claim_offset: u32 = 0;
        for (&self.entries, 0..) |*entry, index| {
            const family = composition.TRANSCRIPT_ORDER[index];
            const pinned_family = &PINNED_BY_FAMILY[@intFromEnum(family)];
            const descriptor = composition.descriptor(family);
            if (entry.family != family or
                entry.composition_index != index)
            {
                return error.InvalidFamilyOrder;
            }
            if (entry.semantic_adapter_index != 2 * index or
                entry.lookup_adapter_index != 2 * index + 1)
            {
                return error.InvalidAdapterPlacement;
            }
            if (entry.is_first_column != 2 * index or
                entry.is_active_column != 2 * index + 1)
            {
                return error.InvalidPreprocessedPlacement;
            }
            if (entry.main_column_offset != main_offset or
                entry.main_column_count != descriptor.main_columns)
            {
                return error.InvalidMainGeometry;
            }
            if (entry.interaction_column_offset != interaction_offset or
                entry.interaction_column_count !=
                    entry.lookup_authority.interaction_column_count)
            {
                return error.InvalidBatchGeometry;
            }
            if (entry.detailed_claim_offset != claim_offset or
                entry.detailed_claim_count !=
                    entry.lookup_authority.batch_count)
            {
                return error.InvalidClaimGeometry;
            }
            if (!std.mem.eql(
                u8,
                &entry.typed_authority_identity,
                &descriptor.authority_digest,
            ) or !std.meta.eql(entry.lookup_authority, pinned_family.authority)) {
                return error.InvalidAuthority;
            }
            try entry.lookup_authority.validate();
            try validateBatches(entry, pinned_family);
            main_offset = std.math.add(
                u32,
                main_offset,
                entry.main_column_count,
            ) catch return error.CountOverflow;
            interaction_offset = std.math.add(
                u32,
                interaction_offset,
                entry.interaction_column_count,
            ) catch return error.CountOverflow;
            claim_offset = std.math.add(
                u32,
                claim_offset,
                entry.detailed_claim_count,
            ) catch return error.CountOverflow;
        }
        if (main_offset != self.total_main_columns or
            interaction_offset != self.total_interaction_columns or
            claim_offset != self.total_batches)
        {
            return error.InvalidManifestIdentity;
        }
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.identity))
            return error.InvalidManifestIdentity;
    }

    pub fn identityDigest(self: *const Manifest) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(IDENTITY_DOMAIN);
        hashInteger(&hash, u16, self.format_version);
        hashInteger(&hash, u16, self.family_count);
        hashInteger(&hash, u32, self.total_lookup_entries);
        hashInteger(&hash, u32, self.total_batches);
        hashInteger(&hash, u32, self.total_interaction_columns);
        hashInteger(&hash, u32, self.total_main_columns);
        hashInteger(&hash, u32, self.total_preprocessed_columns);
        hashInteger(&hash, u32, self.total_adapters);
        for (self.entries) |entry| {
            hashInteger(&hash, u8, @intFromEnum(entry.family));
            hashInteger(&hash, u8, entry.composition_index);
            hashInteger(&hash, u8, entry.semantic_adapter_index);
            hashInteger(&hash, u8, entry.lookup_adapter_index);
            hashInteger(&hash, u32, entry.is_first_column);
            hashInteger(&hash, u32, entry.is_active_column);
            hashInteger(&hash, u32, entry.main_column_offset);
            hashInteger(&hash, u32, entry.main_column_count);
            hashInteger(&hash, u32, entry.interaction_column_offset);
            hashInteger(&hash, u32, entry.interaction_column_count);
            hashInteger(&hash, u32, entry.detailed_claim_offset);
            hashInteger(&hash, u32, entry.detailed_claim_count);
            hash.update(&entry.typed_authority_identity);
            hashAuthority(&hash, entry.lookup_authority);
            hashInteger(&hash, u8, entry.batches.len);
            for (entry.activeBatches()) |batch| {
                hashInteger(&hash, u32, batch.first_entry);
                hashInteger(&hash, u8, batch.entry_count);
                hashInteger(&hash, u32, batch.interaction_degree);
            }
        }
        return hash.finalResult();
    }

    /// Slow diagnostic only: re-run typed discovery, selection, and lowering
    /// and require byte-for-byte agreement with the static physical artifact.
    pub fn auditAgainstCompiler(
        self: *const Manifest,
        allocator: std.mem.Allocator,
    ) !void {
        try self.validate();
        for (0..FAMILY_COUNT) |family_index| {
            const family: Family = @enumFromInt(family_index);
            var plan = try selected.FamilyPlan.initNativeV1(allocator, family);
            defer plan.deinit();
            var program = try lowering.lowerSelected(allocator, &plan);
            defer program.deinit();
            const authority = try program.authority();
            const entry = self.entryForFamily(family);
            if (!std.meta.eql(authority, entry.lookup_authority) or
                plan.selection.batches.len != entry.batches.len)
            {
                return error.InvalidAuthority;
            }
            for (plan.selection.batches, entry.activeBatches()) |
                actual,
                expected,
            | {
                if (actual.first_event != expected.first_entry or
                    actual.event_count != expected.entry_count or
                    actual.terms.final != expected.interaction_degree)
                {
                    return error.InvalidBatchGeometry;
                }
            }
        }
    }
};

/// Statement-scoped admission token. The base statement remains separately
/// transcript-bound; this value binds its opcode shard sequence to the V2
/// physical widths and to one exact manifest before component construction.
pub const AuthenticatedStatement = struct {
    format_version: u16 = STATEMENT_FORMAT_VERSION,
    manifest_identity: Digest,
    statement_identity: Digest,
    activation_identity: Digest,
    component_count: u32,
    opcode_main_columns: u32,
    opcode_interaction_columns: u32,
    detailed_claim_count: u32,

    pub fn init(
        statement: *const statement_mod.RiscVStatement,
        manifest: *const Manifest,
    ) !AuthenticatedStatement {
        try manifest.validate();
        return deriveStatement(statement, manifest);
    }

    pub fn validateAgainst(
        self: *const AuthenticatedStatement,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const Manifest,
    ) !void {
        if (self.format_version != STATEMENT_FORMAT_VERSION)
            return error.InvalidStatementGeometry;
        try manifest.validate();
        const expected = try deriveStatement(statement, manifest);
        if (!std.mem.eql(
            u8,
            &self.manifest_identity,
            &expected.manifest_identity,
        )) return error.InvalidManifestIdentity;
        if (!std.mem.eql(
            u8,
            &self.statement_identity,
            &expected.statement_identity,
        )) return error.InvalidStatementIdentity;
        if (!std.mem.eql(
            u8,
            &self.activation_identity,
            &expected.activation_identity,
        )) return error.InvalidActivationIdentity;
        if (self.component_count != expected.component_count or
            self.opcode_main_columns != expected.opcode_main_columns or
            self.opcode_interaction_columns !=
                expected.opcode_interaction_columns or
            self.detailed_claim_count != expected.detailed_claim_count)
        {
            return error.InvalidStatementGeometry;
        }
    }

    /// Binds the exact physical interpretation before relation challenges or
    /// commitment roots are consumed. Selecting the V2 proof entry point is
    /// therefore cryptographic protocol activation, not a backend hint.
    pub fn mixInto(self: *const AuthenticatedStatement, channel: anytype) void {
        channel.mixU32s(&.{
            TRANSCRIPT_TAG,
            FORMAT_VERSION,
            self.format_version,
            self.component_count,
            self.opcode_main_columns,
            self.opcode_interaction_columns,
            self.detailed_claim_count,
        });
        mixDigest(channel, self.manifest_identity);
        mixDigest(channel, self.statement_identity);
        mixDigest(channel, self.activation_identity);
    }

    pub fn totalInteractionColumns(
        self: *const AuthenticatedStatement,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const Manifest,
    ) !usize {
        try self.validateAgainst(statement, manifest);
        var total: usize = self.opcode_interaction_columns;
        for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
            total = std.math.add(
                usize,
                total,
                statement_mod.nInteractionColsForInfra(descriptor.kind),
            ) catch return error.CountOverflow;
        }
        return total;
    }

    /// Canonical V2 claim projection. Compatibility-only claim slots beyond a
    /// selected family width must be zero and are never mixed into the V2
    /// component total or reported as committed Tree-2 columns.
    pub fn canonicalInteractionClaim(
        self: *const AuthenticatedStatement,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const Manifest,
        claim: *const statement_mod.RiscVInteractionClaim,
    ) !statement_mod.CanonicalInteractionClaim {
        try self.validateAgainst(statement, manifest);
        if (claim.n_components != statement.n_components or
            claim.n_infra != statement.n_infra)
        {
            return error.InvalidClaimGeometry;
        }
        var result = try claim.canonical(statement);
        result.n_log_sizes = 0;
        for (statement.component_descs[0..statement.n_components], 0..) |
            descriptor,
            index,
        | {
            const physical = manifest.entryForFamily(descriptor.family);
            const selected_count: usize = @intCast(physical.detailed_claim_count);
            const compatibility_count = opcode_entries.batchCount(
                descriptor.family,
            );
            var compatibility_total = QM31.zero();
            for (claim.opcode_claims[index][0..compatibility_count]) |value|
                compatibility_total = compatibility_total.add(value);
            var selected_total = QM31.zero();
            for (claim.opcode_claims[index][0..selected_count]) |value|
                selected_total = selected_total.add(value);
            for (claim.opcode_claims[index][selected_count..compatibility_count]) |value| {
                if (!value.isZero()) return error.InvalidClaimGeometry;
            }
            const claim_index = @intFromEnum(
                composition.transcriptComponent(descriptor.family),
            );
            result.claimed_sums[claim_index] = result.claimed_sums[claim_index]
                .sub(compatibility_total).add(selected_total);
            for (0..physical.interaction_column_count) |_| {
                if (result.n_log_sizes == result.log_sizes.len)
                    return error.CountOverflow;
                result.log_sizes[result.n_log_sizes] = descriptor.log_size;
                result.n_log_sizes += 1;
            }
        }
        for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
            for (0..statement_mod.nInteractionColsForInfra(descriptor.kind)) |_| {
                if (result.n_log_sizes == result.log_sizes.len)
                    return error.CountOverflow;
                result.log_sizes[result.n_log_sizes] = descriptor.log_size;
                result.n_log_sizes += 1;
            }
        }
        if (result.n_log_sizes !=
            try self.totalInteractionColumns(statement, manifest))
        {
            return error.InvalidClaimGeometry;
        }
        return result;
    }

    pub fn mixInteractionClaim(
        self: *const AuthenticatedStatement,
        channel: anytype,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const Manifest,
        claim: *const statement_mod.RiscVInteractionClaim,
    ) !void {
        const canonical = try self.canonicalInteractionClaim(
            statement,
            manifest,
            claim,
        );
        const view = canonical.view();
        if (comptime @hasDecl(@TypeOf(channel.*), "absorbRiscVClaimedSums")) {
            try channel.absorbRiscVClaimedSums(&view.claimed_sums);
        } else {
            view.mixInto(channel);
        }
    }
};

const PinnedFamily = struct {
    authority: Authority,
    batches: FixedBatches,
};

pub const PINNED_BY_FAMILY: [FAMILY_COUNT]PinnedFamily = .{
    pinned("f8cf9c0b60b41fc948ec7c5efd61caf5abf96ec30f242c6a375845ab905e61c5", "b4cd91e80e9fa82a167c4d4d6f66fd40b76eab9d7a62965fc947a74c32f2bfe8", "1a54e8a1c56a3bce5c4e5d6d76c0b127ff1c4b7bdb9f9904d3c8056210c6eadd", "c2d7de74590c3067dc5750a3b8ec0e05fd323ee263e8533e08b1979a4302e92f", 18, uniformPairs(18, 0)),
    pinned("77cac74f85ee61abc8aa1ab97ee37c3f1fddb61eda7c9c982f166c75122908a6", "f5e87b5108995a107af0e1a69adb8b79062f50b43cda71c00893397c902fbc64", "66c2345767f4734bc4ff3e94a706869d0abece653ee466489d3e314b31f0e130", "73e80cced387b3ddafaddd747ea8ba7ad9327275bea684a6653c13ddf2069634", 16, uniformPairs(16, 0)),
    pinned("c40d1f981405a9108fe64ca3a4ec0037aa6c006733e9edd0ceb4787a4687ae09", "f8767bd258db6447d79957872c258ed5a40f0208bae7659f76da6d606932fde6", "a059475a858743b7eec7e00a089b7d33113c391d626ec2ce5148c3c48b187ffe", "e31ad855be7a65b740cc2e3427b27d6cb33a736dce26b3aab9615977e5ef2269", 20, uniformPairs(20, 0)),
    pinned("6eda0a9643861c820271cde92eb3c8f5ac99c7efbffd5a25ef0865a249e454df", "15e76e2660117874e65a6d6c504dcae8f1dd5016d6defacd53f91de494a6fc6c", "78c8190dc5dbf32838f0b676069b93c861c31df29730c0ef3376160a41ca1b13", "60648f017a70b50165b4ec15995be43c8cdcb2692ca6f0da9a2ef7bf38a83bea", 16, uniformPairs(16, 0)),
    pinned("e28ede4abf49917335d8ecec6e4f5c6bfdea3e4e8f967501313a95dad4d703b0", "cc497668eb35c17cbda4e87f31b14a52e88860d5724268fe1ef945df25f6286d", "9c5df40b51c10972a0c1c36b5078dea46899b15ffd1b55138ca1d7ec17104ac5", "bc2dda9e0447bebef420180e41c735b150149c2c9749956406f38d2fb5e5fa71", 14, uniformPairs(14, 0)),
    pinned("21a4a1214f2ed1e8cb6cc311434a6114d5faf3c3e91dff3229835b1316084551", "f25ecc1b3f1c3d022821f0ceee7d16d757856eaf7990e43692068343c371c34e", "2064240e379dba81c914f514b0029ec9bb3edf82ca9cca0ce5ff31d86b3f19b4", "f402881b6fe38d272ab1b49ebdf89b26e99087ae4a96778052b3026a1d4f7f34", 11, uniformPairs(11, 2)),
    pinned("4b7ac248bf672d93a01cbd659e59a7a98f1ec81ab5b50dd29090ca8816e49b09", "4099a47c2026659e46a0e860873e0fd0e5eaf48b7dbaf805b088e60004c9a25c", "a680b072e6ac47f11d23eeddaaeb8d7ca1e220f2db70bcab864830444250d95e", "f4d0324a02a4dc9cdb32a49373f25d873cd1f84cdb4117492f53767733049a4a", 9, uniformPairs(9, 3)),
    pinned("262eae1d57530034e41143c0c5961e3c7826d0e5c3af69a0b656ede2d0eeeded", "7d2e6c0e46a507355e0396a1821a920f1b6ef5564aff1fbaaac6fb678126d465", "180be1baada41226aeee490f518d3dc8faafe4b0730b3b15515e4ec6b7c6bb8f", "af73a77bde628a6b1671dca1a8db970f7978ca3914101ef045590f07ddc6ef5c", 11, uniformPairs(11, 2)),
    pinned("3f69a47662e9216f86c03bba257b52fb280542af610972a4c98cf7630252fd68", "00ceccf93a338a52ae22c22b78ed80e5bc7a0f704c97c2758ebfcdb136ba5669", "cc8d944d2ba8664aceaf1c8ddd2d458048f839ae849a82849d267134e94cc2e6", "699ed4f103f2642c71a758a5df8d3b7d35a737f87a2f5a3bbff9ab85b486af3b", 7, uniformPairs(7, 2)),
    pinned("b65eb0279c680db06f9fe36f4bbf3db1f1c99d913afb5e0a0e00e3a1b0f9abfe", "259a2fff44300e17d6f70c9a69c888e7d128fcfe090d61d04fffc2c3bb9195d2", "1741cedd22a93c0efbceb867bdab33cb4d4ce5b4db7310c9e145d83dc8c43582", "95a53062231763171f323b01f1fe515af4122064473602115b7e2319028696f6", 12, uniformPairs(12, 0)),
    pinned("9e374e33bcc65926240d5181eac52bad8b57b699097a211425715ba372a86f28", "7c4dd5ff50249940d1569ce4caa2bdd241b33390974a9dc2b2415e5ae683491e", "60b9a38deb57f48b7dfd36ba0b1360a3bf8f6607eed4e45b0561708a5995cd28", "c6a245a6f8c5cc3ecfade69e26528daee56ab9201acfbc9f3c15f39635508200", 18, uniformPairs(18, 0)),
    pinned("0677d8ecf741d37f938ae0f77e647e782952fbec11a8f07702e62d6980735dc5", "87a71a7115d1de0eca7e8c2b93e5fd963ae3023c7ed5c4184a297742c2ca6b0c", "90a08d816b29d272d592086ab1f5f8f652a632e7343b4251094afed3cfb91268", "15da2de519c16b0de6e9fcd232d5fde7466f5b258a035f5d2d4192a995332fd9", 8, uniformPairs(8, 0)),
    pinned("ec8aefea7299e84a480524c3848c1ccc73241caea4e89f983f7c2605e6b04e90", "f235af0b630699c29e61d978bd4189acadc04f5d16fef9344853a0a9c86872d2", "3e956330e88ff263f37312181694296d1516dc03fc3be45ade21e67a6ef41b81", "3115c366d1c493f89aed81c4cb1f7154984aaff9e5e97f636a82c288c9598e80", 16, uniformPairs(16, 0)),
    pinned("0d93e601535fa7ec6cb6c744afbf72418f12ca68cbbd16dc18a9fea4b33bfce4", "9b96a967bfc76fe1c63fe0fcd1bcb66ece7fbc98dea227815ba9b23b9392879f", "e27f9a8e484a45085b7a9b593c4245fd69a66b4dde4859a78f6a96a77f45c3ee", "eabc7908ba523e3d1c7badb7fe3b334a8ae030e2ed95f5108ccf226d39dd8abd", 16, batchPlan(&.{ .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 1, 2 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 2, 3 }, .{ 1, 2 } })),
    pinned("00d717cfbaa5ba3f82604ce9fdedd1e3f4de1ede56d3fe09ddd835d3118c0e7b", "c618b7f69fbe50c7ff2c8bae59a35eb347a62e3f24bc019ae7aa70a05181e8a8", "edb107f67652e047bfda901d9f6075ce4924ac04efcd5968cd0643e8de7407aa", "b74dd37ef0dbd0511bc31756c238bd77873a353438461c59f24d0846998f8a78", 22, batchPlan(&.{ .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 1, 2 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 1, 2 } })),
    pinned("a33fd73890a391f954566eac75c54111c3ab5da54f20554ce095f7083b9e3ec2", "48d3f29da4e5f1e221227380fad487704270bbbec858b223bb994ee19b207d4a", "856d68cb81ed0c420d0c5e89302ab61d0c91e7c201a5757932979bea483c039f", "fe4ca39ddf594b544e8e522194512e66a060e142c4cf468488ed7c30d8ef7467", 25, batchPlan(&.{ .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 2, 3 }, .{ 1, 2 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 3 }, .{ 1, 2 }, .{ 1, 3 }, .{ 2, 3 }, .{ 2, 3 } })),
    pinned("ed5fd16042ad5918b843e6afd45393d527b0dfb3dfba2dcf29fe93caf041d3f2", "80c9186add61ae57e27e1e79efc90f3f3d5bb3a48920f54709e9121916468617", "027e9ab0891eb81d4095b8659437b873a1bf320c4b919d40258df04e4e06b6a1", "66dd9335b26133dd5506102a41ea85771aac5c18ae6c4d6262a88f6d4a8474c3", 3, uniformPairs(3, 2)),
};

/// Allocation-free family-level admission used after the enclosing manifest
/// and statement token have been checked once. Comparing the complete fixed
/// record also rejects mutations in capacity slack, which is intentionally
/// absent from the manifest identity serialization.
pub fn validatePinnedEntry(entry: *const FamilyEntry) !void {
    const rank = composition.compositionIndex(entry.family);
    const expected = nativeEntries()[rank];
    if (!std.meta.eql(entry.*, expected)) return error.InvalidAuthority;
    try entry.lookup_authority.validate();
    try validateBatches(
        entry,
        &PINNED_BY_FAMILY[@intFromEnum(entry.family)],
    );
}

fn deriveStatement(
    statement: *const statement_mod.RiscVStatement,
    manifest: *const Manifest,
) !AuthenticatedStatement {
    if (statement.n_components > statement_mod.MAX_COMPONENTS)
        return error.InvalidStatementGeometry;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(STATEMENT_IDENTITY_DOMAIN);
    hashInteger(&hash, u16, STATEMENT_FORMAT_VERSION);
    hash.update(&manifest.identity);
    hashInteger(&hash, u32, statement.n_components);

    var previous_rank: ?usize = null;
    var main_offset: u32 = 0;
    var interaction_offset: u32 = 0;
    var claim_offset: u32 = 0;
    for (statement.component_descs[0..statement.n_components], 0..) |
        descriptor,
        component_index,
    | {
        const rank = composition.compositionIndex(descriptor.family);
        if (previous_rank) |previous| {
            if (rank < previous) return error.InvalidFamilyOrder;
        }
        previous_rank = rank;
        const entry = manifest.entryForFamily(descriptor.family);
        if (descriptor.n_columns != entry.main_column_count)
            return error.InvalidMainGeometry;

        hashInteger(&hash, u32, @intCast(component_index));
        hashInteger(&hash, u8, @intFromEnum(descriptor.family));
        hashInteger(&hash, u32, descriptor.log_size);
        hashInteger(&hash, u32, descriptor.n_rows);
        hashInteger(&hash, u32, descriptor.n_columns);
        hashInteger(&hash, u32, @intCast(2 * component_index));
        hashInteger(&hash, u32, @intCast(2 * component_index + 1));
        hashInteger(&hash, u32, main_offset);
        hashInteger(&hash, u32, interaction_offset);
        hashInteger(&hash, u32, claim_offset);
        hashInteger(&hash, u32, entry.detailed_claim_count);
        hash.update(&entry.lookup_authority.program_identity);

        main_offset = std.math.add(
            u32,
            main_offset,
            entry.main_column_count,
        ) catch return error.CountOverflow;
        interaction_offset = std.math.add(
            u32,
            interaction_offset,
            entry.interaction_column_count,
        ) catch return error.CountOverflow;
        claim_offset = std.math.add(
            u32,
            claim_offset,
            entry.detailed_claim_count,
        ) catch return error.CountOverflow;
    }
    const statement_identity = hash.finalResult();
    var result = AuthenticatedStatement{
        .manifest_identity = manifest.identity,
        .statement_identity = statement_identity,
        .activation_identity = .{0} ** 32,
        .component_count = statement.n_components,
        .opcode_main_columns = main_offset,
        .opcode_interaction_columns = interaction_offset,
        .detailed_claim_count = claim_offset,
    };
    result.activation_identity = activationDigest(result);
    return result;
}

fn activationDigest(value: AuthenticatedStatement) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ACTIVATION_IDENTITY_DOMAIN);
    hashInteger(&hash, u16, value.format_version);
    hash.update(&value.manifest_identity);
    hash.update(&value.statement_identity);
    hashInteger(&hash, u32, value.component_count);
    hashInteger(&hash, u32, value.opcode_main_columns);
    hashInteger(&hash, u32, value.opcode_interaction_columns);
    hashInteger(&hash, u32, value.detailed_claim_count);
    return hash.finalResult();
}

fn nativeEntries() [FAMILY_COUNT]FamilyEntry {
    var result: [FAMILY_COUNT]FamilyEntry = undefined;
    var main_offset: u32 = 0;
    var interaction_offset: u32 = 0;
    var claim_offset: u32 = 0;
    for (composition.TRANSCRIPT_ORDER, 0..) |family, index| {
        const descriptor = composition.descriptor(family);
        const pinned_family = PINNED_BY_FAMILY[@intFromEnum(family)];
        result[index] = .{
            .family = family,
            .composition_index = @intCast(index),
            .semantic_adapter_index = @intCast(2 * index),
            .lookup_adapter_index = @intCast(2 * index + 1),
            .is_first_column = @intCast(2 * index),
            .is_active_column = @intCast(2 * index + 1),
            .main_column_offset = main_offset,
            .main_column_count = @intCast(descriptor.main_columns),
            .interaction_column_offset = interaction_offset,
            .interaction_column_count = pinned_family.authority.interaction_column_count,
            .detailed_claim_offset = claim_offset,
            .detailed_claim_count = pinned_family.authority.batch_count,
            .typed_authority_identity = descriptor.authority_digest,
            .lookup_authority = pinned_family.authority,
            .batches = pinned_family.batches,
        };
        main_offset += @intCast(descriptor.main_columns);
        interaction_offset +=
            pinned_family.authority.interaction_column_count;
        claim_offset += pinned_family.authority.batch_count;
    }
    return result;
}

fn validateBatches(entry: *const FamilyEntry, pinned_family: *const PinnedFamily) Error!void {
    if (entry.batches.len != entry.lookup_authority.batch_count or
        !std.meta.eql(entry.batches, pinned_family.batches))
    {
        return error.InvalidBatchGeometry;
    }
    var cursor: u32 = 0;
    var maximum_degree: u32 = 0;
    for (entry.activeBatches()) |batch| {
        if (batch.first_entry != cursor or
            batch.entry_count == 0 or
            batch.entry_count > 2)
        {
            return error.InvalidBatchGeometry;
        }
        cursor = std.math.add(
            u32,
            cursor,
            batch.entry_count,
        ) catch return error.CountOverflow;
        maximum_degree = @max(maximum_degree, batch.interaction_degree);
    }
    if (cursor != entry.lookup_authority.entry_count or
        maximum_degree != entry.lookup_authority.maximum_interaction_degree)
    {
        return error.InvalidBatchGeometry;
    }
}

fn pinned(
    comptime component_hex: []const u8,
    comptime partition_hex: []const u8,
    comptime layout_hex: []const u8,
    comptime program_hex: []const u8,
    comptime entry_count: u32,
    comptime batches: FixedBatches,
) PinnedFamily {
    return .{
        .authority = .{
            .component_identity = decodeDigest(component_hex),
            .partition_identity = decodeDigest(partition_hex),
            .layout_identity = decodeDigest(layout_hex),
            .program_identity = decodeDigest(program_hex),
            .entry_count = entry_count,
            .batch_count = batches.len,
            .interaction_column_count = 4 * @as(u32, batches.len),
            .maximum_interaction_degree = maximumDegree(batches),
        },
        .batches = batches,
    };
}

fn uniformPairs(
    comptime entry_count: u32,
    comptime final_singleton_degree: u32,
) FixedBatches {
    var result = FixedBatches{
        .len = 0,
        .values = .{@as(Batch, .{
            .first_entry = 0,
            .entry_count = 0,
            .interaction_degree = 0,
        })} ** MAX_BATCHES_PER_FAMILY,
    };
    var cursor: u32 = 0;
    while (cursor < entry_count) {
        const width: u8 = if (entry_count - cursor >= 2) 2 else 1;
        result.values[result.len] = .{
            .first_entry = cursor,
            .entry_count = width,
            .interaction_degree = if (width == 2)
                3
            else
                final_singleton_degree,
        };
        result.len += 1;
        cursor += width;
    }
    return result;
}

fn batchPlan(comptime specs: []const struct { u8, u32 }) FixedBatches {
    var result = FixedBatches{
        .len = @intCast(specs.len),
        .values = .{@as(Batch, .{
            .first_entry = 0,
            .entry_count = 0,
            .interaction_degree = 0,
        })} ** MAX_BATCHES_PER_FAMILY,
    };
    var cursor: u32 = 0;
    for (specs, 0..) |spec, index| {
        result.values[index] = .{
            .first_entry = cursor,
            .entry_count = spec[0],
            .interaction_degree = spec[1],
        };
        cursor += spec[0];
    }
    return result;
}

fn maximumDegree(comptime batches: FixedBatches) u32 {
    var result: u32 = 0;
    for (batches.values[0..batches.len]) |batch| {
        result = @max(result, batch.interaction_degree);
    }
    return result;
}

fn decodeDigest(comptime encoded: []const u8) Digest {
    @setEvalBranchQuota(100_000);
    if (encoded.len != 64) @compileError("digest must contain 64 hex digits");
    var result: Digest = undefined;
    for (0..result.len) |index| {
        result[index] = (hexNibble(encoded[2 * index]) << 4) |
            hexNibble(encoded[2 * index + 1]);
    }
    return result;
}

fn hexNibble(comptime value: u8) u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => @compileError("digest contains a non-lowercase-hex byte"),
    };
}

fn hashAuthority(hash: anytype, authority: Authority) void {
    hashInteger(hash, u16, authority.format_version);
    hash.update(&authority.component_identity);
    hash.update(&authority.partition_identity);
    hash.update(&authority.layout_identity);
    hash.update(&authority.program_identity);
    hashInteger(hash, u32, authority.entry_count);
    hashInteger(hash, u32, authority.batch_count);
    hashInteger(hash, u32, authority.interaction_column_count);
    hashInteger(hash, u32, authority.maximum_interaction_degree);
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var limbs: [8]u32 = undefined;
    for (&limbs, 0..) |*limb, index| {
        limb.* = std.mem.readInt(
            u32,
            digest[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            .little,
        );
    }
    channel.mixU32s(&limbs);
}

fn hashInteger(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FAMILY_COUNT != 17 or MAX_BATCHES_PER_FAMILY != 25)
        @compileError("lookup physical V2 constants require regeneration");
}
