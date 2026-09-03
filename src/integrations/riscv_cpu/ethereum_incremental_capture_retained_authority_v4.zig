//! Cold-opened retained authority for the fresh 210-segment capture pass.
//!
//! The historical materialization has a complete journal and STWESG31 source
//! set but no complete compact-tape set.  This module admits only those source
//! authorities; the sibling observer must freshly reexecute and mint STWEMT01
//! and STWIMT04 from the same live segments.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");

const source_wire = support.source_wire;
const span = frontend.recursion.span_statement;

const max_elf_bytes: usize = 64 * 1024 * 1024;
const max_input_bytes: usize = 64 * 1024 * 1024;
const max_output_bytes: usize = 16 * 1024 * 1024;
const max_journal_bytes: usize = 64 * 1024 * 1024;

pub const OwnedSourceV4 = struct {
    bytes: []u8,
    value: source_wire.Source,
    identity: publication.ArtifactIdentityV4,
};

const SourceAuthority = union(enum) {
    native: std.json.Parsed(contract.SourceRequest),
    recursive: std.json.Parsed(contract.RecursiveSourceRequestV2),

    fn deinit(self: *SourceAuthority) void {
        switch (self.*) {
            .native => |*value| value.deinit(),
            .recursive => |*value| value.deinit(),
        }
        self.* = undefined;
    }

    fn elf(self: *const SourceAuthority) contract.Identity {
        return switch (self.*) {
            .native => |value| value.value.elf,
            .recursive => |value| value.value.elf,
        };
    }

    fn input(self: *const SourceAuthority) contract.Identity {
        return switch (self.*) {
            .native => |value| value.value.input,
            .recursive => |value| value.value.input,
        };
    }

    fn output(self: *const SourceAuthority) contract.Identity {
        return switch (self.*) {
            .native => |value| value.value.expected_output,
            .recursive => |value| value.value.expected_output,
        };
    }

    fn journal(self: *const SourceAuthority) contract.Identity {
        return switch (self.*) {
            .native => |value| value.value.execution_journal,
            .recursive => |value| value.value.execution_journal,
        };
    }

    fn segmentCount(self: *const SourceAuthority) u32 {
        return switch (self.*) {
            .native => |value| value.value.segment_count,
            .recursive => |value| value.value.segment_count,
        };
    }

    fn segmentStepBudget(self: *const SourceAuthority) usize {
        return switch (self.*) {
            .native => |value| value.value.segment_step_budget,
            .recursive => |value| value.value.segment_step_budget,
        };
    }

    fn validateJournal(
        self: *const SourceAuthority,
        allocator: std.mem.Allocator,
        bytes: []const u8,
    ) ![][32]u8 {
        return switch (self.*) {
            .native => |value| journal_authority.validate(
                allocator,
                bytes,
                value.value,
            ),
            .recursive => |value| journal_authority.validate(
                allocator,
                bytes,
                value.value,
            ),
        };
    }
};

pub const RetainedAuthorityV4 = struct {
    allocator: std.mem.Allocator,
    materialization_bytes: []u8,
    materialization: std.json.Parsed(contract.MaterializationResult),
    materialization_identity: publication.ArtifactIdentityV4,
    source_request_bytes: []u8,
    source_authority: SourceAuthority,
    source_request_identity: publication.ArtifactIdentityV4,
    journal_bytes: []u8,
    journal_identity: publication.ArtifactIdentityV4,
    journal_records: [][32]u8,
    elf_bytes: []u8,
    elf_identity: publication.ArtifactIdentityV4,
    input_bytes: []u8,
    input_identity: publication.ArtifactIdentityV4,
    output_bytes: []u8,
    output_identity: publication.ArtifactIdentityV4,
    sources: []OwnedSourceV4,

    pub fn open(
        allocator: std.mem.Allocator,
        materialization_path: []const u8,
    ) !RetainedAuthorityV4 {
        const materialization_bytes = try artifact_io.readFileBounded(
            allocator,
            materialization_path,
            contract.max_json_bytes,
        );
        errdefer allocator.free(materialization_bytes);
        var materialization = try contract.parseMaterializationResult(
            allocator,
            materialization_bytes,
        );
        errdefer materialization.deinit();
        if (materialization.value.segment_count !=
            publication.CANONICAL_SEGMENT_COUNT)
        {
            return error.CanonicalIncrementalSegmentCountRequired;
        }

        const source_identity = identityFromTyped(
            materialization.value.source_request,
        );
        const source_request_bytes = try support.readIdentity(
            allocator,
            source_identity,
            contract.max_json_bytes,
        );
        errdefer allocator.free(source_request_bytes);
        var source_authority = switch (try contract.sourceKind(
            allocator,
            source_request_bytes,
        )) {
            .native_blake2s_v1 => SourceAuthority{
                .native = try contract.parseSource(
                    allocator,
                    source_request_bytes,
                ),
            },
            .recursive_poseidon2_v2 => SourceAuthority{
                .recursive = try contract.parseRecursiveSource(
                    allocator,
                    source_request_bytes,
                ),
            },
        };
        errdefer source_authority.deinit();
        if (source_authority.segmentCount() != publication.CANONICAL_SEGMENT_COUNT or
            !identityEqual(
                source_authority.input(),
                materialization.value.input,
            ) or !identityEqual(
            source_authority.output(),
            materialization.value.expected_output,
        ) or !identityEqual(
            source_authority.journal(),
            materialization.value.execution_journal,
        )) return error.RetainedIncrementalAuthorityMismatch;

        const elf_bytes = try support.readIdentity(
            allocator,
            source_authority.elf(),
            max_elf_bytes,
        );
        errdefer allocator.free(elf_bytes);
        if (try frontend.runner.elf_loader.requestedExecutionProfile(elf_bytes) !=
            .rv32im_zkvm_ethereum_v1)
        {
            return error.ExecutionProfileMismatch;
        }
        const input_bytes = try support.readIdentity(
            allocator,
            source_authority.input(),
            max_input_bytes,
        );
        errdefer allocator.free(input_bytes);
        const output_bytes = try support.readIdentity(
            allocator,
            source_authority.output(),
            max_output_bytes,
        );
        errdefer allocator.free(output_bytes);
        const journal_bytes = try support.readIdentity(
            allocator,
            source_authority.journal(),
            max_journal_bytes,
        );
        errdefer allocator.free(journal_bytes);
        const records = try source_authority.validateJournal(
            allocator,
            journal_bytes,
        );
        errdefer allocator.free(records);
        if (records.len != publication.CANONICAL_SEGMENT_COUNT)
            return error.CanonicalIncrementalSegmentCountRequired;

        const sources = try allocator.alloc(
            OwnedSourceV4,
            publication.CANONICAL_SEGMENT_COUNT,
        );
        var opened_count: usize = 0;
        errdefer {
            for (sources[0..opened_count]) |source| allocator.free(source.bytes);
            allocator.free(sources);
        }
        for (
            materialization.value.leaf_sources,
            records,
            sources,
            0..,
        ) |leaf, journal_record, *destination, index| {
            const bytes = try support.readIdentity(
                allocator,
                leaf.authority,
                source_wire.encoded_size,
            );
            errdefer allocator.free(bytes);
            const source = try source_wire.decode(bytes);
            if (source.metadata.segment_index != index or
                !std.mem.eql(
                    u8,
                    &source.journal_record_sha256,
                    &journal_record,
                ) or !std.meta.eql(
                try source.metadata.identity(),
                try contract.parseM31Digest(leaf.metadata_id_m31_le),
            ) or !std.meta.eql(
                statementId(&source.metadata.base_statement_words),
                try contract.parseM31Digest(leaf.statement_id_m31_le),
            ) or !std.mem.eql(
                u8,
                &try source.statementSha256(),
                &try contract.parseSha256(leaf.statement_sha256),
            )) return error.RetainedIncrementalSourceMismatch;
            if (index != 0) try frontend.recursion
                .segment_leaf_local_authority_v3.requireAdjacentMetadata(
                &sources[index - 1].value.metadata,
                &source.metadata,
            );
            destination.* = .{
                .bytes = bytes,
                .value = source,
                .identity = publication.ArtifactIdentityV4.fromBytes(bytes),
            };
            opened_count += 1;
        }

        return .{
            .allocator = allocator,
            .materialization_bytes = materialization_bytes,
            .materialization = materialization,
            .materialization_identity = publication.ArtifactIdentityV4.fromBytes(
                materialization_bytes,
            ),
            .source_request_bytes = source_request_bytes,
            .source_authority = source_authority,
            .source_request_identity = publication.ArtifactIdentityV4.fromBytes(
                source_request_bytes,
            ),
            .journal_bytes = journal_bytes,
            .journal_identity = publication.ArtifactIdentityV4.fromBytes(
                journal_bytes,
            ),
            .journal_records = records,
            .elf_bytes = elf_bytes,
            .elf_identity = publication.ArtifactIdentityV4.fromBytes(elf_bytes),
            .input_bytes = input_bytes,
            .input_identity = publication.ArtifactIdentityV4.fromBytes(input_bytes),
            .output_bytes = output_bytes,
            .output_identity = publication.ArtifactIdentityV4.fromBytes(output_bytes),
            .sources = sources,
        };
    }

    pub fn deinit(self: *RetainedAuthorityV4) void {
        for (self.sources) |source| self.allocator.free(source.bytes);
        self.allocator.free(self.sources);
        self.allocator.free(self.output_bytes);
        self.allocator.free(self.input_bytes);
        self.allocator.free(self.elf_bytes);
        self.allocator.free(self.journal_records);
        self.allocator.free(self.journal_bytes);
        self.source_authority.deinit();
        self.allocator.free(self.source_request_bytes);
        self.materialization.deinit();
        self.allocator.free(self.materialization_bytes);
        self.* = undefined;
    }

    pub fn executionAuthority(
        self: *const RetainedAuthorityV4,
    ) !publication.ExecutionAuthorityV4 {
        const value = publication.ExecutionAuthorityV4{
            .elf = self.elf_identity,
            .input = self.input_identity,
            .expected_output = self.output_identity,
            .execution_profile_semantic_sha256 = frontend.isa.execution_profile
                .ethereum_semantic_digest,
            .segment_count = publication.CANONICAL_SEGMENT_COUNT,
            .segment_step_budget = self.source_authority.segmentStepBudget(),
        };
        try value.validate();
        return value;
    }

    pub fn elfEvidence(self: *const RetainedAuthorityV4) evidence.FileIdentity {
        return evidence.identity(self.source_authority.elf().path, self.elf_bytes);
    }

    pub fn inputEvidence(self: *const RetainedAuthorityV4) evidence.FileIdentity {
        return evidence.identity(
            self.materialization.value.input.path,
            self.input_bytes,
        );
    }

    pub fn outputEvidence(self: *const RetainedAuthorityV4) evidence.FileIdentity {
        return evidence.identity(
            self.materialization.value.expected_output.path,
            self.output_bytes,
        );
    }

    pub fn journalEvidence(self: *const RetainedAuthorityV4) evidence.FileIdentity {
        return evidence.identity(
            self.materialization.value.execution_journal.path,
            self.journal_bytes,
        );
    }

    pub fn sourceRequestEvidence(
        self: *const RetainedAuthorityV4,
    ) evidence.FileIdentity {
        return evidence.identity(
            self.materialization.value.source_request.path,
            self.source_request_bytes,
        );
    }
};

fn identityFromTyped(value: contract.TypedIdentity) contract.Identity {
    return .{
        .bytes = value.bytes,
        .path = value.path,
        .sha256 = value.sha256,
    };
}

fn identityEqual(left: contract.Identity, right: contract.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn statementId(words: *const span.StatementWords) span.Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return frontend.recursion.protocol.statementId(&canonical);
}
