//! Cold reconstruction of one retained unoptimized Ethereum leaf authority.
//!
//! The caller supplies only absolute file paths.  Admission independently
//! reopens the exact leaf request, SourceRequest V2, materialization, journal,
//! selected STWESG31 source, host executable and both guest-ELF custodians.
//! It then reruns the existing `openAuthority` join and derives the session and
//! statements locally before sealing a non-production receipt.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const product_contract = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const receipt = @import("ethereum_unoptimized_baseline_admission_receipt_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub const maximum_executable_bytes: usize = 512 * 1024 * 1024;
pub const maximum_materialization_bytes: usize = contract.max_json_bytes;
pub const maximum_request_bytes: usize = contract.max_json_bytes;
pub const production_active = false;
pub const proof_or_fresh_verification = false;

pub const Input = struct {
    host_executable_path: []const u8,
    immutable_guest_elf_path: []const u8,
    source_request_v2_path: []const u8,
    materialization_v2_path: []const u8,
    selected_source_segment_path: []const u8,
    leaf_request_path: []const u8,

    pub fn validate(self: Input) !void {
        inline for (.{
            self.host_executable_path,
            self.immutable_guest_elf_path,
            self.source_request_v2_path,
            self.materialization_v2_path,
            self.selected_source_segment_path,
            self.leaf_request_path,
        }) |path| if (!std.fs.path.isAbsolute(path))
            return error.InvalidUnoptimizedBaselineAdmissionInput;
    }
};

/// Returns the canonical sealed receipt.  The returned bytes own all string
/// data; no path or JSON slice borrowed during cold admission escapes.
pub fn coldAdmitAlloc(
    allocator: std.mem.Allocator,
    input: Input,
) ![]u8 {
    if (production_active or proof_or_fresh_verification)
        return error.UnoptimizedBaselineAdmissionActivated;
    try input.validate();

    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        input.leaf_request_path,
        maximum_request_bytes,
    );
    defer allocator.free(request_bytes);
    const request_file = receipt.fileIdentity(
        input.leaf_request_path,
        request_bytes,
    );
    var parsed_request = try product_contract.parseRequest(
        allocator,
        request_bytes,
    );
    defer parsed_request.deinit();
    const request = parsed_request.value;
    if (!std.mem.eql(
        u8,
        request.source_request.path,
        input.source_request_v2_path,
    ) or !std.mem.eql(
        u8,
        request.source_segment.path,
        input.selected_source_segment_path,
    )) return error.UnoptimizedBaselineRequestPathMismatch;

    const host_bytes = try artifact_io.readFileBounded(
        allocator,
        input.host_executable_path,
        maximum_executable_bytes,
    );
    defer allocator.free(host_bytes);
    const host_file = receipt.fileIdentity(
        input.host_executable_path,
        host_bytes,
    );
    if (!std.mem.eql(
        u8,
        &host_file.sha256,
        &try contract.parseSha256(request.producer_sha256),
    ) or !std.mem.eql(
        u8,
        &host_file.sha256,
        &try contract.parseSha256(request.verifier_sha256),
    )) return error.UnoptimizedBaselineHostExecutableMismatch;

    const immutable_guest_bytes = try artifact_io.readFileBounded(
        allocator,
        input.immutable_guest_elf_path,
        maximum_executable_bytes,
    );
    defer allocator.free(immutable_guest_bytes);
    const immutable_guest_file = receipt.fileIdentity(
        input.immutable_guest_elf_path,
        immutable_guest_bytes,
    );

    const source_bytes = try artifact_io.readFileBounded(
        allocator,
        input.source_request_v2_path,
        contract.max_json_bytes,
    );
    defer allocator.free(source_bytes);
    const source_file = receipt.fileIdentity(
        input.source_request_v2_path,
        source_bytes,
    );
    try requireTypedIdentity(
        source_file,
        request.source_request,
        contract.recursive_source_schema,
    );

    var opened = try product_support.openAuthority(allocator, &request);
    defer opened.deinit();
    const source = opened.source.value;

    const source_guest_bytes = try support.readIdentity(
        allocator,
        source.elf,
        product_support.max_elf_bytes,
    );
    defer allocator.free(source_guest_bytes);
    const source_guest_file = receipt.fileIdentity(
        source.elf.path,
        source_guest_bytes,
    );
    if (immutable_guest_file.bytes != source_guest_file.bytes or
        !std.mem.eql(
            u8,
            &immutable_guest_file.sha256,
            &source_guest_file.sha256,
        )) return error.UnoptimizedBaselineGuestElfMismatch;

    const journal_bytes = try support.readIdentity(
        allocator,
        source.execution_journal,
        product_support.max_journal_bytes,
    );
    defer allocator.free(journal_bytes);
    const journal_file = receipt.fileIdentity(
        source.execution_journal.path,
        journal_bytes,
    );
    const input_bytes = try support.readIdentity(
        allocator,
        source.input,
        product_support.max_input_bytes,
    );
    defer allocator.free(input_bytes);
    const input_file = receipt.fileIdentity(source.input.path, input_bytes);
    const output_bytes = try support.readIdentity(
        allocator,
        source.expected_output,
        product_support.max_output_bytes,
    );
    defer allocator.free(output_bytes);
    const output_file = receipt.fileIdentity(
        source.expected_output.path,
        output_bytes,
    );

    const selected_bytes = try artifact_io.readFileBounded(
        allocator,
        input.selected_source_segment_path,
        support.source_wire.encoded_size,
    );
    defer allocator.free(selected_bytes);
    const selected_file = receipt.fileIdentity(
        input.selected_source_segment_path,
        selected_bytes,
    );
    try requireIdentity(selected_file, request.source_segment);

    const materialization_bytes = try artifact_io.readFileBounded(
        allocator,
        input.materialization_v2_path,
        maximum_materialization_bytes,
    );
    defer allocator.free(materialization_bytes);
    const materialization_file = receipt.fileIdentity(
        input.materialization_v2_path,
        materialization_bytes,
    );
    var parsed_materialization = try contract.parseMaterializationResult(
        allocator,
        materialization_bytes,
    );
    defer parsed_materialization.deinit();
    const materialization = parsed_materialization.value;
    try validateMaterializationJoin(
        materialization,
        source,
        source_file,
        journal_file,
        input_file,
        output_file,
        selected_file,
        request,
        &opened.expected,
    );

    const session_sha256 = try contract.parseSha256(request.session_id);
    const session_m31_le = product_support.fieldDigestBytes(
        support.sessionDigest(session_sha256),
    );
    const metadata_id_m31_le = product_support.fieldDigestBytes(
        try opened.expected.metadata.identity(),
    );
    const statement_id_m31_le = product_support.fieldDigestBytes(
        statementId(&opened.expected.metadata.base_statement_words),
    );
    const source_statement = try opened.expected.statementSha256();
    const recursive_statement = statement_plan.statementSha256(
        &opened.expected.metadata.base_statement_words,
    );
    const body = receipt.AuthorityBody{
        .build = .{
            .host_executable = host_file,
            .immutable_guest_elf = immutable_guest_file,
            .source_declared_guest_elf = source_guest_file,
        },
        .corpus = .{
            .source_request_v2 = source_file,
            .materialization_v2 = materialization_file,
            .execution_journal = journal_file,
            .input = input_file,
            .expected_output = output_file,
            .selected_source_segment = selected_file,
            .leaf_request = request_file,
        },
        .profile = .{
            .execution_profile = source.execution_profile,
            .profile_wire_id = source.profile_wire_id,
            .profile_abi_version = source.profile_abi_version,
            .profile_semantic_digest = try contract.parseSha256(
                source.profile_semantic_digest,
            ),
            .segment_step_budget = source.segment_step_budget,
        },
        .leaf = .{
            .segment_index = request.segment_index,
            .segment_count = source.segment_count,
            .total_cycles = materialization.total_cycles,
            .global_cycle_start = opened.expected.metadata.global_cycle_start,
            .global_cycle_end = opened.expected.metadata.global_cycle_end,
            .local_cycle_count = opened.expected.metadata.local_cycle_count,
            .materialization_content_sha256 = try contract.parseSha256(
                materialization.content_sha256,
            ),
            .leaf_request_content_sha256 = try contract.parseSha256(
                request.content_sha256,
            ),
            .producer_executable_sha256 = try contract.parseSha256(
                request.producer_sha256,
            ),
            .verifier_executable_sha256 = try contract.parseSha256(
                request.verifier_sha256,
            ),
            .session_sha256 = session_sha256,
            .session_m31_le = session_m31_le,
            .journal_record_sha256 = opened.expected.journal_record_sha256,
            .metadata_id_m31_le = metadata_id_m31_le,
            .statement_id_m31_le = statement_id_m31_le,
            .source_public_statement_sha256 = source_statement,
            .recursive_statement_sha256 = recursive_statement,
            .job = .{
                .final_state_sha256 = try contract.parseSha256(
                    materialization.job.final_state_sha256,
                ),
                .initial_state_sha256 = try contract.parseSha256(
                    materialization.job.initial_state_sha256,
                ),
                .job_sha256 = try contract.parseSha256(
                    materialization.job.job_sha256,
                ),
                .program_m31_le = try contract.parseSha256(
                    materialization.job.program_m31_le,
                ),
                .public_input_m31_le = try contract.parseSha256(
                    materialization.job.public_input_m31_le,
                ),
                .public_output_m31_le = try contract.parseSha256(
                    materialization.job.public_output_m31_le,
                ),
            },
            .open_authority_reconstructed = true,
            .session_reconstructed = true,
            .statement_reconstructed = true,
        },
    };
    const authority = try receipt.Authority.create(allocator, body);
    return receipt.encodeAlloc(allocator, authority);
}

/// Reopens all receipt-declared paths, reconstructs the admission again from
/// the explicit input paths, and requires byte-identical canonical receipts.
pub fn validateReopened(
    allocator: std.mem.Allocator,
    expected_receipt: []const u8,
    input: Input,
) !void {
    var parsed = try receipt.decodeAlloc(allocator, expected_receipt);
    defer parsed.deinit();
    try parsed.value.authority.validateReopenedFiles();
    const actual = try coldAdmitAlloc(allocator, input);
    defer allocator.free(actual);
    if (!std.mem.eql(u8, actual, expected_receipt))
        return error.UnoptimizedBaselineColdReadmissionMismatch;
}

fn validateMaterializationJoin(
    materialization: contract.MaterializationResult,
    source: contract.RecursiveSourceRequestV2,
    source_file: receipt.FileIdentity,
    journal_file: receipt.FileIdentity,
    input_file: receipt.FileIdentity,
    output_file: receipt.FileIdentity,
    selected_file: receipt.FileIdentity,
    request: product_contract.Request,
    selected: *const support.source_wire.Source,
) !void {
    try requireTypedIdentity(
        source_file,
        materialization.source_request,
        contract.recursive_source_schema,
    );
    try requireIdentity(journal_file, materialization.execution_journal);
    try requireIdentity(input_file, materialization.input);
    try requireIdentity(output_file, materialization.expected_output);
    if (!std.mem.eql(
        u8,
        materialization.execution_profile,
        source.execution_profile,
    ) or materialization.segment_count != source.segment_count or
        !pcsEql(materialization.pcs, source.pcs) or
        request.segment_index >= materialization.leaf_sources.len)
    {
        return error.UnoptimizedBaselineMaterializationMismatch;
    }
    const leaf = materialization.leaf_sources[request.segment_index];
    try requireIdentity(selected_file, leaf.authority);
    const metadata = product_support.fieldDigestBytes(
        try selected.metadata.identity(),
    );
    const statement_id = product_support.fieldDigestBytes(
        statementId(&selected.metadata.base_statement_words),
    );
    const source_statement = try selected.statementSha256();
    const recursive_statement = statement_plan.statementSha256(
        &selected.metadata.base_statement_words,
    );
    if (!std.mem.eql(
        u8,
        &metadata,
        &try contract.parseSha256(leaf.metadata_id_m31_le),
    ) or !std.mem.eql(
        u8,
        &statement_id,
        &try contract.parseSha256(leaf.statement_id_m31_le),
    ) or !std.mem.eql(
        u8,
        &source_statement,
        &try contract.parseSha256(leaf.statement_sha256),
    ) or !std.mem.eql(
        u8,
        &source_statement,
        &try contract.parseSha256(
            request.expected_source_public_statement_sha256,
        ),
    ) or !std.mem.eql(
        u8,
        &recursive_statement,
        &try contract.parseSha256(
            request.expected_recursive_statement_sha256,
        ),
    )) return error.UnoptimizedBaselineMaterializationMismatch;
}

fn statementId(
    words: *const frontend.recursion.span_statement.StatementWords,
) frontend.recursion.poseidon2_channel.Digest {
    var canonical: [
        frontend.recursion.span_statement
            .SPAN_STATEMENT_CANONICAL_WORDS
    ]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return frontend.recursion.protocol.statementId(&canonical);
}

fn requireIdentity(
    actual: receipt.FileIdentity,
    expected: contract.Identity,
) !void {
    try expected.validate(true);
    if (actual.bytes != expected.bytes or
        !std.mem.eql(u8, actual.path, expected.path) or
        !std.mem.eql(
            u8,
            &actual.sha256,
            &try contract.parseSha256(expected.sha256),
        )) return error.UnoptimizedBaselineFileIdentityMismatch;
}

fn requireTypedIdentity(
    actual: receipt.FileIdentity,
    expected: contract.TypedIdentity,
    expected_schema: []const u8,
) !void {
    try expected.validate();
    if (!std.mem.eql(u8, expected.schema, expected_schema))
        return error.UnoptimizedBaselineFileIdentityMismatch;
    try requireIdentity(actual, .{
        .bytes = expected.bytes,
        .path = expected.path,
        .sha256 = expected.sha256,
    });
}

fn pcsEql(
    left: contract.PcsAuthority,
    right: contract.PcsAuthority,
) bool {
    return std.mem.eql(u8, left.commitment_hash, right.commitment_hash) and
        std.mem.eql(u8, left.field, right.field) and
        left.fold_step == right.fold_step and
        left.lifting_log_size == right.lifting_log_size and
        left.log_blowup_factor == right.log_blowup_factor and
        left.log_last_layer_degree_bound ==
            right.log_last_layer_degree_bound and
        left.n_queries == right.n_queries and left.pow_bits == right.pow_bits and
        std.mem.eql(u8, left.transcript_hash, right.transcript_hash);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        receipt.production_eligible or receipt.proof_or_fresh_verification or
        receipt.git_source_closure_present)
    {
        @compileError("unoptimized baseline cold admission became active");
    }
}
