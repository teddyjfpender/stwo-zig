//! Capture-stage controller for the non-production matched A/B corpus.
//!
//! This is intentionally only the first transaction. It runs the established
//! ordinary materializer and combined-candidate capture with the same 2^20
//! segment budget, under one common input/output authority. It publishes no
//! matched authority and no leaf requests; those remain impossible until the
//! independent all-leaf legacy geometry audit closes.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const authority =
    @import("ethereum_matched_ab_rematerialization_authority_v1.zig");
const candidate_capture =
    @import("ethereum_candidate_combined_execution_capture_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const materializer = @import("ethereum_block_leaf_materializer.zig");

pub const baseline_source_basename = "baseline-leaf-sources-v2";
pub const baseline_source_request_basename = "baseline-source-request-v2.json";
pub const baseline_journal_basename = "baseline-execution-manifest-v3.ndjson";
pub const baseline_result_basename = "baseline-materialization-result-v2.json";
pub const candidate_capture_basename = "candidate-execution-capture-v1";
pub const maximum_input_bytes: usize = 512 * 1024 * 1024;
pub const maximum_authority_bytes: usize = 64 * 1024 * 1024;

pub const Options = struct {
    baseline_elf: []const u8,
    candidate_admission_receipt: []const u8,
    candidate_elf: []const u8,
    expected_output: []const u8,
    historical_baseline_materialization: []const u8,
    input: []const u8,
    output_root: []const u8,
    power_source: []const u8,
    candidate_hard_cap_ns: u64,

    pub fn validate(self: Options) !void {
        if (self.candidate_hard_cap_ns == 0 or self.power_source.len == 0)
            return error.InvalidMatchedAbRematerializationOptions;
        inline for (.{
            self.baseline_elf,
            self.candidate_admission_receipt,
            self.candidate_elf,
            self.expected_output,
            self.historical_baseline_materialization,
            self.input,
            self.output_root,
        }) |path| {
            if (!std.fs.path.isAbsolute(path))
                return error.AbsolutePathRequired;
        }
    }
};

pub fn captureBoth(allocator: std.mem.Allocator, options: Options) !void {
    try options.validate();
    const historical_bytes = try artifact_io.readFileBounded(
        allocator,
        options.historical_baseline_materialization,
        maximum_authority_bytes,
    );
    defer allocator.free(historical_bytes);
    var historical = try contract.parseMaterializationResult(
        allocator,
        historical_bytes,
    );
    defer historical.deinit();
    const expected_baseline_segments = try segmentCountForCycles(
        historical.value.total_cycles,
    );
    try validateHistoricalSemanticAuthority(
        allocator,
        historical.value,
        options,
    );

    try artifact_io.createDirectoryCreateOnly(options.output_root);
    const baseline_source_root = try child(
        allocator,
        options.output_root,
        baseline_source_basename,
    );
    defer allocator.free(baseline_source_root);
    const baseline_source_request = try child(
        allocator,
        options.output_root,
        baseline_source_request_basename,
    );
    defer allocator.free(baseline_source_request);
    const baseline_journal = try child(
        allocator,
        options.output_root,
        baseline_journal_basename,
    );
    defer allocator.free(baseline_journal);
    const baseline_result = try child(
        allocator,
        options.output_root,
        baseline_result_basename,
    );
    defer allocator.free(baseline_result);
    const candidate_root = try child(
        allocator,
        options.output_root,
        candidate_capture_basename,
    );
    defer allocator.free(candidate_root);

    const segment_count = try std.fmt.allocPrint(
        allocator,
        "{d}",
        .{expected_baseline_segments},
    );
    defer allocator.free(segment_count);
    const segment_budget = try std.fmt.allocPrint(
        allocator,
        "{d}",
        .{authority.segment_step_budget},
    );
    defer allocator.free(segment_budget);
    const baseline_arguments = [_][]const u8{
        "--elf",                 options.baseline_elf,
        "--expected-output",     options.expected_output,
        "--input",               options.input,
        "--journal",             baseline_journal,
        "--proof-profile",       contract.recursive_proof_profile_name,
        "--result",              baseline_result,
        "--segment-count",       segment_count,
        "--segment-step-budget", segment_budget,
        "--source-request",      baseline_source_request,
        "--source-root",         baseline_source_root,
    };
    try materializer.run(allocator, &baseline_arguments);
    try validateBaselineTerminal(
        allocator,
        baseline_result,
        options,
        expected_baseline_segments,
    );

    try candidate_capture.capture(allocator, .{
        .receipt_path = options.candidate_admission_receipt,
        .elf_path = options.candidate_elf,
        .input_path = options.input,
        .expected_output_path = options.expected_output,
        .output_root = candidate_root,
        .power_source = options.power_source,
        .segment_step_budget = authority.segment_step_budget,
        .hard_cap_ns = options.candidate_hard_cap_ns,
    });
    // Deliberately no controller receipt here. The capture artifacts are inputs
    // to the next transaction; only geometry closure may authorize requests.
}

fn validateHistoricalSemanticAuthority(
    allocator: std.mem.Allocator,
    historical: contract.MaterializationResult,
    options: Options,
) !void {
    const source_bytes = try artifact_io.readFileBounded(
        allocator,
        historical.source_request.path,
        maximum_authority_bytes,
    );
    defer allocator.free(source_bytes);
    try requireBytesMatchIdentity(
        source_bytes,
        historical.source_request.bytes,
        historical.source_request.sha256,
    );
    var source = try contract.parseRecursiveSource(allocator, source_bytes);
    defer source.deinit();
    try requireCurrentFileMatches(allocator, options.baseline_elf, source.value.elf);
    try requireCurrentFileMatches(allocator, options.input, historical.input);
    try requireCurrentFileMatches(
        allocator,
        options.expected_output,
        historical.expected_output,
    );
}

fn validateBaselineTerminal(
    allocator: std.mem.Allocator,
    path: []const u8,
    options: Options,
    expected_segment_count: u32,
) !void {
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        maximum_authority_bytes,
    );
    defer allocator.free(bytes);
    var parsed = try contract.parseMaterializationResult(allocator, bytes);
    defer parsed.deinit();
    if (parsed.value.segment_count != expected_segment_count or
        parsed.value.total_cycles == 0)
    {
        return error.MatchedAbBaselineCaptureDidNotClose;
    }
    try requireCurrentFileMatches(allocator, options.input, parsed.value.input);
    try requireCurrentFileMatches(
        allocator,
        options.expected_output,
        parsed.value.expected_output,
    );
}

fn segmentCountForCycles(total_cycles: u64) !u32 {
    if (total_cycles == 0) return error.InvalidHistoricalCycleCount;
    const budget: u64 = authority.segment_step_budget;
    const adjusted = std.math.add(u64, total_cycles, budget - 1) catch
        return error.MatchedAbSegmentCountOverflow;
    const count = adjusted / budget;
    const result = std.math.cast(u32, count) orelse
        return error.MatchedAbSegmentCountOverflow;
    if (result < 2) return error.InvalidHistoricalCycleCount;
    return result;
}

fn requireCurrentFileMatches(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: contract.Identity,
) !void {
    const bytes = try artifact_io.readFileBounded(
        allocator,
        path,
        maximum_input_bytes,
    );
    defer allocator.free(bytes);
    try requireBytesMatchIdentity(bytes, expected.bytes, expected.sha256);
}

fn requireBytesMatchIdentity(
    bytes: []const u8,
    expected_bytes: u64,
    expected_sha256: []const u8,
) !void {
    if (bytes.len != expected_bytes) return error.MatchedAbFileIdentityMismatch;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &encoded, expected_sha256))
        return error.MatchedAbFileIdentityMismatch;
}

fn child(
    allocator: std.mem.Allocator,
    parent: []const u8,
    basename: []const u8,
) ![]u8 {
    return artifact_io.resolveCreateOnlyChild(allocator, parent, basename);
}

comptime {
    if (authority.production_active or authority.proof_or_fresh_verification or
        authority.segment_step_budget != 1_048_576)
    {
        @compileError("matched A/B capture controller policy drifted");
    }
}

test "matched segment count is ceiling of cycles at fixed 2^20 budget" {
    try std.testing.expectEqual(@as(u32, 2), try segmentCountForCycles(
        authority.segment_step_budget + 1,
    ));
    try std.testing.expectEqual(@as(u32, 109), try segmentCountForCycles(
        113_491_411,
    ));
    try std.testing.expectError(
        error.InvalidHistoricalCycleCount,
        segmentCountForCycles(0),
    );
}
