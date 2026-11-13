//! Ethereum session/capability policy over the one native diagnostic journal kernel.
const std = @import("std");
const Core = @import("stwo_riscv_frontend").diagnostics.segment_manifest;
const canonical_runner_a174c4 = @import("stwo_riscv_rv32").execution.elf_loader;
const canonical_runner_b82b34 = @import("stwo_riscv_rv32").execution.base_result;
const canonical_runner_88791c = @import("stwo_riscv_rv32").execution.segment_session_contract;
const canonical_runner_a5909c = @import("../runner/segment_session.zig");
const execution_profile = @import("stwo_riscv_isa").execution_profile;
const bulk_registry = @import("stwo_riscv_isa").bulk_memcpy_private_registry;
const stack_swap = @import("stwo_riscv_isa").stack_swap_candidate;
const candidate_capability = @import("../runner/guest_precompile/ethereum_candidate_execution_capability.zig");
const result_mod = @import("stwo_riscv_rv32").execution.base_result;
const ExternalFamilyRows = Core.ExternalFamilyRows;
const maximum_external_families = Core.maximum_external_families;
const u64FromUsize = Core.u64FromUsize;
const validateExternalFamilyRows = Core.validateExternalFamilyRows;
pub const HEADER_SCHEMA = Core.HEADER_SCHEMA;
pub const SEGMENT_SCHEMA = Core.SEGMENT_SCHEMA;
pub const SUMMARY_SCHEMA = Core.SUMMARY_SCHEMA;
pub const CLAIM_BOUNDARY = Core.CLAIM_BOUNDARY;
pub const SegmentClockFrame = Core.SegmentClockFrame;
pub fn stream(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    segment_step_budget: usize,
    strict_completion: bool,
    clock_frame: canonical_runner_b82b34.SegmentClockFrame,
    writer: *std.Io.Writer,
) !void {
    var observer = Core.NoopObserver{};
    return streamObserved(
        allocator,
        elf_bytes,
        input,
        segment_step_budget,
        strict_completion,
        clock_frame,
        writer,
        &observer,
    );
}

pub fn streamObserved(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    segment_step_budget: usize,
    strict_completion: bool,
    clock_frame: canonical_runner_b82b34.SegmentClockFrame,
    writer: *std.Io.Writer,
    observer: anytype,
) !void {
    const profile = try canonical_runner_a174c4.requestedExecutionProfile(elf_bytes);
    return switch (profile) {
        inline .rv32im_zkvm_ethereum_v1, .rv32im_zkvm_ethereum_sha_v1 => |selected| Core.streamWithAdapter(selected, DefaultStreamAdapter(selected), {}, allocator, elf_bytes, input, segment_step_budget, strict_completion, clock_frame, writer, observer),
        else => Core.streamObserved(allocator, elf_bytes, input, segment_step_budget, strict_completion, clock_frame, writer, observer),
    };
}

pub fn streamCandidateObserved(
    allocator: std.mem.Allocator,
    capability: candidate_capability.Capability,
    reopened_elf: []const u8,
    input: []const u8,
    segment_step_budget: usize,
    strict_completion: bool,
    clock_frame: canonical_runner_b82b34.SegmentClockFrame,
    writer: *std.Io.Writer,
    observer: anytype,
) !void {
    try capability.validate();
    if (capability.executable_class != .combined_candidate or
        !capability.final_candidate_executable)
    {
        return error.FinalEthereumCombinedCandidateCapabilityRequired;
    }
    return Core.streamWithAdapter(
        .rv32im_zkvm_ethereum_v1,
        CombinedCandidateStreamAdapter,
        capability,
        allocator,
        reopened_elf,
        input,
        segment_step_budget,
        strict_completion,
        clock_frame,
        writer,
        observer,
    );
}

fn DefaultStreamAdapter(comptime profile: execution_profile.ExecutionProfile) type {
    return struct {
        pub const SessionAuthority = void;

        pub fn initSession(
            _: SessionAuthority,
            allocator: std.mem.Allocator,
            elf_bytes: []const u8,
            input: []const u8,
            strict_completion: bool,
            clock_frame: canonical_runner_b82b34.SegmentClockFrame,
            retirement_observer: ?canonical_runner_88791c.RetirementObserverV1,
        ) !canonical_runner_a5909c.ExecutionSession(profile) {
            return canonical_runner_a5909c.ExecutionSession(profile).init(allocator, elf_bytes, .{
                .input = input,
                .stop_on_halt_flag = strict_completion,
                .strict_completion = strict_completion,
                .trace_retention = .segment_owned,
                .clock_frame = clock_frame,
                .retirement_observer = retirement_observer,
            });
        }

        pub fn baseSegment(configured: anytype) *result_mod.SegmentResult {
            return &configured.base;
        }

        pub fn initializeExternalFamilyRows(
            storage: *[maximum_external_families]ExternalFamilyRows,
        ) []ExternalFamilyRows {
            return initializeDefaultExternalFamilyRows(profile, storage);
        }

        pub fn segmentExternalFamilyRows(
            configured: anytype,
            external_rows: u64,
            storage: *[maximum_external_families]ExternalFamilyRows,
        ) ![]ExternalFamilyRows {
            return defaultSegmentExternalFamilyRows(
                profile,
                configured,
                external_rows,
                storage,
            );
        }
    };
}

const CombinedCandidateStreamAdapter = struct {
    pub const SessionAuthority = candidate_capability.Capability;

    pub fn initSession(
        capability: SessionAuthority,
        allocator: std.mem.Allocator,
        elf_bytes: []const u8,
        input: []const u8,
        strict_completion: bool,
        clock_frame: canonical_runner_b82b34.SegmentClockFrame,
        retirement_observer: ?canonical_runner_88791c.RetirementObserverV1,
    ) !candidate_capability.CombinedSession {
        return capability.initCombinedSession(allocator, elf_bytes, .{
            .input = input,
            .stop_on_halt_flag = strict_completion,
            .strict_completion = strict_completion,
            .trace_retention = .segment_owned,
            .clock_frame = clock_frame,
            .retirement_observer = retirement_observer,
        });
    }

    pub fn baseSegment(configured: anytype) *result_mod.SegmentResult {
        return &configured.ethereum.base;
    }

    pub fn initializeExternalFamilyRows(
        storage: *[maximum_external_families]ExternalFamilyRows,
    ) []ExternalFamilyRows {
        storage[0] = .{
            .family = execution_profile.keccakf_capability,
            .calls = 0,
            .execution_rows = 0,
        };
        storage[1] = .{
            .family = execution_profile.secp256k1_recover_capability,
            .calls = 0,
            .execution_rows = 0,
        };
        storage[2] = .{
            .family = bulk_registry.semantic_name,
            .calls = 0,
            .execution_rows = 0,
        };
        storage[3] = .{
            .family = stack_swap.registry_request.semantic_name,
            .calls = 0,
            .execution_rows = 0,
        };
        return storage[0..maximum_external_families];
    }

    pub fn segmentExternalFamilyRows(
        configured: anytype,
        external_rows: u64,
        storage: *[maximum_external_families]ExternalFamilyRows,
    ) ![]ExternalFamilyRows {
        const rows = initializeExternalFamilyRows(storage);
        rows[0].calls = try u64FromUsize(configured.ethereum.keccakf_calls.len());
        rows[0].execution_rows = try u64FromUsize(
            configured.ethereum.keccakf_execution_rows.rows().len,
        );
        rows[1].calls = try u64FromUsize(
            configured.ethereum.signer_recovery_calls.len(),
        );
        rows[1].execution_rows = try u64FromUsize(
            configured.ethereum.signer_recovery_execution_rows.rows().len,
        );
        rows[2].calls = try u64FromUsize(configured.bulk_memcpy.records().len);
        rows[2].execution_rows = try u64FromUsize(configured.bulk_memcpy.rows().len);
        rows[3].calls = try u64FromUsize(configured.stack_swap.records().len);
        rows[3].execution_rows = try u64FromUsize(configured.stack_swap.rows().len);
        try validateExternalFamilyRows(rows, external_rows);
        return rows;
    }
};

fn initializeDefaultExternalFamilyRows(comptime profile: execution_profile.ExecutionProfile, storage: *[maximum_external_families]ExternalFamilyRows) []ExternalFamilyRows {
    storage[0] = .{ .family = execution_profile.keccakf_capability, .calls = 0, .execution_rows = 0 };
    storage[1] = .{ .family = execution_profile.secp256k1_recover_capability, .calls = 0, .execution_rows = 0 };
    if (comptime profile == .rv32im_zkvm_ethereum_sha_v1) {
        storage[2] = .{ .family = execution_profile.sha256_capability, .calls = 0, .execution_rows = 0 };
        return storage[0..3];
    }
    return storage[0..2];
}
fn defaultSegmentExternalFamilyRows(comptime profile: execution_profile.ExecutionProfile, configured: anytype, external_rows: u64, storage: *[maximum_external_families]ExternalFamilyRows) ![]ExternalFamilyRows {
    const rows = initializeDefaultExternalFamilyRows(profile, storage);
    if (comptime profile == .rv32im_zkvm_ethereum_sha_v1) {
        rows[0].calls = try u64FromUsize(configured.extension.keccakf_calls.len());
        rows[0].execution_rows = try u64FromUsize(configured.extension.keccakf_execution_rows.rows().len);
        rows[1].calls = try u64FromUsize(configured.extension.signer_recovery_calls.len());
        rows[1].execution_rows = try u64FromUsize(configured.extension.signer_recovery_execution_rows.rows().len);
        rows[2].calls = try u64FromUsize(configured.extension.sha_calls.len());
        rows[2].execution_rows = rows[2].calls;
    } else {
        rows[0].calls = try u64FromUsize(configured.keccakf_calls.len());
        rows[0].execution_rows = try u64FromUsize(configured.keccakf_execution_rows.rows().len);
        rows[1].calls = try u64FromUsize(configured.signer_recovery_calls.len());
        rows[1].execution_rows = try u64FromUsize(configured.signer_recovery_execution_rows.rows().len);
    }
    try validateExternalFamilyRows(rows, external_rows);
    return rows;
}

test "Ethereum manifest separates Keccak and signer-recovery rows" {
    const test_elf = @import("stwo_riscv_rv32").testing.execution.guest_precompile.test_elf;
    const elf = test_elf.buildEthereum();
    var output = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer output.deinit();
    try stream(std.testing.allocator, &elf, &.{}, 16, false, .leaf_local, &output.writer);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.written(),
        "\"external_family_rows\":[{\"family\":\"stwo.keccakf-1600.permute-in-place@1\",\"calls\":1,\"execution_rows\":1},{\"family\":\"stwo.secp256k1.recover-signer@1\",\"calls\":1,\"execution_rows\":1}]",
    ) != null);
}
