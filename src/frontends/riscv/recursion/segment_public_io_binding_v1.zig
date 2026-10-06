//! Experimental, versioned public-I/O check for a verified SegmentV2 capture.
//!
//! The V2 wire retains sparse memory values, but discards runner WordRole bits
//! and does not retain I/O addresses or lengths. An independently trusted ABI
//! and expected byte strings must therefore accompany this check. Call
//! `validateVerifiedCapture` only on the capture returned by the native proof
//! verifier; this module does not activate an equivalent recursive AIR relation.

const std = @import("std");
const public_data_v2 = @import("../air/public_data_v2.zig");
const runner_result = @import("../runner/result.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const segment_contract = @import("segment_statement_v2_contract.zig");
const span = @import("span_statement.zig");

pub const FORMAT_VERSION: u32 = 1;
pub const INPUT_DOMAIN: u32 = 0x5332_4931; // "S2I1"
pub const OUTPUT_DOMAIN: u32 = 0x5332_4f31; // "S2O1"
pub const RECURSIVE_PROOF_ACTIVATION = false;
pub const Digest = segment_v2.Digest;

pub const Expected = struct {
    input_start: u32,
    input: []const u8,
    output_len_addr: u32,
    output_data_addr: u32,
    output: []const u8,

    pub fn validate(self: Expected) Error!void {
        const input_len = std.math.cast(u32, self.input.len) orelse return error.IoRangeOutOfBounds;
        const output_len = std.math.cast(u32, self.output.len) orelse return error.IoRangeOutOfBounds;
        const input_end = std.math.add(u32, self.input_start, input_len) catch return error.IoRangeOutOfBounds;
        const output_end = std.math.add(u32, self.output_data_addr, output_len) catch return error.IoRangeOutOfBounds;
        if (self.input_start >= segment_v2.MAX_RW_ADDRESS_EXCLUSIVE or
            self.output_data_addr >= segment_v2.MAX_RW_ADDRESS_EXCLUSIVE or
            (self.output_len_addr & 3) != 0 or
            self.output_len_addr > segment_v2.MAX_RW_ADDRESS_EXCLUSIVE - 4 or
            input_end > segment_v2.MAX_RW_ADDRESS_EXCLUSIVE or
            output_end > segment_v2.MAX_RW_ADDRESS_EXCLUSIVE)
        {
            return error.IoRangeOutOfBounds;
        }
    }
};

pub const Error = public_data_v2.Error || error{
    IncompleteIoCoverage,
    InputDigestMismatch,
    InputMemoryMismatch,
    IoRangeOutOfBounds,
    MixedIoCampaign,
    DiscontinuousIoCampaign,
    NonZeroPublicIoState,
    OutputDigestMismatch,
    OutputLengthMismatch,
    OutputMemoryMismatch,
    RunnerIoMismatch,
};

/// One verified leaf covers only the edge memory it actually owns. The
/// remaining fields let a caller reject endpoints borrowed from another job.
pub const Coverage = struct {
    input: bool,
    output: bool,
    session_id: Digest,
    job_id: Digest,
    input_digest: Digest,
    output_digest: Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u32,
    global_cycle_end: u32,
};

/// Requires every leaf in one ordered V2 campaign exactly once. These values
/// must originate from validated verifier captures; this host-side check is
/// not itself a recursive proof of the leaf chain.
pub fn requireComplete(coverages: []const Coverage) Error!void {
    if (coverages.len == 0) return error.IncompleteIoCoverage;
    const first = coverages[0];
    const count = std.math.cast(u32, coverages.len) orelse return error.IncompleteIoCoverage;
    if (first.segment_count != count) return error.IncompleteIoCoverage;
    var previous_end: u32 = 0;
    for (coverages, 0..) |coverage, index| {
        if (!std.meta.eql(coverage.session_id, first.session_id) or
            !std.meta.eql(coverage.job_id, first.job_id) or
            !std.meta.eql(coverage.input_digest, first.input_digest) or
            !std.meta.eql(coverage.output_digest, first.output_digest) or
            coverage.segment_count != first.segment_count)
            return error.MixedIoCampaign;
        if (coverage.segment_index != @as(u32, @intCast(index)) or
            coverage.input != (index == 0) or
            coverage.output != (index + 1 == coverages.len) or
            (index == 0 and coverage.global_cycle_start != 0) or
            (index != 0 and coverage.global_cycle_start != previous_end) or
            coverage.global_cycle_end <= coverage.global_cycle_start)
            return error.DiscontinuousIoCampaign;
        previous_end = coverage.global_cycle_end;
    }
}

pub fn inputDigest(expected: Expected) Error!Digest {
    try expected.validate();
    var hasher = segment_contract.IdentityHasher.init(INPUT_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(expected.input_start);
    hasher.u32Value(@intCast(expected.input.len));
    hashBytes(&hasher, expected.input);
    return hasher.finalize();
}

pub fn outputDigest(expected: Expected) Error!Digest {
    try expected.validate();
    var hasher = segment_contract.IdentityHasher.init(OUTPUT_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(expected.output_len_addr);
    hasher.u32Value(expected.output_data_addr);
    hasher.u32Value(@intCast(expected.output.len));
    hashBytes(&hasher, expected.output);
    return hasher.finalize();
}

/// Call only on a proof verifier's successfully minted capture. The capture
/// revalidates its proof-side authority before the I/O claim is inspected.
pub fn validateVerifiedCapture(
    comptime Engine: type,
    capture: *const @import("../prover/verifier.zig").VerifiedSegmentV2CaptureForEngine(Engine),
    expected: Expected,
) !Coverage {
    try capture.validate();
    return validateAuthenticatedWire(&capture.public_data.data, expected);
}

/// Checks a canonical wire's claims and sparse memory against external I/O.
/// Authentication alone is not proof verification; proof consumers should use
/// `validateVerifiedCapture` after native AIR, PCS, Merkle and FRI success.
pub fn validateAuthenticatedWire(
    data: *const public_data_v2.PublicDataV2,
    expected: Expected,
) Error!Coverage {
    try expected.validate();
    const view = try data.authenticatedView();
    const base = try view.statement.base();
    const executed = switch (base.body) {
        .executed => |value| value,
        .empty => return error.SegmentLeafRequired,
    };
    const zero: Digest = .{0} ** 8;
    for ([_]span.MachineState{
        base.job.complete.initial_state,
        base.job.complete.final_state,
        executed.entry,
        executed.exit,
    }) |state| {
        if (!std.meta.eql(state.public_io_state, zero))
            return error.NonZeroPublicIoState;
    }
    if (!std.meta.eql(base.job.complete.public_input, try inputDigest(expected)))
        return error.InputDigestMismatch;
    if (!std.meta.eql(base.job.complete.public_output, try outputDigest(expected)))
        return error.OutputDigestMismatch;

    const is_first = executed.first_segment == 0;
    const is_final = executed.endSegment() == base.job.segment_count;
    if (is_first) {
        for (expected.input, 0..) |byte, index| {
            const address = expected.input_start + @as(u32, @intCast(index));
            if (sparseByte(&view, view.entry_snapshot, address) != byte)
                return error.InputMemoryMismatch;
        }
    }
    if (is_final) {
        if (sparseWord(&view, view.exit_snapshot, expected.output_len_addr) != @as(u32, @intCast(expected.output.len)))
            return error.OutputLengthMismatch;
        for (expected.output, 0..) |byte, index| {
            const address = expected.output_data_addr + @as(u32, @intCast(index));
            if (sparseByte(&view, view.exit_snapshot, address) != byte)
                return error.OutputMemoryMismatch;
        }
    }
    const metadata = try data.metadata();
    return .{
        .input = is_first,
        .output = is_final,
        .session_id = metadata.session_id,
        .job_id = metadata.job_id,
        .input_digest = base.job.complete.public_input,
        .output_digest = base.job.complete.public_output,
        .segment_index = metadata.segment_index,
        .segment_count = metadata.segment_count,
        .global_cycle_start = metadata.global_cycle_start,
        .global_cycle_end = metadata.global_cycle_end,
    };
}

/// Native construction guard: the external I/O must match the runner result.
/// The verifier-side sparse checks above remain required for proof acceptance.
pub fn validateRunner(result: *const runner_result.SegmentResult, expected: Expected) Error!void {
    try expected.validate();
    if (result.input_start != expected.input_start or
        result.output_len_addr != expected.output_len_addr or
        result.output_data_addr != expected.output_data_addr)
    {
        return error.RunnerIoMismatch;
    }
    if (result.segment_role.is_first and
        !std.mem.eql(u8, result.input orelse return error.RunnerIoMismatch, expected.input))
    {
        return error.RunnerIoMismatch;
    }
    if (result.segment_role.is_last and
        (result.output_len != @as(u32, @intCast(expected.output.len)) or
            !std.mem.eql(u8, result.output orelse &.{}, expected.output)))
    {
        return error.RunnerIoMismatch;
    }
}

fn hashBytes(hasher: *segment_contract.IdentityHasher, bytes: []const u8) void {
    var index: usize = 0;
    while (index < bytes.len) : (index += 4) {
        var word: u32 = 0;
        for (bytes[index..@min(index + 4, bytes.len)], 0..) |byte, shift| {
            word |= @as(u32, byte) << @as(u5, @intCast(shift * 8));
        }
        hasher.u32Value(word);
    }
}

fn sparseByte(view: *const segment_v2.CanonicalWireViewV2, section: segment_v2.RetainedSectionV2, address: u32) u8 {
    const word = sparseWord(view, section, address & ~@as(u32, 3));
    return @truncate(word >> @as(u5, @intCast((address & 3) * 8)));
}

fn sparseWord(view: *const segment_v2.CanonicalWireViewV2, section: segment_v2.RetainedSectionV2, address: u32) u32 {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const item = view.sparseEntry(section, mid);
        if (item.address < address) {
            low = mid + 1;
        } else if (item.address > address) {
            high = mid;
        } else {
            return item.value;
        }
    }
    return 0;
}
