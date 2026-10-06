//! Opt-in public-I/O admission boundary for native segments and verified leaves.
//!
//! The verifier supplies the ABI and bytes from its own request/expected
//! result, never from a candidate statement, edge claim, or proof artifact.
//! They are copied before admission so a mutable request buffer cannot change
//! the expectation between leaves. This is a host-side gate, not an AIR proof
//! that the VM performed the I/O. V2 verification semantics remain unchanged.
//! Before V3 publication, a versioned proof-visible relation must connect the
//! verified VM's input/output operations and output-length word to these exact
//! bytes, their addresses, the public-I/O state transition, and the recursive
//! statement/edge digests. Merely hashing a caller-supplied wire is insufficient.

const std = @import("std");
const binding = @import("segment_public_io_binding_v1.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const span = @import("span_statement.zig");
const runner_result = @import("../runner/result.zig");
const verifier = @import("../prover/verifier.zig");
const prover_types = @import("../prover/types.zig");
const pcs = @import("stwo_core").pcs;
const statement_v2 = @import("../air/statement_v2.zig");

pub const NATIVE_ADMISSION_AVAILABLE = true;
pub const RECURSIVE_PROOF_ACTIVATION = false;
pub const PROOF_VISIBLE_IO_RELATION = false;

/// Owned expectation established outside the candidate's proof/statement.
/// Its constructor deliberately takes bytes and ABI, not advertised digests.
pub const VerifierExpectedIo = struct {
    allocator: std.mem.Allocator,
    input_start: u32,
    input: []u8,
    output_len_addr: u32,
    output_data_addr: u32,
    output: []u8,

    pub fn initOwned(allocator: std.mem.Allocator, external: binding.Expected) !VerifierExpectedIo {
        try external.validate();
        const input = try allocator.dupe(u8, external.input);
        errdefer allocator.free(input);
        const output = try allocator.dupe(u8, external.output);
        return .{
            .allocator = allocator,
            .input_start = external.input_start,
            .input = input,
            .output_len_addr = external.output_len_addr,
            .output_data_addr = external.output_data_addr,
            .output = output,
        };
    }

    pub fn deinit(self: *VerifierExpectedIo) void {
        self.allocator.free(self.input);
        self.allocator.free(self.output);
        self.* = undefined;
    }

    fn expected(self: *const VerifierExpectedIo) binding.Expected {
        return .{
            .input_start = self.input_start,
            .input = self.input,
            .output_len_addr = self.output_len_addr,
            .output_data_addr = self.output_data_addr,
            .output = self.output,
        };
    }

    /// Native construction guard. Rejects a result/statement that differs
    /// from verifier-owned bytes or that advertises arbitrary I/O edge state.
    pub fn admitNativeSource(
        self: *const VerifierExpectedIo,
        session_id: segment_v2.Digest,
        statement: span.SpanStatement,
        result: *const runner_result.SegmentResult,
    ) !segment_v2.SourceV2 {
        try binding.validateRunner(result, self.expected());
        try self.validateStatement(&statement);
        const source = try segment_v2.SourceV2.fromSegmentResult(session_id, statement, result);
        try self.validateRunnerMemory(result);
        return source;
    }

    /// A recursive ingress guard must receive the capture minted by a fresh
    /// native verifier transaction. A detached Coverage record is insufficient.
    pub fn admitVerifiedCapture(
        self: *const VerifierExpectedIo,
        comptime Engine: type,
        capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine),
    ) !binding.Coverage {
        return binding.validateVerifiedCapture(Engine, capture, self.expected());
    }

    /// Fresh proof-verification entrypoint. `proof_in` is consumed by the
    /// native verifier. The capture is published only after both proof
    /// verification and independent public-I/O admission succeed; the caller
    /// owns and must deinit it on success.
    pub fn verifyAndAdmitLeafIntoCapture(
        self: *const VerifierExpectedIo,
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs.PcsConfig,
        statement: statement_v2.RiscVStatementV2,
        proof_in: prover_types.ProofForEngine(Engine),
        claim: *const prover_types.RiscVInteractionClaim,
        capture_out: *verifier.VerifiedSegmentV2CaptureForEngine(Engine),
    ) !binding.Coverage {
        var channel = Engine.Channel{};
        var verified: verifier.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
        try verifier.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
            Engine,
            allocator,
            pcs_config,
            statement,
            proof_in,
            claim,
            &channel,
            &verified,
        );
        errdefer verified.deinit(allocator);
        const coverage = try self.admitVerifiedCapture(Engine, &verified);
        capture_out.* = verified;
        return coverage;
    }

    /// Revalidates every capture against the same independent expectation,
    /// then checks exact order and complete campaign coverage. No caller-owned
    /// Coverage values are accepted as recursive ingress authority.
    pub fn admitVerifiedCampaign(
        self: *const VerifierExpectedIo,
        comptime Engine: type,
        allocator: std.mem.Allocator,
        captures: []const *const verifier.VerifiedSegmentV2CaptureForEngine(Engine),
    ) !void {
        if (captures.len == 0) return error.IncompleteIoCoverage;
        const coverages = try allocator.alloc(binding.Coverage, captures.len);
        defer allocator.free(coverages);
        for (captures, coverages) |capture, *coverage| {
            coverage.* = try self.admitVerifiedCapture(Engine, capture);
        }
        try binding.requireComplete(coverages);
    }

    /// Diagnostic wire gate for tests and ingestion audits. Authentication
    /// of a wire does not replace fresh native proof verification.
    pub fn inspectAuthenticatedWire(
        self: *const VerifierExpectedIo,
        data: *const @import("../air/public_data_v2.zig").PublicDataV2,
    ) !binding.Coverage {
        return binding.validateAuthenticatedWire(data, self.expected());
    }

    fn validateStatement(self: *const VerifierExpectedIo, statement: *const span.SpanStatement) !void {
        try statement.validate();
        const base = statement.*;
        const executed = switch (base.body) {
            .executed => |value| value,
            .empty => return error.SegmentLeafRequired,
        };
        const zero: span.Digest = .{0} ** 8;
        for ([_]span.MachineState{
            base.job.complete.initial_state,
            base.job.complete.final_state,
            executed.entry,
            executed.exit,
        }) |state| {
            if (!std.meta.eql(state.public_io_state, zero)) return error.NonZeroPublicIoState;
        }
        if (!std.meta.eql(base.job.complete.public_input, try binding.inputDigest(self.expected())))
            return error.InputDigestMismatch;
        if (!std.meta.eql(base.job.complete.public_output, try binding.outputDigest(self.expected())))
            return error.OutputDigestMismatch;
    }

    fn validateRunnerMemory(self: *const VerifierExpectedIo, result: *const runner_result.SegmentResult) !void {
        if (result.segment_role.is_first) {
            for (self.input, 0..) |byte, index| {
                const address = self.input_start + @as(u32, @intCast(index));
                if (runnerByte(result, .initial_word, address) != byte)
                    return error.InputMemoryMismatch;
            }
        }
        if (result.segment_role.is_last) {
            if (runnerWord(result, .final_word, self.output_len_addr) != @as(u32, @intCast(self.output.len)))
                return error.OutputLengthMismatch;
            for (self.output, 0..) |byte, index| {
                const address = self.output_data_addr + @as(u32, @intCast(index));
                if (runnerByte(result, .final_word, address) != byte)
                    return error.OutputMemoryMismatch;
            }
        }
    }
};

const BoundarySide = enum { initial_word, final_word };

fn runnerByte(result: *const runner_result.SegmentResult, comptime side: BoundarySide, address: u32) u8 {
    const word = runnerWord(result, side, address & ~@as(u32, 3));
    return @truncate(word >> @as(u5, @intCast((address & 3) * 8)));
}

fn runnerWord(result: *const runner_result.SegmentResult, comptime side: BoundarySide, address: u32) u32 {
    const words = result.rw_memory.words;
    var low: usize = 0;
    var high: usize = words.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const word = words[mid];
        if (word.addr < address) {
            low = mid + 1;
        } else if (word.addr > address) {
            high = mid;
        } else {
            return @field(word, @tagName(side));
        }
    }
    return 0;
}
