//! Internal span statement authority shard; use span_statement.zig publicly.

const dependency_0 = @import("span_statement_executed_span.zig").Contract(false);

const CompleteExecution = dependency_0.CompleteExecution;
const Digest = dependency_0.Digest;

const EdgeClaim = dependency_0.EdgeClaim;
const Error = dependency_0.Error;
const ExecutedSpan = dependency_0.ExecutedSpan;
const JobContext = dependency_0.JobContext;
const MachineState = dependency_0.MachineState;

const StatementWords = dependency_0.StatementWords;

const m31 = dependency_0.m31;

const protocol = dependency_0.protocol;
const public_data_mod = dependency_0.public_data_mod;

const std = dependency_0.std;

const vm_claim = dependency_0.vm_claim;

const semantics = @import("span_statement_semantics.zig").Semantics(dependency_0);
pub const SpanStatement = semantics.SpanStatement;
pub const RootStatement = semantics.RootStatement;
pub const isIntegerWord = semantics.isIntegerWord;

/// Allocation-free production result for a complete one-segment VM proof.
pub const SegmentLeaf = struct {
    root: RootStatement,
    words: StatementWords,

    pub fn init(
        data: *const public_data_mod.PublicData,
        claim: *const vm_claim.Encoded,
        protocol_id: Digest,
    ) Error!SegmentLeaf {
        try claim.validateAgainst(data);
        if (!std.meta.eql(protocol_id, protocol.protocolId())) return error.DigestMismatch;
        const initial_rw = data.initial_rw_root orelse return error.InitialRwRootMissing;
        const final_rw = data.final_rw_root orelse return error.FinalRwRootMissing;
        const program = try expandRoot(data.program_root orelse unreachable);
        const zero = [_]u32{0} ** 8;
        const initial = try MachineState.init(
            data.initial_pc,
            data.initial_regs,
            try expandRoot(initial_rw),
            zero,
        );
        const final = try MachineState.init(
            data.final_pc,
            data.final_regs,
            try expandRoot(final_rw),
            zero,
        );
        const complete = try CompleteExecution.init(
            protocol_id,
            program,
            initial,
            final,
            claim.public_input_digest,
            claim.public_output_digest,
            data.clock,
        );
        const job = try JobContext.init(complete, 1);
        const executed = try ExecutedSpan.init(
            0,
            1,
            0,
            data.clock,
            initial,
            final,
            try EdgeClaim.present(claim.public_input_digest),
            try EdgeClaim.present(claim.public_output_digest),
        );
        const statement = try SpanStatement.segmentLeaf(job, 0, executed);
        const root = try RootStatement.init(statement);
        return .{ .root = root, .words = try statement.canonicalWords() };
    }

    pub fn validateAgainst(
        self: SegmentLeaf,
        data: *const public_data_mod.PublicData,
        claim: *const vm_claim.Encoded,
    ) Error!void {
        const expected = try SegmentLeaf.init(data, claim, protocol.protocolId());
        if (!std.meta.eql(expected, self)) return error.DigestMismatch;
    }
};

pub fn expandRoot(root: u32) Error!Digest {
    if (root >= m31.Modulus) return error.NonCanonicalDigest;
    var digest = [_]u32{0} ** 8;
    digest[0] = root;
    return digest;
}
