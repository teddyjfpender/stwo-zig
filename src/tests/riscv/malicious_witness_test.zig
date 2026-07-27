//! CP-12 malicious-witness rejection matrix for the RISC-V verifier.
//!
//! One honest ELF execution is proven once; the proof is serialized through
//! the postcard wire and re-decoded for every adversarial attempt so a single
//! prove backs the whole matrix. An untampered decoded clone must verify,
//! proving that later rejections come from the mutation and not from
//! proof-encoding drift. Every claim family in `RiscVInteractionClaim` and
//! every statement field the public boundary sums depend on is then mutated
//! individually, and `verifyRiscV` must reject each mutation.

const std = @import("std");
const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");
const prover = @import("../../frontends/riscv/prover.zig");
const postcard = @import("../../interop/postcard.zig");
const runner_mod = @import("../../frontends/riscv/runner/mod.zig");
const release_elf_fixture = @import("release_elf_fixture.zig");
const public_data_mod = @import("../../frontends/riscv/air/public_data.zig");
const access_clock = @import("../../frontends/riscv/access_clock.zig");
const clock_update_interaction = @import("../../frontends/riscv/air/clock_update_interaction.zig");
const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const merkle_node = @import("../../frontends/riscv/air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../frontends/riscv/air/memory_commitment/poseidon2_air.zig");
const transcript = @import("../../frontends/riscv/air/transcript/mod.zig");
const pcs_core = @import("stwo_core").pcs;
const qm31 = @import("stwo_core").fields.qm31;

const QM31 = qm31.QM31;

const TEST_PCS_CONFIG = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

fn bump(value: QM31) QM31 {
    return value.add(QM31.one());
}

/// One prove, many verify attempts: every attempt decodes a fresh proof from
/// the shared wire bytes because `verifyRiscV` consumes the proof it is given.
const RejectionMatrix = struct {
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    proof_bytes: []const u8,
    tree0_root: prover.Hasher.Hash,
    tree1_root: prover.Hasher.Hash,
    statement: prover.RiscVStatement,
    claim: prover.RiscVInteractionClaim,
    rejected: usize = 0,
    pow_rejected: usize = 0,
    logup_rejected: usize = 0,
    bound_pow_classified: usize = 0,
    bound_logup_classified: usize = 0,

    fn cloneProof(self: *const RejectionMatrix) !prover.Proof {
        var stream = std.io.fixedBufferStream(self.proof_bytes);
        return postcard.deserializeProof(prover.Hasher, self.allocator, stream.reader());
    }

    /// Most shape-preserving statement mutations invalidate the interaction
    /// nonce. A fixed 10-bit nonce can occasionally remain valid after a
    /// mutation; in that exact case verification advances to relation closure.
    fn expectedBoundRejection(
        self: *RejectionMatrix,
        statement: prover.RiscVStatement,
    ) anyerror {
        var channel = riscv_cpu.CpuProverEngine.Channel{};
        self.config.mixInto(&channel);
        statement.public_data.mixInto(&channel);
        riscv_cpu.CpuProverEngine.MerkleChannel.mixRoot(&channel, self.tree0_root);
        riscv_cpu.CpuProverEngine.MerkleChannel.mixRoot(&channel, self.tree1_root);
        const main_claim = statement.canonicalMainClaim();
        main_claim.mixInto(&channel);
        statement.mixShardManifest(&channel);
        if (channel.verifyPowNonce(transcript.INTERACTION_POW_BITS, self.claim.interaction_pow)) {
            self.bound_logup_classified += 1;
            return error.LogupSumNonZero;
        }
        self.bound_pow_classified += 1;
        return error.InvalidInteractionProofOfWork;
    }

    fn expectRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        sub: usize,
        expected_error: anyerror,
        statement: prover.RiscVStatement,
        claim: prover.RiscVInteractionClaim,
    ) !void {
        const proof = try self.cloneProof();
        const result = riscv_cpu.verifyRiscV(self.allocator, self.config, statement, proof, &claim);
        if (result) |_| {
            std.debug.print("forged {s}[{d}][{d}] was accepted\n", .{ label, index, sub });
            return error.ForgedWitnessAccepted;
        } else |actual_error| {
            if (actual_error != expected_error) {
                std.debug.print(
                    "forged {s}[{d}][{d}] rejected as {s}, expected {s}\n",
                    .{ label, index, sub, @errorName(actual_error), @errorName(expected_error) },
                );
                return error.UnexpectedRejectionClass;
            }
            switch (actual_error) {
                error.InvalidInteractionProofOfWork => self.pow_rejected += 1,
                error.LogupSumNonZero => self.logup_rejected += 1,
                else => {},
            }
        }
        self.rejected += 1;
    }

    fn expectClaimRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        sub: usize,
        expected_error: anyerror,
        claim: prover.RiscVInteractionClaim,
    ) !void {
        try self.expectRejected(label, index, sub, expected_error, self.statement, claim);
    }

    fn expectStatementRejected(
        self: *RejectionMatrix,
        label: []const u8,
        index: usize,
        expected_error: anyerror,
        statement: prover.RiscVStatement,
    ) !void {
        try self.expectRejected(label, index, 0, expected_error, statement, self.claim);
    }
};

test "riscv prover: malicious-witness matrix rejects every claim and boundary mutation" {
    const alloc = std.testing.allocator;
    const elf_buf = try release_elf_fixture.buildPublicIoHaltElf(alloc);
    defer alloc.free(elf_buf);

    const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var run_result = try runner_mod.runWithInput(alloc, elf_buf, &input, 1000);
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u32, 4), run_result.output_len);
    try std.testing.expectEqual(@as(usize, 2), run_result.output_words.len);
    try std.testing.expectEqual(@as(u32, 0x0403_0201), run_result.output_words[1].value);
    try std.testing.expectEqual(@as(usize, 10), run_result.step_count);
    try std.testing.expectEqual(runner_mod.CompletionReason.halt_flag, run_result.completion_reason);

    const input_words = try public_data_mod.packInputWords(alloc, &input);
    defer alloc.free(input_words);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x0403_0201, 0x0807_0605, 0x0000_0009 },
        input_words,
    );
    const output_words = try alloc.alloc(public_data_mod.OutputWord, run_result.output_words.len);
    defer alloc.free(output_words);
    for (run_result.output_words, 0..) |word, i| output_words[i] = .{
        .addr = word.addr,
        .value = word.value,
        .clock = word.clock,
    };

    var output = try riscv_cpu.proveRiscVWithPublicData(
        alloc,
        TEST_PCS_CONFIG,
        &run_result.execution_trace,
        &run_result.state_chain_tracker,
        &run_result.rw_memory,
        null,
        .{
            .initial_pc = run_result.initial_pc,
            .final_pc = run_result.final_pc,
            .clock = @intCast(run_result.step_count),
            .initial_regs = run_result.initial_regs,
            .final_regs = run_result.final_regs,
            .reg_last_clock = run_result.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = try public_data_mod.completionFromRun(run_result),
            .io_entries = .{
                .input_start = run_result.input_start,
                .input_len = @intCast(run_result.input.len),
                .input_words = input_words,
                .output_len = run_result.output_len,
                .output_len_addr = run_result.output_len_addr,
                .output_data_addr = run_result.output_data_addr,
                .output_words = output_words,
            },
        },
    );
    defer output.deinit(alloc);

    var proof_bytes: std.ArrayList(u8) = .{};
    defer proof_bytes.deinit(alloc);
    try postcard.serializeProof(prover.Hasher, proof_bytes.writer(alloc), output.proof);

    var matrix = RejectionMatrix{
        .allocator = alloc,
        .config = TEST_PCS_CONFIG,
        .proof_bytes = proof_bytes.items,
        .tree0_root = output.proof.commitment_scheme_proof.commitments.items[0],
        .tree1_root = output.proof.commitment_scheme_proof.commitments.items[1],
        .statement = output.statement,
        .claim = output.interaction_claim.*,
    };

    // Baseline: an untampered decoded clone must verify, so every rejection
    // below is attributable to its mutation rather than to encoding drift.
    try riscv_cpu.verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        matrix.statement,
        try matrix.cloneProof(),
        &matrix.claim,
    );

    const n_components: usize = matrix.claim.n_components;
    try std.testing.expect(n_components >= 3);

    // -- Interaction-claim families: per-component LogUp sums. --
    var n_opcode_claims: usize = 0;
    for (0..n_components) |i| {
        const family = matrix.statement.component_descs[i].family;
        n_opcode_claims += opcode_entries.batchCount(family);
        for (0..opcode_entries.batchCount(family)) |j| {
            var claim = matrix.claim;
            claim.opcode_claims[i][j] = bump(claim.opcode_claims[i][j]);
            try matrix.expectClaimRejected(
                "opcode_claims",
                i,
                j,
                error.LogupSumNonZero,
                claim,
            );
        }
    }

    // -- Interaction-claim families: exact infrastructure sums. --
    for (0..matrix.claim.program_claims[0].len) |j| {
        var claim = matrix.claim;
        claim.program_claims[0][j] = bump(claim.program_claims[0][j]);
        try matrix.expectClaimRejected("program_claims", 0, j, error.LogupSumNonZero, claim);
    }
    var n_memory_infra: usize = 0;
    for (0..matrix.statement.n_infra) |i| {
        if (matrix.statement.infra_descs[i].kind != .memory) continue;
        n_memory_infra += 1;
        for (0..matrix.claim.memory_claims[i].len) |j| {
            var claim = matrix.claim;
            claim.memory_claims[i][j] = bump(claim.memory_claims[i][j]);
            try matrix.expectClaimRejected("memory_claims", i, j, error.LogupSumNonZero, claim);
        }
    }
    try std.testing.expect(n_memory_infra >= 1);
    var n_merkle_infra: usize = 0;
    var n_poseidon_infra: usize = 0;
    var n_clock_infra: usize = 0;
    var n_lookup_infra: usize = 0;
    for (0..matrix.statement.n_infra) |i| {
        switch (matrix.statement.infra_descs[i].kind) {
            .merkle => {
                n_merkle_infra += 1;
                for (0..merkle_node.N_SUMS) |j| {
                    var claim = matrix.claim;
                    claim.merkle_claims[i][j] = bump(claim.merkle_claims[i][j]);
                    try matrix.expectClaimRejected(
                        "merkle_claims",
                        i,
                        j,
                        error.LogupSumNonZero,
                        claim,
                    );
                }
            },
            .poseidon2 => {
                n_poseidon_infra += 1;
                for (0..poseidon2_air.N_SUMS) |j| {
                    var claim = matrix.claim;
                    claim.poseidon_claims[i][j] = bump(claim.poseidon_claims[i][j]);
                    try matrix.expectClaimRejected(
                        "poseidon_claims",
                        i,
                        j,
                        error.LogupSumNonZero,
                        claim,
                    );
                }
            },
            .clock_update => {
                n_clock_infra += 1;
                for (0..clock_update_interaction.N_SUMS) |j| {
                    var claim = matrix.claim;
                    claim.clock_claims[i][j] = bump(claim.clock_claims[i][j]);
                    try matrix.expectClaimRejected(
                        "clock_claims",
                        i,
                        j,
                        error.LogupSumNonZero,
                        claim,
                    );
                }
            },
            .bitwise,
            .range_check_20,
            .range_check_8_11,
            .range_check_8_8_4,
            .range_check_8_8,
            .range_check_m31,
            => {
                n_lookup_infra += 1;
                var claim = matrix.claim;
                claim.lookup_claims[i] = bump(claim.lookup_claims[i]);
                try matrix.expectClaimRejected(
                    "lookup_claims",
                    i,
                    0,
                    error.LogupSumNonZero,
                    claim,
                );
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 1), n_merkle_infra);
    try std.testing.expectEqual(@as(usize, 1), n_poseidon_infra);
    try std.testing.expectEqual(@as(usize, 1), n_clock_infra);

    // -- Interaction-claim envelope: PoW nonce and component count. --
    {
        var claim = matrix.claim;
        claim.interaction_pow +%= 1;
        try matrix.expectClaimRejected(
            "interaction_pow",
            0,
            0,
            error.InvalidInteractionProofOfWork,
            claim,
        );
    }
    {
        var claim = matrix.claim;
        claim.n_components += 1;
        try matrix.expectClaimRejected(
            "claim.n_components",
            0,
            0,
            error.InvalidInteractionClaim,
            claim,
        );
    }
    {
        var claim = matrix.claim;
        claim.n_infra += 1;
        try matrix.expectClaimRejected(
            "claim.n_infra",
            0,
            0,
            error.InvalidInteractionClaim,
            claim,
        );
    }

    // -- Statement PC/step boundary fields. Lone mutations must fail the
    // statement/public-data consistency check; coordinated PC mutations
    // survive shape validation but fail the exact bound proof prefix. --
    {
        var statement = matrix.statement;
        statement.initial_pc +%= 4;
        try matrix.expectStatementRejected(
            "initial_pc (statement only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement = matrix.statement;
        statement.public_data.initial_pc +%= 4;
        try matrix.expectStatementRejected(
            "initial_pc (public only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement.initial_pc +%= 4;
        statement.public_data.initial_pc = statement.initial_pc;
        try matrix.expectStatementRejected(
            "initial_pc (coordinated)",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.final_pc +%= 4;
        try matrix.expectStatementRejected(
            "final_pc (statement only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement = matrix.statement;
        statement.public_data.final_pc +%= 4;
        try matrix.expectStatementRejected(
            "final_pc (public only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement.final_pc +%= 4;
        statement.public_data.final_pc = statement.final_pc;
        try matrix.expectStatementRejected(
            "final_pc (coordinated)",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.total_steps +%= 1;
        try matrix.expectStatementRejected(
            "total_steps (statement only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement = matrix.statement;
        statement.public_data.clock +%= 1;
        try matrix.expectStatementRejected(
            "clock (public only)",
            0,
            error.InvalidStatement,
            statement,
        );
        statement.total_steps +%= 1;
        statement.public_data.clock = statement.total_steps;
        try matrix.expectStatementRejected(
            "total_steps (coordinated)",
            0,
            error.InvalidStatement,
            statement,
        );
    }

    // -- Every register value and access clock feeding memory-access closure. --
    for (0..matrix.statement.public_data.initial_regs.len) |r| {
        var statement = matrix.statement;
        statement.public_data.initial_regs[r] +%= 1;
        const expected_error = if (r == 0)
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(statement);
        try matrix.expectStatementRejected(
            "initial_regs",
            r,
            expected_error,
            statement,
        );
    }
    for (0..matrix.statement.public_data.final_regs.len) |r| {
        var statement = matrix.statement;
        statement.public_data.final_regs[r] +%= 1;
        const expected_error = if (r == 0)
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(statement);
        try matrix.expectStatementRejected(
            "final_regs",
            r,
            expected_error,
            statement,
        );
    }
    for (0..matrix.statement.public_data.reg_last_clock.len) |r| {
        var statement = matrix.statement;
        statement.public_data.reg_last_clock[r] +%= 1;
        const expected_error = if (!access_clock.isWithinExecution(
            statement.public_data.reg_last_clock[r],
            statement.total_steps,
            true,
        ))
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(statement);
        try matrix.expectStatementRejected("reg_last_clock", r, expected_error, statement);
    }

    // -- Every optional root is bound by both value and presence. The release
    // proof has all three roots because it is a single, unsegmented execution. --
    try std.testing.expect(matrix.statement.public_data.program_root != null);
    try std.testing.expect(matrix.statement.public_data.initial_rw_root != null);
    try std.testing.expect(matrix.statement.public_data.final_rw_root != null);
    {
        var statement = matrix.statement;
        statement.public_data.program_root.? +%= 1;
        try matrix.expectStatementRejected(
            "program_root value",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        statement = matrix.statement;
        statement.public_data.program_root = null;
        try matrix.expectStatementRejected(
            "program_root presence",
            0,
            error.InvalidStatement,
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.initial_rw_root.? +%= 1;
        try matrix.expectStatementRejected(
            "initial_rw_root value",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        statement = matrix.statement;
        statement.public_data.initial_rw_root = null;
        try matrix.expectStatementRejected(
            "initial_rw_root presence",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.final_rw_root.? +%= 1;
        try matrix.expectStatementRejected(
            "final_rw_root value",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        statement = matrix.statement;
        statement.public_data.final_rw_root = null;
        try matrix.expectStatementRejected(
            "final_rw_root presence",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }

    // -- Completion presence, kind, and every relation tuple field. --
    {
        var statement = matrix.statement;
        statement.public_data.completion = null;
        try matrix.expectStatementRejected(
            "completion presence",
            0,
            error.InvalidStatement,
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.completion.?.address +%= 4;
        try matrix.expectStatementRejected(
            "completion address",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.completion.?.value +%= 1;
        try matrix.expectStatementRejected(
            "completion value",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.completion.?.clock -%= 1;
        const expected_error = if (!access_clock.isWithinExecution(
            statement.public_data.completion.?.clock,
            statement.total_steps,
            false,
        ))
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(statement);
        try matrix.expectStatementRejected(
            "completion clock",
            0,
            expected_error,
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.completion =
            public_data_mod.Completion.canonicalSelfLoop(statement.final_pc);
        try matrix.expectStatementRejected(
            "completion kind and tuple",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }

    // -- Public input metadata, every word, ordering, count, and final-word
    // padding. Slice mutations are restored before the next verifier attempt. --
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.input_start +%= 4;
        try matrix.expectStatementRejected(
            "input_start",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.input_len += 1;
        try matrix.expectStatementRejected(
            "input_len",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
    }
    for (input_words, 0..) |*word, k| {
        const original = word.*;
        word.* +%= 1;
        try matrix.expectStatementRejected(
            "input word value",
            k,
            matrix.expectedBoundRejection(matrix.statement),
            matrix.statement,
        );
        word.* = original;
    }
    std.mem.swap(u32, &input_words[0], &input_words[1]);
    try matrix.expectStatementRejected(
        "input word order",
        0,
        matrix.expectedBoundRejection(matrix.statement),
        matrix.statement,
    );
    std.mem.swap(u32, &input_words[0], &input_words[1]);
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.input_words = input_words[0 .. input_words.len - 1];
        try matrix.expectStatementRejected(
            "input word count (short)",
            0,
            error.InvalidStatement,
            statement,
        );
    }
    {
        var extended: [4]u32 = undefined;
        @memcpy(extended[0..input_words.len], input_words);
        extended[input_words.len] = 0;
        var statement = matrix.statement;
        statement.public_data.io_entries.input_words = &extended;
        try matrix.expectStatementRejected(
            "input word count (long)",
            0,
            error.InvalidStatement,
            statement,
        );
    }
    {
        const final_index = input_words.len - 1;
        const original = input_words[final_index];
        input_words[final_index] |= 0x0000_0100;
        try matrix.expectStatementRejected(
            "input word padding",
            final_index,
            error.InvalidStatement,
            matrix.statement,
        );
        input_words[final_index] = original;
    }

    // -- Public output metadata and every output-word field. Shape-preserving
    // coordinated mutations prove that each metadata value reaches the proof
    // transcript, while malformed lone mutations exercise strict validation. --
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.output_len_addr +%= 0x100;
        try matrix.expectStatementRejected(
            "output_len_addr (lone)",
            0,
            error.InvalidStatement,
            statement,
        );
        const original = output_words[0];
        output_words[0].addr = statement.public_data.io_entries.output_len_addr;
        try matrix.expectStatementRejected(
            "output_len_addr (coordinated)",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        output_words[0] = original;
    }
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.output_data_addr +%= 0x100;
        try matrix.expectStatementRejected(
            "output_data_addr (lone)",
            0,
            error.InvalidStatement,
            statement,
        );
        const original = output_words[1];
        output_words[1].addr = statement.public_data.io_entries.output_data_addr;
        try matrix.expectStatementRejected(
            "output_data_addr (coordinated)",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        output_words[1] = original;
    }
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.output_len -%= 1;
        try matrix.expectStatementRejected(
            "output_len (lone)",
            0,
            error.InvalidStatement,
            statement,
        );
        const original = output_words[0];
        output_words[0].value = statement.public_data.io_entries.output_len;
        try matrix.expectStatementRejected(
            "output_len (coordinated)",
            0,
            matrix.expectedBoundRejection(statement),
            statement,
        );
        output_words[0] = original;
    }
    for (output_words, 0..) |*word, k| {
        const original = word.*;
        word.value +%= 1;
        const expected_value_error = if (k == 0)
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(matrix.statement);
        try matrix.expectStatementRejected(
            "output word value",
            k,
            expected_value_error,
            matrix.statement,
        );
        word.* = original;
        word.clock +%= 1;
        const expected_clock_error = if (!access_clock.isWithinExecution(
            word.clock,
            matrix.statement.total_steps,
            false,
        ))
            error.InvalidStatement
        else
            matrix.expectedBoundRejection(matrix.statement);
        try matrix.expectStatementRejected(
            "output word clock",
            k,
            expected_clock_error,
            matrix.statement,
        );
        word.* = original;
        word.addr +%= 4;
        try matrix.expectStatementRejected(
            "output word addr",
            k,
            error.InvalidStatement,
            matrix.statement,
        );
        word.* = original;
    }
    std.mem.swap(public_data_mod.OutputWord, &output_words[0], &output_words[1]);
    try matrix.expectStatementRejected(
        "output word order",
        0,
        error.InvalidStatement,
        matrix.statement,
    );
    std.mem.swap(public_data_mod.OutputWord, &output_words[0], &output_words[1]);
    {
        var statement = matrix.statement;
        statement.public_data.io_entries.output_words = output_words[0 .. output_words.len - 1];
        try matrix.expectStatementRejected(
            "output word count (short)",
            0,
            error.InvalidStatement,
            statement,
        );
    }
    {
        var extended: [3]public_data_mod.OutputWord = undefined;
        @memcpy(extended[0..output_words.len], output_words);
        extended[output_words.len] = .{
            .addr = output_words[output_words.len - 1].addr + 4,
            .value = 0,
            .clock = output_words[output_words.len - 1].clock,
        };
        var statement = matrix.statement;
        statement.public_data.io_entries.output_words = &extended;
        try matrix.expectStatementRejected(
            "output word count (long)",
            0,
            error.InvalidStatement,
            statement,
        );
    }

    // The matrix is exhaustive over the families above: every attempt must
    // have run and been rejected.
    const expected_rejections = n_opcode_claims +
        matrix.claim.program_claims[0].len + // program claims
        n_memory_infra * 4 + // memory_claims entries
        n_merkle_infra * merkle_node.N_SUMS +
        n_poseidon_infra * poseidon2_air.N_SUMS +
        n_clock_infra * clock_update_interaction.N_SUMS +
        n_lookup_infra +
        3 + // interaction_pow, claim.n_components, claim.n_infra
        9 + // initial_pc/final_pc/clock: statement, public, and coordinated
        matrix.statement.public_data.initial_regs.len +
        matrix.statement.public_data.final_regs.len +
        matrix.statement.public_data.reg_last_clock.len + // reg_last_clock entries
        6 + // three optional roots, value and presence
        5 + // completion presence, address, value, clock, and coordinated kind
        2 + // input_start and shape-preserving input_len
        input_words.len + // every input word value
        4 + // input order, short count, long count, and non-canonical padding
        6 + // output metadata: lone and coordinated address/length mutations
        output_words.len * 3 + // output word value/clock/addr
        3; // output order, short count, and long count
    try std.testing.expectEqual(expected_rejections, matrix.rejected);
    try std.testing.expect(matrix.pow_rejected > 0);
    try std.testing.expect(matrix.logup_rejected > 0);
    // A shape-preserving statement mutation reaches LogUp only when the
    // original fixed 10-bit interaction nonce happens to remain valid. That
    // is deliberately rare and must not be a test-coverage requirement.
    try std.testing.expect(
        matrix.bound_pow_classified + matrix.bound_logup_classified > 0,
    );

    // Attribute the sampled honest execution to the pinned architectural
    // model after every proof-independent mutation assertion has run. The
    // release fixture supplies the runner's declared public-input image;
    // Sail reads those words from its own seeded memory rather than trusting
    // the trace's load claims. This must stay last so an absent oracle skips
    // only the sampled Sail leg.
    const sail_memory = try release_elf_fixture.initialMemory(&input);
    try runner_mod.sail_oracle.requireAgreement(
        alloc,
        "malicious-witness matrix public-I/O guest",
        elf_buf,
        &run_result.execution_trace,
        run_result.cpu_final,
        &sail_memory,
    );
}
