//! Exact schema-v4 reconstruction for independent artifact verification.

const std = @import("std");
const stwo = @import("stwo");

const artifact_mod = stwo.interop.riscv_artifact;
const prover = stwo.frontends.riscv.prover_mod;
const statement_mod = stwo.frontends.riscv.air.statement;

pub const Reconstruction = struct {
    statement: prover.RiscVStatement,
    claim: prover.RiscVInteractionClaim,
    output_words: []stwo.frontends.riscv.air.public_data.OutputWord,

    pub fn init(allocator: std.mem.Allocator, artifact: artifact_mod.Artifact) !Reconstruction {
        const wire_statement = artifact.statement;
        if (wire_statement.components.len > prover.MAX_COMPONENTS or
            wire_statement.infrastructure.len > prover.MAX_INFRA_COMPONENTS)
            return error.InvalidArtifact;

        var result: Reconstruction = undefined;
        result.statement = undefined;
        result.statement.n_components = @intCast(wire_statement.components.len);
        result.statement.n_infra = @intCast(wire_statement.infrastructure.len);
        result.statement.initial_pc = wire_statement.initial_pc;
        result.statement.final_pc = wire_statement.final_pc;
        result.statement.total_steps = wire_statement.total_steps;
        for (wire_statement.components, 0..) |wire, index| {
            result.statement.component_descs[index] = .{
                .family = std.meta.intToEnum(
                    @TypeOf(result.statement.component_descs[0].family),
                    wire.family,
                ) catch return error.InvalidArtifact,
                .log_size = wire.log_size,
                .n_rows = wire.n_rows,
                .n_columns = wire.n_columns,
            };
        }
        for (wire_statement.infrastructure, 0..) |wire, index| {
            result.statement.infra_descs[index] = .{
                .kind = std.meta.intToEnum(
                    @TypeOf(result.statement.infra_descs[0].kind),
                    wire.kind,
                ) catch return error.InvalidArtifact,
                .log_size = wire.log_size,
                .n_rows = wire.n_rows,
                .n_columns = wire.n_columns,
            };
        }

        const public = wire_statement.public_data;
        result.output_words = try allocator.alloc(
            stwo.frontends.riscv.air.public_data.OutputWord,
            public.output_words.len,
        );
        errdefer allocator.free(result.output_words);
        for (result.output_words, public.output_words) |*destination, wire| {
            destination.* = .{ .addr = wire.addr, .value = wire.value, .clock = wire.clock };
        }
        result.statement.public_data = .{
            .initial_pc = public.initial_pc,
            .final_pc = public.final_pc,
            .clock = public.clock,
            .initial_regs = public.initial_regs,
            .final_regs = public.final_regs,
            .reg_last_clock = public.reg_last_clock,
            .program_root = public.program_root,
            .initial_rw_root = public.initial_rw_root,
            .final_rw_root = public.final_rw_root,
            .completion = .{
                .kind = switch (public.completion.kind) {
                    .halt_flag => .halt_flag,
                    .unretired_self_loop => .unretired_self_loop,
                },
                .address = public.completion.address,
                .value = public.completion.value,
                .clock = public.completion.clock,
            },
            .io_entries = .{
                .input_start = public.input_start,
                .input_len = public.input_len,
                .input_words = public.input_words,
                .output_len = public.output_len,
                .output_len_addr = public.output_len_addr,
                .output_data_addr = public.output_data_addr,
                .output_words = result.output_words,
            },
        };

        result.claim = prover.RiscVInteractionClaim.initZero();
        result.claim.n_components = result.statement.n_components;
        result.claim.n_infra = result.statement.n_infra;
        result.claim.interaction_pow = artifact.interaction_claim.interaction_pow;
        if (artifact.interaction_claim.opcode_claims.len != result.statement.n_components or
            artifact.interaction_claim.infrastructure_claims.len != result.statement.n_infra)
            return error.InvalidArtifact;
        for (artifact.interaction_claim.opcode_claims, 0..) |wire, index| {
            if (wire.component_index != index) return error.InvalidArtifact;
            const family = result.statement.component_descs[index].family;
            const expected = try result.claim.opcodeClaims(family, index);
            if (wire.claimed_sums.len != expected.len) return error.InvalidArtifact;
            for (wire.claimed_sums, 0..) |sum, sum_index| {
                result.claim.opcode_claims[index][sum_index] = qm31FromWire(sum);
            }
        }
        for (artifact.interaction_claim.infrastructure_claims, 0..) |wire, index| {
            if (wire.infrastructure_index != index) return error.InvalidArtifact;
            const kind = result.statement.infra_descs[index].kind;
            if (wire.claimed_sums.len != statement_mod.nClaimedSumsForInfra(kind))
                return error.InvalidArtifact;
            for (wire.claimed_sums, 0..) |sum, sum_index| {
                try result.claim.setInfraClaim(kind, index, sum_index, qm31FromWire(sum));
            }
        }
        return result;
    }

    pub fn deinit(self: *Reconstruction, allocator: std.mem.Allocator) void {
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

fn qm31FromWire(wire: artifact_mod.Qm31Wire) stwo.core.fields.qm31.QM31 {
    return stwo.core.fields.qm31.QM31.fromU32Unchecked(wire[0], wire[1], wire[2], wire[3]);
}
