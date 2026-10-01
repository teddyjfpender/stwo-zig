//! The circuit-verifier statement: a circuit proof's public claim.
//!
//! Ports `crates/circuit_verifier/src/statement.rs` (`CircuitStatement`,
//! `circuit_component_log_sizes`, `circuit_verifier_proof_config`) and
//! `CircuitConfig` of `verify.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). The statement implements
//! the `stark_verifier.verify` statement interface over the 11 circuit-AIR
//! evaluators of the circuit-AIR table (`air_eval.circuit_components`).
//!
//! `CircuitStatement.init` emits, in order: the in-circuit circuit hash
//! (config words as constants, then Blake2s over them and the guessed root)
//! and the three constants of the packed component log sizes.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const circuit_hash = @import("../common/circuit_hash.zig");
const preprocessed = @import("../common/preprocessed.zig");
const proof = @import("../stark_verifier/proof.zig");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");
const logup = @import("../stark_verifier/logup.zig");
const proof_from_stark_proof = @import("../stark_verifier/proof_from_stark_proof.zig");
const verify_mod = @import("../stark_verifier/verify.zig");
const component_table = @import("../air_eval/component_table.zig");

const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const U32Wrapper = builder.wrappers.U32Wrapper;
const simd = builder.simd;
const N_COMPONENTS = component_list.N_COMPONENTS;
const N_RESERVED = component_list.N_RESERVED;

/// `CircuitConfig`: the PCS config and preprocessed layout of a verified
/// circuit.
pub const CircuitConfig = struct {
    config: PcsConfigV2,
    preprocessed_column_log_sizes: preprocessed.ColumnLayout,
};

/// `circuit_component_log_sizes`: the static log size of every circuit
/// component under `layout`.
pub fn circuitComponentLogSizes(
    layout: *const preprocessed.ColumnLayout,
) component_list.LogSizeError!component_list.PerComponent(u32) {
    return component_list.circuitComponentLogSizes(layout);
}

/// The component shapes in `CircuitStatement::new` iteration order
/// (`all_circuit_components`).
pub const circuit_component_shapes: [N_COMPONENTS]proof.ComponentShape = blk: {
    var shapes: [N_COMPONENTS]proof.ComponentShape = undefined;
    for (component_list.component_facts.toArray(), &shapes) |facts, *shape| {
        shape.* = .{ .trace_columns = facts.trace_columns, .interaction_columns = facts.interaction_columns };
    }
    break :blk shapes;
};

/// `circuit_verifier_proof_config`: the `ProofConfig` of proofs of a circuit
/// with this preprocessed layout, verified by the circuit verifier.
pub fn circuitVerifierProofConfig(
    allocator: std.mem.Allocator,
    layout: *const preprocessed.ColumnLayout,
    pcs_config: PcsConfigV2,
) proof.ConfigError!proof.ProofConfig {
    return proof.ProofConfig.init(
        allocator,
        &circuit_component_shapes,
        layout.entries.len,
        pcs_config,
        component_list.INTERACTION_POW_BITS,
    );
}

pub const Error = builder.context.Error || circuit_hash.Error || component_list.LogSizeError || error{
    /// The evaluator table is not the 11-component circuit table.
    NotTheCircuitTable,
    EmptyLookupElement,
};

/// `CircuitStatement<Value>`.
pub fn CircuitStatement(comptime V: type) type {
    return struct {
        const Self = @This();
        const Context = builder.Context(V);

        /// The 11 circuit-AIR evaluators (`all_circuit_components`).
        table: *const component_table.Table,
        /// The verified circuit's output digest, at its reserved output wires.
        output_digest: HashValue(Var),
        /// Per-component log sizes, packed.
        component_log_sizes: simd.Simd,
        layout: *const preprocessed.ColumnLayout,
        preprocessed_ids: [preprocessed.N_PREPROCESSED_COLUMNS][]const u8,
        preprocessed_root: HashValue(Var),
        circuit_hash: HashValue(Var),

        /// `CircuitStatement::new`.
        pub fn init(
            ctx: *Context,
            table: *const component_table.Table,
            config: *const CircuitConfig,
            preprocessed_root: HashValue(Var),
            output_digest: HashValue(Var),
        ) Error!Self {
            if (table.entries.len != N_COMPONENTS) return error.NotTheCircuitTable;
            const layout = &config.preprocessed_column_log_sizes;
            const log_sizes = try circuitComponentLogSizes(layout);
            const hash = try circuit_hash.circuitHash(V, ctx, log_sizes, config.config.fri_config.log_blowup_factor, preprocessed_root);

            var packed_values: [proof_from_stark_proof.nPackedQm31s(N_COMPONENTS)]QM31 = undefined;
            _ = proof_from_stark_proof.packIntoQm31s(&log_sizes.toArray(), &packed_values);
            const packed_vars = try ctx.scratch().alloc(Var, packed_values.len);
            for (packed_vars, packed_values) |*v, value| v.* = try ctx.constant(value);

            var ids: [preprocessed.N_PREPROCESSED_COLUMNS][]const u8 = undefined;
            for (&ids, layout.entries) |*id, entry| id.* = entry.id;
            return .{
                .table = table,
                .output_digest = output_digest,
                .component_log_sizes = .fromPacked(packed_vars, N_COMPONENTS),
                .layout = layout,
                .preprocessed_ids = ids,
                .preprocessed_root = preprocessed_root,
                .circuit_hash = hash,
            };
        }

        /// `claims_to_mix`: the circuit hash words, then the output digest as
        /// four words per QM31 wire.
        pub fn claimsToMix(self: *const Self, ctx: *Context) Error![]const []const U32Wrapper(Var) {
            var digest_vars: [N_RESERVED]Var = undefined;
            for (&digest_vars, self.output_digest.words) |*v, word| v.* = word.get();
            const output_words = try builder.blake.unpackQm31sToU32Words(V, ctx, &digest_vars);
            const claims = try ctx.scratch().alloc([]const U32Wrapper(Var), 2);
            claims[0] = &self.circuit_hash.words;
            claims[1] = output_words;
            return claims;
        }

        pub fn componentLogSizes(self: *const Self) simd.Simd {
            return self.component_log_sizes;
        }

        pub fn preprocessedRoot(self: *const Self, _: *Context) Error!HashValue(Var) {
            return self.preprocessed_root;
        }

        pub fn preprocessedColumnIds(self: *const Self) []const []const u8 {
            return &self.preprocessed_ids;
        }

        /// `public_logup_sum`: the uses of the output gates, at addresses
        /// `3..3 + N_RESERVED`, and of `u` at address 2.
        pub fn publicLogupSum(self: *const Self, ctx: *Context, interaction_elements: [2]Var) Error!Var {
            var sum = ctx.zero();
            const gate_relation_id = try ctx.constant(QM31.fromBase(M31.fromCanonical(component_list.GATE_RELATION_ID)));
            var addresses: [N_RESERVED + 1]Var = undefined;
            for (addresses[0..N_RESERVED], 0..) |*address, i| {
                address.* = try ctx.constant(QM31.fromBase(M31.fromCanonical(@intCast(builder.context.u_var_idx + 1 + i))));
            }
            addresses[N_RESERVED] = try ctx.constant(QM31.fromBase(M31.fromCanonical(builder.context.u_var_idx)));
            var values: [N_RESERVED + 1]Var = undefined;
            for (values[0..N_RESERVED], self.output_digest.words) |*v, word| v.* = word.get();
            values[N_RESERVED] = ctx.u();

            for (addresses, values) |address, value| {
                const lanes = try simd.unpack(V, ctx, .fromPacked(&.{value}, 4));
                const element = [_]Var{ gate_relation_id, address, lanes[0], lanes[1], lanes[2], lanes[3] };
                const term = try ctx.inv(try logup.combineTerm(Context, ctx, &element, interaction_elements));
                sum = try ctx.add(sum, term);
            }
            return sum;
        }

        /// The circuit AIR has no public parameters.
        pub fn publicParams(_: *const Self, _: *Context, _: *constraint_eval.ColumnMap(Var)) Error!void {}

        /// `sorting_required`: the default. The query columns are sorted into
        /// committed order (by log size, then column index) before hashing.
        pub fn sortingRequired(_: *const Self) bool {
            return true;
        }

        pub fn nComponents(_: *const Self) usize {
            return N_COMPONENTS;
        }

        pub fn relationUsesPerRow(self: *const Self, index: usize) []const component_list.RelationUse {
            return self.table.entries[index].shape.relation_uses_per_row;
        }

        pub fn evaluateComponent(
            self: *const Self,
            index: usize,
            ctx: *Context,
            data: *const constraint_eval.ComponentData(V),
            acc: *constraint_eval.CompositionConstraintAccumulator(Context),
        ) !void {
            try self.table.evaluate(index, Context, ctx, data, acc, ctx.scratch());
        }

        /// The circuit statement has no claim-level checks.
        pub fn verifyClaim(_: *const Self, _: *Context, _: []const Var, _: *const verify_mod.ShiftedRelationUses) Error!void {}
    };
}
