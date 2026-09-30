//! Port of `crates/stark_verifier/src/test_utils.rs::TestComponentData`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): component data allocated as
//! fresh variables, in the upstream harness order. Test-only.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const constraint_eval = circuit.stark_verifier.constraint_eval;
const ivalue = circuit.builder.ivalue;

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;

/// Number of `n_instances` bit variables the upstream harness allocates.
pub const n_instances_bits = 31;

pub fn TestComponentData(comptime Ctx: type) type {
    return struct {
        const Self = @This();
        const Var = Ctx.Var;
        const Interaction = constraint_eval.InteractionAtOods(Var);

        trace: []Var,
        interaction_trace: []Interaction,
        n_instances_var: Var,
        n_instances_bits: [n_instances_bits]Var,

        /// Allocation order: trace columns; each interaction QM31 as four M31
        /// limbs; the four limbs of `last_row_sum` as `at_prev` of the last
        /// four interaction limbs; 31 bits of `n_instances`, LSB first; then
        /// `n_instances`.
        pub fn fromValues(
            allocator: std.mem.Allocator,
            ctx: *Ctx,
            trace_values: []const QM31,
            interaction_values: []const QM31,
            last_row_sum: QM31,
            n_instances: u32,
        ) !Self {
            const trace = try allocator.alloc(Var, trace_values.len);
            errdefer allocator.free(trace);
            for (trace, trace_values) |*v, value| v.* = try ctx.newVar(ivalue.fromQm31(Ctx.Value, value));

            const interaction = try allocator.alloc(Interaction, 4 * interaction_values.len);
            errdefer allocator.free(interaction);
            for (interaction_values, 0..) |value, i| {
                for (value.toM31Array(), 0..) |limb, j| {
                    interaction[4 * i + j] = .{ .at_oods = try ctx.newVar(ivalue.fromQm31(Ctx.Value, QM31.fromBase(limb))) };
                }
            }
            if (interaction.len != 0) {
                const tail = interaction[interaction.len - 4 ..];
                for (tail, last_row_sum.toM31Array()) |*column, limb| {
                    column.at_prev = try ctx.newVar(ivalue.fromQm31(Ctx.Value, QM31.fromBase(limb)));
                }
            }
            var bits: [n_instances_bits]Var = undefined;
            for (&bits, 0..) |*bit, position| {
                const value: u32 = (n_instances >> @intCast(position)) & 1;
                bit.* = try ctx.newVar(ivalue.fromQm31(Ctx.Value, QM31.fromBase(M31.fromCanonical(value))));
            }
            const count = try ctx.newVar(ivalue.fromQm31(Ctx.Value, QM31.fromBase(M31.fromU64(n_instances))));
            return .{ .trace = trace, .interaction_trace = interaction, .n_instances_var = count, .n_instances_bits = bits };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.trace);
            allocator.free(self.interaction_trace);
            self.* = undefined;
        }

        pub fn traceColumns(self: *const Self) []const Var {
            return self.trace;
        }

        pub fn interactionColumns(self: *const Self) []const Interaction {
            return self.interaction_trace;
        }

        pub fn nInstances(self: *const Self) Var {
            return self.n_instances_var;
        }

        pub fn getNInstancesBit(self: *const Self, _: *Ctx, bit: usize) !Var {
            if (bit >= n_instances_bits) return error.InstanceBitOutOfRange;
            return self.n_instances_bits[bit];
        }

        pub fn maxComponentSizeBits(_: *const Self) usize {
            return n_instances_bits;
        }
    };
}
