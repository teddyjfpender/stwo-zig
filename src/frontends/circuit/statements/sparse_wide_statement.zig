//! Statement for S31's sparse-wide-v5 proof profile. Only the four AIRs
//! actually committed by that prover enter the recursive verifier. The
//! source digest, circuit identity, preprocessed root, and PCS geometry are
//! fixed by the caller's sealed child key.
const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const sparse = @import("../common/sparse_wide.zig");
const proof = @import("../stark_verifier/proof.zig");
const proof_from_stark_proof = @import("../stark_verifier/proof_from_stark_proof.zig");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");
const logup = @import("../stark_verifier/logup.zig");
const verify_mod = @import("../stark_verifier/verify.zig");
const channel_mod = @import("../stark_verifier/channel.zig");
const component_table = @import("../air_eval/component_table.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const U32 = builder.wrappers.U32Wrapper(Var);
const N = sparse.active_component_indices.len;

pub const shapes: [N]proof.ComponentShape = blk: {
    const facts = component_list.component_facts.toArray();
    var result: [N]proof.ComponentShape = undefined;
    for (sparse.active_component_indices, &result) |index, *shape|
        shape.* = .{ .trace_columns = facts[index].trace_columns, .interaction_columns = facts[index].interaction_columns };
    break :blk result;
};

pub fn proofConfig(allocator: std.mem.Allocator, layout: *const sparse.Layout, pcs: core.pcs.config_v2.PcsConfigV2) proof.ConfigError!proof.ProofConfig {
    return proof.ProofConfig.init(allocator, &shapes, layout.entries.len, pcs, component_list.INTERACTION_POW_BITS);
}

pub const Error = builder.context.Error || error{ InvalidComponentTable, InvalidSparseLayout, EmptyLookupElement };

pub fn SparseWideStatement(comptime V: type) type {
    return struct {
        const Self = @This();
        const Context = builder.Context(V);
        table: *const component_table.Table,
        layout: *const sparse.Layout,
        ids: [sparse.N_COLUMNS][]const u8,
        log_sizes: builder.simd.Simd,
        root: HashValue(Var),
        identity: HashValue(Var),
        output: HashValue(Var),
        source_digest: [32]u8,

        pub fn init(
            ctx: *Context,
            table: *const component_table.Table,
            layout: *const sparse.Layout,
            root: [32]u8,
            identity: [32]u8,
            output: HashValue(Var),
            source_digest: [32]u8,
        ) Error!Self {
            if (table.entries.len != component_list.N_COMPONENTS) return error.InvalidComponentTable;
            const facts = component_list.component_facts.toArray();
            for (sparse.active_component_indices) |index| {
                if (!std.mem.eql(u8, table.entries[index].name, component_list.COMPONENT_NAMES[index]) or
                    !table.entries[index].shape.eql(.fromFacts(facts[index])))
                    return error.InvalidComponentTable;
            }
            const logs = [N]u32{
                layout.logSize("eq_in0_address") orelse return error.InvalidSparseLayout,
                layout.logSize("qm31_ops_in0_address") orelse return error.InvalidSparseLayout,
                layout.logSize("m31_to_u32_input_addr") orelse return error.InvalidSparseLayout,
                16,
            };
            var packed_values: [proof_from_stark_proof.nPackedQm31s(N)]QM31 = undefined;
            _ = proof_from_stark_proof.packIntoQm31s(&logs, &packed_values);
            const vars = try ctx.scratch().alloc(Var, packed_values.len);
            for (vars, packed_values) |*v, value| v.* = try ctx.constant(value);
            var ids: [sparse.N_COLUMNS][]const u8 = undefined;
            for (&ids, layout.entries) |*id, entry| id.* = entry.id;
            return .{
                .table = table,
                .layout = layout,
                .ids = ids,
                .log_sizes = .fromPacked(vars, N),
                .root = try builder.blake.constantHash(V, ctx, builder.blake.hashValueFromDigest(QM31, root)),
                .identity = try builder.blake.constantHash(V, ctx, builder.blake.hashValueFromDigest(QM31, identity)),
                .output = output,
                .source_digest = source_digest,
            };
        }

        /// Native sparse-wide prover prefix: mix_u64(profile_tag), source
        /// digest words, then three zero words. Each mix is a separate hash.
        pub fn mixProfile(self: *const Self, ctx: *Context, channel: *channel_mod.Channel) Error!void {
            const tag = sparse.profile_tag;
            try channel.mixU32s(V, ctx, &.{
                try builder.wrappers.constU32(V, ctx, @truncate(tag)),
                try builder.wrappers.constU32(V, ctx, @truncate(tag >> 32)),
            });
            var source: [8]U32 = undefined;
            for (&source, 0..) |*word, i|
                word.* = try builder.wrappers.constU32(V, ctx, std.mem.readInt(u32, self.source_digest[4 * i ..][0..4], .little));
            try channel.mixU32s(V, ctx, &source);
            var zero_words: [sparse.profile_zero_words.len]U32 = undefined;
            for (&zero_words, sparse.profile_zero_words) |*word, value|
                word.* = try builder.wrappers.constU32(V, ctx, value);
            try channel.mixU32s(V, ctx, &zero_words);
        }

        pub fn claimsToMix(self: *const Self, ctx: *Context) Error![]const []const U32 {
            var values: [component_list.N_RESERVED]Var = undefined;
            for (&values, self.output.words) |*v, word| v.* = word.get();
            const output_words = try builder.blake.unpackQm31sToU32Words(V, ctx, &values);
            const claims = try ctx.scratch().alloc([]const U32, 2);
            claims[0] = &self.identity.words;
            claims[1] = output_words;
            return claims;
        }

        pub fn componentLogSizes(self: *const Self) builder.simd.Simd { return self.log_sizes; }
        pub fn preprocessedRoot(self: *const Self, _: *Context) Error!HashValue(Var) { return self.root; }
        pub fn preprocessedColumnIds(self: *const Self) []const []const u8 { return &self.ids; }
        pub fn publicLogupSum(self: *const Self, ctx: *Context, elements: [2]Var) Error!Var {
            var sum = ctx.zero();
            const relation = try ctx.constant(QM31.fromBase(M31.fromCanonical(component_list.GATE_RELATION_ID)));
            var addresses: [component_list.N_RESERVED + 1]Var = undefined;
            for (addresses[0..component_list.N_RESERVED], 0..) |*address, i|
                address.* = try ctx.constant(QM31.fromBase(M31.fromCanonical(@intCast(builder.context.u_var_idx + 1 + i))));
            addresses[component_list.N_RESERVED] = try ctx.constant(QM31.fromBase(M31.fromCanonical(builder.context.u_var_idx)));
            var values: [component_list.N_RESERVED + 1]Var = undefined;
            for (values[0..component_list.N_RESERVED], self.output.words) |*v, word| v.* = word.get();
            values[component_list.N_RESERVED] = ctx.u();
            for (addresses, values) |address, value| {
                const lanes = try builder.simd.unpack(V, ctx, .fromPacked(&.{value}, 4));
                const term = try ctx.inv(try logup.combineTerm(Context, ctx, &.{ relation, address, lanes[0], lanes[1], lanes[2], lanes[3] }, elements));
                sum = try ctx.add(sum, term);
            }
            return sum;
        }
        pub fn publicParams(_: *const Self, _: *Context, _: *constraint_eval.ColumnMap(Var)) Error!void {}
        pub fn sortingRequired(_: *const Self) bool { return true; }
        pub fn nComponents(_: *const Self) usize { return N; }
        pub fn relationUsesPerRow(self: *const Self, index: usize) []const component_list.RelationUse {
            return self.table.entries[sparse.active_component_indices[index]].shape.relation_uses_per_row;
        }
        pub fn evaluateComponent(self: *const Self, index: usize, ctx: *Context, data: *const constraint_eval.ComponentData(V), acc: *constraint_eval.CompositionConstraintAccumulator(Context)) !void {
            try self.table.evaluate(sparse.active_component_indices[index], Context, ctx, data, acc, ctx.scratch());
        }
        pub fn verifyClaim(_: *const Self, _: *Context, _: []const Var, _: *const verify_mod.ShiftedRelationUses) Error!void {}
    };
}
