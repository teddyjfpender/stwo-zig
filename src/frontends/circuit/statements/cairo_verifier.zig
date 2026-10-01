//! The Cairo verifier (leaf) circuit: `CairoVerifierConfig`,
//! `enabled_components`, `build_and_fill_cairo_verifier_circuit` and
//! `build_cairo_verifier_circuit` of `crates/cairo_verifier/src/verify.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), design §5.3.
//!
//! `VerifierStatement(V)` is the `impl Statement for CairoStatement` of
//! `statement.rs`: it binds the `CairoStatement` port (over the builder
//! facade) to the `stark_verifier.verify` statement interface and to the
//! enabled slots of the 83-slot Cairo evaluator table (`air_eval.cairo_components`). It adds no gates of
//! its own; every builder call is the statement's or an evaluator's.
//!
//! The leaf circuit is `CairoStatement::new`, the proof guess, `verify` and
//! `finalize(false)`, then ZK blinding when configured. Its topology depends
//! only on the config: the Cairo preprocessed root and the program are
//! interned as constants, everything proof-specific is guessed.

const std = @import("std");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const circuit_hash = @import("../common/circuit_hash.zig");
const zk_blinding = @import("../common/zk_blinding.zig");
const component_table = @import("../air_eval/component_table.zig");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");
const proof = @import("../stark_verifier/proof.zig");
const verify_mod = @import("../stark_verifier/verify.zig");
const cairo_statement = @import("cairo_statement.zig");
const BuilderFacade = @import("cairo_statement_builder.zig").BuilderFacade;

const layout = core.cairo_air_layout;
const M31 = core.fields.m31.M31;
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const U32Wrapper = builder.wrappers.U32Wrapper;

/// `NON_QUERY_INFO_LEAK`: M31s of trace information in a proof besides the
/// query answers (two OODS queries of four each, plus two for safety). The
/// leaf's ZK blinding amount is `n_queries + NON_QUERY_INFO_LEAK`.
pub const NON_QUERY_INFO_LEAK: usize = 10;

/// `CairoVerifierConfig`: everything the leaf circuit's topology depends
/// on. Borrowed; the caller owns every slice and the proof config.
pub const CairoVerifierConfig = struct {
    proof_config: proof.ProofConfig,
    /// One flag per `all_components()` slot, in the table's slot order.
    enabled_bits: []const bool,
    /// The program every verified proof attests to, as 28-limb felts.
    program: []const layout.ProgramFelt,
    /// The Cairo preprocessed root, interned as a constant.
    preprocessed_root: [8]u32,
    variant: layout.Variant,
    /// Rounds of ZK blinding; `null` disables it.
    zk_blinding_amount: ?usize = null,

    pub fn nEnabledComponents(self: *const CairoVerifierConfig) usize {
        var count: usize = 0;
        for (self.enabled_bits) |bit| count += @intFromBool(bit);
        return count;
    }

    /// `serialize_aux_data`'s length for this config.
    pub fn auxDataLen(self: *const CairoVerifierConfig) usize {
        return layout.aux_data_fixed_len + self.program.len + self.nEnabledComponents();
    }
};

pub const Error = error{
    /// `enabled_bits` does not have one flag per table slot.
    EnabledBitsMismatch,
    /// The component count differs from the proof config's.
    ComponentCountMismatch,
    /// The statement has no `Opcodes` relation uses to range-check.
    MissingOpcodesRelation,
};

/// `impl Statement for CairoStatement<Value>`.
pub fn VerifierStatement(comptime V: type) type {
    return struct {
        const Self = @This();
        const Context = builder.Context(V);
        pub const Inner = cairo_statement.CairoStatement(BuilderFacade(V));

        inner: Inner,
        /// The 83-slot Cairo evaluator table (`all_components`).
        table: *const component_table.Table,
        /// The table slot of each enabled component, in statement order
        /// (`enabled_components`).
        slots: []const usize,
        /// `get_preprocessed_column_ids`, owned by the context's scratch.
        preprocessed_ids: []const []const u8,

        /// `CairoStatement::new`. Scratch-owned: lives until the context is
        /// deinitialized.
        pub fn init(
            ctx: *Context,
            table: *const component_table.Table,
            config: *const CairoVerifierConfig,
            constants: cairo_statement.Constants,
            serialized_aux_data: []const M31,
            output_hash: ?[8]u32,
        ) anyerror!Self {
            if (config.enabled_bits.len != table.entries.len) return error.EnabledBitsMismatch;
            const allocator = ctx.scratch();
            const slot_names = try allocator.alloc([]const u8, table.entries.len);
            for (slot_names, table.entries) |*name, entry| name.* = entry.name;
            const slots = try allocator.alloc(usize, config.nEnabledComponents());
            var at: usize = 0;
            for (config.enabled_bits, 0..) |bit, slot| if (bit) {
                slots[at] = slot;
                at += 1;
            };
            if (slots.len != config.proof_config.nComponents()) return error.ComponentCountMismatch;

            var columns: [layout.max_preprocessed_columns]layout.ColumnId = undefined;
            const ids = try layout.preprocessedColumns(config.variant, &columns);
            const preprocessed_ids = try allocator.alloc([]const u8, ids.len);
            for (preprocessed_ids, ids) |*id, *column| id.* = try allocator.dupe(u8, column.name());

            const inner = try Inner.init(allocator, ctx, .{
                .constants = constants,
                .serialized_aux_data = serialized_aux_data,
                .output_hash = output_hash,
                .program = config.program,
                .slot_names = slot_names,
                .enabled_bits = config.enabled_bits,
                .preprocessed_root = config.preprocessed_root,
                .variant = config.variant,
            });
            return .{ .inner = inner, .table = table, .slots = slots, .preprocessed_ids = preprocessed_ids };
        }

        pub fn preprocessedRoot(self: *const Self, ctx: *Context) anyerror!HashValue(Var) {
            return wrapHash(try self.inner.getPreprocessedRoot(ctx));
        }

        pub fn componentLogSizes(self: *const Self) builder.simd.Simd {
            return self.inner.getComponentLogSizes();
        }

        pub fn claimsToMix(self: *const Self, ctx: *Context) anyerror![]const []const U32Wrapper(Var) {
            const groups = try self.inner.claimsToMix(ctx);
            const claims = try ctx.scratch().alloc([]const U32Wrapper(Var), groups.len);
            for (claims, groups) |*claim, group| {
                const words = try ctx.scratch().alloc(U32Wrapper(Var), group.len);
                for (words, group) |*word, v| word.* = .newUnsafe(v);
                claim.* = words;
            }
            return claims;
        }

        pub fn publicLogupSum(self: *const Self, ctx: *Context, interaction_elements: [2]Var) anyerror!Var {
            return self.inner.publicLogupSum(ctx, interaction_elements);
        }

        pub fn publicParams(self: *const Self, ctx: *Context, params: *constraint_eval.ColumnMap(Var)) anyerror!void {
            for (self.inner.publicParams()) |param| try params.put(ctx.scratch(), param.name, param.value);
        }

        pub fn preprocessedColumnIds(self: *const Self) []const []const u8 {
            return self.preprocessed_ids;
        }

        /// `sorting_required`: the default.
        pub fn sortingRequired(_: *const Self) bool {
            return true;
        }

        pub fn nComponents(self: *const Self) usize {
            return self.slots.len;
        }

        pub fn relationUsesPerRow(self: *const Self, index: usize) []const component_list.RelationUse {
            return self.table.entries[self.slots[index]].shape.relation_uses_per_row;
        }

        pub fn evaluateComponent(
            self: *const Self,
            index: usize,
            ctx: *Context,
            data: *const constraint_eval.ComponentData(V),
            acc: *constraint_eval.CompositionConstraintAccumulator(Context),
        ) !void {
            try self.table.evaluate(self.slots[index], Context, ctx, data, acc, ctx.scratch());
        }

        pub fn verifyClaim(
            self: *const Self,
            ctx: *Context,
            component_sizes: []const Var,
            shifted_relation_uses: *const verify_mod.ShiftedRelationUses,
        ) anyerror!void {
            const opcodes = shifted_relation_uses.get("Opcodes") orelse return error.MissingOpcodesRelation;
            return self.inner.verifyClaim(ctx, component_sizes, opcodes);
        }

        fn wrapHash(words: [8]Var) HashValue(Var) {
            var hash: HashValue(Var) = undefined;
            for (&hash.words, words) |*word, v| word.* = .newUnsafe(v);
            return hash;
        }
    };
}

/// The proof-dependent inputs of a leaf circuit.
pub fn CairoVerifierInput(comptime V: type) type {
    return struct {
        proof: *const proof.Proof(V),
        /// `serialize_aux_data` (zeros of `auxDataLen` in topology mode).
        serialized_aux_data: []const M31,
        /// The public output digest; `null` in topology mode.
        output_hash: ?[8]u32,
    };
}

/// `build_and_fill_cairo_verifier_circuit` (`V = QM31`) and
/// `build_cairo_verifier_circuit` (`V = NoValue`): the finalized, unpadded
/// leaf circuit. `table` is the 83-slot Cairo evaluator table; `stages`
/// observes `verify` (see `verify_mod.NoStages`).
pub fn buildCairoVerifierCircuit(
    comptime V: type,
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    config: *const CairoVerifierConfig,
    constants: cairo_statement.Constants,
    input: CairoVerifierInput(V),
    stages: anytype,
) !builder.Context(V) {
    return buildCairoVerifierCircuitWithGateRecording(V, gpa, table, config, constants, input, true, stages);
}

/// Value-only reconstruction against an authenticated, cached leaf topology.
/// Callers that disable gate recording must not preprocess or locally check
/// this context; they must prove and independently verify using that topology.
pub fn buildCairoVerifierCircuitWithGateRecording(
    comptime V: type,
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    config: *const CairoVerifierConfig,
    constants: cairo_statement.Constants,
    input: CairoVerifierInput(V),
    record_gates: bool,
    stages: anytype,
) !builder.Context(V) {
    var ctx = try builder.Context(V).initWithGateRecording(gpa, component_list.N_RESERVED, record_gates);
    errdefer ctx.deinit();
    const statement = try VerifierStatement(V).init(&ctx, table, config, constants, input.serialized_aux_data, input.output_hash);
    const proof_vars = try proof.guess(V, &ctx, input.proof);
    try verify_mod.verify(V, &ctx, &proof_vars, config.proof_config, &statement, stages);
    try ctx.finalize(false);

    if (config.zk_blinding_amount) |amount| {
        const seed: [32]u8 = if (V == builder.NoValue) [_]u8{0} ** 32 else blk: {
            var words: [8]u32 = undefined;
            for (&words, input.proof.trace_root.words) |*word, value| word.* = builder.ivalue.unpackU32(V, value.get());
            break :blk blake2_hash.digestFromU32s(words);
        };
        try zk_blinding.addZkBlinding(V, &ctx, seed, amount);
    }
    return ctx;
}

/// `build_cairo_verifier_circuit`: the leaf circuit topology, built over an
/// `empty_proof` and zero aux data.
pub fn buildCairoVerifierTopology(
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    config: *const CairoVerifierConfig,
    constants: cairo_statement.Constants,
    stages: anytype,
) !builder.Context(builder.NoValue) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const empty = try proof.emptyProof(arena.allocator(), config.proof_config);
    const aux = try arena.allocator().alloc(M31, config.auxDataLen());
    @memset(aux, M31.zero());
    return buildCairoVerifierCircuit(builder.NoValue, gpa, table, config, constants, .{
        .proof = &empty,
        .serialized_aux_data = aux,
        .output_hash = null,
    }, stages);
}
