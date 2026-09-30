//! In-circuit Cairo statement: a call-order-exact port of
//! `crates/cairo_verifier/src/statement.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230), design §5.3.
//!
//! Every function keeps the Rust order of builder calls, because that order
//! numbers the variables and interns the constants of the leaf circuit
//! (design §3.3). The statement is generic over a builder facade `B`:
//! `cairo_statement_builder.BuilderFacade(V)` is the builder (`builder/`), and the
//! structural tests supply a recording facade. `B` must provide, with Rust
//! semantics:
//!
//! | `B` member | Rust |
//! |---|---|
//! | `Context`, `Var`, `Simd` | `Context<Value>`, `Var`, `Simd` |
//! | `zero(ctx)`, `one(ctx)` | `context.zero()`, `context.one()` |
//! | `constant(ctx, QM31)` | `context.constant` |
//! | `constU32(ctx, u32)` | `U32Wrapper::const_u32` |
//! | `constHash(ctx, [8]u32)` | `HashValue::<QM31>::constant` |
//! | `guessM31(ctx, M31)` | `M31Wrapper::from_m31(..).guess` |
//! | `guessHash(ctx, ?[8]u32)` | `HashValue::<Value>::guess` (`null` = `NoValue`) |
//! | `setOutputs(ctx, []const Var)` | `context.set_outputs` |
//! | `add`, `sub`, `mul(ctx, Var, Var)` | the `eval!` binary operators |
//! | `eq(ctx, Var, Var)` | `ops::eq` |
//! | `simdFromPacked(ctx, []const Var, len)` | `Simd::from_packed` |
//! | `simdPack(ctx, []const Var)` | `Simd::pack` |
//! | `simdUnpack(ctx, Simd)`, `simdUnpackIdx(ctx, Simd, usize)` | `Simd::unpack`, `Simd::unpack_idx` |
//! | `simdSub`, `simdMul(ctx, Simd, Simd)` | `Simd::sub`, `Simd::mul` |
//! | `combineBits(ctx, []const Simd)` | `Simd::combine_bits` |
//! | `extractBits(ctx, Simd, u32)` | `extract_bits::extract_bits` |
//! | `m31ToU32(ctx, Var)` | `blake::m31_to_u32` |
//! | `blake2sU32s(ctx, []const Var, usize)` | `blake::blake2s_u32s` |
//! | `logupUseTerm(ctx, []const Var, [2]Var)` | `logup::logup_use_term` |
//!
//! Fallible members return `anyerror!T`; slices they return are owned by the
//! context's arena. Cairo AIR facts (variants, ordered preprocessed ids,
//! builtin cells, leaf components, the aux-data layout, `ProgramFelt` and the
//! `claims_to_mix` program hash) come from `stwo_core.cairo_air_layout`;
//! the memory constants come from the projection header (the evaluator table's
//! `constants`), `RELATION_USES_NUM_ROWS_SHIFT` from `stark_verifier.verify`, and the
//! three relation ids from the caller, so no third copy of them exists here.

const std = @import("std");
const core = @import("stwo_core");
const manual_cairo = @import("../air_eval/manual/cairo.zig");
const verify = @import("../stark_verifier/verify.zig");

const layout = core.cairo_air_layout;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

// The aux-data layout, the program felt and the program hash are shared with
// the Cairo lane's host inputs through `stwo_core.cairo_air_layout`.
const n_segments = layout.n_segments;
const n_safe_call_ids = layout.n_safe_call_ids;
const memory_values_limbs = layout.memory_values_limbs;
const n_outputs = layout.n_outputs;
const aux_data_fixed_len = layout.aux_data_fixed_len;
const n_words_per_output_cell = layout.n_words_per_output_cell;
const ProgramFelt = layout.ProgramFelt;
const limb_bits = 9;
const memory_address_bits: u32 = 29;
const builtin_usage_bits: u32 = 27;
const m31_modulus: u64 = core.fields.m31.Modulus;

const relation_uses_num_rows_shift: u32 = verify.RELATION_USES_NUM_ROWS_SHIFT;

/// Constants the statement reads from outside `statement.rs`.
pub const Constants = struct {
    opcodes_relation_id: u32,
    memory_address_to_id_relation_id: u32,
    memory_id_to_big_relation_id: u32,
    /// The projection header's memory constants (`component_table.Table.constants`).
    memory: manual_cairo.Constants,

    /// The `const` sanity checks of `verify_claim`.
    pub fn validate(self: Constants) error{InvalidStatementConstants}!void {
        const max_sequence = @as(u64, 1) << @intCast(self.memory.max_sequence_log_size);
        if (@as(u64, self.memory.memory_address_to_id_split) * max_sequence > @as(u64, 1) << memory_address_bits or
            max_sequence > self.memory.large_memory_value_id_base)
            return error.InvalidStatementConstants;
    }
};

comptime {
    std.debug.assert(relation_uses_num_rows_shift < memory_address_bits);
}

pub fn CasmState(comptime Var: type) type {
    return struct { pc: Var, ap: Var, fp: Var };
}

pub fn PubMemoryAddress(comptime Var: type) type {
    return struct { id: Var, value: Var };
}

pub fn SegmentRange(comptime Var: type) type {
    return struct { start: PubMemoryAddress(Var), end: PubMemoryAddress(Var) };
}

/// `AuxData`: the parsed auxiliary-data variables.
pub fn AuxData(comptime Var: type) type {
    return struct {
        initial_state: CasmState(Var),
        final_state: CasmState(Var),
        segment_ranges: [n_segments]SegmentRange(Var),
        safe_call_ids: [n_safe_call_ids]Var,
        output_ids: []const Var,
        program_ids: []const Var,
        component_log_sizes: []const Var,

        const Self = @This();

        /// `AuxData::parse_from_vars`: the fixed fields, then `output_ids`,
        /// `program_ids` and `component_log_sizes`.
        pub fn parseFromVars(data: []const Var, program_len: usize, n_components: usize) error{InvalidAuxData}!Self {
            if (data.len != aux_data_fixed_len + program_len + n_components) return error.InvalidAuxData;
            var at: usize = 0;
            const next = struct {
                fn take(slice: []const Var, cursor: *usize) Var {
                    defer cursor.* += 1;
                    return slice[cursor.*];
                }
            }.take;
            var result: Self = undefined;
            result.initial_state = .{ .pc = next(data, &at), .ap = next(data, &at), .fp = next(data, &at) };
            result.final_state = .{ .pc = next(data, &at), .ap = next(data, &at), .fp = next(data, &at) };
            for (&result.segment_ranges) |*range| range.* = .{
                .start = .{ .id = next(data, &at), .value = next(data, &at) },
                .end = .{ .id = next(data, &at), .value = next(data, &at) },
            };
            result.safe_call_ids = .{ next(data, &at), next(data, &at) };
            result.output_ids = data[at..][0..n_outputs];
            at += n_outputs;
            result.program_ids = data[at..][0..program_len];
            at += program_len;
            result.component_log_sizes = data[at..];
            return result;
        }
    };
}

/// `CairoStatement<Value>` over builder facade `B`.
pub fn CairoStatement(comptime B: type) type {
    const Var = B.Var;
    const Simd = B.Simd;
    const Ctx = B.Context;

    return struct {
        allocator: std.mem.Allocator,
        constants: Constants,
        variant: layout.Variant,
        /// One flag per `all_components()` slot.
        enabled_bits: []const bool,
        /// The enabled slot names, in `all_components()` order (the
        /// `components` IndexMap keys; the evaluator table binds the evaluators to them).
        components: []const []const u8,
        aux_data: AuxData(Var),
        packed_component_log_sizes: Simd,
        program: []const ProgramFelt,
        outputs: [n_outputs][memory_values_limbs]Var,
        preprocessed_root: [8]u32,

        const Self = @This();

        pub const Inputs = struct {
            constants: Constants,
            /// `serialize_aux_data`; zeros of the right length in topology mode.
            serialized_aux_data: []const M31,
            /// The public output digest; `null` builds the topology (`NoValue`).
            output_hash: ?[8]u32,
            program: []const ProgramFelt,
            /// `all_components()` slot names (the projection's 83-slot order).
            slot_names: []const []const u8,
            enabled_bits: []const bool,
            preprocessed_root: [8]u32,
            variant: layout.Variant,
        };

        /// `CairoStatement::new`, in upstream order: enabled components,
        /// output-hash guess, `set_outputs`, output limbs, aux-data guesses,
        /// `AuxData::parse_from_vars`, `Simd::pack` of the log sizes.
        pub fn init(allocator: std.mem.Allocator, ctx: *Ctx, inputs: Inputs) anyerror!Self {
            try inputs.constants.validate();
            const components = try enabledComponents(allocator, inputs.slot_names, inputs.enabled_bits);
            const n_components = components.len;

            const output_hash = try B.guessHash(ctx, inputs.output_hash);
            try B.setOutputs(ctx, &output_hash);
            const outputs = try outputLimbsFromHash(allocator, ctx, output_hash);

            const aux_data_len = aux_data_fixed_len + inputs.program.len + n_components;
            if (inputs.serialized_aux_data.len != aux_data_len) return error.InvalidAuxData;
            const aux_vars = try allocator.alloc(Var, aux_data_len);
            for (inputs.serialized_aux_data, aux_vars) |value, *slot| slot.* = try B.guessM31(ctx, value);

            const aux_data = try AuxData(Var).parseFromVars(aux_vars, inputs.program.len, n_components);
            const packed_component_log_sizes = try B.simdPack(ctx, aux_data.component_log_sizes);
            return .{
                .allocator = allocator,
                .constants = inputs.constants,
                .variant = inputs.variant,
                .enabled_bits = inputs.enabled_bits,
                .components = components,
                .aux_data = aux_data,
                .packed_component_log_sizes = packed_component_log_sizes,
                .program = inputs.program,
                .outputs = outputs,
                .preprocessed_root = inputs.preprocessed_root,
            };
        }

        /// `verify::enabled_components`: the enabled slot names in slot order.
        pub fn enabledComponents(
            allocator: std.mem.Allocator,
            slot_names: []const []const u8,
            enabled_bits: []const bool,
        ) (error{EnabledBitsMismatch} || std.mem.Allocator.Error)![]const []const u8 {
            if (slot_names.len != enabled_bits.len) return error.EnabledBitsMismatch;
            var count: usize = 0;
            for (enabled_bits) |bit| count += @intFromBool(bit);
            const names = try allocator.alloc([]const u8, count);
            var at: usize = 0;
            for (slot_names, enabled_bits) |name, bit| if (bit) {
                names[at] = name;
                at += 1;
            };
            return names;
        }

        fn componentIndex(self: *const Self, name: []const u8) ?usize {
            for (self.components, 0..) |component, index| {
                if (std.mem.eql(u8, component, name)) return index;
            }
            return null;
        }

        // -------------------------------------------------------------------
        // Statement trait

        pub fn getComponentLogSizes(self: *const Self) Simd {
            return self.packed_component_log_sizes;
        }

        /// `get_preprocessed_column_ids`: the variant's ordered ids.
        pub fn getPreprocessedColumnIds(
            self: *const Self,
            out: *[layout.max_preprocessed_columns]layout.ColumnId,
        ) layout.Error![]layout.ColumnId {
            return layout.preprocessedColumns(self.variant, out);
        }

        /// `get_preprocessed_root`: interned as constants, never guessed.
        pub fn getPreprocessedRoot(self: *const Self, ctx: *Ctx) anyerror![8]Var {
            return B.constHash(ctx, self.preprocessed_root);
        }

        /// One M31 var per word, zero-padded to a multiple of four with
        /// `U32Wrapper::const_u32(0)`; each group is one `mix_u32s`.
        fn toPaddedU32Words(self: *const Self, ctx: *Ctx, vars: []const Var) anyerror![]Var {
            const padded_len = std.mem.alignForward(usize, vars.len, 4);
            const words = try self.allocator.alloc(Var, padded_len);
            for (vars, words[0..vars.len]) |v, *word| word.* = try B.m31ToU32(ctx, v);
            for (words[vars.len..]) |*word| word.* = try B.constU32(ctx, 0);
            return words;
        }

        fn constantU32(ctx: *Ctx, value: u32) anyerror!Var {
            return B.constant(ctx, QM31.fromM31(M31.fromCanonical(value), M31.zero(), M31.zero(), M31.zero()));
        }

        /// `claims_to_mix`: enable count, enable bits, log sizes, program
        /// length, aux data, Blake2s of the output limbs, program hash.
        pub fn claimsToMix(self: *const Self, ctx: *Ctx) anyerror![7][]const Var {
            const enable_count = try constantU32(ctx, @intCast(self.enabled_bits.len));
            const enable_count_words = try self.toPaddedU32Words(ctx, &.{enable_count});
            const enable_bit_vars = try self.allocator.alloc(Var, self.enabled_bits.len);
            for (self.enabled_bits, enable_bit_vars) |bit, *v| v.* = try constantU32(ctx, @intFromBool(bit));
            const enable_bits_words = try self.toPaddedU32Words(ctx, enable_bit_vars);

            const log_sizes_words = try self.toPaddedU32Words(ctx, self.aux_data.component_log_sizes);

            const program_len = try constantU32(ctx, @intCast(self.program.len));
            const program_len_words = try self.toPaddedU32Words(ctx, &.{program_len});
            const aux = &self.aux_data;
            var aux_vars = std.ArrayList(Var).empty;
            try aux_vars.appendSlice(self.allocator, &.{
                aux.initial_state.pc, aux.initial_state.ap, aux.initial_state.fp,
                aux.final_state.pc,   aux.final_state.ap,   aux.final_state.fp,
            });
            for (aux.segment_ranges) |range|
                try aux_vars.appendSlice(self.allocator, &.{ range.start.id, range.start.value, range.end.id, range.end.value });
            try aux_vars.appendSlice(self.allocator, &aux.safe_call_ids);
            try aux_vars.appendSlice(self.allocator, aux.output_ids);
            try aux_vars.appendSlice(self.allocator, aux.program_ids);
            const aux_data_words = try self.toPaddedU32Words(ctx, aux_vars.items);

            const output_limb_vars: []const Var = @ptrCast(&self.outputs);
            const n_output_bytes = 4 * output_limb_vars.len;
            const output_limb_words = try self.toPaddedU32Words(ctx, output_limb_vars);
            const output_hash = try B.blake2sU32s(ctx, output_limb_words, n_output_bytes);

            const program_hash = try B.constHash(ctx, layout.programHash(self.program));
            return .{
                enable_count_words,
                enable_bits_words,
                log_sizes_words,
                program_len_words,
                aux_data_words,
                try self.allocator.dupe(Var, &output_hash),
                try self.allocator.dupe(Var, &program_hash),
            };
        }

        /// `public_logup_sum`: the program limbs as constants, then the sum.
        pub fn publicLogupSum(self: *const Self, ctx: *Ctx, interaction_elements: [2]Var) anyerror!Var {
            const program = try self.allocator.alloc([memory_values_limbs]Var, self.program.len);
            for (self.program, program) |felt, *vars| {
                for (felt, vars) |limb, *v| v.* = try B.constant(ctx, QM31.fromM31(limb, M31.zero(), M31.zero(), M31.zero()));
            }
            return publicLogupSumOf(ctx, self.constants, &self.aux_data, program, &self.outputs, interaction_elements);
        }

        pub const PublicParam = struct { name: []const u8, value: Var };
        pub const public_param_names = [n_segments][]const u8{
            "output_segment_start",
            "pedersen_builtin_segment_start",
            "range_check_builtin_segment_start",
            "ecdsa_builtin_segment_start",
            "bitwise_builtin_segment_start",
            "ec_op_builtin_segment_start",
            "keccak_builtin_segment_start",
            "poseidon_builtin_segment_start",
            "range_check96_builtin_segment_start",
            "add_mod_builtin_segment_start",
            "mul_mod_builtin_segment_start",
        };

        /// `public_params`: every segment's start address, by name. Emits no
        /// gates; consumers look names up (upstream returns a HashMap).
        pub fn publicParams(self: *const Self) [n_segments]PublicParam {
            var params: [n_segments]PublicParam = undefined;
            for (&params, public_param_names, self.aux_data.segment_ranges) |*param, name, range|
                param.* = .{ .name = name, .value = range.start.value };
            return params;
        }

        /// `verify_builtins`.
        pub fn verifyBuiltins(self: *const Self, ctx: *Ctx, component_sizes: []const Var) anyerror!void {
            const ranges = &self.aux_data.segment_ranges;
            const output_range = ranges[0];
            const diff = try B.sub(ctx, output_range.end.value, output_range.start.value);
            const n_outputs_var = try constantU32(ctx, n_outputs);
            try B.eq(ctx, diff, n_outputs_var);

            // `segment_ranges` order: output, pedersen, range_check_128, ecdsa,
            // bitwise, ec_op, keccak, poseidon, range_check96, add_mod, mul_mod.
            const segment_of = [_]usize{ 1, 2, 4, 7, 5, 3, 6, 8, 9, 10 };
            const order = layout.verify_builtins_order;
            comptime std.debug.assert(order.len == segment_of.len);
            var starts: [order.len]Var = undefined;
            var ends: [order.len]Var = undefined;
            for (segment_of, &starts, &ends) |segment, *start, *end| {
                start.* = ranges[segment].start.value;
                end.* = ranges[segment].end.value;
            }
            const start_addresses = try B.simdPack(ctx, &starts);
            const end_addresses = try B.simdPack(ctx, &ends);
            const diffs = try B.simdSub(ctx, end_addresses, start_addresses);

            var inverses: [order.len]M31 = undefined;
            for (order, &inverses) |builtin, *inverse| inverse.* = try M31.fromCanonical(builtin.memoryCells()).inv();
            var inverse_vars: [(order.len + 3) / 4]Var = undefined;
            for (&inverse_vars, 0..) |*v, chunk| {
                var lanes = [_]M31{M31.zero()} ** 4;
                for (&lanes, 0..) |*lane, i| {
                    if (chunk * 4 + i < order.len) lane.* = inverses[chunk * 4 + i];
                }
                v.* = try B.constant(ctx, QM31.fromM31(lanes[0], lanes[1], lanes[2], lanes[3]));
            }
            const packed_inverses = try B.simdFromPacked(ctx, &inverse_vars, order.len);
            const n_uses = try B.simdMul(ctx, diffs, packed_inverses);
            _ = try B.extractBits(ctx, n_uses, builtin_usage_bits);

            const actual_uses = try B.simdUnpack(ctx, n_uses);
            var range_checks: [order.len]Var = undefined;
            var n_range_checks: usize = 0;
            var max_supported_size: u64 = 0;
            for (order, actual_uses) |builtin, uses| {
                const index = self.componentIndex(builtin.componentName(self.variant)) orelse {
                    try B.eq(ctx, uses, B.zero(ctx));
                    continue;
                };
                max_supported_size = @max(max_supported_size, builtin.memoryCells());
                range_checks[n_range_checks] = try B.sub(ctx, component_sizes[index], uses);
                n_range_checks += 1;
            }
            if ((@as(u64, 1) << memory_address_bits) + (@as(u64, 1) << builtin_usage_bits) * max_supported_size >= m31_modulus)
                return error.BuiltinUsageOverflow;
            const rc = try B.simdPack(ctx, range_checks[0..n_range_checks]);
            _ = try B.extractBits(ctx, rc, builtin_usage_bits);
        }

        /// `verify_claim`.
        pub fn verifyClaim(
            self: *const Self,
            ctx: *Ctx,
            component_sizes: []const Var,
            shifted_opcode_relation_uses: Var,
        ) anyerror!void {
            try self.verifyBuiltins(ctx, component_sizes);
            const initial = self.aux_data.initial_state;
            const final = self.aux_data.final_state;
            var range_checks: [2]Var = undefined;

            try B.eq(ctx, initial.pc, B.one(ctx));
            const four = try constantU32(ctx, 4);
            range_checks[0] = try B.sub(ctx, initial.ap, four);
            try B.eq(ctx, initial.fp, final.fp);
            try B.eq(ctx, initial.fp, initial.ap);
            const expected_final_pc = try constantU32(ctx, 5);
            try B.eq(ctx, final.pc, expected_final_pc);
            range_checks[1] = try B.sub(ctx, final.ap, initial.ap);

            const rc = try B.simdPack(ctx, &range_checks);
            _ = try B.extractBits(ctx, rc, memory_address_bits);

            const opcode_uses = try B.simdFromPacked(ctx, &.{shifted_opcode_relation_uses}, 1);
            _ = try B.extractBits(ctx, opcode_uses, memory_address_bits - relation_uses_num_rows_shift);
        }

        // -------------------------------------------------------------------
        // Free functions of statement.rs, in file order

        /// `CasmState::logup_term`.
        pub fn casmLogupTerm(ctx: *Ctx, constants: Constants, state: CasmState(Var), interaction_elements: [2]Var) anyerror!Var {
            const elements = [_]Var{ try constantU32(ctx, constants.opcodes_relation_id), state.pc, state.ap, state.fp };
            return B.logupUseTerm(ctx, &elements, interaction_elements);
        }

        /// `split_address_to_9bit_limbs`.
        pub fn splitAddressTo9bitLimbs(ctx: *Ctx, value: Var) anyerror![4]Var {
            const simd = try B.simdFromPacked(ctx, &.{value}, 1);
            const bits = try B.extractBits(ctx, simd, memory_address_bits);
            var limbs: [4]Var = undefined;
            for (&limbs, 0..) |*limb, index| {
                const start = index * limb_bits;
                const limb_simd = try B.combineBits(ctx, bits[start..@min(start + limb_bits, bits.len)]);
                limb.* = (try B.simdUnpack(ctx, limb_simd))[0];
            }
            return limbs;
        }

        /// `word_to_le_bits`: the 32 LE bits of a `(low_u16, high_u16)` word.
        fn wordToLeBits(allocator: std.mem.Allocator, ctx: *Ctx, word: Var) anyerror![]Simd {
            const packed_word = try B.simdFromPacked(ctx, &.{word}, 2);
            const low = try B.simdFromPacked(ctx, &.{try B.simdUnpackIdx(ctx, packed_word, 0)}, 1);
            const high = try B.simdFromPacked(ctx, &.{try B.simdUnpackIdx(ctx, packed_word, 1)}, 1);
            const low_bits = try B.extractBits(ctx, low, 16);
            const high_bits = try B.extractBits(ctx, high, 16);
            return std.mem.concat(allocator, Simd, &.{ low_bits, high_bits });
        }

        /// `output_limbs_from_hash`: each 128-bit half as 28 nine-bit limbs;
        /// the 15th limb is partial and limbs 15..27 are the zero constant.
        pub fn outputLimbsFromHash(allocator: std.mem.Allocator, ctx: *Ctx, hash: [8]Var) anyerror![n_outputs][memory_values_limbs]Var {
            const zero = try B.constant(ctx, QM31.zero());
            var outputs: [n_outputs][memory_values_limbs]Var = undefined;
            for (&outputs, 0..) |*cell, half| {
                var bits = std.ArrayList(Simd).empty;
                defer bits.deinit(allocator);
                for (hash[half * n_words_per_output_cell ..][0..n_words_per_output_cell]) |word| {
                    const word_bits = try wordToLeBits(allocator, ctx, word);
                    defer allocator.free(word_bits);
                    try bits.appendSlice(allocator, word_bits);
                }
                for (cell, 0..) |*limb, index| {
                    const start = index * limb_bits;
                    if (start >= bits.items.len) {
                        limb.* = zero;
                        continue;
                    }
                    const chunk = bits.items[start..@min(start + limb_bits, bits.items.len)];
                    const combined = try B.combineBits(ctx, chunk);
                    limb.* = try B.simdUnpackIdx(ctx, combined, 0);
                }
            }
            return outputs;
        }

        /// `segment_ranges_logup_sum`.
        pub fn segmentRangesLogupSum(
            ctx: *Ctx,
            constants: Constants,
            interaction_elements: [2]Var,
            segment_ranges: *const [n_segments]SegmentRange(Var),
            argument_address_start: Var,
            return_value_address_start: Var,
        ) anyerror!Var {
            const one = B.one(ctx);
            var sum = B.zero(ctx);
            var argument_address = argument_address_start;
            var return_value_address = return_value_address_start;
            for (segment_ranges, 0..) |range, index| {
                if (index != 0) {
                    argument_address = try B.add(ctx, argument_address, one);
                    return_value_address = try B.add(ctx, return_value_address, one);
                }
                const start_limbs = try splitAddressTo9bitLimbs(ctx, range.start.value);
                const start_term = try publicMemoryLogupTerms(ctx, constants, interaction_elements, argument_address, range.start.id, &start_limbs);
                sum = try B.add(ctx, sum, start_term);
                const end_limbs = try splitAddressTo9bitLimbs(ctx, range.end.value);
                const end_term = try publicMemoryLogupTerms(ctx, constants, interaction_elements, return_value_address, range.end.id, &end_limbs);
                sum = try B.add(ctx, sum, end_term);
            }
            return sum;
        }

        /// `public_memory_logup_terms`: address-to-id plus id-to-value.
        fn publicMemoryLogupTerms(
            ctx: *Ctx,
            constants: Constants,
            interaction_elements: [2]Var,
            address: Var,
            id: Var,
            value_limbs: []const Var,
        ) anyerror!Var {
            const address_relation = try constantU32(ctx, constants.memory_address_to_id_relation_id);
            const address_to_id = try B.logupUseTerm(ctx, &.{ address_relation, address, id }, interaction_elements);
            const big_relation = try constantU32(ctx, constants.memory_id_to_big_relation_id);
            var elements: [2 + memory_values_limbs]Var = undefined;
            elements[0] = big_relation;
            elements[1] = id;
            @memcpy(elements[2..][0..value_limbs.len], value_limbs);
            const id_to_value = try B.logupUseTerm(ctx, elements[0 .. 2 + value_limbs.len], interaction_elements);
            return B.add(ctx, address_to_id, id_to_value);
        }

        /// `memory_segment_logup_sum`.
        pub fn memorySegmentLogupSum(
            ctx: *Ctx,
            constants: Constants,
            interaction_elements: [2]Var,
            start_address: Var,
            ids: []const Var,
            memory_values: []const [memory_values_limbs]Var,
        ) anyerror!Var {
            if (ids.len != memory_values.len) return error.MemorySegmentLengthMismatch;
            const one = B.one(ctx);
            var sum = B.zero(ctx);
            var address = start_address;
            for (ids, memory_values, 0..) |id, *limbs, index| {
                if (index != 0) address = try B.add(ctx, address, one);
                const term = try publicMemoryLogupTerms(ctx, constants, interaction_elements, address, id, limbs);
                sum = try B.add(ctx, sum, term);
            }
            return sum;
        }

        /// `public_logup_sum` (free function): states, safe-call cells,
        /// segment ranges, output segment, program segment.
        pub fn publicLogupSumOf(
            ctx: *Ctx,
            constants: Constants,
            aux: *const AuxData(Var),
            program: []const [memory_values_limbs]Var,
            outputs: []const [memory_values_limbs]Var,
            interaction_elements: [2]Var,
        ) anyerror!Var {
            const initial_ap = aux.initial_state.ap;
            const final_ap = aux.final_state.ap;
            const final_term = try casmLogupTerm(ctx, constants, aux.final_state, interaction_elements);
            const initial_term = try casmLogupTerm(ctx, constants, aux.initial_state, interaction_elements);
            var sum = try B.sub(ctx, final_term, initial_term);

            const one = B.one(ctx);
            const two = try constantU32(ctx, 2);
            const safe_call_addresses = [2]Var{ try B.sub(ctx, initial_ap, two), try B.sub(ctx, initial_ap, one) };
            // memory[initial_ap - 2] = (id0, initial_ap); memory[initial_ap - 1] = (id1, 0),
            // whose limbs are passed as an empty slice (trailing zeros do not change
            // the combined term).
            const split_initial_ap = try splitAddressTo9bitLimbs(ctx, initial_ap);
            const safe_call_values = [2][]const Var{ &split_initial_ap, &.{} };
            for (safe_call_addresses, aux.safe_call_ids, safe_call_values) |address, id, limbs| {
                const term = try publicMemoryLogupTerms(ctx, constants, interaction_elements, address, id, limbs);
                sum = try B.add(ctx, sum, term);
            }

            const n_segments_var = try constantU32(ctx, n_segments);
            const return_value_address = try B.sub(ctx, final_ap, n_segments_var);
            const segments = try segmentRangesLogupSum(ctx, constants, interaction_elements, &aux.segment_ranges, initial_ap, return_value_address);
            sum = try B.add(ctx, sum, segments);

            const output_sum = try memorySegmentLogupSum(ctx, constants, interaction_elements, aux.segment_ranges[0].start.value, aux.output_ids, outputs);
            sum = try B.add(ctx, sum, output_sum);
            const program_sum = try memorySegmentLogupSum(ctx, constants, interaction_elements, aux.initial_state.pc, aux.program_ids, program);
            return B.add(ctx, sum, program_sum);
        }
    };
}

test {
    _ = @import("cairo_statement_test.zig");
}
