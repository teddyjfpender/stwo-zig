//! The circuit builder: variables, interned constants, guesses, reserved
//! outputs, the primitive gate operations and finalization.
//!
//! Port of `crates/circuits/src/context.rs` and the primitive operations of
//! `crates/circuits/src/ops.rs` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), call order exact:
//!
//! - vars 0, 1 and 2 are the interned constants zero, one and `u`; `u` is
//!   marked as an output by the constructor;
//! - `Context.init(gpa, n)` reserves vars `3..3+n` for `setOutputs`;
//! - every other var is numbered in call order; constants are interned in
//!   first-use order and stay interned after `finalize`;
//! - `add`, `mul` elide gates only by index (var 0 and var 1), never by value;
//!   `sub` and `pointwiseMul` never elide.
//!
//! `Context(QM31)` carries values (the production value path); `Context(NoValue)`
//! builds the same topology with no values.
//!
//! Ownership: the circuit, the value table and the bookkeeping sets are owned
//! by `gpa`. Gadget temporaries (`Simd` data, unpacked word lists, returned
//! slices) come from `scratch()`, an arena that lives until `deinit`. An
//! allocation failure leaves the context inconsistent; it may only be
//! `deinit`ed afterwards.
//!
//! Upstream's `debug_info` map (diagnostic names for `circuit_analysis`) is
//! not ported: it never affects numbering and nothing in the parity path
//! reads it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_mod = @import("circuit.zig");
const ivalue = @import("ivalue.zig");
const finalize_constants = @import("finalize_constants.zig");

const Allocator = std.mem.Allocator;
const QM31 = stwo_core.fields.qm31.QM31;

pub const Var = circuit_mod.Var;
pub const Circuit = circuit_mod.Circuit;
pub const NoValue = ivalue.NoValue;

/// The address of the `u` variable.
pub const u_var_idx: u32 = 2;
/// The value of `u`: `(0 + 0i) + (1 + 0i)u`.
pub const u_value: QM31 = QM31.fromU32Unchecked(0, 0, 1, 0);

/// A variable provided by the prover, and the constraint finalization adds
/// for it.
pub const GuessVar = union(enum) {
    /// Constrained to the base field by `var .* one = var`.
    m31: Var,
    /// Unrestricted; yielded by `var + 0 = var`.
    qm31: Var,
    /// Constrained to `[0, 2^16)` by `m31_to_u32(var) = var`.
    u16: Var,
};

/// Circuit-level operation counters (upstream `Stats`). They count builder
/// operations, not AIR rows, and never affect numbering.
pub const Stats = struct {
    equals: usize = 0,
    add: usize = 0,
    sub: usize = 0,
    mul: usize = 0,
    /// Each inversion also counts one `mul`, `guess` and `equals`.
    inv: usize = 0,
    /// Each division also counts one `mul`, `guess` and `equals`.
    div: usize = 0,
    pointwise_mul: usize = 0,
    guess: usize = 0,
    blake_updates: usize = 0,
    /// The number of inputs to permutation gates.
    permutation_inputs: usize = 0,
    outputs: usize = 0,
    triple_xor: usize = 0,
    m31_to_u32: usize = 0,
};

/// Failures of the builder operations.
pub const Error = Allocator.Error || error{
    /// The circuit would reach 2^31 variables, which no longer fit M31 addresses.
    TooManyVars,
    /// `assert_eq_on_eval` is on and an `eq` gate joined two different values.
    EqFailedOnEval,
};

/// Failures of `finalize` (upstream panics for each).
pub const FinalizeError = Error || error{
    /// Some reserved variables were never assigned by `setOutputs`.
    UnassignedReservedVars,
    /// `checkVarsUsed`: a variable marked unused is used by a gate.
    UsedVarMarkedUnused,
    /// `checkVarsUsed`: a variable no gate uses was not marked unused.
    UnusedVarNotMarked,
};

/// The key of the interned-constant table: the four canonical limbs.
pub fn constantKey(value: QM31) u128 {
    const l = ivalue.limbs(value);
    return @as(u128, l[0]) | (@as(u128, l[1]) << 32) | (@as(u128, l[2]) << 64) | (@as(u128, l[3]) << 96);
}

/// The QM31 a `constantKey` encodes.
pub fn constantFromKey(key: u128) QM31 {
    return QM31.fromU32Unchecked(@truncate(key), @truncate(key >> 32), @truncate(key >> 64), @truncate(key >> 96));
}

pub fn Context(comptime V: type) type {
    ivalue.assertValueType(V);
    return struct {
        const Self = @This();
        pub const Value = V;
        pub const Var = circuit_mod.Var;

        gpa: Allocator,
        scratch_arena: std.heap.ArenaAllocator,
        circuit: Circuit = .{},
        /// Interned constants, in first-use order (upstream `IndexMap<QM31, Var>`).
        constants: std.AutoArrayHashMapUnmanaged(u128, circuit_mod.Var) = .empty,
        /// One value per variable in value mode; empty in topology mode.
        value_table: std.ArrayListUnmanaged(QM31) = .empty,
        stats: Stats = .{},
        /// Marked unused; `checkVarsUsed` asserts no gate uses them.
        unused_vars: std.AutoHashMapUnmanaged(u32, void) = .empty,
        /// Marked maybe-unused; skipped by `checkVarsUsed`.
        maybe_unused_vars: std.AutoHashMapUnmanaged(u32, void) = .empty,
        /// Guessed variables, in guess order, until `finalizeGuessedVars`.
        guessed_vars: std.ArrayListUnmanaged(GuessVar) = .empty,
        guesses_finalized: bool = false,
        /// Reserved variables awaiting `setOutputs`.
        reserved_vars: std.ArrayListUnmanaged(u32) = .empty,
        finalized: bool = false,
        /// Debug only: assert equality when an `eq` gate is added.
        assert_eq_on_eval: bool = false,

        /// `Context::new(n_reserved)`: the default context (zero, one, `u`,
        /// with `u` marked as an output) followed by `n_reserved` reserved
        /// variables at `3..3+n_reserved`.
        pub fn init(gpa: Allocator, n_reserved: usize) Error!Self {
            var self: Self = .{ .gpa = gpa, .scratch_arena = .init(gpa) };
            errdefer self.deinit();
            _ = try self.constant(QM31.zero());
            _ = try self.constant(QM31.one());
            const u_var = try self.constant(u_value);
            std.debug.assert(u_var.idx == u_var_idx);
            try self.output(u_var);
            for (0..n_reserved) |_| _ = try self.reserve();
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.circuit.deinit(self.gpa);
            self.constants.deinit(self.gpa);
            self.value_table.deinit(self.gpa);
            self.unused_vars.deinit(self.gpa);
            self.maybe_unused_vars.deinit(self.gpa);
            self.guessed_vars.deinit(self.gpa);
            self.reserved_vars.deinit(self.gpa);
            self.scratch_arena.deinit();
            self.* = undefined;
        }

        /// The arena for gadget temporaries; freed by `deinit`.
        pub fn scratch(self: *Self) Allocator {
            return self.scratch_arena.allocator();
        }

        pub fn zero(_: *const Self) circuit_mod.Var {
            return .{ .idx = 0 };
        }

        pub fn one(_: *const Self) circuit_mod.Var {
            return .{ .idx = 1 };
        }

        pub fn u(_: *const Self) circuit_mod.Var {
            return .{ .idx = u_var_idx };
        }

        /// The value of every variable (value mode only).
        pub fn values(self: *const Self) []const QM31 {
            comptime if (V != QM31) @compileError("values() exists only in value mode");
            return self.value_table.items;
        }

        /// Consumes the context: returns the value table and frees
        /// everything else (gates, constants, scratch), for a prover that
        /// needs only the values once the circuit is preprocessed. On error
        /// the context is unchanged. Value mode only.
        pub fn intoValues(self: *Self) Allocator.Error![]QM31 {
            comptime if (V != QM31) @compileError("intoValues() exists only in value mode");
            const table = try self.value_table.toOwnedSlice(self.gpa);
            self.deinit();
            return table;
        }

        /// The interned constants and their variables, in first-use order.
        pub fn constantVars(self: *const Self) []const circuit_mod.Var {
            return self.constants.values();
        }

        /// Creates a new variable holding `value`.
        pub fn newVar(self: *Self, value: V) Error!circuit_mod.Var {
            const idx = self.circuit.n_vars;
            if (idx >= circuit_mod.max_vars - 1) return error.TooManyVars;
            if (V == QM31) try self.value_table.append(self.gpa, value);
            self.circuit.n_vars = idx + 1;
            return .{ .idx = idx };
        }

        /// The value of `v`. Reading a reserved variable before `setOutputs`
        /// is a programmer error and panics, as upstream.
        pub fn get(self: *const Self, v: circuit_mod.Var) V {
            for (self.reserved_vars.items) |reserved| {
                if (reserved == v.idx) @panic("read of reserved variable");
            }
            return if (V == QM31) self.value_table.items[v.idx] else .{};
        }

        /// Allocates a variable whose value `setOutputs` supplies later.
        pub fn reserve(self: *Self) Error!circuit_mod.Var {
            const reserved = try self.newVar(ivalue.placeholder(V));
            try self.reserved_vars.append(self.gpa, reserved.idx);
            return reserved;
        }

        /// Copies the values of `vars` into the reserved variables, yields each
        /// reserved variable with `var + 0 = reserved` and marks it as an
        /// output. `vars` must match the reserved variables one to one.
        pub fn setOutputs(self: *Self, vars: []const circuit_mod.Var) (Error || error{OutputCountMismatch})!void {
            if (vars.len != self.reserved_vars.items.len) return error.OutputCountMismatch;
            var reserved = self.reserved_vars;
            self.reserved_vars = .empty;
            defer reserved.deinit(self.gpa);
            for (reserved.items, vars) |reserved_idx, v| {
                if (V == QM31) self.value_table.items[reserved_idx] = self.get(v);
                try self.circuit.add.append(self.gpa, .{ .in0 = v.idx, .in1 = 0, .out = reserved_idx });
                try self.output(.{ .idx = reserved_idx });
            }
        }

        /// The variable of the constant `value`, interned on first use.
        pub fn constant(self: *Self, value: QM31) Error!circuit_mod.Var {
            const key = constantKey(value);
            if (self.constants.get(key)) |existing| return existing;
            const v = try self.newVar(ivalue.fromQm31(V, value));
            try self.constants.put(self.gpa, key, v);
            return v;
        }

        /// Marks `v` as unused; `checkVarsUsed` then asserts that no gate uses it.
        pub fn markAsUnused(self: *Self, v: circuit_mod.Var) Error!void {
            const entry = try self.unused_vars.getOrPut(self.gpa, v.idx);
            if (entry.found_existing) @panic("variable marked unused twice");
        }

        /// Marks `v` as maybe unused; `checkVarsUsed` skips it.
        pub fn markAsMaybeUnused(self: *Self, v: circuit_mod.Var) Error!void {
            const entry = try self.maybe_unused_vars.getOrPut(self.gpa, v.idx);
            if (entry.found_existing) @panic("variable marked maybe-unused twice");
        }

        /// Checks that every variable is used by a gate, except those marked
        /// unused or maybe unused, and that no variable marked unused is used.
        pub fn checkVarsUsed(self: *const Self) (Allocator.Error || error{ UsedVarMarkedUnused, UnusedVarNotMarked })!void {
            var multiplicities = try self.circuit.computeMultiplicities(self.gpa);
            defer multiplicities.deinit(self.gpa);
            for (multiplicities.n_uses, 0..) |uses, idx| {
                const marked_unused = self.unused_vars.contains(@intCast(idx));
                if (uses != 0 and marked_unused) return error.UsedVarMarkedUnused;
                if (uses == 0 and !marked_unused and !self.maybe_unused_vars.contains(@intCast(idx))) return error.UnusedVarNotMarked;
            }
        }

        /// Adds the trivial constraint that yields each guessed variable once:
        /// `var .* one = var` (M31), `var + zero = var` (QM31) and
        /// `m31_to_u32(var) = var` (U16), in guess order. Called by `finalize`;
        /// public for isolated tests (upstream `test_utils::finalize_guessed_vars`).
        pub fn finalizeGuessedVars(self: *Self) Error!void {
            if (self.guesses_finalized) @panic("guessed variables already finalized");
            self.guesses_finalized = true;
            for (self.guessed_vars.items) |guessed| switch (guessed) {
                .m31 => |v| try self.pointwiseMulInto(v, self.one(), v),
                .qm31 => |v| try self.addInto(v, self.zero(), v),
                .u16 => |v| try self.m31ToU32Into(v, v),
            };
            self.guessed_vars.clearAndFree(self.gpa);
        }

        /// `Context::finalize`: yields every constant (`finalize_constants`),
        /// optionally checks variable use, then yields every guess. Afterwards
        /// only gates that need no new guesses may be added (padding, blinding).
        pub fn finalize(self: *Self, check_vars_used: bool) FinalizeError!void {
            if (self.reserved_vars.items.len != 0) return error.UnassignedReservedVars;
            try finalize_constants.finalizeConstants(V, self);
            if (check_vars_used) try self.checkVarsUsed();
            try self.finalizeGuessedVars();
            self.finalized = true;
        }

        /// Whether the values satisfy every gate (value mode only).
        pub fn isCircuitValid(self: *const Self) Allocator.Error!bool {
            return try self.circuit.check(self.gpa, self.values()) == null;
        }

        // Primitive operations (`crates/circuits/src/ops.rs`).

        /// Adds an equality gate `[a] = [b]`.
        pub fn eq(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!void {
            self.stats.equals += 1;
            if (V == QM31 and self.assert_eq_on_eval and !self.get(a).eql(self.get(b))) return error.EqFailedOnEval;
            try self.circuit.eq.append(self.gpa, .{ .in0 = a.idx, .in1 = b.idx });
        }

        /// `a + b`; returns the other operand, with no gate, when either is var 0.
        pub fn add(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!circuit_mod.Var {
            if (a.idx == 0) return b;
            if (b.idx == 0) return a;
            const out = try self.newVar(ivalue.add(V, self.get(a), self.get(b)));
            try self.addInto(a, b, out);
            return out;
        }

        /// Adds `a + b = out` for an existing `out` whose value the caller owns.
        pub fn addInto(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var, out: circuit_mod.Var) Error!void {
            self.stats.add += 1;
            try self.circuit.add.append(self.gpa, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
        }

        /// `a - b`; never elided.
        pub fn sub(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!circuit_mod.Var {
            const out = try self.newVar(ivalue.sub(V, self.get(a), self.get(b)));
            try self.subInto(a, b, out);
            return out;
        }

        /// Adds `a - b = out` for an existing `out`.
        pub fn subInto(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var, out: circuit_mod.Var) Error!void {
            self.stats.sub += 1;
            try self.circuit.sub.append(self.gpa, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
        }

        /// `a * b`; returns var 0 when either operand is var 0, and the other
        /// operand when either is var 1, with no gate.
        pub fn mul(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!circuit_mod.Var {
            if (a.idx == 0 or b.idx == 0) return self.zero();
            if (a.idx == 1) return b;
            if (b.idx == 1) return a;
            const out = try self.newVar(ivalue.mul(V, self.get(a), self.get(b)));
            try self.mulInto(a, b, out);
            return out;
        }

        /// Adds `a * b = out` for an existing `out`.
        pub fn mulInto(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var, out: circuit_mod.Var) Error!void {
            self.stats.mul += 1;
            try self.circuit.mul.append(self.gpa, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
        }

        /// The coordinate-wise product `a .* b`; never elided.
        pub fn pointwiseMul(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!circuit_mod.Var {
            const out = try self.newVar(ivalue.pointwiseMul(V, self.get(a), self.get(b)));
            try self.pointwiseMulInto(a, b, out);
            return out;
        }

        /// Adds `a .* b = out` for an existing `out`.
        pub fn pointwiseMulInto(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var, out: circuit_mod.Var) Error!void {
            self.stats.pointwise_mul += 1;
            try self.circuit.pointwise_mul.append(self.gpa, .{ .in0 = a.idx, .in1 = b.idx, .out = out.idx });
        }

        /// Adds `m31_to_u32(input) = out` for an existing `out`.
        pub fn m31ToU32Into(self: *Self, input: circuit_mod.Var, out: circuit_mod.Var) Error!void {
            self.stats.m31_to_u32 += 1;
            try self.circuit.m31_to_u32.append(self.gpa, .{ .input = input.idx, .out = out.idx });
        }

        /// `a / b`: guesses the quotient and constrains `out * b = a`. Does not
        /// constrain `b != 0`. Panics in value mode when `b` is zero, as upstream.
        pub fn div(self: *Self, a: circuit_mod.Var, b: circuit_mod.Var) Error!circuit_mod.Var {
            self.stats.div += 1;
            const out = try self.guess(ivalue.div(V, self.get(a), self.get(b)));
            const product = try self.mul(out, b);
            try self.eq(product, a);
            return out;
        }

        /// `1 / b`: guesses the inverse and constrains `b * b_inv = 1`, which
        /// proves `b != 0`.
        pub fn inv(self: *Self, b: circuit_mod.Var) Error!circuit_mod.Var {
            self.stats.inv += 1;
            const b_inv = try self.guess(ivalue.div(V, self.get(self.one()), self.get(b)));
            const product = try self.mul(b, b_inv);
            try self.eq(product, self.one());
            return b_inv;
        }

        /// A new unconstrained QM31 variable holding `value`.
        pub fn guess(self: *Self, value: V) Error!circuit_mod.Var {
            return self.guessAs(.qm31, value);
        }

        /// A new variable holding `value`, constrained to M31 at finalization.
        pub fn guessM31(self: *Self, value: V) Error!circuit_mod.Var {
            return self.guessAs(.m31, value);
        }

        /// A new variable holding `value`, constrained to `[0, 2^16)` at finalization.
        pub fn guessU16(self: *Self, value: V) Error!circuit_mod.Var {
            return self.guessAs(.u16, value);
        }

        fn guessAs(self: *Self, comptime kind: std.meta.Tag(GuessVar), value: V) Error!circuit_mod.Var {
            if (self.guesses_finalized) @panic("guess after the guessed variables were finalized");
            self.stats.guess += 1;
            const out = try self.newVar(value);
            try self.guessed_vars.append(self.gpa, @unionInit(GuessVar, @tagName(kind), out));
            return out;
        }

        /// Adds a permutation gate: new output variables hold `permutation`
        /// applied to the input values. Returns the outputs (scratch-owned).
        pub fn permute(
            self: *Self,
            inputs: []const circuit_mod.Var,
            comptime permutation: fn (in: []const V, out: []V) void,
        ) Error![]const circuit_mod.Var {
            self.stats.permutation_inputs += inputs.len;
            const arena = self.scratch();
            const in_values = try arena.alloc(V, inputs.len);
            for (in_values, inputs) |*value, v| value.* = self.get(v);
            const out_values = try arena.alloc(V, inputs.len);
            permutation(in_values, out_values);
            const outputs = try arena.alloc(circuit_mod.Var, inputs.len);
            for (outputs, out_values) |*out, value| out.* = try self.newVar(value);
            const input_idx = try arena.alloc(u32, inputs.len);
            for (input_idx, inputs) |*idx, v| idx.* = v.idx;
            const output_idx = try arena.alloc(u32, inputs.len);
            for (output_idx, outputs) |*idx, v| idx.* = v.idx;
            try self.circuit.permutation.append(self.gpa, input_idx, output_idx);
            return outputs;
        }

        /// Adds an output gate marking `a`.
        pub fn output(self: *Self, a: circuit_mod.Var) Error!void {
            self.stats.outputs += 1;
            try self.circuit.output.append(self.gpa, a.idx);
        }
    };
}

test {
    _ = @import("context_test.zig");
}
