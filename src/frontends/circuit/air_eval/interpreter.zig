//! Interpreter of projected constraint functions: the in-circuit evaluators
//! that upstream generates as Rust text, replayed through the builder.
//!
//! This transliterates `crates/air_code_gen/src/circuit/component.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The emitted builder calls must
//! equal the generated code's, one for one, because gate order and variable
//! numbering are the parity contract. One `accumulate_constraints` body runs:
//!
//! 1. unpack the inputs: `verifier_input_limbs`, `enabler`, `state_names` for
//!    an Inline function, `state_names` otherwise;
//! 2. read `used_external_states` in their (sorted) order; `Seq` runs
//!    `seq_of_component_size`, once per function body, re-emitting its gates
//!    in every body (subroutines included) that reads `Seq`;
//! 3. read `used_public_params` in their (sorted) order;
//! 4. walk the steps. `eval!` emits the left subtree, the right subtree, then
//!    the op; `-x` is `sub(zero, x)` after `x`; a literal is `constant(v)`.
//!    A lookup term evaluates its felts left to right, then its numerator
//!    (negated for a Yield), then combines the tuple;
//! 5. an Inline function returns its `verifier_output` array, evaluated left
//!    to right.
//!
//! `Component::evaluate` of a sized component then checks
//! `eq(get_n_instances_bit(log_height), one)` after the body.
//!
//! The interpreter calls only builder ops and never folds, interns or caches
//! values itself; the builder's index-only peepholes decide what is a gate.

const std = @import("std");
const stwo_core = @import("stwo_core");
const projection_mod = @import("projection.zig");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");
const component_utils = @import("../common/component_utils.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const Projection = projection_mod.Projection;
const Source = projection_mod.Source;
const Function = projection_mod.Function;
const ExprId = projection_mod.ExprId;
const Str = projection_mod.Str;

pub const Error = error{
    InputCountMismatch,
    UnboundName,
    MissingEnabler,
    UnexpectedCallResult,
    CallResultCountMismatch,
    NotAnExpression,
    NotInline,
};

/// Evaluates the functions of one projection source through the builder
/// `Ctx`, the accumulator `Acc` and the component data `Data` (see
/// `constraint_eval.zig` for the component-data surface).
pub fn Interpreter(comptime Ctx: type, comptime Data: type) type {
    return struct {
        const Self = @This();
        const Var = Ctx.Var;
        pub const Accumulator = constraint_eval.CompositionConstraintAccumulator(Ctx);
        /// Calls recurse through subroutines, so the set is named rather than
        /// inferred; it spans the builder's, the component data's and the
        /// accumulator's failures, which are generic here.
        pub const EvalError = anyerror;

        projection: *const Projection,
        source: *const Source,
        ctx: *Ctx,
        data: *const Data,
        acc: *Accumulator,
        /// Frame maps and call results; reset by the caller between components.
        scratch: std.mem.Allocator,

        /// One `accumulate_constraints` invocation. Names share one Rust
        /// scope: inputs, then `let` bindings, which shadow in step order.
        const Frame = struct {
            function: *const Function,
            names: std.AutoHashMapUnmanaged(Str, Var) = .empty,
            externals: std.AutoHashMapUnmanaged(Str, Var) = .empty,
            params: std.AutoHashMapUnmanaged(Str, Var) = .empty,
            enabler: ?Var = null,
        };

        /// `Component::evaluate` of a generated component: the body over the
        /// trace columns, then the fixed-size check when the height is fixed.
        pub fn evaluateComponent(self: *Self, function_index: u32) !void {
            const function = &self.source.functions[function_index];
            if (function.trace_type == .inline_fn) return error.NotAnExpression;
            _ = try self.call(function_index, self.data.traceColumns());
            if (function.log_height) |log_height| {
                const size_bit = try self.data.getNInstancesBit(self.ctx, log_height);
                try self.ctx.eq(size_bit, self.ctx.one());
            }
        }

        /// `<callee>::accumulate_constraints(inputs, ...)`. Returns the
        /// verifier output of an Inline function (scratch-owned) and an empty
        /// slice otherwise.
        pub fn call(self: *Self, function_index: u32, inputs: []const Var) EvalError![]const Var {
            const function = &self.source.functions[function_index];
            var frame: Frame = .{ .function = function };
            try self.bindInputs(&frame, inputs);
            try self.readExternalStates(&frame);
            for (self.projection.nameList(function.used_public_params)) |name| {
                try frame.params.put(self.scratch, name, try self.acc.getPublicParam(self.projection.str(name)));
            }
            for (function.steps.slice(projection_mod.Step, self.projection.steps)) |step| {
                try self.runStep(&frame, step);
            }
            const output = function.verifier_output orelse return &.{};
            return self.evalList(&frame, self.projection.exprs[output].array);
        }

        /// A function called by name, as the hand-written evaluators do.
        pub fn callByName(self: *Self, name: []const u8, inputs: []const Var) ![]const Var {
            const index = self.source.findFunction(self.projection, name) orelse return error.NotInline;
            if (self.source.functions[index].trace_type != .inline_fn) return error.NotInline;
            return self.call(index, inputs);
        }

        fn bindInputs(self: *Self, frame: *Frame, inputs: []const Var) !void {
            const function = frame.function;
            const states = self.projection.nameList(function.state_names);
            var rest = inputs;
            if (function.trace_type == .inline_fn) {
                const limbs = self.projection.nameList(function.verifier_input_limbs);
                if (inputs.len != limbs.len + 1 + states.len) return error.InputCountMismatch;
                for (limbs, inputs[0..limbs.len]) |name, v| try frame.names.put(self.scratch, name, v);
                frame.enabler = inputs[limbs.len];
                rest = inputs[limbs.len + 1 ..];
            } else if (inputs.len != states.len) return error.InputCountMismatch;
            for (states, rest) |name, v| try frame.names.put(self.scratch, name, v);
        }

        fn readExternalStates(self: *Self, frame: *Frame) !void {
            for (self.projection.nameList(frame.function.used_external_states)) |id| {
                const text = self.projection.str(id);
                const value = if (std.mem.eql(u8, text, "Seq"))
                    try component_utils.seqOfComponentSize(Ctx, self.ctx, self.data, self.acc.preprocessed_columns)
                else
                    try self.acc.getPreprocessedColumn(text);
                try frame.externals.put(self.scratch, id, value);
            }
        }

        fn runStep(self: *Self, frame: *Frame, step: projection_mod.Step) EvalError!void {
            switch (step) {
                .constraint => |expr| {
                    const value = try self.evalExpr(frame, expr);
                    try self.acc.addConstraint(self.ctx, value);
                },
                .intermediate => |intermediate| {
                    const names = self.projection.nameList(intermediate.felt_names);
                    switch (self.projection.exprs[intermediate.value]) {
                        .static_call => |call_expr| {
                            const results = try self.evalCall(frame, call_expr.callee, call_expr.args);
                            // `let [names..] = call(..).try_into().unwrap()`, or a bare call.
                            if (names.len != 0 and names.len != results.len) return error.CallResultCountMismatch;
                            if (names.len != 0) for (names, results) |name, v| try frame.names.put(self.scratch, name, v);
                        },
                        else => {
                            if (names.len != 1) return error.CallResultCountMismatch;
                            try frame.names.put(self.scratch, names[0], try self.evalExpr(frame, intermediate.value));
                        },
                    }
                },
                .lookup_term => |term| {
                    const felts = try self.evalList(frame, term.felts);
                    const multiplicity = try self.evalExpr(frame, term.multiplicity);
                    const numerator = switch (term.use_or_yield) {
                        .use => multiplicity,
                        .yield => try self.ctx.sub(self.ctx.zero(), multiplicity),
                    };
                    try self.acc.addToRelation(self.ctx, numerator, felts);
                },
            }
        }

        fn evalCall(self: *Self, frame: *Frame, callee: u32, args: projection_mod.Span) EvalError![]const Var {
            const inputs = try self.evalList(frame, args);
            return self.call(callee, inputs);
        }

        fn evalList(self: *Self, frame: *Frame, span: projection_mod.Span) EvalError![]Var {
            const items = self.projection.exprList(span);
            const values = try self.scratch.alloc(Var, items.len);
            for (items, values) |item, *v| v.* = try self.evalExpr(frame, item);
            return values;
        }

        /// The `eval!` expansion of one expression.
        fn evalExpr(self: *Self, frame: *Frame, id: ExprId) EvalError!Var {
            return switch (self.projection.exprs[id]) {
                .constant => |value| self.ctx.constant(QM31.fromBase(M31.fromCanonical(value))),
                .variable, .state => |name| frame.names.get(name) orelse error.UnboundName,
                .external_state => |name| frame.externals.get(name) orelse error.UnboundName,
                .public_param => |name| frame.params.get(name) orelse error.UnboundName,
                .enabler => frame.enabler orelse error.MissingEnabler,
                .binary => |node| blk: {
                    const lhs = try self.evalExpr(frame, node.lhs);
                    const rhs = try self.evalExpr(frame, node.rhs);
                    break :blk switch (node.op) {
                        .add => self.ctx.add(lhs, rhs),
                        .sub => self.ctx.sub(lhs, rhs),
                        .mul => self.ctx.mul(lhs, rhs),
                    };
                },
                .negate => |operand| blk: {
                    const value = try self.evalExpr(frame, operand);
                    break :blk self.ctx.sub(self.ctx.zero(), value);
                },
                .static_call, .array => error.NotAnExpression,
            };
        }
    };
}
