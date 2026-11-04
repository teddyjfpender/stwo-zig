//! CPU-only prototype: explicit canonical padding provenance, never a shortcut
//! for constraints. The full padded Circuit/PP remains the proof authority.
const std = @import("std");
const C = @import("../builder/context.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = @import("plan.zig");
const G = @import("../builder/circuit.zig");
const Finalize = @import("../common/finalize.zig");
pub const Error = error{ InvalidPaddingProvenance, PaddingOriginsRequired, PaddingRangeGpuUnsupported };
pub const Kind = enum(u32) { add_two, triple_zero, m31_zero, blake_zero };
pub const Range = struct {
    kind: Kind,
    first: u32,
    count: u32,
    first_gate: usize,
    gate_count: usize,
    pub fn value(self: Range) Q {
        return if (self.kind == .add_two) Q.fromU32Unchecked(2, 0, 0, 0) else Q.zero();
    }
};
const Snapshot = struct {
    variables: u32,
    eq: usize,
    add: usize,
    sub: usize,
    mul: usize,
    pointwise_mul: usize,
    triple: usize,
    m31: usize,
    blake: usize,
    permutations: usize,
    permutation_inputs: usize,
    permutation_outputs: usize,
    outputs: usize,
    constants: usize,
    origins: usize,
    fn read(ctx: *const C.Context(Q)) Snapshot {
        const circuit = &ctx.circuit;
        return .{ .variables = circuit.n_vars, .eq = circuit.eq.items.len, .add = circuit.add.items.len, .sub = circuit.sub.items.len, .mul = circuit.mul.items.len, .pointwise_mul = circuit.pointwise_mul.items.len, .triple = circuit.triple_xor.items.len, .m31 = circuit.m31_to_u32.items.len, .blake = circuit.blake_g_gate.items.len, .permutations = circuit.permutation.len(), .permutation_inputs = circuit.permutation.inputs.items.len, .permutation_outputs = circuit.permutation.outputs.items.len, .outputs = circuit.output.items.len, .constants = ctx.constants.count(), .origins = if (ctx.witness_metadata) |m| m.origins.items.len else 0 };
    }
};
pub const Provenance = struct {
    before: Snapshot,
    after: Snapshot,
    /// Only this producer wraps the original padding routine. Metadata is not
    /// accepted on faith: every use rechecks canonical gates and exact coverage.
    pub fn captureAndPad(ctx: *C.Context(Q), targets: Finalize.ComponentSizes) !Provenance {
        if (ctx.witness_metadata == null) return error.PaddingOriginsRequired;
        if (!ctx.finalized or !ctx.record_gates) return error.InvalidPaddingProvenance;
        const before = Snapshot.read(ctx);
        try Finalize.padToTargets(Q, ctx, targets);
        const self = Provenance{ .before = before, .after = Snapshot.read(ctx) };
        _ = try self.validate(ctx);
        return self;
    }
    pub fn validate(self: Provenance, ctx: *const C.Context(Q)) ![4]Range {
        if (!ctx.finalized or !ctx.record_gates or ctx.witness_metadata == null) return error.InvalidPaddingProvenance;
        if (!std.meta.eql(self.after, Snapshot.read(ctx))) return error.InvalidPaddingProvenance;
        const b = self.before;
        const e = self.after;
        if (b.variables < 3 or e.variables >= G.max_vars) return error.InvalidPaddingProvenance;
        for (ctx.constants.values()) |variable| if (variable.idx >= b.variables) return error.InvalidPaddingProvenance;
        for (ctx.witness_metadata.?.origins.items) |origin| if (origin.out >= b.variables) return error.InvalidPaddingProvenance;
        for (ctx.circuit.output.items) |variable| if (variable >= b.variables) return error.InvalidPaddingProvenance;
        if (b.variables > e.variables or b.eq > e.eq or b.add > e.add or b.triple > e.triple or b.m31 > e.m31 or b.blake > e.blake) return error.InvalidPaddingProvenance;
        inline for (.{ "sub", "mul", "pointwise_mul", "permutations", "permutation_inputs", "permutation_outputs", "outputs", "constants", "origins" }) |field| {
            if (@field(b, field) != @field(e, field)) return error.InvalidPaddingProvenance;
        }
        const zero = ctx.constants.get(C.constantKey(Q.zero())) orelse return error.InvalidPaddingProvenance;
        const one = ctx.constants.get(C.constantKey(Q.one())) orelse return error.InvalidPaddingProvenance;
        if (zero.idx != 0 or one.idx != 1) return error.InvalidPaddingProvenance;
        const widths = [_]u32{ 1, 1, 1, 4 };
        const starts = [_]usize{ b.add, b.triple, b.m31, b.blake };
        const ends = [_]usize{ e.add, e.triple, e.m31, e.blake };
        var ranges: [4]Range = undefined;
        var next: u32 = b.variables;
        for (&ranges, widths, starts, ends, std.enums.values(Kind)) |*range, width, first_gate, last_gate, kind| {
            const count = std.math.mul(u32, std.math.cast(u32, last_gate - first_gate) orelse return error.InvalidPaddingProvenance, width) catch return error.InvalidPaddingProvenance;
            range.* = .{ .kind = kind, .first = next, .count = count, .first_gate = first_gate, .gate_count = last_gate - first_gate };
            next = std.math.add(u32, next, count) catch return error.InvalidPaddingProvenance;
            if (next > e.variables) return error.InvalidPaddingProvenance;
        }
        if (next != e.variables) return error.InvalidPaddingProvenance;
        for (ctx.circuit.eq.items[b.eq..]) |gate| if (gate.in0 != 0 or gate.in1 != 0) return error.InvalidPaddingProvenance;
        for (ranges) |range| {
            for (0..range.gate_count) |i| {
                const index = range.first_gate + i;
                const output = range.first + @as(u32, @intCast(i)) * (if (range.kind == .blake_zero) @as(u32, 4) else 1);
                switch (range.kind) {
                    .add_two => {
                        const gate = ctx.circuit.add.items[index];
                        if (gate.in0 != 1 or gate.in1 != 1 or gate.out != output) return error.InvalidPaddingProvenance;
                    },
                    .triple_zero => {
                        const gate = ctx.circuit.triple_xor.items[index];
                        if (gate.input_a != 0 or gate.input_b != 0 or gate.input_c != 0 or gate.out != output) return error.InvalidPaddingProvenance;
                    },
                    .m31_zero => {
                        const gate = ctx.circuit.m31_to_u32.items[index];
                        if (gate.input != 0 or gate.out != output) return error.InvalidPaddingProvenance;
                    },
                    .blake_zero => {
                        const gate = ctx.circuit.blake_g_gate.items[index];
                        for (gate.inputs()) |input| if (input != 0) return error.InvalidPaddingProvenance;
                        if (gate.out_base != output) return error.InvalidPaddingProvenance;
                    },
                }
            }
        }
        return ranges;
    }
    /// Borrowed header/slices only. Never deinit this view; original ctx owns
    /// every buffer. Existing Schedule.build revalidates all prefix addresses
    /// against the smaller n_vars, including forbidden references into padding.
    fn prefix(self: Provenance, ctx: *const C.Context(Q)) C.Context(Q) {
        var out = ctx.*;
        const b = self.before;
        out.circuit.n_vars = b.variables;
        out.circuit.eq.items = out.circuit.eq.items[0..b.eq];
        out.circuit.add.items = out.circuit.add.items[0..b.add];
        out.circuit.triple_xor.items = out.circuit.triple_xor.items[0..b.triple];
        out.circuit.m31_to_u32.items = out.circuit.m31_to_u32.items[0..b.m31];
        out.circuit.blake_g_gate.items = out.circuit.blake_g_gate.items[0..b.blake];
        return out;
    }
};
pub const Plan = struct {
    prefix_plan: Schedule.Plan,
    provenance: Provenance,
    ranges: [4]Range,
    pub fn build(a: std.mem.Allocator, ctx: *const C.Context(Q), provenance: Provenance) !Plan {
        const ranges = try provenance.validate(ctx);
        const prefix = provenance.prefix(ctx);
        return .{ .prefix_plan = try Schedule.build(a, &prefix), .provenance = provenance, .ranges = ranges };
    }
    pub fn deinit(self: *Plan) void {
        self.prefix_plan.deinit();
        self.* = undefined;
    }
    /// No production factory accepts this prototype and no optional device
    /// range initializer has been implemented or qualified.
    pub fn requireGpuSupported(_: *const Plan) Error!void {
        return error.PaddingRangeGpuUnsupported;
    }
    /// CPU qualification replay only. Full padded constraint checking remains
    /// mandatory after filling exactly the validated, explicitly covered tail.
    pub fn evaluate(self: *const Plan, a: std.mem.Allocator, ctx: *const C.Context(Q)) ![]Q {
        const ranges = try self.provenance.validate(ctx);
        if (!std.meta.eql(ranges, self.ranges)) return error.InvalidPaddingProvenance;
        var prefix = self.provenance.prefix(ctx);
        // Allocate the final assignment once. Replay/check only the original
        // prefix gates first; range writes precede mandatory full padded check.
        prefix.circuit.n_vars = ctx.circuit.n_vars;
        const values = try Schedule.evaluate(a, &prefix, self.prefix_plan);
        errdefer a.free(values);
        for (ranges) |range| @memset(values[range.first .. range.first + range.count], range.value());
        if (try ctx.circuit.check(a, values) != null) return error.InvalidReconstructedWitness;
        return values;
    }
};

test {
    _ = @import("padding_plan_test.zig");
}
