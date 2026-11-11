//! Bind one component's authenticated C kernels once, then share immutable
//! metadata across bounded row workers. No trace or parameter work per row.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cairo = @import("stwo_cairo_frontend");
const aot = @import("circuit_composition_cpu_aot");
const E = @import("program.zig");
const P = @import("protocol.zig");
const N = cairo.proving.air.native_evaluator;
pub const ABI = N.Om31;
const Bundle = cairo.witness.composition_bundle;
const Domain = prover.air.accumulation.ForField(P.O);
pub const Poly = prover.air.component_trace.Poly;
pub const Resolver = struct {
    context: *const anyopaque,
    get: *const fn (*const anyopaque, u8, u32) anyerror!Poly,
};
pub const Read = struct { tree: u8, column: u32, offset: i32 };

pub fn kernel(p: E.Program) ?ABI.Kernel {
    if (comptime @hasDecl(aot, "om31Executor")) return aot.om31Executor().resolve(N.identity(p));
    return null;
}
pub fn enabled() bool {
    return @import("builtin").cpu.arch == .aarch64 and !std.process.hasEnvVarConstant("STWO_CIRCUIT_OM31_INTERPRETER");
}
/// First-appearance order is the emitter's. Each logical quartic INTER
/// coordinate reads both physical halves of its octic pack.
pub fn reads(a: std.mem.Allocator, p: E.Program) ![]Read {
    var out: std.ArrayList(Read) = .empty;
    errdefer out.deinit(a);
    for (p.base_insts) |i| {
        if (i.op != .trace_col and i.op != .preprocessed_col) continue;
        const low = if (i.interaction == 2) 8 * (i.a / 4) + i.a % 4 else i.a;
        try out.append(a, .{ .tree = i.interaction, .column = low, .offset = i.imm });
        if (i.interaction == 2) try out.append(a, .{ .tree = 2, .column = low + 4, .offset = i.imm });
    }
    return out.toOwnedSlice(a);
}

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    coefficients: []P.O,
    entries: []Entry,
    const Entry = struct { sites: []N.Column, range: ABI.Range, function: ABI.Kernel };

    pub fn init(a: std.mem.Allocator, captured: *const Bundle.Component, parameters: []const P.O, column: Domain.ColumnAccumulator, resolver: Resolver) !?Prepared {
        for (captured.parts) |part| if (kernel(part.program) == null) return null;
        const log = captured.evaluation_log_size;
        if (captured.trace_log_size < 4 or log != captured.trace_log_size + 1 or log >= 31 or column.random_coeff_powers.len != captured.n_constraints or captured.denominator_inverses.len != 2) return error.InvalidOm31NativeGeometry;
        const n = @as(usize, 1) << @intCast(log);
        if (column.col.len() != n) return error.InvalidOm31NativeGeometry;
        const coefficients = try a.alloc(P.O, column.random_coeff_powers.len);
        errdefer a.free(coefficients);
        for (coefficients, 0..) |*out, i| out.* = column.random_coeff_powers[coefficients.len - 1 - i];
        const entries = try a.alloc(Entry, captured.parts.len);
        errdefer a.free(entries);
        var made: usize = 0;
        errdefer for (entries[0..made]) |entry| a.free(entry.sites);
        for (entries, captured.parts) |*entry, part| {
            try E.validateLens(a, part.program);
            if (parameters.len != part.program.header.n_ext_params or part.program.header.n_base_params != 0 or part.rc_base > coefficients.len or part.program.constraint_roots.len > coefficients.len - part.rc_base) return error.InvalidOm31Parameters;
            const inputs = try reads(a, part.program);
            defer a.free(inputs);
            const sites = try a.alloc(N.Column, inputs.len);
            entry.* = .{ .sites = sites, .function = kernel(part.program).?, .range = .{
                .sites = sites.ptr,
                .parameters = @ptrCast(parameters.ptr),
                .coefficients = @ptrCast(coefficients.ptr),
                .denominators = captured.denominator_inverses.ptr,
                .output = undefined,
                .first = 0,
                .end = n,
                .evaluation_log = log,
                .trace_log = captured.trace_log_size,
                .constraint_base = part.rc_base,
                .additive = 1,
            } };
            made += 1;
            for (column.col.columns, &entry.range.output) |values, *out| out.* = @ptrCast(values.ptr);
            for (inputs, sites) |input, *site| {
                const poly = try resolver.get(resolver.context, input.tree, input.column);
                try poly.validate();
                if (poly.device != null or poly.values.len == 0) return error.Om31CircuitRequiresHostLde;
                if (poly.log_size > log) return error.InvalidOm31NativeGeometry;
                const shift = log - poly.log_size + 1;
                const last = (((n - 1) >> @intCast(shift)) << 1) + 1;
                if (last >= poly.values.len) return error.InvalidOm31NativeGeometry;
                site.* = .{ .values = @ptrCast(poly.values.ptr), .shift = shift };
            }
        }
        return .{ .allocator = a, .coefficients = coefficients, .entries = entries };
    }
    pub fn deinit(self: *Prepared) void {
        for (self.entries) |entry| self.allocator.free(entry.sites);
        self.allocator.free(self.entries);
        self.allocator.free(self.coefficients);
        self.* = undefined;
    }
    pub fn evaluateRange(self: *const Prepared, first: usize, end: usize) !void {
        if (first > end or first % 4 != 0 or end % 4 != 0) return error.InvalidOm31NativeGeometry;
        for (self.entries) |entry| {
            if (end > entry.range.end) return error.InvalidOm31NativeGeometry;
            var range = entry.range;
            range.first = first;
            range.end = end;
            entry.function(&range);
        }
    }
};

comptime {
    if (@sizeOf(P.O) != 32 or @offsetOf(P.O, "c1") != 16 or @sizeOf(P.Q) != 16 or @sizeOf(P.M) != 4) @compileError("OM31 native field ABI mismatch");
}
