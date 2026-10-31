//! Per-request ROM counts, with no request data in immutable program material.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Program = @import("program.zig").Program;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const CHUNK: usize = 4096;
pub const Source = struct {
    allocator: std.mem.Allocator,
    program: *const Program,
    counts: []const u64,
    main: []M,
    interaction: []M = &.{},
    dictionary: []Q = &.{},
    pub fn init(a: std.mem.Allocator, program: *const Program, counts: []const u64) !Source {
        const n = program.size();
        if (counts.len != n) return error.InvalidExecutionRomShape;
        if (!program.fixed_retired) try program.validateFixedWitness();
        if (program.fixed_retired and program.fixed.len != 0) return error.InvalidExecutionRomShape;
        var total: u64 = 0;
        for (0..n) |logical| {
            const p = X.layout.physical(logical, program.log_size);
            const count = counts[p];
            total = std.math.add(u64, total, count) catch return error.ExecutionRomMassExceeded;
            if (total >= core.fields.m31.Modulus) return error.ExecutionRomMassExceeded;
            if (count != 0) {
                const valid = if (program.fixed_retired) (try program.tupleAt(logical))[0] else program.fixed[p];
                if (valid.isZero()) return error.ExecutionRomMassExceeded;
            }
        }
        const main = try a.alloc(M, n);
        for (main, counts) |*value, count| value.* = M.fromCanonical(@intCast(count));
        return .{ .allocator = a, .program = program, .counts = counts, .main = main };
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.interaction);
        self.allocator.free(self.dictionary);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        if (tree == 0 and self.program.fixed_retired) return error.ExecutionFixedWitnessRetired;
        const data = switch (tree) {
            0 => self.program.fixed,
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidExecutionRomTree,
        };
        const n = self.program.size();
        if (data.len == 0 or data.len % n != 0) return error.InvalidExecutionRomPhase;
        const cols = try a.alloc(engine.pcs.ColumnEvaluation, data.len / n);
        for (cols, 0..) |*col, i| col.* = .{ .log_size = self.program.log_size, .values = data[i * n ..][0..n] };
        return cols;
    }
    pub fn generate(self: *Source, ch: @FieldType(X.types.Challenges, "rom")) !Q {
        if (self.interaction.len != 0 or self.dictionary.len != 0) return error.InvalidExecutionRomPhase;
        const a = self.allocator;
        const n = self.program.size();
        const dictionary = try a.alloc(Q, n);
        errdefer a.free(dictionary);
        const scratch = try a.alloc(Q, CHUNK);
        defer a.free(scratch);
        const output = try a.alloc(M, 8 * n);
        errdefer a.free(output);
        if (self.program.fixed_retired) {
            for (0..n) |logical| {
                const tuple = try self.program.tupleAt(logical);
                var d = ch.offset;
                for (ch.coefficients, tuple) |coef, value| d = d.sub(coef.mulM31(value));
                dictionary[X.layout.physical(logical, self.program.log_size)] = d;
            }
        } else try self.program.validateFixedWitness();
        var begin: usize = 0;
        while (begin < n) : (begin += CHUNK) {
            const count = @min(CHUNK, n - begin);
            if (!self.program.fixed_retired) for (0..count) |i| {
                const p = begin + i;
                var d = ch.offset;
                for (ch.coefficients, 0..) |coef, c| d = d.sub(coef.mulM31(self.program.fixed[c * n + p]));
                dictionary[p] = d;
            };
            try core.fields.batchInverseInPlace(Q, dictionary[begin..][0..count], scratch[0..count]);
            @memcpy(dictionary[begin..][0..count], scratch[0..count]);
        }
        var claim = Q.zero();
        for (dictionary, self.counts) |inverse, count| claim = claim.sub(inverse.mulM31(M.fromCanonical(@intCast(count))));
        var prefix = claim.neg();
        for (0..n) |i| {
            const p = X.layout.physical(i, self.program.log_size);
            const inverse = dictionary[p];
            prefix = prefix.sub(inverse.mulM31(M.fromCanonical(@intCast(self.counts[p]))));
            for (inverse.toM31Array(), 0..) |value, c| output[c * n + p] = value;
            for (prefix.toM31Array(), 0..) |value, c| output[(4 + c) * n + p] = value;
        }
        if (!prefix.isZero()) return error.InvalidExecutionRomLedger;
        self.dictionary = dictionary;
        self.interaction = output;
        return claim;
    }
};
