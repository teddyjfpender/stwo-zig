//! Shared owned trace fixture for opcode prepared-domain contract tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs = @import("stwo_core").pcs;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const trace = @import("../../runner/trace.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");

pub const OpcodeFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    preprocessed: [1]prover_component.Poly,
    main: [trace.MAX_FAMILY_COLUMNS]prover_component.Poly,
    secure: [opcode_interaction.MAX_COLUMNS]prover_component.Poly,
    trees: [3][]const prover_component.Poly,
    trace_data: prover_component.Trace,
    eval_log_size: u32,
    eval_size: usize,
    n_main: usize,
    n_interaction: usize,

    pub fn init(
        self: *@This(),
        allocator: std.mem.Allocator,
        family: trace.OpcodeFamily,
        log_size: u32,
    ) !void {
        const eval_log_size = log_size + 1;
        const eval_size = @as(usize, 1) << @intCast(eval_log_size);
        const n_main = trace.nColumnsForFamily(family);
        const n_interaction = opcode_entries.interactionColumnCount(family);
        const source_count = 1 + n_main + n_interaction;
        self.* = undefined;
        self.allocator = allocator;
        self.storage = try allocator.alloc(M31, source_count * eval_size);
        self.eval_log_size = eval_log_size;
        self.eval_size = eval_size;
        self.n_main = n_main;
        self.n_interaction = n_interaction;
        var source: usize = 0;
        self.preprocessed[0] = self.poly(source);
        source += 1;
        for (self.main[0..n_main]) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        for (self.secure[0..n_interaction]) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        self.trees = .{
            self.preprocessed[0..],
            self.main[0..n_main],
            self.secure[0..n_interaction],
        };
        self.trace_data = .{
            .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&self.trees),
        };
    }

    fn poly(self: *@This(), source: usize) prover_component.Poly {
        const start = source * self.eval_size;
        const values = self.storage[start .. start + self.eval_size];
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64((@as(u64, source) + 1) * 65_537 + row * 257 + 1);
        }
        return .{ .log_size = self.eval_log_size, .values = values };
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
