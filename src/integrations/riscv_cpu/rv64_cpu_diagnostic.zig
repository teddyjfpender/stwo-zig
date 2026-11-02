//! Debug native-row checker. This is diagnostic only: trace-row satisfaction
//! does not establish the composition degree bound or replace a physical proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.rv64_air;
const E = air.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const C = @import("rv64_keccak_cpu.zig");
const frame = air.full.frame;
pub const Options = struct { first_row: u32 = 0, row_count: ?u32 = null };
pub const Failure = struct {
    logical_row: u32,
    physical_row: usize,
    constraint_index: usize,
    residual: [4]u32,
    active: u32,
    pc: ?u64,
    opcode: ?u8,
    opcode_name: ?[]const u8,
    raw_instruction: ?u32,
};
pub const Result = struct { checked_rows: u32, total_rows: u32, constraint_count: usize, first_failure: ?Failure };
pub fn inspect(a: std.mem.Allocator, materials: *const C.PreparedMaterials, public: C.Public, trace: *const C.Trace, original_cpu_main: []const M, claims: C.Claims, challenges: C.Support.Challenges, cpu_interaction_columns: []const engine.pcs.ColumnEvaluation, options: Options) !Result {
    var components = try C.Support.Components.init(materials, public, claims, challenges);
    const component = &components.base.cpu;
    const n = @as(usize, 1) << @intCast(materials.base.log_size);
    if (trace.cpu.log_size != materials.base.log_size or original_cpu_main.len != component.mainCount() * n or cpu_interaction_columns.len < component.interactionCount() or options.first_row > n) return error.InvalidCpuDiagnosticShape;
    for (cpu_interaction_columns[0..component.interactionCount()]) |column| if (column.log_size != materials.base.log_size or column.values.len != n) return error.InvalidCpuDiagnosticShape;
    const count: usize = options.row_count orelse @as(u32, @intCast(n - options.first_row));
    if (count > n - options.first_row) return error.InvalidCpuDiagnosticShape;
    const current_main = try a.alloc(Q, component.mainCount());
    defer a.free(current_main);
    const previous_main = try a.alloc(Q, component.mainCount());
    defer a.free(previous_main);
    @memset(previous_main, Q.zero());
    const current = try a.alloc(Q, component.interactionCount());
    defer a.free(current);
    const previous = try a.alloc(Q, component.interactionCount());
    defer a.free(previous);
    @memset(previous, Q.zero());
    const residuals = try a.alloc(Q, component.constraint_count);
    defer a.free(residuals);
    var result = Result{ .checked_rows = 0, .total_rows = @intCast(n), .constraint_count = component.constraint_count, .first_failure = null };
    for (options.first_row..options.first_row + count) |logical| {
        const physical = air.witness.physical(logical, materials.base.log_size);
        const prior = air.witness.physical((logical + n - 1) % n, materials.base.log_size);
        for (current_main, 0..) |*value, column| {
            value.* = Q.fromBase(original_cpu_main[column * n + physical]);
            if (component.needsPreviousMain(column)) previous_main[column] = Q.fromBase(original_cpu_main[column * n + prior]);
        }
        for (current, cpu_interaction_columns[0..component.interactionCount()], 0..) |*value, column, i| {
            value.* = Q.fromBase(column.values[physical]);
            if (component.needsPreviousInteraction(i)) previous[i] = Q.fromBase(column.values[prior]);
        }
        var sink = E.Sink{ .values = residuals };
        component.emit(.{ E.q(@intCast(logical)), E.q(@intFromBool(logical == 0)), E.q(@intFromBool(logical + 1 == n)) }, current_main, previous_main, current, previous, &sink);
        if (sink.count != component.constraint_count) return error.InvalidCpuDiagnosticConstraintCount;
        result.checked_rows += 1;
        for (residuals, 0..) |residual, ordinal| if (!residual.isZero()) {
            var coordinates: [4]u32 = undefined;
            for (&coordinates, residual.toM31Array()) |*coordinate, value| coordinate.* = value.v;
            const pc = pcAt(original_cpu_main, materials.base.plan.main_count, n, physical, materials.base.plan.control_policy);
            var opcode: ?u8 = null;
            for (0..E.L.fixed.OPCODES) |op| if (original_cpu_main[(materials.base.plan.main_count + frame.SELECTORS + op) * n + physical].v == 1) {
                opcode = @intCast(op);
            };
            const rom_index: ?usize = if (pc) |address| materials.base.program.lookup(address) catch null else null;
            result.first_failure = .{ .logical_row = @intCast(logical), .physical_row = physical, .constraint_index = ordinal, .residual = coordinates, .active = original_cpu_main[(materials.base.plan.main_count + frame.ACTIVE) * n + physical].v, .pc = pc, .opcode = opcode, .opcode_name = if (opcode) |op| @tagName(@as(frontend.rv64.decode.Opcode, @enumFromInt(op))) else null, .raw_instruction = if (rom_index) |index| materials.base.program.decoded[index].raw else null };
            return result;
        };
    }
    return result;
}
fn pcAt(main: []const M, cpu_columns: usize, n: usize, row: usize, control: air.control_policy.Policy) ?u64 {
    var pc: u64 = 0;
    if (control == .limbs24_v2) {
        for (0..3) |limb| {
            const value = main[(cpu_columns + frame.ENTRY + 1 + limb) * n + row].v;
            if (value > (if (limb == 2) @as(u32, 0xffff) else 0xffffff)) return null;
            pc |= @as(u64, value) << @as(u6, @intCast(24 * limb));
        }
        return pc;
    }
    // Compact tuple starts with valid followed by all eight PC bytes.
    for (0..8) |byte| {
        const value = main[(cpu_columns + frame.ENTRY + 1 + byte) * n + row].v;
        if (value > 255) return null;
        pc |= @as(u64, value) << @as(u6, @intCast(8 * byte));
    }
    return pc;
}
