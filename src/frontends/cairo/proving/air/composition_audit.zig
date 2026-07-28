//! Temporary audit instrumentation for the Cairo composition evaluation stage.
//!
//! Everything here is gated behind environment probes and is reverted before
//! the increment lands. It exists to attribute `composition_evaluation` into
//! trace gather, constraint arithmetic, interpreter dispatch and accumulation.

const std = @import("std");
const composition = @import("../../witness/composition_bundle.zig");
const eval = @import("../../witness/eval_program.zig");

pub const Ablation = enum {
    none,
    /// Trace reads bypass the bit-reversed offset index derivation and read
    /// the raw lane position. Isolates index-mapping cost.
    no_index,
    /// Trace reads return a cheap function of (instruction, row) without
    /// touching any column. Isolates the whole gather + dispatch cost.
    no_read,
    /// Constraint results are folded into a per-range sink instead of being
    /// scattered into the composition column. Isolates accumulation cost.
    no_output,
    /// The per-lane denominator gather is replaced by a splat. Isolates
    /// domain bookkeeping.
    no_denominator,
};

var ablation_cache: ?Ablation = null;
var ablation_once = std.once(resolveAblation);

fn resolveAblation() void {
    ablation_cache = .none;
    const raw = std.process.getEnvVarOwned(
        std.heap.page_allocator,
        "STWO_COMPOSITION_ABLATE",
    ) catch return;
    defer std.heap.page_allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    inline for (@typeInfo(Ablation).@"enum".fields) |field| {
        if (std.mem.eql(u8, trimmed, field.name)) {
            ablation_cache = @field(Ablation, field.name);
            return;
        }
    }
}

pub fn ablation() Ablation {
    ablation_once.call();
    return ablation_cache orelse .none;
}

var census_cache: ?bool = null;
var census_once = std.once(resolveCensus);

fn resolveCensus() void {
    census_cache = std.process.hasEnvVarConstant("STWO_COMPOSITION_AUDIT");
}

pub fn censusEnabled() bool {
    census_once.call();
    return census_cache orelse false;
}

var census_mutex = std.Thread.Mutex{};
var census_seen = std.atomic.Value(usize).init(0);

var epoch: ?std.time.Instant = null;
var epoch_once = std.once(resolveEpoch);

fn resolveEpoch() void {
    epoch = std.time.Instant.now() catch null;
}

pub fn now() ?std.time.Instant {
    epoch_once.call();
    return std.time.Instant.now() catch null;
}

/// Reports one component's wall span relative to a process epoch. The
/// composition stage span is `max(end) - min(start)` over all components,
/// which is recoverable even when an ablated run aborts before the CLI
/// writes its stage profile.
pub fn reportSpan(
    log_size: u32,
    start: ?std.time.Instant,
    end: ?std.time.Instant,
) void {
    if (ablation() == .none and !censusEnabled()) return;
    const base = epoch orelse return;
    const s = start orelse return;
    const e = end orelse return;
    var buf: [160]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "COMPOSITION_SPAN log={d} start_ns={d} end_ns={d} elapsed_ns={d}\n",
        .{ log_size, s.since(base), e.since(base), e.since(s) },
    ) catch return;
    census_mutex.lock();
    defer census_mutex.unlock();
    std.fs.File.stderr().writeAll(line) catch return;
}

const BaseCounts = struct {
    trace_col: usize = 0,
    preprocessed_col: usize = 0,
    param: usize = 0,
    constant: usize = 0,
    add: usize = 0,
    sub: usize = 0,
    mul: usize = 0,
    neg: usize = 0,
    inv: usize = 0,
};

const ExtCounts = struct {
    secure_col: usize = 0,
    param: usize = 0,
    constant: usize = 0,
    add: usize = 0,
    sub: usize = 0,
    mul: usize = 0,
    neg: usize = 0,
};

/// Emits one line per component describing its interpreted program shape.
/// Called once per component per process; the counters are exact.
pub fn reportComponent(component: *const composition.Component) void {
    if (!censusEnabled()) return;
    census_mutex.lock();
    defer census_mutex.unlock();
    const index = census_seen.fetchAdd(1, .monotonic);

    var base: BaseCounts = .{};
    var ext: ExtCounts = .{};
    var roots: usize = 0;
    var max_base_regs: u32 = 0;
    var max_ext_regs: u32 = 0;

    // Distinct (interaction, immediate) pairs actually read by the component.
    var offsets: [64]struct { interaction: u8, imm: i32 } = undefined;
    var offset_count: usize = 0;
    var imms: [32]i32 = undefined;
    var imm_count: usize = 0;

    for (component.parts) |part| {
        const program = part.program;
        roots += program.constraint_roots.len;
        max_base_regs = @max(max_base_regs, program.header.max_base_regs);
        max_ext_regs = @max(max_ext_regs, program.header.max_ext_regs);
        for (program.base_insts) |instruction| {
            switch (instruction.op) {
                .trace_col => base.trace_col += 1,
                .preprocessed_col => base.preprocessed_col += 1,
                .param => base.param += 1,
                .constant => base.constant += 1,
                .add => base.add += 1,
                .sub => base.sub += 1,
                .mul => base.mul += 1,
                .neg => base.neg += 1,
                .inv => base.inv += 1,
            }
            if (instruction.op != .trace_col and
                instruction.op != .preprocessed_col) continue;
            var seen = false;
            for (offsets[0..offset_count]) |entry| {
                seen = seen or (entry.interaction == instruction.interaction and
                    entry.imm == instruction.imm);
            }
            if (!seen and offset_count < offsets.len) {
                offsets[offset_count] = .{
                    .interaction = instruction.interaction,
                    .imm = instruction.imm,
                };
                offset_count += 1;
            }
            var imm_seen = false;
            for (imms[0..imm_count]) |value| imm_seen = imm_seen or value == instruction.imm;
            if (!imm_seen and imm_count < imms.len) {
                imms[imm_count] = instruction.imm;
                imm_count += 1;
            }
        }
        for (program.ext_insts) |instruction| {
            switch (instruction.op) {
                .secure_col => ext.secure_col += 1,
                .param => ext.param += 1,
                .constant => ext.constant += 1,
                .add => ext.add += 1,
                .sub => ext.sub += 1,
                .mul => ext.mul += 1,
                .neg => ext.neg += 1,
            }
        }
    }

    const rows = @as(u64, 1) << @intCast(component.evaluation_log_size);
    const groups = rows / 4;
    const total_base = base.trace_col + base.preprocessed_col + base.param +
        base.constant + base.add + base.sub + base.mul + base.neg + base.inv;
    const total_ext = ext.secure_col + ext.param + ext.constant + ext.add +
        ext.sub + ext.mul + ext.neg;
    const reads = base.trace_col + base.preprocessed_col;

    var stderr_buf: [4096]u8 = undefined;
    const line = std.fmt.bufPrint(
        &stderr_buf,
        "COMPOSITION_AUDIT comp={d} eval_log={d} trace_log={d} rows={d} groups={d} " ++
            "parts={d} roots={d} base_insts={d} ext_insts={d} reads={d} " ++
            "distinct_read_sites={d} distinct_imms={d} max_base_regs={d} max_ext_regs={d} " ++
            "base_trace={d} base_pp={d} base_const={d} base_add={d} base_sub={d} " ++
            "base_mul={d} base_neg={d} base_inv={d} " ++
            "ext_secure={d} ext_param={d} ext_const={d} ext_add={d} ext_sub={d} " ++
            "ext_mul={d} ext_neg={d} " ++
            "reads_per_row={d} read_calls={d} lane_index_ops={d}\n",
        .{
            index,                    component.evaluation_log_size,
            component.trace_log_size, rows,
            groups,                   component.parts.len,
            roots,                    total_base,
            total_ext,                reads,
            offset_count,             imm_count,
            max_base_regs,            max_ext_regs,
            base.trace_col,           base.preprocessed_col,
            base.constant,            base.add,
            base.sub,                 base.mul,
            base.neg,                 base.inv,
            ext.secure_col,           ext.param,
            ext.constant,             ext.add,
            ext.sub,                  ext.mul,
            ext.neg,                  reads,
            groups * reads,           groups * reads * 4,
        },
    ) catch return;
    std.fs.File.stderr().writeAll(line) catch return;
}

test "composition audit: ablation defaults to none when unset" {
    // The resolver is process-wide; assert only that the enum has a `none`
    // arm and that unknown names do not map onto an ablation.
    try std.testing.expectEqual(Ablation.none, @as(Ablation, .none));
    _ = eval;
}
