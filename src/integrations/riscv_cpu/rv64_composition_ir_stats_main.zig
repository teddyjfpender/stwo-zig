//! Exports every RV64 Word16 v3 component's composition through the symbolic
//! lane into `secure_polynomial_program_v2` and writes per-component kernel
//! weight statistics as JSON. Records shapes only; constructs no witness.
//! Usage: rv64-composition-ir-stats OUT.json
const std = @import("std");
const R = @import("composition_ir/record.zig");
const K = @import("composition_ir/case.zig");
const Core = @import("composition_ir/catalog.zig");
const Services = @import("composition_ir/catalog_services.zig");
const Truths = @import("composition_ir/catalog_truths.zig");
const A = @import("stwo_riscv_frontend").rv64_air;

/// M31-multiplication equivalents of one product, per secure field:
/// base x base = 1; base x secure = degree; secure x secure = Karatsuba
/// (QM31: 3 CM31 products of 3 = 9; OM31: 3 QM31 products of 9 = 27).
const Cost = struct { mixed: usize, secure: usize };
const QM31_COST = Cost{ .mixed = 4, .secure = 9 };
const OM31_COST = Cost{ .mixed = 8, .secure = 27 };

fn rowCost(s: R.ir.Stats, c: Cost) usize {
    // Expression products, plus the composition fold: one secure power times
    // each residual (mixed for base residuals, secure otherwise), plus the
    // final base-field vanishing-inverse scale of the folded secure value.
    const fold = (s.constraints - s.secure_roots) * c.mixed + s.secure_roots * c.secure;
    return s.base_multiplications + s.mixed_multiplications * c.mixed + s.secure_multiplications * c.secure + fold + c.mixed;
}

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputPath;
    var prng = std.Random.DefaultPrng.init(0x53544154);
    const rng = prng.random();
    var cases: std.ArrayList(K.Case) = .empty;
    defer {
        for (cases.items) |*c| c.deinit(a);
        cases.deinit(a);
    }
    var sources: std.ArrayList([]const u8) = .empty;
    defer sources.deinit(a);
    inline for (.{ .{ Core, "cpu_proof_core" }, .{ Services, "service_bridge" }, .{ Truths, "truth" } }) |entry| {
        const before = cases.items.len;
        try entry[0].all(a, rng, &cases);
        for (before..cases.items.len) |_| try sources.append(a, entry[1]);
    }
    // The wide-clock fused CPU exists only at log 23: shape statistics only.
    {
        var wide = try Core.cpu(a, rng, A.word16_execution.layout.MAX_LOG, true, false);
        errdefer wide.deinit(a);
        if (!std.mem.eql(u8, wide.name, "cpu.fused_tail.wide_clock")) {
            wide.deinit(a);
        } else {
            try cases.append(a, wide);
            try sources.append(a, "cpu_proof_core");
        }
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    const w = out.writer(a);
    try w.writeAll("{\n  \"schema\": \"stwo/rv64/composition-ir-stats/v1\",\n  \"ir\": \"secure_polynomial_program_v2\",\n");
    try w.writeAll("  \"notes\": [\n");
    try w.writeAll("    \"Per trace-domain row of the evaluation domain; nodes are distinct subexpressions after hash-consing and exact folding (x+0, x*1, x*0, x-x, literal folding); dead nodes removed.\",\n");
    try w.writeAll("    \"base = M31 values (mask reads, integer literals); secure = extension values (FS challenges, claims, publics are invocation parameters).\",\n");
    try w.writeAll("    \"m31_mul_equiv_per_row counts expression products plus the composition fold (power x residual) plus the vanishing-inverse scale: base*base=1, base*secure=degree, secure*secure=9 (QM31) / 27 (OM31).\",\n");
    try w.writeAll("    \"requested_lane_ops = arithmetic lane calls the native emitter makes before folding/CSE (an upper bound on unoptimised per-row work).\"\n  ],\n");
    try w.writeAll("  \"components\": [\n");
    var totals = struct { constraints: usize = 0, nodes: usize = 0 }{};
    for (cases.items, sources.items, 0..) |*c, source, i| {
        const p = &c.exported.program;
        const s = try p.stats(a);
        totals.constraints += s.constraints;
        totals.nodes += s.nodes;
        const shape = c.exported.shape;
        const parity = if (shape.log_size > 21) "shape_only" else "random_trace_bit_exact";
        try w.print("    {{\"name\": \"{s}\", \"group\": \"{s}\", \"proof\": \"{s}\", \"sample_log_size\": {d}, \"eval_log_size\": {d}, \"eval_rows_per_trace_row\": {d}, \"parity\": \"{s}\",\n", .{ c.name, c.group, source, shape.log_size, shape.eval_log, @as(usize, 1) << @intCast(shape.eval_log - shape.log_size), parity });
        try w.print("     \"constraints\": {d}, \"max_degree\": {d}, \"declared_degree_bound\": {?d}, \"degree_histogram\": [{d},{d},{d},{d},{d},{d},{d},{d}], \"secure_residuals\": {d},\n", .{ s.constraints, s.max_degree, shape.declared_degree, s.degree_histogram[0], s.degree_histogram[1], s.degree_histogram[2], s.degree_histogram[3], s.degree_histogram[4], s.degree_histogram[5], s.degree_histogram[6], s.degree_histogram[7], s.secure_roots });
        try w.print("     \"distinct_subexpressions\": {d}, \"requested_lane_ops\": {d}, \"base_additions\": {d}, \"secure_additions\": {d}, \"negations\": {d},\n", .{ s.nodes, c.exported.requested_ops, s.base_additions, s.secure_additions, s.negations });
        try w.print("     \"base_multiplications\": {d}, \"base_by_secure_multiplications\": {d}, \"secure_multiplications\": {d}, \"m31_mul_equiv_per_row_qm31\": {d}, \"m31_mul_equiv_per_row_om31\": {d},\n", .{ s.base_multiplications, s.mixed_multiplications, s.secure_multiplications, rowCost(s, QM31_COST), rowCost(s, OM31_COST) });
        try w.print("     \"columns_read\": {{\"fixed\": {d}, \"main\": {d}, \"interaction\": {d}}}, \"columns_declared\": {{\"fixed\": {d}, \"main\": {d}, \"interaction\": {d}}}, \"mask_inputs\": {d}, \"shifted_mask_inputs\": {d}, \"mask_offset_min\": {d}, \"mask_offset_max\": {d},\n", .{ s.columns_read[0], s.columns_read[1], s.columns_read[2], shape.widths[0], shape.widths[1], shape.widths[2], s.inputs, s.shifted_inputs, s.min_offset, s.max_offset });
        try w.print("     \"parameters\": {d}, \"literal_constants\": {d}, \"identity\": \"{s}\"}}{s}\n", .{ s.parameters, s.constants, std.fmt.bytesToHex(p.identity, .lower), if (i + 1 == cases.items.len) "" else "," });
    }
    try w.print("  ],\n  \"totals\": {{\"components\": {d}, \"constraints\": {d}, \"distinct_subexpressions\": {d}}}\n}}\n", .{ cases.items.len, totals.constraints, totals.nodes });
    try std.fs.cwd().writeFile(.{ .sub_path = args[1], .data = out.items });
    std.debug.print("wrote {d} components ({d} constraints, {d} IR nodes) to {s}\n", .{ cases.items.len, totals.constraints, totals.nodes, args[1] });
}
