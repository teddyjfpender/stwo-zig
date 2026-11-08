const std = @import("std");
const core = @import("stwo_core");
const T = @import("rv64/truth_domain_fixtures.zig");
const P = @import("rv64/composition_sparse.zig");
const Oracle = @import("rv64/joined_fixture_support.zig");
pub fn main() !void {
    const a = std.heap.page_allocator;
    var item = try T.record(a, 0);
    defer item.artifact.deinit();
    const p = &item.artifact.program;
    var plan = try P.init(a, p, 512);
    defer plan.deinit(a);
    try plan.validate(a, p);
    var cache = try P.cache(a, &plan, 1024);
    defer cache.deinit(a);
    try cache.validate(a, &plan);
    const values = try a.alloc(core.fields.om31.OM31, p.nodes.len);
    defer a.free(values);
    const inputs = try a.alloc(core.fields.om31.OM31, p.inputs.len);
    defer a.free(inputs);
    const roots = try a.alloc(core.fields.om31.OM31, p.roots.len);
    defer a.free(roots);
    const rebuilt = try a.alloc(core.fields.om31.OM31, p.roots.len);
    defer a.free(rebuilt);
    var rng = std.Random.DefaultPrng.init(0x535041525345);
    for (0..8) |trial| {
        for (p.parameters) |*v| v.* = Oracle.random(rng.random());
        for (inputs) |*v| v.* = core.fields.om31.OM31.fromBase(core.fields.m31.M31.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus)));
        p.evaluateRow(values, inputs, roots);
        @memset(rebuilt, core.fields.om31.OM31.zero());
        for (plan.terms) |term| rebuilt[term.root] = if (term.negative) rebuilt[term.root].sub(values[term.node]) else rebuilt[term.root].add(values[term.node]);
        for (roots, rebuilt) |x, y| if (!x.eql(y)) return error.SignedSparseCoverNumericalMismatch;
        std.debug.print("SIGNED_COVER numerical_trial={} roots={} terms={} pass=true\n", .{ trial, roots.len, plan.terms.len });
    }
    plan.terms[0].negative = !plan.terms[0].negative;
    var rejected = false;
    plan.validate(a, p) catch {
        rejected = true;
    };
    if (!rejected) return error.SignedSparseMutantAccepted;
    plan.terms[0].negative = !plan.terms[0].negative;
    var mutants: usize = 1;
    const saved_first = plan.terms[0];
    plan.terms[0].root = @intCast(p.roots.len);
    plan.validate(a, p) catch {
        mutants += 1;
    };
    plan.terms[0] = saved_first;
    const saved_second = plan.terms[1];
    plan.terms[1] = plan.terms[0];
    plan.validate(a, p) catch {
        mutants += 1;
    };
    plan.terms[1] = saved_second;
    const saved_terms = plan.terms;
    plan.terms = plan.terms[0 .. plan.terms.len - 1];
    plan.validate(a, p) catch {
        mutants += 1;
    };
    plan.terms = saved_terms;
    const saved_column = plan.groups[0].columns[0];
    plan.groups[0].columns[0] = @intCast(plan.columns.len);
    plan.validate(a, p) catch {
        mutants += 1;
    };
    plan.groups[0].columns[0] = saved_column;
    const saved_slot = cache.steps[0].column_slots[saved_column];
    cache.steps[0].column_slots[saved_column] = std.math.maxInt(u32);
    cache.validate(a, &plan) catch {
        mutants += 1;
    };
    cache.steps[0].column_slots[saved_column] = saved_slot;
    if (mutants != 6) return error.SparsePlanMutantAccepted;
    const data = try std.json.Stringify.valueAlloc(a, .{ .status = "CPU_source_and_numerical_qualified_GPU_pending", .source_identity = std.fmt.bytesToHex(p.identity, .lower), .plan_identity = std.fmt.bytesToHex(plan.identity, .lower), .program_nodes = p.nodes.len, .program_roots = p.roots.len, .input_masks = p.inputs.len, .columns = plan.columns.len, .union_columns = plan.union_columns, .terms = plan.terms.len, .groups = plan.groups.len, .column_cap = plan.column_cap, .cache_slots = cache.slots, .cache_fills = cache.fills, .LDE_duplication_ratio = @as(f64, @floatFromInt(cache.fills)) / @as(f64, @floatFromInt(plan.union_columns)), .widths = item.widths, .cover_trials = 8, .mutated_sign_rejected = rejected, .mutants_rejected = mutants }, .{ .whitespace = .indent_2 });
    defer a.free(data);
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2 and args.len != 3) return error.ExpectedReportPath;
    try std.fs.cwd().writeFile(.{ .sub_path = args[1], .data = data });
    if (args.len == 3) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        var tw = try @import("stwo_prover_engine").poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(20).circleDomain().half_coset);
        defer @import("stwo_prover_engine").poly.twiddles.deinitM31(a, &tw);
        try directory.writeFile(.{ .sub_path = "twiddles-20.bin", .data = std.mem.sliceAsBytes(tw.twiddles[tw.twiddles.len - (1 << 19) ..]) });
        const mapping = try std.json.Stringify.valueAlloc(a, .{ .plan = plan, .cache = cache, .inputs = p.inputs }, .{});
        defer a.free(mapping);
        try directory.writeFile(.{ .sub_path = "mapping.json", .data = mapping });
        for (plan.groups, 0..) |_, id| {
            var source: std.ArrayList(u8) = .empty;
            defer source.deinit(a);
            const name = try std.fmt.allocPrint(a, "stwo_rv64_truth0_sparse_{}", .{id});
            defer a.free(name);
            try @import("rv64/composition_sparse_codegen.zig").emit(a, source.writer(a), p, &plan, @intCast(id), name);
            const filename = try std.fmt.allocPrint(a, "group-{}.cu", .{id});
            defer a.free(filename);
            try directory.writeFile(.{ .sub_path = filename, .data = source.items });
        }
    }
}
