//! Offline export of exact parent AIR programs and independent rational oracles.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("stwo_prover_engine").air.component_prover;
const air = @import("../recursion/air/mod.zig");
const Airs = @import("../recursion/air/blake3_parent_row_storage.zig").Airs;
const Tables = @import("../air/lookups/tables/framework_export.zig");
const Table = @import("../air/lookups/tables/component.zig").LookupTableComponent;
const Relations = @import("../air/relation_challenges.zig").Relations;
const Schema = @import("../air/lookups/tables/schema.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub fn Collection(comptime Code: type) type {
    return struct { programs: [22]C.OwnedFrameworkPolynomialProgramV1, counts: [22][3]usize, entries: [22]Code.Entry };
}
/// All pointers remain owned by the supplied arena; no producer witness is used.
pub fn collect(comptime Code: type, temp: std.mem.Allocator) !*Collection(Code) {
    const result = try temp.create(Collection(Code));
    const programs = &result.programs;
    const counts = &result.counts;
    const entries = &result.entries;
    inline for (0..20) |i| {
        const Air = Airs[i];
        var definition = if (@typeInfo(@TypeOf(Air.build)).@"fn".params.len == 2) try Air.build(temp, .generated) else try Air.build(temp);
        defer definition.deinit();
        const direct = try air.direct_constraint_program.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        const relations = try air.universal_relation_binding.Binding(Air).authenticate(&definition);
        programs[i] = try air.framework_polynomial_export_v1.exportLocalPrepared(Air, temp, &direct, &relations);
        counts[i] = .{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
        entries[i] = .{ .program = &programs[i], .tree_column_counts = &counts[i] };
    }
    const relations = Relations.dummy();
    inline for (.{ Schema.Kind.bitwise, Schema.Kind.range_check_8_8 }, 20..) |kind, i| {
        const tuple = [_]usize{ 0, 1, 2, 3 };
        const arity = Schema.arity(kind);
        const component = try Table.initProver(kind, arity, tuple[0..arity], 0, 0, &relations, Q.one());
        counts[i] = .{ arity + 1, 1, 4 };
        programs[i] = try Tables.exportProgram(temp, &component, &counts[i]);
        entries[i] = .{ .program = &programs[i], .tree_column_counts = &counts[i] };
    }
    return result;
}
// Passed by the top-level product to avoid crossing its package boundary.
pub fn exportCatalog(comptime Code: type, a: std.mem.Allocator, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const collection = try collect(Code, temp);
    const entries = collection.entries;
    const source = try Code.generateLibrary(temp, &entries);
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "kernels.cu", .data = source });
    const Record = struct { executable_identity: []const u8, kernel: []const u8, abi_schema: u32 = 30, argument_count: u32 = 11, cache_key: u64 };
    var records: std.ArrayList(Record) = .empty;
    var unique: std.ArrayList(Code.Entry) = .empty;
    for (entries) |entry| {
        const id = try Code.identity(temp, entry);
        const id_hex = try std.fmt.allocPrint(temp, "{s}", .{std.fmt.bytesToHex(id, .lower)});
        var found = false;
        for (records.items) |record| if (std.mem.eql(u8, record.executable_identity, id_hex)) {
            found = true;
            break;
        };
        if (found) continue;
        try records.append(temp, .{ .executable_identity = id_hex, .kernel = try Code.kernelName(temp, entry), .cache_key = Code.cacheKey(id) });
        try unique.append(temp, entry);
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const document = .{ .version = @as(u32, 1), .target = "cuda", .scope = "riscv-recursive-parent-composition", .source_file = "kernels.cu", .source_sha256 = std.fmt.bytesToHex(digest, .lower), .programs = records.items, .dynamic_claims_and_challenges = true, .proof_acceptance_authority = false, .device_compiled = false, .device_executed = false };
    const json = try std.json.Stringify.valueAlloc(temp, document, .{ .whitespace = .indent_2 });
    try dir.writeFile(.{ .sub_path = "source_manifest.json", .data = json });
    var binary: std.Io.Writer.Allocating = .init(temp);
    defer binary.deinit();
    try word(&binary.writer, @intCast(unique.items.len * 6));
    for (unique.items, 0..) |entry, index| for (0..6) |variant| try oracleCase(temp, &binary.writer, entry.program, @intCast(index), @intCast(variant));
    try dir.writeFile(.{ .sub_path = "numeric.bin", .data = binary.written() });
    var runner: std.Io.Writer.Allocating = .init(temp);
    defer runner.deinit();
    try runner.writer.writeAll(@embedFile("cuda_framework_numeric_runner_v1.cpp"));
    try runner.writer.writeAll("\nconst void *kernel(unsigned i) { switch(i) {\n");
    for (records.items, 0..) |record, i| try runner.writer.print("case {d}: return (const void*){s};\n", .{ i, record.kernel });
    try runner.writer.writeAll("default: throw std::runtime_error(\"kernel ordinal\"); }}\n");
    try dir.writeFile(.{ .sub_path = "numeric_runner.cu", .data = runner.written() });
    std.debug.print("CUDA_FRAMEWORK_EXPORT programs={d} cases={d} source_bytes={d} vectors_bytes={d} source_sha256={s}\n", .{ records.items.len, unique.items.len * 6, source.len, binary.written().len, std.fmt.bytesToHex(digest, .lower) });
}
fn word(w: anytype, x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try w.writeAll(&b);
}
fn words(w: anytype, x: []const u32) !void {
    try word(w, @intCast(x.len));
    for (x) |v| try word(w, v);
}
fn qwords(a: std.mem.Allocator, values: []const Q) ![]u32 {
    const out = try a.alloc(u32, values.len * 4);
    for (values, 0..) |q, i| for (q.toM31Array(), 0..) |m, j| {
        out[i * 4 + j] = m.toU32();
    };
    return out;
}
fn evaluateNodes(out: []M, nodes: []const C.BasePolynomialNode, inputs: []const M) void {
    for (nodes, 0..) |n, i| out[i] = switch (n.op) {
        .constant => M.fromCanonical(n.value),
        .column => inputs[n.value],
        .add => out[n.lhs].add(out[n.rhs]),
        .sub => out[n.lhs].sub(out[n.rhs]),
        .mul => out[n.lhs].mul(out[n.rhs]),
        .neg => out[n.lhs].neg(),
    };
}
fn sample(index: usize, variant: u32) M {
    return M.fromU64((@as(u64, index) + 11) * 31337 + @as(u64, variant) * 100003 + (@as(u64, index) *% 0x9e3779b9));
}
fn oracleCase(a: std.mem.Allocator, w: anytype, p: *const C.OwnedFrameworkPolynomialProgramV1, kernel: u32, variant: u32) !void {
    const trace_log: u32 = if (variant < 3) 2 else 5;
    const log = trace_log + 1 + variant % 3;
    const rows = @as(usize, 1) << @intCast(log);
    var trees: [3][]u32 = undefined;
    var tree_counts: [3]usize = @splat(0);
    const offsets = try a.alloc(u64, p.inputs.len + p.interaction_columns.len);
    for (p.inputs, offsets[0..p.inputs.len]) |input, *offset| switch (input) {
        .profile_parameter => offset.* = std.math.maxInt(u64),
        .trace_column => |col| {
            offset.* = tree_counts[col.tree_index] * rows + 7;
            tree_counts[col.tree_index] += 1;
        },
    };
    for (p.interaction_columns, offsets[p.inputs.len..]) |col, *offset| {
        offset.* = tree_counts[col.tree_index] * rows + 7;
        tree_counts[col.tree_index] += 1;
    }
    for (&trees, tree_counts, 0..) |*tree, n, i| {
        tree.* = try a.alloc(u32, n * rows + 16);
        for (tree.*, 0..) |*v, j| v.* = sample(j + i * 100003, variant).toU32();
    }
    const profile = try a.alloc(M, p.profile_parameter_count);
    for (profile, 0..) |*v, i| v.* = sample(i + 911, variant);
    const rel = try a.alloc(Q, p.lookupParameterCount());
    for (rel, 0..) |*v, i| v.* = Q.fromM31Array(.{ sample(i, variant), sample(i + 233, variant), sample(i + 311, variant), sample(i + 499, variant) });
    const claims = try a.alloc(Q, p.batches.len);
    for (claims, 0..) |*v, i| v.* = Q.fromM31Array(.{ sample(i + 33, variant), sample(i + 7, variant), sample(i + 19, variant), sample(i + 71, variant) });
    const parameters = C.FrameworkPolynomialParametersV1{ .profile_values = profile, .relation_values = rel, .trace_log_size = trace_log, .claimed_sum = if (p.layout == .same_row_prefix_v1) claims[0] else Q.zero(), .batch_claims = if (p.layout == .independent_prefix_v1) claims else &.{} };
    try parameters.validate(p);
    const rel_payload = try a.alloc(Q, rel.len + parameters.claimPayloadCount(p));
    @memcpy(rel_payload[0..rel.len], rel);
    for (0..parameters.claimPayloadCount(p)) |i| rel_payload[rel.len + i] = try parameters.claimPayload(p, i);
    const powers = try a.alloc(Q, p.direct.roots.len + p.batches.len);
    for (powers, 0..) |*v, i| v.* = Q.fromM31Array(.{ sample(i + 1, variant), sample(i + 4, variant), sample(i + 8, variant), sample(i + 16, variant) });
    const initial = try a.alloc(u32, rows * 4);
    for (initial, 0..) |*v, i| v.* = sample(i + 641, variant).toU32();
    const expected = try a.dupe(u32, initial);
    const inputs = try a.alloc(M, p.inputs.len);
    const direct = try a.alloc(M, p.direct.nodes.len);
    const lookup = try a.alloc(M, p.lookup_nodes.len);
    const fractions = try a.alloc(Q, p.entries.len);
    const denominators = try a.alloc(Q, p.entries.len);
    const geometry = try core.poly.circle.quotient_geometry.derive(trace_log, log);
    const invs = core.poly.circle.quotient_geometry.words(geometry);
    for (0..rows) |row| {
        for (p.inputs, inputs, 0..) |input, *v, i| v.* = switch (input) {
            .profile_parameter => |idx| profile[idx],
            .trace_column => |col| M.fromCanonical(trees[col.tree_index][@as(usize, @intCast(offsets[i])) + row]),
        };
        evaluateNodes(direct, p.direct.nodes, inputs);
        evaluateNodes(lookup, p.lookup_nodes, inputs);
        var folded = Q.zero();
        for (p.direct.roots, 0..) |root, i| folded = folded.add(powers[powers.len - 1 - i].mulM31(direct[root]));
        var cursor: usize = 0;
        for (p.entries, 0..) |entry, i| {
            var denominator = rel[cursor].neg();
            for (entry.values[0..entry.arity], 0..) |value, j| denominator = denominator.add(rel[cursor + 1 + j].mulM31(lookup[value]));
            cursor += 1 + entry.arity;
            denominators[i] = denominator;
            fractions[i] = Q.fromBase(lookup[entry.numerator]).mul(try denominator.inv());
        }
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, log);
        var previous_current = Q.zero();
        for (p.batches, 0..) |batch, i| {
            var current_words: [4]M = undefined;
            var previous_words: [4]M = undefined;
            for (0..4) |j| {
                const slot = batch.interaction_column_start + j;
                const column = p.interaction_columns[slot];
                const offset: usize = @intCast(offsets[p.inputs.len + slot]);
                current_words[j] = M.fromCanonical(trees[column.tree_index][offset + row]);
                previous_words[j] = M.fromCanonical(trees[column.tree_index][offset + prior]);
            }
            const current = Q.fromM31Array(current_words);
            const previous = Q.fromM31Array(previous_words);
            var residual = if (p.layout == .independent_prefix_v1) current.sub(previous).add(claims[i].mulM31(inputs[p.is_first_input.?])) else current.sub(previous_current);
            if (p.layout == .same_row_prefix_v1 and i + 1 == p.batches.len) residual = residual.sub(previous).add(try parameters.claimedSumShift());
            var product = Q.one();
            for (batch.first_entry..batch.first_entry + batch.entry_count) |e| {
                residual = residual.sub(fractions[e]);
                product = product.mul(denominators[e]);
            }
            folded = folded.add(powers[p.batches.len - 1 - i].mul(residual.mul(product)));
            previous_current = current;
        }
        const value = folded.mulM31(M.fromCanonical(invs[row / (rows / geometry.count)]));
        for (value.toM31Array(), 0..) |m, j| expected[j * rows + row] = M.fromCanonical(initial[j * rows + row]).add(m).add(m).toU32();
    }
    try word(w, kernel);
    try word(w, @intCast(rows));
    try word(w, geometry.count);
    for (trees) |tree| try words(w, tree);
    try words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(offsets)));
    try words(w, @ptrCast(profile));
    try words(w, try qwords(a, rel_payload));
    try words(w, try qwords(a, powers));
    try words(w, &invs);
    try words(w, initial);
    try words(w, expected);
}
