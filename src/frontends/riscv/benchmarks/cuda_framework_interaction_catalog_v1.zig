//! Combined offline catalog. Original composition identities are unchanged;
//! interaction fractions and scans carry independent executable identities.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("stwo_prover_engine").air.component_prover;
const Catalog = @import("cuda_framework_catalog_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub fn exportCatalog(comptime Base: type, comptime Code: type, a: std.mem.Allocator, path: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const collection = try Catalog.collect(Base, temp);
    var source: std.Io.Writer.Allocating = .init(temp);
    defer source.deinit();
    try source.writer.writeAll(try Base.generateLibrary(temp, &collection.entries));
    try Code.appendLibrary(temp, &source.writer, &collection.entries);
    const Record = struct { executable_identity: []const u8, kernel: []const u8, abi_schema: u32, argument_count: u32, cache_key: u64 };
    var records: std.ArrayList(Record) = .empty;
    var fractions: std.ArrayList(Record) = .empty;
    var unique: std.ArrayList(Base.Entry) = .empty;
    for (collection.entries) |entry| {
        const id = try Base.identity(temp, entry);
        const hex = try std.fmt.allocPrint(temp, "{s}", .{std.fmt.bytesToHex(id, .lower)});
        var found = false;
        for (records.items) |record| if (std.mem.eql(u8, record.executable_identity, hex)) {
            found = true;
            break;
        };
        if (!found) try records.append(temp, .{ .executable_identity = hex, .kernel = try Base.kernelName(temp, entry), .abi_schema = 30, .argument_count = 11, .cache_key = Base.cacheKey(id) });
    }
    for (collection.entries) |entry| {
        const id = try Code.identity(temp, entry);
        const hex = try std.fmt.allocPrint(temp, "{s}", .{std.fmt.bytesToHex(id, .lower)});
        var found = false;
        for (fractions.items) |record| if (std.mem.eql(u8, record.executable_identity, hex)) {
            found = true;
            break;
        };
        if (found) continue;
        const record: Record = .{ .executable_identity = hex, .kernel = try Code.name(temp, id), .abi_schema = 31, .argument_count = 8, .cache_key = Base.cacheKey(id) };
        try fractions.append(temp, record);
        try records.append(temp, record);
        try unique.append(temp, entry);
    }
    var scans: [3][]const u8 = undefined;
    inline for (std.meta.tags(Code.Scan), 0..) |kind, i| {
        const id = try Code.scanIdentity(temp, kind);
        scans[i] = try Code.scanName(temp, kind, id);
        try records.append(temp, .{ .executable_identity = try std.fmt.allocPrint(temp, "{s}", .{std.fmt.bytesToHex(id, .lower)}), .kernel = scans[i], .abi_schema = 32, .argument_count = 6, .cache_key = Base.cacheKey(id) });
    }
    // Reject catalog collisions before producing an offline artifact.
    for (records.items, 0..) |record, i| for (records.items[0..i]) |prior| if (record.cache_key == prior.cache_key) return error.DuplicateFrameworkKernel;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source.written(), &digest, .{});
    const document = .{ .version = @as(u32, 2), .target = "cuda", .scope = "riscv-recursive-parent-composition-and-interaction", .source_file = "kernels.cu", .source_sha256 = std.fmt.bytesToHex(digest, .lower), .programs = records.items, .dynamic_claims_and_challenges = true, .proof_acceptance_authority = false, .device_compiled = false, .device_executed = false };
    var dir = try std.fs.cwd().makeOpenPath(path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "kernels.cu", .data = source.written() });
    try dir.writeFile(.{ .sub_path = "source_manifest.json", .data = try std.json.Stringify.valueAlloc(temp, document, .{ .whitespace = .indent_2 }) });
    var binary: std.Io.Writer.Allocating = .init(temp);
    defer binary.deinit();
    var cases: u32 = 0;
    for (unique.items) |entry| cases += 6 + @as(u32, if (entry.program.is_first_input != null) 1 else 0);
    try word(&binary.writer, cases);
    for (unique.items, 0..) |entry, index| {
        for (0..6) |variant| try oracleCase(temp, &binary.writer, entry.program, @intCast(index), @intCast(variant));
        if (entry.program.is_first_input != null) try oracleCase(temp, &binary.writer, entry.program, @intCast(index), 6);
    }
    try dir.writeFile(.{ .sub_path = "interaction_numeric.bin", .data = binary.written() });
    var runner: std.Io.Writer.Allocating = .init(temp);
    defer runner.deinit();
    try runner.writer.writeAll(@embedFile("cuda_framework_interaction_numeric_runner_v1.cpp"));
    try runner.writer.writeAll("\nconst void *fraction(unsigned i) {switch(i){\n");
    for (fractions.items, 0..) |record, i| try runner.writer.print("case {d}:return (const void*){s};\n", .{ i, record.kernel });
    try runner.writer.writeAll("default:throw std::runtime_error(\"fraction ordinal\");}}\nconst void *scan(unsigned i){switch(i){\n");
    for (scans, 0..) |name, i| try runner.writer.print("case {d}:return (const void*){s};\n", .{ i, name });
    try runner.writer.writeAll("default:throw std::runtime_error(\"scan ordinal\");}}\n");
    try dir.writeFile(.{ .sub_path = "interaction_numeric_runner.cu", .data = runner.written() });
    std.debug.print("CUDA_FRAMEWORK_INTERACTION_EXPORT programs={d} fractions={d} cases={d} source_bytes={d} vectors_bytes={d} source_sha256={s}\n", .{ records.items.len, fractions.items.len, cases, source.written().len, binary.written().len, std.fmt.bytesToHex(digest, .lower) });
}
fn word(w: anytype, x: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, x, .little);
    try w.writeAll(&bytes);
}
fn words(w: anytype, values: []const u32) !void {
    try word(w, @intCast(values.len));
    for (values) |x| try word(w, x);
}
fn sample(index: usize, variant: u32) M {
    return M.fromU64((@as(u64, index) + 11) * 31337 + @as(u64, variant) * 100003 + (@as(u64, index) *% 0x9e3779b9));
}
fn evaluate(out: []M, nodes: []const C.BasePolynomialNode, inputs: []const M) void {
    for (nodes, 0..) |n, i| out[i] = switch (n.op) {
        .constant => M.fromCanonical(n.value),
        .column => inputs[n.value],
        .add => out[n.lhs].add(out[n.rhs]),
        .sub => out[n.lhs].sub(out[n.rhs]),
        .mul => out[n.lhs].mul(out[n.rhs]),
        .neg => out[n.lhs].neg(),
    };
}
fn store(out: []u32, rows: usize, batch: usize, row: usize, q: Q) void {
    for (q.toM31Array(), 0..) |m, j| out[(4 * batch + j) * rows + row] = m.toU32();
}
fn load(out: []const u32, rows: usize, batch: usize, row: usize) Q {
    var m: [4]M = undefined;
    for (&m, 0..) |*v, j| v.* = M.fromCanonical(out[(4 * batch + j) * rows + row]);
    return Q.fromM31Array(m);
}
fn oracleCase(a: std.mem.Allocator, w: anytype, p: *const C.OwnedFrameworkPolynomialProgramV1, kernel: u32, variant: u32) !void {
    const log: u32 = switch (variant) {
        0 => 1,
        1 => 3,
        2 => 9,
        3 => 10,
        else => 3,
    };
    const rows = @as(usize, 1) << @intCast(log);
    var tree_counts: [2]usize = @splat(0);
    const offsets = try a.alloc(u64, p.inputs.len);
    for (p.inputs, offsets) |input, *offset| switch (input) {
        .profile_parameter => offset.* = 0,
        .trace_column => |column| {
            offset.* = tree_counts[column.tree_index] * rows + 7;
            tree_counts[column.tree_index] += 1;
        },
    };
    var trees: [2][]u32 = undefined;
    for (&trees, tree_counts, 0..) |*tree, count, i| {
        tree.* = try a.alloc(u32, count * rows + 16);
        for (tree.*, 0..) |*v, j| v.* = sample(j + i * 100003, variant).toU32();
    }
    if (p.is_first_input) |slot| {
        const column = p.inputs[slot].trace_column;
        for (0..rows) |row| trees[column.tree_index][@as(usize, @intCast(offsets[slot])) + row] = @intFromBool(row == 0);
    }
    const profile = try a.alloc(M, p.profile_parameter_count);
    for (profile, 0..) |*v, i| v.* = sample(i + 911, variant);
    const rel = try a.alloc(Q, p.lookupParameterCount());
    for (rel, 0..) |*v, i| v.* = Q.fromM31Array(.{ sample(i, variant), sample(i + 233, variant), sample(i + 311, variant), sample(i + 499, variant) });
    const claim_count: usize = if (p.layout == .same_row_prefix_v1) 1 else p.batches.len;
    const expected = try a.alloc(u32, p.interaction_columns.len * rows + 4 * claim_count);
    @memset(expected, 0);
    const inputs = try a.alloc(M, p.inputs.len);
    const lookup = try a.alloc(M, p.lookup_nodes.len);
    const fractions = try a.alloc(Q, p.entries.len);
    for (0..rows) |row| {
        for (p.inputs, inputs, 0..) |input, *v, i| v.* = switch (input) {
            .profile_parameter => |idx| profile[idx],
            .trace_column => |column| M.fromCanonical(trees[column.tree_index][@as(usize, @intCast(offsets[i])) + row]),
        };
        evaluate(lookup, p.lookup_nodes, inputs);
        var cursor: usize = 0;
        // Independent oracle sums individual rational entries; it does not
        // share paired/wide numerator lowering or device scan implementation.
        for (p.entries, 0..) |entry, i| {
            var den = rel[cursor].neg();
            for (entry.values[0..entry.arity], 0..) |value, j| den = den.add(rel[cursor + 1 + j].mulM31(lookup[value]));
            cursor += 1 + entry.arity;
            fractions[i] = Q.fromBase(lookup[entry.numerator]).mul(try den.inv());
        }
        var cumulative = Q.zero();
        for (p.batches, 0..) |batch, i| {
            var f = Q.zero();
            for (fractions[batch.first_entry .. batch.first_entry + batch.entry_count]) |v| f = f.add(v);
            cumulative = if (p.layout == .same_row_prefix_v1) cumulative.add(f) else f;
            store(expected, rows, i, row, cumulative);
        }
    }
    for (0..claim_count) |scan_batch| {
        const batch = if (p.layout == .same_row_prefix_v1) p.batches.len - 1 else scan_batch;
        var total = Q.zero();
        for (0..rows) |logical| {
            const row = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log), log);
            total = total.add(load(expected, rows, batch, row));
            store(expected, rows, batch, row, total);
        }
        for (total.toM31Array(), 0..) |m, j| expected[p.interaction_columns.len * rows + scan_batch * 4 + j] = m.toU32();
        if (p.layout == .same_row_prefix_v1) {
            const mean = total.mulM31(try M.fromU64(rows).inv());
            for (0..rows) |logical| {
                const row = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log), log);
                store(expected, rows, batch, row, load(expected, rows, batch, row).sub(mean.mulM31(M.fromU64(logical + 1))));
            }
        }
    }
    // Negative cases use the same valid original geometry, then inject a
    // zero denominator, noncanonical source, or wrong fixed first selector.
    var status: u32 = 0;
    if (variant == 4) {
        @memset(rel, Q.zero());
        status = 1;
    }
    if (variant == 5) {
        for (p.inputs, 0..) |input, i| switch (input) {
            .profile_parameter => {},
            .trace_column => |column| {
                if (p.is_first_input != null and p.is_first_input.? == i) continue;
                trees[column.tree_index][@intCast(offsets[i])] = core.fields.m31.Modulus;
                status = 4;
                break;
            },
        };
        if (status == 0) return error.MissingNegativeInput;
    }
    if (variant == 6) {
        const slot = p.is_first_input.?;
        const column = p.inputs[slot].trace_column;
        trees[column.tree_index][@intCast(offsets[slot])] = 0;
        status = 2;
    }
    try word(w, kernel);
    try word(w, @intCast(rows));
    try word(w, @intCast(p.batches.len));
    try word(w, @intFromEnum(p.layout));
    try word(w, status);
    for (trees) |tree| try words(w, tree);
    try words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(offsets)));
    try words(w, @ptrCast(profile));
    const relation_words = try a.alloc(u32, rel.len * 4);
    for (rel, 0..) |q, i| for (q.toM31Array(), 0..) |m, j| {
        relation_words[i * 4 + j] = m.toU32();
    };
    try words(w, relation_words);
    try words(w, expected);
}
