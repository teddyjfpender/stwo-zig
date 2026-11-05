//! Explicit beta16/q27/P20 PCS numerical oracle; four trees/masks/periodicity.
//! CPU source authority and GPU byte parity, not an AIR/execution proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Base = @import("rv64_pcs_fixture_main.zig");
const C = struct {
    pub const O = Base.O;
    pub const M = Base.M;
    pub const H = Base.H;
    pub const Point = Base.Point;
    pub const Channel = Base.Channel;
    pub const TreeVec = Base.TreeVec;
    pub const Scheme = Base.Scheme;
    pub const Verifier = Base.Verifier;
    pub const Reader = Base.Reader;
    pub const bases = Base.bases;
    pub const checkpoint = Base.checkpoint;
    pub const digest = Base.digest;
    pub const friMetadata = Base.friMetadata;
    pub const hashWords = Base.hashWords;
    pub fn config() core.pcs.PcsConfig {
        return .{ .pow_bits = 20, .fri_config = .{ .log_blowup_factor = 4, .log_last_layer_degree_bound = 0, .n_queries = 27, .fold_step = 4 } };
    }
};
const F = @import("rv64/fri.zig");
const T = @import("rv64/trace.zig");
const IO = @import("rv64/fixture_io.zig");
const O = C.O;
const M = C.M;
const H = C.H;
const Point = C.Point;
const Channel = C.Channel;
const TreeVec = C.TreeVec;
const a = std.heap.page_allocator;
const tree_degrees = [_][]const u32{ &.{ 3, 3, 7, 7 }, &.{ 5, 5, 9, 9, 9, 9 }, &.{ 5, 7, 9, 9 }, &([_]u32{9} ** 16) };
const output_log: u32 = 13;
fn initial() Channel {
    var c = Channel.init();
    c.mixU32s(&.{ 0x52564d53, 2 });
    return c;
}
fn masks(tree: usize, column: usize) []const isize {
    return switch (tree) {
        0 => switch (column) {
            0 => &.{},
            1 => &.{0},
            2 => &.{ 0, 2 },
            else => &.{-1},
        },
        1 => switch (column) {
            0 => &.{ 0, 2 },
            1 => &.{-1},
            2 => &.{ 0, -1 },
            3 => &.{0},
            4 => &.{2},
            else => &.{ 2, 0 },
        },
        2 => switch (column) {
            0 => &.{ -1, 0 },
            1 => &.{ 0, 2 },
            2 => &.{0},
            else => &.{2},
        },
        else => &.{0},
    };
}
fn offset(mask: isize) core.circle.CirclePointM31 {
    return core.poly.circle.canonic.CanonicCoset.new(9).step().mulSigned(mask);
}
fn pointsFor(channel: *Channel) !TreeVec([][]Point) {
    const base = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, channel.drawSecureFelt());
    const trees = try a.alloc([][]Point, tree_degrees.len);
    errdefer a.free(trees);
    var nt: usize = 0;
    errdefer for (trees[0..nt]) |columns| {
        for (columns) |p| a.free(p);
        a.free(columns);
    };
    for (tree_degrees, trees, 0..) |degrees, *columns, t| {
        columns.* = try a.alloc([]Point, degrees.len);
        var nc: usize = 0;
        errdefer {
            for (columns.*[0..nc]) |p| a.free(p);
            a.free(columns.*);
        }
        for (columns.*, 0..) |*p, c| {
            p.* = try a.alloc(Point, masks(t, c).len);
            nc += 1;
            for (masks(t, c), p.*) |m, *v| {
                const shift = offset(m);
                v.* = base.add(.{ .x = O.fromBase(shift.x), .y = O.fromBase(shift.y) });
            }
        }
        nt += 1;
    }
    return TreeVec([][]Point).initOwned(trees);
}
const Term = struct { source: u32, exponent: u32, original: ?u32 };
const Group = struct { shift: core.circle.CirclePointM31, degree: u32, terms: std.ArrayList(Term) = .empty };
fn add(groups: *std.ArrayList(Group), shift: core.circle.CirclePointM31, degree: u32, term: Term) !void {
    for (groups.items) |*g| if (g.degree == degree and g.shift.eql(shift)) {
        try g.terms.append(a, term);
        return;
    };
    try groups.append(a, .{ .shift = shift, .degree = degree });
    try groups.items[groups.items.len - 1].terms.append(a, term);
}
fn exportFixture(dir: std.fs.Dir, imported: bool) !void {
    var scheme = try C.Scheme.init(a, C.config());
    var scheme_owned = true;
    defer if (scheme_owned) scheme.deinit(a);
    var channel = initial();
    var coefficients: std.ArrayList(M) = .empty;
    defer coefficients.deinit(a);
    var sources: std.ArrayList(u32) = .empty;
    defer sources.deinit(a);
    var source_groups: std.ArrayList(u32) = .empty;
    defer source_groups.deinit(a);
    var trees: std.ArrayList(u32) = .empty;
    defer trees.deinit(a);
    var counts: std.ArrayList(u32) = .empty;
    defer counts.deinit(a);
    var groups: std.ArrayList(Group) = .empty;
    defer {
        for (groups.items) |*g| g.terms.deinit(a);
        groups.deinit(a);
    }
    var twiddles: std.ArrayList(M) = .empty;
    defer twiddles.deinit(a);
    var tw_offset: [10]u32 = @splat(0);
    var tw_count: [10]u32 = @splat(0);
    for ([_]u32{ 3, 5, 7, 9 }) |degree| {
        tw_offset[degree] = @intCast(twiddles.items.len);
        var tw = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(degree + 4).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        tw_count[degree] = @intCast(tw.twiddles.len);
        try twiddles.appendSlice(a, tw.twiddles);
    }
    var random = std.Random.DefaultPrng.init(0x62bbf39);
    var source_index: u32 = 0;
    var sample_index: u32 = 0;
    var exponent: u32 = 0;
    var source_eval_words: u32 = 0;
    var expected_roots: std.ArrayList(H.Hash) = .empty;
    defer expected_roots.deinit(a);
    for (tree_degrees, 0..) |degrees, tree| {
        const first_source = source_index;
        const first_group: u32 = @intCast(source_groups.items.len / 8);
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, degrees.len);
        defer a.free(columns);
        var done: usize = 0;
        defer for (columns[0..done]) |c| a.free(c.values);
        var column: usize = 0;
        while (column < degrees.len) {
            const degree = degrees[column];
            const start = column;
            const eval_offset = source_eval_words;
            while (column < degrees.len and degrees[column] == degree) : (column += 1) {
                const n = @as(usize, 1) << @intCast(degree);
                const coeff = try a.alloc(M, n);
                defer a.free(coeff);
                for (coeff) |*v| v.* = M.fromCanonical(random.random().uintLessThan(u32, core.fields.m31.Modulus));
                try sources.appendSlice(a, &.{ @intCast(coefficients.items.len), 0, 0, degree });
                try coefficients.appendSlice(a, coeff);
                const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(coeff);
                columns[column] = .{ .log_size = degree, .values = (try poly.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(degree).circleDomain())).values };
                done += 1;
                const ms = masks(tree, column);
                try counts.append(a, @intCast(ms.len));
                if (ms.len == 2) {
                    const periodic = core.poly.circle.canonic.CanonicCoset.new(output_log).step().repeatedDouble(degree + 4);
                    try add(&groups, offset(ms[1]).add(periodic), degree, .{ .source = source_index, .exponent = exponent, .original = null });
                    exponent += 1;
                }
                for (ms) |m| {
                    try add(&groups, offset(m), degree, .{ .source = source_index, .exponent = exponent, .original = sample_index });
                    exponent += 1;
                    sample_index += 1;
                }
                source_index += 1;
                source_eval_words += @as(u32, 1) << @intCast(degree + 4);
            }
            try source_groups.appendSlice(a, &.{ eval_offset, 0, degree, degree + 4, first_source + @as(u32, @intCast(start)), @intCast(column - start), tw_offset[degree], tw_count[degree] });
        }
        try trees.appendSlice(a, &.{ first_source, @intCast(degrees.len), first_group, @as(u32, @intCast(source_groups.items.len / 8)) - first_group, std.mem.max(u32, degrees) + 4, 0 });
        var builder = scheme.treeBuilder(a);
        defer builder.deinit();
        _ = try builder.extendColumns(columns);
        try builder.commit(&channel);
        try expected_roots.append(a, scheme.trees.items[tree].commitment.root());
    }
    const points = try pointsFor(&channel);
    const imported_channel = channel;
    const imported_point = points.items[0][1][0]; // receiver mask0 for this fixed fixture column
    scheme_owned = false;
    var extended = try scheme.proveValues(a, points, &channel);
    var owns_extended = true;
    defer if (owns_extended) extended.deinit(a);
    const json = try std.json.Stringify.valueAlloc(a, extended.proof, .{});
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = "native-reference.json", .data = json });
    var proof_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(json, &proof_hash, .{});
    var replay = initial();
    var verifier = try C.Verifier.init(a, C.config());
    defer verifier.deinit(a);
    for (expected_roots.items, tree_degrees) |root, degrees| try verifier.commit(a, root, degrees, &replay);
    const fresh_points = try pointsFor(&replay);
    const proof = extended.proof;
    extended.aux.deinit(a);
    owns_extended = false;
    try verifier.verifyValues(a, fresh_points, proof, &replay);
    if (!std.mem.eql(u8, &replay.inner.digest, &channel.inner.digest) or replay.inner.n_draws != channel.inner.n_draws) return error.NativeMaskedPcsChannelMismatch;
    var terms: std.ArrayList(u32) = .empty;
    defer terms.deinit(a);
    var deep_groups: std.ArrayList(u32) = .empty;
    defer deep_groups.deinit(a);
    var recipes: std.ArrayList(u32) = .empty;
    defer recipes.deinit(a);
    var deep_tw: std.ArrayList(u32) = .empty;
    defer deep_tw.deinit(a);
    const map = try a.alloc(u32, sample_index);
    defer a.free(map);
    @memset(map, std.math.maxInt(u32));
    var combined_coeff: u32 = 0;
    var combined_eval: u32 = 0;
    for (groups.items, 0..) |g, gi| {
        const first: u32 = @intCast(terms.items.len / 4);
        for (g.terms.items) |term| {
            if (term.original) |index| {
                if (map[index] != std.math.maxInt(u32)) return error.DuplicateOriginalSample;
                map[index] = @intCast(terms.items.len / 4);
            }
            try terms.appendSlice(a, &.{ term.source, @intCast(gi), term.exponent, 0 });
        }
        try deep_groups.appendSlice(a, &.{ first, @intCast(terms.items.len / 4), g.degree, g.degree + 4, combined_coeff, 0, combined_eval, 0 });
        try recipes.appendSlice(a, &.{ g.shift.x.v, g.shift.y.v, output_log - (g.degree + 4), g.degree });
        try deep_tw.appendSlice(a, &.{ tw_offset[g.degree], tw_count[g.degree] });
        combined_coeff += @as(u32, 8) << @intCast(g.degree);
        combined_eval += @as(u32, 8) << @intCast(g.degree + 4);
    }
    for (map) |index| if (index == std.math.maxInt(u32)) return error.MissingOriginalSample;
    const plan = try F.Plan.init(9, C.config().fri_config);
    var fri_desc: std.ArrayList(u32) = .empty;
    defer fri_desc.deinit(a);
    var fri_tw: std.ArrayList(M) = .empty;
    defer fri_tw.deinit(a);
    try C.friMetadata(plan, &fri_desc, &fri_tw);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564d53, 2, 0, 9, output_log, 4, 27, 4, source_index, exponent, @intCast(groups.items.len), @intCast(source_groups.items.len / 8), 4, sample_index, @intCast(plan.len), @intCast(coefficients.items.len), source_eval_words, combined_coeff, combined_eval, @intCast(twiddles.items.len), @intCast(fri_tw.items.len), @intFromBool(imported), 20, 0 });
    try C.checkpoint(w, if (imported) imported_channel else initial());
    if (imported) {
        try C.bases(w, &imported_point.x.toM31Array());
        try C.bases(w, &imported_point.y.toM31Array());
    }
    try IO.words(w, sources.items);
    try IO.words(w, terms.items);
    try IO.words(w, deep_groups.items);
    try IO.words(w, source_groups.items);
    try IO.words(w, trees.items);
    try IO.words(w, recipes.items);
    try IO.words(w, deep_tw.items);
    try IO.words(w, map);
    try IO.words(w, counts.items);
    try C.bases(w, coefficients.items);
    try C.bases(w, twiddles.items);
    try IO.words(w, fri_desc.items);
    try C.bases(w, fri_tw.items);
    const domain = core.poly.circle.canonic.CanonicCoset.new(output_log).circleDomain();
    for (0..@as(usize, 1) << output_log) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, output_log));
        try IO.words(w, &.{ p.x.v, p.y.v });
    }
    for (expected_roots.items) |root| try C.hashWords(w, root);
    try C.hashWords(w, proof_hash);
    try C.checkpoint(w, channel);
    try dir.writeFile(.{ .sub_path = "case-0.bin", .data = bytes.items });
    std.debug.print("PASS native masked PCS trees=4 sources={} samples={} terms={} groups={} periodic_terms={}\n", .{ source_index, sample_index, exponent, groups.items.len, exponent - sample_index });
}
const Assembly = @import("rv64/pcs_assembly.zig");
const Attack = enum { none, sample, sample_order, trace_value, fri_root, terminal, nonce, trace_root, tree_order };
fn verifyAttempt(shape: Assembly.Shape, data: Assembly.Input, attack: Attack, expected_hash: [32]u8, readback_path: []const u8) !void {
    var proof = try Assembly.assemble(a, shape, data);
    var owned = true;
    defer if (owned) proof.deinit(a);
    switch (attack) {
        .none => {},
        .sample => proof.sampled_values.items[0][1][0] = proof.sampled_values.items[0][1][0].add(O.one()),
        .sample_order => std.mem.swap(O, &proof.sampled_values.items[1][0][0], &proof.sampled_values.items[1][0][1]),
        .trace_value => proof.queried_values.items[0][0][0] = proof.queried_values.items[0][0][0].add(M.one()),
        .fri_root => proof.fri_proof.first_layer.commitment[0] ^= 1,
        .terminal => {
            const c = @constCast(proof.fri_proof.last_layer_poly.coefficients());
            c[0] = c[0].add(O.one());
        },
        .nonce => proof.proof_of_work += 1,
        .trace_root => proof.commitments.items[0][0] ^= 1,
        .tree_order => std.mem.swap(H.Hash, &proof.commitments.items[0], &proof.commitments.items[1]),
    }
    var actual_hash: [32]u8 = undefined;
    if (attack == .none) {
        const json = try std.json.Stringify.valueAlloc(a, proof, .{});
        defer a.free(json);
        std.crypto.hash.sha2.Sha256.hash(json, &actual_hash, .{});
        const path = try std.fmt.allocPrint(a, "{s}.native.json", .{readback_path});
        defer a.free(path);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = json });
    }
    var channel = initial();
    var verifier = try C.Verifier.init(a, C.config());
    defer verifier.deinit(a);
    for (proof.commitments.items, tree_degrees) |root, degrees| try verifier.commit(a, root, degrees, &channel);
    const points = try pointsFor(&channel);
    owned = false;
    verifier.verifyValues(a, points, proof, &channel) catch |err| {
        if (attack == .none) return err;
        std.debug.print("REJECT beta16 masked native PCS mutation={s} error={s}\n", .{ @tagName(attack), @errorName(err) });
        return;
    };
    if (attack != .none) return error.PcsMutationAccepted;
    if (!std.mem.eql(u8, &actual_hash, &expected_hash)) return error.NativePcsProofParityMismatch;
    std.debug.print("PASS beta16 masked GPU PCS proof native_verified=true native_proof_byte_parity=true trees=4\n", .{});
}
fn verifyFixture(fixture_path: []const u8, readback_path: []const u8) !void {
    var f = try C.Reader.init(fixture_path);
    defer f.deinit();
    var r = try C.Reader.init(readback_path);
    defer r.deinit();
    const h = try f.take(24);
    if (!std.mem.eql(u32, h[0..15], &.{ 0x52564d53, 2, 0, 9, 13, 4, 27, 4, 30, 41, 13, 8, 4, 35, 3 }) or h[21] > 1 or (h[22] != 20 or h[23] != 0)) return error.InvalidPcsFixture;
    _ = try f.take(9 + 16 * h[21] + h[8] * 4 + h[9] * 4 + h[10] * 8 + h[11] * 8 + h[12] * 6 + h[10] * 4 + h[10] * 2 + h[13] + h[8] + h[15] + h[19] + h[14] * 8 + h[20] + 2 * (@as(usize, 1) << output_log));
    const expected_steps = 16 - 5 * h[21];
    const expected_roots = try f.take(32);
    const expected_hash = C.digest(try f.take(8));
    const expected_channel = try f.take(9);
    if (f.pos != f.words.len) return error.InvalidPcsFixture;
    if (!std.mem.eql(u32, try r.take(14), &.{ 0x52564d4f, 2, 0, 30, 41, 13, 8, 4, 35, 3, 13, 27, 9, expected_steps })) return error.InvalidPcsReadback;
    const status = (try r.take(1))[0];
    const channel = try r.take(16);
    if (status != 0 or !std.mem.eql(u32, channel[0..9], expected_channel) or channel[9] != expected_steps or channel[10] != 0 or channel[11] != 0 or channel[12] != 17 + expected_steps or !std.mem.allEqual(u32, channel[13..], 0)) return error.NativePcsChannelMismatch;
    const roots = try r.take(32);
    if (!std.mem.eql(u32, roots, expected_roots)) return error.NativePcsRootMismatch;
    const samples = try r.take(35 * 8);
    const nonce = try r.take(2);
    const terminal = try r.take(8);
    const raw = try r.take(27);
    const plan = try F.Plan.init(9, C.config().fri_config);
    var layers: [3]F.LayerReadback = undefined;
    for (&layers, plan.layers[0..plan.len]) |*layer, layer_shape| {
        layer.* = .{ .root = (try r.take(8))[0..8].*, .values = try r.take(layer_shape.valueWords(27)), .paths = try r.take(layer_shape.pathWords(27)) };
    }
    var trees: [4]Assembly.Tree = undefined;
    var trace: [4]T.Readback = undefined;
    var orders: [4][16]u32 = undefined;
    var counts: [4][16]u32 = undefined;
    for (tree_degrees, 0..) |degrees, t| {
        for (degrees, 0..) |_, c| {
            orders[t][c] = @intCast(c);
            counts[t][c] = @intCast(masks(t, c).len);
        }
        trees[t] = .{ .coefficient_logs = degrees, .sorted_to_original = orders[t][0..degrees.len], .sample_counts = counts[t][0..degrees.len] };
        trace[t] = .{ .root = roots[t * 8 ..][0..8].*, .values = try r.take(degrees.len * 27), .paths = try r.take(27 * (std.mem.max(u32, degrees) + 4) * 8) };
    }
    if (r.pos != r.words.len) return error.InvalidPcsReadback;
    const shape = Assembly.Shape{ .config = C.config(), .degree_log = 9, .trees = &trees };
    const data = Assembly.Input{ .raw_queries = raw, .samples = samples, .trace = &trace, .fri = &layers, .terminal = terminal[0..8].*, .nonce = @as(u64, nonce[0]) | (@as(u64, nonce[1]) << 32) };
    for (std.enums.values(Attack)) |attack| try verifyAttempt(shape, data, attack, expected_hash, readback_path);
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "verify")) return verifyFixture(args[2], args[3]);
    if (args.len != 3 or (!std.mem.eql(u8, args[1], "export") and !std.mem.eql(u8, args[1], "export-imported"))) return error.ExpectedExportDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    try exportFixture(dir, std.mem.eql(u8, args[1], "export-imported"));
}
