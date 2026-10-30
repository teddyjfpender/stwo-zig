const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const R = @import("../resident_parent_child_transcript_v1.zig");
const Packet = @import("../resident_parent_child_packet_v1.zig");
const Native = @import("../../../frontends/riscv/prover/block_v7_native_proof_v1.zig");
const Profile = @import("../../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Support = @import("../../../frontends/riscv/prover/block_v7_execution_test_support.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("../../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
fn wordsDigest(d: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, d[i * 4 ..][0..4], .little);
    return out;
}
fn snapshot(out: []u32, ch: core.channel.blake3.Channel) void {
    @memcpy(out[0..8], &wordsDigest(ch.digest));
    out[8] = @truncate(ch.n_draws);
    out[9] = @truncate(ch.n_draws >> 32);
}
fn ref(v: R.Ref, raw: []const u32) u32 {
    return if (v.kind == 0) v.index else raw[v.index];
}
fn oracle(a: std.mem.Allocator, p: *const Packet.Owned, r: *const R.Owned) !struct { output: []u32, trace: []u32, end: core.channel.blake3.Channel } {
    const output = try a.alloc(u32, r.output_words);
    errdefer a.free(output);
    @memset(output, 0);
    const trace = try a.alloc(u32, r.trace_words);
    errdefer a.free(trace);
    @memset(trace, 0);
    var ch = core.channel.blake3.Channel{};
    var first = true;
    for (r.tasks) |t| {
        if (!first) snapshot(trace[t.trace_first..], ch);
        first = false;
        switch (t.kind) {
            0 => ch = .{},
            1, 2, 3, 4, 6 => {
                const values = try a.alloc(u32, t.count);
                defer a.free(values);
                for (values, r.refs[t.first..][0..t.count]) |*v, x| v.* = ref(x, p.words);
                switch (t.kind) {
                    1 => ch.mixU32s(values),
                    2 => {
                        const qs = try a.alloc(core.fields.qm31.QM31, values.len / 4);
                        defer a.free(qs);
                        for (qs, 0..) |*q, i| q.* = core.fields.qm31.QM31.fromU32Unchecked(values[4 * i], values[4 * i + 1], values[4 * i + 2], values[4 * i + 3]);
                        ch.mixFelts(qs);
                    },
                    3 => ch.mixU64(@as(u64, values[0]) | (@as(u64, values[1]) << 32)),
                    4 => {
                        var d: [32]u8 = undefined;
                        for (values, 0..) |v, i| std.mem.writeInt(u32, d[i * 4 ..][0..4], v, .little);
                        ch.mixRoot(d);
                    },
                    6 => {
                        const h = (core.channel.blake3.Frame{ .pow = .{ .state = ch.digest, .bits = t.aux, .nonce = @as(u64, values[0]) | (@as(u64, values[1]) << 32) } }).hash();
                        try std.testing.expect(@ctz(std.mem.readInt(u32, h[0..4], .little)) >= t.aux);
                    },
                    else => unreachable,
                }
            },
            5, 7 => {
                var pending: u32 = 1;
                var consumed: u32 = 0;
                var produced: usize = 0;
                for (0..t.attempt_count) |attempt| {
                    const at = t.attempt_first + 32 * attempt;
                    const h = wordsDigest((core.channel.blake3.Frame{ .draw = .{ .state = ch.digest, .index = ch.n_draws } }).hash());
                    @memcpy(trace[at..][0..8], &h);
                    var valid = true;
                    for (h, 0..) |v, i| {
                        const sample = core.channel.blake3.sampleWord(v);
                        valid = valid and sample != null;
                        trace[at + 8 + i] = if (sample) |s| s.v else 0;
                    }
                    trace[at + 16] = pending;
                    trace[at + 17] = @intFromBool(valid);
                    trace[at + 18] = @truncate(ch.n_draws);
                    trace[at + 19] = @truncate(ch.n_draws >> 32);
                    @memcpy(trace[at + 22 ..][0..8], &wordsDigest(ch.digest));
                    if (t.kind == 5) {
                        ch.n_draws += pending;
                        if (pending == 1 and valid) {
                            @memcpy(output[t.output..][0..t.count], trace[at + 8 ..][0..t.count]);
                            pending = 0;
                            consumed = @intCast(attempt + 1);
                        }
                    } else {
                        ch.n_draws += 1;
                        for (h) |v| {
                            if (produced == t.count) break;
                            output[t.output + produced] = v & ((@as(u32, 1) << @intCast(t.aux)) - 1);
                            produced += 1;
                        }
                    }
                    trace[at + 20] = @truncate(ch.n_draws);
                    trace[at + 21] = @truncate(ch.n_draws >> 32);
                    trace[at + 30] = pending;
                    trace[at + 31] = consumed;
                }
                if (t.kind == 5) try std.testing.expectEqual(@as(u32, 0), pending);
            },
            else => return error.InvalidTestTask,
        }
        snapshot(trace[t.trace_first + 10 ..], ch);
    }
    return .{ .output = output, .trace = trace, .end = ch };
}
fn writeWords(file: std.fs.File, words: []const u32) !void {
    var buf: [4]u8 = undefined;
    for (words) |w| {
        std.mem.writeInt(u32, &buf, w, .little);
        try file.writeAll(&buf);
    }
}
test "actual original native child packet transcript device vectors" {
    const a = std.testing.allocator;
    const code = [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
    const elf = @import("../../../frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var session = try @import("../../../frontends/riscv/runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(code.len - 1);
    defer executed.deinit();
    var counters = try @import("../../../frontends/riscv/air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    defer segment.deinit();
    const entries = [_]E.Entry{try segment.pin.entry(a)};
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, 1);
    var proof = try Native.For(Cpu).prove(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries);
    defer proof.deinit(a);
    var verified = try Native.For(Cpu).verifyAndCapture(a, &proof, segment.pin, epoch, &entries);
    defer verified.deinit();
    const profile = try Profile.Owned.derive(a, segment.pin, epoch, &entries, .{});
    defer profile.deinit();
    var packet = try Packet.Owned.initNative(a, profile, &proof, .{});
    defer packet.deinit();
    var replay = try R.Owned.initNative(a, profile, &packet, 2, .{});
    defer replay.deinit();
    var expected_plan = try @import("../../../frontends/riscv/recursion/air/block_v7_native_transcript_v1.zig").planReplay(a, profile, &verified, 2);
    defer expected_plan.deinit();
    try std.testing.expectEqualSlices(u8, &expected_plan.plan.id, &replay.plan_id);
    var frames = try @import("../resident_parent_child_frames_v1.zig").Owned.init(a, &replay, 1_000_000, 1 << 24);
    defer frames.deinit();
    const counts_expected = expected_plan.plan.fixed.hashCounts();
    try std.testing.expectEqual(counts_expected.g, frames.g_rows);
    try std.testing.expectEqual(counts_expected.xor, frames.xor_rows);
    var g_offset: usize = 0;
    for (frames.frames) |frame| {
        var local_hash = try @import("../../../frontends/riscv/recursion/air/blake3_hash_plan.zig").build(a, frame.words.len * 4);
        defer local_hash.deinit();
        const metadata = expected_plan.plan.fixed.hash_metadata orelse return error.MissingTestMetadata;
        for (metadata.g_rows[g_offset..][0..local_hash.g.len]) |fixed_row| try std.testing.expectEqual(frame.circuit, fixed_row[1].v);
        g_offset += local_hash.g.len;
    }

    const expected = try oracle(a, &packet, &replay);
    defer a.free(expected.output);
    defer a.free(expected.trace);
    try std.testing.expectEqualDeep(verified.final_channel, expected.end);
    for (expected_plan.plan.fixed.draw_outputs) |draw| {
        const values = try expected_plan.drawValues(draw);
        const at: usize = switch (draw.role) {
            .universal => |i| i * 8,
            .universal_half => |h| h.relation * 8 + @as(usize, h.half) * 4,
            .composition => replay.composition_first,
            .oods => replay.oods_first,
            .deep => replay.deep_first,
            .fri => |i| replay.fri_first + 4 * i,
            else => return error.InvalidTestRole,
        };
        for (values[0..draw.words], 0..) |v, j| try std.testing.expectEqual(v.v, expected.output[at + j]);
    }
    const path = std.process.getEnvVarOwned(a, "STWO_RESIDENT_CHILD_VECTOR") catch return;
    defer a.free(path);
    const fri_path = try std.fmt.allocPrint(a, "{s}.fri", .{path});
    defer a.free(fri_path);
    const fri_file = try std.fs.cwd().createFile(fri_path, .{});
    defer fri_file.close();
    try writeWords(fri_file, &.{ 0x42374652, @intCast(verified.proof.queries.raw.len), @intCast(verified.proof.fri.layers.len), profile.shape.lifting_log });
    for (verified.proof.queries.raw) |q| try writeWords(fri_file, &.{@intCast(q)});
    for (verified.proof.deep_answers) |v| for (v.toM31Array()) |f| {
        try writeWords(fri_file, &.{f.v});
    };
    for (verified.proof.fri.layers, 0..) |layer, index| {
        const raw_layer = if (index == 0) proof.stark.commitment_scheme_proof.fri_proof.first_layer else proof.stark.commitment_scheme_proof.fri_proof.inner_layers[index - 1];
        try writeWords(fri_file, &.{ layer.fold_width, @intCast(raw_layer.fri_witness.len), @intCast(layer.values.len) });
        for (layer.folding_alpha.toM31Array()) |f| try writeWords(fri_file, &.{f.v});
        for (raw_layer.fri_witness) |v| for (v.toM31Array()) |f| {
            try writeWords(fri_file, &.{f.v});
        };
        for (layer.values) |v| for (v.toM31Array()) |f| {
            try writeWords(fri_file, &.{f.v});
        };
    }
    const Paths = @import("../resident_parent_child_paths_v1.zig");
    const expanded = try a.alloc(Packet.Span, verified.proof.fri.layers.len);
    defer a.free(expanded);
    var values: std.ArrayList(u32) = .empty;
    defer values.deinit(a);
    for (verified.proof.fri.layers, expanded) |layer, *span| {
        span.* = .{ .first = @intCast(values.items.len), .count = @intCast(layer.values.len * 4) };
        for (layer.values) |v| for (v.toM31Array()) |f| {
            try values.append(a, f.v);
        };
    }
    var paths = try Paths.Owned.init(a, &packet, profile, expanded, .{});
    defer paths.deinit();
    const path_name = try std.fmt.allocPrint(a, "{s}.paths", .{path});
    defer a.free(path_name);
    const path_file = try std.fs.cwd().createFile(path_name, .{});
    defer path_file.close();
    const path_expected = try a.alloc(u32, paths.output_words);
    defer a.free(path_expected);
    @memset(path_expected, 0);
    var path_index: usize = 0;
    for (verified.proof.trace_paths, profile.shape.columns) |captured, logs| {
        if (logs.len == 0) continue;
        const t = paths.trees[path_index];
        path_index += 1;
        for (captured.siblings, 0..) |digest, i| for (0..8) |w| {
            path_expected[t.output_first + 8 * i + w] = std.mem.readInt(u32, digest[4 * w ..][0..4], .little);
        };
    }
    for (verified.proof.fri.layers) |layer| {
        const t = paths.trees[path_index];
        path_index += 1;
        for (0..packet.query_count) |query| for (layer.queryPath(query), 0..) |digest, level| for (0..8) |w| {
            path_expected[t.output_first + (query * t.depth + level) * 8 + w] = std.mem.readInt(u32, digest[4 * w ..][0..4], .little);
        };
    }
    // Independent CPU hash oracle is test-only; production emits no path values.
    for (paths.trees) |tree| {
        for (0..packet.query_count) |query| {
            const raw_query = verified.proof.queries.raw[query];
            const position: usize = if (tree.kind == 0) ((raw_query >> @intCast(tree.query_shift + 1)) << 1) | (raw_query & 1) else raw_query >> @intCast(tree.query_shift);
            var digest: [32]u8 = undefined;
            if (tree.kind == 0) {
                const leaf_values = try a.alloc(M, tree.columns_count);
                defer a.free(leaf_values);
                var rank: usize = 0;
                for (verified.proof.queries.unique) |unique| {
                    if (unique < raw_query) rank += 1;
                }
                for (paths.columns[tree.columns_first..][0..tree.columns_count], leaf_values) |column, *v| v.* = M.fromCanonical(packet.words[column.first + rank]);
                digest = (core.channel.blake3.Frame{ .leaf = leaf_values }).hash();
            } else {
                const hashes = try a.alloc([32]u8, tree.leaf_count);
                defer a.free(hashes);
                const leaf_values = try a.alloc(M, tree.leaf_width);
                defer a.free(leaf_values);
                for (hashes, 0..) |*h, leaf_index| {
                    for (leaf_values, 0..) |*v, w| v.* = M.fromCanonical(values.items[tree.values_first + (query * tree.leaf_count + leaf_index) * tree.leaf_width + w]);
                    h.* = (core.channel.blake3.Frame{ .leaf = leaf_values }).hash();
                }
                var count = hashes.len;
                while (count > 1) : (count /= 2) {
                    for (0..count / 2) |i| hashes[i] = (core.channel.blake3.Frame{ .node = .{ .left = hashes[2 * i], .right = hashes[2 * i + 1] } }).hash();
                }
                digest = hashes[0];
            }
            for (0..tree.depth + 1) |level| {
                for (0..8) |w| path_expected[tree.ancestor_first + (query * (tree.depth + 1) + level) * 8 + w] = std.mem.readInt(u32, digest[4 * w ..][0..4], .little);
                if (level == tree.depth) break;
                var sibling: [32]u8 = undefined;
                for (0..8) |w| std.mem.writeInt(u32, sibling[4 * w ..][0..4], path_expected[tree.output_first + (query * tree.depth + level) * 8 + w], .little);
                digest = if ((position >> @intCast(level)) & 1 == 0) (core.channel.blake3.Frame{ .node = .{ .left = digest, .right = sibling } }).hash() else (core.channel.blake3.Frame{ .node = .{ .left = sibling, .right = digest } }).hash();
            }
            if (tree.depth >= 2) {
                const branch = (position >> @intCast(tree.depth - 1)) & 1;
                const side = (position >> @intCast(tree.depth - 2)) & 1;
                path_expected[tree.frontier_first + branch] = 1;
                for (0..8) |w| {
                    path_expected[tree.frontier_first + 2 + (branch * 2 + side) * 8 + w] = path_expected[tree.ancestor_first + (query * (tree.depth + 1) + tree.depth - 2) * 8 + w];
                    path_expected[tree.frontier_first + 2 + (branch * 2 + (side ^ 1)) * 8 + w] = path_expected[tree.output_first + (query * tree.depth + tree.depth - 2) * 8 + w];
                    path_expected[tree.frontier_first + 34 + branch * 8 + w] = path_expected[tree.ancestor_first + (query * (tree.depth + 1) + tree.depth - 1) * 8 + w];
                    path_expected[tree.frontier_first + 34 + (branch ^ 1) * 8 + w] = path_expected[tree.output_first + (query * tree.depth + tree.depth - 1) * 8 + w];
                }
            }
        }
    }
    try writeWords(path_file, &.{ 0x42375041, @intCast(paths.trees.len), @intCast(paths.columns.len), @intCast(packet.words.len), packet.query_count, @intCast(values.items.len), paths.output_words });
    try path_file.writeAll(std.mem.sliceAsBytes(paths.trees));
    try path_file.writeAll(std.mem.sliceAsBytes(paths.columns));
    try writeWords(path_file, packet.words);
    for (verified.proof.queries.raw) |qpos| try writeWords(path_file, &.{@intCast(qpos)});
    try writeWords(path_file, values.items);
    try writeWords(path_file, path_expected);
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try writeWords(file, &.{ 0x42374346, @intCast(replay.tasks.len), @intCast(replay.refs.len), @intCast(packet.words.len), replay.output_words, replay.trace_words });
    try file.writeAll(std.mem.sliceAsBytes(replay.tasks));
    try file.writeAll(std.mem.sliceAsBytes(replay.refs));
    try writeWords(file, packet.words);
    try writeWords(file, expected.output);
    try writeWords(file, expected.trace);
    try writeWords(file, &wordsDigest(expected.end.digest));
    try writeWords(file, &.{ @truncate(expected.end.n_draws), @truncate(expected.end.n_draws >> 32) });
    std.debug.print("resident_child_vector tasks={d} refs={d} packet_words={d} output_words={d} trace_words={d}\n", .{ replay.tasks.len, replay.refs.len, packet.words.len, replay.output_words, replay.trace_words });
}
