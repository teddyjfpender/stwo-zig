//! Cold dependency scheduler for the exact admitted parent rows. Numeric seeds
//! are source descriptors from raw-child/device producers, never CPU values.
//! Missing endpoints/cycles fail closed; no row is replaced by padding.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Program = @import("resident_parent_program_v1.zig");
const Registry = @import("resident_parent_wire_registry_v1.zig");
const Routes = @import("resident_parent_value_routes_v1.zig");
const Hash = @import("resident_parent_hash_plan_v1.zig");
const Arithmetic = @import("resident_parent_arithmetic_plan_v1.zig");
const Types = @import("resident_parent_composite_types_v1.zig");
pub const Seed = struct { key: u64, coordinates: [4]Routes.Source, word: ?Routes.Source = null };
pub const Prelude = struct { tasks: []const Types.Task, writes: []const Types.Write, phase: u32, resident_used: u32, graph_phase: [3]u32 };
pub const Limits = struct { max_rounds: usize = 4096, max_resident_words: usize = 1 << 26, max_tasks: usize = 1 << 22 };
pub const Owned = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    routes: *Routes.Plan,
    tasks: []Types.Task,
    writes: []Types.Write,
    hash_rows: []Types.HashRow,
    row_counts: [23]usize,
    resident_used: usize,
    pub fn deinit(self: *Owned) void {
        self.routes.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn compile(backing: std.mem.Allocator, p: *const Program.Owned, fixed: Storage.FixedTuple(false), registry: *const Registry.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Plan, seeds: []const Seed, prelude: Prelude, raw_bytes: usize, readonly_rows: usize, limits: Limits) !Owned {
        if (!std.mem.eql(u8, &registry.program_id, &p.view().identity) or hash.view().source_endpoints.len != hash.view().calls.len * 32 or arithmetic.graphs.len != 3) return error.InvalidResidentSchedule;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        // Route ownership survives moving this local arena into Owned. Its nested
        // allocator must therefore refer to the stable caller, not &arena.
        var s = Builder{ .a = a, .program = p, .registry = registry, .hash = hash, .limits = limits, .phase = prelude.phase, .resident = prelude.resident_used, .rows = undefined, .offsets = undefined, .done = undefined, .heads = undefined, .next = undefined, .hash_done = try a.alloc(bool, hash.view().calls.len), .routes = try Routes.Builder.init(backing, p, .{ .raw_bytes = raw_bytes, .resident_words = limits.max_resident_words, .main_words = registry.main_words, .arithmetic_words = arithmetic.value_words, .hash_words = hash.view().wire_count, .readonly_words = readonly_rows * 4 }, .{}) };
        defer s.routes.deinit();
        @memset(s.hash_done, false);
        try s.tasks.appendSlice(a, prelude.tasks);
        try s.writes.appendSlice(a, prelude.writes);
        var total: usize = 0;
        inline for (Storage.Airs, 0..) |_, i| {
            s.rows[i] = fixed[i].len;
            s.offsets[i] = total;
            total += fixed[i].len;
        }
        s.done = try a.alloc(bool, total);
        @memset(s.done, false);
        s.heads = try a.alloc(u32, total);
        @memset(s.heads, std.math.maxInt(u32));
        s.next = try a.alloc(u32, registry.candidates.len);
        for (registry.candidates, 0..) |c, i| {
            const row = s.offsets[c.cohort] + c.row;
            s.next[i] = s.heads[row];
            s.heads[row] = @intCast(i);
        }
        for (seeds) |seed| try s.put(seed);
        // Immutable public boundaries have exact fixed bytes/field coordinates.
        for (fixed[2]) |row| if (row[0].v == 1) {
            var cs: [4]Routes.Source = undefined;
            for (&cs, row[4..8]) |*out, m| out.* = Routes.Source.constant(m.v);
            try s.put(.{ .key = key(row[1].v, row[2].v), .coordinates = cs });
        };
        // All original graph nodes are device-owned; no graph arithmetic is replayed
        // while scheduling row writers. Prelude must actually execute these graphs.
        for (arithmetic.graphs, 0..) |g, graph| for (0..g.node_count) |node| {
            var cs: [4]Routes.Source = undefined;
            for (&cs, 0..) |*out, limb| out.* = Routes.Source.arithmetic(@intCast(try arithmetic.valueWord(graph, @intCast(node), @intCast(limb))), prelude.graph_phase[graph]);
            try s.put(.{ .key = key(@intCast(1500 + 2 * graph), @intCast(node)), .coordinates = cs });
        };
        const arithmetic_phase = @max(prelude.graph_phase[0], @max(prelude.graph_phase[1], prelude.graph_phase[2])) + 1;
        try s.routes.appendArithmetic(arithmetic, fixed, arithmetic_phase);
        inline for (.{ 3, 4, 5, 18, 19 }) |cohort| for (0..fixed[cohort].len) |row| try s.mark(cohort, row, arithmetic_phase);
        s.phase = @max(s.phase, arithmetic_phase + 1);
        if (readonly_rows != s.rows[16] or s.rows[16] != s.rows[17]) return error.InvalidResidentSchedule;
        var readonly_done = s.rows[16] == 0;
        var rounds: usize = 0;
        while (!std.mem.allEqual(bool, s.done, true)) {
            if (rounds == limits.max_rounds) return error.ResidentScheduleResourceLimit;
            rounds += 1;
            var progressed = false;
            const phase = s.phase;
            // Independent compression tasks consume only canonical namespaced initial
            // words. Their G/XOR destination maps preserve the original partition order.
            for (s.hash_done, 0..) |done, i| {
                if (done) continue;
                var values: [32]Routes.Source = undefined;
                var ready = true;
                for (&values, hash.view().source_endpoints[i * 32 ..][0..32]) |*out, endpoint| {
                    const v = s.values.get(endpoint) orelse {
                        ready = false;
                        break;
                    };
                    out.* = (try s.word(v, phase)) orelse {
                        ready = false;
                        break;
                    };
                }
                if (!ready) continue;
                const first = s.writes.items.len;
                for (values, 0..) |source, j| try s.writes.append(a, .{ .source = source, .destination = .hash_bytes, .byte_offset = @intCast(i * 128 + j * 4), .bytes = 4, .phase = phase });
                try s.tasks.append(a, .{ .phase = phase, .operation = .{ .write = .{ .first = @intCast(first), .count = 32 } } });
                try s.tasks.append(a, .{ .phase = phase + 1, .operation = .{ .hash_frame = @intCast(i) } });
                const scatter_first = s.hash_rows.items.len;
                for (0..56) |j| {
                    const target = s.gRow(i * 56 + j);
                    try s.hash_rows.append(a, .{ .kind = 0, .source_logical_row = @intCast(i * 56 + j), .destination_cohort = target.cohort, .destination_logical_row = target.row });
                    try s.mark(target.cohort, target.row, phase + 2);
                }
                for (0..16) |j| {
                    try s.hash_rows.append(a, .{ .kind = 1, .source_logical_row = @intCast(i * 16 + j), .destination_cohort = 1, .destination_logical_row = @intCast(i * 16 + j) });
                    try s.mark(1, i * 16 + j, phase + 2);
                }
                try s.tasks.append(a, .{ .phase = phase + 2, .operation = .{ .scatter_hash = .{ .first = @intCast(scatter_first), .count = 72 } } });
                for (hash.view().output_endpoints[i * 16 ..][0..16], 0..) |endpoint, j| {
                    const index = hash.view().calls[i].output[j];
                    var cs: [4]Routes.Source = undefined;
                    for (&cs, 0..) |*out, limb| out.* = .{ .kind = @intFromEnum(Routes.Kind.hash_byte), .index = index, .aux = @intCast(limb), .ready_phase = phase + 2 };
                    try s.put(.{ .key = endpoint, .coordinates = cs, .word = Routes.Source.hashWord(index, phase + 2) });
                }
                s.hash_done[i] = true;
                progressed = true;
            }
            inline for (.{ 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17 }) |cohort| for (fixed[cohort], 0..) |row, index| {
                if (s.done[s.offsets[cohort] + index]) continue;
                var refs: [Routes.dynamicWordCount(cohort)]Routes.Source = undefined;
                var ready = true;
                if (cohort == 2 or cohort == 9 or (cohort == 12 and row[5].v == 0)) {
                    const k = if (cohort == 2) key(row[1].v, row[2].v) else if (cohort == 9) key(row[1].v, row[2].v) else key(row[0].v, row[1].v);
                    if (s.values.get(k)) |v| {
                        if (cohort == 2) refs = v.coordinates else if (cohort == 9) {
                            refs[0] = (try s.word(v, phase)) orelse blk: {
                                ready = false;
                                break :blk Routes.Source.constant(0);
                            };
                        } else refs[0] = v.coordinates[0];
                    } else ready = false;
                } else {
                    const args = try registry.directArguments(p, cohort, @intCast(index));
                    for (args, &refs) |arg, *out| {
                        var cs: [4]Routes.Source = @splat(Routes.Source.constant(0));
                        for (arg.coordinates, 0..) |coordinate, limb| if (coordinate) |c| {
                            const weight = registry.expressions[c.weight];
                            if (weight.op == @intFromEnum(Registry.Op.constant) and weight.value == 0) continue;
                            const v = s.values.get(c.endpoint) orelse {
                                ready = false;
                                break;
                            };
                            cs[limb] = v.coordinates[c.limb];
                        };
                        if (!ready) break;
                        out.* = if (arg.is_packed) (try s.word(.{ .key = 0, .coordinates = cs }, phase)) orelse {
                            ready = false;
                            break;
                        } else cs[0];
                    }
                }
                if (!ready) continue;
                for (refs) |r| if (r.ready_phase > phase) {
                    ready = false;
                    break;
                };
                if (!ready) continue;
                try s.routes.append(cohort, @intCast(index), row, &refs, phase + 1, try s.routes.mainOffset(cohort));
                try s.mark(cohort, index, phase + 1);
                progressed = true;
            };
            if (!readonly_done and std.mem.allEqual(bool, s.done[s.offsets[17]..][0..s.rows[17]], true)) {
                if (readonly_rows != s.rows[16]) return error.InvalidResidentSchedule;
                try s.tasks.append(a, .{ .phase = phase + 2, .operation = .readonly });
                for (fixed[16], 0..) |row, index| {
                    var refs: [4]Routes.Source = undefined;
                    for (&refs, 0..) |*out, j| out.* = Routes.Source.readonlyWord(@intCast(index * 4 + j), phase + 2);
                    try s.routes.append(16, @intCast(index), row, &refs, phase + 3, try s.routes.mainOffset(16));
                    try s.mark(16, index, phase + 3);
                }
                readonly_done = true;
                progressed = true;
            }
            if (!progressed) {
                for (s.hash_done, 0..) |done, call| {
                    if (done) continue;
                    for (hash.view().source_endpoints[call * 32 ..][0..32]) |endpoint| if (!s.values.contains(endpoint)) {
                        std.debug.print("RESIDENT_SCHEDULE_HASH_INPUT call={d} endpoint={d}/{d}\n", .{ call, endpoint >> 32, @as(u32, @truncate(endpoint)) });
                    };
                }
                inline for (Storage.Airs, 0..) |_, cohort| {
                    var missing: usize = 0;
                    for (s.done[s.offsets[cohort]..][0..s.rows[cohort]]) |done| missing += @intFromBool(!done);
                    if (missing != 0) {
                        std.debug.print("RESIDENT_SCHEDULE_BLOCKED cohort={d} rows={d}\n", .{ cohort, missing });
                        var emitted: usize = 0;
                        for (fixed[cohort], 0..) |row, index| {
                            if (s.done[s.offsets[cohort] + index]) continue;
                            if (emitted >= 3) break;
                            emitted += 1;
                            if (cohort == 2 or cohort == 9 or cohort == 12) {
                                const endpoint = if (cohort == 12) key(row[0].v, row[1].v) else key(row[1].v, row[2].v);
                                std.debug.print("RESIDENT_SCHEDULE_ENDPOINT cohort={d} row={d} endpoint={d}/{d} available={any}\n", .{ cohort, index, endpoint >> 32, @as(u32, @truncate(endpoint)), s.values.contains(endpoint) });
                            } else if (cohort >= 6 and cohort <= 17 and cohort != 16) {
                                const args = registry.directArguments(p, cohort, @intCast(index)) catch continue;
                                for (args) |arg| for (arg.coordinates) |coordinate| if (coordinate) |c| if (!s.values.contains(c.endpoint)) {
                                    std.debug.print("RESIDENT_SCHEDULE_ENDPOINT cohort={d} row={d} endpoint={d}/{d}\n", .{ cohort, index, c.endpoint >> 32, @as(u32, @truncate(c.endpoint)) });
                                };
                            }
                        }
                    }
                }
                return error.UnresolvedResidentSchedule;
            }
            s.phase += 4;
            if (s.tasks.items.len > limits.max_tasks or s.resident > limits.max_resident_words) return error.ResidentScheduleResourceLimit;
        }
        s.routes.bounds.resident_words = s.resident;
        const routes = try s.routes.finish(s.rows);
        errdefer routes.deinit();
        for (routes.view().groups, 0..) |g, i| try s.tasks.append(a, .{ .phase = g.phase, .operation = .{ .direct_group = @intCast(i) } });
        // Stable ordering retains write→hash/scatter sequencing inside equal phases.
        std.mem.sort(Types.Task, s.tasks.items, {}, struct {
            fn less(_: void, l: Types.Task, r: Types.Task) bool {
                return l.phase < r.phase;
            }
        }.less);
        return .{ .a = backing, .arena = arena, .routes = routes, .tasks = try s.tasks.toOwnedSlice(a), .writes = try s.writes.toOwnedSlice(a), .hash_rows = try s.hash_rows.toOwnedSlice(a), .row_counts = s.rows, .resident_used = s.resident };
    }
};
fn key(c: u32, w: u32) u64 {
    return (@as(u64, c) << 32) | w;
}
// Shared-root query ownership is explicit in the ORIGINAL fixed recipe: one
// PathSelect owner and negative ByteRoute equality aliases. The aliases remain
// mandatory rows and their signed lookup claims remain fully constrained.
fn uniqueOwner(registry: *const Registry.Plan, endpoint: Registry.Endpoint, index: u32) bool {
    if (endpoint.count == 1) return true;
    const selected = registry.candidates[index];
    if (selected.cohort != 13) return false;
    const positive = registry.expressions[selected.weight];
    if (positive.op != @intFromEnum(Registry.Op.constant) or positive.value == 0 or positive.value >= core.fields.m31.Modulus / 2) return false;
    for (registry.candidates[endpoint.first..][0..endpoint.count], endpoint.first..) |other, i| {
        if (i == index) continue;
        const weight = registry.expressions[other.weight];
        if (other.cohort != 7 or weight.op != @intFromEnum(Registry.Op.constant) or weight.value != core.fields.m31.Modulus - 1) return false;
    }
    return true;
}

const Builder = struct {
    a: std.mem.Allocator,
    program: *const Program.Owned,
    registry: *const Registry.Plan,
    hash: *const Hash.Owned,
    limits: Limits,
    phase: u32,
    resident: usize,
    rows: [23]usize,
    offsets: [23]usize,
    done: []bool,
    heads: []u32,
    next: []u32,
    hash_done: []bool,
    routes: Routes.Builder,
    values: std.AutoHashMapUnmanaged(u64, Seed) = .{},
    tasks: std.ArrayList(Types.Task) = .empty,
    writes: std.ArrayList(Types.Write) = .empty,
    hash_rows: std.ArrayList(Types.HashRow) = .empty,
    fn put(self: *Builder, seed: Seed) !void {
        if (self.values.contains(seed.key)) return;
        try self.values.put(self.a, seed.key, seed);
    }
    fn mark(self: *Builder, cohort: usize, row: usize, phase: u32) !void {
        const flat = self.offsets[cohort] + row;
        if (self.done[flat]) return error.DuplicateResidentScheduleRow;
        self.done[flat] = true;
        var next = self.heads[flat];
        while (next != std.math.maxInt(u32)) {
            const candidate_index = next;
            const c = self.registry.candidates[next];
            next = self.next[next];
            const e = self.registry.endpoint(c.endpoint).?;
            if (!uniqueOwner(self.registry, e, candidate_index)) continue;
            const w = self.registry.expressions[c.weight];
            if (w.op != @intFromEnum(Registry.Op.constant) or w.value == 0) continue;
            var cs: [4]Routes.Source = undefined;
            var simple = true;
            for (c.coordinates, &cs) |id, *out| {
                const v = self.registry.expressions[id];
                out.* = switch (@as(Registry.Op, @enumFromInt(v.op))) {
                    .constant => Routes.Source.constant(v.value),
                    .main => Routes.Source.mainWord(v.value, phase),
                    else => blk: {
                        simple = false;
                        break :blk Routes.Source.constant(0);
                    },
                };
            }
            if (simple) try self.put(.{ .key = c.endpoint, .coordinates = cs });
        }
    }
    fn word(self: *Builder, value: Seed, phase: u32) !?Routes.Source {
        if (value.word) |w| return if (w.ready_phase <= phase) w else null;
        for (value.coordinates) |c| if (c.ready_phase > phase) return null;
        var all_constant = true;
        var scalar: u32 = 0;
        for (value.coordinates, 0..) |c, i| {
            if (c.kind != @intFromEnum(Routes.Kind.constant)) {
                all_constant = false;
                break;
            }
            if (c.index > 255) return error.NonbyteResidentWireSource;
            scalar |= c.index << @as(u5, @intCast(i * 8));
        }
        if (all_constant) return Routes.Source.constant(scalar);
        const first = value.coordinates[0];
        if (first.kind == @intFromEnum(Routes.Kind.main_word)) {
            const second = value.coordinates[1];
            if (second.kind == first.kind and second.index > first.index) {
                const stride = second.index - first.index;
                var same = true;
                for (value.coordinates, 0..) |c, i| if (c.kind != first.kind or c.index != first.index + i * stride) {
                    same = false;
                };
                if (same) return Routes.Source.mainPacked(first.index, stride, phase);
            }
        }
        if (self.resident + 4 > self.limits.max_resident_words) return error.ResidentScheduleResourceLimit;
        const at = self.resident;
        self.resident += 4;
        const start = self.writes.items.len;
        for (value.coordinates, 0..) |c, i| try self.writes.append(self.a, .{ .source = c, .destination = .resident_words, .byte_offset = @intCast((at + i) * 4), .bytes = 4, .phase = phase });
        try self.tasks.append(self.a, .{ .phase = phase, .operation = .{ .write = .{ .first = @intCast(start), .count = 4 } } });
        return Routes.Source.packedBytes(@intCast(at), phase);
    }
    fn gRow(self: *const Builder, index: usize) struct { cohort: u32, row: u32 } {
        var at = index;
        inline for (.{ 0, 20, 21, 22 }) |cohort| {
            if (at < self.rows[cohort]) return .{ .cohort = cohort, .row = @intCast(at) };
            at -= self.rows[cohort];
        }
        unreachable;
    }
};

test "resident schedule compile native body" {
    std.mem.doNotOptimizeAway(&Owned.compile);
}
test "resident schedule builds canonical compression and source rows without private host values" {
    const a = std.testing.allocator;
    const M = core.fields.m31.M31;
    const OriginalHash = @import("../../frontends/riscv/recursion/air/blake3_hash_plan.zig");
    var h = try OriginalHash.build(a, 0);
    defer h.deinit();
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (Storage.Airs, 0..) |_, i| fixed[i] = &.{};
    const gs = try a.alloc(Storage.FixedRow(Storage.Airs[0]), h.g.len);
    defer a.free(gs);
    for (gs, h.g) |*out, g| {
        var uses: [4]u32 = undefined;
        for (g.output, &uses) |wire, *v| v.* = h.uses[wire];
        out.* = Storage.compactFixed(Storage.Airs[0], try Storage.Airs[0].fixedRow(.{ .circuit = 17, .input = g.input, .output = g.output, .uses = uses }));
    }
    fixed[0] = gs;
    const xs = try a.alloc(Storage.FixedRow(Storage.Airs[1]), h.xor.len);
    defer a.free(xs);
    for (xs, h.xor) |*out, x| out.* = Storage.compactFixed(Storage.Airs[1], try Storage.Airs[1].fixedRow(.{ .circuit = 17, .input = x.input, .output = x.output, .uses = h.uses[x.output] }));
    fixed[1] = xs;
    const bs = try a.alloc(Storage.FixedRow(Storage.Airs[2]), h.sources.len);
    defer a.free(bs);
    for (bs, h.sources) |*out, source| out.* = Storage.compactFixed(Storage.Airs[2], try Storage.Airs[2].logicalRow(17, source.wire, M.fromCanonical(h.uses[source.wire]), source.value.constant));
    fixed[2] = bs;
    const nodes = [_]Arithmetic.Original.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};
    const outputs = [_]u32{0};
    const graph = try Arithmetic.Original.CircuitGraph.authenticate(&nodes, &outputs, Arithmetic.Original.computeGraphDigest(&nodes, &outputs));
    var arithmetic = try Arithmetic.Plan.init(a, &.{ graph, graph, graph }, .{});
    defer arithmetic.deinit();
    var admission = try Program.fixtureAdmission();
    admission.key.context.graph_ids = .{ graph.identity_digest, graph.identity_digest, graph.identity_digest };
    admission.key.log_sizes[0] = 6;
    admission.key.log_sizes[1] = 4;
    admission.key.log_sizes[2] = @intCast(std.math.log2_int_ceil(usize, bs.len));
    admission.expected_id = try admission.key.identity();
    const p = try Program.Owned.derive(a, admission, .{});
    defer p.deinit();
    var registry = try Registry.Plan.init(a, p, fixed, .{});
    defer registry.deinit();
    const hash = try Hash.Owned.deriveFixed(a, fixed, .{});
    defer hash.deinit();
    const prelude = Prelude{ .tasks = &.{.{ .phase = 1, .operation = .{ .arithmetic = .{ .first = 0, .count = 3 } } }}, .writes = &.{}, .phase = 2, .resident_used = 0, .graph_phase = .{ 1, 1, 1 } };
    var schedule = try Owned.compile(a, p, fixed, &registry, hash, &arithmetic, &.{}, prelude, 4, 0, .{});
    defer schedule.deinit();
    try std.testing.expectEqual(@as(usize, 72), schedule.hash_rows.len);
    try std.testing.expectEqual(bs.len, schedule.routes.view().calls.len);
    try std.testing.expectEqual(@as(usize, 0), schedule.resident_used);
    var hash_count: usize = 0;
    var readonly_count: usize = 0;
    for (schedule.tasks) |task| switch (task.operation) {
        .hash_frame => hash_count += 1,
        .readonly => readonly_count += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), hash_count);
    try std.testing.expectEqual(@as(usize, 0), readonly_count);
    // Withheld private sources cannot turn into padding or silently zero values.
    bs[0][0] = M.zero();
    try std.testing.expectError(error.UnresolvedResidentSchedule, Owned.compile(a, p, fixed, &registry, hash, &arithmetic, &.{}, prelude, 4, 0, .{}));
}

test "resident schedule shared root owner excludes negative aliases and ambiguous owners" {
    const a = std.testing.allocator;
    const M = core.fields.m31;
    var expressions = [_]Registry.Expr{ .{ .op = @intFromEnum(Registry.Op.constant), .value = 8 }, .{ .op = @intFromEnum(Registry.Op.constant), .value = M.Modulus - 1 }, .{ .op = @intFromEnum(Registry.Op.main), .value = 0 } };
    var candidates = [_]Registry.Candidate{ .{ .endpoint = 19, .cohort = 13, .row = 0, .weight = 0, .coordinates = @splat(0) }, .{ .endpoint = 19, .cohort = 7, .row = 1, .weight = 1, .coordinates = @splat(0) } };
    var registry = Registry.Plan{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .program_id = @splat(0), .expressions = &expressions, .candidates = &candidates, .endpoints = &.{}, .consumers = &.{}, .unresolved = &.{}, .main_words = 0 };
    defer registry.arena.deinit();
    const e = Registry.Endpoint{ .key = 19, .first = 0, .count = 2 };
    try std.testing.expect(uniqueOwner(&registry, e, 0));
    try std.testing.expect(!uniqueOwner(&registry, e, 1));
    candidates[1].cohort = 13;
    try std.testing.expect(!uniqueOwner(&registry, e, 0));
    candidates[1].cohort = 7;
    candidates[1].weight = 0;
    try std.testing.expect(!uniqueOwner(&registry, e, 0));
    candidates[1].weight = 1;
    candidates[0].weight = 2;
    try std.testing.expect(!uniqueOwner(&registry, e, 0));
    candidates[0].weight = 0;
    expressions[1].value = 0;
    try std.testing.expect(!uniqueOwner(&registry, e, 0));
}
