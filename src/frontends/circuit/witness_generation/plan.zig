//! A generation schedule over the original Circuit, not a second constraint IR.
//! Constants and explicit external guesses are seeds. Every deterministic hint
//! has an explicit origin; anonymous permutation algorithms are rejected.
const std = @import("std");
const C = @import("../builder/context.zig");
const G = @import("../builder/circuit.zig");
const W = @import("origins.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
pub const Kind = enum(u8) { add, sub, mul, pointwise_mul, triple_xor, m31_to_u32, blake_g, permutation, hint };
pub const Task = struct { kind: Kind, index: u32, level: u32 = 0 };
pub const Seed = struct { variable: u32, value: Q };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    tasks: []Task,
    seeds: []Seed,
    /// CSR ranges in tasks; level zero contains only seeds, no operations.
    level_ends: []usize,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.tasks);
        self.allocator.free(self.seeds);
        self.allocator.free(self.level_ends);
        self.* = undefined;
    }
};
const missing = std.math.maxInt(u32);
const seeded = missing - 1;
const visiting = missing - 2;
pub fn inputs(ctx: *const C.Context(Q), task: Task, buf: *[6]u32) []const u32 {
    const circuit = &ctx.circuit;
    switch (task.kind) {
        .add, .sub, .mul, .pointwise_mul => {
            const gate = switch (task.kind) {
                .add => circuit.add.items[task.index],
                .sub => circuit.sub.items[task.index],
                .mul => circuit.mul.items[task.index],
                else => circuit.pointwise_mul.items[task.index],
            };
            buf[0] = gate.in0;
            buf[1] = gate.in1;
            return buf[0..2];
        },
        .triple_xor => {
            const gate = circuit.triple_xor.items[task.index];
            buf[0..3].* = .{ gate.input_a, gate.input_b, gate.input_c };
            return buf[0..3];
        },
        .m31_to_u32 => {
            buf[0] = circuit.m31_to_u32.items[task.index].input;
            return buf[0..1];
        },
        .blake_g => {
            buf.* = circuit.blake_g_gate.items[task.index].inputs();
            return buf;
        },
        .permutation => return circuit.permutation.get(task.index).inputs,
        .hint => {
            const hint = ctx.witness_metadata.?.origins.items[task.index];
            if (hint.kind == .zero) return buf[0..0];
            buf[0] = hint.a;
            buf[1] = hint.b;
            return buf[0..if (hint.kind == .divide) @as(usize, 2) else 1];
        },
    }
}
pub fn outputs(ctx: *const C.Context(Q), task: Task, buf: *[4]u32) []const u32 {
    const circuit = &ctx.circuit;
    buf[0] = switch (task.kind) {
        .add => circuit.add.items[task.index].out,
        .sub => circuit.sub.items[task.index].out,
        .mul => circuit.mul.items[task.index].out,
        .pointwise_mul => circuit.pointwise_mul.items[task.index].out,
        .triple_xor => circuit.triple_xor.items[task.index].out,
        .m31_to_u32 => circuit.m31_to_u32.items[task.index].out,
        .hint => ctx.witness_metadata.?.origins.items[task.index].out,
        .blake_g => {
            buf.* = circuit.blake_g_gate.items[task.index].outputs();
            return buf;
        },
        .permutation => return circuit.permutation.get(task.index).outputs,
    };
    return buf[0..1];
}
fn append(a: std.mem.Allocator, ctx: *const C.Context(Q), tasks: *std.ArrayList(Task), producer: []u32, task: Task, metrics: ?*BuildMetrics) !void {
    var obuf: [4]u32 = undefined;
    var ibuf: [6]u32 = undefined;
    const out = outputs(ctx, task, &obuf);
    const in = inputs(ctx, task, &ibuf);
    for (in) |v| if (v >= producer.len) return error.InvalidWitnessVariable;
    for (out) |v| if (v >= producer.len) return error.InvalidWitnessVariable;
    if (out.len == 1 and task.kind != .hint and task.kind != .permutation) {
        // Finalization yields guesses in-place. These are constraints, not
        // computational definitions. They must already have an explicit seed
        // or deterministic hint, checked by complete producer coverage below.
        for (in) |v| if (v == out[0]) return;
    }
    var all_seeded = true;
    for (out) |v| {
        all_seeded = all_seeded and producer[v] == seeded;
    }
    // Interned immutable constants are seeded independently of their original
    // constraining decomposition, which remains in the unchanged Circuit.
    if (all_seeded) return;
    if (tasks.items.len >= visiting) return error.WitnessPlanTooLarge;
    const index: u32 = @intCast(tasks.items.len);
    for (out) |v| {
        if (producer[v] != missing) return error.DuplicateWitnessDefinition;
        producer[v] = index;
    }
    const old_len = tasks.items.len;
    const old_address = @intFromPtr(tasks.items.ptr);
    var growth_timer: ?std.time.Timer = null;
    if (metrics != null and tasks.items.len == tasks.capacity) growth_timer = try std.time.Timer.start();
    try tasks.append(a, task);
    if (growth_timer) |*clock| {
        const m = metrics.?;
        m.task_growth_calls += 1;
        m.task_growth_ns += clock.read();
        if (@intFromPtr(tasks.items.ptr) != old_address) m.task_growth_copy_bytes += old_len * @sizeOf(Task);
    }
}
pub const BuildMetrics = struct {
    producer_init_ns: u64 = 0,
    seeds_ns: u64 = 0,
    tasks_ns: u64 = 0,
    level_init_ns: u64 = 0,
    walk_ns: u64 = 0,
    ordering_ns: u64 = 0,
    ready_tasks: usize = 0,
    dfs_roots: usize = 0,
    task_growth_calls: usize = 0,
    task_growth_ns: u64 = 0,
    task_growth_copy_bytes: usize = 0,
    task_count: usize = 0,
    task_capacity: usize = 0,
};
pub fn build(a: std.mem.Allocator, ctx: *const C.Context(Q)) !Plan {
    return buildProfiled(a, ctx, null);
}
pub fn buildProfiled(a: std.mem.Allocator, ctx: *const C.Context(Q), metrics: ?*BuildMetrics) !Plan {
    return buildImpl(a, ctx, metrics, true, null);
}
/// Test oracle retains the original task-order DFS, including its independent
/// discovery order. Production always uses the ready-variable fast path.
pub fn buildDfsReference(a: std.mem.Allocator, ctx: *const C.Context(Q)) !Plan {
    if (!@import("builtin").is_test) @compileError("DFS reference is qualification-only");
    return buildImpl(a, ctx, null, false, null);
}
fn buildImpl(a: std.mem.Allocator, ctx: *const C.Context(Q), metrics: ?*BuildMetrics, comptime ready_variables: bool, qualification_reserve: ?usize) !Plan {
    if (!@import("builtin").is_test and qualification_reserve != null) return error.QualificationReserveOnly;
    var timer: std.time.Timer = undefined;
    if (metrics) |m| {
        m.* = .{};
        timer = try std.time.Timer.start();
    }
    if (!ctx.finalized or !ctx.record_gates) return error.WitnessTopologyRequired;
    const metadata = ctx.witness_metadata orelse return error.WitnessOriginsRequired;
    if (metadata.permutations.items.len != ctx.circuit.permutation.len()) return error.WitnessPermutationIdentityMissing;
    const producer = try a.alloc(u32, ctx.circuit.n_vars);
    defer a.free(producer);
    @memset(producer, missing);
    if (metrics) |m| m.producer_init_ns = timer.lap();
    var seeds: std.ArrayList(Seed) = .empty;
    defer seeds.deinit(a);
    for (ctx.constants.keys(), ctx.constants.values()) |key, variable| {
        if (producer[variable.idx] != missing) return error.DuplicateWitnessSeed;
        producer[variable.idx] = seeded;
        try seeds.append(a, .{ .variable = variable.idx, .value = C.constantFromKey(key) });
    }
    for (metadata.origins.items) |origin| if (origin.kind == .seed) {
        if (origin.out >= producer.len or producer[origin.out] != missing) return error.DuplicateWitnessSeed;
        producer[origin.out] = seeded;
        try seeds.append(a, .{ .variable = origin.out, .value = origin.value });
    };
    if (metrics) |m| m.seeds_ns = timer.lap();
    var tasks: std.ArrayList(Task) = .empty;
    defer tasks.deinit(a);
    if (qualification_reserve) |capacity| try tasks.ensureTotalCapacityPrecise(a, capacity);
    for (metadata.origins.items, 0..) |origin, i| if (origin.kind != .seed) try append(a, ctx, &tasks, producer, .{ .kind = .hint, .index = @intCast(i) }, metrics);
    const lists = .{ ctx.circuit.add.items, ctx.circuit.sub.items, ctx.circuit.mul.items, ctx.circuit.pointwise_mul.items, ctx.circuit.triple_xor.items, ctx.circuit.m31_to_u32.items, ctx.circuit.blake_g_gate.items };
    const kinds = [_]Kind{ .add, .sub, .mul, .pointwise_mul, .triple_xor, .m31_to_u32, .blake_g };
    inline for (lists, kinds) |list, kind| for (list, 0..) |_, i| try append(a, ctx, &tasks, producer, .{ .kind = kind, .index = @intCast(i) }, metrics);
    for (0..ctx.circuit.permutation.len()) |i| try append(a, ctx, &tasks, producer, .{ .kind = .permutation, .index = @intCast(i) }, metrics);
    for (producer) |p| if (p == missing) return error.WitnessDefinitionMissing;
    if (metrics) |m| {
        m.tasks_ns = timer.lap();
        m.task_count = tasks.items.len;
        m.task_capacity = tasks.capacity;
    }
    const levels = try a.alloc(u32, tasks.items.len);
    defer a.free(levels);
    @memset(levels, missing);
    // Remember the next dependency across child visits. Restarting from input
    // zero makes high-fan-in permutation scheduling quadratic in its inputs.
    const Frame = struct { id: u32, next: usize = 0, maximum: u32 = 0 };
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(a);
    if (metrics) |m| m.level_init_ns = timer.lap();
    var max_level: u32 = 0;
    const starts = if (ready_variables) producer.len else tasks.items.len;
    for (0..starts) |position| {
        const start: u32 = if (ready_variables) producer[position] else @intCast(position);
        if (start == seeded or levels[start] != missing) continue;
        if (ready_variables) {
            // Builders allocate variable IDs in generation order, while gate
            // families are stored separately. Most tasks therefore have every
            // dependency ready in this sweep, avoiding DFS stack traffic and
            // repeated input decoding. Forward references retain the full DFS.
            var input_buffer: [6]u32 = undefined;
            var maximum: u32 = 0;
            var ready = true;
            for (inputs(ctx, tasks.items[start], &input_buffer)) |variable| {
                const parent = producer[variable]; // append checked every ID
                if (parent == seeded) continue;
                const level = levels[parent];
                if (level == missing) {
                    ready = false;
                    break;
                }
                if (level == visiting) return error.CyclicWitnessDefinition;
                maximum = @max(maximum, level);
            }
            if (ready) {
                levels[start] = try std.math.add(u32, maximum, 1);
                max_level = @max(max_level, levels[start]);
                if (metrics) |m| m.ready_tasks += 1;
                continue;
            }
        }
        if (metrics) |m| m.dfs_roots += 1;
        levels[start] = visiting;
        try stack.append(a, .{ .id = @intCast(start) });
        while (stack.items.len != 0) {
            const frame = &stack.items[stack.items.len - 1];
            var buf: [6]u32 = undefined;
            const dependencies = inputs(ctx, tasks.items[frame.id], &buf);
            if (frame.next < dependencies.len) {
                const variable = dependencies[frame.next];
                if (variable >= producer.len) return error.InvalidWitnessVariable;
                const parent = producer[variable];
                if (parent == seeded) {
                    frame.next += 1;
                    continue;
                }
                if (levels[parent] == visiting) return error.CyclicWitnessDefinition;
                if (levels[parent] == missing) {
                    levels[parent] = visiting;
                    // append may move the stack: never use frame afterwards.
                    try stack.append(a, .{ .id = parent });
                    continue;
                }
                frame.maximum = @max(frame.maximum, levels[parent]);
                frame.next += 1;
                continue;
            }
            levels[frame.id] = try std.math.add(u32, frame.maximum, 1);
            max_level = @max(max_level, levels[frame.id]);
            _ = stack.pop();
        }
    }
    if (metrics) |m| m.walk_ns = timer.lap();
    const ends = try a.alloc(usize, @as(usize, max_level) + 1);
    errdefer a.free(ends);
    @memset(ends, 0);
    for (levels) |level| ends[level] += 1;
    for (1..ends.len) |i| ends[i] += ends[i - 1];
    const cursors = try a.dupe(usize, ends);
    defer a.free(cursors);
    const ordered = try a.alloc(Task, tasks.items.len);
    errdefer a.free(ordered);
    // Reverse scatter preserves original order within each level.
    var i = tasks.items.len;
    while (i > 0) {
        i -= 1;
        const level = levels[i];
        cursors[level] -= 1;
        ordered[cursors[level]] = tasks.items[i];
        ordered[cursors[level]].level = level;
    }
    if (metrics) |m| m.ordering_ns = timer.lap();
    return .{ .allocator = a, .tasks = ordered, .seeds = try seeds.toOwnedSlice(a), .level_ends = ends };
}

/// Reference replay for qualifying device scheduling. It never calls the
/// original builder and consumes only the narrow seeds and immutable topology.
pub fn evaluate(a: std.mem.Allocator, ctx: *const C.Context(Q), plan: Plan) ![]Q {
    const value = try a.alloc(Q, ctx.circuit.n_vars);
    errdefer a.free(value);
    @memset(value, Q.zero());
    for (plan.seeds) |seed| {
        if (seed.variable >= value.len) return error.InvalidWitnessVariable;
        value[seed.variable] = seed.value;
    }
    const iv = @import("../builder/ivalue.zig");
    for (plan.tasks) |task| switch (task.kind) {
        .add, .sub, .mul, .pointwise_mul => {
            const gate = switch (task.kind) {
                .add => ctx.circuit.add.items[task.index],
                .sub => ctx.circuit.sub.items[task.index],
                .mul => ctx.circuit.mul.items[task.index],
                else => ctx.circuit.pointwise_mul.items[task.index],
            };
            value[gate.out] = switch (task.kind) {
                .add => value[gate.in0].add(value[gate.in1]),
                .sub => value[gate.in0].sub(value[gate.in1]),
                .mul => value[gate.in0].mul(value[gate.in1]),
                else => iv.pointwiseMul(Q, value[gate.in0], value[gate.in1]),
            };
        },
        .triple_xor => {
            const gate = ctx.circuit.triple_xor.items[task.index];
            value[gate.out] = iv.packU32(Q, iv.unpackU32(Q, value[gate.input_a]) ^ iv.unpackU32(Q, value[gate.input_b]) ^ iv.unpackU32(Q, value[gate.input_c]));
        },
        .m31_to_u32 => {
            const gate = ctx.circuit.m31_to_u32.items[task.index];
            value[gate.out] = iv.m31ToU32(Q, value[gate.input]);
        },
        .blake_g => {
            const gate = ctx.circuit.blake_g_gate.items[task.index];
            var words: [6]u32 = undefined;
            for (gate.inputs(), &words) |v, *out| out.* = iv.unpackU32(Q, value[v]);
            const result = @import("../builder/blake.zig").blake2sG(words[0], words[1], words[2], words[3], words[4], words[5]);
            for (gate.outputs(), result) |v, word| value[v] = iv.packU32(Q, word);
        },
        .permutation => {
            const gate = ctx.circuit.permutation.get(task.index);
            const in = try a.alloc(Q, gate.inputs.len);
            defer a.free(in);
            const out = try a.alloc(Q, gate.outputs.len);
            defer a.free(out);
            for (in, gate.inputs) |*v, index| v.* = value[index];
            switch (ctx.witness_metadata.?.permutations.items[task.index]) {
                .sort_by_u_coordinate => iv.sortByUCoordinate(Q)(in, out),
            }
            for (out, gate.outputs) |v, index| value[index] = v;
        },
        .hint => {
            const hint = ctx.witness_metadata.?.origins.items[task.index];
            value[hint.out] = switch (hint.kind) {
                .seed => return error.InvalidWitnessOrigin,
                .inverse => try value[hint.a].inv(),
                .divide => try value[hint.a].div(value[hint.b]),
                .pointwise_inverse_or_zero => iv.pointwiseInvOrZero(Q, value[hint.a]),
                .pointwise_lsb => iv.pointwiseLsb(Q, value[hint.a]),
                .zero => Q.zero(),
                .is_nonzero => if (value[hint.a].isZero()) Q.zero() else Q.one(),
                .byte, .byte_complement => blk: {
                    if (hint.b > 3) return error.InvalidWitnessByteIndex;
                    const byte: u8 = @truncate(iv.unpackU32(Q, value[hint.a]) >> @intCast(hint.b * 8));
                    break :blk Q.fromU32Unchecked(if (hint.kind == .byte) byte else 255 - @as(u32, byte), 0, 0, 0);
                },
            };
        },
    };
    if (try ctx.circuit.check(a, value) != null) return error.InvalidReconstructedWitness;
    return value;
}

test "witness schedule: compact seeds reproduce finalized reserved outputs and deterministic hints" {
    const a = std.testing.allocator;
    var ctx = try C.Context(Q).initWithWitnessOrigins(a, 1);
    defer ctx.deinit();
    const seed = try ctx.guess(Q.fromU32Unchecked(11, 3, 7, 9));
    const denominator = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    const inverse = try ctx.inv(denominator);
    const quotient = try ctx.div(seed, denominator);
    const sum = try ctx.add(quotient, inverse);
    const simd = @import("../builder/simd.zig");
    const lanes = simd.Simd.fromPacked(&.{seed}, 4);
    _ = try simd.guessInvOrZero(Q, &ctx, lanes);
    _ = try simd.guessLsb(Q, &ctx, lanes);
    _ = try ctx.permuteNamed(&.{ sum, seed, denominator }, .sort_by_u_coordinate);
    try ctx.setOutputs(&.{sum});
    try ctx.finalize(false);
    var plan = try build(a, &ctx);
    defer plan.deinit();
    const reconstructed = try evaluate(a, &ctx, plan);
    defer a.free(reconstructed);
    try std.testing.expectEqualDeep(ctx.values(), reconstructed);
    try std.testing.expect(plan.tasks.len > 0);
    try std.testing.expect(plan.seeds.len < ctx.values().len);
    var prior: u32 = 0;
    for (plan.tasks) |task| {
        try std.testing.expect(task.level >= prior);
        prior = task.level;
    }
    // A deterministic hint must never become an extra externally supplied seed.
    const seed_count = ctx.constants.count() + 2;
    try std.testing.expectEqual(seed_count, plan.seeds.len);
}

test "witness schedule: missing origins and cyclic or unknown input authority reject" {
    const a = std.testing.allocator;
    var plain = try C.Context(Q).init(a, 0);
    defer plain.deinit();
    try plain.finalize(false);
    try std.testing.expectError(error.WitnessOriginsRequired, build(a, &plain));
    var ctx = try C.Context(Q).initWithWitnessOrigins(a, 0);
    defer ctx.deinit();
    const seed = try ctx.guess(Q.one());
    const inv = try ctx.inv(seed);
    try ctx.finalize(false);
    ctx.witness_metadata.?.origins.items[1].a = inv.idx;
    try std.testing.expectError(error.CyclicWitnessDefinition, build(a, &ctx));
    ctx.witness_metadata.?.origins.items[1].a = ctx.circuit.n_vars;
    try std.testing.expectError(error.InvalidWitnessVariable, build(a, &ctx));
}

test "witness schedule: skipped self-yields and seeded outputs still validate input authority" {
    const a = std.testing.allocator;
    var ctx = try C.Context(Q).initWithWitnessOrigins(a, 0);
    defer ctx.deinit();
    const seed = try ctx.guess(Q.one());
    try ctx.finalize(false);
    try ctx.circuit.add.append(a, .{ .in0 = seed.idx, .in1 = ctx.circuit.n_vars, .out = seed.idx });
    try std.testing.expectError(error.InvalidWitnessVariable, build(a, &ctx));
    ctx.circuit.add.items[ctx.circuit.add.items.len - 1] = .{ .in0 = ctx.circuit.n_vars, .in1 = ctx.zero().idx, .out = ctx.one().idx };
    try std.testing.expectError(error.InvalidWitnessVariable, build(a, &ctx));
}

fn traceOnlyFixture(ctx: *C.Context(Q)) !void {
    const iv = @import("../builder/ivalue.zig");
    const simd = @import("../builder/simd.zig");
    const wrappers = @import("../builder/wrappers.zig");
    const x = try ctx.guess(Q.fromU32Unchecked(11, 3, 7, 9));
    const denominator = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    _ = try ctx.div(x, denominator);
    _ = try ctx.inv(denominator);
    const lanes = simd.Simd.fromPacked(&.{x}, 4);
    _ = try simd.guessInvOrZero(Q, ctx, lanes);
    _ = try @import("../builder/extract_bits.zig").extractBits(Q, ctx, lanes, 31);
    _ = try ctx.permuteNamed(&.{ x, denominator }, .sort_by_u_coordinate);
    const nonce = try wrappers.guessU32(Q, ctx, wrappers.u32Value(Q, 0xdeadbeef));
    const message = [_]wrappers.U32Wrapper(G.Var){ nonce, try wrappers.constU32(Q, ctx, 0x12345678) };
    const digest = try @import("../builder/blake.zig").blake2sU32s(Q, ctx, &message, 8);
    var out: [8]G.Var = undefined;
    for (&out, digest.words) |*v, word| v.* = word.get();
    try ctx.setOutputs(&out);
    try ctx.finalize(false);
    _ = iv;
}

test "witness trace-only: exact original topology and assignments without CPU value storage" {
    const a = std.testing.allocator;
    var original = try C.Context(Q).initWithWitnessOrigins(a, 8);
    defer original.deinit();
    var trace = try C.Context(Q).initTraceOnly(a, 8);
    defer trace.deinit();
    try traceOnlyFixture(&original);
    try traceOnlyFixture(&trace);
    try std.testing.expectEqualDeep(original.circuit, trace.circuit);
    // This fixture covers independently seeded constants and four-output
    // Blake tasks, which the producer-order sweep must schedule only once.
    try std.testing.expect(trace.constants.count() > 0);
    try std.testing.expect(trace.circuit.blake_g_gate.items.len > 0);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.items.len);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.capacity);
    var plan = try build(a, &trace);
    defer plan.deinit();
    var reference = try buildDfsReference(a, &trace);
    defer reference.deinit();
    try std.testing.expectEqualDeep(reference.tasks, plan.tasks);
    try std.testing.expectEqualDeep(reference.seeds, plan.seeds);
    try std.testing.expectEqualSlices(usize, reference.level_ends, plan.level_ends);
    const reconstructed = try evaluate(a, &trace, plan);
    defer a.free(reconstructed);
    try std.testing.expectEqualDeep(original.values(), reconstructed);
    // Only four true external proof words: x, denominator, and nonce limbs.
    try std.testing.expectEqual(trace.constants.count() + 4, plan.seeds.len);
}

test "witness schedule profiling preserves exact generation plan" {
    const a = std.testing.allocator;
    var ctx = try C.Context(Q).initWithWitnessOrigins(a, 0);
    defer ctx.deinit();
    const value = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    _ = try ctx.inv(value);
    try ctx.finalize(false);
    var plain = try build(a, &ctx);
    defer plain.deinit();
    var metrics: BuildMetrics = .{};
    var profiled = try buildProfiled(a, &ctx, &metrics);
    defer profiled.deinit();
    try std.testing.expectEqualDeep(plain.tasks, profiled.tasks);
    try std.testing.expectEqualDeep(plain.seeds, profiled.seeds);
    try std.testing.expectEqualSlices(usize, plain.level_ends, profiled.level_ends);
}

test "witness schedule ready-variable sweep retains DFS forward references and rejects cycles" {
    const a = std.testing.allocator;
    var ctx = try C.Context(Q).initTraceOnly(a, 0);
    defer ctx.deinit();
    const seed = try ctx.guess(Q.one());
    const first = try ctx.add(seed, seed);
    const second = try ctx.mul(seed, seed);
    try ctx.finalize(false);
    // A forward definition cannot use the ready fast path, but its level and
    // final stable family order must match the original DFS oracle exactly.
    for (ctx.circuit.add.items) |*gate| if (gate.out == first.idx) {
        gate.in0 = second.idx;
    };
    var plan = try build(a, &ctx);
    defer plan.deinit();
    var reference = try buildDfsReference(a, &ctx);
    defer reference.deinit();
    try std.testing.expectEqualDeep(reference.tasks, plan.tasks);
    try std.testing.expectEqualDeep(reference.seeds, plan.seeds);
    try std.testing.expectEqualSlices(usize, reference.level_ends, plan.level_ends);
    for (ctx.circuit.mul.items) |*gate| if (gate.out == second.idx) {
        gate.in0 = first.idx;
    };
    try std.testing.expectError(error.CyclicWitnessDefinition, build(a, &ctx));
    try std.testing.expectError(error.CyclicWitnessDefinition, buildDfsReference(a, &ctx));
    for (ctx.circuit.mul.items) |*gate| if (gate.out == second.idx) {
        gate.in0 = seed.idx;
        gate.out = first.idx;
    };
    try std.testing.expectError(error.DuplicateWitnessDefinition, build(a, &ctx));
    try std.testing.expectError(error.DuplicateWitnessDefinition, buildDfsReference(a, &ctx));
}

test "witness task capacity audit: validated Blake arithmetic graphs and oracle reserve" {
    const Tracker = struct {
        live: usize = 0,
        peak: usize = 0,
        fn allocator(t: *@This()) std.mem.Allocator {
            return .{ .ptr = t, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
        fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const t: *@This() = @ptrCast(@alignCast(raw));
            const ptr = std.heap.page_allocator.rawAlloc(len, alignment, ra) orelse return null;
            t.live += len;
            t.peak = @max(t.peak, t.live);
            return ptr;
        }
        // Model large recycler growth beyond its existing rounded block:
        // every growth must move. This is not production allocator telemetry.
        fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
            return false;
        }
        fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
            return null;
        }
        fn free(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
            const t: *@This() = @ptrCast(@alignCast(raw));
            t.live -= memory.len;
            std.heap.page_allocator.rawFree(memory, alignment, ra);
        }
    };
    const B = @import("../builder/blake.zig");
    const wrappers = @import("../builder/wrappers.zig");
    const iv = @import("../builder/ivalue.zig");
    for ([_]usize{ 1000, 25000, 250000 }) |rounds| {
        var ctx = try C.Context(Q).initWithWitnessOrigins(std.heap.page_allocator, 1);
        defer ctx.deinit();
        const U = wrappers.U32Wrapper(C.Var);
        var state: [4]U = undefined;
        for (&state, 0..) |*value, i| value.* = .newUnsafe(try ctx.guess(iv.packU32(Q, @intCast(i + 17))));
        const input = U.newUnsafe(try ctx.guess(iv.packU32(Q, 0xdeadbeef)));
        const constant = U.newUnsafe(try ctx.constant(iv.packU32(Q, 123)));
        var accumulator = try ctx.guess(Q.fromU32Unchecked(17, 3, 7, 11));
        for (0..rounds) |i| {
            state = try B.blakeGGate(Q, &ctx, state[0], state[1], state[2], state[3], input, constant);
            accumulator = try ctx.add(try ctx.mul(accumulator, input.get()), state[i % 4].get());
        }
        try ctx.setOutputs(&.{accumulator});
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        for (0..3) |trial| {
            var moving = Tracker{};
            var reserved = Tracker{};
            var ordinary_metrics = BuildMetrics{};
            var reserved_metrics = BuildMetrics{};
            var clock = try std.time.Timer.start();
            var ordinary = try buildProfiled(moving.allocator(), &ctx, &ordinary_metrics);
            const ordinary_ns = clock.lap();
            // Optimistic upper bound only: a previously validated plan supplies
            // the exact count for free. No such oracle is used in production.
            var exact = try buildImpl(reserved.allocator(), &ctx, &reserved_metrics, true, ordinary.tasks.len);
            const reserved_ns = clock.read();
            try std.testing.expectEqualDeep(ordinary.tasks, exact.tasks);
            try std.testing.expectEqualDeep(ordinary.seeds, exact.seeds);
            try std.testing.expectEqualSlices(usize, ordinary.level_ends, exact.level_ends);
            if (trial == 0) {
                const replayed = try evaluate(std.heap.page_allocator, &ctx, ordinary);
                defer std.heap.page_allocator.free(replayed);
                try std.testing.expectEqualDeep(ctx.values(), replayed);
            }
            std.debug.print("TASK_CAPACITY_AUDIT {{\"rounds\":{},\"trial\":{},\"variables\":{},\"tasks\":{},\"capacity\":{},\"growth_calls\":{},\"moved_bytes\":{},\"growth_ns\":{},\"tasks_ns\":{},\"plan_ns\":{},\"plan_allocator_peak_bytes\":{},\"oracle_capacity\":{},\"oracle_tasks_ns\":{},\"oracle_plan_ns\":{},\"oracle_plan_allocator_peak_bytes\":{}}}\n", .{ rounds, trial, ctx.circuit.n_vars, ordinary.tasks.len, ordinary_metrics.task_capacity, ordinary_metrics.task_growth_calls, ordinary_metrics.task_growth_copy_bytes, ordinary_metrics.task_growth_ns, ordinary_metrics.tasks_ns, ordinary_ns, moving.peak, reserved_metrics.task_capacity, reserved_metrics.tasks_ns, reserved_ns, reserved.peak });
            ordinary.deinit();
            exact.deinit();
            try std.testing.expectEqual(@as(usize, 0), moving.live);
            try std.testing.expectEqual(@as(usize, 0), reserved.live);
        }
    }
}
