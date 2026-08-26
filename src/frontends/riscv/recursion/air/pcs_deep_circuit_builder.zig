//! Internal pcs deep circuit authority shard; use pcs_deep_circuit.zig publicly.

const dependency_0 = @import("pcs_deep_circuit_circuit.zig");

const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const Handle = dependency_0.Handle;
const InputBinding = dependency_0.InputBinding;
const InputSource = dependency_0.InputSource;
const M31 = dependency_0.M31;
const OpKey = dependency_0.OpKey;
const Profile = dependency_0.Profile;
const QM31 = dependency_0.QM31;
const SECURE_WORD_COUNT = dependency_0.SECURE_WORD_COUNT;
const SamplePointLayout = dependency_0.SamplePointLayout;
const TreeProfile = dependency_0.TreeProfile;
const checkedAdd = dependency_0.checkedAdd;
const circuitDigest = dependency_0.circuitDigest;
const constantPair = dependency_0.constantPair;
const graph_mod = dependency_0.graph_mod;
const qm31Words = dependency_0.qm31Words;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;

pub const Builder = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(graph_mod.Node),
    outputs: std.ArrayList(u32),
    bindings: std.ArrayList(InputBinding),
    interned: std.AutoHashMap(OpKey, u32),

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .nodes = .empty,
            .outputs = .empty,
            .bindings = .empty,
            .interned = std.AutoHashMap(OpKey, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        self.interned.deinit();
        self.bindings.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn input(self: *Builder, source: InputSource) Error!Handle {
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = .input });
        try self.bindings.append(self.allocator, .{ .node_id = node_id, .source = source });
        return .{ .node = node_id };
    }

    pub fn constrainZero(self: *Builder, value: Handle) Error!void {
        try self.outputs.append(self.allocator, try self.nodeId(value));
    }

    pub fn add(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].add(pair[1]) };
        if (isZeroHandle(lhs)) return rhs;
        if (isZeroHandle(rhs)) return lhs;
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .add = canonicalPair(lhs_id, rhs_id) },
            .{ .add = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    pub fn sub(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].sub(pair[1]) };
        if (isZeroHandle(rhs)) return lhs;
        if (std.meta.eql(lhs, rhs)) return .{ .constant = QM31.zero() };
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .sub = .{ .lhs = lhs_id, .rhs = rhs_id } },
            .{ .sub = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    pub fn mul(self: *Builder, lhs: Handle, rhs: Handle) Error!Handle {
        if (constantPair(lhs, rhs)) |pair|
            return .{ .constant = pair[0].mul(pair[1]) };
        if (isZeroHandle(lhs) or isZeroHandle(rhs))
            return .{ .constant = QM31.zero() };
        if (isOneHandle(lhs)) return rhs;
        if (isOneHandle(rhs)) return lhs;
        const lhs_id = try self.nodeId(lhs);
        const rhs_id = try self.nodeId(rhs);
        return .{ .node = try self.intern(
            .{ .mul = canonicalPair(lhs_id, rhs_id) },
            .{ .mul = .{ .lhs = lhs_id, .rhs = rhs_id } },
        ) };
    }

    fn inverse(self: *Builder, value: Handle) Error!Handle {
        return switch (value) {
            .constant => |constant| .{ .constant = try constant.inv() },
            .node => |node_id| .{ .node = try self.intern(
                .{ .inverse = node_id },
                .{ .inverse = node_id },
            ) },
        };
    }

    fn nodeId(self: *Builder, value: Handle) Error!u32 {
        return switch (value) {
            .node => |node_id| node_id,
            .constant => |constant| blk: {
                const words = qm31Words(constant);
                break :blk try self.intern(
                    .{ .constant = words },
                    .{ .constant = words },
                );
            },
        };
    }

    fn intern(self: *Builder, key: OpKey, op: graph_mod.Op) Error!u32 {
        if (self.interned.get(key)) |node_id| return node_id;
        const node_id = try indexU32(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{ .op = op });
        try self.interned.put(key, node_id);
        return node_id;
    }

    pub fn finish(self: *Builder, profile: Profile) Error!Circuit {
        const trees = try self.allocator.alloc(TreeProfile, profile.trees.len);
        errdefer self.allocator.free(trees);
        const column_count = try profile.columnCount();
        const column_log_storage = try self.allocator.alloc(u32, column_count);
        errdefer self.allocator.free(column_log_storage);
        var cursor: usize = 0;
        for (profile.trees, trees) |source, *target| {
            target.* = .{ .column_log_sizes = column_log_storage[cursor .. cursor + source.column_log_sizes.len] };
            @memcpy(@constCast(target.column_log_sizes), source.column_log_sizes);
            cursor += source.column_log_sizes.len;
        }
        const sample_layouts = try self.allocator.dupe(
            SamplePointLayout,
            profile.sample_layouts,
        );
        errdefer self.allocator.free(sample_layouts);
        const nodes = try self.nodes.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(nodes);
        const outputs = try self.outputs.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(outputs);
        const bindings = try self.bindings.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(bindings);
        const profile_digest = profile.identityDigest();
        const graph_digest = graph_mod.computeGraphDigest(nodes, outputs);
        return .{
            .allocator = self.allocator,
            .trees = trees,
            .column_log_storage = column_log_storage,
            .sample_layouts = sample_layouts,
            .lifting_log_size = profile.lifting_log_size,
            .log_blowup_factor = profile.log_blowup_factor,
            .query_count = profile.query_count,
            .nodes = nodes,
            .outputs = outputs,
            .bindings = bindings,
            .profile_digest = profile_digest,
            .graph_digest = graph_digest,
            .identity_digest = circuitDigest(profile_digest, graph_digest, bindings),
        };
    }
};

pub const SecureHandle = struct {
    value: Handle,
    conjugate: Handle,
};

pub const CircuitPoint = struct {
    x: Handle,
    y: Handle,
    conjugate_x: Handle,
    conjugate_y: Handle,
};

pub const SampleTerm = struct {
    column: usize,
    sample: usize,
    random_power: usize,
};

pub const BatchBuilder = struct {
    point_offset: stwo_core.circle.CirclePointIndex,
    terms: std.ArrayList(SampleTerm),
};

pub const CircuitLine = struct {
    column: usize,
    power: Handle,
};

pub const CircuitBatch = struct {
    point: CircuitPoint,
    lines: []CircuitLine,
    conjugate_y_delta: Handle,
    weighted_a_sum: Handle,
    weighted_value_sum: Handle,
    denominator_determinant: Handle,
    imaginary_x: Handle,
    imaginary_y: Handle,
};

pub fn buildSampleBatches(
    allocator: std.mem.Allocator,
    profile: Profile,
) Error!std.ArrayList(BatchBuilder) {
    var batches = std.ArrayList(BatchBuilder).empty;
    errdefer deinitBatchBuilders(allocator, &batches);
    const lifting_step = stwo_core.poly.circle.CanonicCoset.new(
        profile.lifting_log_size,
    ).stepSize();
    const mask_log_size = profile.lifting_log_size - profile.log_blowup_factor;
    const previous_offset = stwo_core.poly.circle.CanonicCoset.new(
        mask_log_size,
    ).stepSize().neg();
    var sample: usize = 0;
    var column: usize = 0;
    var random_power: usize = 0;
    for (profile.trees) |tree| {
        for (tree.column_log_sizes) |log_size| {
            const layout = profile.sample_layouts[column];
            const count = layout.sampleCount();
            if (layout.hasPeriodicity()) {
                const period_multiplier = @as(usize, 1) << @intCast(log_size);
                const second_offset = switch (layout) {
                    .current_previous => previous_offset,
                    .previous_current => stwo_core.circle.CirclePointIndex.zero(),
                    .none, .current => unreachable,
                };
                try pushSampleTerm(
                    allocator,
                    &batches,
                    second_offset.add(lifting_step.mul(period_multiplier)),
                    .{
                        .column = column,
                        .sample = sample + 1,
                        .random_power = random_power,
                    },
                );
                random_power += 1;
            }
            if (count >= 1) {
                const first_offset = switch (layout) {
                    .current, .current_previous => stwo_core.circle.CirclePointIndex.zero(),
                    .previous_current => previous_offset,
                    .none => unreachable,
                };
                try pushSampleTerm(allocator, &batches, first_offset, .{
                    .column = column,
                    .sample = sample,
                    .random_power = random_power,
                });
                random_power += 1;
            }
            if (layout.hasPeriodicity()) {
                const second_offset = switch (layout) {
                    .current_previous => previous_offset,
                    .previous_current => stwo_core.circle.CirclePointIndex.zero(),
                    .none, .current => unreachable,
                };
                try pushSampleTerm(allocator, &batches, second_offset, .{
                    .column = column,
                    .sample = sample + 1,
                    .random_power = random_power,
                });
                random_power += 1;
            }
            sample += count;
            column += 1;
        }
    }
    if (sample != try profile.sampleCount() or
        column != try profile.columnCount() or
        random_power != try profile.termCount())
    {
        return error.SampleCountMismatch;
    }
    return batches;
}

pub fn pushSampleTerm(
    allocator: std.mem.Allocator,
    batches: *std.ArrayList(BatchBuilder),
    point_offset: stwo_core.circle.CirclePointIndex,
    term: SampleTerm,
) Error!void {
    for (batches.items) |*batch| {
        if (batch.point_offset.eql(point_offset)) {
            try batch.terms.append(allocator, term);
            return;
        }
    }
    try batches.append(allocator, .{
        .point_offset = point_offset,
        .terms = .empty,
    });
    try batches.items[batches.items.len - 1].terms.append(allocator, term);
}

pub fn deinitBatchBuilders(
    allocator: std.mem.Allocator,
    batches: *std.ArrayList(BatchBuilder),
) void {
    for (batches.items) |*batch| batch.terms.deinit(allocator);
    batches.deinit(allocator);
}

pub fn pointFromSeed(builder: *Builder, seed: SecureHandle) Error!CircuitPoint {
    const point = try rationalCirclePoint(builder, seed.value);
    const conjugate = try rationalCirclePoint(builder, seed.conjugate);
    return .{
        .x = point.x,
        .y = point.y,
        .conjugate_x = conjugate.x,
        .conjugate_y = conjugate.y,
    };
}

pub const SimplePoint = struct { x: Handle, y: Handle };

pub fn rationalCirclePoint(builder: *Builder, seed: Handle) Error!SimplePoint {
    const one = Handle{ .constant = QM31.one() };
    const square = try builder.mul(seed, seed);
    const inverse = try builder.inverse(try builder.add(one, square));
    return .{
        .x = try builder.mul(try builder.sub(one, square), inverse),
        .y = try builder.mul(try builder.add(seed, seed), inverse),
    };
}

pub fn queryCirclePoint(
    builder: *Builder,
    bits: []const Handle,
    lifting_log_size: u32,
) Error!CircuitPoint {
    if (bits.len != lifting_log_size) return error.InvalidProfile;
    const half_coset = stwo_core.poly.circle.CanonicCoset.new(
        lifting_log_size,
    ).circleDomain().half_coset;
    var point = SimplePoint{
        .x = .{ .constant = QM31.fromBase(half_coset.initial.x) },
        .y = .{ .constant = QM31.fromBase(half_coset.initial.y) },
    };
    const one = Handle{ .constant = QM31.one() };
    for (bits[1..], 1..) |bit, source_bit| {
        const scalar = @as(usize, 1) << @intCast(lifting_log_size - 1 - source_bit);
        const contribution = half_coset.step_size.mul(scalar).toPoint();
        point = try circleAdd(builder, point, .{
            .x = try builder.add(one, try builder.mul(
                bit,
                try builder.sub(
                    .{ .constant = QM31.fromBase(contribution.x) },
                    one,
                ),
            )),
            .y = try builder.mul(bit, .{
                .constant = QM31.fromBase(contribution.y),
            }),
        });
    }
    point.y = try builder.mul(
        point.y,
        try builder.sub(one, try builder.add(bits[0], bits[0])),
    );
    return .{
        .x = point.x,
        .y = point.y,
        .conjugate_x = point.x,
        .conjugate_y = point.y,
    };
}

pub fn circleAdd(builder: *Builder, lhs: SimplePoint, rhs: SimplePoint) Error!SimplePoint {
    return .{
        .x = try builder.sub(
            try builder.mul(lhs.x, rhs.x),
            try builder.mul(lhs.y, rhs.y),
        ),
        .y = try builder.add(
            try builder.mul(lhs.x, rhs.y),
            try builder.mul(lhs.y, rhs.x),
        ),
    };
}

pub fn addBasePoint(
    builder: *Builder,
    point: CircuitPoint,
    offset: stwo_core.circle.CirclePointIndex,
) Error!CircuitPoint {
    const constant = offset.toPoint();
    const rhs = SimplePoint{
        .x = .{ .constant = QM31.fromBase(constant.x) },
        .y = .{ .constant = QM31.fromBase(constant.y) },
    };
    const shifted = try circleAdd(builder, .{ .x = point.x, .y = point.y }, rhs);
    const conjugate = try circleAdd(
        builder,
        .{ .x = point.conjugate_x, .y = point.conjugate_y },
        rhs,
    );
    return .{
        .x = shifted.x,
        .y = shifted.y,
        .conjugate_x = conjugate.x,
        .conjugate_y = conjugate.y,
    };
}

pub const DenominatorComponents = struct {
    determinant: Handle,
    imaginary_x: Handle,
    imaginary_y: Handle,
};

/// Converts the secure sample point to the native verifier's cached
/// `(determinant, pix, piy)` form once per batch. Query evaluation then needs
/// only two products instead of re-splitting four coordinates for every row.
pub fn denominatorComponents(
    builder: *Builder,
    point: CircuitPoint,
) Error!DenominatorComponents {
    // 2^-1 in the Mersenne prime field (2^31 - 1).
    const half = Handle{ .constant = QM31.fromBase(
        M31.fromCanonical(@as(u32, 1) << 30),
    ) };
    const inverse_two_outer_basis = Handle{ .constant = try QM31.fromU32Unchecked(
        0,
        0,
        2,
        0,
    ).inv() };
    const real_x = try builder.mul(
        try builder.add(point.x, point.conjugate_x),
        half,
    );
    const imaginary_x = try builder.mul(
        try builder.sub(point.x, point.conjugate_x),
        inverse_two_outer_basis,
    );
    const real_y = try builder.mul(
        try builder.add(point.y, point.conjugate_y),
        half,
    );
    const imaginary_y = try builder.mul(
        try builder.sub(point.y, point.conjugate_y),
        inverse_two_outer_basis,
    );
    return .{
        .determinant = try builder.sub(
            try builder.mul(real_x, imaginary_y),
            try builder.mul(real_y, imaginary_x),
        ),
        .imaginary_x = imaginary_x,
        .imaginary_y = imaginary_y,
    };
}

pub fn evaluateQuery(
    builder: *Builder,
    query: usize,
    domain_point: CircuitPoint,
    batches: []const CircuitBatch,
    queried_values: []const Handle,
    query_count: u32,
) Error!Handle {
    var answer = Handle{ .constant = QM31.zero() };
    for (batches) |batch| {
        const denominator = try builder.add(
            try builder.sub(
                batch.denominator_determinant,
                try builder.mul(domain_point.x, batch.imaginary_y),
            ),
            try builder.mul(domain_point.y, batch.imaginary_x),
        );
        var weighted_query_sum = Handle{ .constant = QM31.zero() };
        for (batch.lines) |line| {
            const index = try checkedAdd(
                std.math.mul(usize, line.column, @intCast(query_count)) catch
                    return error.ArithmeticOverflow,
                query,
            );
            if (index >= queried_values.len) return error.InvalidProfile;
            weighted_query_sum = try builder.add(
                weighted_query_sum,
                try builder.mul(queried_values[index], line.power),
            );
        }
        // Sum the conjugate-line coefficients in factored form:
        //   c * Σ p(q-v) + (point.y-domain.y) * Σ p(conj(v)-v).
        // This is the native `Σ p(cq-ay-b)` law with batch-common work
        // hoisted out of every sampled column.
        const numerator = try builder.add(
            try builder.mul(
                batch.conjugate_y_delta,
                try builder.sub(weighted_query_sum, batch.weighted_value_sum),
            ),
            try builder.mul(
                batch.weighted_a_sum,
                try builder.sub(batch.point.y, domain_point.y),
            ),
        );
        answer = try builder.add(
            answer,
            try builder.mul(numerator, try builder.inverse(denominator)),
        );
    }
    return answer;
}

pub const SecureSourceKind = enum {
    sampled_value_word,
    oods_seed_word,
    deep_randomness_word,
    answer_word,
};

pub fn trackedInput(
    builder: *Builder,
    handles: []Handle,
    cursor: *usize,
    source: InputSource,
) Error!Handle {
    if (cursor.* >= handles.len) return error.BindingCountMismatch;
    const value = try builder.input(source);
    handles[cursor.*] = value;
    cursor.* += 1;
    return value;
}

pub fn trackedSecureInput(
    builder: *Builder,
    handles: []Handle,
    cursor: *usize,
    kind: SecureSourceKind,
    index: u32,
) Error!Handle {
    var words: [SECURE_WORD_COUNT]Handle = undefined;
    for (&words, 0..) |*word, word_index| {
        const source: InputSource = switch (kind) {
            .sampled_value_word => .{ .sampled_value_word = .{
                .sample = index,
                .word = @intCast(word_index),
            } },
            .oods_seed_word => .{ .oods_seed_word = @intCast(word_index) },
            .deep_randomness_word => .{ .deep_randomness_word = @intCast(word_index) },
            .answer_word => .{ .answer_word = .{
                .query = index,
                .word = @intCast(word_index),
            } },
        };
        word.* = try trackedInput(builder, handles, cursor, source);
    }
    return (try secureFromWords(builder, words)).value;
}

pub fn secureAt(
    builder: *Builder,
    handles: []const Handle,
    base: usize,
) Error!SecureHandle {
    if (base > handles.len or handles.len - base < SECURE_WORD_COUNT)
        return error.InvalidProfile;
    return secureFromWords(builder, handles[base..][0..SECURE_WORD_COUNT].*);
}

pub fn secureFromWords(
    builder: *Builder,
    words: [SECURE_WORD_COUNT]Handle,
) Error!SecureHandle {
    const basis_1 = Handle{ .constant = QM31.fromU32Unchecked(0, 1, 0, 0) };
    const basis_2 = Handle{ .constant = QM31.fromU32Unchecked(0, 0, 1, 0) };
    const basis_3 = Handle{ .constant = QM31.fromU32Unchecked(0, 0, 0, 1) };
    const common = try builder.add(words[0], try builder.mul(words[1], basis_1));
    const outer_2 = try builder.mul(words[2], basis_2);
    const outer_3 = try builder.mul(words[3], basis_3);
    return .{
        .value = try builder.add(try builder.add(common, outer_2), outer_3),
        .conjugate = try builder.sub(try builder.sub(common, outer_2), outer_3),
    };
}

pub fn select(
    builder: *Builder,
    selector: Handle,
    active: Handle,
    inactive: Handle,
) Error!Handle {
    return builder.add(
        inactive,
        try builder.mul(selector, try builder.sub(active, inactive)),
    );
}

pub fn isZeroHandle(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.isZero(),
        .node => false,
    };
}

pub fn isOneHandle(value: Handle) bool {
    return switch (value) {
        .constant => |constant| constant.eql(QM31.one()),
        .node => false,
    };
}

pub fn canonicalPair(lhs: u32, rhs: u32) graph_mod.BinaryOperands {
    return .{ .lhs = @min(lhs, rhs), .rhs = @max(lhs, rhs) };
}

pub fn indexU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.CircuitTooLarge;
}
