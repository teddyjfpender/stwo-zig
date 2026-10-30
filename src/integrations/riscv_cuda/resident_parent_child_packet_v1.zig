//! Raw, unverified child-proof transport. Host work is bounded shape checking
//! and byte copying only. Numerical validation and derived inputs run on device.
//! This packet is never a VerifiedCapture or an admission receipt.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Native = @import("../../frontends/riscv/prover/block_v7_native_proof_v1.zig");
const Arithmetic = @import("resident_parent_arithmetic_plan_v1.zig");
pub const Span = extern struct { first: u32, count: u32 };
pub const CheckKind = enum(u32) { field, equal_u64, bounded_u64 };
pub const Check = extern struct { kind: u32, first: u32, count: u32, low: u32 = 0, high: u32 = 0 };
pub const Kind = enum(u32) { literal, packet_field, resident_field, query_value, query_bits, count_u64 };
/// All offsets are words. query_value: index=packet column, aux=column length,
/// arg=query ordinal. query_bits: index=query ordinal, aux=shift,arg=mask.
pub const InputDescriptor = extern struct { kind: u32, destination: u32 = 0, index: u32, aux: u32 = 0, arg: u32 = 0 };
pub const Limits = struct { max_words: usize = 1 << 26, max_hashes: usize = 1 << 20, max_queries: usize = 128 };
pub const Layer = struct { root: Span, witness: Span, hashes: Span };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    words: []const u32,
    checks: []const Check,
    roots: []const Span,
    samples: Span,
    queries: []const []const Span,
    tree_hashes: []const Span,
    layers: []const Layer,
    terminal: Span,
    nonce: Span,
    projection_sums: []const Span,
    projection_counts: []const Span,
    memory: []const Memory,
    query_count: u32,
    domain_log: u32,
    profile_id: [32]u8,
    pub const Memory = struct { transition: Span, universal: Span, count: Span, ranges: [7]Span };
    pub fn initNative(backing: std.mem.Allocator, profile: *const Profile.Owned, proof: *const Native.Proof, limits: Limits) !Owned {
        // Profile is independently reconstructed, never derived from this proof.
        try profile.validate();
        const raw = &proof.stark.commitment_scheme_proof;
        const shape = &profile.shape;
        const nq = shape.config.fri_config.n_queries;
        if (nq == 0 or nq > limits.max_queries or limits.max_words > std.math.maxInt(u32) or
            !std.meta.eql(raw.config, shape.config) or raw.revision_config != null or
            raw.commitments.items.len != shape.columns.len or raw.sampled_values.items.len != shape.columns.len or
            raw.queried_values.items.len != shape.columns.len or raw.decommitments.items.len != shape.columns.len or
            proof.claims.len != profile.projections.len or proof.memory_claims.len != profile.slots.len or
            raw.fri_proof.inner_layers.len + 1 != shape.widths.len) return error.InvalidResidentChildShape;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var b = Builder{ .a = a, .limit = limits.max_words };
        const roots = try a.alloc(Span, shape.columns.len);
        const queries = try a.alloc([]const Span, shape.columns.len);
        const hashes = try a.alloc(Span, shape.columns.len);
        for (roots, raw.commitments.items) |*out, root| out.* = try b.hashes(&.{root}, limits.max_hashes);
        // First roots are independently pinned by the selected epoch entry.
        // Validate equality on device rather than accepting packet roots as pins.
        const pinned = [_][32]u8{ profile.pin.roots[0], profile.pin.roots[1], profile.pin.access_root };
        for (roots[0 .. profile.trace_count - 1], pinned[0 .. profile.trace_count - 1]) |span, root| {
            for (0..4) |j| try b.checks.append(a, .{ .kind = @intFromEnum(CheckKind.equal_u64), .first = span.first + @as(u32, @intCast(2 * j)), .count = 2, .low = std.mem.readInt(u32, root[j * 8 ..][0..4], .little), .high = std.mem.readInt(u32, root[j * 8 + 4 ..][0..4], .little) });
        }

        const sample_first = b.words.items.len;
        var column_index: usize = 0;
        for (shape.columns, raw.sampled_values.items) |columns, samples| {
            if (samples.len != columns.len) return error.InvalidResidentChildShape;
            for (samples) |values| {
                if (values.len != shape.layouts[column_index].sampleCount()) return error.InvalidResidentChildShape;
                _ = try b.secure(values);
                column_index += 1;
            }
        }
        const sample_span = Span{ .first = @intCast(sample_first), .count = @intCast(b.words.items.len - sample_first) };
        for (shape.columns, raw.queried_values.items, queries, raw.decommitments.items, hashes) |columns, values, *out, decommit, *hs| {
            if (values.len != columns.len) return error.InvalidResidentChildShape;
            const spans = try a.alloc(Span, columns.len);
            for (values, spans) |column, *s| {
                if (column.len == 0 or column.len > nq) return error.InvalidResidentChildShape;
                s.* = try b.base(column);
            }
            out.* = spans;
            hs.* = try b.hashes(decommit.hash_witness, limits.max_hashes);
        }
        const layers = try a.alloc(Layer, shape.widths.len);
        for (layers, 0..) |*out, i| {
            const layer = if (i == 0) raw.fri_proof.first_layer else raw.fri_proof.inner_layers[i - 1];
            if (layer.fri_witness.len > try std.math.mul(usize, nq, shape.widths[i])) return error.InvalidResidentChildShape;
            out.* = .{ .root = try b.hashes(&.{layer.commitment}, limits.max_hashes), .witness = try b.secure(layer.fri_witness), .hashes = try b.hashes(layer.decommitment.hash_witness, limits.max_hashes) };
        }
        const coeffs = raw.fri_proof.last_layer_poly.coefficients();
        if (coeffs.len != try shape.friProfile().lastLayerCoefficientCount()) return error.InvalidResidentChildShape;
        const terminal = try b.secure(coeffs);
        const nonce = try b.integer(raw.proof_of_work);
        const sums = try a.alloc(Span, proof.claims.len);
        const counts = try a.alloc(Span, proof.claims.len);
        for (proof.claims, profile.projections, sums, counts) |claim, slot, *sum, *count| {
            sum.* = try b.secure(&.{claim.sum});
            count.* = try b.integer(claim.row_count);
            try b.checks.append(a, .{ .kind = @intFromEnum(CheckKind.equal_u64), .first = count.first, .count = 2, .low = @truncate(slot.n_rows), .high = @intCast(@as(u64, slot.n_rows) >> 32) });
        }
        const memory = try a.alloc(Memory, proof.memory_claims.len);
        for (proof.memory_claims, profile.slots, memory) |claim, slot, *out| {
            out.transition = try b.secure(&.{claim.transition_sum});
            out.universal = try b.secure(&.{claim.universal_sum});
            out.count = try b.integer(claim.active_count);
            const bound = @as(u64, 1) << @intCast(slot.log_size);
            try b.checks.append(a, .{ .kind = @intFromEnum(CheckKind.bounded_u64), .first = out.count.first, .count = 2, .low = @truncate(bound), .high = @truncate(bound >> 32) });
            for (claim.range_claims, &out.ranges) |v, *s| s.* = try b.secure(&.{v});
        }
        return .{ .arena = arena, .words = try b.words.toOwnedSlice(a), .checks = try b.checks.toOwnedSlice(a), .roots = roots, .samples = sample_span, .queries = queries, .tree_hashes = hashes, .layers = layers, .terminal = terminal, .nonce = nonce, .projection_sums = sums, .projection_counts = counts, .memory = memory, .query_count = @intCast(nq), .domain_log = shape.lifting_log, .profile_id = profile.seal };
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn sample(self: *const Owned, index: u32, limb: u32) !InputDescriptor {
        if (limb >= 4 or index >= self.samples.count / 4) return error.InvalidResidentChildRoute;
        return packet(self.samples.first + 4 * index + limb);
    }
    pub fn query(self: *const Owned, tree: u32, column: u32, ordinal: u32) !InputDescriptor {
        if (tree >= self.queries.len or column >= self.queries[tree].len or ordinal >= self.query_count) return error.InvalidResidentChildRoute;
        const s = self.queries[tree][column];
        return .{ .kind = @intFromEnum(Kind.query_value), .index = s.first, .aux = s.count, .arg = ordinal };
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    limit: usize,
    words: std.ArrayList(u32) = .empty,
    checks: std.ArrayList(Check) = .empty,
    fn reserve(self: *Builder, n: usize) !Span {
        const end = try std.math.add(usize, self.words.items.len, n);
        if (end > self.limit) return error.ResidentChildPacketLimit;
        const first = self.words.items.len;
        try self.words.resize(self.a, end);
        return .{ .first = @intCast(first), .count = @intCast(n) };
    }
    fn integer(self: *Builder, v: u64) !Span {
        const s = try self.reserve(2);
        self.words.items[s.first] = @truncate(v);
        self.words.items[s.first + 1] = @truncate(v >> 32);
        return s;
    }
    fn secure(self: *Builder, values: []const core.fields.qm31.QM31) !Span {
        const s = try self.reserve(try std.math.mul(usize, values.len, 4));
        for (values, 0..) |v, i| for (v.toM31Array(), 0..) |f, j| {
            self.words.items[s.first + 4 * i + j] = f.v;
        };
        try self.checks.append(self.a, .{ .kind = @intFromEnum(CheckKind.field), .first = s.first, .count = s.count });
        return s;
    }
    fn base(self: *Builder, values: []const core.fields.m31.M31) !Span {
        const s = try self.reserve(values.len);
        for (values, 0..) |v, i| self.words.items[s.first + i] = v.v;
        try self.checks.append(self.a, .{ .kind = @intFromEnum(CheckKind.field), .first = s.first, .count = s.count });
        return s;
    }
    fn hashes(self: *Builder, values: []const [32]u8, max: usize) !Span {
        if (values.len > max) return error.ResidentChildPacketLimit;
        const s = try self.reserve(try std.math.mul(usize, values.len, 8));
        for (values, 0..) |v, i| for (0..8) |j| {
            self.words.items[s.first + 8 * i + j] = std.mem.readInt(u32, v[j * 4 ..][0..4], .little);
        };
        return s;
    }
};
pub fn literal(v: u32) InputDescriptor {
    return .{ .kind = @intFromEnum(Kind.literal), .index = v };
}
pub fn packet(i: u32) InputDescriptor {
    return .{ .kind = @intFromEnum(Kind.packet_field), .index = i };
}
pub fn resident(i: u32) InputDescriptor {
    return .{ .kind = @intFromEnum(Kind.resident_field), .index = i };
}
pub fn queryBits(query: u32, shift: u32, mask: u32) !InputDescriptor {
    if (shift >= 32) return error.InvalidResidentChildRoute;
    return .{ .kind = @intFromEnum(Kind.query_bits), .index = query, .aux = shift, .arg = mask };
}
/// Bind a scalar or one limb of a secure graph input. Every input limb must be
/// written exactly once by the enclosing schedule before graph execution.
pub fn destination(plan: *const Arithmetic.Plan, graph: usize, node: u32, limb: u2, source: InputDescriptor) !InputDescriptor {
    var out = source;
    out.destination = std.math.cast(u32, try plan.inputWord(graph, node, limb)) orelse return error.ResidentChildPacketLimit;
    return out;
}

/// Device-written transcript and FRI intermediate arenas. These are offsets,
/// never CPU-computed challenge/answer values. Expanded FRI layers MUST be
/// produced from raw witnesses + DEEP answers + previous device folds.
pub const DeviceInputs = struct {
    challenges: Span,
    composition: Span,
    oods: Span,
    deep_randomness: Span,
    deep_answers: Span,
    fri_alphas: Span,
    fri_expanded: []const Span,
};
pub const Bindings = struct {
    raw: *const Owned,
    profile: *const Profile.Owned,
    device: DeviceInputs,
    pub fn init(raw: *const Owned, profile: *const Profile.Owned, device: DeviceInputs) !Bindings {
        if (!std.meta.eql(raw.profile_id, profile.seal) or device.challenges.count != 106 * 4 or
            device.composition.count != 4 or device.oods.count != 4 or device.deep_randomness.count != 4 or
            device.deep_answers.count != raw.query_count * 4 or device.fri_alphas.count != profile.shape.widths.len * 4 or
            device.fri_expanded.len != profile.shape.widths.len) return error.InvalidResidentChildRoute;
        for (device.fri_expanded, profile.shape.widths) |s, w| if (s.count != @as(u64, raw.query_count) * w * 4) return error.InvalidResidentChildRoute;
        return .{ .raw = raw, .profile = profile, .device = device };
    }
    fn secureResident(s: Span, index: u32) ![4]InputDescriptor {
        if (index >= s.count / 4 or s.count % 4 != 0 or @as(u64, s.first) + s.count > std.math.maxInt(u32)) return error.InvalidResidentChildRoute;
        var out: [4]InputDescriptor = undefined;
        for (&out, 0..) |*v, i| v.* = resident(s.first + 4 * index + @as(u32, @intCast(i)));
        return out;
    }
    fn securePacket(s: Span) ![4]InputDescriptor {
        if (s.count != 4) return error.InvalidResidentChildRoute;
        var out: [4]InputDescriptor = undefined;
        for (&out, 0..) |*v, i| v.* = packet(s.first + @as(u32, @intCast(i)));
        return out;
    }
    fn scalar(v: InputDescriptor) [4]InputDescriptor {
        return .{ v, literal(0), literal(0), literal(0) };
    }
    pub fn composition(self: Bindings, source: @import("../../frontends/riscv/recursion/air/blake3_execution_composition.zig").Source) ![4]InputDescriptor {
        return switch (source) {
            .sample => |i| .{ try self.raw.sample(i, 0), try self.raw.sample(i, 1), try self.raw.sample(i, 2), try self.raw.sample(i, 3) },
            .challenge => |i| try secureResident(self.device.challenges, i),
            .composition => try secureResident(self.device.composition, 0),
            .oods => try secureResident(self.device.oods, 0),
            .public_input => |i| blk: {
                if (i < 8) {
                    const base = try @import("../../frontends/riscv/prover/block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(self.profile.pin.frame);
                    break :blk scalar(literal(@as(u8, @truncate(base >> @intCast(8 * i)))));
                }
                const index = i - 8;
                if (index < self.raw.projection_sums.len) break :blk try securePacket(self.raw.projection_sums[index]);
                const memory_index = index - self.raw.projection_sums.len;
                if (memory_index / 10 >= self.raw.memory.len) return error.InvalidResidentChildRoute;
                const m = self.raw.memory[memory_index / 10];
                break :blk switch (memory_index % 10) {
                    0 => try securePacket(m.transition),
                    1 => try securePacket(m.universal),
                    2 => scalar(.{ .kind = @intFromEnum(Kind.count_u64), .index = m.count.first }),
                    else => try securePacket(m.ranges[memory_index % 10 - 3]),
                };
            },
            else => error.InvalidResidentChildRoute,
        };
    }
    pub fn deep(self: Bindings, source: @import("../../frontends/riscv/recursion/air/pcs_deep_input_witness_reference.zig").Source) ![4]InputDescriptor {
        const v: InputDescriptor = switch (source) {
            .active_selector => literal(1),
            .sampled_value_word => |s| try self.raw.sample(s.sample, s.word),
            .queried_value => |s| try self.raw.query(s.tree, s.column, s.query),
            .oods_seed_word => |w| try word(self.device.oods, w),
            .deep_randomness_word => |w| try word(self.device.deep_randomness, w),
            .query_bit => |s| blk: {
                if (s.query >= self.raw.query_count or s.bit >= 31) return error.InvalidResidentChildRoute;
                break :blk try queryBits(s.query, s.bit, 1);
            },
            .query_position => |q| blk: {
                if (q >= self.raw.query_count) return error.InvalidResidentChildRoute;
                break :blk try queryBits(q, 0, std.math.maxInt(u32));
            },
            .answer_word => |s| blk: {
                if (s.word >= 4 or s.query >= self.raw.query_count) return error.InvalidResidentChildRoute;
                break :blk try word(self.device.deep_answers, 4 * s.query + s.word);
            },
        };
        return scalar(v);
    }
    pub fn fri(self: Bindings, source: @import("../../frontends/riscv/recursion/air/fri_verifier_circuit.zig").InputSource) ![4]InputDescriptor {
        const v: InputDescriptor = switch (source) {
            .active_selector => literal(1),
            .deep_answer_word => |s| blk: {
                if (s.word >= 4 or s.query >= self.raw.query_count) return error.InvalidResidentChildRoute;
                break :blk try word(self.device.deep_answers, 4 * s.query + s.word);
            },
            .authenticated_value_word => |s| blk: {
                if (s.layer >= self.device.fri_expanded.len or s.query >= self.raw.query_count or s.word >= 4 or s.offset >= self.profile.shape.widths[s.layer]) return error.InvalidResidentChildRoute;
                break :blk try word(self.device.fri_expanded[s.layer], 4 * (s.query * self.profile.shape.widths[s.layer] + s.offset) + s.word);
            },
            .fri_alpha_word => |s| blk: {
                if (s.word >= 4 or s.layer >= self.profile.shape.widths.len) return error.InvalidResidentChildRoute;
                break :blk try word(self.device.fri_alphas, 4 * s.layer + s.word);
            },
            .query_bit => |s| blk: {
                if (s.query >= self.raw.query_count or s.bit >= 31) return error.InvalidResidentChildRoute;
                break :blk try queryBits(s.query, s.bit, 1);
            },
            .fri_position => |s| try self.position(s.layer, s.query, false),
            .fri_offset => |s| try self.position(s.layer, s.query, true),
            .last_layer_position => |s| try self.position(@intCast(self.profile.shape.widths.len), s.query, false),
            .last_layer_coefficient_word => |s| blk: {
                if (s.word >= 4 or s.coefficient >= self.raw.terminal.count / 4) return error.InvalidResidentChildRoute;
                break :blk packet(self.raw.terminal.first + 4 * s.coefficient + s.word);
            },
        };
        return scalar(v);
    }
    fn word(s: Span, index: u32) !InputDescriptor {
        if (index >= s.count or @as(u64, s.first) + index > std.math.maxInt(u32)) return error.InvalidResidentChildRoute;
        return resident(s.first + index);
    }
    fn position(self: Bindings, layer: u32, q: u32, offset: bool) !InputDescriptor {
        if (q >= self.raw.query_count or layer > self.profile.shape.widths.len or (offset and layer == self.profile.shape.widths.len)) return error.InvalidResidentChildRoute;
        var shift: u32 = 0;
        for (self.profile.shape.widths[0..layer]) |w| shift += std.math.log2_int(u32, w);
        return queryBits(q, shift, if (offset) self.profile.shape.widths[layer] - 1 else std.math.maxInt(u32));
    }
};

pub const Routes = struct {
    allocator: std.mem.Allocator,
    composition: []InputDescriptor,
    deep: []InputDescriptor,
    fri: []InputDescriptor,
    pub fn init(a: std.mem.Allocator, bindings: Bindings, plan: *const Arithmetic.Plan, graph_indices: [3]usize, composition: *const @import("../../frontends/riscv/recursion/air/block_v7_native_composition_v1.zig").Compiled, deep: *const @import("../../frontends/riscv/recursion/air/pcs_deep_circuit.zig").Circuit, fri: *const @import("../../frontends/riscv/recursion/air/fri_verifier_circuit.zig").Circuit) !Routes {
        try composition.validateAgainst(bindings.profile);
        try deep.validate();
        try fri.validate();
        if (!std.meta.eql(deep.profile_digest, bindings.profile.shape.deepProfile().identityDigest()) or !std.meta.eql(fri.profile_digest, bindings.profile.shape.friProfile().identityDigest())) return error.InvalidResidentChildRoute;
        const graphs = [_]Arithmetic.Original.CircuitGraph{ composition.circuit.graph(), deep.graph(), fri.graph() };
        for (graph_indices, graphs, 0..) |index, g, i| {
            if (index >= plan.graphs.len or !std.meta.eql(plan.graph_ids[index], g.identity_digest) or plan.graphs[index].node_count != g.nodes.len) return error.InvalidResidentChildRoute;
            for (graph_indices[0..i]) |previous| if (previous == index) return error.InvalidResidentChildRoute;
        }
        const c = try a.alloc(InputDescriptor, composition.sources.len * 4);
        errdefer a.free(c);
        const d = try a.alloc(InputDescriptor, deep.bindings.len * 4);
        errdefer a.free(d);
        const f = try a.alloc(InputDescriptor, fri.bindings.len * 4);
        errdefer a.free(f);
        var cursor: usize = 0;
        for (composition.circuit.nodes, 0..) |n, id| if (n.op == .input) {
            if (cursor >= composition.sources.len) return error.InvalidResidentChildRoute;
            const values = try bindings.composition(composition.sources[cursor]);
            for (values, 0..) |v, limb| c[4 * cursor + limb] = try destination(plan, graph_indices[0], @intCast(id), @intCast(limb), v);
            cursor += 1;
        };
        if (cursor != composition.sources.len) return error.InvalidResidentChildRoute;
        for (deep.bindings, 0..) |b, i| {
            const values = try bindings.deep(b.source);
            for (values, 0..) |v, limb| d[4 * i + limb] = try destination(plan, graph_indices[1], b.node_id, @intCast(limb), v);
        }
        for (fri.bindings, 0..) |b, i| {
            const values = try bindings.fri(b.source);
            for (values, 0..) |v, limb| f[4 * i + limb] = try destination(plan, graph_indices[2], b.node_id, @intCast(limb), v);
        }
        for (graph_indices, [_]usize{ c.len, d.len, f.len }) |index, n| if (n != @as(usize, plan.graphs[index].input_count) * 4) return error.InvalidResidentChildRoute;
        return .{ .allocator = a, .composition = c, .deep = d, .fri = f };
    }
    pub fn deinit(self: *Routes) void {
        self.allocator.free(self.composition);
        self.allocator.free(self.deep);
        self.allocator.free(self.fri);
        self.* = undefined;
    }
};

test "resident child packet preserves untrusted values for device checks and bounds copy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var b = Builder{ .a = arena.allocator(), .limit = 8 };
    var untrusted = core.fields.qm31.QM31.zero();
    untrusted.c0.a.v = 2147483647;
    const s = try b.secure(&.{untrusted});
    try std.testing.expectEqual(@as(u32, 2147483647), b.words.items[s.first]);
    try std.testing.expectEqual(@intFromEnum(CheckKind.field), b.checks.items[0].kind);
    _ = try b.integer(std.math.maxInt(u64));
    try std.testing.expectError(error.ResidentChildPacketLimit, b.secure(&.{core.fields.qm31.QM31.zero()}));
    try std.testing.expectError(error.InvalidResidentChildRoute, queryBits(0, 32, 1));
}
