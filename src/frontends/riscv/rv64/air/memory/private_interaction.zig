//! Concrete private RAM LogUp writer/closure. One borrowed row scratch and a
//! bounded inversion batch serve all RAM tables; byte inverses are shared once.
//! The returned state debt MUST close inside the same CPU/K/PCS transcript.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const T = @import("private_trace.zig");
const CA = @import("chunk_air.zig");
const Cell = @import("cell_air.zig");
const Leaf = @import("leaf_air.zig");
const Node = @import("node_air.zig");
const Side = @import("side_air.zig");
const Permit = @import("permit_air.zig");
const PA = @import("policy_air.zig");
const internal = @import("internal_relations.zig");
const state = @import("../relations.zig");
const P = @import("../protocol.zig");
const Relations = @import("../../../air/relation_challenges.zig").Relations;
const provider = @import("provider_interaction.zig");
const values = @import("values.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const MAX_SUMS = 13;
pub const Challenges = struct {
    permutations: Relations,
    ram: internal.Prepared,
    state: state.Challenges,
    policy: PA.PolicyChallenge,
    bytes: Q,
    /// Same transcript's already drawn state/BYTE challenges. This method
    /// introduces only independent Poseidon, tagged RAM and policy randomness.
    pub fn drawShared(a: std.mem.Allocator, channel: *P.Channel, shared_state: state.Challenges, byte_alpha: Q) !Challenges {
        const permutations = try Relations.draw(a, channel);
        const ram = internal.Challenge.draw(channel).prepare();
        const policy = PA.PolicyChallenge.draw(channel);
        return .{ .permutations = permutations, .ram = ram, .state = shared_state, .policy = policy, .bytes = byte_alpha };
    }
    pub fn draw(a: std.mem.Allocator, channel: *P.Channel) !Challenges {
        const permutations = try Relations.draw(a, channel);
        const ram = internal.Challenge.draw(channel).prepare();
        const s = state.Challenges.draw(channel);
        const policy = PA.PolicyChallenge.draw(channel);
        channel.mixU32s(&.{0x52425954});
        return .{ .permutations = permutations, .ram = ram, .state = s, .policy = policy, .bytes = channel.drawSecureFelt() };
    }
};
pub const Claims = struct {
    tables: [8][MAX_SUMS]Q = @splat(@splat(Q.zero())),
    pub fn validate(self: *const Claims) !void {
        for (T.TABLES) |table| for (self.tables[@intFromEnum(table)][T.sumCount(table)..]) |claim| if (!claim.isZero()) return error.NoncanonicalPrivateRamClaimTail;
    }
    pub fn slice(self: *const Claims, table: T.Table) []const Q {
        return self.tables[@intFromEnum(table)][0..T.sumCount(table)];
    }
    pub fn mix(self: *const Claims, channel: *P.Channel) void {
        for (T.TABLES) |table| channel.mixFelts(self.slice(table));
    }
};
const ROW_BATCH = 64;
const MAX_TERMS = ROW_BATCH * MAX_SUMS * 3;
const Scratch = struct {
    native: [111]M,
    old_native: [111]M,
    main: [111]Q,
    previous: [111]Q,
    fixed: [8]Q,
    denominators: [MAX_TERMS]Q,
    numerators: [MAX_TERMS]Q,
    inverses: [MAX_TERMS]Q,
    destinations: [MAX_TERMS]u16,
    contributions: [ROW_BATCH * MAX_SUMS]Q,
};
fn term(shapes: T.Shapes, table: T.Table, f: []const Q, m: []const Q, previous: []const Q, ch: *const Challenges, group: usize, slot: usize) PA.Term {
    return switch (table) {
        .chunk => if (group == 0) (if (slot == 0) CA.ioTerm(shapes.chunk, f[0..CA.FIXED], m[0..CA.MAIN], previous[0..CA.MAIN], ch.permutations.poseidon2_io) else .{ .denominator = Q.one(), .numerator = Q.zero() }) else CA.ramTerm(shapes.chunk, f[0..CA.FIXED], m[0..CA.MAIN], previous[0..CA.MAIN], &ch.ram, 3 * (group - 1) + slot),
        .common_cells, .edge_cells => blk: {
            const shape = if (table == .common_cells) shapes.common_cells else shapes.edge_cells;
            const row = m[0..Cell.MAIN];
            const fixed = f[0..Cell.FIXED];
            break :blk if (group < Cell.BYTE_SUMS) Cell.byteTerm(row, ch.bytes, 3 * group + slot) else if (group < Cell.HEADER_SUM) Cell.payloadTerm(fixed, row, &ch.ram, 3 * (group - Cell.BYTE_SUMS) + slot) else if (group == Cell.HEADER_SUM) (if (slot == 0) Cell.headerTerm(fixed, row, &ch.ram) else .{ .denominator = Q.one(), .numerator = Q.zero() }) else if (group == Cell.PERMIT_SUM) (if (slot == 0) Cell.permitTerm(shape, fixed, row, &ch.ram) else .{ .denominator = Q.one(), .numerator = Q.zero() }) else Cell.stateTerm(fixed, row, ch.state, slot);
        },
        .leaf => if (group < 5) Leaf.byteTerm(m[0..Leaf.MAIN], ch.bytes, 3 * group + slot) else if (group == 5) Leaf.nodeTerm(m[0..Leaf.MAIN], &ch.ram, slot) else if (group == 6) Leaf.digestTerm(m[0..Leaf.MAIN], &ch.ram, slot) else if (slot == 0) Leaf.headerTerm(f[0..Leaf.FIXED], m[0..Leaf.MAIN], &ch.ram) else .{ .denominator = Q.one(), .numerator = Q.zero() },
        .node => if (group < 2) Node.ioTerm(m[0..Node.MAIN], ch.permutations.poseidon2_io, 3 * group + slot) else if (group < 4) Node.nodeTerm(m[0..Node.MAIN], &ch.ram, 3 * (group - 2) + slot) else Node.byteTerm(m[0..Node.MAIN], ch.bytes, 3 * (group - 4) + slot),
        .side => if (group < 3) Side.byteTerm(m[0..Side.MAIN], ch.bytes, 3 * group + slot) else Side.nodeTerm(m[0..Side.MAIN], &ch.ram, slot),
        .common_permits, .edge_permits => Permit.term(if (table == .common_permits) shapes.common_permits else shapes.edge_permits, m[0..Permit.MAIN], &.{ .bytes = ch.bytes, .policy = ch.policy, .permit = ch.ram.permitChallenge() }, group, slot),
    };
}
fn byteColumn(table: T.Table, group: usize, slot: usize) ?usize {
    return switch (table) {
        .chunk => null,
        .common_cells, .edge_cells => if (group < 7 and 3 * group + slot < 19) 3 * group + slot else null,
        .leaf => if (group < 5) 3 * group + slot else null,
        .node => if (group >= 4 and 3 * (group - 4) + slot < 14) Node.INDEX_BYTES + 3 * (group - 4) + slot else null,
        .side => if (group < 3 and 3 * group + slot < 7) Side.INDEX_BYTES + 3 * group + slot else null,
        .common_permits, .edge_permits => if (group < PA.BYTE_SUMS and 3 * group + slot < PA.RANGES) PA.rangeField(3 * group + slot) else null,
    };
}
/// Borrowed row source. No arena owner is copied into jobs or proof assembly.
pub const Rows = struct {
    shapes: T.Shapes,
    mains: [8][]const M,
    records: []const values.PermutationIO,
    pub fn fromTrace(trace: *const T.Trace) Rows {
        var mains: [8][]const M = undefined;
        for (T.TABLES) |table| mains[@intFromEnum(table)] = T.mainData(trace, table);
        return .{ .shapes = trace.shapes, .mains = mains, .records = trace.recorder.calls.items };
    }
    pub fn validate(self: Rows) !void {
        try self.shapes.validate();
        for (T.TABLES) |table| if (self.mains[@intFromEnum(table)].len != T.mainWidth(table) * (@as(usize, 1) << @intCast(T.tableLog(self.shapes, table)))) return error.InvalidPrivateRamRows;
        if (self.records.len != @as(usize, self.shapes.chunk.hashes) * self.shapes.chunk.geometry.permutations() + @as(usize, self.shapes.node.nodes) * 4) return error.InvalidPrivateRamRows;
    }
};
const Input = union(enum) {
    rows: Rows,
    metadata: *const T.Trace,
    fn validate(self: Input) !void {
        switch (self) {
            .rows => |rows| try rows.validate(),
            .metadata => |trace| try trace.validateMetadata(),
        }
    }
    fn shapes(self: Input) T.Shapes {
        return switch (self) {
            .rows => |rows| rows.shapes,
            .metadata => |trace| trace.shapes,
        };
    }
    fn records(self: Input) []const values.PermutationIO {
        return switch (self) {
            .rows => |rows| rows.records,
            .metadata => |trace| trace.recorder.calls.items,
        };
    }
};
pub const Interaction = struct {
    allocator: std.mem.Allocator,
    tables: [8][]M,
    provider: provider.Interaction,
    claims: Claims,
    pub fn init(a: std.mem.Allocator, trace: *const T.Trace, ch: *const Challenges) !Interaction {
        return initMetadata(a, trace, ch);
    }
    pub fn initRows(a: std.mem.Allocator, rows: Rows, ch: *const Challenges) !Interaction {
        return initInput(a, .{ .rows = rows }, ch);
    }
    pub fn initMetadata(a: std.mem.Allocator, trace: *const T.Trace, ch: *const Challenges) !Interaction {
        return initInput(a, .{ .metadata = trace }, ch);
    }
    fn initInput(a: std.mem.Allocator, input: Input, ch: *const Challenges) !Interaction {
        try input.validate();
        const shapes = input.shapes();
        const scratch = try a.create(Scratch);
        defer a.destroy(scratch);
        var byte_inverses: [256]Q = undefined;
        for (&byte_inverses, 0..) |*inverse, i| inverse.* = try ch.bytes.sub(E.q(@intCast(i))).inv();
        var tables: [8][]M = @splat(&.{});
        var initialized: usize = 0;
        errdefer for (tables[0..initialized]) |data| a.free(data);
        var claims = Claims{};
        for (T.TABLES) |table| {
            const tag = @intFromEnum(table);
            const log = T.tableLog(shapes, table);
            const size = @as(usize, 1) << @intCast(log);
            const sums = T.sumCount(table);
            const width = T.mainWidth(table);
            const fixed_width = T.fixedWidth(table);
            tables[tag] = try a.alloc(M, 4 * sums * size);
            initialized += 1;
            var start: usize = 0;
            while (start < size) {
                const used: usize = @min(ROW_BATCH, size - start);
                var inverse_count: usize = 0;
                @memset(scratch.contributions[0 .. used * sums], Q.zero());
                for (0..used) |i| {
                    const logical = start + i;
                    const at = physical(logical, log);
                    const previous_at = physical((logical + size - 1) % size, log);
                    switch (input) {
                        .rows => |rows| {
                            const data = rows.mains[@intFromEnum(table)];
                            for (0..width) |j| {
                                scratch.native[j] = data[j * size + at];
                                scratch.main[j] = Q.fromBase(scratch.native[j]);
                                scratch.previous[j] = Q.fromBase(data[j * size + previous_at]);
                            }
                        },
                        .metadata => |trace| {
                            try trace.restoreRow(table, logical, scratch.native[0..width]);
                            for (scratch.main[0..width], scratch.native[0..width]) |*field, native| field.* = Q.fromBase(native);
                            @memset(scratch.previous[0..width], Q.zero());
                            if (table == .chunk) {
                                try trace.restoreRow(table, (logical + size - 1) % size, scratch.old_native[0..width]);
                                for (scratch.previous[0..width], scratch.old_native[0..width]) |*field, native| field.* = Q.fromBase(native);
                            }
                        },
                    }
                    var base_fixed: [8]M = undefined;
                    T.fixedAt(shapes, table, logical, base_fixed[0..fixed_width]);
                    for (scratch.fixed[0..fixed_width], base_fixed[0..fixed_width]) |*field, value| field.* = Q.fromBase(value);
                    for (0..sums) |group| for (0..3) |slot| {
                        const t = term(shapes, table, scratch.fixed[0..fixed_width], scratch.main[0..width], scratch.previous[0..width], ch, group, slot);
                        if (t.numerator.isZero()) continue;
                        if (byteColumn(table, group, slot)) |column| {
                            const byte = scratch.native[column].toU32();
                            if (byte < 256) {
                                const destination = i * sums + group;
                                scratch.contributions[destination] = scratch.contributions[destination].add(t.numerator.mul(byte_inverses[byte]));
                                continue;
                            }
                        }
                        scratch.denominators[inverse_count] = t.denominator;
                        scratch.numerators[inverse_count] = t.numerator;
                        scratch.destinations[inverse_count] = @intCast(i * sums + group);
                        inverse_count += 1;
                    };
                }
                if (inverse_count != 0) try core.fields.batchInverseInPlace(Q, scratch.denominators[0..inverse_count], scratch.inverses[0..inverse_count]);
                for (scratch.inverses[0..inverse_count], scratch.numerators[0..inverse_count], scratch.destinations[0..inverse_count]) |inverse, numerator, destination| scratch.contributions[destination] = scratch.contributions[destination].add(numerator.mul(inverse));
                for (0..used) |i| for (0..sums) |group| {
                    claims.tables[tag][group] = claims.tables[tag][group].add(scratch.contributions[i * sums + group]);
                    for (claims.tables[tag][group].toM31Array(), 0..) |coordinate, j| tables[tag][(4 * group + j) * size + physical(start + i, log)] = coordinate;
                };
                start += used;
            }
        }
        const permutations = try provider.generate(a, input.records(), shapes.provider_log, &ch.permutations);
        return .{ .allocator = a, .tables = tables, .provider = permutations, .claims = claims };
    }
    pub fn deinit(self: *Interaction) void {
        for (self.tables) |data| self.allocator.free(data);
        self.provider.deinit();
        self.* = undefined;
    }
};
/// All internal/hash/byte/policy debts close here. State remains a typed debt
/// for the SAME transcript's CPU + K bridge + expected register delta closure.
pub const Debts = struct { state: Q, bytes: Q };
pub fn close(trace_before: values.Digest, trace_after: values.Digest, geometry: values.Geometry, claims: *const Claims, provider_claims: [2]Q, byte_claim: Q, policy_claim: Q, ch: *const Challenges) !Q {
    const debts = try closeWithoutByte(trace_before, trace_after, geometry, claims, provider_claims, policy_claim, ch);
    if (!debts.bytes.add(byte_claim).isZero()) return error.UnbalancedPrivateRamBytes;
    return debts.state;
}
/// Typed debts for a containing proof with ONE global byte provider. No host
/// rational target is accepted or synthesized for either external relation.
pub fn closeWithoutByte(trace_before: values.Digest, trace_after: values.Digest, geometry: values.Geometry, claims: *const Claims, provider_claims: [2]Q, policy_claim: Q, ch: *const Challenges) !Debts {
    try claims.validate();
    const chunk = claims.slice(.chunk);
    const node = claims.slice(.node);
    if (!provider_claims[0].isZero() or !provider_claims[1].add(chunk[0]).add(node[0]).add(node[1]).isZero()) return error.UnbalancedPrivateRamPoseidon;
    var bytes = Q.zero();
    var policy_sum = policy_claim;
    var ram_sum = Q.zero();
    var state_sum = Q.zero();
    for (T.TABLES) |table| {
        const row = claims.slice(table);
        for (row, 0..) |claim, group| {
            const is_byte = switch (table) {
                .chunk => false,
                .node => group >= 4,
                .common_cells, .edge_cells => group < 7,
                .leaf => group < 5,
                .side => group < 3,
                .common_permits, .edge_permits => group < PA.BYTE_SUMS,
            };
            if (is_byte) {
                bytes = bytes.add(claim);
                continue;
            }
            switch (table) {
                .chunk => if (group != 0) {
                    ram_sum = ram_sum.add(claim);
                },
                .node => if (group >= 2) {
                    ram_sum = ram_sum.add(claim);
                },
                .common_cells, .edge_cells => if (group == Cell.STATE_SUM) {
                    state_sum = state_sum.add(claim);
                } else {
                    ram_sum = ram_sum.add(claim);
                },
                .common_permits, .edge_permits => if (group == PA.POLICY_SUM) {
                    policy_sum = policy_sum.add(claim);
                } else {
                    ram_sum = ram_sum.add(claim);
                },
                .leaf, .side => ram_sum = ram_sum.add(claim),
            }
        }
    }
    if (!policy_sum.isZero()) return error.UnbalancedPrivateRamPolicy;
    var before: [9]Q = undefined;
    var after: [9]Q = undefined;
    for (&before, &after, trace_before, trace_after) |*b, *e, x, y| {
        if (x >= core.fields.m31.Modulus or y >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        b.* = E.q(x);
        e.* = E.q(y);
    }
    ram_sum = ram_sum.add(try ch.ram.node(Q.zero(), E.q(geometry.depth()), @splat(Q.zero()), before).inv()).add(try ch.ram.node(Q.one(), E.q(geometry.depth()), @splat(Q.zero()), after).inv());
    if (!ram_sum.isZero()) return error.UnbalancedPrivateRamGraph;
    return .{ .state = state_sum, .bytes = bytes };
}

/// Conservative absolute query mass over PADDED independent table domains.
/// The containing proof must add all other BYTE consumers and require <M31.
pub fn boundByteMass(shapes: T.Shapes) !u64 {
    try shapes.validate();
    var total: u64 = 0;
    total = try std.math.add(u64, total, try std.math.mul(u64, 19, @as(u64, shapes.common_cells.size()) + shapes.edge_cells.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 15, shapes.leaf.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 14, shapes.node.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 7, shapes.side.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, PA.RANGES, @as(u64, shapes.common_permits.size()) + shapes.edge_permits.size()));
    return total;
}
/// Unit node/data/header/permit mass on the shared tagged RAM relation.
pub fn boundInternalMass(shapes: T.Shapes) !u64 {
    try shapes.validate();
    var total: u64 = 2;
    total = try std.math.add(u64, total, try std.math.mul(u64, shapes.chunk.hashes, 4 * shapes.chunk.geometry.cells() + 1));
    total = try std.math.add(u64, total, try std.math.mul(u64, 10, @as(u64, shapes.common_cells.size()) + shapes.edge_cells.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 5, shapes.leaf.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 4, shapes.node.size()));
    total = try std.math.add(u64, total, try std.math.mul(u64, 2, shapes.side.size()));
    total = try std.math.add(u64, total, @as(u64, shapes.common_permits.size()) + shapes.edge_permits.size());
    return total;
}
