//! Same original public tuples, now consuming retained requester scopes rather
//! than a second heterogeneous all-family child. RAM/range are absent here.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Tuple = @import("block_v5_global_public_tuple_algebra_v1.zig");
const Compensation = @import("block_v5_scoped_public_compensation_algebra_v1.zig").Algebra(S);
const Public = @import("../block_v5_requester_public_compensation_v1.zig");
const Bus = @import("../block_v5_requester_public_bus_v1.zig");
const Scoped = @import("../block_v5_heterogeneous_scoped_plan_v1.zig");
const U = @import("universal_challenges.zig");
pub const VERSION = Public.VERSION;
pub const Source = union(enum) { public: Bus.Source, challenge: u32 };
pub const Prepared = struct {
    budget: *Budget,
    arena: Arena,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Source,
    relations: U.UniversalRelations,
    semantic_identity: [32]u8,
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, owner: *const Public.Owner) !void {
        try owner.validate();
        if (!std.meta.eql(self.semantic_identity, owner.identity)) return error.UntrustedRequesterPublicGraph;
    }
};
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: S, _: anyerror) !void {
        try self.builder.check();
        try self.builder.constrainZero(value);
    }
};
const Challenges = struct {
    set: R.ChallengeSet,
    pub fn getExact(self: *const @This(), domain: @import("../../air/lang/relation.zig").Domain) !*const R.ChallengeSet.Element {
        return self.set.get(domain);
    }
};
const ClaimTerm = struct { field: [4]Tuple.Word(S) = undefined, byte: ?S = null, negative: bool = false };
const Claim = []const ClaimTerm;
fn claimValue(terms: Claim) S {
    var total = S.zero();
    for (terms) |term| {
        var value = term.byte orelse S.zero();
        if (term.byte == null) for (term.field, 0..) |bytes, limb| {
            var basis: [4]M = @splat(M.zero());
            basis[limb] = M.one();
            value = value.add(Tuple.reconstruct(S, bytes).mul(S.fromSecure(Q.fromM31Array(basis))));
        };
        total = if (term.negative) total.sub(value) else total.add(value);
    }
    return total;
}
const Inputs = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    owner: *const Public.Owner,
    values: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Source) = .empty,
    fn add(self: *@This(), value: Q, source: Source) !S {
        const symbol = (try self.builder.input()).value;
        try self.values.append(self.a, value);
        try self.sources.append(self.a, source);
        return symbol;
    }
    fn routed(self: *@This(), source: Bus.Source) !S {
        const bytes = try (Bus.Values{ .public = self.owner }).at(.{ .circuit = 0, .wire = 0, .uses = 1, .source = source });
        return self.add(Q.fromM31Array(bytes), .{ .public = source });
    }
    fn word(self: *@This(), window: u32, coordinate: u32) !Tuple.Word(S) {
        var result: Tuple.Word(S) = undefined;
        for (&result, 0..) |*byte, part| byte.* = try self.routed(.{ .public_byte = .{ .window = window, .word = coordinate, .part = @intCast(part) } });
        return result;
    }
    fn compactWord(self: *@This(), coordinate: u32) !Tuple.Word(S) {
        var result: Tuple.Word(S) = undefined;
        for (&result, 0..) |*byte, part| byte.* = try self.routed(.{ .original = .{ .child = 0, .kind = .pairing_coordinate, .coordinate = coordinate, .part = @intCast(part) } });
        return result;
    }
    fn field(self: *@This(), coordinates: [4]u32) ![4]Tuple.Word(S) {
        var result: [4]Tuple.Word(S) = undefined;
        for (&result, coordinates) |*bytes, coordinate| bytes.* = try self.compactWord(coordinate);
        return result;
    }
    fn claim(self: *@This(), key: Scoped.Key) !Claim {
        const id = try self.owner.requirement(key);
        const source = self.owner.compact;
        if (source.ref == .node) {
            const first = (try source.findSlot(id)).first;
            const terms = try self.a.alloc(ClaimTerm, 1);
            terms[0] = .{ .field = try self.field(.{ first, first + 1, first + 2, first + 3 }) };
            return terms;
        }
        const selected = Scoped.Plan.termsFor(self.owner.requester.scoped.requirements[id], source.ref.leaf);
        const terms = try self.a.alloc(ClaimTerm, selected.len);
        for (terms, selected) |*term, selected_term| {
            term.* = .{ .negative = selected_term.negative };
            switch (selected_term.selection) {
                .byte => |ref| term.byte = try self.routed(.{ .original = .{ .child = 0, .kind = .pairing_coordinate, .coordinate = ref.cell, .part = ref.part } }),
                .felt => |ref| {
                    if (ref.frame >= source.frames.len or source.frames[ref.frame].operation != .felts or ref.felt >= source.frames[ref.frame].operation.felts.len) return error.UntrustedRequesterPublicScope;
                    const first = try std.math.add(u32, source.frames[ref.frame].first, try std.math.mul(u32, ref.felt, 4));
                    term.field = try self.field(.{ first, first + 1, first + 2, first + 3 });
                },
                .words => |ref| {
                    var coordinates: [4]u32 = undefined;
                    for (ref.selectors, &coordinates) |selector, *coordinate| {
                        if (selector.frame >= source.frames.len or source.frames[selector.frame].operation != .words or selector.word >= source.frames[selector.frame].operation.words.len) return error.UntrustedRequesterPublicScope;
                        coordinate.* = try std.math.add(u32, source.frames[selector.frame].first, selector.word);
                    }
                    term.field = try self.field(coordinates);
                },
            }
        }
        return terms;
    }
};
pub fn prepare(backing: std.mem.Allocator, owner: *const Public.Owner, max_bytes: usize) !Prepared {
    if (max_bytes == 0) return error.RequesterPublicResourceLimit;
    try owner.validate();
    const budget = try Budget.createRetainingParent(backing, max_bytes);
    errdefer budget.destroy();
    var arena = try Arena.init(budget.allocator());
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var input = Inputs{ .a = a, .builder = &builder, .owner = owner };
    const count = owner.fields.len;
    if (count == 0) return error.RequesterPublicResourceLimit;
    const data = try a.alloc(Tuple.Data(S), count);
    const native = try a.alloc(Claim, count);
    const registers = try a.alloc(Claim, count);
    const digest = try a.alloc([32]Claim, count);
    const expected = try a.alloc([32]S, count);
    for (data, owner.fields, native, registers, digest, expected, 0..) |*window, field, *n, *r, *actual_digest, *expected_digest, ordinal| {
        const index: u32 = @intCast(ordinal);
        const l = field.layout;
        window.initial_pc = try input.word(index, l.pc_clock);
        window.final_pc = try input.word(index, l.pc_clock + 1);
        window.clock = try input.word(index, l.pc_clock + 2);
        for (0..32) |register| {
            const offset: u32 = @intCast(register);
            window.initial[register] = try input.word(index, l.initial + offset);
            window.final[register] = try input.word(index, l.final + offset);
            window.clocks[register] = try input.word(index, l.clocks + offset);
            actual_digest[register] = try input.claim(.{ .kind = .public_auth, .scope = index, .coordinate = offset });
            expected_digest[register] = try input.routed(.{ .public_digest = .{ .window = index, .word = @intCast(register / 4), .part = @intCast(register % 4) } });
        }
        window.completion_address = try input.word(index, l.completion + 2);
        for (&window.decoded, 0..) |*word, part| word.* = try input.word(index, l.decoded + @as(u32, @intCast(part)));
        for (0..2) |limb| {
            @memcpy(window.first_cycle[4 * limb ..][0..4], &(try input.word(index, l.cycles + @as(u32, @intCast(limb)))));
            @memcpy(window.last_cycle[4 * limb ..][0..4], &(try input.word(index, l.cycles + 2 + @as(u32, @intCast(limb)))));
        }
        n.* = try input.claim(.{ .kind = .public_auth, .scope = index, .coordinate = 32 });
        r.* = try input.claim(.{ .kind = .registers, .scope = index, .coordinate = 0 });
    }
    var actual_seal: [32]Claim = undefined;
    var expected_seal: [32]S = undefined;
    for (&actual_seal, &expected_seal, 0..) |*actual, *required, byte| {
        actual.* = try input.claim(.{ .kind = .public_auth, .scope = 0, .coordinate = @intCast(33 + byte) });
        required.* = try input.routed(.{ .original = .{ .child = 1, .kind = .pairing_coordinate, .coordinate = @intCast(byte / 4), .part = @intCast(byte % 4) } });
    }
    var outer_initial: [32]Tuple.Word(S) = undefined;
    var outer_final: [32]Tuple.Word(S) = undefined;
    for (&outer_initial, &outer_final, 0..) |*first, *last, register| {
        for (first, last, 0..) |*before, *after, part| {
            before.* = try input.routed(.{ .outer_register_byte = .{ .final = false, .register = @intCast(register), .part = @intCast(part) } });
            after.* = try input.routed(.{ .outer_register_byte = .{ .final = true, .register = @intCast(register), .part = @intCast(part) } });
        }
    }
    const program = try input.claim(.{ .kind = .program, .scope = 0, .coordinate = 0 });
    const known = try input.claim(.{ .kind = .accounting, .scope = 0, .coordinate = 10 });
    const transition = try input.claim(.{ .kind = .transition, .scope = 0, .coordinate = 0 });
    var transition_output: [4]Tuple.Word(S) = undefined;
    for (&transition_output, 0..) |*word, limb| {
        for (word, 0..) |*byte, part| byte.* = try input.routed(.{ .public_byte = .{ .window = @intCast(count), .word = @intCast(limb), .part = @intCast(part) } });
    }
    var channel = (try owner.policy.native(0)).admitted.sealed.sharedChannel();
    const relations = try U.UniversalRelations.draw(a, &channel);
    var draws: [U.RELATION_COUNT][2]S = undefined;
    for (&draws, relations.elements, 0..) |*pair, element, ordinal| {
        pair[0] = try input.add(element.z, .{ .challenge = @intCast(2 * ordinal) });
        pair[1] = try input.add(element.alpha_powers[1], .{ .challenge = @intCast(2 * ordinal + 1) });
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    var challenges = Challenges{ .set = try R.ChallengeSet.init(draws) };
    for (actual_seal, expected_seal) |actual, required| try sink.zero(claimValue(actual).sub(required), error.UntrustedRequesterPublicSeal);
    try Tuple.registerContinuity(S, &sink, outer_initial, data[0].initial);
    try Tuple.registerContinuity(S, &sink, data[count - 1].final, outer_final);
    const local_zero = owner.policy.windows.version == @import("../../prover/block_v5_register_windows_v1.zig").LOCAL_ZERO_VERSION;
    var boundary = S.zero();
    var compensation = S.zero();
    for (data, digest, expected, native, registers, 0..) |window, actual_digest, expected_digest, n, r, index| {
        for (actual_digest, expected_digest) |actual, required| try sink.zero(claimValue(actual).sub(required), error.UntrustedGlobalPublicDigestSource);
        const p = (try owner.policy.native(@intCast(index))).admitted;
        const sums = try Tuple.evaluate(S, window, &challenges, local_zero, p.shape.public_data.completion.?.kind != .halt_flag);
        try Compensation.window(&sink, claimValue(n), sums.native_compensation, claimValue(r), sums.register_compensation);
        if (local_zero) try Tuple.localZero(S, &sink, window);
        if (index == 0) try Tuple.initialCycle(S, &sink, window.first_cycle) else {
            try Tuple.registerContinuity(S, &sink, data[index - 1].final, window.initial);
            try Tuple.nextCycle(S, &sink, data[index - 1].last_cycle, window.first_cycle);
        }
        boundary = boundary.add(sums.program_boundary);
        compensation = compensation.add(sums.register_compensation);
    }
    try Compensation.terminal(&sink, claimValue(program), boundary);
    try Compensation.accounting(&sink, claimValue(known), boundary, compensation);
    var output_value = S.zero();
    for (transition_output, 0..) |word, limb| {
        var basis: [4]M = @splat(M.zero());
        basis[limb] = M.one();
        output_value = output_value.add(Tuple.reconstruct(S, word).mul(S.fromSecure(Q.fromM31Array(basis))));
    }
    try sink.zero(claimValue(transition).sub(output_value), error.UntrustedRequesterPublicTransition);
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try input.values.toOwnedSlice(a);
    const sources = try input.sources.toOwnedSlice(a);
    const values = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs, values);
    return .{ .budget = budget, .arena = arena, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources, .relations = relations, .semantic_identity = owner.identity };
}
