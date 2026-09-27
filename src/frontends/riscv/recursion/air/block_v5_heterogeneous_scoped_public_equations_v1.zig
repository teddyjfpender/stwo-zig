//! Real compact-summary/public-root byte joins. Native compensation is checked
//! once against its original native field; only the two missing terms enter
//! the original final accounting. Source/initial/endpoint authority stays OPEN.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Values = @import("../block_v5_heterogeneous_scoped_public_values_v1.zig").Values;
const Scoped = @import("../block_v5_heterogeneous_scoped_plan_v1.zig");
const Wire = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire;
const Raw = @import("block_v5_global_join_source_values_v1.zig");
const Wide = @import("block_v5_recursive_u64_span_v1.zig");
const Compensation = @import("block_v5_scoped_public_compensation_algebra_v1.zig").Algebra(S);
pub const Prepared = @import("block_v5_heterogeneous_scoped_equations_v1.zig").Prepared;
const Inputs = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    values: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Wire) = .empty,
    fn deinit(self: *@This()) void {
        self.values.deinit(self.a);
        self.sources.deinit(self.a);
    }
    fn add(self: *@This(), values: Values, source: Wire) !S {
        if (self.values.items.len >= 1 << 22) return error.ScopedPublicBridgeResourceLimit;
        const symbol = (try self.builder.input()).value;
        try self.values.append(self.a, Q.fromM31Array(try values.at(source)));
        try self.sources.append(self.a, source);
        return symbol;
    }
    fn word(self: *@This(), values: Values, kind: @FieldType(Wire, "kind"), child: u32, cell: u32) ![4]S {
        var result: [4]S = undefined;
        for (&result, 0..) |*byte, part| byte.* = try self.add(values, .{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = cell, .part = @intCast(part) });
        return result;
    }
    fn field(self: *@This(), values: Values, child: u32, coordinates: [4]u32) ![4][4]S {
        var result: [4][4]S = undefined;
        for (&result, coordinates) |*word_bytes, cell| word_bytes.* = try self.word(values, .child_cell, child, cell);
        return result;
    }
    fn output(self: *@This(), values: Values, index: u32) ![4][4]S {
        var result: [4][4]S = undefined;
        for (&result, 0..) |*word_bytes, limb| word_bytes.* = try self.word(values, .output_slot, 0, 4 * index + @as(u32, @intCast(limb)));
        return result;
    }
};
const Word = [4]S;
const Field = [4]Word;
const Term = struct { bytes: Field, negative: bool };
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: S, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
fn wordValue(bytes: Word) S {
    var result = S.zero();
    for (bytes, 0..) |byte, part| result = result.add(byte.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    return result;
}
fn fieldValue(bytes: Field) S {
    var result = S.zero();
    for (bytes, 0..) |word, limb| {
        var basis: [4]M = @splat(M.zero());
        basis[limb] = M.one();
        result = result.add(wordValue(word).mul(S.fromSecure(Q.fromM31Array(basis))));
    }
    return result;
}
fn positions(first: u32) ![4]u32 {
    var result: [4]u32 = undefined;
    for (&result, 0..) |*cell, i| cell.* = try std.math.add(u32, first, @intCast(i));
    return result;
}
fn readScope(a: std.mem.Allocator, input: *Inputs, values: Values, id: u32) ![]Term {
    var terms: std.ArrayList(Term) = .empty;
    errdefer terms.deinit(a);
    if (values.compact.ref == .node) {
        const slot = try values.compact.findSlot(id);
        try terms.append(a, .{ .bytes = try input.field(values, 0, try positions(slot.first)), .negative = false });
    } else {
        if (id >= values.owner.scoped.requirements.len) return error.UntrustedScopedPublicBridgeRecipe;
        for (Scoped.Plan.termsFor(values.owner.scoped.requirements[id], values.compact.ref.leaf)) |term| {
            var selected: [4]u32 = undefined;
            switch (term.selection) {
                .felt => |ref| {
                    if (ref.frame >= values.compact.frames.len or values.compact.frames[ref.frame].operation != .felts or ref.felt >= values.compact.frames[ref.frame].operation.felts.len) return error.UntrustedScopedPublicBridgeRecipe;
                    selected = try positions(try std.math.add(u32, values.compact.frames[ref.frame].first, try std.math.mul(u32, ref.felt, 4)));
                },
                .words => |ref| for (ref.selectors, &selected) |word, *cell| {
                    if (word.frame >= values.compact.frames.len or values.compact.frames[word.frame].operation != .words or word.word >= values.compact.frames[word.frame].operation.words.len) return error.UntrustedScopedPublicBridgeRecipe;
                    cell.* = try std.math.add(u32, values.compact.frames[word.frame].first, word.word);
                },
                .byte => return error.UntrustedScopedPublicBridgeRecipe, // These typed QM31 scopes never select pairing bytes.
            }
            try terms.append(a, .{ .bytes = try input.field(values, 0, selected), .negative = term.negative });
        }
    }
    return terms.toOwnedSlice(a);
}
fn readNative(input: *Inputs, values: Values, field: Raw.Field) !Field {
    var selected: [4]u32 = undefined;
    switch (field.form) {
        .felt => |ref| {
            const frame = try values.public.fresh.normalized.originalFrame(field.child, ref.frame);
            if (ref.index >= frame.word_count / 4) return error.UntrustedScopedPublicBridgeRecipe;
            selected = try positions(try std.math.add(u32, frame.first_cell, try std.math.mul(u32, ref.index, 4)));
        },
        .words => |refs| for (refs, &selected) |ref, *cell| {
            const frame = try values.public.fresh.normalized.originalFrame(field.child, ref.frame);
            if (ref.word >= frame.word_count) return error.UntrustedScopedPublicBridgeRecipe;
            cell.* = try std.math.add(u32, frame.first_cell, ref.word);
        },
    }
    return input.field(values, 1, selected);
}
fn sum(terms: []const Term) S {
    var result = S.zero();
    for (terms) |term| result = if (term.negative) result.sub(fieldValue(term.bytes)) else result.add(fieldValue(term.bytes));
    return result;
}
const Window = struct { registers: []Term, native: []Field, exported: [3]Field, outputs: [3]Field, first: [8]S, last: [8]S, carries: [4]Field };
pub fn prepare(a: std.mem.Allocator, values: Values) !Prepared {
    try values.validate();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var input = Inputs{ .a = a, .builder = &builder };
    defer input.deinit();
    const windows = try a.alloc(Window, values.plan.windows.len);
    defer a.free(windows);
    var initialized: usize = 0;
    defer for (windows[0..initialized]) |window| {
        a.free(window.registers);
        a.free(window.native);
    };
    for (windows, values.plan.windows, 0..) |*window, recipe, index| {
        const registers = try readScope(a, &input, values, recipe.registers);
        errdefer a.free(registers);
        const native = try a.alloc(Field, recipe.native_fields.len);
        errdefer a.free(native);
        for (native, recipe.native_fields) |*bytes, field| bytes.* = try readNative(&input, values, field);
        window.registers = registers;
        window.native = native;
        for (&window.exported, &window.outputs, recipe.terms, 0..) |*bytes, *exported, term, kind| {
            bytes.* = try input.field(values, 1, try positions(term.first_cell));
            exported.* = try input.output(values, @intCast(3 * index + kind));
        }
        const first = try recipe.cycles.firstCycle();
        const last = try recipe.cycles.lastCycle();
        for (0..2) |limb| {
            @memcpy(window.first[4 * limb ..][0..4], &(try input.word(values, .child_cell, 1, first.first_cell + @as(u32, @intCast(limb)))));
            @memcpy(window.last[4 * limb ..][0..4], &(try input.word(values, .child_cell, 1, last.first_cell + @as(u32, @intCast(limb)))));
        }
        if (index != 0) {
            for (&window.carries, 0..) |*field, limb| field.* = try input.output(values, @intCast(3 * windows.len + 4 * (index - 1) + limb));
        }
        initialized += 1;
    }
    const program = try readScope(a, &input, values, values.plan.program);
    defer a.free(program);
    const known = try readScope(a, &input, values, values.plan.known_residual);
    defer a.free(known);
    var first_output: [8]S = undefined;
    var last_output: [8]S = undefined;
    for (0..2) |limb| {
        @memcpy(first_output[4 * limb ..][0..4], &(try input.word(values, .output_span, 0, @intCast(limb))));
        @memcpy(last_output[4 * limb ..][0..4], &(try input.word(values, .output_span, 0, @intCast(limb + 2))));
    }
    // Counts/PCs forwarded above remain equal to lower compact public byte
    // cells. Single native leaf index/count are admitted exact0/1; its PCs
    // come from the new genuine public-root byte source.
    var forwarded: [4]Word = undefined;
    var original: [4]Word = undefined;
    for (&forwarded, 0..) |*word, i| word.* = try input.word(values, .output_span, 0, @intCast(i + 4));
    if (values.compact.span_cell) |start| {
        for (&original, [_]u32{ 0, 1, 4, 5 }) |*word, offset| word.* = try input.word(values, .child_cell, 0, start + offset);
    } else {
        const initial = values.plan.windows[0].cycles.pc_clock orelse return error.UntrustedScopedPublicBridgeRecipe;
        const final = values.plan.windows[windows.len - 1].cycles.pc_clock orelse return error.UntrustedScopedPublicBridgeRecipe;
        original[2] = try input.word(values, .child_cell, 1, initial.first_cell);
        original[3] = try input.word(values, .child_cell, 1, final.first_cell + 1);
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    var boundary = S.zero();
    var compensation = S.zero();
    for (windows, 0..) |window, index| {
        for (window.exported, window.outputs) |actual, upper| try sink.zero(fieldValue(actual).sub(fieldValue(upper)), error.UntrustedScopedPublicTermForwarding);
        var native_sum = S.zero();
        for (window.native) |field| native_sum = native_sum.add(fieldValue(field));
        try Compensation.window(&sink, native_sum, fieldValue(window.exported[0]), sum(window.registers), fieldValue(window.exported[1]));
        compensation = compensation.add(fieldValue(window.exported[1]));
        boundary = boundary.add(fieldValue(window.exported[2]));
        if (index != 0) {
            var carry_values: [4]S = undefined;
            for (&carry_values, window.carries) |*carry, field| carry.* = fieldValue(field);
            try Wide.increment(S, &sink, windows[index - 1].last, window.first, carry_values);
        }
    }
    try Wide.equal(S, &sink, windows[0].first, first_output);
    try Wide.equal(S, &sink, windows[windows.len - 1].last, last_output);
    if (values.compact.span_cell != null) {
        for (forwarded, original) |upper, lower| for (upper, lower) |a_byte, b_byte| try sink.zero(a_byte.sub(b_byte), error.UntrustedScopedPublicSpanForwarding);
    } else {
        try sink.zero(wordValue(forwarded[0]), error.UntrustedScopedPublicSpanForwarding);
        try sink.zero(wordValue(forwarded[1]).sub(S.one()), error.UntrustedScopedPublicSpanForwarding);
        for (forwarded[2..], original[2..]) |upper, lower| for (upper, lower) |a_byte, b_byte| try sink.zero(a_byte.sub(b_byte), error.UntrustedScopedPublicSpanForwarding);
    }
    try Compensation.terminal(&sink, sum(program), boundary);
    // Native compensation already belongs to native_open in known residual.
    // Exactly the two missing coordinates are added, each once.
    try Compensation.accounting(&sink, sum(known), boundary, compensation);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try input.values.toOwnedSlice(a);
    errdefer a.free(inputs);
    const sources = try input.sources.toOwnedSlice(a);
    errdefer a.free(sources);
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(evaluated);
    try circuit.evaluateInto(inputs, evaluated);
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .values = evaluated, .sources = sources };
}
