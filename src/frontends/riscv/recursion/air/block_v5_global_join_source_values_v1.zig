//! QM31 reconstruction from ORIGINAL public byte cells, including word-backed
//! claims. Selection/semantic authority belongs to the typed mapping generator.
//! This decoder grants neither source completeness nor cryptographic acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const Frames = @import("../block_v5_heterogeneous_child_frames_v1.zig");
pub const Source = @import("block_v5_heterogeneous_pairing_v1.zig").Source;
pub const Word = struct { frame: u32, word: u32 };
pub const Field = struct { child: u32, form: union(enum) { felt: struct { frame: u32, index: u32 }, words: [4]Word } };
pub const View = struct { frames: []const Frames.Frame, cells: []const [4]M };
pub const Read = struct { value: Q, inputs: [16]Q, sources: [16]Source };
pub fn read(views: []const View, field: Field) !Read {
    if (field.child >= views.len) return error.InvalidGlobalJoinSource;
    const child = views[field.child];
    var positions: [4]usize = undefined;
    var words: [4]M = undefined;
    switch (field.form) {
        .felt => |selection| {
            if (selection.frame >= child.frames.len) return error.InvalidGlobalJoinSource;
            const frame = child.frames[selection.frame];
            const payload = switch (frame.operation) {
                .felts => |values| values,
                else => return error.InvalidGlobalJoinSource,
            };
            if (selection.index >= payload.len) return error.InvalidGlobalJoinSource;
            words = payload[selection.index].toM31Array();
            const first = try std.math.add(usize, frame.first, try std.math.mul(usize, selection.index, 4));
            for (&positions, 0..) |*position, component| position.* = try std.math.add(usize, first, component);
        },
        .words => |selections| for (selections, &positions, &words) |selection, *position, *limb| {
            if (selection.frame >= child.frames.len) return error.InvalidGlobalJoinSource;
            const frame = child.frames[selection.frame];
            const payload = switch (frame.operation) {
                .words => |values| values,
                else => return error.InvalidGlobalJoinSource,
            };
            if (selection.word >= payload.len or payload[selection.word] >= core.fields.m31.Modulus) return error.NoncanonicalGlobalJoinSource;
            limb.* = M.fromCanonical(payload[selection.word]);
            position.* = try std.math.add(usize, frame.first, selection.word);
        },
    }
    var result: Read = .{ .value = Q.fromM31Array(words), .inputs = undefined, .sources = undefined };
    for (positions, words, 0..) |position, word, component| {
        if (position >= child.cells.len or position >= Frames.LIMIT or word.v >= core.fields.m31.Modulus) return error.InvalidGlobalJoinSource;
        for (0..4) |part| {
            const byte = child.cells[position][part];
            if (byte.v != ((word.v >> @as(u5, @intCast(8 * part))) & 255)) return error.MutatedGlobalJoinSource;
            const at = 4 * component + part;
            result.inputs[at] = Q.fromBase(byte);
            result.sources[at] = .{ .child = field.child, .cell = @intCast(position), .part = @intCast(part) };
        }
    }
    return result;
}
pub const Prepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Source,
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.values);
        self.allocator.free(self.sources);
        self.budget.destroy();
        self.* = undefined;
    }
};
/// constraints.record must derive its equations from the independent typed
/// mapping. This primitive never accepts metadata as verifier authority.
pub fn record(backing: std.mem.Allocator, views: []const View, fields: []const Field, constraints: anytype, max_bytes: usize) !Prepared {
    if (fields.len == 0 or fields.len > 65_536 or views.len == 0 or views.len > 1024 or max_bytes == 0) return error.GlobalJoinResourceLimit;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, max_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const count = try std.math.mul(usize, fields.len, 16);
    const inputs = try a.alloc(Q, count);
    errdefer a.free(inputs);
    const sources = try a.alloc(Source, count);
    errdefer a.free(sources);
    const raw = try a.alloc(R.Scalar, count);
    defer a.free(raw);
    const claims = try a.alloc(R.Scalar, fields.len);
    defer a.free(claims);
    for (fields, 0..) |field, ordinal| {
        const decoded = try read(views, field);
        @memcpy(inputs[ordinal * 16 ..][0..16], &decoded.inputs);
        @memcpy(sources[ordinal * 16 ..][0..16], &decoded.sources);
        for (raw[ordinal * 16 ..][0..16]) |*symbol| symbol.* = (try builder.input()).value;
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    for (claims, 0..) |*claim, ordinal| {
        claim.* = R.Scalar.zero();
        for (0..4) |component| {
            var basis: [4]M = @splat(M.zero());
            basis[component] = M.one();
            for (0..4) |part| {
                const weight = Q.fromM31Array(basis).mul(Q.fromBase(M.fromU64(@as(u64, 1) << @as(u6, @intCast(8 * part)))));
                claim.* = claim.add(raw[ordinal * 16 + component * 4 + part].mul(R.Scalar.fromSecure(weight)));
            }
        }
    }
    if (builder.failure) |err| return err;
    try constraints.record(a, &builder, claims);
    if (builder.failure) |err| return err;
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(values);
    try circuit.evaluateInto(inputs, values);
    return .{ .budget = budget, .allocator = a, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources };
}
