//! Direct original caller arithmetic/fused and source raw/fold PAGE verifier
//! rows. The final root joins these rows with native and provider rows before
//! proving once; there is no per-child recursive proof in this preparation.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v6_auxiliary_direct_public_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
pub fn InputFor(comptime family: Bus.Family) type {
    const D = Bus.Definition(family);
    return struct { admitted: *const D.Admission.Prepared, capture: *const D.Capture };
}
pub const Input = union(Bus.Family) {
    caller_arithmetic: InputFor(.caller_arithmetic),
    caller_fused: InputFor(.caller_fused),
    source_raw: InputFor(.source_raw),
    source_fold: InputFor(.source_fold),
    pub fn expected(self: Input) Bus.Expected {
        return switch (self) {
            inline else => |input, family| .{
                .family = family,
                .index = switch (family) {
                    .caller_arithmetic, .caller_fused => input.admitted.binding.execution_index,
                    .source_raw => input.admitted.pin.raw.page.index,
                    .source_fold => input.admitted.pin.page.index,
                },
                .template = input.admitted.template_id,
            },
        };
    }
    pub fn config(self: Input) core.pcs.PcsConfig {
        return switch (self) {
            inline else => |input| input.admitted.config,
        };
    }
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    children: []Bus.Child,
    pub fn values(self: *const Prepared) Bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        for (self.children) |*child| child.value.deinit();
        self.allocator.free(self.children);
        self.allocator.free(self.wires);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, inputs: []const Input, expected: []const Bus.Expected, capacity: u32) !Prepared {
    if (inputs.len == 0 or inputs.len > Bus.MAX_CHILDREN or inputs.len != expected.len or capacity == 0) return error.InvalidAuxiliaryDirectCount;
    // Exact admission order is checked before any wide verifier allocation.
    for (inputs, expected, 0..) |input, pin, i| {
        if (!std.meta.eql(input.expected(), pin)) return error.UntrustedAuxiliaryDirectRoster;
        if (!std.meta.eql(input.config(), inputs[0].config())) return error.AuxiliaryDirectSecurityMismatch;
        if (i != 0 and (@intFromEnum(expected[i - 1].family) > @intFromEnum(pin.family) or
            (expected[i - 1].family == pin.family and expected[i - 1].index >= pin.index))) return error.InvalidAuxiliaryDirectRoster;
    }
    const children = try a.alloc(Bus.Child, inputs.len);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*child| child.value.deinit();
        a.free(children);
    }
    var rows: ?Parent.Prepared = null;
    errdefer if (rows) |*owned| owned.deinit();
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var next_namespace: u32 = 1;
    var contexts: [5]core.channel.blake3.Channel = @splat(.{});
    for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364147, Bus.VERSION, @intCast(i), @intCast(inputs.len) });
    for (inputs, expected, 0..) |input, pin, i| switch (input) {
        inline else => |source, family| {
            const D = Bus.Definition(family);
            try source.capture.validate(source.admitted, pin.template);
            var piece = try D.Bus.prepare(a, source.admitted, source.capture, capacity);
            var moved = false;
            defer if (!moved) piece.deinit();
            const value = if (family == .caller_arithmetic) piece.values else try piece.values.clone(a);
            children[i] = .{ .index = pin.index, .value = @unionInit(Bus.Value, @tagName(family), value) };
            initialized += 1;
            var namespace = try Rebase.prepare(a, &piece.recursive.rows, next_namespace);
            defer namespace.deinit();
            next_namespace = try namespace.end();
            const namespace_identity = try namespace.identity();
            for (piece.wires) |wire| try wires.append(a, .{ .circuit = namespace.map(wire.circuit) orelse return error.MissingAuxiliaryDirectNamespace, .wire = wire.wire, .uses = wire.uses, .child = @intCast(i), .source = @unionInit(Bus.Source, @tagName(family), wire.source), .coordinate = wire.coordinate });
            try Rebase.apply(&piece.recursive.rows, &namespace, namespace_identity);
            contexts[0].mixU32s(&.{ @intFromEnum(family), pin.index });
            contexts[0].mixRoot(pin.template);
            for (contexts[1..4], piece.recursive.context.graph_ids) |*channel, digest| {
                channel.mixRoot(digest);
                channel.mixRoot(namespace_identity);
            }
            contexts[4].mixRoot(piece.recursive.context.transcript_plan_id);
            contexts[4].mixRoot(namespace_identity);
            if (rows) |*previous| {
                const combined = try Join.joinDraining(a, &previous.rows, &piece.recursive.rows, .{
                    .{ .first = 1, .end = namespace.first }, .{ .first = namespace.first, .end = next_namespace },
                });
                const context = previous.context;
                previous.deinit();
                previous.* = .{ .rows = combined, .context = context };
            } else {
                if (piece.recursive.allocation_budget != null) return error.UnsupportedAuxiliaryNestedBudget;
                piece.allocator.free(piece.wires);
                if (family != .caller_arithmetic) piece.values.deinit();
                piece.recursive.allocation_budget = piece.budget;
                rows = piece.recursive;
                moved = true;
            }
        },
    };
    try (Bus.Values{ .children = children }).requireRoster(expected);
    rows.?.context = .{ .child_key_id = contexts[0].digestBytes(), .child_config = inputs[0].config(), .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() }, .transcript_plan_id = contexts[4].digestBytes() };
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, left: Bus.Wire, right: Bus.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    return .{ .allocator = a, .recursive = rows.?, .children = children, .wires = try wires.toOwnedSlice(a) };
}
