//! Exact direct requester/public suppliers. Child0 is the genuine compact
//! transcript, child1 is the independently admitted common B5SS seal. The
//! original tuple graph authenticates the seal against retained native bytes.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_global_public_export_bus_v1.zig");
const Public = @import("block_v5_requester_public_compensation_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const VERSION = Public.VERSION;
pub const Source = Original.Source;
pub const Wire = Original.Wire;
pub const Values = struct {
    public: *const Public.Owner,
    pub fn validate(self: Values) !void {
        try self.public.validate();
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        return switch (wire.source) {
            .original => |source| switch (source.child) {
                0 => block: {
                    if (source.kind == .child_supply_packed) {
                        if (source.part != 0 or source.coordinate >= self.public.compact.terms.len) return error.InvalidRequesterPublicSchedule;
                        break :block self.public.compact.terms[source.coordinate].coordinates;
                    }
                    if (source.coordinate >= self.public.compact.cells.len) return error.InvalidRequesterPublicSchedule;
                    const cell = self.public.compact.cells[source.coordinate];
                    break :block switch (source.kind) {
                        .frame_cell => if (source.part == 0) cell else error.InvalidRequesterPublicSchedule,
                        .pairing_coordinate => .{ cell[source.part], M.zero(), M.zero(), M.zero() },
                        .child_supply_packed => error.InvalidRequesterPublicSchedule,
                        .native_span => error.InvalidRequesterPublicSchedule,
                    };
                },
                1 => block: {
                    if ((source.kind != .frame_cell and source.kind != .pairing_coordinate) or (source.kind == .frame_cell and source.part != 0) or source.coordinate >= 8) return error.InvalidRequesterPublicSchedule;
                    const sealed = (try self.public.policy.native(0)).admitted.sealed.digest;
                    var cell: [4]M = undefined;
                    for (&cell, 0..) |*byte, i| byte.* = M.fromCanonical(sealed[4 * @as(usize, source.coordinate) + i]);
                    break :block if (source.kind == .pairing_coordinate) .{ cell[source.part], M.zero(), M.zero(), M.zero() } else cell;
                },
                else => error.InvalidRequesterPublicSchedule,
            },
            .public_word => |source| if (source.window == self.public.fields.len) transitionWord(self.public.transition, source.word) else (Original.Values{ .public = &self.public.original }).at(wire),
            .public_byte => |source| if (source.window == self.public.fields.len) .{ (try transitionWord(self.public.transition, source.word))[source.part], M.zero(), M.zero(), M.zero() } else (Original.Values{ .public = &self.public.original }).at(wire),
            else => (Original.Values{ .public = &self.public.original }).at(wire),
        };
    }
    pub fn requireConfig(self: Values, config: core.pcs.PcsConfig) !void {
        if (!std.meta.eql(config, self.public.compact.key.config) or !std.meta.eql(config, self.public.requester.coverage.meta.security.recursive)) return error.RequesterPublicSecurityMismatch;
    }
    pub fn mix(self: Values, channel: anytype) !void {
        channel.mixU32s(&.{ 0x52515042, VERSION });
        channel.mixRoot(self.public.identity);
        channel.mixRoot(self.public.requester.pins.coverage);
        channel.mixRoot(self.public.requester.pins.source);
        channel.mixRoot(self.public.compact.expected_id);
        channel.mixRoot(self.public.compact.public_input_digest);
        channel.mixRoot(self.public.compact.seal);
        const fields = self.public.fields;
        channel.mixU32s(&.{ self.public.policy.windows.version, @intCast(fields.len) });
        channel.mixU32s(&self.public.policy.windows.initial_registers);
        channel.mixU32s(&self.public.policy.windows.final_registers);
        channel.mixU32s(fields[0].borrowed_input);
        for (fields, self.public.terms, 0..) |field, terms, index| {
            channel.mixU32s(&.{ @intCast(index), @intFromEnum(field.profile), field.word_count, @intCast(field.hashed_chunks) });
            for (field.chunks, 0..) |chunk, part| {
                channel.mixU32s(&.{chunk.first});
                if (part == 12) channel.mixU32s(&.{@intCast(chunk.words.len)}) else channel.mixU32s(chunk.words);
            }
            channel.mixRoot(field.source_digest);
            channel.mixFelts(&terms);
        }
        // Normative final invocation: the next verifier reads this exact
        // coordinate, which the same-parent graph forwards from requester T.
        channel.mixFelts(&.{self.public.transition});
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    const original = try Original.scheduleDigest(wires);
    for (wires) |wire| if (wire.source == .original) {
        const source = wire.source.original;
        if (source.child > 1 or source.kind == .native_span or
            (source.child == 1 and (source.coordinate >= 8 or (source.kind == .frame_cell and source.part != 0)))) return error.InvalidRequesterPublicSchedule;
    };
    var c = core.channel.blake3.Channel{};
    c.mixU32s(&.{ 0x52515057, VERSION });
    c.mixRoot(original);
    return c.digestBytes();
}
fn transitionWord(value: Q, coordinate: u32) ![4]M {
    if (coordinate >= 4) return error.InvalidRequesterPublicSchedule;
    const word = value.toM31Array()[coordinate].v;
    var bytes: [4]M = undefined;
    for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    return bytes;
}
pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const d = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (d.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try d.inv());
        total = if (wire.negative) total.sub(term) else total.add(term);
    }
    return total;
}
