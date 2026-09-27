//! Versioned OPEN public derivation extension. Every raw/decoded value belongs
//! to independently reconstructed public admission, never to a proof envelope.
//! Complete source authentication is explicitly absent from this statement.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_v5_heterogeneous_public_bus_v1.zig");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const Prepared = @import("block_v5_global_public_export_parent_v1.zig").Prepared;
pub const MAX_WIRES: usize = 16 << 20;
pub const Source = union(enum) {
    original: struct { child: u32, kind: Original.Kind, coordinate: u32, part: u2 = 0 },
    public_word: struct { window: u32, word: u32 },
    public_byte: struct { window: u32, word: u32, part: u2 },
    /// Canonical B5PD digest computed by independent public admission. A graph
    /// compares these bytes with the original authenticated child cells.
    public_digest: struct { window: u32, word: u3, part: u2 },
    outer_register_byte: struct { final: bool, register: u5, part: u2 },
    term_byte: struct { window: u32, kind: Public.TermKind, limb: u2, part: u2 },
};
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, source: Source };
pub const Values = struct {
    public: *const Public.Owner,
    pub const complete_block_authority = false;
    pub fn validate(self: Values) !void {
        try self.public.validate();
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        return switch (wire.source) {
            .original => |source| (Original.Values{ .policy = self.public.policy.original }).at(.{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .child = source.child, .kind = source.kind, .coordinate = source.coordinate, .part = source.part }),
            .public_word => |source| if (source.window < self.public.fields.len) self.public.fields[source.window].bytes(source.word) else error.InvalidGlobalPublicSchedule,
            .public_byte => |source| if (source.window < self.public.fields.len) .{ (try self.public.fields[source.window].bytes(source.word))[source.part], M.zero(), M.zero(), M.zero() } else error.InvalidGlobalPublicSchedule,
            .public_digest => |source| if (source.window < self.public.fields.len) .{ M.fromCanonical(self.public.fields[source.window].source_digest[4 * @as(usize, source.word) + source.part]), M.zero(), M.zero(), M.zero() } else error.InvalidGlobalPublicSchedule,
            .outer_register_byte => |source| block: {
                const word = if (source.final) self.public.policy.windows.final_registers[source.register] else self.public.policy.windows.initial_registers[source.register];
                break :block .{ M.fromCanonical((word >> @as(u5, @intCast(8 * @as(u32, source.part)))) & 255), M.zero(), M.zero(), M.zero() };
            },
            .term_byte => |source| block: {
                if (source.window >= self.public.terms.len) return error.InvalidGlobalPublicSchedule;
                const word = self.public.terms[source.window][@intFromEnum(source.kind)].toM31Array()[source.limb];
                break :block .{ M.fromCanonical((word.v >> @as(u5, @intCast(8 * @as(u32, source.part)))) & 255), M.zero(), M.zero(), M.zero() };
            },
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        self.mixData(channel);
        channel.mixU32s(&.{ 0x42354754, VERSION, @intCast(self.public.terms.len), 3 });
        for (self.public.terms) |terms| channel.mixFelts(&terms);
    }
    pub fn mixData(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354745, VERSION, 0 }); // B5GE: OPEN, no source authority.
        (Original.Values{ .policy = self.public.policy.original }).mix(channel);
        channel.mixU32s(&.{ self.public.policy.windows.version, @intCast(self.public.fields.len) });
        channel.mixU32s(&self.public.policy.windows.initial_registers);
        channel.mixU32s(&self.public.policy.windows.final_registers);
        // One immutable job input, shared by all B5PD windows. The receiver
        // checks equality before using references, not pointer/hash agreement.
        channel.mixU32s(self.public.fields[0].borrowed_input);
        // Absorb the actual canonical public preimage and PUBLIC derivation,
        // including every decoded coordinate/full u64 span limb. A reader may
        // not accept an arbitrary tuple or identity from a transported proof.
        for (self.public.fields, 0..) |field, index| {
            channel.mixU32s(&.{ @intCast(index), @intFromEnum(field.profile), field.word_count, @intCast(field.hashed_chunks) });
            for (field.chunks, 0..) |chunk, chunk_index| {
                channel.mixU32s(&.{chunk.first});
                if (chunk_index == 12) channel.mixU32s(&.{ 0x42354742, @intCast(chunk.words.len) }) else channel.mixU32s(chunk.words);
            }
        }
    }
};
pub fn fromOriginal(wire: Original.Wire) Wire {
    return .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .source = .{ .original = .{ .child = wire.child, .kind = wire.kind, .coordinate = wire.coordinate, .part = wire.part } } };
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidGlobalPublicSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354757, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, index| {
        if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus) return error.InvalidGlobalPublicSchedule;
        if (index > 0 and (wires[index - 1].circuit > wire.circuit or (wires[index - 1].circuit == wire.circuit and wires[index - 1].wire >= wire.wire))) return error.InvalidGlobalPublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), @intFromEnum(std.meta.activeTag(wire.source)) });
        switch (wire.source) {
            .original => |source| {
                if (source.child >= Original.MAX_CHILDREN or (source.kind != .pairing_coordinate and source.part != 0)) return error.InvalidGlobalPublicSchedule;
                channel.mixU32s(&.{ source.child, @intFromEnum(source.kind), source.coordinate, source.part });
            },
            .public_word => |source| channel.mixU32s(&.{ source.window, source.word }),
            .public_byte => |source| channel.mixU32s(&.{ source.window, source.word, source.part }),
            .public_digest => |source| channel.mixU32s(&.{ source.window, source.word, source.part }),
            .outer_register_byte => |source| channel.mixU32s(&.{ @intFromBool(source.final), source.register, source.part }),
            .term_byte => |source| channel.mixU32s(&.{ source.window, @intFromEnum(source.kind), source.limb, source.part }),
        }
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const relation = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        total = if (wire.negative) total.sub(term) else total.add(term);
    }
    return total;
}

/// Exact authenticated public statement coordinates, independent of values.
/// The three terms share one real mixFelts invocation per native window.
pub const ExportCell = struct { window: u32, kind: Public.TermKind, frame: u32, index: u32, first_cell: u32 };
pub const Counter = struct {
    frames: u32 = 0,
    cells: u32 = 0,
    failure: ?anyerror = null,
    fn append(self: *Counter, count: usize) void {
        if (self.failure != null) return;
        const end = std.math.add(usize, self.cells, count) catch |err| {
            self.failure = err;
            return;
        };
        if (end >= core.fields.m31.Modulus or self.frames >= core.fields.m31.Modulus - 1) {
            self.failure = error.GlobalPublicExportResourceLimit;
            return;
        }
        self.cells = @intCast(end);
        self.frames += 1;
    }
    pub fn mixU32s(self: *Counter, words: []const u32) void {
        self.append(words.len);
    }
    pub fn mixRoot(self: *Counter, _: [32]u8) void {
        self.append(8);
    }
    pub fn mixU64(self: *Counter, _: u64) void {
        self.append(2);
    }
    pub fn mixFelts(self: *Counter, values: []const Q) void {
        const count = std.math.mul(usize, values.len, 4) catch |err| {
            self.failure = err;
            return;
        };
        self.append(count);
    }
};
/// Pure geometry of the actual three-felt invocation per window. This carries
/// no admission or verification authority; callers reconstruct it from their
/// independently admitted Values and exact original transcript prefix.
pub const ExportLayout = struct {
    first_frame: u32,
    first_cell: u32,
    windows: u32,
    pub fn fromCounter(counter: Counter, windows: usize) !ExportLayout {
        if (counter.failure) |failure| return failure;
        if (counter.frames >= core.fields.m31.Modulus or counter.cells >= core.fields.m31.Modulus)
            return error.GlobalPublicExportResourceLimit;
        return .{ .first_frame = counter.frames, .first_cell = counter.cells, .windows = std.math.cast(u32, windows) orelse return error.GlobalPublicExportResourceLimit };
    }
    pub fn at(self: ExportLayout, window: u32) ![3]ExportCell {
        if (window >= self.windows) return error.InvalidGlobalPublicSchedule;
        const frame = @as(u64, self.first_frame) + window;
        const first = @as(u64, self.first_cell) + 12 * @as(u64, window);
        const end = first + 12;
        // Original Counter refuses a prior append at frame M-1, and the
        // original final ExportCell check excludes a cell extent reaching M.
        if (frame >= core.fields.m31.Modulus or end >= core.fields.m31.Modulus)
            return error.GlobalPublicExportResourceLimit;
        var result: [3]ExportCell = undefined;
        for (&result, 0..) |*entry, kind| entry.* = .{ .window = window, .kind = @enumFromInt(kind), .frame = @intCast(frame), .index = @intCast(kind), .first_cell = @intCast(first + 4 * kind) };
        return result;
    }
};
pub fn exportLayout(values: Values, prefix: Counter) !ExportLayout {
    try values.validate();
    return exportLayoutAdmitted(values, prefix);
}
fn exportLayoutAdmitted(values: Values, prefix: Counter) !ExportLayout {
    var counter = prefix;
    values.mixData(&counter);
    counter.mixU32s(&.{ 0x42354754, VERSION, @intCast(values.public.terms.len), 3 });
    return ExportLayout.fromCounter(counter, values.public.terms.len);
}
pub fn exportCells(values: Values, prefix: Counter, window: u32) ![3]ExportCell {
    try values.validate();
    if (window >= values.public.terms.len) return error.InvalidGlobalPublicSchedule;
    return (try exportLayoutAdmitted(values, prefix)).at(window);
}
