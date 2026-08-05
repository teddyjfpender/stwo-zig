//! Strict allocation-free semantic comparison for `STWAIRC` v1. Results
//! borrow input storage and are valid only while both inputs remain alive.
const std = @import("std");
const magic = "STWAIRC\x00";
const version: u16 = 1;
const section_count: usize = 7;
const family_count: u8 = 17;
const max_lookup_arity: usize = 32;
const no_node = std.math.maxInt(u32);
pub const Side = enum { expected, actual };
pub const InvalidKind = enum {
    truncated,
    invalid_magic,
    unsupported_version,
    invalid_family,
    invalid_section_count,
    unexpected_section,
    trailing_bytes,
    section_trailing_bytes,
    invalid_utf8,
    invalid_enum,
    invalid_optional,
    invalid_runtime_magic,
    invalid_runtime_program,
    invalid_manifest_binding,
};
pub const Path = struct {
    storage: [144]u8 = undefined,
    len: u8,

    pub fn slice(self: *const Path) []const u8 {
        return self.storage[0..self.len];
    }
};
pub const Invalid = struct { side: Side, kind: InvalidKind, path: Path, offset: usize };
pub const Value = union(enum) { absent, uint: u64, text: []const u8, bytes: []const u8, symbol: struct { code: u64, name: []const u8 } };
pub const Subject = union(enum) { none, name: []const u8, column: struct { logical: []const u8, physical: []const u8 } };
pub const Difference = struct { path: Path, subject: Subject = .none, expected: Value, actual: Value };
pub const Result = union(enum) { equal, difference: Difference, invalid: Invalid };
/// Validates both canonical envelopes and every nested record before returning
/// the first semantic difference. Invalid `expected` data takes precedence.
pub fn compare(expected_generated: []const u8, actual_on_disk: []const u8) Result {
    var expected_fault: ?Invalid = null;
    const expected_manifest = frame(expected_generated, .expected, &expected_fault) catch
        return .{ .invalid = expected_fault.? };
    if (walk(expected_manifest, expected_manifest, &expected_fault, &expected_fault) catch null) |_| {}
    if (expected_fault) |fault| return .{ .invalid = fault };
    var actual_fault: ?Invalid = null;
    const actual_manifest = frame(actual_on_disk, .actual, &actual_fault) catch
        return .{ .invalid = actual_fault.? };
    if (walk(actual_manifest, actual_manifest, &actual_fault, &actual_fault) catch null) |_| {}
    if (actual_fault) |fault| {
        var corrected = fault;
        corrected.side = .actual;
        return .{ .invalid = corrected };
    }
    const difference = walk(
        expected_manifest,
        actual_manifest,
        &expected_fault,
        &actual_fault,
    ) catch return .{ .invalid = expected_fault orelse actual_fault orelse .{
        .side = .expected,
        .kind = .invalid_manifest_binding,
        .path = path("manifest", .{}),
        .offset = 0,
    } };
    return if (difference) |item| .{ .difference = item } else .equal;
}
/// Stable one-line rendering intended for update-command and CI diagnostics.
pub fn writeResult(writer: anytype, result: Result) !void {
    switch (result) {
        .equal => try writer.writeAll("equal"),
        .invalid => |item| try writer.print(
            "invalid {s} manifest at {s} (byte {d}): {s}",
            .{ if (item.side == .expected) "expected/generated" else "actual/on-disk", item.path.slice(), item.offset, invalidText(item.kind) },
        ),
        .difference => |item| {
            try writer.print("difference at {s}", .{item.path.slice()});
            switch (item.subject) {
                .none => {},
                .name => |name| {
                    try writer.writeAll(" (name=");
                    try writeQuoted(writer, name);
                    try writer.writeByte(')');
                },
                .column => |column| {
                    try writer.writeAll(" (column logical=");
                    try writeQuoted(writer, column.logical);
                    try writer.writeAll(", physical=");
                    try writeQuoted(writer, column.physical);
                    try writer.writeByte(')');
                },
            }
            try writer.writeAll(": expected/generated ");
            try writeValue(writer, item.expected);
            try writer.writeAll(", actual/on-disk ");
            try writeValue(writer, item.actual);
        },
    }
}
const SectionView = struct { bytes: []const u8, offset: usize };
const Manifest = struct { family: u8, sections: [section_count]SectionView };
const ParseError = error{Malformed};
const Cursor = struct {
    bytes: []const u8,
    base: usize,
    pos: usize = 0,
    side: Side,
    fault: *?Invalid,
    fn reject(self: *Cursor, kind: InvalidKind, at: Path) ParseError {
        if (self.fault.* == null) self.fault.* = .{
            .side = self.side,
            .kind = kind,
            .path = at,
            .offset = self.base + self.pos,
        };
        return error.Malformed;
    }
    fn take(self: *Cursor, len: usize, at: Path) ParseError![]const u8 {
        if (len > self.bytes.len -| self.pos) return self.reject(.truncated, at);
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }
    fn int(self: *Cursor, comptime T: type, at: Path) ParseError!T {
        const bytes = try self.take(@sizeOf(T), at);
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }
    fn blob(self: *Cursor, at: Path) ParseError!SectionView {
        const len = try self.int(u32, at);
        const offset = self.base + self.pos;
        return .{ .bytes = try self.take(len, at), .offset = offset };
    }
    fn string(self: *Cursor, at: Path) ParseError![]const u8 {
        const result = (try self.blob(at)).bytes;
        if (!std.unicode.utf8ValidateSlice(result)) return self.reject(.invalid_utf8, at);
        return result;
    }
    fn optional(self: *Cursor, comptime T: type, at: Path) ParseError!?T {
        return switch (try self.int(u8, at)) {
            0 => null,
            1 => try self.int(T, at),
            else => return self.reject(.invalid_optional, at),
        };
    }
    fn tag(self: *Cursor, max: u8, at: Path) ParseError!u8 {
        const result = try self.int(u8, at);
        if (result > max) return self.reject(.invalid_enum, at);
        return result;
    }
    fn finish(self: *Cursor, at: Path) ParseError!void {
        if (self.pos != self.bytes.len) return self.reject(.section_trailing_bytes, at);
    }
};
fn frame(bytes: []const u8, side: Side, fault: *?Invalid) ParseError!Manifest {
    var c = Cursor{ .bytes = bytes, .base = 0, .side = side, .fault = fault };
    const got_magic = try c.take(magic.len, path("header.magic", .{}));
    if (!std.mem.eql(u8, got_magic, magic)) return c.reject(.invalid_magic, path("header.magic", .{}));
    const got_version = try c.int(u16, path("header.version", .{}));
    if (got_version != version) return c.reject(.unsupported_version, path("header.version", .{}));
    const family = try c.int(u8, path("header.family", .{}));
    if (family >= family_count) return c.reject(.invalid_family, path("header.family", .{}));
    const count = try c.int(u8, path("header.section_count", .{}));
    if (count != section_count) return c.reject(.invalid_section_count, path("header.section_count", .{}));
    var sections: [section_count]SectionView = undefined;
    for (&sections, 0..) |*section, index| {
        const id_path = path("sections[{d}].id", .{index});
        const id = try c.int(u8, id_path);
        if (id != index + 1) return c.reject(.unexpected_section, id_path);
        section.* = try c.blob(path("sections[{d}].length", .{index}));
    }
    if (c.pos != bytes.len) return c.reject(.trailing_bytes, path("manifest", .{}));
    return .{ .family = family, .sections = sections };
}
const Identity = struct {
    component: []const u8,
    family: u8,
    family_name: []const u8,
    manifest_schema: u32,
    semantic_revision: []const u8,
    layout_revision: []const u8,
    logical_schema: u16,
    digest_version: u16,
    digest_domain: []const u8,
    schedule_version: u16,
    schedule_domain: []const u8,
    layout_policy: []const u8,
    layout_policy_version: u16,
    direct_capability: []const u8,
    lookup_capability: []const u8,
    runtime_version: u16,
    formal_schema: u32,
    formal_kind: []const u8,
    digests: [9][]const u8,
};
fn readIdentity(view: SectionView, manifest_family: u8, side: Side, fault: *?Invalid) ParseError!Identity {
    var c = Cursor{ .bytes = view.bytes, .base = view.offset, .side = side, .fault = fault };
    var result = Identity{
        .component = try c.string(path("identity.component_kind", .{})),
        .family = try c.tag(family_count - 1, path("identity.family", .{})),
        .family_name = try c.string(path("identity.family_name", .{})),
        .manifest_schema = try c.int(u32, path("identity.manifest_schema", .{})),
        .semantic_revision = try c.string(path("identity.semantic_revision", .{})),
        .layout_revision = try c.string(path("identity.layout_revision", .{})),
        .logical_schema = try c.int(u16, path("identity.logical_schema", .{})),
        .digest_version = try c.int(u16, path("identity.semantic_digest.version", .{})),
        .digest_domain = try c.string(path("identity.semantic_digest.domain", .{})),
        .schedule_version = try c.int(u16, path("identity.source_schedule.version", .{})),
        .schedule_domain = try c.string(path("identity.source_schedule.domain", .{})),
        .layout_policy = try c.string(path("identity.layout_policy.id", .{})),
        .layout_policy_version = try c.int(u16, path("identity.layout_policy.version", .{})),
        .direct_capability = try c.string(path("identity.direct_capability", .{})),
        .lookup_capability = try c.string(path("identity.lookup_capability", .{})),
        .runtime_version = try c.int(u16, path("identity.runtime_capability_version", .{})),
        .formal_schema = try c.int(u32, path("identity.formal_schema", .{})),
        .formal_kind = try c.string(path("identity.formal_kind", .{})),
        .digests = undefined,
    };
    inline for (0..9) |index| result.digests[index] = try c.take(32, identityDigestPath(index));
    try c.finish(path("identity", .{}));
    if (result.family != manifest_family or !std.mem.eql(u8, result.family_name, familyName(result.family)))
        return c.reject(.invalid_manifest_binding, path("identity.family", .{}));
    return result;
}
fn walk(e: Manifest, a: Manifest, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    if (du(path("header.family", .{}), .none, e.family, a.family)) |d| return d;
    const ei = try readIdentity(e.sections[0], e.family, .expected, ef);
    const ai = try readIdentity(a.sections[0], a.family, .actual, af);
    if (compareIdentityCore(ei, ai)) |d| return d;
    if (try compareLayout(e.sections[1], a.sections[1], ef, af)) |d| return d;
    if (try compareDirect(e.sections[2], a.sections[2], ef, af)) |d| return d;
    if (try compareLookup(e.sections[3], a.sections[3], ef, af)) |d| return d;
    if (try compareDegrees(e.sections[4], a.sections[4], ef, af)) |d| return d;
    if (try compareHints(e.sections[5], a.sections[5], ef, af)) |d| return d;
    if (try compareFormal(e.sections[6], a.sections[6], ef, af)) |d| return d;
    inline for (0..9) |index|
        if (db(identityDigestPath(index), .none, ei.digests[index], ai.digests[index])) |d| return d;
    return null;
}
fn compareIdentityCore(e: Identity, a: Identity) ?Difference {
    if (dt(path("identity.component_kind", .{}), .none, e.component, a.component)) |d| return d;
    if (du(path("identity.family", .{}), .none, e.family, a.family)) |d| return d;
    if (dt(path("identity.family_name", .{}), .none, e.family_name, a.family_name)) |d| return d;
    if (du(path("identity.manifest_schema", .{}), .none, e.manifest_schema, a.manifest_schema)) |d| return d;
    if (dt(path("identity.semantic_revision", .{}), .none, e.semantic_revision, a.semantic_revision)) |d| return d;
    if (dt(path("identity.layout_revision", .{}), .none, e.layout_revision, a.layout_revision)) |d| return d;
    if (du(path("identity.logical_schema", .{}), .none, e.logical_schema, a.logical_schema)) |d| return d;
    if (du(path("identity.semantic_digest.version", .{}), .none, e.digest_version, a.digest_version)) |d| return d;
    if (dt(path("identity.semantic_digest.domain", .{}), .none, e.digest_domain, a.digest_domain)) |d| return d;
    if (du(path("identity.source_schedule.version", .{}), .none, e.schedule_version, a.schedule_version)) |d| return d;
    if (dt(path("identity.source_schedule.domain", .{}), .none, e.schedule_domain, a.schedule_domain)) |d| return d;
    if (dt(path("identity.layout_policy.id", .{}), .none, e.layout_policy, a.layout_policy)) |d| return d;
    if (du(path("identity.layout_policy.version", .{}), .none, e.layout_policy_version, a.layout_policy_version)) |d| return d;
    if (dt(path("identity.direct_capability", .{}), .none, e.direct_capability, a.direct_capability)) |d| return d;
    if (dt(path("identity.lookup_capability", .{}), .none, e.lookup_capability, a.lookup_capability)) |d| return d;
    if (du(path("identity.runtime_capability_version", .{}), .none, e.runtime_version, a.runtime_version)) |d| return d;
    if (du(path("identity.formal_schema", .{}), .none, e.formal_schema, a.formal_schema)) |d| return d;
    return dt(path("identity.formal_kind", .{}), .none, e.formal_kind, a.formal_kind);
}
const Ref = struct { tree: u8, index: u32 };
const Main = struct { ref: Ref, value: u32, logical: []const u8, physical: []const u8, window: u8 };
fn readRef(c: *Cursor, prefix: Path) ParseError!Ref {
    return .{
        .tree = try c.tag(2, child(prefix, ".tree")),
        .index = try c.int(u32, child(prefix, ".local_index")),
    };
}
fn compareRef(prefix: Path, subject: Subject, e: Ref, a: Ref) ?Difference {
    if (de(child(prefix, ".tree"), subject, e.tree, a.tree, &tree_names)) |d| return d;
    return du(child(prefix, ".local_index"), subject, e.index, a.index);
}
fn compareLayout(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const pre_count_e = try e.int(u32, path("layout.preprocessed.count", .{}));
    const pre_count_a = try a.int(u32, path("layout.preprocessed.count", .{}));
    if (du(path("layout.preprocessed.count", .{}), .none, pre_count_e, pre_count_a)) |d| return d;
    for (0..pre_count_e) |index| {
        const prefix = path("layout.preprocessed[{d}]", .{index});
        const er = try readRef(&e, child(prefix, ".reference"));
        const ek = try e.tag(1, child(prefix, ".kind"));
        const en = try e.string(child(prefix, ".name"));
        const eval = try e.optional(u32, child(prefix, ".value"));
        const ew = try e.tag(1, child(prefix, ".window"));
        const ar = try readRef(&a, child(prefix, ".reference"));
        const ak = try a.tag(1, child(prefix, ".kind"));
        const an = try a.string(child(prefix, ".name"));
        const aval = try a.optional(u32, child(prefix, ".value"));
        const aw = try a.tag(1, child(prefix, ".window"));
        const subject = Subject{ .name = en };
        if (compareRef(child(prefix, ".reference"), subject, er, ar)) |d| return d;
        if (de(child(prefix, ".kind"), subject, ek, ak, &pre_kind_names)) |d| return d;
        if (dt(child(prefix, ".name"), .none, en, an)) |d| return d;
        if (dopt(child(prefix, ".value"), subject, eval, aval)) |d| return d;
        if (de(child(prefix, ".window"), subject, ew, aw, &window_names)) |d| return d;
    }
    const main_count_e = try e.int(u32, path("layout.main.count", .{}));
    const main_count_a = try a.int(u32, path("layout.main.count", .{}));
    if (du(path("layout.main.count", .{}), .none, main_count_e, main_count_a)) |d| return d;
    for (0..main_count_e) |index| {
        const prefix = path("layout.main[{d}]", .{index});
        const em = try readMain(&e, prefix);
        const am = try readMain(&a, prefix);
        const subject = Subject{ .column = .{ .logical = em.logical, .physical = em.physical } };
        if (compareRef(child(prefix, ".reference"), subject, em.ref, am.ref)) |d| return d;
        if (du(child(prefix, ".value"), subject, em.value, am.value)) |d| return d;
        if (dt(child(prefix, ".logical_name"), subject, em.logical, am.logical)) |d| return d;
        if (dt(child(prefix, ".physical_name"), subject, em.physical, am.physical)) |d| return d;
        if (de(child(prefix, ".window"), subject, em.window, am.window, &window_names)) |d| return d;
    }
    const interaction_count_e = try e.int(u32, path("layout.interactions.count", .{}));
    const interaction_count_a = try a.int(u32, path("layout.interactions.count", .{}));
    if (du(path("layout.interactions.count", .{}), .none, interaction_count_e, interaction_count_a)) |d| return d;
    for (0..interaction_count_e) |index| {
        const prefix = path("layout.interactions[{d}]", .{index});
        const er = try readRef(&e, child(prefix, ".reference"));
        const ar = try readRef(&a, child(prefix, ".reference"));
        if (compareRef(child(prefix, ".reference"), .none, er, ar)) |d| return d;
        if (try pairInt(&e, &a, u32, child(prefix, ".batch"), .none)) |d| return d;
        const coordinate = child(prefix, ".coordinate");
        if (de(coordinate, .none, try e.tag(3, coordinate), try a.tag(3, coordinate), &coordinate_names)) |d| return d;
        if (try pairInt(&e, &a, u32, child(prefix, ".first_lookup"), .none)) |d| return d;
        if (try pairInt(&e, &a, u8, child(prefix, ".entry_count"), .none)) |d| return d;
        const window = child(prefix, ".window");
        if (de(window, .none, try e.tag(1, window), try a.tag(1, window), &window_names)) |d| return d;
    }
    try e.finish(path("layout", .{}));
    try a.finish(path("layout", .{}));
    return null;
}
fn readMain(c: *Cursor, prefix: Path) ParseError!Main {
    return .{
        .ref = try readRef(c, child(prefix, ".reference")),
        .value = try c.int(u32, child(prefix, ".value")),
        .logical = try c.string(child(prefix, ".logical_name")),
        .physical = try c.string(child(prefix, ".physical_name")),
        .window = try c.tag(1, child(prefix, ".window")),
    };
}
const Node = struct { op: u8, lhs: u32, rhs: u32, value: u32 };
fn readNode(c: *Cursor, prefix: Path, index: usize, columns: u32) ParseError!Node {
    const node = Node{
        .op = try c.tag(5, child(prefix, ".op")),
        .lhs = try c.int(u32, child(prefix, ".lhs")),
        .rhs = try c.int(u32, child(prefix, ".rhs")),
        .value = try c.int(u32, child(prefix, ".value")),
    };
    const valid = switch (node.op) {
        0 => true,
        1 => node.value < columns,
        2, 3, 4 => node.lhs < index and node.rhs < index,
        5 => node.lhs < index,
        else => false,
    };
    if (!valid) return c.reject(.invalid_runtime_program, prefix);
    return node;
}
fn compareNode(prefix: Path, e: Node, a: Node) ?Difference {
    if (de(child(prefix, ".op"), .none, e.op, a.op, &op_names)) |d| return d;
    if (du(child(prefix, ".lhs"), .none, e.lhs, a.lhs)) |d| return d;
    if (du(child(prefix, ".rhs"), .none, e.rhs, a.rhs)) |d| return d;
    return du(child(prefix, ".value"), .none, e.value, a.value);
}
fn compareBaseRuntime(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid, prefix_text: []const u8) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const prefix = path("{s}.runtime", .{prefix_text});
    try runtimeMagic(&e, "STWBASE\x01", child(prefix, ".magic"));
    try runtimeMagic(&a, "STWBASE\x01", child(prefix, ".magic"));
    const ec = try e.int(u32, child(prefix, ".column_count"));
    const ac = try a.int(u32, child(prefix, ".column_count"));
    if (ec == 0) return e.reject(.invalid_runtime_program, child(prefix, ".column_count"));
    if (ac == 0) return a.reject(.invalid_runtime_program, child(prefix, ".column_count"));
    if (du(child(prefix, ".column_count"), .none, ec, ac)) |d| return d;
    const en = try e.int(u32, child(prefix, ".nodes.count"));
    const an = try a.int(u32, child(prefix, ".nodes.count"));
    if (en == 0) return e.reject(.invalid_runtime_program, child(prefix, ".nodes.count"));
    if (an == 0) return a.reject(.invalid_runtime_program, child(prefix, ".nodes.count"));
    if (du(child(prefix, ".nodes.count"), .none, en, an)) |d| return d;
    for (0..en) |index| {
        const node_path = path("{s}.runtime.nodes[{d}]", .{ prefix_text, index });
        const eni = try readNode(&e, node_path, index, ec);
        const ani = try readNode(&a, node_path, index, ac);
        if (compareNode(node_path, eni, ani)) |d| return d;
    }
    const er = try e.int(u32, child(prefix, ".roots.count"));
    const ar = try a.int(u32, child(prefix, ".roots.count"));
    if (er == 0) return e.reject(.invalid_runtime_program, child(prefix, ".roots.count"));
    if (ar == 0) return a.reject(.invalid_runtime_program, child(prefix, ".roots.count"));
    if (du(child(prefix, ".roots.count"), .none, er, ar)) |d| return d;
    for (0..er) |index| {
        const root_path = path("{s}.runtime.roots[{d}]", .{ prefix_text, index });
        const eri = try e.int(u32, root_path);
        const ari = try a.int(u32, root_path);
        if (eri >= en) return e.reject(.invalid_runtime_program, root_path);
        if (ari >= an) return a.reject(.invalid_runtime_program, root_path);
        if (du(root_path, .none, eri, ari)) |d| return d;
    }
    try e.finish(prefix);
    try a.finish(prefix);
    return null;
}
fn compareDirect(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const edigest = try e.take(32, path("direct.runtime_digest", .{}));
    const adigest = try a.take(32, path("direct.runtime_digest", .{}));
    const eruntime = try e.blob(path("direct.runtime", .{}));
    const aruntime = try a.blob(path("direct.runtime", .{}));
    if (try compareBaseRuntime(eruntime, aruntime, ef, af, "direct")) |d| return d;
    const ec = try e.int(u32, path("direct.constraints.count", .{}));
    const ac = try a.int(u32, path("direct.constraints.count", .{}));
    if (du(path("direct.constraints.count", .{}), .none, ec, ac)) |d| return d;
    for (0..ec) |index| {
        const prefix = path("direct.constraints[{d}]", .{index});
        const eid = try e.int(u32, child(prefix, ".id"));
        const ename = try e.string(child(prefix, ".name"));
        const etyped = try e.int(u32, child(prefix, ".typed_root"));
        const esource = try e.int(u32, child(prefix, ".source_root"));
        const elowered = try e.int(u32, child(prefix, ".lowered_root"));
        const aid = try a.int(u32, child(prefix, ".id"));
        const aname = try a.string(child(prefix, ".name"));
        const atyped = try a.int(u32, child(prefix, ".typed_root"));
        const asource = try a.int(u32, child(prefix, ".source_root"));
        const alowered = try a.int(u32, child(prefix, ".lowered_root"));
        const subject = Subject{ .name = ename };
        if (du(child(prefix, ".id"), subject, eid, aid)) |d| return d;
        if (dt(child(prefix, ".name"), .none, ename, aname)) |d| return d;
        if (du(child(prefix, ".typed_root"), subject, etyped, atyped)) |d| return d;
        if (du(child(prefix, ".source_root"), subject, esource, asource)) |d| return d;
        if (du(child(prefix, ".lowered_root"), subject, elowered, alowered)) |d| return d;
    }
    try e.finish(path("direct", .{}));
    try a.finish(path("direct", .{}));
    return db(path("direct.runtime_digest", .{}), .none, edigest, adigest);
}
fn compareLookupRuntime(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    try runtimeMagic(&e, "STWLOOK\x01", path("lookup.runtime.magic", .{}));
    try runtimeMagic(&a, "STWLOOK\x01", path("lookup.runtime.magic", .{}));
    const ec = try e.int(u32, path("lookup.runtime.column_count", .{}));
    const ac = try a.int(u32, path("lookup.runtime.column_count", .{}));
    if (ec == 0) return e.reject(.invalid_runtime_program, path("lookup.runtime.column_count", .{}));
    if (ac == 0) return a.reject(.invalid_runtime_program, path("lookup.runtime.column_count", .{}));
    if (du(path("lookup.runtime.column_count", .{}), .none, ec, ac)) |d| return d;
    const eb = try e.int(u32, path("lookup.runtime.batch_size", .{}));
    const ab = try a.int(u32, path("lookup.runtime.batch_size", .{}));
    if (eb < 1 or eb > 2) return e.reject(.invalid_runtime_program, path("lookup.runtime.batch_size", .{}));
    if (ab < 1 or ab > 2) return a.reject(.invalid_runtime_program, path("lookup.runtime.batch_size", .{}));
    if (du(path("lookup.runtime.batch_size", .{}), .none, eb, ab)) |d| return d;
    const en = try e.int(u32, path("lookup.runtime.nodes.count", .{}));
    const an = try a.int(u32, path("lookup.runtime.nodes.count", .{}));
    if (en == 0) return e.reject(.invalid_runtime_program, path("lookup.runtime.nodes.count", .{}));
    if (an == 0) return a.reject(.invalid_runtime_program, path("lookup.runtime.nodes.count", .{}));
    if (du(path("lookup.runtime.nodes.count", .{}), .none, en, an)) |d| return d;
    for (0..en) |index| {
        const p = path("lookup.runtime.nodes[{d}]", .{index});
        const eni = try readNode(&e, p, index, ec);
        const ani = try readNode(&a, p, index, ac);
        if (compareNode(p, eni, ani)) |d| return d;
    }
    const ee = try e.int(u32, path("lookup.runtime.entries.count", .{}));
    const ae = try a.int(u32, path("lookup.runtime.entries.count", .{}));
    if (ee == 0) return e.reject(.invalid_runtime_program, path("lookup.runtime.entries.count", .{}));
    if (ae == 0) return a.reject(.invalid_runtime_program, path("lookup.runtime.entries.count", .{}));
    if (du(path("lookup.runtime.entries.count", .{}), .none, ee, ae)) |d| return d;
    for (0..ee) |index| {
        const p = path("lookup.runtime.entries[{d}]", .{index});
        const enumr = try e.int(u32, child(p, ".numerator"));
        const enarity = try e.int(u8, child(p, ".arity"));
        const anumr = try a.int(u32, child(p, ".numerator"));
        const anarity = try a.int(u8, child(p, ".arity"));
        if (enarity == 0 or enarity > max_lookup_arity or enumr >= en)
            return e.reject(.invalid_runtime_program, p);
        if (anarity == 0 or anarity > max_lookup_arity or anumr >= an)
            return a.reject(.invalid_runtime_program, p);
        if (du(child(p, ".numerator"), .none, enumr, anumr)) |d| return d;
        if (du(child(p, ".arity"), .none, enarity, anarity)) |d| return d;
        for (0..max_lookup_arity) |field| {
            const fp = path("lookup.runtime.entries[{d}].values[{d}]", .{ index, field });
            const evalue = try e.int(u32, fp);
            const avalue = try a.int(u32, fp);
            if ((field < enarity and evalue >= en) or (field >= enarity and evalue != no_node))
                return e.reject(.invalid_runtime_program, fp);
            if ((field < anarity and avalue >= an) or (field >= anarity and avalue != no_node))
                return a.reject(.invalid_runtime_program, fp);
            if (du(fp, .none, evalue, avalue)) |d| return d;
        }
    }
    try e.finish(path("lookup.runtime", .{}));
    try a.finish(path("lookup.runtime", .{}));
    return null;
}
fn compareLookup(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const edigest = try e.take(32, path("lookup.runtime_digest", .{}));
    const adigest = try a.take(32, path("lookup.runtime_digest", .{}));
    const eruntime = try e.blob(path("lookup.runtime", .{}));
    const aruntime = try a.blob(path("lookup.runtime", .{}));
    if (try compareLookupRuntime(eruntime, aruntime, ef, af)) |d| return d;
    const ec = try e.int(u32, path("lookup.events.count", .{}));
    const ac = try a.int(u32, path("lookup.events.count", .{}));
    if (du(path("lookup.events.count", .{}), .none, ec, ac)) |d| return d;
    for (0..ec) |index| {
        const p = path("lookup.events[{d}]", .{index});
        const eschema = try e.int(u16, child(p, ".schema_id"));
        const edomain = try e.tag(11, child(p, ".domain"));
        const eversion = try e.int(u16, child(p, ".schema_version"));
        const ename = try e.string(child(p, ".schema_name"));
        const erole = try e.tag(2, child(p, ".role"));
        const elive = try e.int(u32, child(p, ".liveness"));
        const enumr = try e.int(u32, child(p, ".numerator"));
        const earity = try e.int(u8, child(p, ".arity"));
        const eordinal = try e.optional(u8, child(p, ".access_ordinal"));
        const aschema = try a.int(u16, child(p, ".schema_id"));
        const adomain = try a.tag(11, child(p, ".domain"));
        const aversion = try a.int(u16, child(p, ".schema_version"));
        const aname = try a.string(child(p, ".schema_name"));
        const arole = try a.tag(2, child(p, ".role"));
        const alive = try a.int(u32, child(p, ".liveness"));
        const anumr = try a.int(u32, child(p, ".numerator"));
        const aarity = try a.int(u8, child(p, ".arity"));
        const aordinal = try a.optional(u8, child(p, ".access_ordinal"));
        if (eschema >= 12 or earity == 0 or earity > max_lookup_arity) return e.reject(.invalid_enum, p);
        if (aschema >= 12 or aarity == 0 or aarity > max_lookup_arity) return a.reject(.invalid_enum, p);
        const subject = Subject{ .name = ename };
        if (du(child(p, ".schema_id"), subject, eschema, aschema)) |d| return d;
        if (de(child(p, ".domain"), subject, edomain, adomain, &domain_names)) |d| return d;
        if (du(child(p, ".schema_version"), subject, eversion, aversion)) |d| return d;
        if (dt(child(p, ".schema_name"), .none, ename, aname)) |d| return d;
        if (de(child(p, ".role"), subject, erole, arole, &role_names)) |d| return d;
        if (du(child(p, ".liveness"), subject, elive, alive)) |d| return d;
        if (du(child(p, ".numerator"), subject, enumr, anumr)) |d| return d;
        if (du(child(p, ".arity"), subject, earity, aarity)) |d| return d;
        if (dopt(child(p, ".access_ordinal"), subject, eordinal, aordinal)) |d| return d;
        for (0..earity) |field| {
            const fp = path("lookup.events[{d}].values[{d}]", .{ index, field });
            const evalue = try e.int(u32, fp);
            const avalue = try a.int(u32, fp);
            if (du(fp, subject, evalue, avalue)) |d| return d;
        }
    }
    const eb = try e.int(u32, path("lookup.batches.count", .{}));
    const ab = try a.int(u32, path("lookup.batches.count", .{}));
    if (du(path("lookup.batches.count", .{}), .none, eb, ab)) |d| return d;
    for (0..eb) |index| {
        const p = path("lookup.batches[{d}]", .{index});
        if (try pairInt(&e, &a, u32, child(p, ".first_event"), .none)) |d| return d;
        if (try pairInt(&e, &a, u8, child(p, ".event_count"), .none)) |d| return d;
        for (0..4) |coordinate| {
            const rp = path("lookup.batches[{d}].interaction_columns[{d}]", .{ index, coordinate });
            const er = try readRef(&e, rp);
            const ar = try readRef(&a, rp);
            if (compareRef(rp, .none, er, ar)) |d| return d;
        }
    }
    try e.finish(path("lookup", .{}));
    try a.finish(path("lookup", .{}));
    return db(path("lookup.runtime_digest", .{}), .none, edigest, adigest);
}
fn compareDegrees(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    inline for ([_][]const u8{
        "trace_log_size",                        "maximum_direct_degree",      "maximum_lookup_numerator_degree",
        "maximum_lookup_denominator_degree",     "maximum_interaction_degree", "required_direct_log_degree_bound",
        "required_interaction_log_degree_bound",
    }) |field| {
        const p = path("degree.{s}", .{field});
        if (try pairInt(&e, &a, u32, p, .none)) |d| return d;
    }
    const dc_e = try e.int(u32, path("degree.direct.count", .{}));
    const dc_a = try a.int(u32, path("degree.direct.count", .{}));
    if (du(path("degree.direct.count", .{}), .none, dc_e, dc_a)) |d| return d;
    for (0..dc_e) |index| {
        const p = path("degree.direct[{d}]", .{index});
        if (try pairInt(&e, &a, u32, child(p, ".constraint_id"), .none)) |d| return d;
        if (try pairInt(&e, &a, u32, child(p, ".expression"), .none)) |d| return d;
        const eo = try e.optional(u32, child(p, ".explicit_gate"));
        const ao = try a.optional(u32, child(p, ".explicit_gate"));
        if (dopt(child(p, ".explicit_gate"), .none, eo, ao)) |d| return d;
        if (try pairInt(&e, &a, u32, child(p, ".external_row_mask"), .none)) |d| return d;
        if (try pairInt(&e, &a, u32, child(p, ".final"), .none)) |d| return d;
        if (try pairInt(&e, &a, u8, child(p, ".quotient_expansion_bits"), .none)) |d| return d;
        if (try pairInt(&e, &a, u32, child(p, ".required_log_degree_bound"), .none)) |d| return d;
    }
    const lc_e = try e.int(u32, path("degree.lookups.count", .{}));
    const lc_a = try a.int(u32, path("degree.lookups.count", .{}));
    if (du(path("degree.lookups.count", .{}), .none, lc_e, lc_a)) |d| return d;
    for (0..lc_e) |index| {
        inline for ([_][]const u8{ "index", "numerator", "denominator", "maximum_field" }) |field| {
            const p = path("degree.lookups[{d}].{s}", .{ index, field });
            if (try pairInt(&e, &a, u32, p, .none)) |d| return d;
        }
    }
    const ic_e = try e.int(u32, path("degree.interactions.count", .{}));
    const ic_a = try a.int(u32, path("degree.interactions.count", .{}));
    if (du(path("degree.interactions.count", .{}), .none, ic_e, ic_a)) |d| return d;
    for (0..ic_e) |index| {
        inline for ([_]struct { name: []const u8, T: type }{
            .{ .name = "batch", .T = u32 },                  .{ .name = "first_lookup", .T = u32 },
            .{ .name = "entry_count", .T = u8 },             .{ .name = "row_window", .T = u32 },
            .{ .name = "boundary_selector", .T = u32 },      .{ .name = "boundary_claim", .T = u32 },
            .{ .name = "delta", .T = u32 },                  .{ .name = "denominator_product", .T = u32 },
            .{ .name = "combined_numerator", .T = u32 },     .{ .name = "final", .T = u32 },
            .{ .name = "quotient_expansion_bits", .T = u8 }, .{ .name = "required_log_degree_bound", .T = u32 },
        }) |field| {
            const p = path("degree.interactions[{d}].{s}", .{ index, field.name });
            if (try pairInt(&e, &a, field.T, p, .none)) |d| return d;
        }
    }
    try e.finish(path("degree", .{}));
    try a.finish(path("degree", .{}));
    return null;
}
fn compareHints(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const ec = try e.int(u32, path("hints.count", .{}));
    const ac = try a.int(u32, path("hints.count", .{}));
    if (du(path("hints.count", .{}), .none, ec, ac)) |d| return d;
    for (0..ec) |index| {
        const p = path("hints[{d}]", .{index});
        const eid = try e.int(u16, child(p, ".recipe_id"));
        const aid = try a.int(u16, child(p, ".recipe_id"));
        const eversion = try e.int(u16, child(p, ".version"));
        const aversion = try a.int(u16, child(p, ".version"));
        const ename = try e.string(child(p, ".name"));
        const aname = try a.string(child(p, ".name"));
        const subject = Subject{ .name = ename };
        if (du(child(p, ".recipe_id"), subject, eid, aid)) |d| return d;
        if (du(child(p, ".version"), subject, eversion, aversion)) |d| return d;
        if (dt(child(p, ".name"), .none, ename, aname)) |d| return d;
    }
    try e.finish(path("hints", .{}));
    try a.finish(path("hints", .{}));
    return null;
}
fn compareFormal(ev: SectionView, av: SectionView, ef: *?Invalid, af: *?Invalid) ParseError!?Difference {
    var e = cursor(ev, .expected, ef);
    var a = cursor(av, .actual, af);
    const es = try e.int(u32, path("formal.schema", .{}));
    const as = try a.int(u32, path("formal.schema", .{}));
    if (du(path("formal.schema", .{}), .none, es, as)) |d| return d;
    const ek = try e.string(path("formal.kind", .{}));
    const ak = try a.string(path("formal.kind", .{}));
    if (dt(path("formal.kind", .{}), .none, ek, ak)) |d| return d;
    const ec = try e.int(u32, path("formal.exports.count", .{}));
    const ac = try a.int(u32, path("formal.exports.count", .{}));
    if (du(path("formal.exports.count", .{}), .none, ec, ac)) |d| return d;
    for (0..ec) |index| {
        const p = path("formal.exports[{d}]", .{index});
        const eid = try e.int(u32, child(p, ".opcode_id"));
        const aid = try a.int(u32, child(p, ".opcode_id"));
        const ename = try e.string(child(p, ".mnemonic"));
        const aname = try a.string(child(p, ".mnemonic"));
        const elen = try e.int(u32, child(p, ".byte_length"));
        const alen = try a.int(u32, child(p, ".byte_length"));
        const edigest = try e.take(32, child(p, ".sha256"));
        const adigest = try a.take(32, child(p, ".sha256"));
        const subject = Subject{ .name = ename };
        if (du(child(p, ".opcode_id"), subject, eid, aid)) |d| return d;
        if (dt(child(p, ".mnemonic"), .none, ename, aname)) |d| return d;
        if (du(child(p, ".byte_length"), subject, elen, alen)) |d| return d;
        if (db(child(p, ".sha256"), subject, edigest, adigest)) |d| return d;
    }
    try e.finish(path("formal", .{}));
    try a.finish(path("formal", .{}));
    return null;
}
fn cursor(view: SectionView, side: Side, fault: *?Invalid) Cursor {
    return .{ .bytes = view.bytes, .base = view.offset, .side = side, .fault = fault };
}
fn runtimeMagic(c: *Cursor, expected: []const u8, at: Path) ParseError!void {
    if (!std.mem.eql(u8, try c.take(expected.len, at), expected)) return c.reject(.invalid_runtime_magic, at);
}
fn path(comptime fmt: []const u8, args: anytype) Path {
    var result = Path{ .len = 0 };
    const written = std.fmt.bufPrint(&result.storage, fmt, args) catch {
        const fallback = "diagnostic.path_overflow";
        @memcpy(result.storage[0..fallback.len], fallback);
        result.len = fallback.len;
        return result;
    };
    result.len = @intCast(written.len);
    return result;
}
fn child(parent: Path, comptime suffix: []const u8) Path {
    var result = parent;
    @memcpy(result.storage[result.len..][0..suffix.len], suffix);
    result.len += suffix.len;
    return result;
}
fn pairInt(e: *Cursor, a: *Cursor, comptime T: type, at: Path, subject: Subject) ParseError!?Difference {
    return du(at, subject, try e.int(T, at), try a.int(T, at));
}
fn du(at: Path, subject: Subject, expected: anytype, actual: @TypeOf(expected)) ?Difference {
    if (expected == actual) return null;
    return .{ .path = at, .subject = subject, .expected = .{ .uint = @intCast(expected) }, .actual = .{ .uint = @intCast(actual) } };
}
fn dt(at: Path, subject: Subject, expected: []const u8, actual: []const u8) ?Difference {
    if (std.mem.eql(u8, expected, actual)) return null;
    return .{ .path = at, .subject = subject, .expected = .{ .text = expected }, .actual = .{ .text = actual } };
}
fn db(at: Path, subject: Subject, expected: []const u8, actual: []const u8) ?Difference {
    if (std.mem.eql(u8, expected, actual)) return null;
    return .{ .path = at, .subject = subject, .expected = .{ .bytes = expected }, .actual = .{ .bytes = actual } };
}
fn dopt(at: Path, subject: Subject, expected: anytype, actual: @TypeOf(expected)) ?Difference {
    if (expected == actual) return null;
    return .{
        .path = at,
        .subject = subject,
        .expected = if (expected) |v| .{ .uint = v } else .absent,
        .actual = if (actual) |v| .{ .uint = v } else .absent,
    };
}
fn de(at: Path, subject: Subject, expected: u8, actual: u8, names: []const []const u8) ?Difference {
    if (expected == actual) return null;
    return .{
        .path = at,
        .subject = subject,
        .expected = .{ .symbol = .{ .code = expected, .name = names[expected] } },
        .actual = .{ .symbol = .{ .code = actual, .name = names[actual] } },
    };
}
fn identityDigestPath(index: usize) Path {
    const names = [_][]const u8{
        "witness_layout_digest", "source_schedule_digest", "semantic_digest",
        "layout_digest",         "direct_runtime_digest",  "lookup_runtime_digest",
        "degree_digest",         "hint_digest",            "formal_digest",
    };
    return path("identity.{s}", .{names[index]});
}
fn familyName(tag: u8) []const u8 {
    const names = [_][]const u8{
        "base_alu_reg", "base_alu_imm", "shifts_reg", "shifts_imm", "lt_reg",
        "lt_imm",       "branch_eq",    "branch_lt",  "lui",        "auipc",
        "jalr",         "jal",          "load_store", "mul",        "mulh",
        "div",          "fence",
    };
    return names[tag];
}
fn invalidText(kind: InvalidKind) []const u8 {
    return switch (kind) {
        .truncated => "truncated field",
        .invalid_magic => "invalid magic",
        .unsupported_version => "unsupported format version",
        .invalid_family => "invalid family tag",
        .invalid_section_count => "invalid section count",
        .unexpected_section => "unexpected section id or order",
        .trailing_bytes => "trailing manifest bytes",
        .section_trailing_bytes => "trailing section bytes",
        .invalid_utf8 => "invalid UTF-8 string",
        .invalid_enum => "invalid enum tag",
        .invalid_optional => "invalid optional-presence tag",
        .invalid_runtime_magic => "invalid nested runtime magic",
        .invalid_runtime_program => "invalid nested runtime program",
        .invalid_manifest_binding => "inconsistent manifest identity binding",
    };
}
fn writeValue(writer: anytype, value: Value) !void {
    switch (value) {
        .absent => try writer.writeAll("absent"),
        .uint => |number| try writer.print("{d}", .{number}),
        .text => |text| try writeQuoted(writer, text),
        .bytes => |bytes| {
            try writer.writeAll("0x");
            for (bytes) |byte| try writer.print("{x:0>2}", .{byte});
        },
        .symbol => |item| try writer.print("{s} ({d})", .{ item.name, item.code }),
    }
}
fn writeQuoted(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        else => if (byte >= 0x20 and byte <= 0x7e)
            try writer.writeByte(byte)
        else
            try writer.print("\\x{x:0>2}", .{byte}),
    };
    try writer.writeByte('"');
}
const tree_names = [_][]const u8{ "preprocessed", "main", "interaction" };
const pre_kind_names = [_][]const u8{ "is_first", "is_active" };
const window_names = [_][]const u8{ "current", "current_and_previous" };
const coordinate_names = [_][]const u8{ "c0_a", "c0_b", "c1_a", "c1_b" };
const op_names = [_][]const u8{ "constant", "column", "add", "sub", "mul", "neg" };
const role_names = [_][]const u8{ "request", "consume", "emit" };
const domain_names = [_][]const u8{
    "registers_state", "memory_access",   "program_access", "merkle",           "poseidon2",
    "poseidon2_io",    "bitwise",         "range_check_20", "range_check_8_11", "range_check_8_8_4",
    "range_check_8_8", "range_check_m31",
};
