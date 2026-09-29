//! Shared decoders for the circuit-recursion oracle fixtures
//! (`vectors/circuit/README.md`): the checkpoint envelope, QM31 values and
//! hex digests. Test-only; used by the R3 driver and meant for the R1/R2 and
//! R4/R5 drivers as well.

const std = @import("std");
const stwo_core = @import("stwo_core");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const Value = std.json.Value;

pub const checkpoint_schema = "stwo-circuit-oracle-checkpoint-v1";
pub const proving_repository = "https://github.com/starkware-libs/proving";
pub const proving_revision = "5a7c5ede4299c91a61df19a07cba4f7502c14230";

pub const Error = error{ FixtureShape, FixtureEnvelope };

/// A parsed JSON document that owns its bytes.
pub const Document = struct {
    parsed: std.json.Parsed(Value),

    pub fn deinit(self: *Document) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn root(self: *const Document) Value {
        return self.parsed.value;
    }
};

pub fn load(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) !Document {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
    defer allocator.free(bytes);
    return .{ .parsed = try std.json.parseFromSlice(Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}

/// Checks the checkpoint envelope and returns its `body`.
pub fn checkpointBody(document: Value, rung: []const u8, subcommand: []const u8) !Value {
    if (!std.mem.eql(u8, try string(try field(document, "schema")), checkpoint_schema)) return error.FixtureEnvelope;
    if (!std.mem.eql(u8, try string(try field(document, "rung")), rung)) return error.FixtureEnvelope;
    if (!std.mem.eql(u8, try string(try field(document, "subcommand")), subcommand)) return error.FixtureEnvelope;
    const authority = try field(document, "authority");
    if (!std.mem.eql(u8, try string(try field(authority, "repository")), proving_repository)) return error.FixtureEnvelope;
    if (!std.mem.eql(u8, try string(try field(authority, "revision")), proving_revision)) return error.FixtureEnvelope;
    return field(document, "body");
}

pub fn field(object: Value, name: []const u8) Error!Value {
    if (object != .object) return error.FixtureShape;
    return object.object.get(name) orelse error.FixtureShape;
}

pub fn optionalField(object: Value, name: []const u8) Error!?Value {
    if (object != .object) return error.FixtureShape;
    const value = object.object.get(name) orelse return null;
    return if (value == .null) null else value;
}

pub fn array(value: Value) Error![]const Value {
    if (value != .array) return error.FixtureShape;
    return value.array.items;
}

pub fn string(value: Value) Error![]const u8 {
    if (value != .string) return error.FixtureShape;
    return value.string;
}

pub fn boolean(value: Value) Error!bool {
    if (value != .bool) return error.FixtureShape;
    return value.bool;
}

pub fn unsigned(comptime T: type, value: Value) Error!T {
    if (value != .integer) return error.FixtureShape;
    return std.math.cast(T, value.integer) orelse error.FixtureShape;
}

pub fn m31(value: Value) Error!M31 {
    const raw = try unsigned(u32, value);
    if (raw >= stwo_core.fields.m31.Modulus) return error.FixtureShape;
    return M31.fromCanonical(raw);
}

/// A QM31 as `[a, b, c, d]` (checkpoints) or `[[a, b], [c, d]]` (upstream
/// `sample_evaluations.json`), both meaning `(a + b·i) + (c + d·i)·u`.
pub fn qm31(value: Value) Error!QM31 {
    const items = try array(value);
    if (items.len == 4) return QM31.fromM31(try m31(items[0]), try m31(items[1]), try m31(items[2]), try m31(items[3]));
    if (items.len != 2) return error.FixtureShape;
    const lo = try array(items[0]);
    const hi = try array(items[1]);
    if (lo.len != 2 or hi.len != 2) return error.FixtureShape;
    return QM31.fromM31(try m31(lo[0]), try m31(lo[1]), try m31(hi[0]), try m31(hi[1]));
}

pub fn qm31List(allocator: std.mem.Allocator, value: Value) ![]QM31 {
    const items = try array(value);
    const out = try allocator.alloc(QM31, items.len);
    errdefer allocator.free(out);
    for (items, out) |item, *slot| slot.* = try qm31(item);
    return out;
}

/// A 64-character lowercase hex digest.
pub fn digest(value: Value) ![32]u8 {
    const text = try string(value);
    if (text.len != 64) return error.FixtureShape;
    for (text) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return error.FixtureShape;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
