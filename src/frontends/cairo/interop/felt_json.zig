//! The CairoSerde felt transport shared by the Cairo proof formats and the
//! circuit-recursion wire formats (the Cairo frontend's `proof.cairo_serde`
//! and `stwo_circuit_recursion_wire`, which may not import each other):
//!
//! - the streaming pretty JSON array of Starknet field elements, the
//!   `ProofFormat::CairoSerde` file of upstream `crates/cairo-air/src/utils.rs`
//!   (https://github.com/starkware-libs/proving at
//!   5a7c5ede4299c91a61df19a07cba4f7502c14230, and stwo-cairo `82f2125`):
//!   every felt formatted as `"0x{felt:x}"` and the list written with
//!   `serde_json::to_string_pretty`, i.e. two-space indentation, one element
//!   per line, and `[]` for an empty list. Writing element by element keeps a
//!   multi-megabyte proof stream out of memory;
//! - the felt252 primitives of `stwo-cairo-serialize`
//!   (`crates/cairo-serialize`, `serialize.rs` and `deserialize.rs`):
//!   `FeltWriter` and `FeltReader`;
//! - `sort_and_transpose_queried_values` (`crates/cairo-air/src/utils.rs`):
//!   the queried-value layout the Cairo verifier reads.
//!
//! Primitive encodings, all reproduced here:
//!
//! - `u32`, `u64`, `usize`: one felt holding the value;
//! - M31 (`BaseField`): one felt; QM31 (`SecureField`): its four M31 limbs;
//! - `Blake2sHash`: eight felts, the digest's little-endian `u32` words;
//! - `[T]`/`Vec<T>`: a length felt, then the elements; `[T; N]`: the elements;
//! - `Option<T>`: `0` then the value for `Some`, `1` for `None`;
//! - `FriConfig`: `pow_bits, log_blowup_factor, log_last_layer_degree_bound,
//!   n_queries, fold_step`; `PcsConfig`: only its `FriConfig` (the lifting
//!   heights are not on the wire);
//! - `LinePoly`: its coefficient vector, then `ilog2(len)`.
//!
//! Every felt these types produce fits in a `u64`, so the stream is carried
//! as `u64` felts. The one type whose felts can be wide, a Poseidon252 hash,
//! is not part of any stream written here.
//!
//! Decoding is fail-closed where upstream is lenient in ways that would break
//! a byte-identical round trip: a felt above `u64::MAX`, a non-canonical felt
//! JSON string, and an M31 at or above P (upstream `BaseField::from(u32)`
//! reduces it) are rejected. Upstream's panics (`u32` out of range, bad
//! `Option` discriminant, `LinePoly` length mismatch, end of stream) are
//! errors here.

const std = @import("std");
const core = @import("stwo_core");
const transport = @This();

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31_modulus = core.fields.m31.Modulus;

/// Committed trees of a Stwo proof: preprocessed, trace, interaction, composition.
pub const n_queried_trees: usize = 4;

pub const State = struct {
    count: usize = 0,
};

pub fn begin(writer: anytype) !void {
    try writer.writeAll("[");
}

pub fn write(writer: anytype, state: *State, value: u64) !void {
    if (state.count == 0) {
        try writer.writeAll("\n");
    } else {
        try writer.writeAll(",\n");
    }
    try writer.print("  \"0x{x}\"", .{value});
    state.count += 1;
}

pub fn end(writer: anytype, state: State) !void {
    if (state.count != 0) try writer.writeAll("\n");
    try writer.writeAll("]");
}

pub const FriConfig = core.pcs.config_v2.FriConfigV2;
pub const Blake2sHash = [32]u8;

pub const DecodeError = error{
    /// `data.next().unwrap()` on an exhausted stream.
    EndOfStream,
    /// A felt too large for the integer it encodes, or an M31 at or above P.
    ValueOutOfRange,
    /// An `Option` discriminant other than 0 or 1.
    InvalidDiscriminant,
    /// A `LinePoly` whose coefficient count is not `2^log_size`.
    InvalidLinePoly,
};

pub const EncodeError = error{
    /// A `LinePoly` whose coefficient count is not a nonzero power of two.
    InvalidLinePoly,
};

/// Reads upstream `CairoDeserialize` values from a felt stream.
pub const FeltReader = struct {
    felts: []const u64,
    position: usize = 0,

    pub fn remaining(self: FeltReader) usize {
        return self.felts.len - self.position;
    }

    pub fn felt(self: *FeltReader) DecodeError!u64 {
        if (self.position == self.felts.len) return error.EndOfStream;
        defer self.position += 1;
        return self.felts[self.position];
    }

    pub fn @"u32"(self: *FeltReader) DecodeError!u32 {
        return std.math.cast(u32, try self.felt()) orelse error.ValueOutOfRange;
    }

    pub fn @"u64"(self: *FeltReader) DecodeError!u64 {
        return self.felt();
    }

    /// `usize` is decoded as `u64`; lengths must also fit this host's `usize`.
    pub fn length(self: *FeltReader) DecodeError!usize {
        const value = try self.felt();
        // A length cannot exceed the felts left to hold its elements.
        if (value > self.remaining()) return error.ValueOutOfRange;
        return @intCast(value);
    }

    pub fn m31(self: *FeltReader) DecodeError!M31 {
        const value = try self.u32();
        if (value >= m31_modulus) return error.ValueOutOfRange;
        return M31.fromCanonical(value);
    }

    pub fn qm31(self: *FeltReader) DecodeError!QM31 {
        var limbs: [4]M31 = undefined;
        for (&limbs) |*limb| limb.* = try self.m31();
        return QM31.fromM31Array(limbs);
    }

    pub fn blake2sHash(self: *FeltReader) DecodeError!Blake2sHash {
        var hash: Blake2sHash = undefined;
        for (0..8) |word| {
            std.mem.writeInt(u32, hash[word * 4 ..][0..4], try self.u32(), .little);
        }
        return hash;
    }

    /// `Option<T>` discriminant: `true` for `Some`.
    pub fn isSome(self: *FeltReader) DecodeError!bool {
        return switch (try self.felt()) {
            0 => true,
            1 => false,
            else => error.InvalidDiscriminant,
        };
    }

    pub fn friConfig(self: *FeltReader) DecodeError!FriConfig {
        return .{
            .pow_bits = try self.u32(),
            .log_blowup_factor = try self.u32(),
            .log_last_layer_degree_bound = try self.u32(),
            // `usize` upstream; the Zig config holds a `u32`.
            .n_queries = std.math.cast(u32, try self.u64()) orelse return error.ValueOutOfRange,
            .fold_step = try self.u32(),
        };
    }

    pub fn qm31Vec(self: *FeltReader, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)![]QM31 {
        const values = try allocator.alloc(QM31, try self.length());
        errdefer allocator.free(values);
        for (values) |*value| value.* = try self.qm31();
        return values;
    }

    pub fn m31Vec(self: *FeltReader, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)![]M31 {
        const values = try allocator.alloc(M31, try self.length());
        errdefer allocator.free(values);
        for (values) |*value| value.* = try self.m31();
        return values;
    }

    pub fn hashVec(self: *FeltReader, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)![]Blake2sHash {
        const values = try allocator.alloc(Blake2sHash, try self.length());
        errdefer allocator.free(values);
        for (values) |*value| value.* = try self.blake2sHash();
        return values;
    }

    /// `LinePoly`: the coefficients, then `log_size` with `len == 2^log_size`.
    pub fn linePoly(self: *FeltReader, allocator: std.mem.Allocator) (DecodeError || std.mem.Allocator.Error)![]QM31 {
        const coeffs = try self.qm31Vec(allocator);
        errdefer allocator.free(coeffs);
        const log_size = try self.u32();
        if (log_size >= @bitSizeOf(usize) or coeffs.len != @as(usize, 1) << @intCast(log_size)) {
            return error.InvalidLinePoly;
        }
        return coeffs;
    }
};

/// Writes upstream `CairoSerialize` values to a felt sink: any value with
/// `fn felt(self, u64) !void` (`FeltList`, `FeltJsonWriter`).
pub fn FeltWriter(comptime Sink: type) type {
    return struct {
        sink: Sink,

        const Self = @This();

        pub fn felt(self: *Self, value: u64) !void {
            try self.sink.felt(value);
        }

        pub fn m31(self: *Self, value: M31) !void {
            try self.felt(value.v);
        }

        pub fn qm31(self: *Self, value: QM31) !void {
            for (value.toM31Array()) |limb| try self.m31(limb);
        }

        pub fn blake2sHash(self: *Self, hash: *const Blake2sHash) !void {
            for (0..8) |word| try self.felt(std.mem.readInt(u32, hash[word * 4 ..][0..4], .little));
        }

        pub fn some(self: *Self) !void {
            try self.felt(0);
        }

        pub fn none(self: *Self) !void {
            try self.felt(1);
        }

        pub fn friConfig(self: *Self, config: FriConfig) !void {
            try self.felt(config.pow_bits);
            try self.felt(config.log_blowup_factor);
            try self.felt(config.log_last_layer_degree_bound);
            try self.felt(config.n_queries);
            try self.felt(config.fold_step);
        }

        pub fn qm31Vec(self: *Self, values: []const QM31) !void {
            try self.felt(values.len);
            for (values) |value| try self.qm31(value);
        }

        pub fn m31Vec(self: *Self, values: []const M31) !void {
            try self.felt(values.len);
            for (values) |value| try self.m31(value);
        }

        pub fn hashVec(self: *Self, values: []const Blake2sHash) !void {
            try self.felt(values.len);
            for (values) |*value| try self.blake2sHash(value);
        }

        pub fn linePoly(self: *Self, coeffs: []const QM31) !void {
            if (coeffs.len == 0 or !std.math.isPowerOfTwo(coeffs.len)) return error.InvalidLinePoly;
            try self.qm31Vec(coeffs);
            try self.felt(std.math.log2_int(usize, coeffs.len));
        }
    };
}

/// A felt sink collecting into memory.
pub const FeltList = struct {
    list: *std.ArrayList(u64),
    allocator: std.mem.Allocator,

    pub fn felt(self: FeltList, value: u64) std.mem.Allocator.Error!void {
        try self.list.append(self.allocator, value);
    }
};

/// A felt sink streaming the upstream `ProofFormat::CairoSerde` JSON text
/// (`serde_json::to_vec_pretty` of `"0x{felt:x}"` strings).
pub const FeltJsonWriter = struct {
    out: *std.Io.Writer,
    state: State = .{},

    pub fn begin(out: *std.Io.Writer) std.Io.Writer.Error!FeltJsonWriter {
        try transport.begin(out);
        return .{ .out = out };
    }

    pub fn felt(self: *FeltJsonWriter, value: u64) std.Io.Writer.Error!void {
        try transport.write(self.out, &self.state, value);
    }

    pub fn end(self: *FeltJsonWriter) std.Io.Writer.Error!void {
        try transport.end(self.out, self.state);
    }
};

pub const FeltJsonError = error{
    /// Not a JSON array of strings.
    InvalidFeltJson,
    /// A felt string that is not `0x` followed by lowercase hex without
    /// leading zeros, the only form `format!("0x{felt:x}")` produces.
    NonCanonicalFelt,
    /// A felt above `u64::MAX`.
    ValueOutOfRange,
} || std.mem.Allocator.Error;

/// Parses a felt JSON array (the inverse of `FeltJsonWriter`).
pub fn parseFeltJson(allocator: std.mem.Allocator, text: []const u8) FeltJsonError![]u64 {
    var parsed = std.json.parseFromSlice([]const []const u8, allocator, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidFeltJson,
    };
    defer parsed.deinit();
    const felts = try allocator.alloc(u64, parsed.value.len);
    errdefer allocator.free(felts);
    for (parsed.value, felts) |string, *value| value.* = try parseCanonicalFelt(string);
    return felts;
}

fn parseCanonicalFelt(text: []const u8) FeltJsonError!u64 {
    if (text.len < 3 or !std.mem.startsWith(u8, text, "0x")) return error.NonCanonicalFelt;
    const digits = text[2..];
    if (digits.len > 1 and digits[0] == '0') return error.NonCanonicalFelt;
    for (digits) |char| switch (char) {
        '0'...'9', 'a'...'f' => {},
        else => return error.NonCanonicalFelt,
    };
    return std.fmt.parseInt(u64, digits, 16) catch error.ValueOutOfRange;
}

pub const TransposeError = error{
    /// Columns of one tree with different query counts, a log-size list of
    /// the wrong length, or an empty preprocessed tree.
    ShapeMismatch,
} || std.mem.Allocator.Error;

/// `sort_and_transpose_queried_values`: converts tree-major queried values
/// (`queried_values[tree][column][query]`, as the prover stores them) to the
/// layout the Cairo verifier reads: per tree, all columns' values of query 0,
/// then of query 1, and so on. The trace and interaction trees (1 and 2) are
/// first stably sorted by column log size; the preprocessed tree is already
/// sorted and the composition columns share one size, so trees 0 and 3 are
/// only transposed. The query count is taken from the first preprocessed
/// column, as upstream does. The result is owned by `allocator`.
pub fn sortAndTransposeQueriedValues(
    allocator: std.mem.Allocator,
    queried_values: [n_queried_trees][]const []const M31,
    trace_log_sizes: []const u32,
    interaction_log_sizes: []const u32,
) TransposeError![n_queried_trees][]M31 {
    if (queried_values[0].len == 0) return error.ShapeMismatch;
    const n_queries = queried_values[0][0].len;
    const log_sizes = [n_queried_trees]?[]const u32{ null, trace_log_sizes, interaction_log_sizes, null };

    var result: [n_queried_trees][]M31 = undefined;
    var done: usize = 0;
    errdefer for (result[0..done]) |tree| allocator.free(tree);
    for (queried_values, log_sizes, 0..) |columns, sizes, tree| {
        for (columns) |column| if (column.len != n_queries) return error.ShapeMismatch;
        const order = try allocator.alloc(usize, columns.len);
        defer allocator.free(order);
        for (order, 0..) |*slot, index| slot.* = index;
        if (sizes) |column_sizes| {
            if (column_sizes.len != columns.len) return error.ShapeMismatch;
            std.sort.block(usize, order, column_sizes, lessByLogSize);
        }
        const out = try allocator.alloc(M31, columns.len * n_queries);
        for (0..n_queries) |query| {
            for (order, 0..) |column, position| out[query * columns.len + position] = columns[column][query];
        }
        result[tree] = out;
        done += 1;
    }
    return result;
}

fn lessByLogSize(sizes: []const u32, lhs: usize, rhs: usize) bool {
    return sizes[lhs] < sizes[rhs];
}

test "felt JSON uses the upstream pretty-array surface" {
    var storage: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    var state = State{};
    try begin(&writer);
    try write(&writer, &state, 0);
    try write(&writer, &state, 0xabcdef);
    try end(&writer, state);
    try std.testing.expectEqualStrings(
        "[\n  \"0x0\",\n  \"0xabcdef\"\n]",
        writer.buffered(),
    );
}

test "felt JSON writes an empty list as serde_json does" {
    var storage: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const state = State{};
    try begin(&writer);
    try end(&writer, state);
    try std.testing.expectEqualStrings("[]", writer.buffered());
}

test "cairo serialize: primitive encodings follow stwo-cairo-serialize" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u64) = .empty;
    defer list.deinit(allocator);
    var writer: FeltWriter(FeltList) = .{ .sink = .{ .list = &list, .allocator = allocator } };

    var hash: Blake2sHash = undefined;
    for (&hash, 0..) |*byte, index| byte.* = @intCast(index);
    try writer.blake2sHash(&hash);
    try writer.friConfig(.{ .pow_bits = 26, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 4 });
    try writer.some();
    try writer.qm31(QM31.fromU32Unchecked(1, 2, 3, 4));
    try writer.none();
    try writer.linePoly(&.{ QM31.fromU32Unchecked(5, 6, 7, 8), QM31.fromU32Unchecked(9, 10, 11, 12) });

    try std.testing.expectEqualSlices(u64, &.{
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        26,         1,          0,          70,         4,          0,          1,          2,
        3,          4,          1,          2,          5,          6,          7,          8,
        9,          10,         11,         12,         1,
    }, list.items);

    var reader: FeltReader = .{ .felts = list.items };
    try std.testing.expectEqualSlices(u8, &hash, &try reader.blake2sHash());
    try std.testing.expectEqual(@as(u32, 70), (try reader.friConfig()).n_queries);
    try std.testing.expect(try reader.isSome());
    try std.testing.expect((try reader.qm31()).eql(QM31.fromU32Unchecked(1, 2, 3, 4)));
    try std.testing.expect(!try reader.isSome());
    const coeffs = try reader.linePoly(allocator);
    defer allocator.free(coeffs);
    try std.testing.expectEqual(@as(usize, 2), coeffs.len);
    try std.testing.expectEqual(@as(usize, 0), reader.remaining());
    try std.testing.expectError(error.EndOfStream, reader.felt());
}

test "cairo serialize: decoding rejects malformed values" {
    const allocator = std.testing.allocator;
    var reader: FeltReader = .{ .felts = &.{ 1 << 32, m31_modulus, 2, 3, 0, 1 } };
    try std.testing.expectError(error.ValueOutOfRange, reader.u32());
    try std.testing.expectError(error.ValueOutOfRange, reader.m31());
    try std.testing.expectError(error.InvalidDiscriminant, reader.isSome());
    // A two-element length with one felt left cannot be satisfied.
    reader = .{ .felts = &.{ 2, 0 } };
    try std.testing.expectError(error.ValueOutOfRange, reader.length());
    // One coefficient claimed as log size 1.
    reader = .{ .felts = &.{ 1, 0, 0, 0, 0, 1 } };
    try std.testing.expectError(error.InvalidLinePoly, reader.linePoly(allocator));

    var list: std.ArrayList(u64) = .empty;
    defer list.deinit(allocator);
    var writer: FeltWriter(FeltList) = .{ .sink = .{ .list = &list, .allocator = allocator } };
    try std.testing.expectError(error.InvalidLinePoly, writer.linePoly(&.{ QM31.zero(), QM31.zero(), QM31.zero() }));
}

test "cairo serialize: felt JSON round-trips and rejects non-canonical text" {
    const allocator = std.testing.allocator;
    const text = "[\n  \"0x0\",\n  \"0xffffffffffffffff\",\n  \"0x5b4dea27\"\n]";
    const felts = try parseFeltJson(allocator, text);
    defer allocator.free(felts);
    try std.testing.expectEqualSlices(u64, &.{ 0, std.math.maxInt(u64), 0x5b4dea27 }, felts);

    var storage: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&storage);
    var writer = try FeltJsonWriter.begin(&out);
    for (felts) |value| try writer.felt(value);
    try writer.end();
    try std.testing.expectEqualStrings(text, out.buffered());

    try std.testing.expectError(error.NonCanonicalFelt, parseFeltJson(allocator, "[\"0x01\"]"));
    try std.testing.expectError(error.NonCanonicalFelt, parseFeltJson(allocator, "[\"0xA\"]"));
    try std.testing.expectError(error.NonCanonicalFelt, parseFeltJson(allocator, "[\"10\"]"));
    try std.testing.expectError(error.ValueOutOfRange, parseFeltJson(allocator, "[\"0x10000000000000000\"]"));
    try std.testing.expectError(error.InvalidFeltJson, parseFeltJson(allocator, "[1]"));
}

fn m31s(comptime values: anytype) [values.len]M31 {
    var out: [values.len]M31 = undefined;
    inline for (values, 0..) |value, index| out[index] = M31.fromCanonical(value);
    return out;
}

test "felt stream: sort and transpose follows cairo-air utils" {
    const allocator = std.testing.allocator;
    // Two queries per column.
    const pp = [_][]const M31{ &m31s(.{ 1, 2 }), &m31s(.{ 3, 4 }) };
    const trace = [_][]const M31{ &m31s(.{ 10, 11 }), &m31s(.{ 20, 21 }), &m31s(.{ 30, 31 }) };
    const interaction = [_][]const M31{ &m31s(.{ 40, 41 }), &m31s(.{ 50, 51 }) };
    const composition = [_][]const M31{&m31s(.{ 60, 61 })};
    // Trace sizes 5, 3, 5: the stable sort puts column 1 first and keeps 0
    // before 2. Interaction sizes 4, 4 keep their order.
    const result = try sortAndTransposeQueriedValues(
        allocator,
        .{ &pp, &trace, &interaction, &composition },
        &.{ 5, 3, 5 },
        &.{ 4, 4 },
    );
    defer for (result) |tree| allocator.free(tree);
    const expected = [n_queried_trees][]const M31{
        &m31s(.{ 1, 3, 2, 4 }),
        &m31s(.{ 20, 10, 30, 21, 11, 31 }),
        &m31s(.{ 40, 50, 41, 51 }),
        &m31s(.{ 60, 61 }),
    };
    for (expected, result) |want, got| {
        try std.testing.expectEqual(want.len, got.len);
        for (want, got) |a, b| try std.testing.expectEqual(a.v, b.v);
    }
    try std.testing.expectError(error.ShapeMismatch, sortAndTransposeQueriedValues(
        allocator,
        .{ &pp, &trace, &interaction, &composition },
        &.{ 5, 3 },
        &.{ 4, 4 },
    ));
}
