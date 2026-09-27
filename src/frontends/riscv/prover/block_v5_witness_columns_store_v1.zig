//! Bounded proposal storage for witness-once execution. This codec has no proof
//! authority. Callers independently pin scope/logs/SHA and MUST recommit the
//! loaded main columns and compare both original first-round roots before use.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const Hash = std.crypto.hash.sha2.Sha256;
pub const VERSION: u32 = 1;
const MAGIC = "B5WCOL01";
const HEADER_BYTES = 140;
const BUFFER_BYTES = 16 * 1024;

pub const Kind = enum(u32) { native = 1, caller = 2 };
pub const Scope = struct {
    kind: Kind,
    execution_index: u32,
    first_cycle: u64,
    cycle_count: u32,
    /// Independently recomputed native/caller semantic descriptor identity.
    descriptor_digest: [32]u8,
    /// Original fixed/main commitments, not file-derived expected values.
    first_roots: [2][32]u8,
};
pub const Pin = struct { bytes: u64, sha256: [32]u8 };
pub const Limits = struct {
    max_columns: usize,
    max_log_size: u32,
    max_file_bytes: u64,
    max_loaded_bytes: usize,
};
pub const Owned = struct {
    a: std.mem.Allocator,
    columns: []Column,
    pub fn deinit(self: *Owned) void {
        for (self.columns) |column| self.a.free(column.values);
        self.a.free(self.columns);
        self.* = undefined;
    }
};
/// Streaming destination for alternate owned witness layouts. Values are a
/// short-lived canonical chunk; consumers must copy them before returning.
pub const Consumer = struct {
    context: *anyopaque,
    put: *const fn (*anyopaque, usize, usize, []const M) anyerror!void,
};
pub const Provider = struct {
    context: *const anyopaque,
    get: *const fn (*const anyopaque, usize, usize, []M) anyerror!void,
};

fn requireName(name: []const u8) !void {
    if (name.len == 0 or name.len > 200 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
        std.mem.indexOfAny(u8, name, "/\\\x00") != null) return error.InvalidV5WitnessFileName;
}
fn rows(log: u32, limits: Limits) !usize {
    if (log > limits.max_log_size or log > 30) return error.V5WitnessColumnLimit;
    return @as(usize, 1) << @intCast(log);
}
fn geometry(logs: []const u32, limits: Limits) !struct { cells: u64, bytes: u64 } {
    if (logs.len > limits.max_columns or logs.len > std.math.maxInt(u32)) return error.V5WitnessColumnLimit;
    var cells: u64 = 0;
    for (logs) |log| cells = try std.math.add(u64, cells, try rows(log, limits));
    const bytes = try std.math.add(u64, HEADER_BYTES, try std.math.add(u64,
        try std.math.mul(u64, logs.len, 12), try std.math.mul(u64, cells, 4)));
    const loaded = try std.math.add(u64, try std.math.mul(u64, logs.len, @sizeOf(Column)), try std.math.mul(u64, cells, @sizeOf(M)));
    if (bytes > limits.max_file_bytes or loaded > limits.max_loaded_bytes) return error.V5WitnessColumnLimit;
    return .{ .cells = cells, .bytes = bytes };
}
fn header(scope: Scope, count: u32, cells: u64) ![HEADER_BYTES]u8 {
    if (scope.first_cycle == 0 or scope.cycle_count == 0) return error.InvalidV5WitnessScope;
    _ = try std.math.add(u64, scope.first_cycle, scope.cycle_count - 1);
    var raw: [HEADER_BYTES]u8 = undefined;
    @memcpy(raw[0..8], MAGIC);
    std.mem.writeInt(u32, raw[8..12], VERSION, .little);
    std.mem.writeInt(u32, raw[12..16], @intFromEnum(scope.kind), .little);
    std.mem.writeInt(u32, raw[16..20], scope.execution_index, .little);
    std.mem.writeInt(u32, raw[20..24], scope.cycle_count, .little);
    std.mem.writeInt(u64, raw[24..32], scope.first_cycle, .little);
    @memcpy(raw[32..64], &scope.descriptor_digest);
    @memcpy(raw[64..96], &scope.first_roots[0]);
    @memcpy(raw[96..128], &scope.first_roots[1]);
    std.mem.writeInt(u32, raw[128..132], count, .little);
    std.mem.writeInt(u64, raw[132..140], cells, .little);
    return raw;
}

const Writer = struct {
    file: std.fs.File,
    hash: Hash = .init(.{}),
    buffer: [BUFFER_BYTES]u8 = undefined,
    used: usize = 0,
    fn append(self: *Writer, data: []const u8) !void {
        var rest = data;
        while (rest.len != 0) {
            const n: usize = @min(rest.len, self.buffer.len - self.used);
            @memcpy(self.buffer[self.used..][0..n], rest[0..n]);
            self.used += n;
            rest = rest[n..];
            if (self.used == self.buffer.len) try self.flush();
        }
    }
    fn flush(self: *Writer) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.hash.update(self.buffer[0..self.used]);
        self.used = 0;
    }
};

/// Writes one ordered native or complete caller main tree. Empty main trees
/// are allowed only as data proposals; no empty STARK or receipt is fabricated.
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, scope: Scope, columns: []const Column, limits: Limits) !Pin {
    try requireName(name);
    if (columns.len > limits.max_columns) return error.V5WitnessColumnLimit;
    const logs = try a.alloc(u32, columns.len);
    defer a.free(logs);
    for (columns, logs) |column, *log| {
        log.* = column.log_size;
        if (column.values.len != try rows(log.*, limits)) return error.InvalidV5WitnessColumnLength;
    }
    const Source = struct {
        columns: []const Column,
        fn get(raw: *const anyopaque, column: usize, offset: usize, out: []M) !void {
            const self: *const @This() = @ptrCast(@alignCast(raw));
            if (column >= self.columns.len or offset > self.columns[column].values.len or out.len > self.columns[column].values.len - offset)
                return error.InvalidV5WitnessDestination;
            @memcpy(out, self.columns[column].values[offset..][0..out.len]);
        }
    };
    const source = Source{ .columns = columns };
    return writeMapped(a, dir, name, scope, logs, limits, .{ .context = &source, .get = Source.get });
}

/// Project typed row-backed witnesses directly into the canonical column file
/// without allocating a second complete column-major matrix.
pub fn writeMapped(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, scope: Scope, logs: []const u32, limits: Limits, provider: Provider) !Pin {
    try requireName(name);
    const size = try geometry(logs, limits);
    const raw_header = try header(scope, @intCast(logs.len), size.cells);
    const temporary = try std.fmt.allocPrint(a, ".{s}.partial", .{name});
    defer a.free(temporary);
    const file = try dir.createFile(temporary, .{ .exclusive = true });
    defer file.close();
    var committed = false;
    defer if (!committed) dir.deleteFile(temporary) catch {};
    var writer = Writer{ .file = file };
    try writer.append(&raw_header);
    var decoded: [BUFFER_BYTES / 4]M = undefined;
    var encoded: [BUFFER_BYTES]u8 = undefined;
    for (logs, 0..) |log, column| {
        const count = try rows(log, limits);
        var descriptor: [12]u8 = undefined;
        std.mem.writeInt(u32, descriptor[0..4], log, .little);
        std.mem.writeInt(u64, descriptor[4..12], count, .little);
        try writer.append(&descriptor);
        var offset: usize = 0;
        while (offset < count) {
            // @min with a comptime bound may infer a narrow integer. Byte
            // spans must stay usize before multiplying the 4096-cell chunk.
            const n: usize = @min(count - offset, decoded.len);
            try provider.get(provider.context, column, offset, decoded[0..n]);
            for (decoded[0..n], 0..) |value, index| {
                const integer = value.toU32();
                if (integer >= core.fields.m31.Modulus) return error.NonCanonicalV5WitnessM31;
                std.mem.writeInt(u32, encoded[index * 4 ..][0..4], integer, .little);
            }
            try writer.append(encoded[0 .. n * 4]);
            offset += n;
        }
    }
    try writer.flush();
    if ((try file.stat()).size != size.bytes) return error.InvalidV5WitnessFileLength;
    try file.sync();
    var sha256: [32]u8 = undefined;
    writer.hash.final(&sha256);
    // Never silently replace an existing completed source proposal.
    if (dir.openFile(name, .{})) |existing| {
        existing.close();
        return error.V5WitnessFileAlreadyExists;
    } else |err| if (err != error.FileNotFound) return err;
    try dir.rename(temporary, name);
    committed = true;
    return .{ .bytes = size.bytes, .sha256 = sha256 };
}

/// One file/one segment in memory. All allocations and partial reads unwind on
/// failure. Expected scope, ordered logs, length and SHA come from the caller's
/// pinned first-pass manifest; file headers never supply admission authority.
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, scope: Scope, logs: []const u32, pin: Pin, limits: Limits) !Owned {
    _ = try geometry(logs, limits);
    const columns = try a.alloc(Column, logs.len);
    var completed: usize = 0;
    errdefer {
        for (columns[0..completed]) |column| a.free(column.values);
        a.free(columns);
    }
    for (logs, columns) |log, *column| {
        column.* = .{ .log_size = log, .values = try a.alloc(M, try rows(log, limits)) };
        completed += 1;
    }
    const Destination = struct {
        columns: []Column,
        fn put(raw: *anyopaque, column: usize, offset: usize, values: []const M) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (column >= self.columns.len or offset > self.columns[column].values.len or values.len > self.columns[column].values.len - offset)
                return error.InvalidV5WitnessDestination;
            // These buffers are allocated immediately above, not borrowed PCS
            // columns. ColumnEvaluation exposes their immutable public view.
            @memcpy(@constCast(self.columns[column].values)[offset..][0..values.len], values);
        }
    };
    var destination = Destination{ .columns = columns };
    try readMapped(dir, name, scope, logs, pin, limits, .{ .context = &destination, .put = Destination.put });
    return .{ .a = a, .columns = columns };
}

/// Reads directly into the caller's reconstructed owned row/matrix layout;
/// avoids retaining a second column-major copy of the complete caller witness.
/// A consumer may only publish its owner after this final SHA check succeeds.
pub fn readMapped(dir: std.fs.Dir, name: []const u8, scope: Scope, logs: []const u32, pin: Pin, limits: Limits, consumer: Consumer) !void {
    try requireName(name);
    const size = try geometry(logs, limits);
    if (pin.bytes != size.bytes) return error.InvalidV5WitnessFileLength;
    var file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.bytes) return error.InvalidV5WitnessFileLength;
    var hash = Hash.init(.{});
    var raw_header: [HEADER_BYTES]u8 = undefined;
    try readExact(&file, &hash, &raw_header);
    const expected_header = try header(scope, @intCast(logs.len), size.cells);
    if (!std.mem.eql(u8, &raw_header, &expected_header)) return error.ChangedV5WitnessScope;
    var buffer: [BUFFER_BYTES]u8 = undefined;
    var decoded: [BUFFER_BYTES / 4]M = undefined;
    for (logs, 0..) |log, column| {
        const count = try rows(log, limits);
        var descriptor: [12]u8 = undefined;
        try readExact(&file, &hash, &descriptor);
        if (std.mem.readInt(u32, descriptor[0..4], .little) != log or std.mem.readInt(u64, descriptor[4..12], .little) != count)
            return error.ChangedV5WitnessColumnGeometry;
        var offset: usize = 0;
        while (offset < count) {
            const n: usize = @min(count - offset, buffer.len / 4);
            try readExact(&file, &hash, buffer[0 .. n * 4]);
            for (decoded[0..n], 0..) |*value, index| {
                const integer = std.mem.readInt(u32, buffer[index * 4 ..][0..4], .little);
                if (integer >= core.fields.m31.Modulus) return error.NonCanonicalV5WitnessM31;
                value.* = M.fromCanonical(integer);
            }
            try consumer.put(consumer.context, column, offset, decoded[0..n]);
            offset += n;
        }
    }
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.InvalidV5WitnessFileLength;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    if (!std.meta.eql(digest, pin.sha256)) return error.TamperedV5WitnessFile;
}
fn readExact(file: *std.fs.File, hash: *Hash, raw: []u8) !void {
    if (try file.readAll(raw) != raw.len) return error.TruncatedV5WitnessFile;
    hash.update(raw);
}
