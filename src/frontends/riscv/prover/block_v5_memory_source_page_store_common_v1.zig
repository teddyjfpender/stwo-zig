//! Shared typed source-page owner kernel. The schema independently selects
//! exact census/grammar/codec; no shape relabeling or proof authority is added.
const std = @import("std");
const core = @import("stwo_core");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Bounded durable private-page proposal. Selected operand/bit bytes are NOT authority;
        //! replay must recommit actual fixed/main trees and match original root pins.
        const M = core.fields.m31.M31;
        const First = Schema.Protocol;
        const Columns = Schema.Columns;
        const Source = Schema.Source;

        const HEADER_BYTES = 64;
        const BUFFER_BYTES = 4096;
        const MAGIC = Schema.FILE_MAGIC;
        const Hash = std.crypto.hash.sha2.Sha256;
        const CompactReader = struct {
            buffer: [BUFFER_BYTES]u8 = undefined,
            at: usize = 0,
            end: usize = 0,
            remaining: u64,
            fn take(self: *@This(), file: *std.fs.File, hash: *Hash, out: []u8) !void {
                var copied: usize = 0;
                while (copied < out.len) {
                    if (self.at == self.end) {
                        const n: usize = @intCast(@min(BUFFER_BYTES, self.remaining));
                        if (n == 0 or try file.readAll(self.buffer[0..n]) != n) return error.InvalidMemorySourcePageLength;
                        hash.update(self.buffer[0..n]);
                        self.remaining -= n;
                        self.at = 0;
                        self.end = n;
                    }
                    const n: usize = @min(out.len - copied, self.end - self.at);
                    @memcpy(out[copied..][0..n], self.buffer[self.at..][0..n]);
                    self.at += n;
                    copied += n;
                }
            }
        };
        pub const Pin = struct { bytes: u64, sha256: [32]u8 };
        pub const Limits = struct { max_file_bytes: u64 = 2 << 20, max_loaded_cells: usize = 1 << 24 };
        fn nameCheck(name: []const u8) !void {
            if (name.len == 0 or name.len > 96 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or std.mem.indexOfAny(u8, name, "/\\\x00") != null) return error.InvalidMemorySourcePageName;
        }
        fn geometry(plan: First.Plan, expected: First.Pin, admitted: ?*const Source.Admitted, limits: Limits) !struct { rows: usize, bytes_per_column: usize, bytes: u64 } {
            try expected.require(plan);
            const rows = @as(usize, 1) << @intCast(expected.page.row_log);
            if (try std.math.mul(usize, rows, First.MAIN_COUNT + First.FIXED_COUNT) > limits.max_loaded_cells) return error.MemorySourcePageResourceLimit;
            const width = (rows + 7) / 8;
            const bytes = if (@hasDecl(Schema, "CompactCodec")) compact: {
                const source = admitted orelse return error.InvalidMemorySourcePage;
                try source.require();
                if (!std.meta.eql(source.identity, plan.admission_id)) return error.InvalidSourceFirstPlan;
                var total: u64 = HEADER_BYTES;
                for (0..expected.page.chunks) |logical| {
                    const kind = try Schema.Stream.kindAt(source, expected.page.first_chunk + logical);
                    total = try std.math.add(u64, total, try Schema.CompactCodec.size(kind));
                }
                break :compact total;
            } else try std.math.add(u64, HEADER_BYTES, try std.math.mul(u64, width, First.MAIN_COUNT));
            if (bytes > limits.max_file_bytes) return error.MemorySourcePageResourceLimit;
            return .{ .rows = rows, .bytes_per_column = width, .bytes = bytes };
        }
        fn header(plan: First.Plan, expected: First.Pin) ![HEADER_BYTES]u8 {
            var raw: [HEADER_BYTES]u8 = undefined;
            @memcpy(raw[0..8], MAGIC);
            std.mem.writeInt(u32, raw[8..12], Schema.FILE_VERSION, .little);
            std.mem.writeInt(u32, raw[12..16], expected.page.row_log, .little);
            std.mem.writeInt(u32, raw[16..20], expected.page.index, .little);
            std.mem.writeInt(u32, raw[20..24], expected.page.chunks, .little);
            std.mem.writeInt(u64, raw[24..32], expected.page.first_chunk, .little);
            @memcpy(raw[32..64], &(try expected.identity(plan)));
            return raw;
        }
        /// One original private page in memory; constant4KiB encoding buffer. Publication
        /// is synced and exclusive, with no silent replacement or partial-success pin.
        pub fn write(dir: std.fs.Dir, name: []const u8, plan: First.Plan, expected: First.Pin, columns: *const Columns.Columns, limits: Limits) !Pin {
            try nameCheck(name);
            const size = try geometry(plan, expected, if (@hasDecl(Schema, "CompactCodec")) &columns.compact_admission else null, limits);
            if (!std.meta.eql(columns.page, expected.page) or columns.written != expected.page.chunks) return error.InvalidMemorySourcePage;
            var path: [128]u8 = undefined;
            const temporary = try std.fmt.bufPrint(&path, "{s}.part", .{name});
            var file = try dir.createFile(temporary, .{ .exclusive = true });
            var closed = false;
            defer if (!closed) file.close();
            defer dir.deleteFile(temporary) catch {};
            const raw_header = try header(plan, expected);
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            try file.writeAll(&raw_header);
            hash.update(&raw_header);
            if (@hasDecl(Schema, "CompactCodec")) {
                var buffer: [BUFFER_BYTES]u8 = undefined;
                var used: usize = 0;
                for (0..expected.page.chunks) |logical| {
                    const kind = try Schema.Stream.kindAt(&columns.compact_admission, expected.page.first_chunk + logical);
                    const n = try Schema.CompactCodec.size(kind);
                    if (n > buffer.len - used) {
                        try file.writeAll(buffer[0..used]);
                        hash.update(buffer[0..used]);
                        used = 0;
                    }
                    try Schema.CompactCodec.encode(kind, try columns.witness(@intCast(logical)), buffer[used..][0..n]);
                    used += n;
                }
                if (used != 0) {
                    try file.writeAll(buffer[0..used]);
                    hash.update(buffer[0..used]);
                }
                // Omitted rows are still exact zero private main cells; never drop
                // a noncanonical padding witness while shrinking the durable file.
                for (0..First.MAIN_COUNT) |column| for (columns.mainColumn(column), 0..) |value, row| {
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, expected.page.row_log), expected.page.row_log);
                    if (logical >= expected.page.chunks and !value.isZero()) return error.NonCanonicalMemorySourcePageTail;
                };
            } else {
                var buffer: [BUFFER_BYTES]u8 = undefined;
                for (0..First.MAIN_COUNT) |column| {
                    var offset: usize = 0;
                    while (offset < size.bytes_per_column) {
                        const n: usize = @min(buffer.len, size.bytes_per_column - offset);
                        @memset(buffer[0..n], 0);
                        for (0..n) |byte| for (0..8) |bit| {
                            const row = 8 * (offset + byte) + bit;
                            if (row >= size.rows) continue;
                            const value = columns.mainColumn(column)[row].toU32();
                            if (value > 1) return error.InvalidSourcePrivateBit;
                            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, expected.page.row_log), expected.page.row_log);
                            if (logical >= expected.page.chunks and value != 0) return error.NonCanonicalMemorySourcePageTail;
                            buffer[byte] |= @as(u8, @intCast(value)) << @intCast(bit);
                        };
                        try file.writeAll(buffer[0..n]);
                        hash.update(buffer[0..n]);
                        offset += n;
                    }
                }
            }
            if ((try file.stat()).size != size.bytes) return error.InvalidMemorySourcePageLength;
            try file.sync();
            file.close();
            closed = true;
            std.posix.linkat(dir.fd, temporary, dir.fd, name, 0) catch |err| switch (err) {
                error.PathAlreadyExists => return error.ExistingMemorySourcePage,
                else => return err,
            };
            errdefer dir.deleteFile(name) catch {};
            try std.posix.fsync(dir.fd);
            return .{ .bytes = size.bytes, .sha256 = hash.finalResult() };
        }
        /// Scope/logs/root expectation come from independent first-pass pins. Header and
        /// file hash supply integrity only. Loaded cells remain a private proposal.
        pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Source.Admitted, plan: First.Plan, expected: First.Pin, pin: Pin, first_limits: First.Limits, limits: Limits) !Columns.Columns {
            try nameCheck(name);
            try plan.require(admitted, first_limits);
            const size = try geometry(plan, expected, admitted, limits);
            if (pin.bytes != size.bytes) return error.InvalidMemorySourcePageLength;
            var file = try dir.openFile(name, .{});
            defer file.close();
            if ((try file.stat()).size != pin.bytes) return error.InvalidMemorySourcePageLength;
            var received_header: [HEADER_BYTES]u8 = undefined;
            if (try file.readAll(&received_header) != HEADER_BYTES or !std.meta.eql(received_header, try header(plan, expected))) return error.UntrustedMemorySourcePageHeader;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(&received_header);
            var columns = try Columns.Columns.init(a, admitted, plan, expected.page, first_limits);
            errdefer columns.deinit();
            if (@hasDecl(Schema, "CompactCodec")) {
                var operand: [Schema.CompactCodec.MAX_BYTES]u8 = undefined;
                var reader = CompactReader{ .remaining = size.bytes - HEADER_BYTES };
                for (0..expected.page.chunks) |logical| {
                    const kind = try Schema.Stream.kindAt(admitted, expected.page.first_chunk + logical);
                    const n = try Schema.CompactCodec.size(kind);
                    try reader.take(&file, &hash, operand[0..n]);
                    try columns.append(admitted, .{ .kind = kind, .witness = try Schema.CompactCodec.decode(kind, operand[0..n]) });
                }
                if (reader.remaining != 0 or reader.at != reader.end) return error.InvalidMemorySourcePageLength;
            } else {
                var buffer: [BUFFER_BYTES]u8 = undefined;
                for (0..First.MAIN_COUNT) |column| {
                    var offset: usize = 0;
                    while (offset < size.bytes_per_column) {
                        const n: usize = @min(buffer.len, size.bytes_per_column - offset);
                        if (try file.readAll(buffer[0..n]) != n) return error.InvalidMemorySourcePageLength;
                        hash.update(buffer[0..n]);
                        for (0..n) |byte| for (0..8) |bit| {
                            const row = 8 * (offset + byte) + bit;
                            const value = (buffer[byte] >> @intCast(bit)) & 1;
                            if (row >= size.rows) {
                                if (value != 0) return error.NonCanonicalMemorySourcePageTail;
                                continue;
                            }
                            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, expected.page.row_log), expected.page.row_log);
                            if (logical >= expected.page.chunks and value != 0) return error.NonCanonicalMemorySourcePageTail;
                            columns.main[column * size.rows + row] = M.fromCanonical(value);
                        };
                        offset += n;
                    }
                }
            }
            var tail: [1]u8 = undefined;
            if (try file.read(&tail) != 0 or !std.meta.eql(hash.finalResult(), pin.sha256)) return error.UntrustedMemorySourcePageHash;
            columns.written = expected.page.chunks;
            return columns;
        }
    };
}
