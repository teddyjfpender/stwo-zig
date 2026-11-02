//! Internal v3 parking integrity. Fixed byte chunks, independently framed leaves
//! and an ordered root; no proof transcript or second payload buffer.
const std = @import("std");
const Work = @import("stwo_prover_engine").lookups.row_work;
const Blake = std.crypto.hash.blake2.Blake2s256;
pub const CHUNK_BYTES: usize = 4 << 20;
pub const MAX_CHUNKS: usize = 65536;
pub const MAX_SEGMENTS: usize = 65536;
pub const Hash = [32]u8;
pub const Segment = struct { offset: usize, bytes: []const u8 };
pub fn scratchBytes(payload: usize, segments: usize) !usize {
    if (payload == 0 or segments == 0 or segments > MAX_SEGMENTS) return error.RetainedMainIntegrityShape;
    const chunks = try std.math.divCeil(usize, payload, CHUNK_BYTES);
    if (chunks > MAX_CHUNKS) return error.RetainedMainIntegrityLimit;
    return std.math.add(usize, try std.math.mul(usize, chunks, @sizeOf(Hash)), try std.math.mul(usize, segments, @sizeOf(Segment)));
}
fn framedInt(hash: *Blake, value: usize) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
fn validate(segments: []const Segment, payload: usize) !void {
    _ = try scratchBytes(payload, segments.len);
    var end: usize = 0;
    for (segments) |segment| {
        // Exact partition, not merely non-overlapping ranges. Zero-sized native
        // layers remain valid, but cannot disguise a gap or a repeated payload.
        if (segment.offset != end) return error.RetainedMainIntegrityShape;
        end = try std.math.add(usize, end, segment.bytes.len);
        if (end > payload) return error.RetainedMainIntegrityShape;
    }
    if (end != payload) return error.RetainedMainIntegrityShape;
}
/// Positioned writes and hashes read borrowed source slices until all jobs join.
/// If file=null, only hashes (used for read-only mapped restore).
pub fn digest(a: std.mem.Allocator, file: ?std.fs.File, segments: []const Segment, payload: usize) !Hash {
    return digestWithOptions(a, file, segments, payload, .{ .min_rows_per_shard = 1 });
}
pub fn digestWithOptions(a: std.mem.Allocator, file: ?std.fs.File, segments: []const Segment, payload: usize, options: Work.RangeOptions) !Hash {
    try validate(segments, payload);
    const count = try std.math.divCeil(usize, payload, CHUNK_BYTES);
    const hashes = try a.alloc(Hash, count);
    defer a.free(hashes);
    const Context = struct {
        file: ?std.fs.File,
        segments: []const Segment,
        payload: usize,
        hashes: []Hash,
        errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
        pub fn runRange(self: *@This(), ordinal: usize, begin: usize, end: usize) void {
            for (begin..end) |index| {
                const start = index * CHUNK_BYTES;
                const stop = start + @min(CHUNK_BYTES, self.payload - start);
                var hash = Blake.init(.{});
                hash.update("STWO/native-main/park-v3/chunk\x00");
                framedInt(&hash, index);
                framedInt(&hash, start);
                framedInt(&hash, stop - start);
                var consumed: usize = 0;
                for (self.segments) |segment| {
                    const segment_end = segment.offset + segment.bytes.len; // prevalidated
                    if (segment_end <= start) continue;
                    if (segment.offset >= stop) break;
                    const lo = @max(start, segment.offset);
                    const hi = @min(stop, segment_end);
                    const bytes = segment.bytes[lo - segment.offset .. hi - segment.offset];
                    if (self.file) |output_file| output_file.pwriteAll(bytes, lo) catch |err| {
                        self.errors[ordinal] = err;
                        return;
                    };
                    hash.update(bytes);
                    consumed += bytes.len;
                }
                std.debug.assert(consumed == stop - start);
                hash.final(&self.hashes[index]);
            }
        }
    };
    var context = Context{ .file = file, .segments = segments, .payload = payload, .hashes = hashes };
    const shards = Work.forEachRange(count, &context, options);
    for (context.errors[0..shards]) |maybe| if (maybe) |err| return err;
    var root = Blake.init(.{});
    root.update("STWO/native-main/park-v3/ordered-root\x00");
    framedInt(&root, payload);
    framedInt(&root, CHUNK_BYTES);
    framedInt(&root, count);
    for (hashes, 0..) |hash, i| {
        framedInt(&root, i);
        root.update(&hash);
    }
    var result: Hash = undefined;
    root.final(&result);
    return result;
}
