//! Stateless bounded source operand reader. Files/input provide private
//! witness bytes; original PAGE SHA/record/root equations grant authority.
const std = @import("std");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
pub const Reader = struct {
    source: Source.Admitted,
    files: Endpoint.Sources,
    /// Borrowed only during synchronous count/collection, never retained by Job.
    public_input: []const u8,
    pub fn init(source: Source.Admitted, files: Endpoint.Sources, input: []const u8) !Reader {
        try source.require();
        if (input.len != source.byteLength(.public_input)) return error.InvalidSourcePageReaderLength;
        const self = Reader{ .source = source, .files = files, .public_input = input };
        inline for (.{ Source.Stream.input_words, .rw_words, .first_touches, .endpoints }) |stream| {
            if (try self.file(stream).getEndPos() != source.byteLength(stream)) return error.InvalidSourcePageReaderLength;
        }
        return self;
    }
    fn file(self: *const Reader, stream: Source.Stream) std.fs.File {
        return switch (stream) {
            .input_words => self.files.initial.input_words,
            .rw_words => self.files.initial.rw_words,
            .first_touches => self.files.initial.first_touches,
            .endpoints => self.files.endpoints,
            .public_input => unreachable,
        };
    }
    pub fn provider(self: *Reader) Fold.Reader {
        return .{ .context = self, .read = read };
    }
    fn read(raw: *anyopaque, stream: Source.Stream, offset: u64, output: []u8) !void {
        const self: *Reader = @ptrCast(@alignCast(raw));
        const end = try std.math.add(u64, offset, output.len);
        if (end > self.source.byteLength(stream)) return error.InvalidSourcePageReaderOffset;
        if (stream == .public_input) {
            @memcpy(output, self.public_input[@intCast(offset)..@intCast(end)]);
        } else if (try self.file(stream).preadAll(output, offset) != output.len) return error.TruncatedSourcePageReader;
    }
};
