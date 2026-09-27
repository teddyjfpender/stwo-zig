//! Actual durable PUBLIC owner publication adapter. It delegates one genuine
//! proof/fresh check to the original new export stage; metadata never admits it.
const std = @import("std");
const File = @import("block_v5_global_expected_public_file_v1.zig");
const Job = @import("../recursion/block_v5_global_expected_public_job_v1.zig");
const Norm = @import("../recursion/block_v5_global_public_export_normalizer_v1.zig");
const Base = @import("block_v5_global_public_export_stage_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_global_public_export_protocol_v1.zig");
const Rows = @import("../recursion/block_v5_global_public_export_parent_v1.zig");
pub const Session = struct {
    owner: *File.Owned,
    pub fn open(a: std.mem.Allocator, dir: std.fs.Dir, independently_expected: Job.Expected, limits: File.Limits) !Session {
        const pin = try File.write(a, dir, independently_expected, limits);
        return .{ .owner = try File.read(a, dir, pin, independently_expected, limits) };
    }
    pub fn reopen(a: std.mem.Allocator, dir: std.fs.Dir, pin: File.Pin, independently_expected: Job.Expected, limits: File.Limits) !Session {
        return .{ .owner = try File.read(a, dir, pin, independently_expected, limits) };
    }
    pub fn deinit(self: *Session) void {
        self.owner.deinit();
        self.* = undefined;
    }
};
pub const Artifact = struct {
    base: Base.Artifact,
    normalized: Norm.Normalized,
    expected: *File.Owned,
    normalization_source: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        self.base.deinit(a);
        self.normalized.deinit();
        self.expected.deinit();
        self.* = undefined;
    }
};
pub const Sink = struct { context: *anyopaque, put_open: *const fn (*anyopaque, *Artifact) anyerror!void };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Producer = Base.ForBackend(Backend);
        pub const Options = struct { base: Producer.Options, normalizer: Norm.Limits = .{} };
        const Publication = struct {
            allocator: std.mem.Allocator,
            rows: *Rows.Prepared,
            session: *Session,
            limits: Norm.Limits,
            sink: Sink,
            fn put(context: *anyopaque, received: *Base.Artifact) !void {
                const self: *Publication = @ptrCast(@alignCast(context));
                _ = try self.session.owner.bind(self.rows.public.policy);
                const admission = try Protocol.Admission.init(received.key, received.key_id, received.schedule, self.rows.values);
                var normalized = try Norm.normalize(self.allocator, &admission, self.limits);
                errdefer normalized.deinit();
                const owner = try self.session.owner.retain();
                errdefer owner.deinit();
                try normalized.rehomeInput(owner.expected().input_words);
                // Failure retains received under the original stage's ownership.
                // Success transfers all three owners to the consuming sink.
                var artifact = Artifact{ .base = received.*, .normalized = normalized, .expected = owner, .normalization_source = Norm.sourceAuthority() };
                try self.sink.put_open(self.sink.context, &artifact);
                received.* = undefined;
            }
        };
        pub fn publishPrepared(a: std.mem.Allocator, session: *Session, rows: *Rows.Prepared, options: Options, sink: Sink) !void {
            _ = try session.owner.bind(rows.public.policy);
            var publication = Publication{ .allocator = a, .rows = rows, .session = session, .limits = options.normalizer, .sink = sink };
            try Producer.publishPrepared(a, rows, options.base, .{ .context = &publication, .put_open = Publication.put });
        }
    };
}
