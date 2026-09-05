//! `recursive-pipeline-worker-v1` persistent JSONL process.

const std = @import("std");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const mock = @import("recursive_pipeline_worker_mock_v1.zig");
const native_omitted = @import(
    "recursive_pipeline_worker_native_omitted_leaf_v1.zig",
);

const Options = struct {
    store_root: []const u8,
    adapter: []const u8,
};

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = try parseArgs(allocator, args);
    defer allocator.free(options.store_root);
    if (std.mem.eql(u8, options.adapter, mock.adapter_name)) {
        return runAdapter(mock.Adapter, allocator, options.store_root);
    }
    if (std.mem.eql(u8, options.adapter, native_omitted.adapter_name)) {
        return runAdapter(
            native_omitted.Adapter,
            allocator,
            options.store_root,
        );
    }
    return error.UnsupportedRecursivePipelineAdapter;
}

/// Shared framed loop for a statically selected typed adapter. Exporting the
/// loop does not add a CLI route; a campaign command must first install its
/// process-local authority/policy session and still obey `Adapter.available`.
pub fn runAdapter(
    comptime Adapter: type,
    allocator: std.mem.Allocator,
    store_root: []const u8,
) !void {
    var worker = try worker_mod.Worker(Adapter).init(allocator, store_root);
    defer worker.deinit();
    const input_buffer = try allocator.alloc(u8, protocol.max_frame_bytes);
    defer allocator.free(input_buffer);
    var input = std.fs.File.stdin().reader(input_buffer);
    var output_buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&output_buffer);
    const writer = &output.interface;
    var next_sequence: u64 = 0;
    while (try input.interface.takeDelimiter('\n')) |line| {
        var request_arena = std.heap.ArenaAllocator.init(allocator);
        defer request_arena.deinit();
        const request_allocator = request_arena.allocator();
        var parsed = try protocol.parseRequest(
            request_allocator,
            line,
            next_sequence,
        );
        defer parsed.deinit();
        const request = parsed.request;
        const payload = worker.handle(request_allocator, request) catch |err| {
            const context = worker.failureContext();
            if (context.ref) |ref| {
                const digest = std.fmt.bytesToHex(ref.sha256, .lower);
                std.debug.print(
                    "recursive-pipeline-worker phase={s} kind={} format={} schema={} bytes={} sha256={s} cause={s}\n",
                    .{
                        context.phase,
                        @intFromEnum(ref.kind),
                        ref.format_version,
                        ref.schema_version,
                        ref.byte_count,
                        digest,
                        @errorName(err),
                    },
                );
            } else {
                std.debug.print(
                    "recursive-pipeline-worker phase={s} cause={s}\n",
                    .{ context.phase, @errorName(err) },
                );
            }
            try protocol.writeResponse(
                request_allocator,
                writer,
                request.sequence,
                request.action,
                "error",
                try protocol.errorPayload(request_allocator, err),
            );
            next_sequence +%= 1;
            continue;
        };
        try protocol.writeResponse(
            request_allocator,
            writer,
            request.sequence,
            request.action,
            "ok",
            payload,
        );
        next_sequence +%= 1;
        if (request.action == .shutdown) return;
    }
    return error.UncleanRecursiveWorkerEndOfStream;
}

fn parseArgs(
    allocator: std.mem.Allocator,
    args: []const []const u8,
) !Options {
    var store_root: ?[]u8 = null;
    errdefer if (store_root) |value| allocator.free(value);
    var adapter: ?[]const u8 = null;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--store-root")) {
            index += 1;
            if (index >= args.len or store_root != null)
                return error.InvalidRecursiveWorkerArguments;
            store_root = try std.fs.realpathAlloc(allocator, args[index]);
        } else if (std.mem.eql(u8, argument, "--object-root")) {
            index += 1;
            if (index >= args.len or store_root != null)
                return error.InvalidRecursiveWorkerArguments;
            const object_root = try std.fs.realpathAlloc(allocator, args[index]);
            defer allocator.free(object_root);
            if (!std.mem.eql(
                u8,
                std.fs.path.basename(object_root),
                "sha256",
            )) return error.InvalidRecursiveWorkerArguments;
            const objects = std.fs.path.dirname(object_root) orelse
                return error.InvalidRecursiveWorkerArguments;
            if (!std.mem.eql(u8, std.fs.path.basename(objects), "objects"))
                return error.InvalidRecursiveWorkerArguments;
            const root = std.fs.path.dirname(objects) orelse
                return error.InvalidRecursiveWorkerArguments;
            store_root = try allocator.dupe(u8, root);
        } else if (std.mem.eql(u8, argument, "--adapter")) {
            index += 1;
            if (index >= args.len or adapter != null)
                return error.InvalidRecursiveWorkerArguments;
            adapter = args[index];
        } else {
            return error.InvalidRecursiveWorkerArguments;
        }
    }
    return .{
        .store_root = store_root orelse
            return error.MissingRecursiveWorkerStoreRoot,
        .adapter = adapter orelse
            return error.MissingRecursiveWorkerAdapter,
    };
}
