//! Shared fresh CPU receiver for production qualification and standalone load.
//! No producer-side native/caller/recursive receipt is accepted.
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const std = @import("std");
        const Cpu = @import("stwo_cpu_backend").CpuBackend;
        const Global = if (capacity) @import("block_v5_capacity_global_receiver_v1.zig") else @import("block_v5_global_receiver_v1.zig");
        const Metadata = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(capacity);
        const Policy = @import("block_v5_cpu_bundle_policy_v1.zig").ForCapacity(capacity);
        const Store = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(capacity);
        const Manifest = if (capacity) @import("block_v5_capacity_open_forest_manifest_v1.zig") else @import("block_v5_open_forest_manifest_v1.zig");
        const Sources = @import("block_v5_memory_source_writer_v1.zig");
        pub const Pins = struct {
            identity: Metadata.Identity,
            receiver_policy_sha256: [32]u8,
            bundle_manifest_sha256: [32]u8,
            forest_manifest_sha256: [32]u8,
        };
        pub const Limits = struct { metadata: Metadata.Limits, store: Store.Limits, forest: Manifest.Limits };
        pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, public_input: []const u8, pins: Pins, limits: Limits) !Global.VerifiedGlobals {
            const metadata = try Metadata.read(a, dir, pins.receiver_policy_sha256, pins.identity, limits.metadata);
            defer metadata.deinit();
            const globals = metadata.globals();
            const policies = try Policy.build(a, globals, limits.store);
            defer a.free(policies);
            var files = try Store.readPins(a, dir, pins.bundle_manifest_sha256, limits.store);
            defer files.deinit();
            var store = try Store.Store.initReader(a, dir, policies, files.files, pins.identity.config, limits.store);
            defer store.deinit();
            var sources: [4]std.fs.File = undefined;
            var initialized: usize = 0;
            defer for (sources[0..initialized]) |file| file.close();
            for (Sources.filenames, &sources) |name, *file| {
                file.* = try dir.openFile(name, .{});
                initialized += 1;
            }
            var complete = try Global.ForBackend(Cpu).verifyCompleteDetached(a, globals, .{ .public_input = public_input, .endpoint_sources = .{ .initial = .{ .input_words = sources[0], .rw_words = sources[1], .first_touches = sources[2] }, .endpoints = sources[3] }, .memory = store.packedMemoryLoader(), .execution_memory = store.executionMemoryLoader(), .tables = store.tableLoader(), .programs = store.programLoader() }, metadata.recursion(), .{ .dir = dir, .manifest_sha256 = pins.forest_manifest_sha256, .limits = limits.forest });
            defer complete.deinit();
            try store.requireConsumed();
            return complete.globals;
        }
    };
}
