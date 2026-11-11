//! Sequential CPU requests share only source-derived immutable setup. Every
//! request still executes, proves and checks its complete native bundle. Durable
//! independent reception belongs to the external caller, never to this index.
const std = @import("std");
const Driver = @import("../../word16_execution/driver.zig");
const Profile = @import("../../word16_execution/om31_security_candidate.zig").Profile;
const Setup = @import("setup_cache.zig");
const Resources = @import("resources.zig").CandidateResources;
pub const Item = struct { name: []const u8, request: []const u8, resources: []const u8 };
pub const Manifest = struct {
    schema: []const u8,
    immutable_host_key_bytes: usize,
    repeat: usize = 2,
    requests: []const Item,
    pub fn validate(self: Manifest) !void {
        if (!std.mem.eql(u8, self.schema, "rv64-cpu-resident-inputs/v1")) return error.InvalidCpuBatchSchema;
        if (self.repeat == 0 or self.repeat > 4 or self.requests.len == 0 or self.requests.len > 32) return error.InvalidCpuBatchCount;
        if (self.immutable_host_key_bytes == 0 or self.immutable_host_key_bytes > 4 << 30) return error.InvalidCpuBatchKeyBudget;
        for (self.requests, 0..) |item, i| {
            if (item.name.len == 0 or item.name.len > 64 or item.request.len == 0 or item.resources.len == 0) return error.InvalidCpuBatchItem;
            for (item.name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return error.InvalidCpuBatchItem;
            for (self.requests[0..i]) |earlier| if (std.mem.eql(u8, item.name, earlier.name)) return error.DuplicateCpuBatchName;
        }
    }
};
const Entry = struct {
    ordinal: usize,
    repeat: usize,
    name: []const u8,
    proof_directory: []const u8,
    wall_ns: u64,
    setup_cache: ?Setup.Stats,
    immutable_key_classes: usize,
};
pub fn run(comptime Main: type, recycler: *Main.Recycler, profile: Profile, args: []const [:0]u8) !void {
    if (args.len != 4) return error.ExpectedCpuBatchManifestAndOutput;
    if (std.posix.getenv("STWO_ZIG_RV64_SETUP_CACHE")) |directory| if (directory.len != 0) return error.CpuBatchPersistedSetupForbidden;
    const a = recycler.allocator();
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 64 << 10);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Manifest, a, raw, .{});
    defer parsed.deinit();
    const manifest = parsed.value;
    try manifest.validate();
    // Reject every resource schema/budget before the first long proof request.
    for (manifest.requests) |item| {
        const bytes = try std.fs.cwd().readFileAlloc(a, item.resources, 16 << 10);
        defer a.free(bytes);
        const limits = try std.json.parseFromSlice(Resources, a, bytes, .{});
        defer limits.deinit();
        try limits.value.validate();
    }
    if (std.fs.path.dirname(args[3])) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().makeDir(args[3]); // Refuse to overwrite an earlier batch.
    // Linux can use an O_PATH descriptor for the default open options.
    // The batch index needs a directory descriptor that supports fsync.
    var directory = try std.fs.cwd().openDir(args[3], .{ .iterate = true });
    defer directory.close();
    var session = try Main.ResidentSession.init(a, manifest.immutable_host_key_bytes);
    defer session.deinit();
    const entries = try a.alloc(Entry, manifest.repeat * manifest.requests.len);
    defer a.free(entries);
    var initialized: usize = 0;
    defer for (entries[0..initialized]) |entry| a.free(entry.proof_directory);
    var timer = try std.time.Timer.start();
    for (0..manifest.repeat) |repetition| for (manifest.requests) |item| {
        const ordinal = initialized;
        const name = try std.fmt.allocPrint(a, "{d:0>6}-{s}", .{ ordinal, item.name });
        defer a.free(name);
        const output = try std.fs.path.join(a, &.{ args[3], name });
        errdefer a.free(output);
        const texts = [_][]const u8{ "rv64-native-resident", "--security-profile", profile.name(), "produce-candidate", item.request, "-", output, "0", item.resources };
        var argv: [texts.len][:0]u8 = undefined;
        var count: usize = 0;
        defer for (argv[0..count]) |text| a.free(text);
        for (texts, &argv) |text, *arg| {
            arg.* = try a.dupeZ(u8, text);
            count += 1;
        }
        const start = timer.read();
        try Main.runNativeResidentArgs(recycler, &argv, &session);
        entries[ordinal] = .{ .ordinal = ordinal, .repeat = repetition, .name = item.name, .proof_directory = output, .wall_ns = timer.read() - start, .setup_cache = session.setupStats(), .immutable_key_classes = session.keyCount() };
        initialized += 1;
        std.log.info("CPU_RESIDENT_REQUEST ordinal={d} repeat={d} name={s} wall_ns={d}", .{ ordinal, repetition, item.name, entries[ordinal].wall_ns });
    };
    try Driver.writeJson(a, directory, "index.json", .{
        .schema = "rv64-cpu-resident-batch/v1",
        .security_profile = profile.name(),
        .security_qualified = false,
        .scope = "complete native production and in-process checks; external fresh durable reception required",
        .independent_reception = false,
        .persisted_setup_allowed = false,
        .immutable_host_key_bytes = manifest.immutable_host_key_bytes,
        .budget_scope = "component/cache admission; not a process RSS limit",
        .total_ns = timer.read(),
        .requests = entries,
    });
    try std.posix.fsync(directory.fd);
}

test "CPU resident manifest bounds counts names budgets and excludes security selectors" {
    const a = std.testing.allocator;
    const good = "{\"schema\":\"rv64-cpu-resident-inputs/v1\",\"immutable_host_key_bytes\":1024,\"repeat\":2,\"requests\":[{\"name\":\"block-1\",\"request\":\"request.json\",\"resources\":\"limits.json\"}]}";
    const parsed = try std.json.parseFromSlice(Manifest, a, good, .{});
    defer parsed.deinit();
    try parsed.value.validate();
    var bad = parsed.value;
    bad.repeat = 0;
    try std.testing.expectError(error.InvalidCpuBatchCount, bad.validate());
    bad = parsed.value;
    bad.immutable_host_key_bytes = 0;
    try std.testing.expectError(error.InvalidCpuBatchKeyBudget, bad.validate());
    bad = parsed.value;
    bad.requests = &.{.{ .name = "../escape", .request = "r", .resources = "l" }};
    try std.testing.expectError(error.InvalidCpuBatchItem, bad.validate());
    const injected = "{\"schema\":\"rv64-cpu-resident-inputs/v1\",\"immutable_host_key_bytes\":1024,\"requests\":[],\"security_profile\":\"weaker\"}";
    try std.testing.expectError(error.UnknownField, std.json.parseFromSlice(Manifest, a, injected, .{}));
}
