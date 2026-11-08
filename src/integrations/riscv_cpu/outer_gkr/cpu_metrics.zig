//! Optional per-proof counters. Each component owns its slot; atomics also
//! preserve totals if a future scheduler revisits a component concurrently.
const std = @import("std");
const A = std.atomic.Value(u64);
pub const Counters = struct {
    calls: A = .init(0),
    compiled_calls: A = .init(0),
    aux_ns: A = .init(0),
    prepare_ns: A = .init(0),
    rows_ns: A = .init(0),
    base_nodes: A = .init(0),
    secure_nodes: A = .init(0),
    invariant_nodes: A = .init(0),
    workspace_bytes: A = .init(0),
    allocated_slots: A = .init(0),
    actual_shards: A = .init(0),
    pub fn snapshot(self: *const Counters) Snapshot {
        var out: Snapshot = undefined;
        inline for (std.meta.fields(Snapshot)) |field| @field(out, field.name) = @field(self, field.name).load(.monotonic);
        return out;
    }
};
pub const Snapshot = struct {
    calls: u64,
    compiled_calls: u64,
    aux_ns: u64,
    prepare_ns: u64,
    rows_ns: u64,
    base_nodes: u64,
    secure_nodes: u64,
    invariant_nodes: u64,
    workspace_bytes: u64,
    allocated_slots: u64,
    actual_shards: u64,
};
pub fn save(a: std.mem.Allocator, directory: []const u8, authority: [32]u8, counters: []const Counters, labels: []const []const u8, gkr: anytype) !void {
    if (counters.len != labels.len) return error.InvalidHybridMetrics;
    const Row = struct { component: []const u8, metrics: Snapshot };
    const rows = try a.alloc(Row, counters.len);
    defer a.free(rows);
    for (rows, counters, labels) |*out, *counter, label| out.* = .{ .component = label, .metrics = counter.snapshot() };
    const identity = std.fmt.bytesToHex(authority, .lower);
    const encoded = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo.circuit.om31.hybrid-components.v1", .authority = identity[0..], .scope = "summed component wall intervals; may overlap, not block wall time; GKR peak_layer_bytes excludes inputs and other owners", .gkr = gkr, .components = rows }, .{ .whitespace = .indent_2 });
    defer a.free(encoded);
    const parent = try std.fmt.allocPrint(a, "{s}/components", .{directory});
    defer a.free(parent);
    try std.fs.cwd().makePath(parent);
    const path = try std.fmt.allocPrint(a, "{s}/hybrid-{d}.json", .{ parent, std.time.nanoTimestamp() });
    defer a.free(path);
    const file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(encoded);
}
