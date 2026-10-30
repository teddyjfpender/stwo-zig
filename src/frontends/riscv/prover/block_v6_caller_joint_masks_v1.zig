//! Exact ordered union of independently derived original caller masks.
//! This is routing metadata, not proof or admission authority. It neither
//! changes the original equation roster nor normalizes quotient polynomials.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
pub const Layout = @import("../recursion/sample_point_layout.zig").Layout;
const MAX_LOG = @import("../recursion/air/pcs_deep_circuit.zig").MAX_DOMAIN_LOG;
pub const MAX_UNION: usize = 12;
pub const Column = struct { trace_log: u32, mask_log: u32, layout: Layout };
pub const Coordinate = struct {
    mask_log: u32,
    offset: i8,
    pub fn point(self: Coordinate, current: Point) Point {
        return current.add(self.translation());
    }
    fn translation(self: Coordinate) Point {
        if (self.offset == 0) return .{ .x = Q.one(), .y = Q.zero() };
        const step = core.poly.circle.CanonicCoset.new(self.mask_log).step();
        return (Point{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) }).mulSigned(self.offset);
    }
};
pub const Routes = struct { left: []const u8, right: []const u8 };
pub const Limits = struct { max_columns: usize = 32768, max_union_samples: usize = 1 << 20, max_bytes: usize = 256 << 20 };
pub const Owned = struct {
    a: std.mem.Allocator,
    left: []Column,
    right: []Column,
    coordinates: []Coordinate,
    routes: []u8,
    offsets: []usize,
    left_offsets: []usize,
    right_offsets: []usize,
    common_log: u32,
    pub const grants_proof_authority = false;
    pub fn init(a: std.mem.Allocator, left: []const Column, right: []const Column, common_log: u32, limits: Limits) !Owned {
        if (left.len != right.len or left.len > limits.max_columns or common_log == 0 or common_log > MAX_LOG) return error.InvalidCallerJointMasks;
        var samples: usize = 0;
        var route_count: usize = 0;
        for (left, right) |l, r| {
            var union_buffer: [MAX_UNION]Coordinate = undefined;
            var route_buffer: [MAX_UNION]u8 = undefined;
            const counts = try compileColumn(l, r, common_log, &union_buffer, &route_buffer);
            samples = try std.math.add(usize, samples, counts.samples);
            route_count = try std.math.add(usize, route_count, counts.routes);
        }
        if (samples > limits.max_union_samples) return error.CallerJointMaskResourceLimit;
        const offset_count = try std.math.add(usize, left.len, 1);
        var bytes = try std.math.mul(usize, left.len, 2 * @sizeOf(Column));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, samples, @sizeOf(Coordinate)));
        bytes = try std.math.add(usize, bytes, route_count);
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, offset_count, 3 * @sizeOf(usize)));
        if (bytes > limits.max_bytes) return error.CallerJointMaskResourceLimit;
        const l = try a.dupe(Column, left);
        errdefer a.free(l);
        const r = try a.dupe(Column, right);
        errdefer a.free(r);
        const coordinates = try a.alloc(Coordinate, samples);
        errdefer a.free(coordinates);
        const routes = try a.alloc(u8, route_count);
        errdefer a.free(routes);
        const offsets = try a.alloc(usize, offset_count);
        errdefer a.free(offsets);
        const left_offsets = try a.alloc(usize, offset_count);
        errdefer a.free(left_offsets);
        const right_offsets = try a.alloc(usize, offset_count);
        errdefer a.free(right_offsets);
        var cursor: usize = 0;
        var route_cursor: usize = 0;
        for (l, r, 0..) |lc, rc, i| {
            var union_buffer: [MAX_UNION]Coordinate = undefined;
            var route_buffer: [MAX_UNION]u8 = undefined;
            const counts = try compileColumn(lc, rc, common_log, &union_buffer, &route_buffer);
            offsets[i] = cursor;
            left_offsets[i] = route_cursor;
            right_offsets[i] = route_cursor + lc.layout.sampleCount();
            @memcpy(coordinates[cursor..][0..counts.samples], union_buffer[0..counts.samples]);
            @memcpy(routes[route_cursor..][0..counts.routes], route_buffer[0..counts.routes]);
            cursor += counts.samples;
            route_cursor += counts.routes;
        }
        offsets[l.len] = cursor;
        left_offsets[l.len] = route_cursor;
        right_offsets[l.len] = route_cursor;
        return .{ .a = a, .left = l, .right = r, .coordinates = coordinates, .routes = routes, .offsets = offsets, .left_offsets = left_offsets, .right_offsets = right_offsets, .common_log = common_log };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.right_offsets);
        self.a.free(self.left_offsets);
        self.a.free(self.offsets);
        self.a.free(self.routes);
        self.a.free(self.coordinates);
        self.a.free(self.right);
        self.a.free(self.left);
        self.* = undefined;
    }
    pub fn column(self: *const Owned, index: usize) []const Coordinate {
        return self.coordinates[self.offsets[index]..self.offsets[index + 1]];
    }
    pub fn columnRoutes(self: *const Owned, index: usize) Routes {
        return .{ .left = self.routes[self.left_offsets[index]..][0..self.left[index].layout.sampleCount()], .right = self.routes[self.right_offsets[index]..][0..self.right[index].layout.sampleCount()] };
    }
    /// Compare against independently rederived original masks, not a checksum
    /// produced from this mutable object. Key admission must call this boundary.
    pub fn requireCanonical(self: *const Owned, left: []const Column, right: []const Column, common_log: u32, limits: Limits) !void {
        var expected = try Owned.init(self.a, left, right, common_log, limits);
        defer expected.deinit();
        if (self.common_log != expected.common_log or self.left.len != expected.left.len or self.right.len != expected.right.len or self.coordinates.len != expected.coordinates.len or !std.mem.eql(u8, self.routes, expected.routes) or !std.mem.eql(usize, self.offsets, expected.offsets) or !std.mem.eql(usize, self.left_offsets, expected.left_offsets) or !std.mem.eql(usize, self.right_offsets, expected.right_offsets)) return error.UntrustedCallerJointMasks;
        for (self.left, expected.left) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedCallerJointMasks;
        for (self.right, expected.right) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedCallerJointMasks;
        for (self.coordinates, expected.coordinates) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedCallerJointMasks;
    }
};
fn validate(column: Column, common: u32) !void {
    if (column.trace_log == 0 or column.trace_log > MAX_LOG or column.mask_log == 0 or column.mask_log > common or (column.layout != .none and column.trace_log > common)) return error.InvalidCallerJointMasks;
    if (column.layout == .current_keccak_final) {
        if (column.mask_log != column.trace_log) return error.InvalidCallerJointMasks;
    } else if (column.mask_log != common) return error.InvalidCallerJointMasks;
}
fn compileColumn(left: Column, right: Column, common: u32, coordinates: *[MAX_UNION]Coordinate, routes: *[MAX_UNION]u8) !struct { samples: usize, routes: usize } {
    try validate(left, common);
    try validate(right, common);
    if (left.trace_log != right.trace_log) return error.UnsharedCallerJointColumn;
    var used: usize = 0;
    var route: usize = 0;
    for ([_]Column{ left, right }) |original| for (original.layout.offsets()) |offset| {
        if (route == MAX_UNION) return error.CallerJointMaskResourceLimit;
        const coordinate = Coordinate{ .mask_log = if (offset == 0) 0 else original.mask_log, .offset = @intCast(offset) };
        const translation = coordinate.translation();
        var found: ?usize = null;
        for (coordinates[0..used], 0..) |existing, i| if (existing.translation().eql(translation)) {
            found = i;
            break;
        };
        const index = found orelse blk: {
            if (used == MAX_UNION) return error.CallerJointMaskResourceLimit;
            coordinates[used] = coordinate;
            used += 1;
            break :blk used - 1;
        };
        routes[route] = @intCast(index);
        route += 1;
    };
    return .{ .samples = used, .routes = route };
}
