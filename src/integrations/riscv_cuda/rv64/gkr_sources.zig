//! Immutable AOT source catalogue and per-proof physical-column metadata.
//! No numerator, denominator, challenge or expanded MAIN witness is built here.
const std = @import("std");
const core = @import("stwo_core");
const Integration = @import("stwo_riscv_cpu_integration");
const Child = Integration.rv64_gkr_child;
const G = @import("projection_codegen.zig");
const F = @import("projection_fixture_support.zig");
const Source = G.Source;
const D = Integration.rv64_device_pcs;
pub const Catalogue = struct {
    allocator: std.mem.Allocator,
    artifacts: [F.count]G.Artifact,
    pub fn init(a: std.mem.Allocator) !Catalogue {
        var result: Catalogue = .{ .allocator = a, .artifacts = undefined };
        var made: usize = 0;
        errdefer for (result.artifacts[0..made]) |*artifact| artifact.deinit();
        for (F.descriptors(), &result.artifacts) |descriptor, *artifact| {
            artifact.* = try G.record(a, descriptor);
            made += 1;
        }
        return result;
    }
    pub fn deinit(self: *Catalogue) void {
        for (&self.artifacts) |*artifact| artifact.deinit();
        self.* = undefined;
    }
    pub fn find(self: *const Catalogue, descriptor: Source.Descriptor) !u32 {
        for (&self.artifacts, 0..) |*artifact, i| if (std.meta.eql(artifact.descriptor, descriptor)) return @intCast(i);
        return error.UnsupportedGkrProjectionLayout;
    }
};
pub const Group = struct { log: u32, first: u32, count: u32, offset: usize };
pub const Item = struct { kernel: u32, offsets: []u64, public: [Source.Public.count]u32, log: u32, terms: u32, lanes: u32, facts: u32 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    columns: []D.Column,
    groups: []Group,
    offsets: []usize,
    fixed_count: usize,
    cells: usize,
    max_log: u32,
    items: []Item,
    pub fn init(a: std.mem.Allocator, request: Child.NumericalStage.Request, catalogue: *const Catalogue) !Plan {
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        if (request.native_fixed_columns.len == 0 or request.native_main_columns.len == 0) return error.DeviceGkrCoefficientsRequired;
        const total = try std.math.add(usize, request.native_fixed_columns.len, request.native_main_columns.len);
        const columns = try a.alloc(D.Column, total);
        errdefer a.free(columns);
        const offsets = try a.alloc(usize, total);
        errdefer a.free(offsets);
        const order = try a.alloc(usize, total);
        defer a.free(order);
        for (order, 0..) |*index, i| index.* = i;
        const Context = struct {
            fixed: []const D.Column,
            main: []const D.Column,
            fn at(self: @This(), i: usize) D.Column {
                return if (i < self.fixed.len) self.fixed[i] else self.main[i - self.fixed.len];
            }
            fn less(self: @This(), lhs: usize, rhs: usize) bool {
                const l = self.at(lhs).log_size;
                const r = self.at(rhs).log_size;
                return l < r or (l == r and lhs < rhs);
            }
        };
        const context = Context{ .fixed = request.native_fixed_columns, .main = request.native_main_columns };
        std.mem.sort(usize, order, context, Context.less);
        var cells: usize = 0;
        var max_log: u32 = 0;
        var groups: std.ArrayList(Group) = .empty;
        defer groups.deinit(a);
        for (order, columns, 0..) |original, *column, sorted| {
            column.* = context.at(original);
            if (column.log_size < 3 or column.log_size > 28) return error.InvalidGkrSourceColumn;
            const count = @as(usize, 1) << @intCast(column.log_size);
            if (column.device) |device| {
                if (column.coefficients.len != 0 or device.count != count or device.context_token == 0 or device.generation == 0) return error.InvalidGkrSourceColumn;
            } else if (column.coefficients.len != count) return error.InvalidGkrSourceColumn;
            offsets[original] = cells;
            if (groups.items.len == 0 or groups.items[groups.items.len - 1].log != column.log_size)
                try groups.append(a, .{ .log = column.log_size, .first = @intCast(sorted), .count = 0, .offset = cells });
            groups.items[groups.items.len - 1].count += 1;
            cells = try std.math.add(usize, cells, count);
            max_log = @max(max_log, column.log_size);
        }
        const items = try a.alloc(Item, request.instances.len);
        errdefer a.free(items);
        var made: usize = 0;
        errdefer for (items[0..made]) |item| a.free(item.offsets);
        for (request.instances, items) |instance, *item| {
            const mode_role = instance.origin == .core and (instance.origin.core == .cpu or instance.origin.core == .and_table);
            const descriptor = Source.Descriptor{ .origin = instance.origin, .cpu_u8_pairs = mode_role and native.core.cpu.u8_pairs, .cpu_compact_decode = instance.origin == .core and instance.origin.core == .cpu and native.core.cpu.compact };
            const kernel = try catalogue.find(descriptor);
            const artifact = &catalogue.artifacts[kernel];
            if (artifact.terms != instance.terms or try instance.variables() > 28) return error.InvalidGkrSourceColumn;
            const addresses = try a.alloc(u64, artifact.program.inputs.len);
            errdefer a.free(addresses);
            for (artifact.program.inputs, addresses) |input, *offset| {
                if (input.tree == 2) {
                    offset.* = 0;
                    continue;
                }
                const original = if (input.tree == 0) instance.fixed_offset + input.column else request.native_fixed_columns.len + instance.main_offset + input.column;
                if (original >= offsets.len or context.at(original).log_size != instance.row_log) return error.InvalidGkrSourceColumn;
                offset.* = offsets[original];
            }
            const public = try publicWords(native, instance.origin);
            item.* = .{ .kernel = kernel, .offsets = addresses, .public = public, .log = instance.row_log, .terms = artifact.terms, .lanes = artifact.lanes, .facts = @intCast(try instance.facts()) };
            made += 1;
        }
        return .{ .allocator = a, .columns = columns, .groups = try groups.toOwnedSlice(a), .offsets = offsets, .fixed_count = request.native_fixed_columns.len, .cells = cells, .max_log = max_log, .items = items };
    }
    pub fn deinit(self: *Plan) void {
        for (self.items) |item| self.allocator.free(item.offsets);
        self.allocator.free(self.items);
        self.allocator.free(self.columns);
        self.allocator.free(self.groups);
        self.allocator.free(self.offsets);
        self.* = undefined;
    }
};

/// The local-GKR public namespace shared by install plans and live captures.
pub fn publicWords(native: anytype, origin: anytype) ![Source.Public.count]u32 {
    var public: [Source.Public.count]u32 = @splat(0);
    public[Source.Public.epoch] = native.core.cpu.epoch;
    if (native.core.cpu.public.initial_pc >= core.fields.m31.Modulus) return error.InvalidGkrSourceColumn;
    public[Source.Public.initial_pc] = @intCast(native.core.cpu.public.initial_pc);
    for (0..32) |r| {
        for (0..4) |limb| {
            const shift: u6 = @intCast(16 * limb);
            public[Source.Public.initial_registers + 4 * r + limb] = @as(u16, @truncate(native.core.cpu.public.initial_registers[r] >> shift));
            public[Source.Public.final_registers + 4 * r + limb] = @as(u16, @truncate(native.core.cpu.public.final_registers[r] >> shift));
        }
        public[Source.Public.register_clocks + r] = native.core.cpu.public.register_clocks[r];
    }
    if (origin == .sponge) {
        const sponge = native.sponge[@intFromEnum(origin.sponge)] orelse return error.NativeGkrSourceRequired;
        public[Source.Public.sponge_first_id] = sponge.first_id;
    }
    for (public) |v| if (v >= core.fields.m31.Modulus) return error.InvalidGkrSourceColumn;
    return public;
}
