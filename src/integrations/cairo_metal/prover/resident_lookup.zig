//! Metal-resident storage retained from witness generation through LogUp.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const shared_runtime = @import("stwo_metal_backend").shared_runtime;
const interaction_residency =
    @import("stwo_cairo_frontend").witness.interaction_residency;

pub const identity: u64 = 0x5354_5743_4d4c_5531; // STWCMLU1
pub const alpha_power_count: usize = 128;
pub const min_resident_relation_cells: usize = 1 << 22;

pub const Storage = struct {
    allocator: std.mem.Allocator,
    arena: arena_plan.ResidentArena,
    source: arena_plan.Binding,
    outputs: []arena_plan.Binding,
    claimed_sum: arena_plan.Binding,
    alpha_powers: arena_plan.Binding,
    z: arena_plan.Binding,
    scan_scratch: arena_plan.Binding,
    rows: usize,
    interaction_columns: usize,

    pub fn deinit(self: *Storage) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.free(self.outputs);
        allocator.destroy(self);
    }
};

pub fn allocate(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    request: interaction_residency.LookupAllocationRequest,
) !?interaction_residency.LookupAllocation {
    if (request.rows == 0 or !std.math.isPowerOfTwo(request.rows) or
        request.rows > std.math.maxInt(u32) or request.word_columns == 0 or
        request.interaction_columns == 0)
        return error.InvalidResidentLookupGeometry;
    const source_cells = try std.math.mul(
        usize,
        request.rows,
        request.word_columns,
    );
    const output_cells = try std.math.mul(
        usize,
        request.rows,
        try std.math.mul(usize, request.interaction_columns, 4),
    );
    if (try std.math.add(usize, source_cells, output_cells) <
        min_resident_relation_cells) return null;

    var layout = Layout{};
    const source = try layout.add(try byteSize(source_cells));
    const output_count = try std.math.mul(
        usize,
        request.interaction_columns,
        4,
    );
    const outputs = try allocator.alloc(arena_plan.Binding, output_count);
    errdefer allocator.free(outputs);
    for (outputs) |*output|
        output.* = try layout.add(try byteSize(request.rows));
    const claimed_sum = try layout.add(4 * @sizeOf(u32));
    const alpha_powers = try layout.add(
        alpha_power_count * 4 * @sizeOf(u32),
    );
    const z = try layout.add(4 * @sizeOf(u32));
    const blocks = try std.math.divCeil(usize, request.rows, 256);
    const scan_scratch = try layout.add(try byteSize(try std.math.mul(
        usize,
        blocks,
        4,
    )));

    var lease = try shared_runtime.acquireExisting();
    defer lease.deinit();
    var arena = try arena_plan.ResidentArena.initByteLength(
        lease.runtime,
        layout.byte_length,
    );
    errdefer arena.deinit();
    const storage = try allocator.create(Storage);
    errdefer allocator.destroy(storage);
    storage.* = .{
        .allocator = allocator,
        .arena = arena,
        .source = source,
        .outputs = outputs,
        .claimed_sum = claimed_sum,
        .alpha_powers = alpha_powers,
        .z = z,
        .scan_scratch = scan_scratch,
        .rows = request.rows,
        .interaction_columns = request.interaction_columns,
    };

    return .{
        .words = try bindingWords(&storage.arena, storage.source),
        .residency = .{ .identity = identity, .context = storage },
        .context = storage,
        .deinit_fn = deinitOpaque,
    };
}

pub fn fromResidency(
    residency: interaction_residency.Residency,
) ?*Storage {
    if (residency.identity != identity) return null;
    return @ptrCast(@alignCast(residency.context));
}

pub fn bindingWords(
    arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
) ![]u32 {
    const aligned: []align(4) u8 = @alignCast(try arena.bytes(binding));
    return std.mem.bytesAsSlice(u32, aligned);
}

fn deinitOpaque(context: *anyopaque) void {
    const storage: *Storage = @ptrCast(@alignCast(context));
    storage.deinit();
}

fn byteSize(words: usize) !u64 {
    return std.math.mul(u64, words, @sizeOf(u32));
}

const Layout = struct {
    byte_length: u64 = 0,
    next_id: u32 = 1,

    fn add(self: *Layout, size_bytes: u64) !arena_plan.Binding {
        if (size_bytes == 0) return error.InvalidBindingSize;
        const offset = std.mem.alignForward(u64, self.byte_length, 16);
        self.byte_length = try std.math.add(u64, offset, size_bytes);
        defer self.next_id += 1;
        return .{
            .logical_id = self.next_id,
            .slot = self.next_id,
            .offset_bytes = offset,
            .size_bytes = size_bytes,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        };
    }
};
