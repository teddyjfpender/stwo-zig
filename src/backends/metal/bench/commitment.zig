const std = @import("std");
const stwo = @import("stwo");
const metal = stwo.backends.metal.runtime;
const blake2_merkle = stwo.core.vcs_lifted.blake2_merkle;

const Hasher = blake2_merkle.Blake2sMerkleHasher;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var column_count: usize = 512;
    var log_size: u32 = 16;
    var repetitions: usize = 3;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--columns") and index + 1 < args.len) {
            index += 1;
            column_count = try std.fmt.parseInt(usize, args[index], 10);
        } else if (std.mem.eql(u8, args[index], "--log-size") and index + 1 < args.len) {
            index += 1;
            log_size = try std.fmt.parseInt(u32, args[index], 10);
        } else if (std.mem.eql(u8, args[index], "--repetitions") and index + 1 < args.len) {
            index += 1;
            repetitions = try std.fmt.parseInt(usize, args[index], 10);
        } else {
            return error.InvalidArgument;
        }
    }
    if (column_count == 0 or log_size < 1 or log_size >= 31 or repetitions == 0) {
        return error.InvalidArgument;
    }

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();

    const row_count = @as(usize, 1) << @intCast(log_size);
    const storage = try allocator.alloc(u32, column_count * row_count);
    defer allocator.free(storage);
    const columns = try allocator.alloc([]const u32, column_count);
    defer allocator.free(columns);
    const log_sizes = try allocator.alloc(u32, column_count);
    defer allocator.free(log_sizes);
    for (0..column_count) |column_index| {
        const column = storage[column_index * row_count ..][0..row_count];
        for (column, 0..) |*value, row| {
            value.* = @intCast((column_index * 7919 + row * 104729 + 17) % 0x7fffffff);
        }
        columns[column_index] = column;
        log_sizes[column_index] = log_size;
    }

    var best_wall_ms = std.math.inf(f64);
    var best_gpu_ms = std.math.inf(f64);
    for (0..repetitions) |repetition| {
        var timer = try std.time.Timer.start();
        var tree = try runtime.commitColumns(
            allocator,
            columns,
            log_sizes,
            log_size,
            Hasher.leafSeed(),
            Hasher.nodeSeed(),
            Hasher.domainPrefixBytes(),
        );
        const result = try tree.root();
        const wall_ms = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms;
        tree.deinit();
        best_wall_ms = @min(best_wall_ms, wall_ms);
        best_gpu_ms = @min(best_gpu_ms, result.gpu_ms);
        std.debug.print("rep={d} wall_ms={d:.3} gpu_ms={d:.3} root={x}\n", .{
            repetition,
            wall_ms,
            result.gpu_ms,
            result.hash[0..4],
        });
    }

    const cells = column_count * row_count;
    const gpu_cells_per_second = @as(f64, @floatFromInt(cells)) / (best_gpu_ms / 1000.0);
    const wall_cells_per_second = @as(f64, @floatFromInt(cells)) / (best_wall_ms / 1000.0);
    std.debug.print(
        "columns={d} log_size={d} cells={d} input_mib={d:.1} best_wall_ms={d:.3} best_gpu_ms={d:.3} wall_mcells_s={d:.1} gpu_mcells_s={d:.1}\n",
        .{
            column_count,
            log_size,
            cells,
            @as(f64, @floatFromInt(cells * @sizeOf(u32))) / (1024.0 * 1024.0),
            best_wall_ms,
            best_gpu_ms,
            wall_cells_per_second / 1e6,
            gpu_cells_per_second / 1e6,
        },
    );
}
