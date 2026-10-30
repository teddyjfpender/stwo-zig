//! Spill one original memory component, without rebuilding its PCS on restore.
//! Cache cells are untrusted prover material. Only the ordinary fresh source
//! verifier authenticates roots, fixed columns and the resulting proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Codec = @import("block_v6_cpu_checkpoint_codec_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const E = @import("block_v7_execution_epoch_v1.zig");
const Pcs = @import("block_v5_word_pcs_v1.zig");
const Coefficients = @import("block_v7_coefficient_checkpoint_v1.zig");
pub const Storage = enum { resident, coefficients };
pub const Limits = struct { max_file_bytes: u64 = 16 << 30, max_loaded_bytes: usize = 16 << 30, max_row_log: u32 = 22 };
pub const Pin = struct { entry: E.Entry, log: u32, bytes: u64, merkle_bytes: u64, loaded_bytes: usize, storage: Storage = .resident };
fn header(pin: Pin) [128]u8 {
    var out: [128]u8 = @splat(0);
    @memcpy(out[0..8], if (pin.storage == .resident) "B7MEM001" else "B7MEC001");
    std.mem.writeInt(u32, out[8..12], @intFromEnum(pin.entry.family), .little);
    std.mem.writeInt(u32, out[12..16], pin.entry.index, .little);
    std.mem.writeInt(u32, out[16..20], pin.log, .little);
    @memcpy(out[32..64], &pin.entry.identity);
    @memcpy(out[64..96], &pin.entry.roots[0]);
    @memcpy(out[96..128], &pin.entry.roots[1]);
    return out;
}
fn shape(comptime S: type, log: u32, config: core.pcs.PcsConfig, entry: E.Entry, merkle: u64, storage: Storage, limits: Limits) !Pin {
    try entry.validate();
    if (entry.root_count != 2 or log < 1 or log > limits.max_row_log or limits.max_row_log > 24) return error.InvalidV7CohortCheckpoint;
    const extended = try std.math.add(u32, log, config.fri_config.log_blowup_factor);
    if (extended > 30) return error.InvalidV7CohortCheckpoint;
    const width = S.FIXED_COUNT + S.MAIN_COUNT;
    const raw: u64 = @as(u64, width * 4) << @intCast(log);
    const stored: u64 = @as(u64, width * 4) << @intCast(if (storage == .resident) extended else log);
    const max_merkle = ((@as(u64, 1) << @intCast(extended + 1)) - 1) * 64;
    if (merkle < 64 or merkle > max_merkle) return error.InvalidV7CohortCheckpoint;
    const framing = 128 + 16 + width * 4 + (extended + 1) * 16;
    const bytes = try std.math.add(u64, try std.math.add(u64, raw + stored, merkle), framing);
    const coefficient_descriptors: u64 = if (storage == .coefficients) width * @sizeOf(@import("stwo_prover_engine").poly.circle.CircleCoefficients) else 0;
    const loaded = try std.math.add(u64, raw + stored + merkle, 2 * @sizeOf(Codec.Tree) + 2 * width * @sizeOf(Pcs.Column) + coefficient_descriptors + 2 * (extended + 1) * @sizeOf([]core.proof_suites.Blake3.Hasher.Hash));
    if (bytes > limits.max_file_bytes or loaded > limits.max_loaded_bytes) return error.V7CohortCheckpointLimit;
    return .{ .entry = entry, .log = log, .bytes = bytes, .merkle_bytes = merkle, .loaded_bytes = @intCast(loaded), .storage = storage };
}
pub fn For(comptime S: type) type {
    const PC = Pcs.For(Cpu, S);
    return struct {
        pub const Loaded = struct {
            matrix: T.Matrix,
            first: PC.First,
            matrix_live: bool = true,
            pub fn releaseMatrix(self: *Loaded) !void {
                if (!self.matrix_live) return error.InvalidV7CohortCheckpoint;
                self.matrix.deinit();
                self.matrix_live = false;
            }
            pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
                self.first.deinit(a);
                if (self.matrix_live) self.matrix.deinit();
                self.* = undefined;
            }
        };
        pub fn write(dir: std.fs.Dir, name: []const u8, matrix: T.Matrix, first: *const PC.First, entry: E.Entry, limits: Limits) !Pin {
            try Codec.requireName(name);
            if (!first.owns_scheme or first.scheme.pending_commit != null or first.scheme.trees.items.len != 2 or matrix.columns.len != S.FIXED_COUNT + S.MAIN_COUNT or !std.meta.eql(first.roots, entry.roots[0..2].*)) return error.InvalidV7CohortCheckpoint;
            const extended = try std.math.add(u32, matrix.log, first.scheme.config.fri_config.log_blowup_factor);
            if (extended > 30) return error.InvalidV7CohortCheckpoint;
            const storage: Storage = if (first.scheme.trees.items[0].compact_polynomials) .coefficients else .resident;
            var merkle: u64 = 0;
            inline for (.{ S.FIXED_COUNT, S.MAIN_COUNT }, 0..) |width, i| merkle += if (storage == .coefficients) try Coefficients.inspect(&first.scheme.trees.items[i], width, matrix.log, extended, first.roots[i]) else try Codec.inspectTree(&first.scheme.trees.items[i], &(@as([width]u32, @splat(extended))), extended + 1, first.roots[i]);
            const pin = try shape(S, matrix.log, first.scheme.config, entry, merkle, storage, limits);
            const file = try dir.createFile(name, .{ .exclusive = true });
            defer file.close();
            errdefer dir.deleteFile(name) catch {};
            try file.writeAll(&header(pin));
            try Codec.writeValues(file, matrix.storage);
            for (first.scheme.trees.items) |*tree| if (storage == .coefficients) try Coefficients.write(file, tree) else try Codec.writeTree(file, tree);
            if ((try file.stat()).size != pin.bytes) return error.InvalidV7CohortCheckpoint;
            try file.sync();
            return pin;
        }
        pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, config: core.pcs.PcsConfig, pin: Pin, limits: Limits) !Loaded {
            try Codec.requireName(name);
            if (!std.meta.eql(pin, try shape(S, pin.log, config, pin.entry, pin.merkle_bytes, pin.storage, limits))) return error.InvalidV7CohortCheckpoint;
            const file = try dir.openFile(name, .{});
            defer file.close();
            if ((try file.stat()).size != pin.bytes) return error.InvalidV7CohortCheckpoint;
            var actual: [128]u8 = undefined;
            try Codec.readExact(file, &actual);
            if (!std.meta.eql(actual, header(pin))) return error.InvalidV7CohortCheckpoint;
            var matrix = try T.Matrix.init(a, pin.log, S.FIXED_COUNT + S.MAIN_COUNT, limits.max_loaded_bytes);
            errdefer matrix.deinit();
            try Codec.readValues(file, matrix.storage);
            var scheme = try Codec.Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            try scheme.trees.ensureTotalCapacityPrecise(a, 2);
            const extended = pin.log + config.fri_config.log_blowup_factor;
            var used: u64 = 0;
            inline for (.{ S.FIXED_COUNT, S.MAIN_COUNT }, 0..) |width, i| {
                var tree = if (pin.storage == .coefficients) try Coefficients.load(a, file, width, pin.log, extended, &used, pin.merkle_bytes) else try Codec.loadTree(a, file, &(@as([width]u32, @splat(extended))), extended + 1, &used, pin.merkle_bytes);
                errdefer tree.deinit(a);
                if (!std.meta.eql(tree.commitment.root(), pin.entry.roots[i])) return error.InvalidV7CohortCheckpoint;
                scheme.trees.appendAssumeCapacity(tree);
            }
            var extra: [1]u8 = undefined;
            if (used != pin.merkle_bytes or try file.read(&extra) != 0) return error.InvalidV7CohortCheckpoint;
            return .{ .matrix = matrix, .first = .{ .scheme = scheme, .roots = pin.entry.roots[0..2].* } };
        }
    };
}
