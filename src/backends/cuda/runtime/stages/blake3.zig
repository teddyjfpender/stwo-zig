//! Typed BLAKE3 device stage adapter. All arithmetic/hash state remains resident.
//! Host code checks ownership/ranges and submits kernels; it never hashes.
const std = @import("std");
const abi = @import("../../abi/stages/blake3.zig");
const Device = @import("../column.zig").DeviceSlice;
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const telemetry = @import("../telemetry.zig");
pub const Hashes = Device(abi.Hash);
pub const States = Device(abi.State);
pub const Channels = Device(abi.Channel);
pub const max_mixed_segments = abi.max_mixed_segments;
pub const Native = OpsFor(abi);
pub fn OpsFor(comptime Api: type) type {
    return struct {
        fn stageAllowed(session: anytype, stage: telemetry.Stage) !void {
            switch (stage) {
                .trace_commit, .constraint_evaluation, .fri_commit => {},
                else => return error.StageOrderViolation,
            }
            try common.requireStage(session, stage);
        }
        pub fn contiguousLeaves(session: anytype, stage: telemetry.Stage, size: u32, columns: common.WordMatrix, output: Hashes) !void {
            try stageAllowed(session, stage);
            if (!std.math.isPowerOfTwo(size) or output.len != size) return error.InvalidKernelDescriptor;
            const source = try layout.wordMatrix(session, columns, size);
            const dest = try layout.resident(session, abi.Hash, output, size);
            if (layout.overlap(source.range, dest.range)) return error.OverlappingDeviceRange;
            try common.record(session, stage, Api.stwo_blake3_contiguous_leaf_on(size, source.pointer, source.stride_words, columns.storage.len, dest.pointer, session.context.stream));
        }
        pub fn mixedLeaves(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, output: Hashes) !void {
            try mixedWithSeed(session, stage, size, segments, 0, null, null, output);
        }
        pub fn mixedPrefix(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: ?States, output: States) !void {
            try mixedWithSeed(session, stage, size, segments, absorbed, seed, output, null);
        }
        pub fn mixedLeavesFromPrefix(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: States, output: Hashes) !void {
            try mixedWithSeed(session, stage, size, segments, absorbed, seed, null, output);
        }
        fn mixedWithSeed(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: ?States, prefix: ?States, output: ?Hashes) !void {
            try stageAllowed(session, stage);
            if (!std.math.isPowerOfTwo(size) or segments.len == 0 or segments.len > max_mixed_segments or (prefix == null) == (output == null)) return error.InvalidKernelDescriptor;
            const destination = if (prefix) |v| try layout.elementRange(v.address, v.len, @sizeOf(abi.State)) else try layout.elementRange(output.?.address, output.?.len, @sizeOf(abi.Hash));
            const p = if (prefix) |v| blk: {
                if (v.len != size) return error.SizeOverflow;
                break :blk try session.context.deviceSlicePointer(abi.State, v, size);
            } else null;
            const o = if (output) |v| blk: {
                if (v.len != size) return error.SizeOverflow;
                break :blk try session.context.deviceSlicePointer(abi.Hash, v, size);
            } else null;
            const s = if (seed) |v| blk: {
                if (absorbed == 0 or v.len > size or !std.math.isPowerOfTwo(v.len)) return error.InvalidKernelDescriptor;
                const r = try layout.resident(session, abi.State, v, v.len);
                if (layout.overlap(r.range, destination)) return error.OverlappingDeviceRange;
                break :blk r.pointer;
            } else blk: {
                if (absorbed != 0) return error.InvalidKernelDescriptor;
                break :blk null;
            };
            var descriptors: [max_mixed_segments]abi.MixedSegment = undefined;
            var total = absorbed;
            for (segments, descriptors[0..segments.len]) |segment, *desc| {
                if (!std.math.isPowerOfTwo(segment.source_size) or segment.source_size > size) return error.InvalidKernelDescriptor;
                const src = try layout.wordMatrix(session, segment.columns, segment.source_size);
                if (layout.overlap(src.range, destination)) return error.OverlappingDeviceRange;
                total = std.math.add(u32, total, src.column_count) catch return error.SizeOverflow;
                desc.* = .{ .columns = src.pointer, .stride_words = src.stride_words, .capacity_words = segment.columns.storage.len, .source_size = segment.source_size };
            }
            try common.record(session, stage, Api.stwo_blake3_mixed_seeded_on(size, @intCast(segments.len), &descriptors, absorbed, if (seed) |v| @intCast(v.len) else 0, s, p, o, session.context.stream));
        }
        pub fn progressiveInit(session: anytype, stage: telemetry.Stage, states: States) !void {
            try stageAllowed(session, stage);
            try common.record(session, stage, Api.stwo_blake3_progressive_init_on(try common.count(states.len), try session.context.deviceSlicePointer(abi.State, states, states.len), session.context.stream));
        }
        pub fn progressiveAbsorbLifted(session: anytype, stage: telemetry.Stage, size: u32, source_size: u32, absorbed: u32, columns: common.WordMatrix, states: States) !void {
            try stageAllowed(session, stage);
            if (!std.math.isPowerOfTwo(size) or !std.math.isPowerOfTwo(source_size) or source_size > size or states.len != size) return error.InvalidKernelDescriptor;
            const src = try layout.wordMatrix(session, columns, source_size);
            const dst = try layout.resident(session, abi.State, states, size);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            _ = std.math.add(u32, absorbed, src.column_count) catch return error.SizeOverflow;
            try common.record(session, stage, Api.stwo_blake3_progressive_absorb_lifted_on(size, source_size, absorbed, src.pointer, src.stride_words, columns.storage.len, dst.pointer, session.context.stream));
        }
        pub fn progressiveFinalize(session: anytype, stage: telemetry.Stage, absorbed: u32, states: States, output: Hashes) !void {
            try stageAllowed(session, stage);
            if (states.len != output.len) return error.SizeOverflow;
            const src = try layout.resident(session, abi.State, states, states.len);
            const dst = try layout.resident(session, abi.Hash, output, output.len);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            try common.record(session, stage, Api.stwo_blake3_progressive_finalize_on(try common.count(output.len), absorbed, src.pointer, dst.pointer, session.context.stream));
        }
        pub fn reduceNodes(session: anytype, stage: telemetry.Stage, previous: Hashes, output: Hashes) !void {
            try stageAllowed(session, stage);
            if ((std.math.mul(usize, output.len, 2) catch return error.SizeOverflow) != previous.len) return error.SizeOverflow;
            const src = try layout.resident(session, abi.Hash, previous, previous.len);
            const dst = try layout.resident(session, abi.Hash, output, output.len);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            try common.record(session, stage, Api.stwo_blake3_layer_on(src.pointer, try common.count(output.len), dst.pointer, session.context.stream));
        }
        /// Canonical all-layer storage; no interior node is recomputed or discarded.
        pub fn contiguousTail(session: anytype, stage: telemetry.Stage, previous: Hashes, outputs: Hashes, levels: u32) !void {
            if (levels == 0 or levels >= @bitSizeOf(usize) or !std.math.isPowerOfTwo(previous.len)) return error.InvalidKernelDescriptor;
            const final = previous.len >> @intCast(levels);
            if (final == 0 or outputs.len != previous.len - final) return error.SizeOverflow;
            var src = previous;
            var offset: usize = 0;
            for (0..levels) |_| {
                const count = src.len / 2;
                const dst = try outputs.sub(offset, count);
                try reduceNodes(session, stage, src, dst);
                src = dst;
                offset += count;
            }
        }
        pub fn friLeaves(session: anytype, coordinates: common.WordMatrix, size: u32, fold_log: u32, output: Hashes) !void {
            try stageAllowed(session, .fri_commit);
            if (fold_log != 0 and fold_log != 2) return error.InvalidKernelDescriptor;
            if (output.len != size >> @intCast(fold_log)) return error.SizeOverflow;
            const src = try layout.wordMatrix(session, coordinates, size);
            const dst = try layout.resident(session, abi.Hash, output, output.len);
            if (src.column_count != 4 or layout.overlap(src.range, dst.range)) return error.InvalidKernelDescriptor;
            try common.record(session, .fri_commit, Api.stwo_blake3_fri_leaf_on(size, src.pointer, src.stride_words, coordinates.storage.len, fold_log, dst.pointer, session.context.stream));
        }
        pub fn channel(session: anytype, stage: telemetry.Stage, state: Channels, data: common.Words, count: u32, operation: abi.Operation, max_draw_blocks: u32) !void {
            try common.requireStage(session, stage);
            if (state.len != 1) return error.SizeOverflow;
            const s = try layout.resident(session, abi.Channel, state, 1);
            const ptr = if (data.len != 0) blk: {
                const v = try layout.resident(session, u32, data, data.len);
                if (layout.overlap(v.range, s.range)) return error.OverlappingDeviceRange;
                break :blk v.pointer;
            } else null;
            try common.record(session, stage, Api.stwo_blake3_channel_on(&s.pointer[0], ptr, data.len, count, @intFromEnum(operation), max_draw_blocks, session.context.stream));
        }
        pub fn grindRange(session: anytype, state: Channels, bits: u32, first: u64, count: u32, minimum: common.Nonce) !void {
            try common.requireStage(session, .pow);
            if (state.len != 1 or minimum.len != 1) return error.SizeOverflow;
            const s = try layout.resident(session, abi.Channel, state, 1);
            const dst = try layout.resident(session, u64, minimum, 1);
            if (layout.overlap(s.range, dst.range)) return error.OverlappingDeviceRange;
            try common.recordMany(session, .pow, Api.stwo_blake3_pow_range_on(&s.pointer[0], bits, first, count, &dst.pointer[0], session.context.stream), 2);
        }
        pub fn drawQueries(session: anytype, state: Channels, log_domain: u32, queries: common.Words) !void {
            try common.requireStage(session, .decommit);
            if (state.len != 1 or queries.len == 0) return error.SizeOverflow;
            const src = try layout.resident(session, abi.Channel, state, 1);
            const dst = try layout.resident(session, u32, queries, queries.len);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            try common.record(session, .decommit, Api.stwo_blake3_query_on(&src.pointer[0], log_domain, try common.count(queries.len), dst.pointer, queries.len, session.context.stream));
        }
        /// Full device search plus nonce absorption; no nonce/challenge ingress.
        pub fn grind(session: anytype, state: Channels, bits: u32, end_exclusive: u64, blocks: u32, nonce: common.Nonce) !void {
            try common.requireStage(session, .pow);
            if (state.len != 1 or nonce.len != 1) return error.SizeOverflow;
            const src = try layout.resident(session, abi.Channel, state, 1);
            const dst = try layout.resident(session, u64, nonce, 1);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            try common.recordMany(session, .pow, Api.stwo_blake3_grind_on(&src.pointer[0], bits, end_exclusive, blocks, &dst.pointer[0], session.context.stream), 3);
        }
        /// OR failure into an existing terminal verdict. Caller initializes the
        /// verdict on device and must reject it before publishing proof bytes.
        pub fn sealError(session: anytype, states: Channels, terminal: common.Words) !void {
            try common.requireStage(session, .decommit);
            if (states.len == 0 or terminal.len != 1) return error.SizeOverflow;
            const src = try layout.resident(session, abi.Channel, states, states.len);
            const dst = try layout.resident(session, u32, terminal, 1);
            if (layout.overlap(src.range, dst.range)) return error.OverlappingDeviceRange;
            try common.record(session, .decommit, Api.stwo_blake3_channel_verdict_on(src.pointer, try common.count(states.len), &dst.pointer[0], session.context.stream));
        }
    };
}
