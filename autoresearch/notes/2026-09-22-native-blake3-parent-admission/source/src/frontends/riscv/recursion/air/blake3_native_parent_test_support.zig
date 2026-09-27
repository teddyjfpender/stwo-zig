//! Real-proof qualification of the complete native row assembler.
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const std = @import("std");
        const native = @import("blake3_native_parent_rows.zig");
        const protocol = @import("../blake3_native_parent_protocol.zig");
        const f = @import("blake3_proof_fixture.zig").ForBackend(Backend);
        const F = @import("blake3_fixture_roster.zig").WithExtras(.{ native.Airs[3], native.Airs[4], native.Airs[5], native.Airs[6], native.Airs[7], native.Airs[8], native.Airs[9], native.Airs[10], native.Airs[11], native.Airs[12], native.Airs[13], native.Airs[14], native.Airs[15], native.Airs[16], native.Airs[17] });
        pub fn check(backing: std.mem.Allocator, prepared: *native.Prepared, context: protocol.Context) !void {
            var arena = std.heap.ArenaAllocator.init(backing);
            defer arena.deinit();
            const a = arena.allocator();
            var rows: @TypeOf(prepared.rows) = undefined;
            var logs: [18]u32 = undefined;
            inline for (F.Airs, 0..) |Air, i| {
                logs[i] = if (prepared.rows[i].len <= 1) 1 else std.math.log2_int_ceil(usize, prepared.rows[i].len);
                rows[i] = try f.padded(Air, a, prepared.rows[i], logs[i]);
                if (i >= 3 and i <= 5) for (rows[i]) |*row| {
                    row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = native.selectors;
                };
            }
            const trusted = try preprocessing(a, prepared.fixed, logs);
            var key_channel = f.Channel{};
            var key_scheme = try f.Scheme.init(a, protocol.PCS_CONFIG);
            defer key_scheme.deinit(a);
            try key_scheme.commit(a, trusted, &key_channel);
            const key_roots = try key_scheme.roots(a);
            const key = protocol.Key{ .context = context, .log_sizes = logs, .preprocessed_root = key_roots.items[0] };
            const expected = try key.identity();
            const admitted = try protocol.Admission.init(key, expected);
            var wrong_pin = expected;
            wrong_pin[31] ^= 0x80;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(key, wrong_pin));
            var wrong_key = key;
            wrong_key.version += 1;
            try std.testing.expectError(error.InvalidBlake3ParentProfile, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.config.fri_config.n_queries += 1;
            try std.testing.expectError(error.InvalidBlake3ParentProfile, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.context.graph_ids[0][0] ^= 1;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(wrong_key, expected));
            wrong_key = key;
            wrong_key.context.child_config.lifting_log_size = 0;
            try std.testing.expectError(error.UntrustedBlake3ParentKey, protocol.Admission.init(wrong_key, expected));
            var changed_root = key.preprocessed_root;
            changed_root[31] ^= 0x80;
            try std.testing.expectError(error.UntrustedBlake3ParentRoot, admitted.admitRoot(changed_root));
            std.debug.print("V2_BLAKE3_NATIVE_PARENT_KEY id={s} profile=diagnostic_q8_pow0\n", .{std.fmt.bytesToHex(expected, .lower)});
            const saved = prepared.fixed[2][0];
            defer prepared.fixed[2][0] = saved;
            prepared.fixed[2][0][8] = saved[8].add(f.M31.one());
            const false_pp = try preprocessing(a, prepared.fixed, logs);
            prepared.fixed[2][0] = saved;
            std.debug.print("V2_BLAKE3_NATIVE_PARENT start inputs={d} g_rows={d} scalar_rows={d} arithmetic_rows={d}\n", .{ prepared.input_count, prepared.rows[0].len, prepared.rows[12].len, prepared.rows[3].len + prepared.rows[4].len + prepared.rows[5].len });
            try @import("blake3_proof_gate_test_support.zig").ForBackend(Backend).runForParametersProtocol(F, a, rows, logs, trusted, false_pp, .{ .{}, .{}, .{}, native.selectors, native.selectors, native.selectors, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{}, .{} }, admitted, void);
            std.debug.print("V2_BLAKE3_NATIVE_PARENT verified\n", .{});
        }
        fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [18]u32) ![]f.Column {
            var columns: std.ArrayList(f.Column) = .empty;
            inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
            for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
            return columns.toOwnedSlice(a);
        }
    };
}
