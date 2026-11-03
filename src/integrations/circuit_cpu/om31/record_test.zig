const std = @import("std");
const R = @import("record.zig");
const E = @import("program.zig");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
fn get(_: *const anyopaque, tree: u8, col: u32, offset: i32) !P.O {
    const seed = @as(u32, tree) * 173 + col * 19 + @as(u32, @bitCast(offset));
    var coordinates: [8]P.M = undefined;
    for (&coordinates, 0..) |*c, i| c.* = P.M.fromU64(@as(u64, seed) + i * 1777 + 13);
    return P.O.fromM31Array(coordinates);
}
test "outer OM31 GPU polynomial groups exactly match all original native AIR roots" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Air.parse(a, bytes);
    defer bundle.deinit();
    var groups: usize = 0;
    for (bundle.components) |*component| {
        const parameters = try a.alloc(P.O, component.ext_sources.len);
        defer a.free(parameters);
        for (parameters, 0..) |*value, i| value.* = try get(&bundle, 2, @intCast(i), 0);
        for (component.parts, 0..) |part, pi| {
            const expected = try E.evaluate(a, part.program, .{ .context = &bundle, .get = get }, parameters);
            defer a.free(expected);
            var start: u32 = 0;
            while (start < expected.len) {
                const count = @min(R.MAX_ROOTS, @as(u32, @intCast(expected.len)) - start);
                var artifact = try R.record(a, component, pi, start, count);
                defer artifact.deinit();
                const invocation = try artifact.parameters(a, parameters);
                defer a.free(invocation);
                @memcpy(artifact.program.parameters, invocation);
                const inputs = try a.alloc(P.O, artifact.program.inputs.len);
                defer a.free(inputs);
                for (inputs, artifact.program.inputs) |*value, input| value.* = try get(&bundle, input.tree, input.column, input.offset);
                const actual = try artifact.program.evaluate(a, inputs);
                defer a.free(actual);
                for (actual, expected[start..][0..count]) |got, want| try std.testing.expect(got.eql(want));
                const degrees = try artifact.program.degrees(a);
                defer a.free(degrees);
                for (artifact.program.roots) |root| try std.testing.expect(degrees[root] <= 3);
                start += count;
                groups += 1;
            }
        }
    }
    std.debug.print("OM31_OUTER_GPU_RECORD components={} groups={} exact_native_roots=true degree_le3=true\n", .{ bundle.components.len, groups });
}
