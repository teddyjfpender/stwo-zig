//! Experimental real-prover PCS offload. CPU trace/GKR/composition remain
//! explicit hybrid stages; GPU failure is terminal, never a silent fallback.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Export = @import("pcs_request_export.zig");
const Assembly = @import("pcs_assembly.zig");
const F = @import("fri.zig");
const T = @import("trace.zig");
pub const Context = struct {
    helper: []const u8,
    directory: []const u8,
    mutex: std.Thread.Mutex = .{},
    serial: u64 = 0,
    pub fn stage(self: *@This()) D.Stage {
        return .{ .context = self, .prove = prove };
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        const ordinal = self.serial;
        self.serial += 1;
        const input = try std.fmt.allocPrint(a, "{s}/pcs-{}.input", .{ self.directory, ordinal });
        defer a.free(input);
        const output = try std.fmt.allocPrint(a, "{s}/pcs-{}.output", .{ self.directory, ordinal });
        defer a.free(output);
        var total = try std.time.Timer.start();
        var metadata = try Export.exportRequest(a, request, channel.*, input);
        defer metadata.deinit(a);
        const export_ns = total.read();
        var child = std.process.Child.init(&.{ self.helper, input, output }, a);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        const term = try child.spawnAndWait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.GpuPcsFailed,
            else => return error.GpuPcsFailed,
        }
        const device_process_ns = total.read() - export_ns;
        var decoded = try decode(a, metadata.shape, output);
        errdefer decoded.proof.deinit(a);
        // Host formatting carries no field arithmetic. Native final reception
        // still verifies all PCS/AIR/manifest obligations independently.
        channel.* = decoded.channel;
        var coefficient_cells: usize = 0;
        for (request.trees) |tree| for (tree.columns) |column| {
            coefficient_cells += column.coefficients.len;
        };
        std.debug.print("GPU_PCS ordinal={} export_ns={} process_ns={} total_ns={} coefficient_cells={}\n", .{ ordinal, export_ns, device_process_ns, total.read(), coefficient_cells });
        return .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    }
};
const Reader = struct {
    words: []const u32,
    cursor: usize = 0,
    fn take(self: *@This(), n: usize) ![]const u32 {
        if (n > self.words.len - self.cursor) return error.TruncatedGpuPcsProof;
        const values = self.words[self.cursor..][0..n];
        self.cursor += n;
        return values;
    }
};
pub const Decoded = struct { proof: D.P.CommitmentSchemeProof(D.H), channel: D.Channel };
fn decode(a: std.mem.Allocator, shape: Assembly.Shape, path: []const u8) !Decoded {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(bytes);
    if (bytes.len % 4 != 0) return error.InvalidGpuPcsProof;
    const words = try a.alloc(u32, bytes.len / 4);
    defer a.free(words);
    for (words, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return decodeWords(a, shape, words);
}
pub fn decodeWords(a: std.mem.Allocator, shape: Assembly.Shape, words: []const u32) !Decoded {
    var r = Reader{ .words = words };
    const header = try r.take(14);
    const plan = try F.Plan.init(shape.degree_log, shape.config.fri_config);
    if (header[0] != 0x52564d4f or header[1] != 2 or header[7] != shape.trees.len or header[9] != plan.len or header[10] != plan.initial_log or header[11] != plan.queries or header[12] != shape.degree_log) return error.InvalidGpuPcsProof;
    if ((try r.take(1))[0] != 0) return error.GpuPcsNumericalFailure;
    const state = try r.take(16);
    if (state[9] != header[13] or state[10] != 0 or state[11] != 0 or state[12] != 17 + header[13] or !std.mem.allEqual(u32, state[13..], 0)) return error.GpuPcsChannelFailure;
    var channel = D.Channel.init();
    for (0..8) |i| std.mem.writeInt(u32, channel.inner.digest[i * 4 ..][0..4], state[i], .little);
    channel.inner.n_draws = state[8];
    const roots = try r.take(shape.trees.len * 8);
    var sample_count: usize = 0;
    for (shape.trees) |tree| for (tree.sample_counts) |count| {
        sample_count += count;
    };
    if (header[8] != sample_count) return error.InvalidGpuPcsProof;
    const samples = try r.take(sample_count * 8);
    const nonce = try r.take(2);
    const terminal = try r.take(8);
    const queries = try r.take(plan.queries);
    const layers = try a.alloc(F.LayerReadback, plan.len);
    defer a.free(layers);
    for (layers, plan.layers[0..plan.len]) |*layer, item| layer.* = .{ .root = (try r.take(8))[0..8].*, .values = try r.take(item.valueWords(plan.queries)), .paths = try r.take(item.pathWords(plan.queries)) };
    const trace = try a.alloc(T.Readback, shape.trees.len);
    defer a.free(trace);
    for (shape.trees, trace, 0..) |tree, *readback, t| readback.* = .{ .root = roots[t * 8 ..][0..8].*, .values = try r.take(tree.coefficient_logs.len * plan.queries), .paths = try r.take(@as(usize, plan.queries) * (std.mem.max(u32, tree.coefficient_logs) + shape.config.fri_config.log_blowup_factor) * 8) };
    if (r.cursor != words.len) return error.InvalidGpuPcsProof;
    return .{ .proof = try Assembly.assemble(a, shape, .{ .raw_queries = queries, .samples = samples, .trace = trace, .fri = layers, .terminal = terminal[0..8].*, .nonce = @as(u64, nonce[0]) | (@as(u64, nonce[1]) << 32) }), .channel = channel };
}
