//! Actual OP packet CPU proof: OWNER GKR, all80RAM words and Wire-joined truth.
const std = @import("std");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const Join = @import("pure_p2_op_cpu_fixture.zig");
const CPU = @import("pure_p2_cpu_leaf_test.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const Hook = struct {
    pub fn run(a: std.mem.Allocator, join: Join.VerifiedJoin) !void {
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, join.encoded.bytes);
        defer native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), join.setup, join.key.profile.config());
        const values = try V.proof.fromNative(arena.allocator(), &native, join.capture, &shape);
        const source = CPU.ShapeView{ .op_span = join.span, .setup = join.setup, .request = join.request, .first = join.first_ids, .expected = join.expected, .key = join.key, .manifest = join.manifest.digest, .main = native.commitment_scheme_proof.commitments.items[1], .receipt = join.stage_one.local.?.receipt, .claims = join.encoded.claims, .child = join.stage_one.local.?.proof, .shape = &shape, .values = &values };
        var phases: CPU.CompleteCounts = .{};
        var timer = try std.time.Timer.start();
        var owner = try source.build(a, false, &phases);
        var owns_owner = true;
        defer if (owns_owner) owner.deinit();
        const build_ns = timer.read();
        const outputs = try source.expectedOutput(a);
        var old = source;
        old.op_span = null;
        try std.testing.expectError(error.UnsupportedOpPurePoseidonStatement, old.build(a, false, null));
        var wrong = source;
        wrong.op_span.?.first_id += 1;
        const wrong_outputs = try wrong.expectedOutput(a);
        try std.testing.expect(!std.mem.eql(u8, std.mem.asBytes(&outputs), std.mem.asBytes(&wrong_outputs)));
        // Counts are source-admitted publics consumed by the tower AIR, not
        // an unbound field in a receipt: keep source-ID/proof fixed and falsify.
        try std.testing.expectError(error.TestUnexpectedResult, wrong.build(a, false, null));
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actualOP_CPU_with_OWNER_RAM80_Wire32_and_Miller_truth_native_join", .raw = try owner.rawCounts(), .cells = try owner.census(false), .phases = phases, .native_assignment_exact = true, .span_mutation_rejected = true, .legacy_constructor_rejected = true, .production_admission_open = false, .recursive_root_accepted = false }, .{});
        defer a.free(json);
        std.debug.print("OP_PURE_P2_OP_CPU_CIRCUIT {s}\n", .{json});
        // A fresh source graph must derive exactly the same layout authority.
        {
            var receiver_source = try source.build(a, true, null);
            defer receiver_source.deinit();
            try std.testing.expectEqualDeep(try owner.rawCounts(), try receiver_source.rawCounts());
        }
        if (std.posix.getenv("STWO_OP_P2_OP_CPU_PHYSICAL")) |selection| {
            if (std.mem.eql(u8, selection, "1")) {
                owns_owner = false;
                try CPU.proveSourcePhysical(a, source, owner, build_ns, "OP_PURE_P2_OP_CPU");
            } else if (selection.len != 0 and !std.mem.eql(u8, selection, "0")) return error.InvalidOpP2PhysicalGateSelection;
        }
    }
};
test "OP pure P2 OP CPU packet leaf authenticates span OWNER RAM and native truth join" {
    try Join.exercise(Hook);
}
