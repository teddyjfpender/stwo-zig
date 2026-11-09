//! Shared pinned OP capture/request planning. This owns execution advice once;
//! it does not build FIXED keys, grant source-suite admission or accept proofs.
const std = @import("std");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Capture = @import("pure_p2_op_capture.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Plan = @import("../word16_global_execution/ethereum/plan.zig");
const Coverage = @import("../word16_execution/coverage.zig");
pub const Options = struct {
    local_truth: bool,
    truth_limits: struct { live_bytes: usize, main_bytes: usize, interaction_bytes: usize, gkr_bytes: usize },
    /// Internal source planner choice; production suite validation is separate.
    detached_sponge: bool = false,
    extra_workers: usize = 0,
    capture_hooks: Capture.Hooks = .{},
};
pub const Timing = struct { image_ns: u64, program_ns: u64, capture_ns: u64, captured_at: u64 };
pub const Owner = struct {
    allocator: std.mem.Allocator,
    image: *Image.Owner,
    program: *Program,
    captured: Capture.Owner,
    declarations: []Wire.CpuDeclaration,
    requests: []P.Request,
    spans: []T.OpTowerSpan,
    compact: []Wire.CompactRequest,
    tower: []Bounds.OpTowerTruthDeclaration,
    truths: []Wire.TruthDeclaration,
    timing: Timing,
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        a.free(self.truths);
        a.free(self.tower);
        a.free(self.compact);
        a.free(self.spans);
        a.free(self.requests);
        a.free(self.declarations);
        self.captured.deinit();
        self.program.deinit();
        a.destroy(self.program);
        self.image.deinit();
        a.destroy(self.image);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, config: Request.Config, profile: @import("op_profile.zig").Profile, options: Options, timer: *std.time.Timer) !Owner {
        try Request.validateBudgetForOp(config);
        const image = try a.create(Image.Owner);
        errdefer a.destroy(image);
        image.* = try Image.Owner.initForOp(a, config);
        errdefer image.deinit();
        const image_ns = timer.read();
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.initWithAuthority(a, &image.authority);
        errdefer program.deinit();
        try program.makeCompact();
        const program_ns = timer.read() - image_ns;
        const capture_start = timer.read();
        var captured = try Capture.Owner.initWithHooks(a, config, image, program, options.capture_hooks);
        errdefer captured.deinit();
        const captured_at = timer.read();
        const count = captured.native.len;
        const declarations = try a.alloc(Wire.CpuDeclaration, count);
        errdefer a.free(declarations);
        const req = try a.alloc(P.Request, count);
        errdefer a.free(req);
        const spans = try a.alloc(T.OpTowerSpan, count);
        errdefer a.free(spans);
        const compact = try a.alloc(Wire.CompactRequest, count);
        errdefer a.free(compact);
        var next: u32 = 1;
        var total: [T.FAMILIES]u32 = @splat(0);
        for (captured.native, 0..) |n, i| {
            declarations[i] = try Plan.cpuForSegment(n, &captured.advice, i, count, captured.advice.initial.len, Plan.CpuLayout.forOpGkr());
            // Only the explicit detached planner removes this original
            // provider. Classical admission and source modes stay unchanged.
            if (options.detached_sponge) declarations[i].bridges.sponge = .{};
            const calls = std.math.cast(u32, captured.advice.tower[i].len) orelse return error.InvalidOpTowerCoverage;
            spans[i] = if (calls == 0) .{} else .{ .calls = calls, .first_id = next };
            next = try std.math.add(u32, next, calls);
            if (calls != 0) declarations[i].bridges.tower = try Coverage.minimalPrefixLog(try std.math.mul(u32, calls, 32));
            req[i] = try Coordinator.requestView(captured.native, &captured.advice, i);
            try Coordinator.routeDword(&req[i], declarations[i].bridges, captured.advice.events[i]);
            for (&total, req[i].calls) |*sum, value| sum.* = try std.math.add(u32, sum.*, value);
            total[0] = try std.math.add(u32, total[0], req[i].sponge.perms);
        }
        try Coordinator.assignSpongeIds(req);
        for (req, compact) |r, *out| out.* = Wire.CompactRequest.from(r);
        var tower: std.ArrayList(Bounds.OpTowerTruthDeclaration) = .empty;
        defer tower.deinit(a);
        var first: u32 = 1;
        while (first < next) {
            const calls = @min(1023, next - first);
            const log = @max(15, try Coverage.minimalPrefixLog(try std.math.mul(u32, calls, 32)));
            try tower.append(a, .{ .calls = calls, .first_id = first, .frontier_log = log, .arithmetic_log = log });
            first += calls;
        }
        const reserved_workers = try std.math.add(usize, try std.math.add(usize, count, tower.items.len), options.extra_workers);
        if (reserved_workers > @import("pure_p2_manifest.zig").MAX_WORKERS) return error.InvalidOpNativeInventory;
        const truths = if (options.local_truth)
            try @import("pure_p2_truth_local_plan.zig").declarations(a, total, profile.config(), options.truth_limits, @import("pure_p2_manifest.zig").MAX_WORKERS - reserved_workers)
        else
            try Plan.truthsForServiceCounts(a, total, .{}, 18);
        errdefer a.free(truths);
        return .{ .allocator = a, .image = image, .program = program, .captured = captured, .declarations = declarations, .requests = req, .spans = spans, .compact = compact, .tower = try tower.toOwnedSlice(a), .truths = truths, .timing = .{ .image_ns = image_ns, .program_ns = program_ns, .capture_ns = captured_at - capture_start, .captured_at = captured_at } };
    }
};
