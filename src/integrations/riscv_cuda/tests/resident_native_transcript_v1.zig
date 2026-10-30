const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const ABI = cuda.abi.stages.blake3;
const Q = core.fields.qm31.QM31;
const T = @import("../resident_native_transcript_v1.zig");
const Native = @import("../../../frontends/riscv/prover/block_v7_native_proof_v1.zig");
const Fused = @import("../../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");

fn view(comptime F: type, items: []F) cuda.runtime.column.DeviceSlice(F) {
    return .{ .address = @intFromPtr(items.ptr), .len = items.len, .owner = 1, .generation = 1 };
}
fn words(v: common.Words) []u32 {
    return @as([*]u32, @ptrFromInt(v.address))[0..v.len];
}
const Mock = struct {
    context: Context = .{},
    channel: core.proof_suites.Blake3.Channel = .{},
    const Context = struct {
        active_stage: cuda.runtime.telemetry.Stage = .ingress,
        pub fn requireStage(self: *Context, stage: cuda.runtime.telemetry.Stage) !void {
            if (self.active_stage != stage) return error.StageOrderViolation;
        }
        pub fn uploadSlice(_: *Context, comptime F: type, target: cuda.runtime.column.DeviceSlice(F), source: []const F) !void {
            if (target.len != source.len) return error.SizeOverflow;
            @memcpy(@as([*]F, @ptrFromInt(target.address))[0..target.len], source);
        }
    };
};
const Ops = struct {
    pub fn channel(s: *Mock, stage: cuda.runtime.telemetry.Stage, _: cuda.runtime.stages.blake3.Channels, v: common.Words, count: u32, op: ABI.Operation, _: u32) !void {
        try s.context.requireStage(stage);
        const data = words(v);
        switch (op) {
            .init => s.channel = .{},
            .words => s.channel.mixU32s(data[0..count]),
            .root => {
                var root: [32]u8 = undefined;
                for (data[0..8], 0..) |w, i| std.mem.writeInt(u32, root[4 * i ..][0..4], w, .little);
                s.channel.mixRoot(root);
            },
            .integer => s.channel.mixU64(@as(u64, data[0]) | (@as(u64, data[1]) << 32)),
            .felts => {
                const f = try std.testing.allocator.alloc(Q, count / 4);
                defer std.testing.allocator.free(f);
                for (f, 0..) |*x, i| x.* = Q.fromU32Unchecked(data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]);
                s.channel.mixFelts(f);
            },
            .secure => {
                const f = try s.channel.drawSecureFelts(std.testing.allocator, count);
                defer std.testing.allocator.free(f);
                for (f, 0..) |x, i| for (x.toM31Array(), 0..) |m, j| {
                    data[4 * i + j] = m.v;
                };
            },
            else => return error.UnexpectedNativeTranscriptOp,
        }
    }
    pub fn requireRoot(s: *Mock, expected: common.Words, actual: common.Words, status: common.Words) !void {
        try s.context.requireStage(.trace_commit);
        if (!std.mem.eql(u32, words(expected), words(actual))) words(status)[0] |= 1 << 21;
    }
    pub fn grind(s: *Mock, _: cuda.runtime.stages.blake3.Channels, bits: u32, _: u64, _: u32, nonce: common.Nonce) !void {
        try s.context.requireStage(.pow);
        const n = s.channel.grind(bits);
        @as(*u64, @ptrFromInt(nonce.address)).* = n;
        s.channel.mixU64(n);
    }
    pub fn drawQueries(s: *Mock, _: cuda.runtime.stages.blake3.Channels, log: u32, out: common.Words) !void {
        try s.context.requireStage(.decommit);
        const qs = try core.queries.drawQueries(&s.channel, std.testing.allocator, log, out.len);
        defer std.testing.allocator.free(qs);
        for (words(out), qs) |*v, q| v.* = @intCast(q);
    }
    pub fn sealError(_: *Mock, _: cuda.runtime.stages.blake3.Channels, _: common.Words) !void {}
};
fn readQ(v: []const u32) Q {
    return Q.fromU32Unchecked(v[0], v[1], v[2], v[3]);
}
fn fillQ(v: []u32, q: Q) void {
    for (q.toM31Array(), 0..) |m, i| v[i] = m.v;
}

test "native transcript original four five tree exact prefix claims and full suffix" {
    const a = std.testing.allocator;
    inline for (.{ 4, 5 }) |N| {
        const p = try @import("../resident_native_plan_test_v1.zig").fixture(N, a, true);
        defer p.deinit();
        const profile = p.view().profile;
        var static = try T.ForCommitments(N).Static.derive(a, p);
        defer static.deinit();
        var device_state: [1]ABI.Channel = undefined;
        const sw = try a.alloc(u32, static.count);
        defer a.free(sw);
        var draws: [424]u32 = undefined;
        const routes = try a.alloc(u32, static.claims.routes.len * 4);
        defer a.free(routes);
        const fields = try a.alloc(u32, static.claims.statement.felts.len * 4);
        defer a.free(fields);
        @memset(fields, 0);
        const counts = try a.alloc(u64, static.claims.access_count);
        defer a.free(counts);
        @memset(counts, 0);
        var status = [_]u32{0};
        const bindings: T.Bindings = .{ .state = view(ABI.Channel, &device_state), .static_words = view(u32, sw), .draws = try view(u32, &draws).cast(cuda.abi.field.SecureField), .route_words = view(u32, routes), .statement_fields = try view(u32, fields).cast(cuda.abi.field.SecureField), .count_words = try view(u64, counts).cast(u32), .error_flag = view(u32, &status) };
        var session = Mock{};
        const Sink = T.ForCommitments(N).Sink(Mock, Ops);
        var sink = try Sink.init(&session, p, &static, bindings);
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.initialize());
        try sink.prime();
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.prime());
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.initialize());
        var wrong = bindings;
        wrong.draws.len -= 1;
        try std.testing.expectError(error.InvalidResidentNativeTranscript, Sink.init(&session, p, &static, wrong));
        wrong = bindings;
        wrong.error_flag = try wrong.static_words.sub(0, 1);
        try std.testing.expectError(error.InvalidResidentNativeTranscript, Sink.init(&session, p, &static, wrong));
        try std.testing.expectError(error.StageOrderViolation, sink.checkFirstRoot(0, view(u32, sw[0..8])));
        session.context.active_stage = .trace_commit;
        var hostile_sink = sink;
        var wrong_root: [8]u32 = undefined;
        @memcpy(&wrong_root, static.words[static.statement_first + static.claims.statement.roots_offset[0] ..][0..8]);
        wrong_root[0] ^= 1;
        try hostile_sink.checkFirstRoot(0, view(u32, &wrong_root));
        try std.testing.expectEqual(@as(u32, 1 << 21), status[0]);
        status[0] = 0;
        for (0..N - 2) |i| {
            var root: [8]u32 = undefined;
            @memcpy(&root, static.words[static.statement_first + static.claims.statement.roots_offset[i] ..][0..8]);
            try sink.checkFirstRoot(i, view(u32, &root));
        }
        try std.testing.expectEqual(@as(u32, 0), status[0]);
        try sink.initialize();
        const drawn = try profile.epoch.draw(a);
        try std.testing.expectEqualDeep(drawn.channel, session.channel);
        for (drawn.word.universal_prefix.elements, 0..) |e, i| {
            try std.testing.expectEqualDeep(e.z, readQ(draws[8 * i ..]));
            try std.testing.expectEqualDeep(e.alpha, readQ(draws[8 * i + 4 ..]));
        }
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
            const e = @field(drawn.word, name);
            try std.testing.expectEqualDeep(e.z, readQ(draws[376 + 8 * i ..]));
            try std.testing.expectEqualDeep(e.alpha, readQ(draws[380 + 8 * i ..]));
        }
        try std.testing.expectEqualDeep(drawn.memory.interval.z, readQ(draws[416..]));
        try std.testing.expectEqualDeep(drawn.memory.interval.powers[1], readQ(draws[420..]));
        const physical = try a.alloc(u32, static.claims.source_words);
        defer a.free(physical);
        @memset(physical, 0);
        const claims = try a.alloc(Fused.Claim, profile.projections.len);
        defer a.free(claims);
        for (claims, profile.projections, 0..) |*claim, slot, i| {
            claim.* = .{ .sum = Q.fromU32Unchecked(@intCast(i + 1), 3, 5, 7), .row_count = slot.n_rows };
            fillQ(physical[4 * i ..], claim.sum);
        }
        const memory = try a.alloc(Memory.Claim, profile.slots.len);
        defer a.free(memory);
        for (memory, 0..) |*m, i| {
            m.* = .{ .transition_sum = Q.fromU32Unchecked(11, @intCast(i + 2), 13, 17), .universal_sum = Q.fromU32Unchecked(19, 23, 29, @intCast(i + 3)), .active_count = 1, .range_claims = undefined };
            const first = claims.len * 4 + i * 40;
            fillQ(physical[first..], m.transition_sum);
            fillQ(physical[first + 4 ..], m.universal_sum);
            physical[first + 8] = 1;
            for (&m.range_claims, 0..) |*q, j| {
                q.* = Q.fromU32Unchecked(@intCast(31 + j), 37, 41, 43);
                fillQ(physical[first + 12 + j * 4 ..], q.*);
            }
        }
        // Test-only host simulation of the independently tested ClaimPack routes.
        // Production Sink never reads these values or patches them on the CPU.
        for (static.claims.routes) |route| switch (route.kind) {
            .word => sw[static.statement_first + route.destination] = physical[route.source],
            .field => fields[route.destination] = physical[route.source],
            .count => {
                sw[static.statement_first + route.destination] = physical[route.source];
                sw[static.statement_first + route.destination + 1] = 0;
                counts[(route.source - claims.len * 4) / 40] = physical[route.source];
            },
        };
        var expected = try Native.channel(&drawn, profile.pin, try profile.pin.entry(a), profile.projections, profile.slots, claims, memory);
        try sink.mixClaims();
        try std.testing.expectEqualDeep(expected, session.channel);
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.mixClaims());
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.mixTraceRoot(0, view(u32, sw[0..8])));
        var rootwords = [_]u32{ 1, 3, 5, 7, 11, 13, 17, 19 };
        var rootbytes: [32]u8 = undefined;
        for (rootwords, 0..) |v, i| std.mem.writeInt(u32, rootbytes[4 * i ..][0..4], v, .little);
        try sink.mixTraceRoot(N - 2, view(u32, &rootwords));
        expected.mixRoot(rootbytes);
        var qwords: [4]u32 = undefined;
        const qout = try view(u32, &qwords).cast(cuda.abi.field.SecureField);
        session.context.active_stage = .constraint_evaluation;
        try sink.drawCompositionAlpha(qout);
        try std.testing.expectEqualDeep(expected.drawSecureFelt(), readQ(&qwords));
        try sink.mixTraceRoot(N - 1, view(u32, &rootwords));
        expected.mixRoot(rootbytes);
        session.context.active_stage = .oods;
        try sink.drawOodsParameter(qout);
        try std.testing.expectEqualDeep(expected.drawSecureFelt(), readQ(&qwords));
        const sample = try a.alloc(Q, static.sample_count);
        defer a.free(sample);
        @memset(sample, Q.fromU32Unchecked(47, 53, 59, 61));
        const sv = try view(Q, sample).cast(cuda.abi.field.SecureField);
        try std.testing.expectError(error.InvalidResidentNativeTranscript, sink.mixSamples(sv, static.sample_count + 1));
        try sink.mixSamples(sv, static.sample_count);
        expected.mixFelts(sample);
        session.context.active_stage = .quotient;
        try sink.drawQuotientAlpha(qout);
        try std.testing.expectEqualDeep(expected.drawSecureFelt(), readQ(&qwords));
        try sink.setFriLayers(@intCast(p.view().fri_layers.len));
        session.context.active_stage = .fri_commit;
        for (p.view().fri_layers) |_| {
            try sink.mixFriRoot(view(u32, &rootwords));
            expected.mixRoot(rootbytes);
            try sink.drawFriAlpha(qout);
            try std.testing.expectEqualDeep(expected.drawSecureFelt(), readQ(&qwords));
        }
        const last = try a.alloc(Q, @as(usize, 1) << @intCast(profile.epoch.config.fri_config.log_last_layer_degree_bound));
        defer a.free(last);
        @memset(last, Q.fromU32Unchecked(67, 71, 73, 79));
        try sink.mixLastLayer(try view(Q, last).cast(cuda.abi.field.SecureField));
        expected.mixFelts(last);
        session.context.active_stage = .pow;
        var nonce = [_]u64{0};
        try sink.absorbQueryPow(view(u64, &nonce));
        const en = expected.grind(profile.epoch.config.pow_bits);
        expected.mixU64(en);
        try std.testing.expectEqual(en, nonce[0]);
        session.context.active_stage = .decommit;
        const queries = try a.alloc(u32, profile.epoch.config.fri_config.n_queries);
        defer a.free(queries);
        try sink.drawQueries(view(u32, queries), p.view().fri_log);
        const eq = try core.queries.drawQueries(&expected, a, p.view().fri_log, queries.len);
        defer a.free(eq);
        for (eq, queries) |x, y| try std.testing.expectEqual(x, y);
        try sink.sealVerdict(view(u32, &status));
        try sink.requireComplete();
        try std.testing.expectEqualDeep(expected, session.channel);
    }
}

test "native transcript native runtime semantic" {
    inline for (.{ 4, 5 }) |N| {
        const S = T.ForCommitments(N).NativeSink;
        inline for (.{ T.ForCommitments(N).Static.bind, T.ForCommitments(N).Static.requirements, S.init, S.claimBindings, S.prime, S.checkFirstRoot, S.initialize, S.mixClaims, S.mixTraceRoot, S.drawCompositionAlpha, S.drawOodsParameter, S.mixSamples, S.drawQuotientAlpha, S.setFriLayers, S.mixFriRoot, S.drawFriAlpha, S.mixLastLayer, S.absorbQueryPow, S.drawQueries, S.sealVerdict, S.requireComplete }) |method| std.mem.doNotOptimizeAway(&method);
    }
}
