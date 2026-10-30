//! Exact original native-source transcript for the finite four/five-tree roster.
//! Only public immutable grammar is uploaded. Claims, roots, challenges, samples,
//! query nonces and queries stay resident throughout the original proof.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const B3 = cuda.runtime.stages.blake3;
const ABI = cuda.abi.stages.blake3;
const Stage = cuda.runtime.telemetry.Stage;
const Epoch = @import("resident_native_epoch_v1.zig");
const ClaimRoutes = @import("resident_native_claim_routes_v1.zig");
const ClaimPack = @import("resident_native_claim_pack_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 86016;
pub const Bindings = struct {
    state: B3.Channels,
    static_words: common.Words,
    draws: common.SecureFields,
    route_words: common.Words,
    statement_fields: common.SecureFields,
    count_words: common.Words,
    error_flag: common.Words,
};
pub const NativeOps = struct {
    pub const channel = B3.Native.channel;
    pub const grind = B3.Native.grind;
    pub const drawQueries = B3.Native.drawQueries;
    pub const sealError = B3.Native.sealError;
    pub const requireRoot = ClaimPack.requireRoot;
};
pub fn ForCommitments(comptime N: usize) type {
    const Program = @import("resident_native_program_v1.zig").ForCommitments(N);
    return struct {
        pub const Static = struct {
            allocator: std.mem.Allocator,
            epoch: Epoch.Plan,
            claims: *ClaimRoutes.Plan,
            words: []const u32,
            statement_first: usize,
            epoch_root_first: usize,
            count: usize,
            sample_count: usize,
            program_identity: [32]u8,
            pub fn derive(a: std.mem.Allocator, program: *const Program.Owned) !Static {
                const p = program.view();
                try p.profile.validate();
                var epoch = try Epoch.Plan.init(a, p.profile.epoch);
                errdefer epoch.deinit();
                const claims = try ClaimRoutes.Plan.init(a, p.profile);
                errdefer claims.deinit();
                if (claims.source_words != p.physical_claim_count * 4) return error.InvalidResidentNativeTranscript;
                const statement_first = epoch.words.len;
                const root_first = try std.math.add(usize, statement_first, claims.statement.words.len);
                const count = try std.math.add(usize, root_first, 8);
                if (count > std.math.maxInt(u32)) return error.InvalidResidentNativeTranscript;
                const words = try a.alloc(u32, count);
                errdefer a.free(words);
                @memcpy(words[0..statement_first], epoch.words);
                @memcpy(words[statement_first..root_first], claims.statement.words);
                for (words[root_first..], 0..) |*w, i| w.* = std.mem.readInt(u32, p.profile.epoch.digest[4 * i ..][0..4], .little);
                return .{ .allocator = a, .epoch = epoch, .claims = claims, .words = words, .statement_first = statement_first, .epoch_root_first = root_first, .count = count, .sample_count = try p.profile.sampleCount(), .program_identity = p.identity };
            }
            pub fn deinit(self: *Static) void {
                self.allocator.free(self.words);
                self.claims.deinit();
                self.epoch.deinit();
                self.* = undefined;
            }
            /// Caller frees only this metadata slice. All buffers belong to the
            /// original proof transaction; no independent device allocations.
            pub fn requirements(self: *const Static, a: std.mem.Allocator) ![]cuda.runtime.arena.Requirement {
                const out = try a.alloc(cuda.runtime.arena.Requirement, 3);
                out[0] = .{ .id = FIRST_ID, .words = @max(1, self.claims.routes.len * @sizeOf(ClaimRoutes.Route) / 4), .alignment_words = 4, .live_from = .ingress, .live_through = .trace_commit };
                out[1] = .{ .id = FIRST_ID + 1, .words = @max(4, self.claims.statement.felts.len * 4), .alignment_words = 4, .live_from = .ingress, .live_through = .trace_commit };
                out[2] = .{ .id = FIRST_ID + 2, .words = @max(2, self.claims.access_count * 2), .alignment_words = 2, .live_from = .ingress, .live_through = .proof_assembly };
                return out;
            }
            pub fn bind(self: *const Static, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, state: B3.Channels, words: common.Words, draws: common.SecureFields, status: common.Words) !Bindings {
                return .{ .state = state, .static_words = words, .draws = draws, .route_words = try (try tx.slot(FIRST_ID)).sub(0, self.claims.routes.len * @sizeOf(ClaimRoutes.Route) / 4), .statement_fields = try (try (try tx.slot(FIRST_ID + 1)).sub(0, self.claims.statement.felts.len * 4)).cast(cuda.abi.field.SecureField), .count_words = try (try tx.slot(FIRST_ID + 2)).sub(0, self.claims.access_count * 2), .error_flag = status };
            }
        };
        pub fn Sink(comptime Session: type, comptime Ops: type) type {
            return struct {
                const Self = @This();
                session: *Session,
                program: *const Program.Owned,
                static: *const Static,
                bindings: Bindings,
                next: u32 = 0,
                first_roots_checked: usize = 0,
                fri_layers: u32 = 0,
                fri_cursor: u32 = 0,
                primed: bool = false,
                grind_limit: u64 = @as(u64, 1) << 36,
                grind_blocks: u32 = 256,
                pub fn init(session: *Session, program: *const Program.Owned, static: *const Static, bindings: Bindings) !Self {
                    if (!std.mem.eql(u8, &program.view().identity, &static.program_identity) or bindings.state.len != 1 or bindings.static_words.len != static.count or bindings.draws.len != Epoch.DRAW_COUNT or bindings.route_words.len != static.claims.routes.len * @sizeOf(ClaimRoutes.Route) / 4 or bindings.statement_fields.len != static.claims.statement.felts.len or bindings.count_words.len != static.claims.access_count * 2 or bindings.error_flag.len != 1) return error.InvalidResidentNativeTranscript;
                    const spans = [_]common.Words{ try bindings.state.cast(u32), bindings.static_words, try bindings.draws.cast(u32), bindings.route_words, try bindings.statement_fields.cast(u32), bindings.count_words, bindings.error_flag };
                    for (spans, 0..) |span, i| {
                        if (span.owner != bindings.state.owner or span.generation != bindings.state.generation) return error.InvalidResidentNativeTranscript;
                        const end = try std.math.add(usize, span.address, try std.math.mul(usize, 4, span.len));
                        for (spans[0..i]) |prior| if (span.len != 0 and prior.len != 0 and span.address < try std.math.add(usize, prior.address, try std.math.mul(usize, 4, prior.len)) and prior.address < end) return error.InvalidResidentNativeTranscript;
                    }
                    return .{ .session = session, .program = program, .static = static, .bindings = bindings };
                }
                pub fn claimBindings(self: *const Self) !ClaimPack.Bindings {
                    return .{ .routes = self.bindings.route_words, .words = try self.bindings.static_words.sub(self.static.statement_first, self.static.claims.statement.words.len), .fields = self.bindings.statement_fields, .counts = self.bindings.count_words, .error_flag = self.bindings.error_flag };
                }
                pub fn prime(self: *Self) !void {
                    if (self.primed) return error.InvalidResidentNativeTranscript;
                    try common.requireStage(self.session, .ingress);
                    try self.session.context.uploadSlice(u32, self.bindings.static_words, self.static.words);
                    self.primed = true;
                }
                fn require(self: *const Self, n: u32) !void {
                    if (!self.primed or self.next != n) return error.InvalidResidentNativeTranscript;
                }
                fn channel(self: *Self, stage: Stage, value: common.Words, count: usize, op: ABI.Operation) !void {
                    try Ops.channel(self.session, stage, self.bindings.state, value, @intCast(count), op, 1024);
                }
                fn draw(self: *Self, stage: Stage, output: common.SecureFields, count: usize) !void {
                    if (output.len != count) return error.InvalidResidentNativeTranscript;
                    try self.channel(stage, try output.cast(u32), count, .secure);
                }
                pub fn checkFirstRoot(self: *Self, index: usize, actual: common.Words) !void {
                    try self.require(0);
                    try common.requireStage(self.session, .trace_commit);
                    if (index != self.first_roots_checked or index >= N - 2 or actual.len != 8) return error.InvalidResidentNativeTranscript;
                    const first = self.static.statement_first + self.static.claims.statement.roots_offset[index];
                    try Ops.requireRoot(self.session, try self.bindings.static_words.sub(first, 8), actual, self.bindings.error_flag);
                    self.first_roots_checked += 1;
                }
                pub fn initialize(self: *Self) !void {
                    try self.require(0);
                    if (self.first_roots_checked != N - 2) return error.InvalidResidentNativeTranscript;
                    try self.channel(.trace_commit, try self.bindings.static_words.sub(0, 0), 0, .init);
                    try self.channel(.trace_commit, try self.bindings.static_words.sub(0, 3), 3, .words);
                    try self.channel(.trace_commit, try self.bindings.static_words.sub(self.static.epoch_root_first, 8), 8, .root);
                    for (self.static.epoch.steps) |step| switch (step) {
                        .words => |span| try self.channel(.trace_commit, try self.bindings.static_words.sub(span.first, span.count), span.count, .words),
                        .secure => |span| try self.draw(.trace_commit, try self.bindings.draws.sub(span.first, span.count), span.count),
                    };
                    self.next = 1;
                }
                pub fn mixClaims(self: *Self) !void {
                    try self.require(1);
                    const words = (try self.claimBindings()).words;
                    for (self.static.claims.statement.claims) |step| switch (step) {
                        .words => |span| try self.channel(.trace_commit, try words.sub(span.first, span.len), span.len, .words),
                        .root => |first| try self.channel(.trace_commit, try words.sub(first, 8), 8, .root),
                        .integer => |first| try self.channel(.trace_commit, try words.sub(first, 2), 2, .integer),
                        .felts => |span| try self.channel(.trace_commit, try (try self.bindings.statement_fields.sub(span.first, span.len)).cast(u32), 4 * @as(usize, span.len), .felts),
                    };
                    self.next = 2;
                }
                pub fn mixTraceRoot(self: *Self, index: u32, root: common.Words) !void {
                    const expected: u32 = if (index == N - 2) 2 else if (index == N - 1) 4 else return error.InvalidResidentNativeTranscript;
                    try self.require(expected);
                    if (root.len != 8) return error.InvalidResidentNativeTranscript;
                    try self.channel(if (index == N - 1) .constraint_evaluation else .trace_commit, root, 8, .root);
                    self.next += 1;
                }
                pub fn drawCompositionAlpha(self: *Self, output: common.SecureFields) !void {
                    try self.require(3);
                    try self.draw(.constraint_evaluation, output, 1);
                    self.next = 4;
                }
                pub fn drawOodsParameter(self: *Self, output: common.SecureFields) !void {
                    try self.require(5);
                    try self.draw(.oods, output, 1);
                    self.next = 6;
                }
                pub fn mixSamples(self: *Self, samples: common.SecureFields, expected_count: usize) !void {
                    try self.require(6);
                    if (samples.len != self.static.sample_count or samples.len != expected_count or samples.len == 0) return error.InvalidResidentNativeTranscript;
                    try self.channel(.oods, try samples.cast(u32), 4 * samples.len, .felts);
                    self.next = 7;
                }
                pub fn drawQuotientAlpha(self: *Self, output: common.SecureFields) !void {
                    try self.require(7);
                    try self.draw(.quotient, output, 1);
                    self.next = 8;
                }
                pub fn setFriLayers(self: *Self, count: u32) !void {
                    try self.require(8);
                    if (count != self.program.view().fri_layers.len) return error.InvalidResidentNativeTranscript;
                    self.fri_layers = count;
                    self.next = 9;
                }
                pub fn mixFriRoot(self: *Self, root: common.Words) !void {
                    try self.require(9);
                    if (self.fri_cursor >= self.fri_layers or root.len != 8) return error.InvalidResidentNativeTranscript;
                    try self.channel(.fri_commit, root, 8, .root);
                    self.next = 10;
                }
                pub fn drawFriAlpha(self: *Self, output: common.SecureFields) !void {
                    try self.require(10);
                    try self.draw(.fri_commit, output, 1);
                    self.fri_cursor += 1;
                    self.next = 9;
                }
                pub fn mixLastLayer(self: *Self, coefficients: common.SecureFields) !void {
                    try self.require(9);
                    if (self.fri_cursor != self.fri_layers or coefficients.len != @as(usize, 1) << @intCast(self.program.view().profile.epoch.config.fri_config.log_last_layer_degree_bound)) return error.InvalidResidentNativeTranscript;
                    try self.channel(.fri_commit, try coefficients.cast(u32), 4 * coefficients.len, .felts);
                    self.next = 11;
                }
                pub fn absorbQueryPow(self: *Self, nonce: common.Nonce) !void {
                    try self.require(11);
                    if (nonce.len != 1 or self.grind_limit == 0 or self.grind_blocks == 0) return error.InvalidResidentNativeTranscript;
                    try Ops.grind(self.session, self.bindings.state, self.program.view().profile.epoch.config.pow_bits, self.grind_limit, self.grind_blocks, nonce);
                    self.next = 12;
                }
                pub fn drawQueries(self: *Self, output: common.Words, log_domain: u32) !void {
                    try self.require(12);
                    if (output.len != self.program.view().profile.epoch.config.fri_config.n_queries or log_domain != self.program.view().fri_log) return error.InvalidResidentNativeTranscript;
                    try Ops.drawQueries(self.session, self.bindings.state, log_domain, output);
                    self.next = 13;
                }
                pub fn sealVerdict(self: *Self, terminal: common.Words) !void {
                    try self.require(13);
                    try Ops.sealError(self.session, self.bindings.state, terminal);
                    self.next = 14;
                }
                pub fn requireComplete(self: *const Self) !void {
                    try self.require(14);
                }
            };
        }
        pub const NativeSink = Sink(cuda.runtime.NativeSession, NativeOps);
    };
}
