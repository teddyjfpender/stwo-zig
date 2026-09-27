//! Lazy authentic NEW lower-root source for a statically selected higher
//! topology. Raw windows are never coerced to the old H/six-word grammar.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Base = @import("blake3_execution_parent_protocol.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Recorder = @import("air/blake3_native_recorder.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn ForModules(comptime R: type, comptime Protocol: type, comptime public_circuit: u32) type {
    return struct {
        pub const PUBLIC_CIRCUIT: u32 = public_circuit;
        pub const Coordinate = struct { first_cell: u32, word_count: u32 };
        pub const Window = struct {
            first: Coordinate,
            last: Coordinate,
            pub fn firstCycle(self: Window) Coordinate {
                return self.first;
            }
            pub fn lastCycle(self: Window) Coordinate {
                return self.last;
            }
        };
        const Prefix = struct {
            words: [32]u32 = undefined,
            len: u32 = 0,
            failure: ?anyerror = null,
            pub fn mixU32s(self: *Prefix, v: []const u32) void {
                if (self.failure != null) return;
                const end = std.math.add(usize, self.len, v.len) catch {
                    self.failure = error.InvalidWidePublicPrefix;
                    return;
                };
                if (end > self.words.len) {
                    self.failure = error.InvalidWidePublicPrefix;
                    return;
                }
                @memcpy(self.words[self.len..end], v);
                self.len = @intCast(end);
            }
            pub fn mixRoot(self: *Prefix, v: [32]u8) void {
                var words: [8]u32 = undefined;
                for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, v[4 * i ..][0..4], .little);
                self.mixU32s(&words);
            }
            pub fn mixFelts(self: *Prefix, v: []const Q) void {
                for (v) |value| {
                    const words = value.toM31Array();
                    var raw: [4]u32 = undefined;
                    for (&raw, words) |*word, limb| word.* = limb.v;
                    self.mixU32s(&raw);
                }
            }
        };
        pub fn prefix(admission: *const Protocol.Admission) !Prefix {
            var p = Prefix{};
            p.mixU32s(&.{ 0x42354d50, Protocol.VERSION, @intFromEnum(admission.key.profile) });
            admission.key.config.mixInto(&p);
            p.mixRoot(admission.expected_id);
            if (p.failure) |failure| return failure;
            return p;
        }
        const Replay = struct {
            recorder: *Recorder.Recorder,
            cursor: u32 = 0,
            fn source(self: *Replay, count: usize) @import("air/blake3_transcript_witness.zig").Caller {
                const start = self.cursor;
                self.cursor = std.math.add(u32, self.cursor, std.math.cast(u32, count) orelse {
                    self.recorder.failure = error.InvalidWidePublicCell;
                    return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = start };
                }) catch {
                    self.recorder.failure = error.InvalidWidePublicCell;
                    return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = start };
                };
                return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = start };
            }
            pub fn mixU32s(self: *Replay, words: []const u32) void {
                self.recorder.mixPublicWords(self.source(words.len), words);
            }
            pub fn mixRoot(self: *Replay, root: [32]u8) void {
                self.recorder.mixPublicRoot(self.source(8), root);
            }
            pub fn mixFelts(self: *Replay, values: []const Q) void {
                self.recorder.mixPublicFelts(self.source(values.len * 4), values);
            }
            pub fn mixU64(self: *Replay, value: u64) void {
                self.recorder.mixPublicInteger(self.source(2), value);
            }
        };
        pub const Source = struct {
            allocator: std.mem.Allocator,
            owner: ?*Budget,
            fresh: *const R.Fresh,
            terms: []Term,
            prefix_count: u32,
            cell_count: u32,
            public_input_digest: [32]u8,
            pub const complete_source_authority = false;
            pub const complete_block_authority = false;
            /// Fresh, its independent original policies and key/schedule owners must
            /// outlive Source and every higher reader. No proof authority is cached.
            pub fn init(a: std.mem.Allocator, fresh: *const R.Fresh) !Source {
                try fresh.validate();
                const admitted = try fresh.authority();
                const first = try prefix(&admitted);
                const owner = Budget.fromAllocator(a);
                if (owner) |value| _ = value.retain();
                errdefer if (owner) |value| value.destroy();
                const terms = try a.alloc(Term, fresh.policy.schedule.len);
                errdefer a.free(terms);
                for (terms, fresh.policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admitted.values.at(wire) };
                return .{ .allocator = a, .owner = owner, .fresh = fresh, .terms = terms, .prefix_count = first.len, .cell_count = try std.math.add(u32, first.len, fresh.public.cell_count), .public_input_digest = try admitted.publicInputIdentity() };
            }
            pub fn deinit(self: *Source) void {
                const owner = self.owner;
                self.allocator.free(self.terms);
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
            pub fn validate(self: *const Source) !void {
                try self.fresh.validate();
                const admitted = try self.fresh.authority();
                const first = try prefix(&admitted);
                if (self.prefix_count != first.len or self.cell_count != try std.math.add(u32, first.len, self.fresh.public.cell_count) or !std.meta.eql(self.public_input_digest, try admitted.publicInputIdentity()) or self.terms.len != self.fresh.policy.schedule.len) return error.UntrustedWidePublicSource;
                for (self.terms, self.fresh.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try admitted.values.at(wire))) return error.UntrustedWidePublicSource;
            }
            pub fn cell(self: *const Source, coordinate: u32) ![4]M {
                if (coordinate >= self.cell_count) return error.InvalidWidePublicCell;
                if (coordinate >= self.prefix_count) return self.fresh.public.cell(coordinate - self.prefix_count);
                const admitted = try self.fresh.authority();
                const first = try prefix(&admitted);
                const word = first.words[coordinate];
                var out: [4]M = undefined;
                for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
                return out;
            }
            pub fn originalCell(self: *const Source, window_index: u32, coordinate: u32) !u32 {
                return std.math.add(u32, self.prefix_count, try self.fresh.public.originalCell(window_index, coordinate));
            }
            pub fn originalFrame(self: *const Source, window_index: u32, ordinal: u32) !Coordinate {
                const local = try self.fresh.public.localIndex(window_index);
                const frame = try self.fresh.public.sources[local].frameAt(ordinal);
                const count: usize = switch (frame.operation) {
                    .words => |v| v.len,
                    .root => 8,
                    .felts => |v| try std.math.mul(usize, v.len, 4),
                    .integer => 2,
                };
                return .{ .first_cell = try self.originalCell(window_index, frame.first), .word_count = std.math.cast(u32, count) orelse return error.InvalidWidePublicCell };
            }
            pub fn window(self: *const Source, index: u32) !Window {
                const cycles = try self.fresh.public.cycles(index);
                return .{ .first = .{ .first_cell = try std.math.add(u32, self.prefix_count, cycles.first), .word_count = 2 }, .last = .{ .first_cell = try std.math.add(u32, self.prefix_count, cycles.last), .word_count = 2 } };
            }

            /// All indices are the original job's indices, never rounded or re-based.
            pub const input_digest_link_proved = false;
            /// Authentic lower public root coordinates. No original capacity leaf yet
            /// exports this separately from B5PD; that in-circuit link remains OPEN.
            pub fn inputRoot(self: *const Source) Coordinate {
                return .{ .first_cell = self.prefix_count + self.fresh.public.input_root_first, .word_count = 8 };
            }
            pub fn inputLength(self: *const Source) Coordinate {
                return .{ .first_cell = self.prefix_count + 5, .word_count = 1 };
            }
            pub fn inputPrefix(self: *const Source) !Coordinate {
                const c = try self.fresh.public.inputPrefix();
                return .{ .first_cell = try std.math.add(u32, self.prefix_count, c.first_cell), .word_count = c.word_count };
            }
            pub fn inputFrontier(self: *const Source, ordinal: u32) !Coordinate {
                const c = try self.fresh.public.inputFrontier(ordinal);
                return .{ .first_cell = try std.math.add(u32, self.prefix_count, c.first_cell), .word_count = c.word_count };
            }
            pub fn firstWindow(self: *const Source) u32 {
                return self.fresh.policy.public.first_window;
            }
            pub fn windowCount(self: *const Source) u32 {
                return @intCast(self.fresh.public.sources.len);
            }
            pub fn rangeCoordinates(self: *const Source) struct { first_window: u32, window_count: u32, job_window_count: u32 } {
                return .{ .first_window = self.prefix_count + 2, .window_count = self.prefix_count + 3, .job_window_count = self.prefix_count + 4 };
            }
            pub fn firstCycle(self: *const Source) !Coordinate {
                return (try self.window(self.firstWindow())).first;
            }
            pub fn lastCycle(self: *const Source) !Coordinate {
                return (try self.window(try std.math.add(u32, self.firstWindow(), self.windowCount() - 1))).last;
            }
            pub fn exportTerms(self: *const Source, index: u32) ![3]Coordinate {
                const cells = try self.fresh.public.exportTerms(index);
                var out: [3]Coordinate = undefined;
                for (&out, cells) |*coordinate, exported| coordinate.* = .{ .first_cell = try std.math.add(u32, self.prefix_count, exported.first_cell), .word_count = exported.word_count };
                return out;
            }
            pub fn mix(self: *const Source, channel: anytype) !void {
                const admitted = try self.fresh.authority();
                try admitted.mix(channel);
            }
            pub fn replayPublic(self: *const Source, recorder: *Recorder.Recorder) void {
                var routed = Replay{ .recorder = recorder };
                const admitted = self.fresh.authority() catch |failure| {
                    recorder.failure = failure;
                    return;
                };
                admitted.mix(&routed) catch |failure| {
                    recorder.failure = failure;
                    return;
                };
                if (routed.cursor != self.cell_count) recorder.failure = error.UntrustedWidePublicSource;
            }
        };
        pub const Admission = struct {
            pub const open_parent_v5_v2 = true;
            source: *const Source,
            key: Base.Key,
            expected_id: [32]u8,
            pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
            pub fn init(source: *const Source) Admission {
                const k = source.fresh.policy.key;
                return .{ .source = source, .key = .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
            }
            pub fn validate(self: *const Admission) !void {
                try self.source.validate();
                const expected = init(self.source);
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedWidePublicSource;
            }
            pub fn config(self: *const Admission) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
                try self.validate();
                const admitted = try self.source.fresh.authority();
                try admitted.admitRoot(root);
            }
            pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
                try self.validate();
                return self.source.public_input_digest;
            }
            pub fn mix(self: *const Admission, channel: anytype) !void {
                try self.validate();
                try self.source.mix(channel);
            }
            pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
                try self.validate();
                const admitted = try self.source.fresh.authority();
                try admitted.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const admitted = try self.source.fresh.authority();
                try admitted.validateClaimsForRelations(claims, relations);
            }
        };
    };
}
