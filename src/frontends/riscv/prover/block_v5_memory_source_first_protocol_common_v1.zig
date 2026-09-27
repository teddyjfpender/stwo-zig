//! Shared typed source-page owner kernel. The schema independently selects
//! exact census/grammar/codec; no shape relabeling or proof authority is added.
const std = @import("std");
const core = @import("stwo_core");
const BaseSeal = @import("block_v5_source_seal_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! B5SC: prechallenge source witness commitments. Distinct from B5SS/file SHA
        //! pins and from a source proof receipt. A source seal commits an exact roster;
        //! it does not verify any source equation or discharge a global obligation.
        const suite = core.proof_suites.Blake3;
        const Source = Schema.Source;
        const Stream = Schema.Stream;
        const Eq = Schema.Equations;
        pub const TAG: u32 = Schema.TAG;
        pub const VERSION: u32 = Schema.VERSION;
        pub const FIXED_COUNT: usize = Schema.FIXED_COUNT;
        pub const MAIN_COUNT: usize = Schema.MAIN_COUNT;
        pub const Limits = struct {
            page_row_log: u32 = 12,
            max_pages: u32 = 262144,
            max_chunks: u64 = 1 << 30,
            max_private_cells: usize = 1 << 24,
            max_page_heap_bytes: usize = 512 << 20,
            max_catalog_bytes: usize = 64 << 20,
        };
        pub const Page = struct { index: u32, first_chunk: u64, chunks: u32, row_log: u32 };
        pub const Plan = struct {
            admission_id: [32]u8,
            total_chunks: u64,
            pages: u32,
            row_log: u32,
            config: core.pcs.PcsConfig,
            identity: [32]u8,
            pub fn page(self: Plan, index: u32) !Page {
                if (self.row_log < 1 or self.row_log > 12 or self.total_chunks == 0 or self.total_chunks > 1 << 30 or self.pages == 0 or self.pages > 262144 or index >= self.pages) return error.InvalidSourceFirstPage;
                const capacity = @as(u64, 1) << @intCast(self.row_log);
                if (self.pages != (self.total_chunks + capacity - 1) / capacity) return error.InvalidSourceFirstPage;
                const first = @as(u64, index) * capacity;
                return .{ .index = index, .first_chunk = first, .chunks = @intCast(@min(capacity, self.total_chunks - first)), .row_log = self.row_log };
            }
            pub fn require(self: Plan, admitted: *const Source.Admitted, limits: Limits) !void {
                const expected = try init(admitted, self.config, limits);
                if (!std.meta.eql(self, expected)) return error.InvalidSourceFirstPlan;
            }
        };
        pub fn abiId() [32]u8 {
            return Schema.abiId();
        }

        pub fn init(admitted: *const Source.Admitted, config: core.pcs.PcsConfig, limits: Limits) !Plan {
            try admitted.require();
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            if (limits.page_row_log < 1 or limits.page_row_log > 12 or limits.max_pages == 0 or limits.max_pages > 262144 or limits.max_chunks == 0 or limits.max_page_heap_bytes == 0 or limits.max_catalog_bytes == 0) return error.SourceFirstResourceLimit;
            const fri = config.fri_config;
            if (limits.page_row_log + fri.log_blowup_factor >= core.circle.M31_CIRCLE_LOG_ORDER or limits.page_row_log < fri.fold_step or limits.page_row_log - fri.fold_step < fri.log_last_layer_degree_bound) return error.InvalidSourceFirstGeometry;
            const rows = @as(usize, 1) << @intCast(limits.page_row_log);
            if (try std.math.mul(usize, rows, MAIN_COUNT) > limits.max_private_cells or try std.math.mul(usize, try std.math.mul(usize, rows, MAIN_COUNT + FIXED_COUNT), @sizeOf(core.fields.m31.M31)) > limits.max_page_heap_bytes) return error.SourceFirstResourceLimit;
            const chunks = (try Stream.census(admitted)).total;
            const pages = (chunks + rows - 1) / rows;
            if (chunks > limits.max_chunks or pages > limits.max_pages or try std.math.mul(usize, @intCast(pages), @sizeOf(Pin)) > limits.max_catalog_bytes) return error.SourceFirstResourceLimit;
            var channel = suite.Channel{};
            channel.mixRoot(abiId());
            channel.mixRoot(admitted.identity);
            channel.mixU32s(&.{ TAG, VERSION, limits.page_row_log, @intCast(pages), FIXED_COUNT, MAIN_COUNT });
            channel.mixU64(chunks);
            config.mixInto(&channel);
            return .{ .admission_id = admitted.identity, .total_chunks = chunks, .pages = @intCast(pages), .row_log = limits.page_row_log, .config = config, .identity = channel.digestBytes() };
        }
        pub const Pin = struct {
            plan_id: [32]u8,
            page: Page,
            roots: [2][32]u8,
            config: core.pcs.PcsConfig,
            pub fn require(self: Pin, plan: Plan) !void {
                if (!std.meta.eql(self.page, try plan.page(self.page.index)) or !std.meta.eql(self.plan_id, plan.identity) or !std.meta.eql(self.config, plan.config)) return error.UntrustedSourceFirstPin;
                for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourceFirstPin;
            }
            pub fn identity(self: Pin, plan: Plan) ![32]u8 {
                try self.require(plan);
                var channel = firstChannel(plan, self.page);
                for (self.roots) |root| channel.mixRoot(root);
                return channel.digestBytes();
            }
        };
        pub fn firstChannel(plan: Plan, page: Page) suite.Channel {
            var channel = suite.Channel{};
            mixFirst(&channel, plan, page);
            return channel;
        }
        /// Identical original first-channel absorption for typed recorders.
        pub fn mixFirst(channel: anytype, plan: Plan, page: Page) void {
            channel.mixRoot(abiId());
            channel.mixRoot(plan.identity);
            channel.mixU32s(&.{ TAG, VERSION, 0x46525354, page.index, page.chunks, page.row_log });
            channel.mixU64(page.first_chunk);
            plan.config.mixInto(channel);
        }
        pub const Sealed = struct {
            digest: [32]u8,
            plan_id: [32]u8,
            base_digest: [32]u8,
            pages: u32,
            pub fn require(self: Sealed, admitted: *const Source.Admitted, plan: Plan, entries: []const Pin, expected_digest: [32]u8, limits: Limits) !void {
                const expected = try seal(admitted, plan, entries, limits);
                if (!std.meta.eql(self, expected) or !std.meta.eql(self.digest, expected_digest)) return error.UntrustedSourceFirstSeal;
            }
        };
        pub fn seal(admitted: *const Source.Admitted, plan: Plan, entries: []const Pin, limits: Limits) !Sealed {
            try plan.require(admitted, limits);
            if (entries.len != plan.pages) return error.InvalidSourceFirstRoster;
            var channel = suite.Channel{};
            channel.mixRoot(abiId());
            channel.mixRoot(admitted.sealed_digest);
            channel.mixRoot(plan.identity);
            channel.mixU32s(&.{ TAG, VERSION, 0x5345414c, plan.pages });
            for (entries, 0..) |entry, index| {
                if (entry.page.index != index) return error.InvalidSourceFirstRoster;
                channel.mixRoot(try entry.identity(plan));
            }
            return .{ .digest = channel.digestBytes(), .plan_id = plan.identity, .base_digest = admitted.sealed_digest, .pages = plan.pages };
        }
        /// Preserve the already established sorted-RAM challenge suffix exactly. Only
        /// internal source buses incorporate the new prechallenge source commitment.
        /// The entire independent root roster is mixed before any internal source draw.
        pub fn draw(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: Plan, entries: []const Pin, source_sealed: Sealed, expected_digest: [32]u8, base_sealed: anytype, limits: Limits) !Source.Challenges {
            try source_sealed.require(admitted, plan, entries, expected_digest, limits);
            if (!std.meta.eql(base_sealed.digest, admitted.sealed_digest)) return error.UntrustedSourceFirstSeal;
            var channel = base_sealed.sharedChannel();
            return drawFromChannel(a, &channel, source_sealed);
        }
        /// Continue one transcript line. Caller must first independently admit the
        /// complete source roster and initialize the channel from its checked B5SS.
        pub fn drawFromChannel(a: std.mem.Allocator, channel: *suite.Channel, source_sealed: Sealed) !Source.Challenges {
            const word = try Word.Challenges.drawFromChannel(a, channel);
            channel.mixU32s(&.{ TAG, VERSION, 0x4348414c, 6, 4, 5, 4, 8, 71, 36, 7, 37 });
            channel.mixRoot(abiId());
            channel.mixRoot(source_sealed.digest);
            const values = try channel.drawSecureFelts(a, 18);
            defer a.free(values);
            return .{ .word = word, .bytes = .init(values[0], values[1]), .input = .init(values[2], values[3]), .insertion = .init(values[4], values[5]), .before = .init(values[6], values[7]), .after = .init(values[8], values[9]), .route = .init(values[10], values[11]), .roots = .init(values[12], values[13]), .ordering = .init(values[14], values[15]), .sha_chain = .init(values[16], values[17]) };
        }
        /// A received chunk descriptor is checked against independent physical ordinal.
        /// No caller-selected kind, stale admission ID, or alternate row ordering.
        pub fn admitChunk(admitted: *const Source.Admitted, plan: Plan, pin: Pin, logical_row: u32, proposed: Eq.Kind, limits: Limits) !u64 {
            try plan.require(admitted, limits);
            try pin.require(plan);
            if (logical_row >= pin.page.chunks) return error.InvalidSourceFirstChunk;
            const index = pin.page.first_chunk + logical_row;
            if (!std.meta.eql(proposed, try Stream.kindAt(admitted, index))) return error.UntrustedSourceFirstChunk;
            return index;
        }

        /// Independent metadata admission only. A future proof receiver must freshly
        /// verify the committed source arithmetic and same-main input bindings.
        pub const PageAdmission = struct {
            source_id: [32]u8,
            plan_id: [32]u8,
            source_seal: [32]u8,
            pin: Pin,
            private_inputs_per_chunk: usize = MAIN_COUNT,
        };
        pub fn admitPage(admitted: *const Source.Admitted, plan: Plan, expected: Pin, entries: []const Pin, source_sealed: Sealed, expected_digest: [32]u8, base_pins: BaseSeal.Pins, base_entries: []const BaseSeal.Entry, base_sealed: BaseSeal.Sealed, limits: Limits) !PageAdmission {
            const rebuilt = try Source.admit(admitted.pins, base_pins, base_entries, base_sealed, admitted.limits);
            if (!std.meta.eql(rebuilt.identity, admitted.identity) or !std.meta.eql(plan.config, base_pins.config)) return error.UntrustedSourceFirstAdmission;
            try plan.require(admitted, limits);
            try expected.require(plan);
            try source_sealed.require(admitted, plan, entries, expected_digest, limits);
            if (expected.page.index >= entries.len or !std.meta.eql(entries[expected.page.index], expected)) return error.UntrustedSourceFirstAdmission;
            return .{ .source_id = admitted.identity, .plan_id = plan.identity, .source_seal = source_sealed.digest, .pin = expected };
        }
    };
}
