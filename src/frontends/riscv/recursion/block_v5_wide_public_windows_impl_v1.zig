//! Independently reconstructed full-u64 multi-window PUBLIC inputs. This is
//! not a closure receipt; original native proofs and same-parent equations
//! remain required. The shared input is serialized once, never once/window.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Job = @import("block_v5_global_expected_public_job_v1.zig");
const File = @import("../prover/block_v5_global_expected_public_file_v1.zig");
const Native = @import("block_v5_wide_original_child_source_v1.zig").ForSubtype(.capacity_v1);
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Windows = @import("../prover/block_v5_register_windows_v1.zig");
const C = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const U = @import("air/universal_challenges.zig");
const Tuple = @import("air/block_v5_global_public_tuple_algebra_v1.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn ForInputPolicy(comptime Input: type) type {
    return struct {
        pub const VERSION: u32 = Input.VERSION;
        pub const TAG: u32 = Input.TAG; // B5WM distinct multi-window public grammar.
        pub const Terms = [3]Q;
        pub const Range = struct {
            first: u32,
            count: u32,
            pub fn require(self: Range, total: usize) !u32 {
                if (self.count == 0 or self.count > 4) return error.UntrustedWidePublicWindowRoster;
                const end = std.math.add(u32, self.first, self.count) catch return error.UntrustedWidePublicWindowRoster;
                if (end > total) return error.UntrustedWidePublicWindowRoster;
                return end;
            }
        };
        pub const Policy = struct {
            coverage: *const C.Plan,
            expected: *File.Owned,
            input: *Input.Owned,
            input_expected: Input.Expected,
            instances: []const Native.Policy,
            first_window: u32,
            pub const MAX_FAN_IN: usize = 4;
            pub const complete_source_authority = false;
            pub fn native(self: Policy, index: u32) !Native.Policy {
                if (index >= self.instances.len) return error.UntrustedWidePublicWindowRoster;
                return self.instances[index];
            }
            pub fn validate(self: Policy) !void {
                try self.coverage.requireExact(self.coverage.meta);
                try self.input.require(self.input_expected);
                if (self.input.job != self.expected) return error.UntrustedWideExpectedInput;
                const expected = self.expected.expected();
                try expected.validate(self.expected.limits.job);
                const end = try (Range{ .first = self.first_window, .count = std.math.cast(u32, self.instances.len) orelse return error.UntrustedWidePublicWindowRoster }).require(expected.windows.len);
                if (expected.register_plan.version != Windows.LOCAL_ZERO_VERSION or self.instances.len == 0 or self.instances.len > MAX_FAN_IN or end > expected.windows.len or expected.windows.len != self.coverage.meta.sources[@intFromEnum(C.SourceKind.register_windows)].count or !std.meta.eql(expected.coverage_digest, self.coverage.pinned_digest) or !std.meta.eql(expected.seal_digest, self.coverage.meta.seal_digest) or expected.recipe != @intFromEnum(self.coverage.meta.recipe)) return error.UntrustedWidePublicWindowRoster;
                const plan_digest = try expected.register_plan.digest();
                if (!std.meta.eql(plan_digest, self.coverage.meta.sources[@intFromEnum(C.SourceKind.register_windows)].identity)) return error.UntrustedWidePublicWindowRoster;
                var physical_count: usize = 0;
                var selected_count: usize = 0;
                for (self.coverage.meta.physical) |physical| if (physical.kind == .native_arithmetic) {
                    if (physical.index != physical_count) return error.UntrustedWidePublicWindowRoster;
                    if (physical.index >= self.first_window and physical.index < end) {
                        if (!std.meta.eql(physical, self.instances[selected_count].physical)) return error.UntrustedWidePublicWindowRoster;
                        selected_count += 1;
                    }
                    physical_count += 1;
                };
                if (physical_count != expected.windows.len or selected_count != self.instances.len) return error.UntrustedWidePublicWindowRoster;
                for (self.instances, expected.windows[self.first_window..end], 0..) |instance, window, local| {
                    const index = try std.math.add(u32, self.first_window, @intCast(local));
                    const p = instance.admitted;
                    try p.validate(p.template_id);
                    try self.coverage.meta.security.require(instance.key.config);
                    if (instance.physical.index != index or instance.physical.kind != .native_arithmetic or instance.physical.subtype != .capacity_v1 or !std.meta.eql(instance.source_seal, expected.seal_digest) or instance.recipe != self.coverage.meta.recipe or p.sealed.register_custody_mode != 1 or !std.meta.eql(p.sealed.register_endpoint_plan_digest, plan_digest) or p.pin.context.first_cycle != window.first_cycle or p.pin.context.last_cycle != window.last_cycle or p.template.execution_profile != window.profile) return error.UntrustedWidePublicWindowRoster;
                    try window.data.requireEqual(Job.Data.fromPublic(&p.shape.public_data));
                    if (!std.mem.eql(u32, expected.input_words, p.shape.public_data.io_entries.input_words)) return error.UntrustedWidePublicWindowRoster;
                    try expected.register_plan.requireNative(p.shape);
                    try expected.register_plan.windows[index].requirePublic(@intCast(index), window.first_cycle, &p.shape.public_data);
                }
            }
        };
        pub const Limits = struct { original: @import("block_v5_wide_original_child_source_v1.zig").Limits = .{}, job: Job.Limits = .{}, fields: Fields.Limits = .{}, max_windows: usize = Policy.MAX_FAN_IN, max_cells: usize = 64 << 20 };
        pub const Coordinate = struct { first_cell: u32, word_count: u32 };
        pub const CycleCoordinates = struct { first: u32, last: u32 };
        pub const Layout = struct { original_first: u32, fields_first: u32, digest_first: u32, terms_first: u32, auxiliary_first: u32, public_words: u32 };
        fn byteWord(raw_word: u32) [4]M {
            var out: [4]M = undefined;
            for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((raw_word >> @as(u5, @intCast(8 * part))) & 255);
            return out;
        }
        const Relations = struct {
            elements: U.UniversalRelations,
            pub fn getExact(self: *const Relations, domain: @import("../air/lang/relation.zig").Domain) !Element {
                return .{ .inner = try self.elements.getExact(domain) };
            }
            const Element = struct {
                inner: *const U.Elements,
                pub fn combine(self: Element, values: []const Q) !Q {
                    return self.inner.combineSecure(values);
                }
            };
        };
        fn dataFrom(field: *const Fields.Fields) !Tuple.Data(Q) {
            var out: Tuple.Data(Q) = undefined;
            const l = field.layout;
            out.initial_pc = try word(field, l.pc_clock);
            out.final_pc = try word(field, l.pc_clock + 1);
            out.clock = try word(field, l.pc_clock + 2);
            out.completion_address = try word(field, l.completion + 2);
            for (0..32) |index| {
                out.initial[index] = try word(field, l.initial + @as(u32, @intCast(index)));
                out.final[index] = try word(field, l.final + @as(u32, @intCast(index)));
                out.clocks[index] = try word(field, l.clocks + @as(u32, @intCast(index)));
            }
            for (0..4) |index| out.decoded[index] = try word(field, l.decoded + @as(u32, @intCast(index)));
            for (0..2) |limb| {
                const first = try word(field, l.cycles + @as(u32, @intCast(limb)));
                const last = try word(field, l.cycles + 2 + @as(u32, @intCast(limb)));
                @memcpy(out.first_cycle[4 * limb ..][0..4], &first);
                @memcpy(out.last_cycle[4 * limb ..][0..4], &last);
            }
            return out;
        }
        fn word(field: *const Fields.Fields, index: u32) ![4]Q {
            const raw = try field.bytes(index);
            var out: [4]Q = undefined;
            for (raw, &out) |value, *scalar| scalar.* = Q.fromBase(value);
            return out;
        }
        pub const Owner = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            limits: Limits,
            expected: *File.Owned,
            policy: Policy,
            sources: []Native.Source,
            fields: []Fields.Fields,
            terms: []Terms,
            layouts: []Layout,
            relations: U.UniversalRelations,
            input_root_first: u32,
            input_supplement_first: u32,
            input: *Input.Owned,
            outer_first: u32,
            cell_count: u32,
            pub const complete_block_authority = false;
            pub const complete_source_authority = false;
            pub const input_digest_link_proved = false;
            pub fn requireComplete(_: *const Owner) !void {
                return error.WidePublicGlobalSourceClosureUnavailable;
            }
            pub fn deinit(self: *Owner) void {
                const a = self.allocator;
                const lease = self.allocation_owner;
                const expected = self.expected;
                const input = self.input;
                for (self.fields) |*field| field.deinit();
                for (self.sources) |*source| source.deinit();
                a.free(self.sources);
                a.free(self.fields);
                a.free(self.terms);
                a.free(self.layouts);
                self.* = undefined;
                expected.deinit();
                input.deinit();
                if (lease) |value| value.destroy();
            }
            pub fn validate(self: *const Owner) !void {
                try self.policy.validate();
                try self.expected.expected().validate(self.limits.job);
                if (self.sources.len > self.limits.max_windows or self.cell_count > self.limits.max_cells) return error.WidePublicResourceLimit;
                const expected = self.policy.expected.expected();
                if (self.input != self.policy.input or self.expected != self.policy.expected or self.sources.len != self.policy.instances.len or self.fields.len != self.sources.len or self.layouts.len != self.sources.len or self.terms.len != self.sources.len) return error.MutatedWidePublicWindows;
                var channel = self.policy.instances[0].admitted.sealed.sharedChannel();
                const relations = try U.UniversalRelations.draw(self.allocator, &channel);
                if (!std.meta.eql(relations, self.relations)) return error.MutatedWidePublicWindows;
                var cursor: u32 = 6 + 8 * 3; // version/count header and independent policy IDs
                if (self.input_root_first != cursor) return error.MutatedWidePublicWindows;
                cursor = try std.math.add(u32, cursor, 8);
                if (self.input_supplement_first != cursor) return error.MutatedWidePublicWindows;
                cursor = try std.math.add(u32, cursor, @intCast(Input.supplementCells(self.input)));
                if (self.outer_first != cursor) return error.MutatedWidePublicWindows;
                cursor = try std.math.add(u32, cursor, 64);
                for (self.sources, self.fields, self.terms, self.layouts, 0..) |*source, *field, terms, layout, index| {
                    try source.validate();
                    if (!std.meta.eql(source.policy, self.policy.instances[index])) return error.MutatedWidePublicWindows;
                    const p = source.policy.admitted;
                    try field.validate(&p.shape.public_data, p.template.execution_profile, p.pin.context.first_cycle, p.pin.context.last_cycle);
                    const expected_layout = try advance(&cursor, source, field);
                    if (!std.meta.eql(layout, expected_layout)) return error.MutatedWidePublicWindows;
                    const sums = try Tuple.evaluate(Q, try dataFrom(field), &Relations{ .elements = relations }, expected.register_plan.version == Windows.LOCAL_ZERO_VERSION, p.shape.public_data.completion.?.kind != .halt_flag);
                    const required = Terms{ sums.native_compensation, sums.register_compensation, sums.program_boundary };
                    for (terms, required) |actual, value| if (!actual.eql(value)) return error.MutatedWidePublicWindows;
                }
                if (cursor != self.cell_count) return error.MutatedWidePublicWindows;
            }
            pub fn sealedCells(self: *const Owner) !struct { child: u32, first: u32 } {
                if (self.sources.len == 0) return error.UntrustedWidePublicWindowRoster;
                const frame = try self.sources[0].frameAt(4);
                if (frame.operation != .root or !std.meta.eql(frame.operation.root, self.policy.instances[0].admitted.sealed.digest)) return error.UntrustedWidePublicWindowRoster;
                return .{ .child = 0, .first = frame.first };
            }
            pub fn auxiliary(self: *const Owner, window: u32) ![9]u32 {
                if (window >= self.fields.len) return error.InvalidWidePublicCell;
                const field = &self.fields[window];
                const steps = self.policy.instances[window].admitted.shape.public_data.clock - 1;
                const add = try @import("block_v5_wide_native_public_values_v1.zig").addCarries(field.first_cycle, steps);
                const increment = try @import("air/block_v5_recursive_u64_span_v1.zig").carries(steps);
                return .{ steps, add[0], add[1], add[2], add[3], increment[0], increment[1], increment[2], increment[3] };
            }
            pub fn localIndex(self: *const Owner, window: u32) !usize {
                if (window < self.policy.first_window or window - self.policy.first_window >= self.sources.len) return error.InvalidWidePublicCell;
                return window - self.policy.first_window;
            }
            pub fn publicWord(self: *const Owner, window: u32, original_word: u32) !u32 {
                const local = try self.localIndex(window);
                const field = &self.fields[local];
                if (original_word >= field.word_count) {
                    const extra = original_word - field.word_count;
                    if (extra < 9) return std.math.add(u32, self.layouts[local].auxiliary_first, extra);
                    return std.math.add(u32, self.input_supplement_first, try Input.supplementOffset(self.input, extra - 9));
                }
                const input = field.chunks[12];
                if (original_word >= input.first and original_word - input.first < input.words.len) return error.WideRawInputCellsNotExported;
                return std.math.add(u32, self.layouts[local].fields_first, original_word - @as(u32, @intCast(if (original_word >= input.first) input.words.len else 0)));
            }
            pub fn originalCell(self: *const Owner, window: u32, coordinate: u32) !u32 {
                const local = try self.localIndex(window);
                if (coordinate >= self.sources[local].cell_count) return error.InvalidWidePublicCell;
                return std.math.add(u32, self.layouts[local].original_first, coordinate);
            }
            pub fn inputPrefix(self: *const Owner) !Coordinate {
                if (comptime Input.VERSION == 2) {
                    return .{ .first_cell = self.input_supplement_first, .word_count = @intCast(self.input.prefix_count) };
                } else return error.WideRawInputCellsNotExported;
            }
            pub fn inputFrontier(self: *const Owner, ordinal: u32) !Coordinate {
                if (comptime Input.VERSION == 2) {
                    if (ordinal >= self.input.frontier.len) return error.InvalidWidePublicCell;
                    const word_index = try std.math.add(u32, @intCast(self.input.prefix_count), try std.math.mul(u32, ordinal, 8));
                    return .{ .first_cell = try std.math.add(u32, self.input_supplement_first, try Input.supplementOffset(self.input, word_index)), .word_count = 8 };
                } else return error.WideRawInputCellsNotExported;
            }
            pub fn exportTerms(self: *const Owner, window: u32) ![3]Coordinate {
                const local = try self.localIndex(window);
                var out: [3]Coordinate = undefined;
                for (&out, 0..) |*coordinate, index| coordinate.* = .{ .first_cell = self.layouts[local].terms_first + 4 * @as(u32, @intCast(index)), .word_count = 4 };
                return out;
            }
            pub fn cycles(self: *const Owner, window: u32) !CycleCoordinates {
                const local = try self.localIndex(window);
                return .{ .first = try self.publicWord(window, self.fields[local].layout.cycles), .last = try self.publicWord(window, self.fields[local].layout.cycles + 2) };
            }
            pub fn at(self: *const Owner, wire: Bus.Wire) ![4]M {
                if (wire.kind == .child_term) {
                    if (wire.child >= self.sources.len or wire.coordinate >= self.sources[wire.child].terms.len or wire.part != null) return error.InvalidWidePublicCell;
                    return self.sources[wire.child].terms[wire.coordinate].coordinates;
                }
                if (wire.kind != .child_cell) return error.InvalidWidePublicCell;
                const value = if (wire.child < self.sources.len) try self.sources[wire.child].cell(wire.coordinate) else if (wire.child == self.sources.len) try self.cell(wire.coordinate) else return error.InvalidWidePublicCell;
                return if (wire.part) |part| .{ value[part], M.zero(), M.zero(), M.zero() } else value;
            }
            pub fn cell(self: *const Owner, coordinate: u32) ![4]M {
                if (coordinate >= self.cell_count) return error.InvalidWidePublicCell;
                const expected = self.expected.expected();
                if (coordinate < 6) return byteWord(([_]u32{ TAG, VERSION, self.policy.first_window, @intCast(self.sources.len), @intCast(expected.windows.len), @intCast(expected.input_words.len) })[coordinate]);
                if (coordinate < 30) {
                    const slot = (coordinate - 6) / 8;
                    const root = switch (slot) {
                        0 => expected.coverage_digest,
                        1 => expected.seal_digest,
                        2 => try expected.register_plan.digest(),
                        else => unreachable,
                    };
                    const limb = (coordinate - 6) % 8;
                    return byteWord(std.mem.readInt(u32, root[4 * @as(usize, limb) ..][0..4], .little));
                }
                if (coordinate < self.input_supplement_first) {
                    const limb = coordinate - self.input_root_first;
                    return byteWord(std.mem.readInt(u32, self.policy.input_expected.root[4 * @as(usize, limb) ..][0..4], .little));
                }
                if (coordinate < self.outer_first) return byteWord(try Input.supplementCell(self.input, coordinate - self.input_supplement_first));
                if (coordinate < self.outer_first + 64) {
                    const offset = coordinate - self.outer_first;
                    return byteWord(if (offset < 32) expected.register_plan.initial_registers[offset] else expected.register_plan.final_registers[offset - 32]);
                }
                var low: usize = 0;
                var high = self.layouts.len;
                while (low < high) {
                    const middle = low + (high - low) / 2;
                    if (self.layouts[middle].original_first <= coordinate) low = middle + 1 else high = middle;
                }
                if (low == 0) return error.InvalidWidePublicCell;
                const index = low - 1;
                const layout = self.layouts[index];
                const field = &self.fields[index];
                if (coordinate < layout.fields_first) return self.sources[index].cell(coordinate - layout.original_first);
                if (coordinate < layout.digest_first) {
                    const local = coordinate - layout.fields_first;
                    const input = field.chunks[12];
                    return field.bytes(local + @as(u32, @intCast(if (local >= input.first) input.words.len else 0)));
                }
                if (coordinate < layout.auxiliary_first) {
                    const limb = coordinate - layout.digest_first;
                    return byteWord(std.mem.readInt(u32, field.source_digest[4 * @as(usize, limb) ..][0..4], .little));
                }
                if (coordinate < layout.terms_first) return byteWord((try self.auxiliary(@intCast(index)))[coordinate - layout.auxiliary_first]);
                const local = coordinate - layout.terms_first;
                return byteWord(self.terms[index][local / 4].toM31Array()[local % 4].v);
            }
            /// NEW parent public grammar only. Each original child replay uses its own
            /// exact source.mix/replayPublic; this never appends to those channels.
            pub fn mix(self: *const Owner, channel: anytype) !void {
                try self.validate();
                const expected = self.expected.expected();
                channel.mixU32s(&.{ TAG, VERSION, self.policy.first_window, @intCast(self.sources.len), @intCast(expected.windows.len), @intCast(expected.input_words.len) });
                channel.mixRoot(expected.coverage_digest);
                channel.mixRoot(expected.seal_digest);
                channel.mixRoot(try expected.register_plan.digest());
                channel.mixRoot(self.policy.input_expected.root);
                Input.mixSupplement(self.input, channel);
                channel.mixU32s(&expected.register_plan.initial_registers);
                channel.mixU32s(&expected.register_plan.final_registers);
                for (self.sources, self.fields, self.terms, 0..) |*source, field, terms, index| {
                    try source.mix(channel);
                    for (field.chunks, 0..) |chunk, chunk_index| if (chunk_index != 12) {
                        channel.mixU32s(chunk.words);
                    };
                    channel.mixRoot(field.source_digest);
                    channel.mixU32s(&(try self.auxiliary(@intCast(index))));
                    channel.mixFelts(&terms);
                }
            }
        };
        pub fn layoutFor(cursor: *u32, original_cells: u32, field_words: u32, input_words: u32) !Layout {
            const first = cursor.*;
            cursor.* = try std.math.add(u32, cursor.*, original_cells);
            const fields_first = cursor.*;
            const public_words = try std.math.sub(u32, field_words, input_words);
            cursor.* = try std.math.add(u32, cursor.*, public_words);
            const digest_first = cursor.*;
            cursor.* = try std.math.add(u32, cursor.*, 8);
            const auxiliary_first = cursor.*;
            cursor.* = try std.math.add(u32, cursor.*, 9);
            const terms_first = cursor.*;
            cursor.* = try std.math.add(u32, cursor.*, 12);
            return .{ .original_first = first, .fields_first = fields_first, .digest_first = digest_first, .terms_first = terms_first, .auxiliary_first = auxiliary_first, .public_words = public_words };
        }
        fn advance(cursor: *u32, source: *const Native.Source, field: *const Fields.Fields) !Layout {
            return layoutFor(cursor, source.cell_count, field.word_count, @intCast(field.borrowed_input.len));
        }
        pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Owner {
            try policy.validate();
            try policy.expected.expected().validate(limits.job);
            if (limits.max_cells == 0 or limits.max_windows == 0) return error.WidePublicResourceLimit;
            const count = policy.instances.len;
            if (count > limits.max_windows) return error.WidePublicResourceLimit;
            const lease = Budget.fromAllocator(a);
            if (lease) |value| _ = value.retain();
            errdefer if (lease) |value| value.destroy();
            const input = try Input.retain(policy.input);
            errdefer input.deinit();
            const expected = try policy.expected.retain();
            errdefer expected.deinit();
            const sources = try a.alloc(Native.Source, count);
            errdefer a.free(sources);
            var made: usize = 0;
            errdefer for (sources[0..made]) |*source| source.deinit();
            for (sources, policy.instances) |*source, native| {
                source.* = try Native.Source.init(a, native, limits.original);
                made += 1;
            }
            const fields = try a.alloc(Fields.Fields, count);
            errdefer a.free(fields);
            var fields_made: usize = 0;
            errdefer for (fields[0..fields_made]) |*field| field.deinit();
            for (fields, policy.instances) |*field, native| {
                const p = native.admitted;
                field.* = try Fields.init(a, &p.shape.public_data, p.template.execution_profile, p.pin.context.first_cycle, p.pin.context.last_cycle, limits.fields);
                fields_made += 1;
            }
            const terms = try a.alloc(Terms, count);
            errdefer a.free(terms);
            const layouts = try a.alloc(Layout, count);
            errdefer a.free(layouts);
            var channel = policy.instances[0].admitted.sealed.sharedChannel();
            const relations = try U.UniversalRelations.draw(a, &channel);
            const job = expected.expected();
            const input_root_first: u32 = 30;
            const input_supplement_first: u32 = 38;
            const outer_first: u32 = try std.math.add(u32, input_supplement_first, @intCast(Input.supplementCells(policy.input)));
            var cursor = try std.math.add(u32, outer_first, 64);
            for (sources, fields, terms, layouts, 0..) |*source, *field, *term, *layout, index| {
                layout.* = try advance(&cursor, source, field);
                const sums = try Tuple.evaluate(Q, try dataFrom(field), &Relations{ .elements = relations }, job.register_plan.version == Windows.LOCAL_ZERO_VERSION, policy.instances[index].admitted.shape.public_data.completion.?.kind != .halt_flag);
                term.* = .{ sums.native_compensation, sums.register_compensation, sums.program_boundary };
            }
            if (cursor > limits.max_cells or cursor >= core.fields.m31.Modulus) return error.WidePublicResourceLimit;
            const out = Owner{ .allocator = a, .allocation_owner = lease, .limits = limits, .expected = expected, .policy = policy, .sources = sources, .fields = fields, .terms = terms, .layouts = layouts, .relations = relations, .input_root_first = input_root_first, .input_supplement_first = input_supplement_first, .input = input, .outer_first = outer_first, .cell_count = cursor };
            try out.validate();
            return out;
        }
    };
}
