//! V7 independent caller geometry. Original equations are reused without any
//! legacy seal, caller receipt or producer-selected key supplying authority.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Source = Policy.Source;
        const Epoch = @import("block_v7_execution_epoch_v1.zig");
        const Profile = @import("blake3_ethereum_sha_profile.zig");
        const Protocol = @import("block_v5_precompile_protocol_v1.zig");
        const Fused = @import("block_v5_caller_fused_proof_v1.zig");
        const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
        const Components = @import("block_v6_caller_joint_components_v1.zig");
        const OldGeometry = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
        const Component = OldGeometry.Component;
        const MAX_CLAIM_VALUES = OldGeometry.MAX_CLAIM_VALUES;
        pub const Limits = struct { max_columns: usize = 32768, max_claims: usize = 32768, max_samples: usize = 262144, max_capture_bytes: usize = 512 << 20, max_entries: usize = 4096 };
        pub const Arithmetic = struct {
            allocator: std.mem.Allocator,
            statement: Profile.admission.Statement,
            total_steps: u32,
            config: core.pcs.PcsConfig,
            elements: Profile.Relations,
            logs: [3][]u32,
            components: [Profile.component_count]Component,
            selected: [Profile.component_count]bool,
            physical_detail_counts: [Profile.component_count]u32,
            air_instruction_count: u32,
            detailed_claim_count: u32,
            template_id: [32]u8,
            max_columns: usize,
            pub fn init(a: std.mem.Allocator, statement: Profile.admission.Statement, total_steps: u32, config: core.pcs.PcsConfig, relations: Profile.Relations, max_columns: usize) !Arithmetic {
                try Protocol.validate(&statement, total_steps, config);
                var logs: [3][]u32 = undefined;
                var initialized: usize = 0;
                errdefer for (logs[0..initialized]) |values| a.free(values);
                for ([_]Protocol.Tree{ .fixed, .main, .interaction }, 0..) |tree, i| {
                    logs[i] = if (Policy.active) try (try @import("block_v7_caller_active_layout_v1.zig").Layout.derive(&statement, total_steps)).columnLogs(a, i) else try Protocol.columnLogs(a, &statement, tree);
                    initialized += 1;
                    if (logs[i].len > max_columns) return error.V7CallerResourceLimit;
                }
                const claims = try Profile.ExtensionClaim.zeroForStatement(&statement);
                const assembly = if (Policy.active) try Policy.Assembly(.verifier).init(a, &statement, total_steps, &relations, &claims) else try Policy.Assembly(.verifier).createBlockV5Standalone(a, &statement, total_steps, &relations, &claims);
                defer assembly.destroy(a);
                const handles = assembly.active();
                const selected: [19]bool = if (Policy.active) (try @import("block_v7_caller_active_layout_v1.zig").Layout.derive(&statement, total_steps)).active else @splat(true);
                var selected_count: usize = 0;
                for (selected) |included| selected_count += @intFromBool(included);
                if (handles.len != selected_count) return error.UntrustedCallerRecursiveGeometry;
                const all = core.air.components.Components{ .components = handles, .n_preprocessed_columns = logs[0].len };
                const log = all.compositionLogDegreeBound();
                const split = try all.compositionLogSplit();
                const placements = assembly.extensionPlacements();
                const views = claims.componentClaims();
                const descriptors = Profile.descriptors(&statement);
                var components: [Profile.component_count]Component = undefined;
                var constraint_count: u32 = 0;
                var detail_count: u32 = 0;
                var public_count: usize = 0;
                var handle_at: usize = 0;
                var physical_detail_counts: [19]u32 = undefined;
                for (&components, placements, views, descriptors, 0..) |*component, placement, view, desc, i| {
                    const count: u32 = if (selected[i]) std.math.cast(u32, handles[handle_at].nConstraints()) orelse return error.CallerRecursiveResourceLimit else 0;
                    handle_at += @intFromBool(selected[i]);
                    physical_detail_counts[i] = @intCast(view.detailed.len);
                    const batches: u32 = if (selected[i]) std.math.cast(u32, if (i < 14) view.detailed.len else desc.interaction_columns / 4) orelse return error.CallerRecursiveResourceLimit else 0;
                    if (count < batches) return error.UntrustedCallerRecursiveGeometry;
                    component.* = .{ .kind = statement.ethereum.components[@min(i, 13)].kind, .log_size = desc.log_size, .spans = .{ .{ .offset = placement.preprocessed_offset, .column_count = desc.preprocessed_columns }, .{ .offset = placement.main_offset, .column_count = desc.main_columns }, .{ .offset = placement.interaction_offset, .column_count = desc.interaction_columns } }, .direct_constraint_count = count - batches, .interaction_batch_count = batches };
                    constraint_count = try std.math.add(u32, constraint_count, count);
                    detail_count = try std.math.add(u32, detail_count, @intCast(view.detailed.len));
                    public_count = try std.math.add(usize, public_count, view.detailed.len + @intFromBool(view.has_batch_frame));
                    if (public_count > MAX_CLAIM_VALUES) return error.CallerRecursiveResourceLimit;
                }
                _ = log;
                _ = split;
                var result = Arithmetic{ .allocator = a, .statement = statement, .total_steps = total_steps, .config = config, .elements = relations, .logs = logs, .components = components, .selected = selected, .physical_detail_counts = physical_detail_counts, .air_instruction_count = constraint_count, .detailed_claim_count = detail_count, .template_id = undefined, .max_columns = max_columns };
                result.template_id = result.identity();
                return result;
            }
            pub fn deinit(self: *Arithmetic) void {
                for (self.logs) |values| self.allocator.free(values);
                self.* = undefined;
            }
            pub fn identity(self: *const Arithmetic) [32]u8 {
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ Source.TAG, Source.VERSION, 10, self.total_steps, self.air_instruction_count, self.detailed_claim_count });
                self.config.mixInto(&ch);
                if (Policy.active) {
                    ch.mixU32s(&.{ @import("block_v7_caller_active_layout_v1.zig").TAG, @import("block_v7_caller_active_layout_v1.zig").VERSION });
                    for (self.selected, self.physical_detail_counts) |included, count| ch.mixU32s(&.{ @intFromBool(included), count });
                }
                for (self.components) |component| {
                    ch.mixU32s(&.{ @intFromEnum(component.kind), component.log_size, component.direct_constraint_count, component.interaction_batch_count });
                    for (component.spans) |span| {
                        ch.mixU64(span.offset);
                        ch.mixU64(span.column_count);
                    }
                }
                for (self.logs) |values| {
                    ch.mixU64(values.len);
                    ch.mixU32s(values);
                }
                return ch.digestBytes();
            }
            pub fn validate(self: *const Arithmetic, expected: [32]u8) !void {
                var rebuilt = try init(self.allocator, self.statement, self.total_steps, self.config, self.elements, self.max_columns);
                defer rebuilt.deinit();
                if (!std.meta.eql(expected, self.template_id) or !std.meta.eql(expected, self.identity()) or !std.meta.eql(expected, rebuilt.template_id)) return error.UntrustedV7CallerGeometry;
            }
        };
        pub const Relations = struct {
            pub const Prepared = struct {
                schedule: Schedule,
                frame: @import("../air/block/memory_event.zig").Frame,
                logs: [4][]const u32,
            };
        };
        pub const Prepared = struct {
            allocator: std.mem.Allocator,
            arithmetic: Arithmetic,
            relations: Relations.Prepared,
            source: Source.Pin,
            epoch: Epoch.Epoch,
            entries: []Epoch.Entry,
            composition_log: u32,
            composition_split: u32,
            mask_log: u32,
            constraint_count: usize,
            template_id: [32]u8,
            limits: Limits,
            pub fn init(a: std.mem.Allocator, expected: Source.Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry, limits: Limits) !Prepared {
                if (entries.len > limits.max_entries or limits.max_columns == 0 or limits.max_claims == 0 or limits.max_samples == 0 or limits.max_capture_bytes == 0) return error.V7CallerResourceLimit;
                const entry = try expected.require(a, epoch, entries);
                const drawn = try Source.draw(a, epoch, entry);
                var arithmetic = try Arithmetic.init(a, expected.statement.*, expected.total_steps, expected.config, drawn.relations, limits.max_columns);
                errdefer arithmetic.deinit();
                var schedule = if (Policy.active) try @import("block_v7_caller_active_schedule_v1.zig").derive(a, expected.statement, expected.total_steps, expected.frame) else try Schedule.init(a, expected.statement, expected.total_steps, expected.frame, 1);
                errdefer schedule.deinit();
                const access = try schedule.witnessLogs();
                errdefer a.free(access);
                const interaction = try schedule.interactionLogs();
                errdefer a.free(interaction);
                if (access.len > limits.max_columns or interaction.len > limits.max_columns) return error.V7CallerResourceLimit;
                const roster = try a.dupe(Epoch.Entry, entries);
                errdefer a.free(roster);
                var result = Prepared{ .allocator = a, .arithmetic = arithmetic, .relations = .{ .schedule = schedule, .frame = expected.frame, .logs = .{ schedule.fixed, schedule.main, access, interaction } }, .source = expected, .epoch = epoch, .entries = roster, .composition_log = 0, .composition_split = 0, .mask_log = 0, .constraint_count = 0, .template_id = undefined, .limits = limits };
                const zero = try Profile.ExtensionClaim.zeroForStatement(expected.statement);
                var claims = try zeroClaims(a, &result.relations.schedule);
                defer claims.deinit(a);
                const equations = try EquationOwner.create(a, &result, &zero, &claims);
                defer equations.destroy();
                result.composition_log = equations.joint.bound;
                result.composition_split = equations.joint.split;
                result.mask_log = result.composition_log - result.composition_split;
                result.constraint_count = equations.joint.constraints;
                result.template_id = try result.identity();
                return result;
            }
            pub fn pin(self: *const Prepared) Source.Pin {
                var out = self.source;
                out.statement = &self.arithmetic.statement;
                return out;
            }
            pub fn logs(self: *const Prepared) [5][]const u32 {
                return .{ self.arithmetic.logs[0], self.arithmetic.logs[1], self.relations.logs[2], self.arithmetic.logs[2], self.relations.logs[3] };
            }
            pub fn deinit(self: *Prepared) void {
                self.allocator.free(self.relations.logs[2]);
                self.allocator.free(self.relations.logs[3]);
                self.relations.schedule.deinit();
                self.arithmetic.deinit();
                self.allocator.free(self.entries);
                self.* = undefined;
            }
            pub fn identity(self: *const Prepared) ![32]u8 {
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ Source.TAG, Source.VERSION, 11, 5, 6, self.composition_log, self.composition_split, self.mask_log });
                ch.mixRoot(self.epoch.digest);
                (try self.pin().entry(self.allocator)).mix(&ch);
                ch.mixRoot(self.arithmetic.template_id);
                @import("block_v5_caller_fused_schedule_v1.zig").mix(&ch, &self.relations.schedule);
                ch.mixU64(self.constraint_count);
                for (self.logs()) |values| {
                    ch.mixU64(values.len);
                    ch.mixU32s(values);
                }
                return ch.digestBytes();
            }
            pub fn validate(self: *const Prepared) !void {
                var rebuilt = try init(self.allocator, self.pin(), self.epoch, self.entries, self.limits);
                defer rebuilt.deinit();
                if (!std.meta.eql(self.template_id, try self.identity()) or !std.meta.eql(self.template_id, rebuilt.template_id)) return error.UntrustedV7CallerGeometry;
                for (self.logs(), rebuilt.logs()) |actual, expected| if (!std.mem.eql(u32, actual, expected)) return error.UntrustedV7CallerGeometry;
            }
        };
        pub const EquationOwner = struct {
            allocator: std.mem.Allocator,
            drawn: Source.Drawn,
            arithmetic: *Policy.Assembly(.verifier),
            relations: Fused.Components,
            handles: []core.air.components.Component,
            joint: *Components.Owner(false),
            pub fn create(a: std.mem.Allocator, admitted: *const Prepared, arithmetic: *const Profile.ExtensionClaim, claims: *const Fused.ClaimFrames) !*EquationOwner {
                try arithmetic.validate(&admitted.arithmetic.statement);
                const schedule = &admitted.relations.schedule;
                if (claims.program_claims.len != schedule.program.len or claims.state_claims.len != schedule.program.len or claims.table_claims.len != schedule.tables.len or claims.memory_claims.len != schedule.memory.len) return error.InvalidV7CallerClaims;
                const self = try a.create(EquationOwner);
                errdefer a.destroy(self);
                self.allocator = a;
                self.drawn = try Source.draw(a, admitted.epoch, try admitted.pin().require(a, admitted.epoch, admitted.entries));
                self.arithmetic = if (Policy.active) try Policy.Assembly(.verifier).init(a, &admitted.arithmetic.statement, admitted.arithmetic.total_steps, &self.drawn.relations, arithmetic) else try Policy.Assembly(.verifier).createBlockV5Standalone(a, &admitted.arithmetic.statement, admitted.arithmetic.total_steps, &self.drawn.relations, arithmetic);
                errdefer self.arithmetic.destroy(a);
                self.relations = try Fused.Components.init(a, schedule, claims, &self.drawn.relations, &self.drawn.epoch.bytes, &self.drawn.epoch.word, admitted.relations.logs[3], admitted.relations.logs[2], 1);
                errdefer self.relations.deinit();
                self.handles = try self.relations.verifier();
                errdefer a.free(self.handles);
                self.joint = try Components.Owner(false).create(a, self.arithmetic.active(), self.handles, admitted.logs(), self.relations.memory.len);
                return self;
            }
            pub fn destroy(self: *EquationOwner) void {
                const a = self.allocator;
                self.joint.destroy();
                a.free(self.handles);
                self.relations.deinit();
                self.arithmetic.destroy(a);
                a.destroy(self);
            }
        };
        pub const zeroClaims = @import("block_v6_caller_joint_admission_v1.zig").zeroClaims;
    };
}
