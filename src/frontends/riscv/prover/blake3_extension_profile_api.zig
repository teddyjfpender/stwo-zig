//! Admission context for the shared extension pipeline. Existing profiles keep
//! their exact transcript; allocating typed admission uses the caller's budget.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../air/statement.zig").Blake3ExecutionStatement;
const Pin = @import("blake3_commitment_plan.zig").Admission;
const Vm = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
pub fn ForProfile(comptime Profile: type) type {
    return struct {
        const Statement = Profile.admission.Statement;
        const Logs = Profile.admission.HashLogs;
        pub fn validate(a: ?std.mem.Allocator, extension: *const Statement, native: *const Native, pin: Pin, logs: Logs) !void {
            if (@hasDecl(Profile.admission, "validateWithAllocator"))
                try Profile.admission.validateWithAllocator(a orelse return error.MissingAdmissionAllocator, extension, native, pin, logs)
            else
                try Profile.admission.validate(extension, native, pin, logs);
        }
        pub fn mix(a: ?std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, native: *const Native, extension: *const Statement, pin: Pin, logs: Logs) !void {
            if (@hasDecl(Profile.protocol, "mixWithAllocator"))
                try Profile.protocol.mixWithAllocator(a orelse return error.MissingAdmissionAllocator, channel, config, native, extension, pin, logs)
            else
                try Profile.protocol.mix(channel, config, native, extension, pin, logs);
        }
        /// Called only after complete admission. Typed protocols avoid a second
        /// fallible allocation after the compact transcript has already changed.
        pub fn mixValidated(a: ?std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, native: *const Native, extension: *const Statement, pin: Pin, logs: Logs) !void {
            if (@hasDecl(Profile.protocol, "mixValidated"))
                try Profile.protocol.mixValidated(channel, config, native, extension, pin, logs)
            else
                try mix(a, channel, config, native, extension, pin, logs);
        }
        pub fn identity(a: ?std.mem.Allocator, config: core.pcs.PcsConfig, native: *const Native, extension: *const Statement, pin: Pin, logs: Logs, root: [32]u8) ![32]u8 {
            if (@hasDecl(Profile.protocol, "identityWithAllocator"))
                return Profile.protocol.identityWithAllocator(a orelse return error.MissingAdmissionAllocator, config, native, extension, pin, logs, root);
            return Profile.protocol.identity(config, native, extension, pin, logs, root);
        }
        pub fn draw(a: std.mem.Allocator, channel: anytype, vm: Vm) !Profile.Relations {
            if (@hasDecl(Profile.Relations, "drawAfterVm")) return Profile.Relations.drawAfterVm(a, channel, vm);
            const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&vm);
            return Profile.Relations.drawAfterBase(a, channel, shared.native);
        }
        pub fn replay(vm: Vm, draws: []const core.fields.qm31.QM31) !Profile.Relations {
            if (draws.len != Profile.draw_count) return error.InvalidChallengeDraw;
            if (@hasDecl(Profile.Relations, "fromVmDraws")) return Profile.Relations.fromVmDraws(vm, draws);
            const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&vm);
            return Profile.Relations.fromDraws(shared.native, draws[0..Profile.draw_count]);
        }
    };
}
