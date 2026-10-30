//! Explicit first-round identity for the experimental native/endpoint source.
//! Metadata alone is not proof authority. Receivers independently derive this
//! descriptor from admitted public policy and require the exact fixed/main
//! columns and all physical claims in the enclosing B8 original STARK.
const std = @import("std");
const core = @import("stwo_core");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Frame = @import("../air/block/memory_event.zig").Frame;
const Kernel = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Native = @import("block_v8_native_endpoint_closure_v1.zig");
const Layout = @import("block_v8_native_endpoint_layout_v1.zig");
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const Descriptor = struct {
    scope: Native.Scope,
    frame: Frame,
    layout: [32]u8,
    // The fixed root is the enclosing complete merged fixed tree. The three
    // private roots belong to native, endpoint and endpoint-range witnesses.
    // This four-root family cannot masquerade as the old V7 native entry.
    roots: [4][32]u8,
    /// Endpoint count is NOT the number of executed memory accesses. The
    /// global sorted provider consumes these compressed transitions; logical
    /// execution counts remain native statement / ROM closure obligations.
    pub fn derive(a: std.mem.Allocator, shape: *const Shape, profile: @import("../runner/elf_loader.zig").ExecutionProfile, frame: Frame, policy: Kernel.Policy, endpoint_count: u32, roots: [4][32]u8) !Descriptor {
        return deriveWithHalt(a, shape, profile, frame, policy, endpoint_count, roots, null);
    }
    pub fn deriveWithHalt(a: std.mem.Allocator, shape: *const Shape, profile: @import("../runner/elf_loader.zig").ExecutionProfile, frame: Frame, policy: Kernel.Policy, endpoint_count: u32, roots: [4][32]u8, halt: ?@import("block_v8_native_halt_policy_v1.zig").Policy) !Descriptor {
        return deriveWithNativeProfile(a, shape, profile, frame, policy, endpoint_count, roots, halt, .endpoint_v2);
    }
    pub fn deriveWithNativeProfile(a: std.mem.Allocator, shape: *const Shape, profile: @import("../runner/elf_loader.zig").ExecutionProfile, frame: Frame, policy: Kernel.Policy, endpoint_count: u32, roots: [4][32]u8, halt: ?@import("block_v8_native_halt_policy_v1.zig").Policy, native_profile: @import("block_v8_native_endpoint_profile_v1.zig").Profile) !Descriptor {
        if (native_profile.isDirect() and (halt == null)) return error.UnsupportedDirectRamClockProfile;
        if (halt) |p| try p.validate();
        if (frame.clock_frame != .leaf_local or frame.global_first_cycle == 0 or
            frame.cycle_count != shape.public_data.clock)
            return error.InvalidEndpointSourceFrame;
        try shape.validateBlake3ExecutionWithExternal(0);
        try policy.validate();
        for (roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidEndpointSourceRoots;
        var layout = try @import("block_v8_native_endpoint_profile_v1.zig").layout(a, shape, native_profile);
        defer layout.deinit();
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42384e44, VERSION, @intFromEnum(profile), policy.source_ordinal, policy.max_local_clock, endpoint_count });
        if (native_profile.isDirect()) channel.mixU32s(&.{ 0x52434c33, @intFromEnum(native_profile) });
        channel.mixU32s(&.{@intFromBool(halt != null)});
        if (halt) |p| channel.mixU32s(&.{ p.halt_address, p.permitted_final_instruction_cycle orelse 0 });
        channel.mixU64(try policy.globalClock());
        channel.mixRoot(layout.digest);
        shape.public_data.mixInto(&channel);
        shape.mixShardManifest(&channel);
        channel.mixU64(frame.global_first_cycle);
        channel.mixU32s(&.{frame.cycle_count});
        // Including every root binds witness identity into the epoch before
        // any shared relation challenge is drawn. No phantom access root.
        for (roots) |root| channel.mixRoot(root);
        const scope = Native.Scope{ .native_index = policy.source_ordinal, .native_profile = native_profile, .execution_profile = profile, .native_identity = channel.digestBytes(), .endpoint_count = endpoint_count, .policy = policy, .halt = halt };
        try scope.admit(shape, 0);
        return .{ .scope = scope, .frame = frame, .layout = layout.digest, .roots = roots };
    }
    pub fn entry(self: Descriptor) !Epoch.Entry {
        return Epoch.Entry.init(.native, self.scope.native_index, self.scope.native_identity, &self.roots);
    }
    /// This is a comparison against independently reconstructed metadata,
    /// never a self-authentication check on producer-supplied identity bytes.
    pub fn require(self: Descriptor, expected: Descriptor) !void {
        if (!std.meta.eql(self, expected)) return error.UntrustedEndpointSourceDescriptor;
    }
};
