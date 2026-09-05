//! Exact two-member CUSTOM-0 classifier for the combined candidate session.

const authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry_v1.zig");
const bulk_dispatch = @import("bulk_memcpy_candidate_dispatch_v1.zig");
const swap_dispatch = @import("stack_swap_candidate_dispatch_v1.zig");

pub const production_active = false;

pub const Dispatcher = struct {
    authority: authority_mod.Authority,
    bulk_memcpy: bulk_dispatch.Dispatcher,
    stack_swap: swap_dispatch.Dispatcher,

    pub fn init(authority: authority_mod.Authority) !Dispatcher {
        try authority.validate();
        return .{
            .authority = authority,
            .bulk_memcpy = try .init(authority.bulk_memcpy.bulk_memcpy),
            .stack_swap = try .init(authority.stack_swap.stack_swap),
        };
    }

    pub fn validate(self: Dispatcher) !void {
        try self.authority.validate();
        try self.bulk_memcpy.validate();
        try self.stack_swap.validate();
    }

    pub fn claim(
        self: Dispatcher,
        inst_word: u32,
    ) !?registry_mod.MemberKind {
        try self.validate();
        const bulk = self.bulk_memcpy.claims(inst_word);
        const swap = self.stack_swap.claims(inst_word);
        if (bulk and swap) return error.EthereumCandidateDispatchCollision;
        if (bulk) return .bulk_memcpy_v1;
        if (swap) return .stack_swap_v1;
        return null;
    }
};

comptime {
    if (production_active or authority_mod.production_active or
        registry_mod.production_active or bulk_dispatch.production_active or
        swap_dispatch.production_active)
    {
        @compileError("combined candidate dispatcher became active");
    }
}

test "combined dispatcher claims exactly the two ordered registry words" {
    var digest = [_]u8{0} ** 32;
    digest[0] = 1;
    const authority = try authority_mod.Authority.create(digest);
    const dispatcher = try Dispatcher.init(authority);
    try @import("std").testing.expectEqual(
        registry_mod.MemberKind.bulk_memcpy_v1,
        (try dispatcher.claim(authority.bulk_memcpy.bulk_memcpy.fixed_word)).?,
    );
    try @import("std").testing.expectEqual(
        registry_mod.MemberKind.stack_swap_v1,
        (try dispatcher.claim(authority.stack_swap.stack_swap.fixed_word)).?,
    );
    try @import("std").testing.expect((try dispatcher.claim(0x0000_0013)) == null);
}
