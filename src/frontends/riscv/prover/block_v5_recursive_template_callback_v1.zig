//! Producer setup notification, not proof authority. The original recursive
//! stage calls this only after fresh base verification and real row-derived
//! key construction. Receivers reconstruct the same template independently.
pub fn ForTypes(comptime Prepared: type, comptime Key: type, comptime Wire: type) type {
    return struct {
        context: *anyopaque,
        derived: *const fn (*anyopaque, *const Prepared, Key, [32]u8, []const Wire) anyerror!void,
        pub fn admit(self: @This(), prepared: *const Prepared, key: Key, id: [32]u8, wires: []const Wire) !void {
            try self.derived(self.context, prepared, key, id, wires);
        }
    };
}

/// Only an exact retained source owner can bind a durable writer slot. Keys
/// and schedules are copied by the bounded Store, never borrowed from an
/// artifact or chosen by a received envelope.
pub fn ForStore(comptime StoreModule: type, comptime Prepared: type, comptime Key: type, comptime Wire: type, comptime indexOf: fn (*const Prepared) u32) type {
    return struct {
        const Self = @This();
        pub const Callback = ForTypes(Prepared, Key, Wire);
        store: *StoreModule.Store,
        pub fn callback(self: *Self) Callback {
            return .{ .context = self, .derived = derived };
        }
        fn derived(raw: *anyopaque, prepared: *const Prepared, key: Key, id: [32]u8, wires: []const Wire) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(raw));
            const index = indexOf(prepared);
            const source = try self.store.sourceFor(index);
            if (source.prepared != prepared) return error.UntrustedRecursiveTemplateSourceOwner;
            try self.store.bindWriterTemplate(index, .{ .key = key, .key_id = id, .schedule = wires });
        }
    };
}
