pub const ResidentStorage = struct {
    handle: *anyopaque,
    destroyFn: *const fn (*anyopaque) void,
    /// Optional local owner context; handle remains the real device handle.
    /// Copying storage does not retain this consuming owner.
    owner_context: ?*anyopaque = null,
    destroyContextFn: ?*const fn (*anyopaque, *anyopaque) void = null,

    pub fn deinit(self: ResidentStorage) void {
        if (self.destroyContextFn) |destroy| {
            destroy(self.owner_context orelse unreachable, self.handle);
        } else self.destroyFn(self.handle);
    }
};
