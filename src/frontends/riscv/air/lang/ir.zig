//! Owned storage for the typed AIR logical program.
//!
//! The arena owns every stable string and source record. No caller-provided
//! slice is retained, and no process-global context is used.

const std = @import("std");
const source_mod = @import("source.zig");
const types = @import("types.zig");

pub const ArenaError = error{
    EmptyStableName,
    UnknownSource,
};

pub const Arena = struct {
    allocator: std.mem.Allocator,
    names: std.ArrayList([]const u8),
    names_by_text: std.StringHashMap(types.NameId),
    sources: std.ArrayList(source_mod.Source),
    sources_by_path: std.AutoHashMap(types.NameId, types.SourceId),

    pub fn init(allocator: std.mem.Allocator) Arena {
        return .{
            .allocator = allocator,
            .names = .empty,
            .names_by_text = std.StringHashMap(types.NameId).init(allocator),
            .sources = .empty,
            .sources_by_path = std.AutoHashMap(types.NameId, types.SourceId).init(allocator),
        };
    }

    pub fn deinit(self: *Arena) void {
        self.sources_by_path.deinit();
        self.sources.deinit(self.allocator);
        self.names_by_text.deinit();
        for (self.names.items) |stable_name| self.allocator.free(stable_name);
        self.names.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn internName(self: *Arena, text: []const u8) !types.NameId {
        if (text.len == 0) return error.EmptyStableName;
        if (self.names_by_text.get(text)) |existing| return existing;

        const id = try types.idFromIndex(types.NameId, self.names.items.len);
        const owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned);
        try self.names.append(self.allocator, owned);
        errdefer _ = self.names.pop();
        try self.names_by_text.put(owned, id);
        return id;
    }

    pub fn name(self: *const Arena, id: types.NameId) ?[]const u8 {
        const index = types.idIndex(id);
        if (index >= self.names.items.len) return null;
        return self.names.items[index];
    }

    pub fn addSource(self: *Arena, path: []const u8) !types.SourceId {
        const path_id = try self.internName(path);
        if (self.sources_by_path.get(path_id)) |existing| return existing;

        const id = try types.idFromIndex(types.SourceId, self.sources.items.len);
        try self.sources.append(self.allocator, .{ .path = path_id });
        errdefer _ = self.sources.pop();
        try self.sources_by_path.put(path_id, id);
        return id;
    }

    pub fn source(self: *const Arena, id: types.SourceId) ?source_mod.Source {
        const index = types.idIndex(id);
        if (index >= self.sources.items.len) return null;
        return self.sources.items[index];
    }

    pub fn sourcePath(self: *const Arena, id: types.SourceId) ?[]const u8 {
        const item = self.source(id) orelse return null;
        return self.name(item.path);
    }

    pub fn validateSpan(
        self: *const Arena,
        span: source_mod.SourceSpan,
    ) !void {
        try span.validate();
        if (span.source) |source_id| {
            if (self.source(source_id) == null) return error.UnknownSource;
        }
    }
};
