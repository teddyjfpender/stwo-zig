//! Concrete bridge from the installed final Stage-102 lifecycle to its
//! path-free immutable inventory receipt.
//!
//! The owner remains process-local and nonserializable.  Only the exact
//! immutable Session projection is encoded.  Callers may retain returned
//! canonical bytes or atomically replace one explicitly selected output path;
//! no command-line route or derived filesystem location exists here.

const std = @import("std");

const description =
    @import("recursive_pipeline_campaign_stage102_inventory_description_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FINAL_SESSION = false;
pub const CALLER_OWNS_OUTPUT_PATH = true;
pub const VALIDATE_BEFORE_OPEN = true;
pub const ATOMIC_REPLACE = true;

pub fn BridgeFor(comptime Lifecycle: type) type {
    assertLifecycle(Lifecycle);
    const Session = Lifecycle.ImmutableSessionV4;
    const Owner = Lifecycle.OwnedFinalSessionV4;
    const Description = description.DescriptionFor(Session);

    return struct {
        pub const ImmutableSessionV4 = Session;
        pub const OwnedFinalSessionV4 = Owner;

        /// Revalidates the installed lifecycle and its complete immutable
        /// Session before returning caller-owned canonical JSON bytes.
        pub fn encodeCanonicalJsonAlloc(
            allocator: std.mem.Allocator,
            owner: *Owner,
        ) ![]u8 {
            try owner.validate(allocator);
            const session = try owner.immutableSession();
            return Description.encodeCanonicalJsonAlloc(allocator, session);
        }

        /// Builds and validates all bytes before opening the selected path.
        /// Once opened, `AtomicFile` keeps the previous file intact unless the
        /// complete new receipt is flushed and renamed into place.
        pub fn writeCanonicalFileAtomic(
            allocator: std.mem.Allocator,
            owner: *Owner,
            directory: std.fs.Dir,
            output_path: []const u8,
        ) !void {
            if (output_path.len == 0)
                return error.InvalidStage102InventoryDescriptionOutputPathV4;
            const encoded = try encodeCanonicalJsonAlloc(allocator, owner);
            defer allocator.free(encoded);

            var write_buffer: [64 * 1024]u8 = undefined;
            var output = try directory.atomicFile(output_path, .{
                .write_buffer = &write_buffer,
            });
            defer output.deinit();
            try output.file_writer.interface.writeAll(encoded);
            try output.finish();
        }
    };
}

fn assertLifecycle(comptime Lifecycle: type) void {
    inline for (.{
        "ImmutableSessionV4",
        "OwnedFinalSessionV4",
    }) |name| if (!@hasDecl(Lifecycle, name))
        @compileError("Stage102 inventory description lifecycle missing " ++ name);
    const Owner = Lifecycle.OwnedFinalSessionV4;
    inline for (.{ "validate", "immutableSession" }) |name|
        if (!@hasDecl(Owner, name))
            @compileError("Stage102 inventory description owner missing " ++ name);
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(Owner, name))
            @compileError("Stage102 final Session owner gained a codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FINAL_SESSION or !CALLER_OWNS_OUTPUT_PATH or
        !VALIDATE_BEFORE_OPEN or !ATOMIC_REPLACE)
    {
        @compileError("Stage102 inventory description bridge drifted");
    }
}
