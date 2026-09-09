//! Exact final-assembly lifetime guard for a live campaign runtime.
//!
//! The installed Session transitively borrows a role-0 Authority and final
//! remint, while `ValidatedAssemblyV2` is the authority that proves those
//! pointers belong to a still-live genuine final owner and ActiveSources.
//! This guard stores and revalidates that exact assembly and source pointer
//! for the full Worker/lease lifetime. It adds no durable identity or route.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXACT_VALIDATED_ASSEMBLY_POINTER_REQUIRED = true;
pub const EXACT_ACTIVE_SOURCES_POINTER_REQUIRED = true;
pub const RUNTIME_DESTROYED_BEFORE_ASSEMBLY_BORROW_RELEASE = true;

pub const Error = error{
    CampaignFinalAssemblyBoundRuntimeMismatchV2,
    CampaignFinalAssemblyBoundRuntimeUnavailableV2,
};

/// `runtime` ownership transfers only after `init` succeeds. The Assembly,
/// ActiveSources, and their transitive genuine-final owner remain borrowed
/// and must outlive this guard. On rejection the caller still owns `runtime`.
pub fn OwnerFor(
    comptime Runtime: type,
    comptime Assembly: type,
    comptime ActiveSources: type,
) type {
    assertTypes(Runtime, Assembly);

    return struct {
        const Self = @This();

        pub const available = Runtime.available;
        pub const OwnedRuntimeV2 = Runtime;
        pub const ValidatedAssemblyV2 = Assembly;
        pub const ActiveSourcesV2 = ActiveSources;

        allocator: std.mem.Allocator,
        runtime: *Runtime,
        assembly: *const Assembly,
        assembly_identity: *const Assembly,
        active_sources: *const ActiveSources,
        active_sources_identity: *const ActiveSources,

        pub fn init(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            runtime: *Runtime,
            assembly: *const Assembly,
            active_sources: *const ActiveSources,
        ) !*Self {
            if (comptime !available)
                return error.CampaignFinalAssemblyBoundRuntimeUnavailableV2;
            const candidate = Self{
                .allocator = owner_allocator,
                .runtime = runtime,
                .assembly = assembly,
                .assembly_identity = assembly,
                .active_sources = active_sources,
                .active_sources_identity = active_sources,
            };
            // Validate before allocation. Failure leaves `runtime` wholly in
            // caller custody and cannot alter the installed provider epoch.
            try candidate.validate(scratch_allocator);
            const self = try owner_allocator.create(Self);
            self.* = candidate;
            return self;
        }

        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.runtime.validate(scratch_allocator);
            try self.assembly.validate();
            const epoch = self.runtime.epoch;
            const session = epoch.session;
            const assembly_sources: *const ActiveSources =
                self.assembly.active_sources;
            if (self.assembly != self.assembly_identity or
                self.active_sources != self.active_sources_identity or
                assembly_sources != self.active_sources or
                epoch.lifecycle != self.runtime.lifecycle or
                session.authority != self.assembly.role0_authority or
                session.authority.final_remint != self.assembly.finalRemint() or
                epoch.driver.final_remint != self.assembly.finalRemint())
            {
                return error.CampaignFinalAssemblyBoundRuntimeMismatchV2;
            }
        }

        pub fn runtimeView(self: *Self) *Runtime {
            return self.runtime;
        }

        /// Failure-atomic while validation fails. On success the assembly
        /// borrow is released only after the caller regains the live runtime.
        pub fn releaseRuntime(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
        ) !*Runtime {
            try self.validate(scratch_allocator);
            const allocator = self.allocator;
            const runtime = self.runtime;
            self.* = undefined;
            allocator.destroy(self);
            return runtime;
        }

        /// Destroys Worker leases, Worker, and installed lifecycle before
        /// dropping this guard's assembly/ActiveSources borrows.
        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.runtime.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertTypes(comptime Runtime: type, comptime Assembly: type) void {
    inline for (.{
        "available",
        "RuntimeEpochV2",
        "LifecycleV4",
        "validate",
        "deinit",
    }) |name| if (!@hasDecl(Runtime, name))
        @compileError("assembly-bound runtime missing " ++ name);
    inline for (.{ "validate", "finalRemint" }) |name|
        if (!@hasDecl(Assembly, name))
            @compileError("assembly-bound authority missing " ++ name);
    inline for (.{ "role0_authority", "active_sources" }) |name|
        if (!@hasField(Assembly, name))
            @compileError("assembly-bound authority field missing " ++ name);
    inline for (.{ "epoch", "lifecycle" }) |name|
        if (!@hasField(Runtime, name))
            @compileError("assembly-bound runtime custody field missing " ++ name);
    rejectCodec(Runtime);
    rejectCodec(Assembly);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("assembly-bound runtime gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !EXACT_VALIDATED_ASSEMBLY_POINTER_REQUIRED or
        !EXACT_ACTIVE_SOURCES_POINTER_REQUIRED or
        !RUNTIME_DESTROYED_BEFORE_ASSEMBLY_BORROW_RELEASE)
    {
        @compileError("campaign assembly-bound runtime contract drifted");
    }
}
