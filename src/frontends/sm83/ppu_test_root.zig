test {
    _ = @import("runner/ppu_mmio.zig");
    _ = @import("runner/rom_only_memory.zig");
    _ = @import("runner/rom_only_hardware_test.zig");
    _ = @import("air/ppu_timing.zig");
    _ = @import("air/ppu_timing_test.zig");
    _ = @import("air/ppu_timing_component.zig");
    _ = @import("air/ppu_binding.zig");
    _ = @import("air/ppu_binding_component.zig");
    _ = @import("air/ppu_binding_test.zig");
    _ = @import("air/ppu_if_memory_lookup.zig");
    _ = @import("air/ppu_if_memory_lookup_component.zig");
    _ = @import("air/ppu_if_memory_lookup_test.zig");
    _ = @import("air/ppu_if_memory_lookup_component_test.zig");
    _ = @import("air/ppu_mmio_lookup.zig");
    _ = @import("air/ppu_mmio_lookup_component.zig");
    _ = @import("air/ppu_mmio_lookup_test.zig");
    _ = @import("air/ppu_mmio_lookup_component_test.zig");
    _ = @import("runner/cartridge_memory_ppu_test.zig");
}
