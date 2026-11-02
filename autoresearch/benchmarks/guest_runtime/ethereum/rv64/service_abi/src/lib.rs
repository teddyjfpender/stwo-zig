//! Audited instruction boundary for the explicit RV64 Ethereum-services v1 ABI.
//! Crypto arithmetic and packet encoding remain in k256 with unsafe forbidden.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// Canonical big-endian coordinates, lhsXYZ followed by rhsXYZ. Only lhsXYZ is
/// overwritten. The alignment is part of the execution and proving contract.
#[repr(C, align(32))]
pub struct AddPacket(pub [[u8; 32]; 6]);
#[repr(C, align(32))]
pub struct DoublePacket(pub [[u8; 32]; 3]);
const _: [(); 192] = [(); core::mem::size_of::<AddPacket>()];
const _: [(); 96] = [(); core::mem::size_of::<DoublePacket>()];
const _: [(); 32] = [(); core::mem::align_of::<AddPacket>()];

#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn add(packet: &mut AddPacket) {
    invoke(packet.0.as_mut_ptr().cast(), 0x0002_0001);
}
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn double(packet: &mut DoublePacket) {
    invoke(packet.0.as_mut_ptr().cast(), 0x0002_0002);
}
#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn invoke(packet: *mut u8, tag: usize) {
    // The admitted ABI preserves all registers and atomically updates the
    // referenced packet. Both public callers pass live, aligned, unique packet
    // references. Default asm memory effects prohibit hoisting packet loads.
    unsafe { core::arch::asm!("ecall", in("a0") packet, in("a7") tag, options(nostack)) };
}

/// V2 keeps the same32-byte coordinate geometry but stores four native little-
/// endian words. It avoids byte-wise field conversion in an RV64IM guest.
pub mod words {
    #[repr(C, align(32))]
    pub struct AddPacket(pub [[u64; 4]; 6]);
    #[repr(C, align(32))]
    pub struct DoublePacket(pub [[u64; 4]; 3]);
    const _: [(); 192] = [(); core::mem::size_of::<AddPacket>()];
    const _: [(); 96] = [(); core::mem::size_of::<DoublePacket>()];
    #[cfg(target_arch = "riscv64")]
    #[inline(always)]
    pub fn add(packet: &mut AddPacket) {
        super::invoke(packet.0.as_mut_ptr().cast(), 0x0002_0011);
    }
    #[cfg(target_arch = "riscv64")]
    #[inline(always)]
    pub fn double(packet: &mut DoublePacket) {
        super::invoke(packet.0.as_mut_ptr().cast(), 0x0002_0012);
    }
}
