//! One `sha256_compress` candidate ECALL per 64-byte block.
//! Packet (96 bytes = 12 u64, 8-aligned): H0..H7 as little-endian u32 (H0 in
//! the low half of word 0), then the block bytes in stream order. Only the
//! state words are updated; all registers are preserved.

const TAG: usize = 0x0003_0010;

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    let mut packet = [0u64; 12];
    for i in 0..4 {
        packet[i] = u64::from(state[2 * i]) | (u64::from(state[2 * i + 1]) << 32);
    }
    for block in blocks {
        let src = block.as_ptr();
        if src as usize & 7 == 0 {
            for i in 0..8 {
                // SAFETY: 8-aligned and inside the 64-byte block.
                packet[4 + i] = unsafe { core::ptr::read(src.add(8 * i).cast::<u64>()) };
            }
        } else {
            for i in 0..8 {
                let mut word = [0u8; 8];
                word.copy_from_slice(&block[8 * i..8 * i + 8]);
                packet[4 + i] = u64::from_le_bytes(word);
            }
        }
        // SAFETY: the packet is live, 8-aligned and unique; the service reads
        // 96 bytes and writes the first 32 in place, preserving all registers.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.as_mut_ptr(), in("a7") TAG, options(nostack));
        }
    }
    for i in 0..4 {
        state[2 * i] = packet[i] as u32;
        state[2 * i + 1] = (packet[i] >> 32) as u32;
    }
}
