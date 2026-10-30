// Matched software-only benchmark ABI for both RV32IM and RV64IM. This replaces
// the pinned upstream's riscv32-only guest glue, not the crypto computations.
// Input/output lengths and halt are u32 on both machines; pointers use XLEN.
core::arch::global_asm!(r#"
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    call __zkvm_start
"#);

unsafe extern "C" {
    static __input_start: u8;
    static __input_end: u8;
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
}

mod guest_lib {
    pub mod io {
        pub unsafe fn read_input_u32() -> u32 {
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(crate::__input_start).cast()) }
        }
        pub unsafe fn read_input_bytes_at(offset: usize, output: &mut [u8]) -> usize {
            let start = core::ptr::addr_of!(crate::__input_start) as usize;
            let end = core::ptr::addr_of!(crate::__input_end) as usize;
            let count = output.len().min(end.saturating_sub(start).saturating_sub(offset));
            for (index, byte) in output[..count].iter_mut().enumerate() {
                *byte = unsafe { core::ptr::read_volatile((start + offset + index) as *const u8) };
            }
            count
        }
    }
}

fn publish_raw(output: &[u8]) -> ! {
    unsafe {
        let destination = core::ptr::addr_of!(__output_data) as *mut u8;
        for (index, byte) in output.iter().enumerate() {
            core::ptr::write_volatile(destination.add(index), *byte);
        }
        core::ptr::write_volatile(core::ptr::addr_of!(__output_len) as *mut u32, output.len() as u32);
        core::ptr::write_volatile(core::ptr::addr_of!(__halt_flag) as *mut u32, 1);
    }
    loop { core::hint::spin_loop(); }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A panic never publishes a completion flag or a successful output.
    loop { core::hint::spin_loop(); }
}

macro_rules! guest_main_raw {
    ($expr:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn __zkvm_start() -> ! { publish_raw(&$expr) }
    };
}
