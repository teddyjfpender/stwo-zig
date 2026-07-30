use super::*;

const ALLOCATION_BYTES: usize = 2 * 1024 * 1024;
const STAGING_BYTES: usize = 64 * 1024;

fn generation_byte(generation: u32) -> u8 {
    (generation as u8).wrapping_mul(73).wrapping_add(19)
}

fn initialized_allocation(context: &CudaExecContext, value: u8) -> VmmAllocation<'_> {
    let allocation = VmmAllocation::new(context, ALLOCATION_BYTES).unwrap();
    unsafe {
        context
            .memset_async(
                allocation.stable_address().as_ptr(),
                value,
                ALLOCATION_BYTES,
            )
            .unwrap();
    }
    context.sync().unwrap();
    allocation
}

#[test]
#[ignore = "requires native CUDA VMM hardware validation"]
fn native_vmm_roundtrips_one_hundred_generations_at_one_address() {
    let context = CudaExecContext::new().unwrap();
    let mut expected = vec![generation_byte(0); ALLOCATION_BYTES];
    let mut actual = vec![0_u8; ALLOCATION_BYTES];
    let mut allocation = initialized_allocation(&context, generation_byte(0));
    let stable_address = allocation.stable_address();
    let mut staging = PinnedDmaWindow::new(STAGING_BYTES).unwrap();

    for current_generation in 0..100_u32 {
        unsafe {
            allocation
                .spill_through_staging(&mut staging, current_generation, &mut actual)
                .unwrap();
        }
        assert_eq!(actual, expected);
        assert_eq!(allocation.stable_address(), stable_address);
        assert_eq!(staging.state(), PinnedDmaWindowState::Ready);
        assert_eq!(
            allocation.state(),
            VmmAllocationState::Unmapped {
                generation: current_generation,
            }
        );

        let next_generation = current_generation + 1;
        expected.fill(generation_byte(next_generation));
        unsafe {
            allocation
                .restore_through_staging(
                    &mut staging,
                    current_generation,
                    next_generation,
                    &expected,
                )
                .unwrap();
        }
        assert_eq!(allocation.stable_address(), stable_address);
        assert_eq!(staging.state(), PinnedDmaWindowState::Ready);
        assert_eq!(
            allocation.state(),
            VmmAllocationState::Mapped {
                generation: next_generation,
            }
        );
    }

    unsafe {
        allocation
            .spill_through_staging(&mut staging, 100, &mut actual)
            .unwrap();
    }
    assert_eq!(actual, expected);
    assert_eq!(allocation.stable_address(), stable_address);
    assert_eq!(staging.state(), PinnedDmaWindowState::Ready);
    assert_eq!(
        allocation.state(),
        VmmAllocationState::Unmapped { generation: 100 }
    );
}

#[test]
#[ignore = "requires native CUDA VMM hardware validation"]
fn native_stale_unmap_poisons_the_raw_handle() {
    let context = CudaExecContext::new().unwrap();
    let allocation = initialized_allocation(&context, 0x5a);
    let bad = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_unmap_release(
            allocation.handle.as_ptr(),
            context.identity_token().as_ptr(),
            1,
        )
    };
    assert_ne!(bad, 0);
    let retry = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_unmap_release(
            allocation.handle.as_ptr(),
            context.identity_token().as_ptr(),
            0,
        )
    };
    assert_ne!(retry, 0, "a poisoned raw handle admitted a correct retry");
    assert_eq!(
        allocation.state(),
        VmmAllocationState::Mapped { generation: 0 }
    );
}

#[test]
#[ignore = "requires native CUDA VMM hardware validation"]
fn native_stale_and_skipped_remaps_poison_the_raw_handle() {
    let context = CudaExecContext::new().unwrap();
    for (current_generation, next_generation) in [(1, 2), (0, 2)] {
        let mut allocation = initialized_allocation(&context, 0x5a);
        let mut staging = PinnedDmaWindow::new(STAGING_BYTES).unwrap();
        let mut host = vec![0_u8; ALLOCATION_BYTES];
        unsafe {
            allocation
                .spill_through_staging(&mut staging, 0, &mut host)
                .unwrap();
        }
        let bad = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_remap_next(
                allocation.handle.as_ptr(),
                context.identity_token().as_ptr(),
                current_generation,
                next_generation,
            )
        };
        assert_ne!(bad, 0);
        let retry = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_vmm_allocation_remap_next(
                allocation.handle.as_ptr(),
                context.identity_token().as_ptr(),
                0,
                1,
            )
        };
        assert_ne!(retry, 0, "a poisoned raw handle admitted a correct retry");
        assert_eq!(
            allocation.state(),
            VmmAllocationState::Unmapped { generation: 0 }
        );
        assert_eq!(staging.state(), PinnedDmaWindowState::Ready);
    }
}
