use stwo_backend_cuda_kernels::raw::CudaFunctionAttributes;

use super::replacement_stage4_common::LoadedFunctionReceipt;

pub fn loaded_function_receipts() -> Vec<LoadedFunctionReceipt> {
    const FUNCTIONS: &[(u32, &str, &str)] = &[
        (
            0,
            "baseline_staged_packed",
            "stwo_quotient_numerator_packed_single_write_kernel",
        ),
        (
            1,
            "candidate_prepacked_prepare",
            "stwo_prepare_quotient_numerator_prepacked_terms_kernel",
        ),
        (
            2,
            "candidate_prepacked_validate",
            "stwo_validate_quotient_numerator_prepacked_terms_kernel",
        ),
        (
            3,
            "candidate_prepacked_hot",
            "stwo_quotient_numerator_prepacked_single_write_kernel",
        ),
        (
            4,
            "candidate_group_direct",
            "stwo_quotient_numerator_group_direct_kernel",
        ),
    ];
    let target_sms = stwo_backend_cuda_kernels::static_cuda_module_target_sms();
    assert!(!target_sms.is_empty());
    let receipts = FUNCTIONS
        .iter()
        .map(|&(role, name, symbol)| {
            let mut attributes = CudaFunctionAttributes::default();
            let code = unsafe {
                stwo_quotient_numerator_single_write_function_attributes(role, &mut attributes)
            };
            assert_eq!(code, 0, "loaded-function query failed for {symbol}");
            assert!(
                attributes.abi_version == 1
                    && attributes.reserved == 0
                    && attributes.max_threads_per_block >= 256
                    && attributes.binary_version != 0
                    && attributes.ptx_version != 0
                    && attributes.ptx_version <= attributes.binary_version
                    && target_sms.contains(&attributes.binary_version),
                "invalid loaded-function facts for {symbol}: {attributes:?}"
            );
            LoadedFunctionReceipt {
                role: name,
                symbol,
                launch_threads: 256,
                dynamic_shared_bytes: 0,
                abi_version: attributes.abi_version,
                max_threads_per_block: attributes.max_threads_per_block,
                registers_per_thread: attributes.registers_per_thread,
                binary_version: attributes.binary_version,
                ptx_version: attributes.ptx_version,
                reserved: attributes.reserved,
                local_bytes: attributes.local_bytes,
                static_shared_bytes: attributes.static_shared_bytes,
            }
        })
        .collect::<Vec<_>>();
    let mut invalid = CudaFunctionAttributes::default();
    assert_ne!(
        unsafe { stwo_quotient_numerator_single_write_function_attributes(u32::MAX, &mut invalid) },
        0
    );
    assert_eq!(invalid, CudaFunctionAttributes::default());
    receipts
}

extern "C" {
    fn stwo_quotient_numerator_single_write_function_attributes(
        role: u32,
        out: *mut CudaFunctionAttributes,
    ) -> i32;
}
