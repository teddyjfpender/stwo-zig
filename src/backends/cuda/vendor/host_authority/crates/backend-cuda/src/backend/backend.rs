use serde::{Deserialize, Serialize};
use stwo::core::channel::Blake2sChannelGeneric;
use stwo::core::proof_of_work::GrindOps;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Backend, BackendForChannel};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct CudaBackend;

impl Backend for CudaBackend {}

// Byte-equality: grinding must reproduce the reference nonce, so it delegates to the
// SIMD backend on both channel variants.
impl GrindOps<Blake2sChannelGeneric<false>> for CudaBackend {
    /// GPU grind: chunked `atomicMin` search returning the LOWEST valid nonce, which
    /// matches the SIMD search order byte-exactly (same `H(POW_PREFIX, [0;12], digest,
    /// pow_bits)` preimage, same trailing-zero check on the first output word).
    fn grind(channel: &Blake2sChannelGeneric<false>, pow_bits: u32) -> u64 {
        use stwo::core::vcs::blake2_hash::Blake2sHasherGeneric;
        assert!(pow_bits <= 32, "pow_bits > 32 is not supported");
        let digest = channel.digest();

        let mut hasher = Blake2sHasherGeneric::<false>::default();
        hasher.update(&Blake2sChannelGeneric::<false>::POW_PREFIX.to_le_bytes());
        hasher.update(&[0_u8; 12]);
        hasher.update(&digest.0[..]);
        hasher.update(&pow_bits.to_le_bytes());
        let prefixed_digest = hasher.finalize();
        let prefixed_words: Vec<u32> = prefixed_digest
            .0
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        crate::columns::bindings::ensure_mem_pool_init();
        unsafe { stwo_backend_cuda_kernels::raw::grind_blake2s(prefixed_words.as_ptr(), pow_bits) }
    }
}

impl GrindOps<Blake2sChannelGeneric<true>> for CudaBackend {
    /// The M31-output channel's PoW hash differs at finalize; the GPU kernel implements
    /// the non-M31 variant only, so this delegates (NitrooZK does the same).
    fn grind(channel: &Blake2sChannelGeneric<true>, pow_bits: u32) -> u64 {
        SimdBackend::grind(channel, pow_bits)
    }
}

impl BackendForChannel<Blake2sMerkleChannel> for CudaBackend {
    fn prove_values_driver<'a>(
        commitment_scheme: stwo::prover::pcs::CommitmentSchemeProver<
            'a,
            Self,
            Blake2sMerkleChannel,
        >,
        sampled_points: stwo::core::pcs::TreeVec<
            stwo::core::ColumnVec<
                Vec<stwo::core::circle::CirclePoint<stwo::core::fields::qm31::SecureField>>,
            >,
        >,
        channel: &mut stwo::core::channel::Blake2sChannel,
    ) -> stwo::core::pcs::quotients::ExtendedCommitmentSchemeProof<
        <Blake2sMerkleChannel as stwo::core::channel::MerkleChannel>::H,
    > {
        // Migration-only escape hatch for same-binary typed-driver review.
        // Strict gpu-native orchestration rejects this variable before proving.
        if std::env::var("STWO_CUDA_PCS_REFERENCE").as_deref() == Ok("1") {
            return commitment_scheme.prove_values_reference(sampled_points, channel);
        }
        let mut config = super::pcs_driver::CudaPcsDriverConfig::detached_eager();
        super::pcs_driver::prove_values_with_config(
            commitment_scheme,
            sampled_points,
            channel,
            &mut config,
        )
        .expect("detached CUDA PCS driver has no fallible graph hook")
        .proof
    }
}

impl BackendForChannel<Blake2sM31MerkleChannel> for CudaBackend {
    fn prove_values_driver<'a>(
        commitment_scheme: stwo::prover::pcs::CommitmentSchemeProver<
            'a,
            Self,
            Blake2sM31MerkleChannel,
        >,
        sampled_points: stwo::core::pcs::TreeVec<
            stwo::core::ColumnVec<
                Vec<stwo::core::circle::CirclePoint<stwo::core::fields::qm31::SecureField>>,
            >,
        >,
        channel: &mut stwo::core::channel::Blake2sM31Channel,
    ) -> stwo::core::pcs::quotients::ExtendedCommitmentSchemeProof<
        <Blake2sM31MerkleChannel as stwo::core::channel::MerkleChannel>::H,
    > {
        if std::env::var("STWO_CUDA_PCS_REFERENCE").as_deref() == Ok("1") {
            return commitment_scheme.prove_values_reference(sampled_points, channel);
        }
        let mut config = super::pcs_driver::CudaPcsDriverConfig::detached_eager();
        super::pcs_driver::prove_values_with_config(
            commitment_scheme,
            sampled_points,
            channel,
            &mut config,
        )
        .expect("detached CUDA PCS driver has no fallible graph hook")
        .proof
    }
}

impl stwo_constraint_framework::FrameworkBackend for CudaBackend {
    fn evaluate_constraint_quotients_on_domain<
        E: stwo_constraint_framework::FrameworkEval + Sync,
    >(
        component: &stwo_constraint_framework::FrameworkComponent<E>,
        trace: &stwo::prover::Trace<'_, Self>,
        evaluation_accumulator: &mut stwo::prover::DomainEvaluationAccumulator<Self>,
    ) {
        // Per-component GPU kernels (NitrooZK lineage) with CPU fallback on the same
        // accumulator claim; STWO_CUDA_DISABLE_CONSTRAINT_KERNELS forces the fallback.
        super::constraint_eval::evaluate_constraint_quotients(
            component,
            trace,
            evaluation_accumulator,
        );
    }
}

/// Process-wide pinned (page-locked) staging buffer for witness upload.
///
/// Pinned pages let `cudaMemcpy` run at full PCIe bandwidth; pageable copies bounce
/// through the driver's internal staging area at roughly half speed. The buffer is
/// grow-only scratch reused across batches and proves: it carries NO cached data and
/// is never read after the upload, so reusing the allocation needs no cache key (the
/// repository's cache-keying rule applies to cached *content*, of which there is
/// none here). Capacity is capped so big traces are uploaded in batches instead of
/// page-locking gigabytes of host RAM.
struct PinnedStaging {
    ptr: *mut u32,
    capacity_words: usize,
}
// The raw pointer is only ever used under the Mutex below.
unsafe impl Send for PinnedStaging {}

/// 256 Mi u32 words = 1 GiB of page-locked staging at most.
const PINNED_STAGING_CAP_WORDS: usize = 1 << 28;

fn pinned_staging() -> &'static std::sync::Mutex<PinnedStaging> {
    static STAGING: std::sync::OnceLock<std::sync::Mutex<PinnedStaging>> =
        std::sync::OnceLock::new();
    STAGING.get_or_init(|| {
        std::sync::Mutex::new(PinnedStaging {
            ptr: std::ptr::null_mut(),
            capacity_words: 0,
        })
    })
}

/// STWO_CUDA_ASYNC_SPINE=1 (Stage A′): route the staging-loop H2D through
/// `cudaMemcpyAsync` on the legacy stream with ONE fence per batch, instead of a
/// synchronous copy (full queue drain) per column. Byte-identical — same stream-0
/// ordering, same bytes — only the host stops blocking ~2,500 times per prove.
fn async_spine_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_ASYNC_SPINE").as_deref() == Ok("1"))
}

impl stwo::prover::backend::FromSimdColumns for CudaBackend {
    fn from_simd_base_column(
        column: stwo::prover::backend::Col<SimdBackend, stwo::core::fields::m31::BaseField>,
    ) -> stwo::prover::backend::Col<Self, stwo::core::fields::m31::BaseField> {
        use stwo::prover::backend::Column;
        crate::columns::BaseFieldVec::from_vec(column.to_cpu())
    }

    /// Batched witness ingestion. The default (and previous) path uploaded the trace
    /// one column at a time: a single-threaded SIMD unpack, then an allocating H2D
    /// copy per column — hundreds of small pageable transfers, each paying the full
    /// allocator and synchronization overhead. Here:
    ///
    /// 1. Columns are packed into the process-wide PINNED staging buffer in parallel (rayon), in
    ///    batches that fit the staging cap.
    /// 2. Each column is uploaded from its staging offset with one `cudaMemcpy` from pinned memory
    ///    into its own freshly allocated device buffer.
    ///
    /// The device contents are word-for-word identical to the per-column path, so
    /// proof byte-equality is unaffected.
    fn from_simd_evals(
        evals: Vec<
            stwo::prover::poly::circle::CircleEvaluation<
                SimdBackend,
                stwo::core::fields::m31::BaseField,
                stwo::prover::poly::BitReversedOrder,
            >,
        >,
    ) -> Vec<
        stwo::prover::poly::circle::CircleEvaluation<
            Self,
            stwo::core::fields::m31::BaseField,
            stwo::prover::poly::BitReversedOrder,
        >,
    > {
        use rayon::prelude::*;
        use stwo::prover::backend::Column;

        if evals.is_empty() {
            return Vec::new();
        }
        crate::columns::bindings::ensure_mem_pool_init();

        let mut staging = pinned_staging().lock().unwrap();
        // Capacity: the whole batch if it fits the cap, otherwise the cap — but always
        // at least the largest single column (so every batch below is non-empty).
        let total: usize = evals.iter().map(|eval| eval.values.len()).sum();
        let largest: usize = evals.iter().map(|eval| eval.values.len()).max().unwrap();
        let needed = largest.max(total.min(PINNED_STAGING_CAP_WORDS));
        if staging.capacity_words < needed {
            unsafe {
                crate::columns::bindings::cuda_free_pinned_host_u32(staging.ptr);
                staging.ptr = crate::columns::bindings::cuda_alloc_pinned_host_u32(needed as u64);
            }
            staging.capacity_words = if staging.ptr.is_null() { 0 } else { needed };
        }

        // Pinned allocation failed (or stub backend): plain per-column fallback.
        if staging.ptr.is_null() {
            return evals
                .into_iter()
                .map(|eval| {
                    stwo::prover::poly::circle::CircleEvaluation::new(
                        eval.domain,
                        Self::from_simd_base_column(eval.values),
                    )
                })
                .collect();
        }

        let mut results = Vec::with_capacity(evals.len());
        let mut batch_start = 0;
        while batch_start < evals.len() {
            // Greedily take columns while they fit the staging buffer (always at
            // least one: capacity covers the largest single column).
            let mut batch_end = batch_start;
            let mut words = 0usize;
            let mut offsets = Vec::new();
            while batch_end < evals.len()
                && (batch_end == batch_start
                    || words + evals[batch_end].values.len() <= staging.capacity_words)
            {
                offsets.push(words);
                words += evals[batch_end].values.len();
                batch_end += 1;
            }
            let batch = &evals[batch_start..batch_end];

            // Parallel pack: each column unpacks its SIMD lanes straight into its
            // disjoint staging slice (BaseField is a transparent u32 wrapper).
            let staging_slice =
                unsafe { std::slice::from_raw_parts_mut(staging.ptr, staging.capacity_words) };
            let mut chunks: Vec<&mut [u32]> = Vec::with_capacity(batch.len());
            let mut rest = staging_slice;
            for eval in batch.iter() {
                let (chunk, tail) = rest.split_at_mut(eval.values.len());
                chunks.push(chunk);
                rest = tail;
            }
            batch
                .par_iter()
                .zip(chunks.par_iter_mut())
                .for_each(|(eval, chunk)| {
                    // `as_slice` is a zero-copy view over the SIMD column's packed
                    // lanes (PackedM31 is a transparent [u32; 16]), truncated to the
                    // logical length — one copy straight into pinned staging, no
                    // intermediate Vec per column.
                    let host = eval.values.as_slice();
                    // BaseField is repr(transparent) over u32.
                    let words: &[u32] =
                        unsafe { std::slice::from_raw_parts(host.as_ptr().cast(), host.len()) };
                    chunk.copy_from_slice(words);
                });

            // Upload each column from its pinned staging offset into its own buffer.
            // Async spine: enqueue all uploads async (disjoint pinned source regions,
            // ordered on stream 0), then a SINGLE fence before the next batch reuses
            // the staging buffer — vs a synchronous drain per column. The fence also
            // guarantees the pinned buffer is free before the mutex unlocks.
            let async_spine = async_spine_enabled();
            for (i, eval) in batch.iter().enumerate() {
                let len = eval.values.len();
                let column = crate::columns::BaseFieldVec::new_uninitialized(len);
                unsafe {
                    if async_spine {
                        crate::columns::bindings::copy_uint32_t_vec_from_host_to_device_into_async(
                            staging.ptr.add(offsets[i]),
                            column.device_ptr,
                            len as u64,
                        );
                    } else {
                        crate::columns::bindings::copy_uint32_t_vec_from_host_to_device_into(
                            staging.ptr.add(offsets[i]),
                            column.device_ptr,
                            len as u64,
                        );
                    }
                }
                results.push(stwo::prover::poly::circle::CircleEvaluation::new(
                    eval.domain,
                    column,
                ));
            }
            if async_spine {
                unsafe { crate::columns::bindings::stwo_legacy_stream_sync() };
            }
            batch_start = batch_end;
        }
        results
    }
}
