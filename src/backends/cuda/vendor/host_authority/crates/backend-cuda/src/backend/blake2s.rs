use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasherGeneric;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::{Column, ColumnOps};
use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;

use crate::backend::{CudaBackend, UploadedDevicePointerVec, UploadedUint32Vec};
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::bindings;
use crate::columns::blake_2s_hash_vec::Blake2sHashVec;

impl ColumnOps<Blake2sHash> for CudaBackend {
    type Column = Blake2sHashVec;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!("Blake2sHash column bit-reverse is not implemented on CudaBackend")
    }
}

/// STWO_MERKLE_SPANS=1: true GPU time per Merkle op (sync–time–sync), for
/// ranking leaf vs interior vs tail across the ~14 commits of a prove.
/// Observational only — the syncs run solely under the flag.
fn merkle_span_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_MERKLE_SPANS").as_deref() == Ok("1"))
}

fn merkle_span<T>(label: &str, n_cols: usize, log_size: u32, f: impl FnOnce() -> T) -> T {
    if !merkle_span_enabled() || !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return f();
    }
    unsafe { stwo_backend_cuda_kernels::raw::stwo_legacy_stream_sync() };
    let t0 = std::time::Instant::now();
    let out = f();
    unsafe { stwo_backend_cuda_kernels::raw::stwo_legacy_stream_sync() };
    eprintln!(
        "merkle_span[{label}]: cols={n_cols} log={log_size} ms={:.2}",
        t0.elapsed().as_secs_f64() * 1e3
    );
    out
}

/// `STWO_CUDA_BLAKE2S_LEAF_ILP=1`: opt-in ILP lane for the LEAF-hash update
/// kernel (Step 3.2). Each CUDA thread hashes TWO adjacent leaf rows with the
/// two blake2s G-function streams interleaved, doubling the independent
/// instruction chains per thread — latency hiding through ILP instead of
/// occupancy (occupancy hints measured FLAT on the 255-register kernels).
/// Byte-identical digests either way; default OFF until the measured pod gate
/// (>= 450 GB/s absorbed leaf bytes) passes. Read once per process, so eager
/// launches and graph capture always pick the same kernel.
pub(crate) fn blake2s_leaf_ilp2_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_BLAKE2S_LEAF_ILP").as_deref() == Ok("1"))
}

/// Mirror of `BLOCK_SIZE` in `blake2s.cuh` (the leaf kernels' block width).
pub(crate) const CUDA_BLAKE2S_BLOCK_SIZE: u32 = 256;

/// ILP2 grid math, kept in LOCKSTEP with `number_of_ilp2_blocks_for` in
/// `blake2s.cu`: one thread per ROW PAIR; an odd row count adds one final
/// single-row thread (the kernel's scalar tail).
pub(crate) fn leaf_ilp2_row_pairs(rows: u32) -> u32 {
    rows / 2 + (rows & 1)
}

/// Blocks launched for the ILP2 leaf-update kernel: `ceil(ceil(rows/2) / 256)`
/// — half the scalar kernel's grid (up to the odd-row thread).
pub(crate) fn leaf_ilp2_grid_blocks(rows: u32) -> u32 {
    leaf_ilp2_row_pairs(rows).div_ceil(CUDA_BLAKE2S_BLOCK_SIZE)
}

/// `STWO_CUDA_BLAKE2S_INTERIOR_FUSED=1`: opt-in FOUR-level interior Merkle
/// fusion (Step 3.2 second half). Where four consecutive column-free interior
/// levels have all three intermediate levels UNRETAINED (prune-depth scratch),
/// one `stwo_blake2s_interior4_on` launch replaces four per-level launches;
/// the intermediates live in shared memory and never round-trip HBM.
/// Byte-identical output level by construction (same
/// `blake2s_hash_children_device` routine, same parent[i] = H(child[2i],
/// child[2i+1]) mapping per level — locked by `interior4_spec_tests` below).
/// Default OFF until the pod gate (interior >= 400 GB/s, parity run) passes.
/// Read once per process (OnceLock), so eager launches and graph capture
/// always plan the same topology.
///
/// Consumed by `commit_graph.rs` planning (the prepared/resident commit
/// island, which serves both eager and captured execution). The legacy trait
/// path in this file (`build_next_layer`) is driven one level at a time by
/// `tree_from_leaves` and must return every level to its caller, so it stays
/// per-level regardless of the flag.
pub(crate) fn blake2s_interior_fused_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_BLAKE2S_INTERIOR_FUSED").as_deref() == Ok("1"))
}

/// Outputs produced per block by the interior4 kernel (256 threads / 8).
/// Spec-lock mirror (test-only on the Rust side — the grid is computed in the
/// .cu launcher); kept in LOCKSTEP with `STWO_INTERIOR4_OUT_PER_BLOCK`.
#[cfg(test)]
pub(crate) const CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK: u32 = CUDA_BLAKE2S_BLOCK_SIZE / 8;

/// Interior4 grid math, kept in LOCKSTEP with `number_of_interior4_blocks_for`
/// in `blake2s.cu`: one block per 32 output hashes.
#[cfg(test)]
pub(crate) fn interior4_grid_blocks(out_size: u32) -> u32 {
    out_size.div_ceil(CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK)
}

/// Keep the historical low-VRAM policy on CUDA by default. Set
/// `STWO_CUDA_MERKLE_PRUNE_DEPTH=1` to experimentally retain the bottom three
/// interior layers and trade additional VRAM for less host-side recomputation.
fn cuda_merkle_prune_depth_from(raw: Option<&str>) -> u32 {
    match raw.map(str::trim) {
        None | Some("") | Some("4") => 4,
        Some("1") => 1,
        Some(value) => {
            panic!("unsupported STWO_CUDA_MERKLE_PRUNE_DEPTH={value:?}; expected 1 or 4")
        }
    }
}

impl<const IS_M31_OUTPUT: bool> MerkleOpsLifted<Blake2sMerkleHasherGeneric<IS_M31_OUTPUT>>
    for CudaBackend
{
    fn merkle_prune_depth() -> u32 {
        cuda_merkle_prune_depth_from(
            std::env::var("STWO_CUDA_MERKLE_PRUNE_DEPTH")
                .ok()
                .as_deref(),
        )
    }

    fn batch_gather_column_rows(
        columns: &[&BaseFieldVec],
        rows: &[Vec<usize>],
    ) -> Vec<Vec<stwo::core::fields::m31::BaseField>> {
        // Migration-only same-binary rollback for the one live decommit-path
        // override introduced by the resident work. `gather_unreduced` keeps
        // raw device words (including P) exactly like the batched kernel.
        if std::env::var("STWO_CUDA_DECOMMIT_GATHER_REFERENCE").as_deref() == Ok("1") {
            assert_eq!(columns.len(), rows.len());
            return columns
                .iter()
                .zip(rows)
                .map(|(column, indices)| column.gather_unreduced(indices))
                .collect();
        }
        crate::backend::decommit_gather::gather_column_rows_host(columns, rows)
            .unwrap_or_else(|error| panic!("CUDA multi-column decommit gather failed: {error}"))
    }

    fn build_leaves(columns: &[&BaseFieldVec], lifting_log_size: u32) -> Blake2sHashVec {
        // First commit hook hit per tree — report the resolved commit-fusion
        // configuration once so a pod operator / the bisecting integration agent
        // can confirm which lanes took effect. Silent when the master switch is off
        // (the default), so a normal prove prints nothing.
        crate::backend::fused_commit::log_selected_lanes_once();
        if columns.is_empty() {
            let hasher = Blake2sMerkleHasherGeneric::<IS_M31_OUTPUT>::default();
            return Blake2sHashVec::from_vec(vec![hasher.finalize()]);
        }
        if IS_M31_OUTPUT {
            // The GPU kernel implements the non-M31 hasher; the M31-output variant is
            // hashed on the host to match the reference byte stream exactly (same
            // decision as the Metal port).
            return build_leaves_host::<IS_M31_OUTPUT>(columns, lifting_log_size);
        }

        assert!(lifting_log_size < usize::BITS);
        assert!(columns[0].len() >= 2, "A column must be of length >= 2.");

        let mut previous_len = columns[0].len();
        let mut column_log_sizes = Vec::with_capacity(columns.len());
        for column in columns {
            let len = column.len();
            assert!(
                len.is_power_of_two(),
                "column lengths must be powers of two"
            );
            assert!(len >= 2, "A column must be of length >= 2.");
            assert!(
                previous_len <= len,
                "lifted Blake2s columns must be sorted increasingly by length"
            );
            let log_size = len.ilog2();
            assert!(
                log_size <= lifting_log_size,
                "lifting_log_size must be at least the largest column log size"
            );
            column_log_sizes.push(log_size);
            previous_len = len;
        }

        let size = 1usize << lifting_log_size;
        let result = Blake2sHashVec::new_uninitialized(size);
        merkle_span("leaves", columns.len(), lifting_log_size, || unsafe {
            Self::commit_on_first_layer_lifted_using_gpu(
                columns,
                &column_log_sizes,
                lifting_log_size,
                result.device_ptr,
            );
        });
        result
    }

    fn batch_layer_reads(
        layers: &[&Blake2sHashVec],
        pairs: &[(u32, u32)],
    ) -> Vec<<Blake2sMerkleHasherGeneric<IS_M31_OUTPUT> as MerkleHasherLifted>::Hash> {
        // One gather kernel + one D2H for the whole read set, vs a synchronous
        // 32-byte round-trip per node (the decommit walk issues thousands).
        // Semantics identical to the trait default: `layers[l].at(i)` per pair,
        // in order. The kernel's pointer table is capped at 24 layers; deeper
        // read sets (never seen — trees are ≤2^24 leaves) fall back per-element.
        use stwo::prover::backend::Column;
        const MAX_LAYERS: usize = 24;
        if pairs.is_empty() {
            return Vec::new();
        }
        if IS_M31_OUTPUT || layers.len() > MAX_LAYERS {
            return pairs
                .iter()
                .map(|&(l, i)| layers[l as usize].at(i as usize))
                .collect();
        }
        let mut layer_ptrs: Vec<*const stwo::core::vcs::blake2_hash::Blake2sHash> =
            layers.iter().map(|l| l.device_ptr).collect();
        layer_ptrs.resize(MAX_LAYERS, std::ptr::null());
        let pair_structs: Vec<crate::columns::bindings::LayerIndexPair> = pairs
            .iter()
            .map(|&(l, i)| crate::columns::bindings::LayerIndexPair {
                layer_idx: l,
                hash_idx: i,
            })
            .collect();
        let mut out = vec![stwo::core::vcs::blake2_hash::Blake2sHash::default(); pairs.len()];
        unsafe {
            crate::columns::bindings::cuda_multi_layer_batch_get_blake_2s_hash(
                layer_ptrs.as_ptr(),
                out.as_mut_ptr(),
                pair_structs.as_ptr(),
                pairs.len() as u32,
            );
        }
        // The generic hasher's Hash type is Blake2sHash for the non-M31 lane
        // (asserted by the IS_M31_OUTPUT early-out above).
        unsafe {
            std::mem::transmute::<Vec<stwo::core::vcs::blake2_hash::Blake2sHash>, Vec<_>>(out)
        }
    }

    fn stream_commit_leaves(
        coeffs: &[&stwo::prover::poly::circle::CircleCoefficients<Self>],
        log_blowup_factor: u32,
        twiddles: &stwo::prover::poly::twiddles::TwiddleTree<Self>,
        lifting_log_size: u32,
    ) -> Option<Blake2sHashVec> {
        // The M31-output hasher runs host-side (see build_leaves); streaming is the
        // device word-block lane only.
        if IS_M31_OUTPUT {
            return None;
        }
        // Group width trades streaming-commit launch overhead (fewer, larger
        // batched groups) against the transient LDE peak (~G blown-up columns
        // resident; the big log24 columns dominate and sort last, so peak ≈
        // G·2^lift·4B over the coeff floor). Env-tunable (STWO_STREAM_GROUP_COLS,
        // multiple of 16) to sweep the commit-speed/peak Pareto against the
        // two-proof VRAM budget without a rebuild. Default 32 (~+8GB, keeps two
        // proofs under 80GB while roughly halving the launch count vs 16).
        let group_cols = std::env::var("STWO_STREAM_GROUP_COLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&g| g >= 16)
            .map(|g| g / 16 * 16)
            .unwrap_or(32);
        Some(Self::stream_commit_leaves_from_coeffs(
            coeffs,
            log_blowup_factor,
            twiddles,
            lifting_log_size,
            group_cols,
        ))
    }

    fn build_next_layer(prev_layer: &Blake2sHashVec) -> Blake2sHashVec {
        let size = prev_layer.len() / 2;
        if IS_M31_OUTPUT {
            let prev = prev_layer.to_vec();
            let hashes = (0..size)
                .map(|i| {
                    Blake2sMerkleHasherGeneric::<IS_M31_OUTPUT>::hash_children((
                        prev[2 * i],
                        prev[2 * i + 1],
                    ))
                })
                .collect();
            return Blake2sHashVec::from_vec(hashes);
        }
        let result = Blake2sHashVec::new_uninitialized(size);

        merkle_span("interior", 0, size.ilog2(), || unsafe {
            Self::commit_on_layer_using_gpu(size, 0, &[], Some(prev_layer), result.device_ptr);
        });

        result
    }

    /// Commit fusion (C2): the top `n_levels` in ONE fused launch
    /// (`stwo_blake2s_tail` — same `blake2s_hash_children_device` routine as
    /// the per-layer kernel; scheduling only). The M31-output lane keeps the
    /// host default (its per-layer path is host-side already).
    fn build_top_layers(first: &Blake2sHashVec, n_levels: u32) -> Vec<Blake2sHashVec> {
        assert!(n_levels >= 1 && first.len() >> n_levels >= 1);
        if IS_M31_OUTPUT || !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            // The trait default's exact loop (can't call it directly from an
            // override): chained build_next_layer, parent-first.
            let mut out = Vec::with_capacity(n_levels as usize);
            let next_layer = <Self as MerkleOpsLifted<
                Blake2sMerkleHasherGeneric<IS_M31_OUTPUT>,
            >>::build_next_layer;
            let mut current = next_layer(first);
            for _ in 1..n_levels {
                let next = next_layer(&current);
                out.push(current);
                current = next;
            }
            out.push(current);
            return out;
        }
        let levels: Vec<Blake2sHashVec> = (1..=n_levels)
            .map(|l| Blake2sHashVec::new_uninitialized(first.len() >> l))
            .collect();
        let ptrs: Vec<*const u32> = levels.iter().map(|l| l.device_ptr.cast::<u32>()).collect();
        let table = crate::backend::UploadedDevicePointerVec::upload(&ptrs);
        let rc = merkle_span("tail", 0, n_levels, || unsafe {
            stwo_backend_cuda_kernels::raw::stwo_blake2s_tail(
                first.device_ptr.cast(),
                first.len() as u32,
                table.as_ptr().cast(),
                n_levels,
            )
        });
        drop(table);
        assert_eq!(rc, 0, "blake2s tail launch failed");
        levels
    }
}

/// Pure-Rust gate for the ILP2 grid math (no device needed). The formulas are
/// duplicated in `number_of_ilp2_blocks_for` in `blake2s.cu`; these tests lock
/// the Rust mirror, and the native byte-identity tests lock the kernel that
/// consumes the C++ copy.
#[cfg(test)]
mod leaf_ilp2_grid_tests {
    use super::{leaf_ilp2_grid_blocks, leaf_ilp2_row_pairs, CUDA_BLAKE2S_BLOCK_SIZE};

    #[test]
    fn row_pairs_cover_every_row_with_at_most_one_unpaired() {
        for rows in [
            1u32,
            2,
            3,
            255,
            256,
            257,
            511,
            512,
            513,
            (1 << 20) - 1,
            1 << 20,
            (1 << 20) + 1,
            (1 << 25),
        ] {
            let pairs = leaf_ilp2_row_pairs(rows);
            assert!(2 * pairs >= rows, "rows={rows}: pairs must cover all rows");
            assert!(
                2 * pairs - rows <= 1,
                "rows={rows}: at most one single-row (odd-tail) thread"
            );
        }
    }

    #[test]
    fn grid_blocks_are_tight_and_halve_the_scalar_grid() {
        let scalar_blocks = |rows: u32| rows.div_ceil(CUDA_BLAKE2S_BLOCK_SIZE);
        for rows in [1u32, 2, 3, 511, 512, 513, 1 << 13, (1 << 20) - 1, 1 << 20] {
            let blocks = leaf_ilp2_grid_blocks(rows);
            let pairs = leaf_ilp2_row_pairs(rows);
            // Cover all pairs, with no fully idle trailing block.
            assert!(blocks * CUDA_BLAKE2S_BLOCK_SIZE >= pairs, "rows={rows}");
            assert!(
                (blocks - 1) * CUDA_BLAKE2S_BLOCK_SIZE < pairs,
                "rows={rows}: last block must not be empty"
            );
            assert!(blocks <= scalar_blocks(rows), "rows={rows}");
        }
        // Power-of-two production shapes (leaf counts) halve exactly.
        for log in [13u32, 20, 24, 25] {
            let rows = 1u32 << log;
            assert_eq!(
                leaf_ilp2_grid_blocks(rows),
                scalar_blocks(rows) / 2,
                "log={log}"
            );
        }
        // Odd counts: the unpaired row still gets a thread.
        assert_eq!(leaf_ilp2_row_pairs(33), 17);
        assert_eq!(leaf_ilp2_grid_blocks(33), 1);
        assert_eq!(leaf_ilp2_row_pairs(513), 257);
        assert_eq!(leaf_ilp2_grid_blocks(513), 2);
    }
}

#[cfg(test)]
mod prune_policy_tests {
    use super::cuda_merkle_prune_depth_from;

    #[test]
    fn cuda_defaults_to_four_and_supports_depth_one_opt_in() {
        assert_eq!(cuda_merkle_prune_depth_from(None), 4);
        assert_eq!(cuda_merkle_prune_depth_from(Some("1")), 1);
        assert_eq!(cuda_merkle_prune_depth_from(Some("4")), 4);
    }

    #[test]
    #[should_panic(expected = "expected 1 or 4")]
    fn cuda_rejects_depth_zero() {
        cuda_merkle_prune_depth_from(Some("0"));
    }
}

/// Host-side leaf builder for the M31-output hasher: mirrors the CPU reference's byte
/// stream over downloaded column copies (chunked update of up to 16 columns per leaf).
fn build_leaves_host<const IS_M31_OUTPUT: bool>(
    columns: &[&BaseFieldVec],
    lifting_log_size: u32,
) -> Blake2sHashVec {
    use itertools::Itertools;
    let hasher = Blake2sMerkleHasherGeneric::<IS_M31_OUTPUT>::default();
    let host_columns: Vec<Vec<stwo::core::fields::m31::BaseField>> =
        columns.iter().map(|column| column.to_vec()).collect();

    let mut prev_layer: Vec<Blake2sMerkleHasherGeneric<IS_M31_OUTPUT>> = Vec::new();
    let mut prev_layer_log_size: u32 = 0;
    for (log_size, group) in
        &itertools::Itertools::group_by(host_columns.iter(), |column| column.len().ilog2())
    {
        let group_columns = group.collect_vec();
        if prev_layer.is_empty() {
            prev_layer = vec![hasher.clone(); 1 << log_size];
        } else {
            let log_ratio = log_size - prev_layer_log_size;
            prev_layer = (0..1usize << log_size)
                .map(|idx| prev_layer[(idx >> (log_ratio + 1) << 1) + (idx & 1)].clone())
                .collect();
        }
        for chunk_columns in group_columns.chunks(16) {
            for (i, hasher) in prev_layer.iter_mut().enumerate() {
                let mut chunk_bytes = [0u8; 16 * 4];
                let mut used = 0usize;
                for column in chunk_columns {
                    chunk_bytes[used..used + 4].copy_from_slice(&column[i].0.to_le_bytes());
                    used += 4;
                }
                hasher.update(&chunk_bytes[..used]);
            }
        }
        prev_layer_log_size = log_size;
    }

    let log_ratio = lifting_log_size - prev_layer_log_size;
    if log_ratio > 0 {
        prev_layer = (0..1usize << lifting_log_size)
            .map(|idx| prev_layer[(idx >> (log_ratio + 1) << 1) + (idx & 1)].clone())
            .collect();
    }
    Blake2sHashVec::from_vec(prev_layer.into_iter().map(|x| x.finalize()).collect())
}

impl CudaBackend {
    unsafe fn commit_on_first_layer_lifted_using_gpu(
        columns: &[&BaseFieldVec],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
        result_pointer: *const Blake2sHash,
    ) {
        let size = 1usize << lifting_log_size;
        let device_column_pointers_vector: Vec<*const u32> =
            columns.iter().map(|column| column.device_ptr).collect();
        let device_column_pointers =
            UploadedDevicePointerVec::upload(&device_column_pointers_vector);
        let uploaded_column_log_sizes = UploadedUint32Vec::upload(column_log_sizes);

        bindings::commit_on_first_layer_lifted(
            size,
            columns.len(),
            device_column_pointers.as_ptr(),
            uploaded_column_log_sizes.as_ptr(),
            lifting_log_size,
            result_pointer as *mut Blake2sHash,
        );
    }

    unsafe fn commit_on_layer_using_gpu(
        size: usize,
        number_of_columns: usize,
        columns: &[&BaseFieldVec],
        prev_layer: Option<&Blake2sHashVec>,
        result_pointer: *const Blake2sHash,
    ) {
        let device_column_pointers_vector: Vec<*const u32> =
            columns.iter().map(|column| column.device_ptr).collect();

        let device_column_pointers =
            UploadedDevicePointerVec::upload(&device_column_pointers_vector);

        if let Some(previous_layer) = prev_layer {
            bindings::commit_on_layer_with_previous(
                size,
                number_of_columns,
                device_column_pointers.as_ptr(),
                previous_layer.device_ptr,
                result_pointer as *mut Blake2sHash,
            );
        } else {
            bindings::commit_on_first_layer(
                size,
                number_of_columns,
                device_column_pointers.as_ptr(),
                result_pointer as *mut Blake2sHash,
            );
        }
    }

    /// Streaming leaf layer (VRAM diet): hashes the same lifted leaf digests as
    /// [`Self::commit_on_first_layer_lifted_using_gpu`], but feeds the columns
    /// through the running-state kernels in GROUPS of `group_cols` (rounded to a
    /// multiple of 16) so the caller can materialize columns a group at a time.
    ///
    /// This entry point takes columns already resident (it isolates and gates the
    /// streaming KERNEL logic against the all-at-once path). The memory win comes
    /// from the caller LDE'ing each group on demand and dropping it after the
    /// corresponding `stream_leaf_update` — see the commit driver.
    ///
    /// `columns` must be sorted by length ascending (as `build_leaves` sorts) and
    /// `column_log_sizes[i]` = `columns[i].len().ilog2()`. Byte-identical to the
    /// reference: non-final groups carry whole 64-byte blocks (multiple-of-16
    /// column counts, `last=0`); the trailing `rem in 1..=16` block is finalized.
    pub fn stream_leaf_layer(
        columns: &[&BaseFieldVec],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
        group_cols: usize,
    ) -> Blake2sHashVec {
        Self::stream_leaf_layer_impl(
            columns,
            column_log_sizes,
            lifting_log_size,
            group_cols,
            blake2s_leaf_ilp2_enabled(),
        )
    }

    /// [`Self::stream_leaf_layer`] with the ILP2 lane pinned explicitly, so the
    /// byte-identity tests can exercise BOTH kernels in one process regardless
    /// of the environment (the env switch is a process-global `OnceLock`).
    pub(crate) fn stream_leaf_layer_impl(
        columns: &[&BaseFieldVec],
        column_log_sizes: &[u32],
        lifting_log_size: u32,
        group_cols: usize,
        use_ilp2: bool,
    ) -> Blake2sHashVec {
        let size = 1usize << lifting_log_size;
        let state = Blake2sHashVec::new_uninitialized(size);
        let n = columns.len();
        unsafe {
            bindings::stream_leaf_init(size as u32, state.device_ptr.cast_mut());
        }
        if n == 0 {
            // Match the reference's empty-column behavior via the all-at-once path.
            return <CudaBackend as MerkleOpsLifted<
                Blake2sMerkleHasherGeneric<false>,
            >>::build_leaves(columns, lifting_log_size);
        }
        // Final block = the trailing rem columns (rem in 1..=16); everything before
        // it is whole 16-column blocks, streamed in groups.
        let rem = (n - 1) % 16 + 1;
        let n_full = n - rem;
        let step = group_cols.max(16) / 16 * 16; // round down to a multiple of 16, >= 16
        let mut off = 0usize;
        while off < n_full {
            let end = (off + step).min(n_full);
            let g = end - off;
            let ptrs: Vec<*const u32> = columns[off..end].iter().map(|c| c.device_ptr).collect();
            let table = UploadedDevicePointerVec::upload(&ptrs);
            let logs = UploadedUint32Vec::upload(&column_log_sizes[off..end]);
            unsafe {
                if use_ilp2 {
                    // Halved grid, two rows per thread — every row still covered
                    // (the .cu launcher implements exactly this formula).
                    debug_assert!(
                        u64::from(leaf_ilp2_grid_blocks(size as u32))
                            * u64::from(CUDA_BLAKE2S_BLOCK_SIZE)
                            * 2
                            >= size as u64
                    );
                    bindings::stream_leaf_update_ilp2(
                        size as u32,
                        g as u32,
                        table.as_ptr(),
                        logs.as_ptr(),
                        lifting_log_size,
                        off as u32,
                        state.device_ptr.cast_mut(),
                    );
                } else {
                    bindings::stream_leaf_update(
                        size as u32,
                        g as u32,
                        table.as_ptr(),
                        logs.as_ptr(),
                        lifting_log_size,
                        off as u32,
                        state.device_ptr.cast_mut(),
                    );
                }
            }
            drop((table, logs));
            off = end;
        }
        // Finalize the trailing block in place (state -> digests).
        let ptrs: Vec<*const u32> = columns[n_full..n].iter().map(|c| c.device_ptr).collect();
        let table = UploadedDevicePointerVec::upload(&ptrs);
        let logs = UploadedUint32Vec::upload(&column_log_sizes[n_full..n]);
        unsafe {
            bindings::stream_leaf_finalize(
                size as u32,
                rem as u32,
                table.as_ptr(),
                logs.as_ptr(),
                lifting_log_size,
                n_full as u32,
                state.device_ptr.cast_mut(),
            );
        }
        drop((table, logs));
        state
    }

    /// The VRAM diet: build the lifted leaf layer by LDE'ing the base columns
    /// one GROUP at a time from their coefficients (retained), feeding each
    /// group into the running leaf-hash state, then DROPPING the group's
    /// evaluations before the next. Peak = the coefficients + one group's LDE +
    /// the h[8]-per-leaf state, instead of ALL columns' LDE resident at once.
    ///
    /// `coeffs` must be sorted by `log_size()` ascending (as `build_leaves`
    /// sorts by eval length — the blowup is constant, so the orders coincide).
    /// `group_cols` bounds how many columns are LDE'd concurrently (rounded to a
    /// multiple of 16 so non-final groups are whole 64-byte blocks). Byte-identical
    /// to `build_leaves(evaluate_polynomials(coeffs))` — same NTT, same sorted
    /// lifted-index word stream, same block boundaries (gated by
    /// `stream_commit_leaves_matches_bulk`).
    pub fn stream_commit_leaves_from_coeffs(
        coeffs: &[&stwo::prover::poly::circle::CircleCoefficients<Self>],
        log_blowup_factor: u32,
        twiddles: &stwo::prover::poly::twiddles::TwiddleTree<Self>,
        lifting_log_size: u32,
        group_cols: usize,
    ) -> Blake2sHashVec {
        Self::stream_commit_leaves_from_coeffs_impl(
            coeffs,
            log_blowup_factor,
            twiddles,
            lifting_log_size,
            group_cols,
            blake2s_leaf_ilp2_enabled(),
        )
    }

    /// [`Self::stream_commit_leaves_from_coeffs`] with the ILP2 lane pinned
    /// explicitly (see [`Self::stream_leaf_layer_impl`]).
    pub(crate) fn stream_commit_leaves_from_coeffs_impl(
        coeffs: &[&stwo::prover::poly::circle::CircleCoefficients<Self>],
        log_blowup_factor: u32,
        twiddles: &stwo::prover::poly::twiddles::TwiddleTree<Self>,
        lifting_log_size: u32,
        group_cols: usize,
        use_ilp2: bool,
    ) -> Blake2sHashVec {
        use stwo::core::poly::circle::CanonicCoset;
        let size = 1usize << lifting_log_size;
        let state = Blake2sHashVec::new_uninitialized(size);
        unsafe {
            bindings::stream_leaf_init(size as u32, state.device_ptr.cast_mut());
        }
        let n = coeffs.len();
        if n == 0 {
            return <CudaBackend as MerkleOpsLifted<
                Blake2sMerkleHasherGeneric<false>,
            >>::build_leaves(&[], lifting_log_size);
        }
        // LDE one column to its blown-up evaluation domain (same domain the bulk
        // `evaluate_polynomials` uses — the NTT is deterministic, so the values
        // match bit-for-bit).
        let lde = |c: &stwo::prover::poly::circle::CircleCoefficients<Self>| -> BaseFieldVec {
            let domain = CanonicCoset::new(c.log_size() + log_blowup_factor).circle_domain();
            c.evaluate_with_twiddles(domain, twiddles).values
        };

        let rem = (n - 1) % 16 + 1;
        let n_full = n - rem;
        let step = group_cols.max(16) / 16 * 16;
        let mut off = 0usize;
        while off < n_full {
            let end = (off + step).min(n_full);
            let evals: Vec<BaseFieldVec> = coeffs[off..end].iter().map(|c| lde(c)).collect();
            let ptrs: Vec<*const u32> = evals.iter().map(|e| e.device_ptr).collect();
            let logs: Vec<u32> = evals.iter().map(|e| e.len().ilog2()).collect();
            let table = UploadedDevicePointerVec::upload(&ptrs);
            let uploaded_logs = UploadedUint32Vec::upload(&logs);
            unsafe {
                if use_ilp2 {
                    bindings::stream_leaf_update_ilp2(
                        size as u32,
                        (end - off) as u32,
                        table.as_ptr(),
                        uploaded_logs.as_ptr(),
                        lifting_log_size,
                        off as u32,
                        state.device_ptr.cast_mut(),
                    );
                } else {
                    bindings::stream_leaf_update(
                        size as u32,
                        (end - off) as u32,
                        table.as_ptr(),
                        uploaded_logs.as_ptr(),
                        lifting_log_size,
                        off as u32,
                        state.device_ptr.cast_mut(),
                    );
                }
            }
            drop((table, uploaded_logs, evals)); // free the group's LDE now
            off = end;
        }
        // Finalize the trailing block.
        let evals: Vec<BaseFieldVec> = coeffs[n_full..n].iter().map(|c| lde(c)).collect();
        let ptrs: Vec<*const u32> = evals.iter().map(|e| e.device_ptr).collect();
        let logs: Vec<u32> = evals.iter().map(|e| e.len().ilog2()).collect();
        let table = UploadedDevicePointerVec::upload(&ptrs);
        let uploaded_logs = UploadedUint32Vec::upload(&logs);
        unsafe {
            bindings::stream_leaf_finalize(
                size as u32,
                rem as u32,
                table.as_ptr(),
                uploaded_logs.as_ptr(),
                lifting_log_size,
                n_full as u32,
                state.device_ptr.cast_mut(),
            );
        }
        drop((table, uploaded_logs, evals));
        state
    }
}

#[cfg(test)]
mod stream_leaf_tests {
    use stwo::core::fields::m31::M31;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasherGeneric;
    use stwo::prover::backend::Column;
    use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;

    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;

    // The streaming leaf layer must be BYTE-IDENTICAL to the all-at-once
    // `build_leaves`, especially where the column count is a multiple of 16 (the
    // final word block is full — the exact shape that broke the eager word-block
    // loop in M4). Mixed sizes exercise the lifted index; several group sizes
    // exercise the group-boundary/finalize split.
    fn cols(n: usize) -> Vec<Vec<M31>> {
        // Sorted ascending by size (as build_leaves requires): sizes cycle 2^3..2^7.
        let mut v: Vec<Vec<M31>> = (0..n)
            .map(|i| {
                let log = 3 + (i % 5) as u32;
                (0..(1usize << log))
                    .map(|j| M31::from((i * 7 + j * 13 + 1) as u32))
                    .collect()
            })
            .collect();
        v.sort_by_key(|c| c.len());
        v
    }

    #[test]
    fn stream_leaf_layer_matches_build_leaves() {
        // CUDA-only: the stub backend aborts on any device call. Skip locally
        // (matches the conformance-test gate); runs on the pod.
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return;
        }
        // Both leaf-update kernels are gated here: the scalar reference lane
        // and the opt-in ILP2 lane (two rows per thread, halved grid) must be
        // BYTE-IDENTICAL to build_leaves. Pinned explicitly (not via env) so a
        // single process covers both regardless of STWO_CUDA_BLAKE2S_LEAF_ILP.
        for ilp2 in [false, true] {
            for n_columns in [1usize, 15, 16, 17, 31, 32, 33, 64, 100] {
                for group in [16usize, 32, 48] {
                    let cpu_cols = cols(n_columns);
                    let gpu_cols: Vec<BaseFieldVec> = cpu_cols
                        .iter()
                        .map(|c| BaseFieldVec::from_vec(c.clone()))
                        .collect();
                    let refs: Vec<&BaseFieldVec> = gpu_cols.iter().collect();
                    let log_sizes: Vec<u32> = gpu_cols.iter().map(|c| c.len().ilog2()).collect();
                    let lifting = *log_sizes.last().unwrap();

                    let reference = <CudaBackend as MerkleOpsLifted<
                        Blake2sMerkleHasherGeneric<false>,
                    >>::build_leaves(&refs, lifting);
                    let streamed = CudaBackend::stream_leaf_layer_impl(
                        &refs, &log_sizes, lifting, group, ilp2,
                    );

                    assert_eq!(
                        streamed.to_cpu(),
                        reference.to_cpu(),
                        "n_columns={n_columns} group={group} ilp2={ilp2}"
                    );
                }
            }
        }
    }

    // Odd-row tail gate for the ILP2 kernel: the leaf-state row count is a
    // power of two in production, but the kernel guards odd counts (last
    // unpaired row runs the scalar stream). Drive the raw bindings with an odd
    // state count and require the ILP2 mid-stream states to match the scalar
    // kernel's word-for-word.
    #[test]
    fn ilp2_update_matches_scalar_on_odd_row_counts() {
        use crate::columns::bindings;
        use crate::columns::blake_2s_hash_vec::Blake2sHashVec;

        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return;
        }
        const LIFTING: u32 = 6; // columns hold 64 rows; we hash the first `rows` states
        for rows in [1u32, 3, 33, 63] {
            let cpu_cols: Vec<Vec<M31>> = (0..16)
                .map(|i| {
                    (0..(1usize << LIFTING))
                        .map(|j| M31::from((i * 11 + j * 3 + 1) as u32))
                        .collect()
                })
                .collect();
            let gpu_cols: Vec<BaseFieldVec> = cpu_cols
                .iter()
                .map(|c| BaseFieldVec::from_vec(c.clone()))
                .collect();
            let ptrs: Vec<*const u32> = gpu_cols.iter().map(|c| c.device_ptr).collect();
            let logs: Vec<u32> = vec![LIFTING; 16];
            let table = crate::backend::UploadedDevicePointerVec::upload(&ptrs);
            let uploaded_logs = crate::backend::UploadedUint32Vec::upload(&logs);

            let run = |ilp2: bool| -> Vec<_> {
                let state = Blake2sHashVec::new_uninitialized(rows as usize);
                unsafe {
                    bindings::stream_leaf_init(rows, state.device_ptr.cast_mut());
                    if ilp2 {
                        bindings::stream_leaf_update_ilp2(
                            rows,
                            16,
                            table.as_ptr(),
                            uploaded_logs.as_ptr(),
                            LIFTING,
                            0,
                            state.device_ptr.cast_mut(),
                        );
                    } else {
                        bindings::stream_leaf_update(
                            rows,
                            16,
                            table.as_ptr(),
                            uploaded_logs.as_ptr(),
                            LIFTING,
                            0,
                            state.device_ptr.cast_mut(),
                        );
                    }
                }
                state.to_cpu()
            };

            assert_eq!(run(true), run(false), "rows={rows}");
        }
    }

    // End-to-end diet gate: the coeff-driven streaming commit (LDE per group,
    // free per group) must produce the SAME leaf layer as the bulk path
    // (evaluate_polynomials -> build_leaves). Covers the NTT + lifted-index +
    // block-boundary composition on real coefficients.
    #[test]
    fn stream_commit_leaves_matches_bulk() {
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::prover::mempool::BaseColumnPool;
        use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};

        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return;
        }
        const BLOWUP: u32 = 1;
        for ilp2 in [false, true] {
            for n_columns in [16usize, 17, 32, 48] {
                // Mixed-size coefficient columns, sorted ascending by log_size.
                let mut logs: Vec<u32> = (0..n_columns).map(|i| 4 + (i % 4) as u32).collect();
                logs.sort_unstable();
                let coeffs: Vec<CircleCoefficients<CudaBackend>> = logs
                    .iter()
                    .enumerate()
                    .map(|(i, &log)| {
                        let vals: Vec<M31> = (0..(1usize << log))
                            .map(|j| M31::from((i * 5 + j + 1) as u32))
                            .collect();
                        CircleCoefficients::new(BaseFieldVec::from_vec(vals))
                    })
                    .collect();
                let lifting = logs.last().unwrap() + BLOWUP;

                // Reference: bulk LDE all -> build_leaves (sorted refs).
                let twiddles = CudaBackend::precompute_twiddles(
                    CanonicCoset::new(lifting).circle_domain().half_coset,
                );
                let pool = BaseColumnPool::<CudaBackend>::new();
                let polys = <CudaBackend as PolyOps>::evaluate_polynomials(
                    coeffs.clone(),
                    BLOWUP,
                    &twiddles,
                    true,
                    &pool,
                );
                let mut eval_cols: Vec<&BaseFieldVec> =
                    polys.iter().map(|p| &p.evals.values).collect();
                eval_cols.sort_by_key(|c| c.len());
                let ref_logs: Vec<u32> = eval_cols.iter().map(|c| c.len().ilog2()).collect();
                let reference = <CudaBackend as MerkleOpsLifted<
                    Blake2sMerkleHasherGeneric<false>,
                >>::build_leaves(&eval_cols, lifting);

                let _ = ref_logs;
                let coeff_refs: Vec<&CircleCoefficients<CudaBackend>> = coeffs.iter().collect();
                let streamed = CudaBackend::stream_commit_leaves_from_coeffs_impl(
                    &coeff_refs,
                    BLOWUP,
                    &twiddles,
                    lifting,
                    16,
                    ilp2,
                );

                assert_eq!(
                    streamed.to_cpu(),
                    reference.to_cpu(),
                    "n_columns={n_columns} ilp2={ilp2}"
                );
            }
        }
    }
}

#[cfg(any())] // legacy (pre-lifted-merkle) test, superseded by the testkit
mod tests {
    use stwo::core::fields::m31::{BaseField, M31};
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
    use stwo::prover::backend::{Column, CpuBackend};
    use stwo::prover::vcs::ops::MerkleOps;

    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;
    use crate::columns::blake_2s_hash_vec::Blake2sHashVec;

    #[test]
    fn test_commit_on_first_layer_with_many_columns_compared_with_cpu() {
        let log_size = 16;
        let size = 1 << log_size;

        let cpu_columns_vector: Vec<Vec<BaseField>> = columns_test_vector(100, size);
        let gpu_columns_vector: Vec<BaseFieldVec> = gpu_columns_from(&cpu_columns_vector);

        let expected_result = <CpuBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
            log_size,
            None,
            &cpu_columns_vector.iter().collect::<Vec<_>>(),
        );
        let result: Blake2sHashVec =
            <CudaBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
                log_size,
                None,
                &gpu_columns_vector.iter().collect::<Vec<_>>(),
            );

        assert_eq!(result.to_cpu(), expected_result);
    }

    #[test]
    fn test_commit_on_layer_with_previous_layer_compared_with_cpu() {
        let current_layer_log_size = 10;
        let current_layer_size = 1 << current_layer_log_size;
        let previous_layer_log_size = current_layer_log_size + 1;
        let previous_layer_size = 1 << previous_layer_log_size;

        // First layer

        let cpu_columns_vector: Vec<Vec<BaseField>> = columns_test_vector(35, previous_layer_size);
        let gpu_columns_vector: Vec<BaseFieldVec> = gpu_columns_from(&cpu_columns_vector);

        let cpu_previous_layer = <CpuBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
            previous_layer_log_size,
            None,
            &cpu_columns_vector.iter().collect::<Vec<_>>(),
        );
        let gpu_previous_layer: Blake2sHashVec =
            <CudaBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
                previous_layer_log_size,
                None,
                &gpu_columns_vector.iter().collect::<Vec<_>>(),
            );

        // Current layer

        let cpu_columns_vector: Vec<Vec<BaseField>> = columns_test_vector(16, current_layer_size);
        let gpu_columns_vector: Vec<BaseFieldVec> = gpu_columns_from(&cpu_columns_vector);

        let expected_result = <CpuBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
            current_layer_log_size,
            Some(&cpu_previous_layer),
            &cpu_columns_vector.iter().collect::<Vec<_>>(),
        );
        let result: Blake2sHashVec =
            <CudaBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
                current_layer_log_size,
                Some(&gpu_previous_layer),
                &gpu_columns_vector.iter().collect::<Vec<_>>(),
            );

        assert_eq!(result.to_cpu(), expected_result);
    }

    fn gpu_columns_from(columns: &Vec<Vec<BaseField>>) -> Vec<BaseFieldVec> {
        columns
            .clone()
            .into_iter()
            .map(|vector| BaseFieldVec::from_vec(vector))
            .collect()
    }

    fn columns_test_vector(
        number_of_columns: usize,
        size_of_columns: usize,
    ) -> Vec<Vec<BaseField>> {
        (0..number_of_columns)
            .map(|index_of_column| {
                (0..size_of_columns)
                    .map(|index_in_column| M31::from(index_in_column * index_of_column))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_commit_on_first_layer_log24() {
        // Test at log_size=24 to check for size-related issues
        let log_size = 24u32;
        let size = 1 << log_size;

        // Use fewer columns to save memory - just 4 columns
        let cpu_columns_vector: Vec<Vec<BaseField>> = columns_test_vector(4, size);
        let gpu_columns_vector: Vec<BaseFieldVec> = gpu_columns_from(&cpu_columns_vector);

        let expected_result = <CpuBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
            log_size,
            None,
            &cpu_columns_vector.iter().collect::<Vec<_>>(),
        );
        let result: Blake2sHashVec =
            <CudaBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
                log_size,
                None,
                &gpu_columns_vector.iter().collect::<Vec<_>>(),
            );

        // Compare first and last hashes
        let cpu_hashes = expected_result.clone();
        let gpu_hashes = result.to_cpu();

        assert_eq!(gpu_hashes.len(), size);
        assert_eq!(cpu_hashes.len(), size);

        // Check first 100 hashes
        assert_eq!(
            gpu_hashes[..100],
            cpu_hashes[..100],
            "First 100 hashes mismatch"
        );
        // Check last 100 hashes
        assert_eq!(
            gpu_hashes[size - 100..],
            cpu_hashes[size - 100..],
            "Last 100 hashes mismatch"
        );
        // Full equality
        assert_eq!(gpu_hashes, cpu_hashes);
    }
}

#[cfg(all(test, stwo_cuda_link))]
mod lifted_tests {
    use stwo::core::fields::m31::{BaseField, M31};
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
    use stwo::prover::backend::{Column, CpuBackend};
    use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;

    use crate::backend::CudaBackend;
    use crate::columns::base_field_vec::BaseFieldVec;
    use crate::columns::blake_2s_hash_vec::Blake2sHashVec;

    #[test]
    fn test_build_leaves_with_mixed_column_sizes_compared_with_cpu() {
        let cpu_columns = vec![
            base_field_column(4, 1),
            base_field_column(4, 3),
            base_field_column(8, 5),
            base_field_column(8, 7),
            base_field_column(16, 11),
        ];
        let gpu_columns = gpu_columns_from(&cpu_columns);
        let expected = <CpuBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_leaves(
            &cpu_columns.iter().collect::<Vec<_>>(),
            4,
        );
        let result: Blake2sHashVec =
            <CudaBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_leaves(
                &gpu_columns.iter().collect::<Vec<_>>(),
                4,
            );

        assert_eq!(result.to_cpu(), expected);
    }

    #[test]
    fn test_build_leaves_with_additional_lifting_compared_with_cpu() {
        let cpu_columns = vec![
            base_field_column(4, 13),
            base_field_column(8, 17),
            base_field_column(8, 19),
        ];
        let gpu_columns = gpu_columns_from(&cpu_columns);
        let expected = <CpuBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_leaves(
            &cpu_columns.iter().collect::<Vec<_>>(),
            5,
        );
        let result: Blake2sHashVec =
            <CudaBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_leaves(
                &gpu_columns.iter().collect::<Vec<_>>(),
                5,
            );

        assert_eq!(result.to_cpu(), expected);
    }

    fn gpu_columns_from(columns: &[Vec<BaseField>]) -> Vec<BaseFieldVec> {
        columns
            .iter()
            .cloned()
            .map(BaseFieldVec::from_vec)
            .collect()
    }

    fn base_field_column(size: usize, multiplier: u32) -> Vec<BaseField> {
        (0..size)
            .map(|index| M31::from(index as u32 * multiplier + multiplier))
            .collect()
    }
}

impl stwo::prover::vcs_lifted::ops::PackLeavesOps for CudaBackend {
    fn pack_leaves_input(
        values: &[&BaseFieldVec; stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE],
    ) -> [BaseFieldVec;
           stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE
               * stwo::core::vcs_lifted::verifier::PACKED_LEAF_SIZE] {
        use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
        use stwo::core::vcs_lifted::verifier::PACKED_LEAF_SIZE;
        // Mirrors the CPU reference over host copies (small FRI-commit path).
        let len = values[0].len();
        assert!(values.iter().all(|column| column.len() == len));
        assert!(len.is_multiple_of(PACKED_LEAF_SIZE));
        let packed_len = len / PACKED_LEAF_SIZE;

        let coords: [Vec<stwo::core::fields::m31::BaseField>; SECURE_EXTENSION_DEGREE] =
            std::array::from_fn(|coord| values[coord].to_vec());
        let mut packed: [Vec<stwo::core::fields::m31::BaseField>;
            SECURE_EXTENSION_DEGREE * PACKED_LEAF_SIZE] =
            std::array::from_fn(|_| Vec::with_capacity(packed_len));
        for packed_row in 0..packed_len {
            let row_start = packed_row * PACKED_LEAF_SIZE;
            for offset in 0..PACKED_LEAF_SIZE {
                for coord in 0..SECURE_EXTENSION_DEGREE {
                    packed[coord + offset * SECURE_EXTENSION_DEGREE]
                        .push(coords[coord][row_start + offset]);
                }
            }
        }
        packed.map(BaseFieldVec::from_vec)
    }
}

/// Host-only spec gate for the Workstream D layer-pair fusion kernel
/// (`commit_on_two_layers_using_previous_in_gpu`). The kernel produces, for each
/// grandparent index `i`,
///     H( H(prev[4i], prev[4i+1]), H(prev[4i+2], prev[4i+3]) )
/// This test proves that composition is **byte-identical to two sequential
/// single-level `hash_children` passes** — the reference the GPU path must match —
/// using the CPU reference hasher only (no device, runs anywhere). It locks the
/// child byte-ordering the kernel encodes; if the reference `hash_children` stream
/// ever changes, this fails before the kernel is trusted on a pod.
#[cfg(test)]
mod layer_pair_spec_tests {
    use stwo::core::vcs::blake2_hash::Blake2sHash;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasherGeneric;
    use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

    type H = Blake2sMerkleHasherGeneric<false>;

    /// One reference tree level: `out[j] = hash_children(prev[2j], prev[2j+1])`.
    /// Column-free (internal-tree) case, matching the fused lane's precondition.
    fn single_layer(prev: &[Blake2sHash]) -> Vec<Blake2sHash> {
        assert!(prev.len().is_multiple_of(2));
        (0..prev.len() / 2)
            .map(|j| H::hash_children((prev[2 * j], prev[2 * j + 1])))
            .collect()
    }

    /// What the fused two-layer kernel computes: two levels in one pass.
    fn layer_pair_fused(prev: &[Blake2sHash]) -> Vec<Blake2sHash> {
        assert!(prev.len().is_multiple_of(4));
        (0..prev.len() / 4)
            .map(|i| {
                let left_mid = H::hash_children((prev[4 * i], prev[4 * i + 1]));
                let right_mid = H::hash_children((prev[4 * i + 2], prev[4 * i + 3]));
                H::hash_children((left_mid, right_mid))
            })
            .collect()
    }

    fn sample_hashes(n: usize) -> Vec<Blake2sHash> {
        // Deterministic, distinct, non-trivial byte patterns.
        (0..n)
            .map(|k| {
                let mut bytes = [0u8; 32];
                for (b, slot) in bytes.iter_mut().enumerate() {
                    *slot = ((k * 31 + b * 7 + 1) % 251) as u8;
                }
                Blake2sHash(bytes)
            })
            .collect()
    }

    #[test]
    fn layer_pair_matches_two_single_layers() {
        for &grandparents in &[1usize, 2, 3, 8, 37, 256] {
            let prev = sample_hashes(4 * grandparents);
            let fused = layer_pair_fused(&prev);
            let two_pass = single_layer(&single_layer(&prev));
            assert_eq!(
                fused.len(),
                grandparents,
                "output arity for {grandparents} grandparents"
            );
            assert_eq!(
                fused, two_pass,
                "layer-pair fusion diverged from two single-layer passes at \
                 {grandparents} grandparents"
            );
        }
    }

    #[test]
    fn grandparent_consumes_its_four_children_only() {
        // Changing child 4i+3 must change out[i] and leave out[i+1] untouched —
        // confirms the 4-consecutive-children index mapping the kernel uses.
        let mut prev = sample_hashes(8); // two grandparents
        let base = layer_pair_fused(&prev);
        prev[3].0[0] ^= 0xFF; // perturb a child of grandparent 0
        let perturbed = layer_pair_fused(&prev);
        assert_ne!(base[0], perturbed[0], "out[0] must depend on child 3");
        assert_eq!(base[1], perturbed[1], "out[1] must not depend on child 3");
    }
}

/// Host-only spec gate for the Step 3.2 FOUR-level interior fusion kernel
/// (`blake2s_interior4_kernel` / `stwo_blake2s_interior4_on`): for output `i`
/// the kernel computes the level-4 ancestor of children `16i..16i+16` with
/// parent[j] = H(child[2j], child[2j+1]) at every local level. This proves the
/// composition is **byte-identical to four sequential single-level passes**
/// using the CPU reference hasher only (no device, runs anywhere). Also locks
/// the Rust mirror of the kernel's grid math.
#[cfg(test)]
mod interior4_spec_tests {
    use stwo::core::vcs::blake2_hash::Blake2sHash;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasherGeneric;
    use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

    use super::{interior4_grid_blocks, CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK};

    type H = Blake2sMerkleHasherGeneric<false>;

    /// One reference tree level: `out[j] = hash_children(prev[2j], prev[2j+1])`.
    fn single_layer(prev: &[Blake2sHash]) -> Vec<Blake2sHash> {
        assert!(prev.len().is_multiple_of(2));
        (0..prev.len() / 2)
            .map(|j| H::hash_children((prev[2 * j], prev[2 * j + 1])))
            .collect()
    }

    /// What the fused four-level kernel computes: the level-4 ancestor of each
    /// aligned 16-child window, all intermediates local.
    fn interior4_fused(prev: &[Blake2sHash]) -> Vec<Blake2sHash> {
        assert!(prev.len().is_multiple_of(16));
        (0..prev.len() / 16)
            .map(|i| {
                let window = &prev[16 * i..16 * i + 16];
                let l1 = single_layer(window);
                let l2 = single_layer(&l1);
                let l3 = single_layer(&l2);
                H::hash_children((l3[0], l3[1]))
            })
            .collect()
    }

    fn sample_hashes(n: usize) -> Vec<Blake2sHash> {
        (0..n)
            .map(|k| {
                let mut bytes = [0u8; 32];
                for (b, slot) in bytes.iter_mut().enumerate() {
                    *slot = ((k * 37 + b * 11 + 3) % 251) as u8;
                }
                Blake2sHash(bytes)
            })
            .collect()
    }

    #[test]
    fn interior4_matches_four_single_layers() {
        for &outputs in &[1usize, 2, 3, 32, 33, 64] {
            let prev = sample_hashes(16 * outputs);
            let fused = interior4_fused(&prev);
            let four_pass = single_layer(&single_layer(&single_layer(&single_layer(&prev))));
            assert_eq!(fused.len(), outputs, "output arity for {outputs} outputs");
            assert_eq!(
                fused, four_pass,
                "interior4 fusion diverged from four single-level passes at \
                 {outputs} outputs"
            );
        }
    }

    #[test]
    fn output_consumes_its_sixteen_children_only() {
        // Perturbing child 16i+15 must change out[i] and leave out[i+1]
        // untouched — confirms the aligned 16-consecutive-children window
        // mapping the kernel uses.
        let mut prev = sample_hashes(32); // two outputs
        let base = interior4_fused(&prev);
        prev[15].0[0] ^= 0xFF; // perturb the last child of output 0
        let perturbed = interior4_fused(&prev);
        assert_ne!(base[0], perturbed[0], "out[0] must depend on child 15");
        assert_eq!(base[1], perturbed[1], "out[1] must not depend on child 15");
    }

    #[test]
    fn interior4_grid_blocks_are_tight() {
        assert_eq!(CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK, 32);
        for out_size in [1u32, 2, 31, 32, 33, 512, 1 << 20] {
            let blocks = interior4_grid_blocks(out_size);
            // Cover all outputs, with no fully idle trailing block.
            assert!(
                blocks * CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK >= out_size,
                "out_size={out_size}"
            );
            assert!(
                (blocks - 1) * CUDA_BLAKE2S_INTERIOR4_OUT_PER_BLOCK < out_size,
                "out_size={out_size}: last block must not be empty"
            );
        }
        // Power-of-two production shapes divide exactly.
        for log in [5u32, 9, 21] {
            assert_eq!(interior4_grid_blocks(1 << log), 1 << (log - 5), "log={log}");
        }
    }
}
