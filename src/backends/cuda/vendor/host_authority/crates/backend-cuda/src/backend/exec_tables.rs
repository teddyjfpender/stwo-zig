//! Device-resident Cairo execution tables + a device `deduce_output` primitive — the
//! ENDGAME_ARCHITECTURE.md §2 keystone — and a self-contained, hardware-in-the-loop
//! validation harness for it and the witness-JIT launch seam.
//!
//! # What this delivers
//!
//! 1. [`DeviceExecutionTables`]: the adapter's dedup'd memory table uploaded ONCE per proof (pinned
//!    H2D of `addr_to_id` + the f252/small value tables), from which the 28/8 9-bit limb tables are
//!    born on device (reusing the proven [`super::memory_witness`] limb-split kernels). This is the
//!    device residency the module blocker note in [`super::jit_witness`] names as the prerequisite
//!    for turning the host `sub_state.deduce_output(key)` HashMap lookup into a device read.
//! 2. A composed device `deduce_output` (the new `exec_deduce_output` kernel): per address, `addr
//!    -> raw encoded id -> decode -> 28 value limbs`, byte-compared against an independent host
//!    reference over the real PIE memory.
//! 3. The witness-JIT launch seam ([`super::jit_witness`]'s recorded programs launched via
//!    `stwo_cuda_jit_witness_launch`) validated end-to-end on hardware: each recorded decode
//!    replayed on device and byte-compared against the reference interpreter over real `(pc, ap,
//!    fp)` states drawn from the PIE.
//!
//! Everything here is gated behind [`run_witness_jit_selftest`] — nothing runs in a
//! normal prove. The witness-JIT prove lanes stay default OFF (their gate is
//! `STWO_CUDA_WITNESS_JIT`, unchanged); this harness is the differential instrument
//! that must pass on a pod before that default can ever flip.
//!
//! # Why the launch harness compares against the interpreter
//!
//! The recorded programs ([`super::jit_witness::programs`]) are unit-proven bit-equal
//! to the native SIMD decode on the host. The reference [`interp`] executes the same
//! bytecode with the same M31/wrapping formulas the CUDA codegen emits. So
//! device-kernel == interpreter closes the chain: native decode == recording ==
//! interpreter == device kernel, for the recorded decode scope, on real instruction
//! bits.

use std::collections::HashMap;
use std::time::Instant;

use stwo::core::fields::m31::BaseField;

use super::jit_witness::{codegen, interp, isa, recorded_program};
use super::memory_witness::{limb_split_big, limb_split_small};
use super::pointer_vec::{UploadedDevicePointerVec, UploadedUint32Vec};
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::bindings;

// --- Protocol constants (mirror stwo-cairo-common::memory / prover_types::felt). ---
// These are stable encoding constants; duplicated here because backend-cuda must not
// depend on the stwo-cairo crate graph. Provenance: `EncodedMemoryValueId` (tag in the
// top two bits) and `FELT252_BITS_PER_WORD`.
const LARGE_MEMORY_VALUE_ID_BASE: u32 = 0x4000_0000;
const DEFAULT_ID: u32 = LARGE_MEMORY_VALUE_ID_BASE - 1;
const FELT252_BITS_PER_WORD: u32 = 9;
const LIMB_MASK: u32 = (1 << FELT252_BITS_PER_WORD) - 1;
const N_BIG_LIMBS: usize = 28;
const N_SMALL_LIMBS: usize = 8;
const F252_N_WORDS: usize = 8;
/// N_LANES (SIMD width) — the minimum column length the limb-split kernels expect.
const N_LANES: usize = 16;

/// LSB-first split of an 8-word (252-bit) value into 28 9-bit limbs — the exact
/// algorithm of `memory_witness.cu::split_le_9bit<8, 28>` and stwo-cairo-common's
/// `split`. Used as the host reference for the deduce_output differential.
fn split_le_9bit_28(words: &[u32; F252_N_WORDS]) -> [u32; N_BIG_LIMBS] {
    let mut limbs = [0u32; N_BIG_LIMBS];
    let mut n_bits_in_word: u32 = 32;
    let mut word_i: usize = 0;
    let mut word = words[0];
    for limb in limbs.iter_mut() {
        if n_bits_in_word > FELT252_BITS_PER_WORD {
            *limb = word & LIMB_MASK;
            word >>= FELT252_BITS_PER_WORD;
            n_bits_in_word -= FELT252_BITS_PER_WORD;
            continue;
        }
        *limb = word;
        word_i += 1;
        word = if word_i < F252_N_WORDS {
            words[word_i]
        } else {
            0
        };
        if n_bits_in_word < FELT252_BITS_PER_WORD {
            *limb |= (word << n_bits_in_word) & LIMB_MASK;
            word >>= FELT252_BITS_PER_WORD - n_bits_in_word;
        }
        n_bits_in_word += 32 - FELT252_BITS_PER_WORD;
    }
    limbs
}

/// The 8 little-endian u32 words of the value behind a raw encoded id, matching the host
/// `memory_id_to_big.deduce_output` (small values are zero-extended to 8 words).
fn value_words(id: u32, f252_values: &[[u32; 8]], small_values: &[u128]) -> [u32; 8] {
    let tag = id >> 30;
    let val = (id & 0x3FFF_FFFF) as usize;
    if tag == 1 {
        f252_values[val]
    } else {
        let s = small_values[val];
        [
            s as u32,
            (s >> 32) as u32,
            (s >> 64) as u32,
            (s >> 96) as u32,
            0,
            0,
            0,
            0,
        ]
    }
}

/// The 28 9-bit value limbs the host `memory_id_to_big.deduce_output(id)` produces.
fn host_deduce_limbs(id: u32, f252_values: &[[u32; 8]], small_values: &[u128]) -> [u32; 28] {
    split_le_9bit_28(&value_words(id, f252_values, small_values))
}

/// Device-resident execution tables, uploaded once per proof (§2 keystone). Owns the
/// dense `addr_to_id` LUT and the id->limb split tables; a witness kernel deduces a
/// memory value by reading these instead of a host HashMap.
pub struct DeviceExecutionTables {
    /// `addr_to_id[addr]` = raw encoded id (matches host `memory.get_raw_id(addr)`).
    pub addr_to_id: BaseFieldVec,
    /// 28 device columns; `big_limbs[j][f252_id]` = limb j of the big value.
    pub big_limbs: Vec<BaseFieldVec>,
    /// 8 device columns; `small_limbs[j][small_id]` = limb j of the small value.
    pub small_limbs: Vec<BaseFieldVec>,
    pub n_addrs: usize,
    pub n_big: usize,
    pub n_small: usize,
    pub big_column_length: usize,
    pub small_column_length: usize,
    /// Bytes moved host->device for the tables (the once-per-proof PCIe cost the §2
    /// budget must overlap): addr_to_id + f252 values + small values.
    pub h2d_bytes: usize,
    /// Wall seconds spent uploading + generating the device limb tables.
    pub build_seconds: f64,
}

impl DeviceExecutionTables {
    /// Upload the dedup'd memory tables and generate the device limb tables. `addr_to_id`
    /// is `memory.address_to_id[a].0` for `a in 0..len`; `f252_values`/`small_values` are
    /// the adapter's dedup'd value tables.
    pub fn upload(addr_to_id: &[u32], f252_values: &[[u32; 8]], small_values: &[u128]) -> Self {
        bindings::ensure_mem_pool_init();
        let start = Instant::now();

        // addr_to_id: one raw-u32 H2D (no M31 canonicalization — ids carry tag bits).
        let addr_dev = unsafe {
            bindings::copy_uint32_t_vec_from_host_to_device(
                addr_to_id.as_ptr(),
                addr_to_id.len() as u32,
            )
        };
        let addr_to_id_vec = BaseFieldVec::new(addr_dev, addr_to_id.len());

        // Big value table -> 28 device limb columns (single flat segment: column_length
        // >= n_big so every f252 id is in-bounds). Values upload row-major (8 words each).
        let n_big = f252_values.len();
        let big_column_length = n_big.next_power_of_two().max(N_LANES);
        let big_words: Vec<BaseField> = f252_values
            .iter()
            .flat_map(|v| v.iter().map(|&w| BaseField::from_u32_unchecked(w)))
            .collect();
        let big_values_dev = BaseFieldVec::from_vec(big_words);
        let big_limbs = limb_split_big(&big_values_dev, n_big, big_column_length);

        // Small value table -> 8 device limb columns (4 words per value, u128 LE).
        let n_small = small_values.len();
        let small_column_length = n_small.next_power_of_two().max(N_LANES);
        let small_words: Vec<BaseField> = small_values
            .iter()
            .flat_map(|&s| {
                [
                    s as u32,
                    (s >> 32) as u32,
                    (s >> 64) as u32,
                    (s >> 96) as u32,
                ]
                .map(BaseField::from_u32_unchecked)
            })
            .collect();
        let small_values_dev = BaseFieldVec::from_vec(small_words);
        let small_limbs = limb_split_small(&small_values_dev, n_small, small_column_length);

        let h2d_bytes = addr_to_id.len() * 4 + n_big * F252_N_WORDS * 4 + n_small * 4 * 4;

        Self {
            addr_to_id: addr_to_id_vec,
            big_limbs,
            small_limbs,
            n_addrs: addr_to_id.len(),
            n_big,
            n_small,
            big_column_length,
            small_column_length,
            h2d_bytes,
            build_seconds: start.elapsed().as_secs_f64(),
        }
    }

    /// Composed device `deduce_output` over `addresses` (all must be non-empty cells):
    /// returns `(ids, limbs)` where `limbs[q]` is the 28 value limbs for query `q`.
    pub fn deduce_output_device(&self, addresses: &[u32]) -> (Vec<u32>, Vec<[u32; 28]>) {
        let n = addresses.len();
        if n == 0 {
            return (Vec::new(), Vec::new());
        }
        assert_eq!(self.big_limbs.len(), N_BIG_LIMBS);
        assert_eq!(self.small_limbs.len(), N_SMALL_LIMBS);
        let addr_dev = UploadedUint32Vec::upload(addresses);
        let big_ptrs: Vec<*const u32> = self.big_limbs.iter().map(|c| c.device_ptr).collect();
        let small_ptrs: Vec<*const u32> = self.small_limbs.iter().map(|c| c.device_ptr).collect();
        let big_table = UploadedDevicePointerVec::upload(&big_ptrs);
        let small_table = UploadedDevicePointerVec::upload(&small_ptrs);

        let out_ids = BaseFieldVec::new_uninitialized(n);
        let out_limbs: Vec<BaseFieldVec> = (0..N_BIG_LIMBS)
            .map(|_| BaseFieldVec::new_uninitialized(n))
            .collect();
        let out_ptrs: Vec<*const u32> = out_limbs.iter().map(|c| c.device_ptr).collect();
        let out_table = UploadedDevicePointerVec::upload(&out_ptrs);

        unsafe {
            stwo_backend_cuda_kernels::raw::exec_deduce_output(
                self.addr_to_id.device_ptr,
                big_table.as_ptr(),
                small_table.as_ptr(),
                addr_dev.as_ptr(),
                n as u32,
                out_ids.device_ptr.cast_mut(),
                out_table.as_ptr().cast::<*mut u32>(),
            );
        }

        let ids: Vec<u32> = out_ids.to_vec().into_iter().map(|f| f.0).collect();
        let limb_cols: Vec<Vec<u32>> = out_limbs
            .iter()
            .map(|c| c.to_vec().into_iter().map(|f| f.0).collect())
            .collect();
        let limbs: Vec<[u32; 28]> = (0..n)
            .map(|q| std::array::from_fn(|j| limb_cols[j][q]))
            .collect();
        (ids, limbs)
    }
}

/// Outcome of one differential leg.
pub struct LegResult {
    pub label: String,
    pub n_checked: usize,
    pub n_mismatch: usize,
    pub note: String,
}

impl LegResult {
    fn ok(&self) -> bool {
        self.n_mismatch == 0
    }
}

/// Run the deduce_output differential over up to `max_queries` non-empty addresses.
fn deduce_output_leg(
    tables: &DeviceExecutionTables,
    f252_values: &[[u32; 8]],
    small_values: &[u128],
    addr_to_id: &[u32],
    max_queries: usize,
) -> LegResult {
    // Collect non-empty addresses (skip address 0 — reserved — and empty cells).
    let addresses: Vec<u32> = (1..addr_to_id.len())
        .filter(|&a| addr_to_id[a] != DEFAULT_ID)
        .take(max_queries)
        .map(|a| a as u32)
        .collect();

    let (dev_ids, dev_limbs) = tables.deduce_output_device(&addresses);
    let mut n_mismatch = 0usize;
    let mut first_bad = String::new();
    for (i, &addr) in addresses.iter().enumerate() {
        let want_id = addr_to_id[addr as usize];
        let want_limbs = host_deduce_limbs(want_id, f252_values, small_values);
        if dev_ids[i] != want_id || dev_limbs[i] != want_limbs {
            if n_mismatch == 0 {
                first_bad = format!(
                    "addr={addr} host_id={want_id} dev_id={} host_limb0={} dev_limb0={}",
                    dev_ids[i], want_limbs[0], dev_limbs[i][0]
                );
            }
            n_mismatch += 1;
        }
    }
    LegResult {
        label: "deduce_output".to_string(),
        n_checked: addresses.len(),
        n_mismatch,
        note: if n_mismatch == 0 {
            format!("{} addrs (big+small), 28 limbs each", addresses.len())
        } else {
            format!("first mismatch: {first_bad}")
        },
    }
}

/// A `TableOracle` over the flat tables, matching the device kernel's reads exactly.
/// Records the maximum table-0 key touched (to size the dense array and detect an
/// out-of-cap chained address) and flags any out-of-range access.
/// Truth oracle for the reference interpreter: answers table reads from the REAL
/// memory tables with the kernel's exact dispatch semantics (`stwo_wit_deduce_limb`),
/// so interpreter output == host writer values on every deduce chain.
struct ExecTablesOracle<'a> {
    addr_to_id: &'a [u32],
    f252_values: &'a [[u32; 8]],
    small_values: &'a [u128],
}

impl interp::TableOracle for ExecTablesOracle<'_> {
    fn table_limb(&self, table: u32, key: u32, limb: u32) -> u32 {
        match table {
            0 => *self.addr_to_id.get(key as usize).unwrap_or(&0),
            1 => {
                let tag = key >> 30;
                let val = (key & 0x3FFF_FFFF) as usize;
                if tag == 1 {
                    if val < self.f252_values.len() {
                        split_le_9bit_28(&self.f252_values[val])[limb as usize]
                    } else {
                        0
                    }
                } else if limb < 8 && val < self.small_values.len() {
                    let s = self.small_values[val];
                    let words = [
                        s as u32,
                        (s >> 32) as u32,
                        (s >> 64) as u32,
                        (s >> 96) as u32,
                        0,
                        0,
                        0,
                        0,
                    ];
                    split_le_9bit_28(&words)[limb as usize]
                } else {
                    0
                }
            }
            t => panic!("unexpected table id {t}"),
        }
    }
}

/// The witness-JIT kernel's table ABI (matches `stwo_wit_deduce_limb` in the
/// codegen): pointer slots [0]=addr_to_id, [1..29]=the 28 big limb columns,
/// [29..37]=the 8 small limb columns; the strides array carries the clamp lengths
/// [n_addrs, n_big, n_small].
pub(super) fn witness_table_pointers(t: &DeviceExecutionTables) -> (Vec<*const u32>, Vec<u32>) {
    let mut ptrs = Vec::with_capacity(37);
    ptrs.push(t.addr_to_id.device_ptr);
    for c in &t.big_limbs {
        ptrs.push(c.device_ptr);
    }
    for c in &t.small_limbs {
        ptrs.push(c.device_ptr);
    }
    (
        ptrs,
        vec![t.n_addrs as u32, t.n_big as u32, t.n_small as u32],
    )
}

/// Process-global device-tables cache for the prove lane: one upload per memory
/// (keyed by the caller's stable address of the adapter table), shared by every
/// component and every rep. Leaked deliberately — the tables live as long as the
/// process, exactly like the registered recordings.
pub fn exec_tables_cached(
    key: usize,
    build: impl FnOnce() -> DeviceExecutionTables,
) -> &'static DeviceExecutionTables {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<usize, &'static DeviceExecutionTables>>> = OnceLock::new();
    let mut map = CACHE.get_or_init(Default::default).lock().unwrap();
    if let Some(t) = map.get(&key) {
        return t;
    }
    let leaked: &'static DeviceExecutionTables = Box::leak(Box::new(build()));
    map.insert(key, leaked);
    leaked
}

/// Bring up one recorded component on hardware: build the flat instruction tables from
/// the real memory, run the reference interpreter over the real states (also discovering
/// the table extents), launch the generated kernel against the device tables, and
/// byte-compare the committed decode columns.
#[allow(clippy::too_many_arguments)]
fn launch_leg(
    label: &str,
    samples: &[(u32, u32, u32)],
    addr_to_id: &[u32],
    f252_values: &[[u32; 8]],
    small_values: &[u128],
    tables: &DeviceExecutionTables,
) -> LegResult {
    let Some(program) = recorded_program(label) else {
        return skipped(label, "no recorded program");
    };
    if samples.is_empty() {
        return skipped(label, "no states of this opcode in the PIE");
    }
    // Inputs 0..2 are pc/ap/fp; input 3, when present, is the ENABLER (the emitted
    // full-width writer recordings read it; hand decode-subsets did not). Every
    // selftest-sampled row is a real (non-padding) row, so the enabler feed is
    // constant 1 — matching what the host writer's Enabler column evaluates to on
    // real rows.
    assert!(
        program.n_inputs <= 4,
        "{label}: expected <=4 inputs (pc/ap/fp[/enabler])"
    );

    // Sample sanity (an empty/out-of-range pc means the harness fed garbage).
    let mut distinct = std::collections::HashSet::new();
    for &(pc, ..) in samples {
        if pc as usize >= addr_to_id.len() {
            return skipped(label, "sample pc outside memory (unexpected)");
        }
        if addr_to_id[pc as usize] == DEFAULT_ID {
            return skipped(label, "sample pc is an empty cell (unexpected)");
        }
        distinct.insert(pc);
    }
    let n_distinct = distinct.len();

    // Reference interpreter pass against the TRUTH oracle (the real memory tables
    // with exact host deduce semantics) — so a kernel-vs-interpreter match here
    // means the kernel matches the HOST WRITER's values, not merely a shared model.
    let oracle = ExecTablesOracle {
        addr_to_id,
        f252_values,
        small_values,
    };
    let mut host_rows: Vec<interp::RowOutputs> = Vec::with_capacity(samples.len());
    for &(pc, ap, fp) in samples {
        host_rows.push(interp::interpret_row(program, &[pc, ap, fp, 1], &oracle));
    }

    let (device_cols, device_lookup, device_sub) = launch_witness_program(program, samples, tables);

    // Byte-compare the FULL prove-lane data contract (device kernel vs reference
    // interpreter): committed columns, then the word-major lookup/sub-input flats the
    // prove path feeds into `LookupData` reconstruction and sub-component feeding.
    let n_cols = program.n_cols as usize;
    let n = samples.len();
    let mut n_mismatch = 0usize;
    let mut first_bad = String::new();
    for (row, host) in host_rows.iter().enumerate() {
        for col in 0..n_cols {
            let dev = device_cols[col][row];
            if dev != host.columns[col] {
                if n_mismatch == 0 {
                    let (pc, ap, fp) = samples[row];
                    first_bad = format!(
                        "row {row} (pc={pc} ap={ap} fp={fp}) col {col}: host {} device {dev}",
                        host.columns[col]
                    );
                }
                n_mismatch += 1;
            }
        }
        for (w, &hv) in host.lookup_words.iter().enumerate() {
            let dev = device_lookup[w * n + row];
            if dev != hv {
                if n_mismatch == 0 {
                    first_bad = format!("row {row} lookup word {w}: host {hv} device {dev}");
                }
                n_mismatch += 1;
            }
        }
        for (w, &hv) in host.sub_words.iter().enumerate() {
            let dev = device_sub[w * n + row];
            if dev != hv {
                if n_mismatch == 0 {
                    first_bad = format!("row {row} sub word {w}: host {hv} device {dev}");
                }
                n_mismatch += 1;
            }
        }
    }
    let words_per_row = (program.n_lookup_words + program.n_sub_words) as usize;
    LegResult {
        label: format!("wt:{label}"),
        n_checked: samples.len() * (n_cols + words_per_row),
        n_mismatch,
        note: if n_mismatch == 0 {
            format!(
                "{} states x {} cols + {} lookup + {} sub words; {} distinct instrs",
                samples.len(),
                n_cols,
                program.n_lookup_words,
                program.n_sub_words,
                n_distinct
            )
        } else {
            format!("first mismatch: {first_bad}")
        },
    }
}

/// PROVE-path launch of a registered recorded witness program: returns the trace
/// columns DEVICE-RESIDENT (ready to feed the committed tree without a round trip)
/// plus host copies of the flat lookup words (`n_lookup_words * n` u32s) and
/// sub-input words (`n_sub_words * n` u32s), both WORD-MAJOR (`word_idx * n + row`
/// — the codegen's store layout; each 16-lane PackedM31 repack is one contiguous
/// 64B run). `samples` must already be padded to the column length by the caller
/// (replicating the first input, matching the host writer); `tables` are the §2
/// device execution tables for the SAME memory the states ran against (build once
/// per prove via [`exec_tables_cached`]) — the kernel deduces EVERY memory operand
/// (pc decode AND dst/op0/op1 value chains) through them. The first `n_real` rows
/// get enabler=1 and the padding tail enabler=0 — the recorded program consumes the
/// enabler as input slot 3 exactly like the host writer's Enabler column.
///
/// Returns None whenever the lane cannot produce PROVABLY-correct output — no CUDA,
/// no registered program, a program shape this path does not support — and the
/// caller falls back to the host writer. Never launches with known-garbage inputs.
/// Stage B′ (`STWO_CUDA_STREAM_FANOUT`): pool-stream count the witness lanes
/// round-robin across. MUST match `STWO_N_POOL_STREAMS` in `cuda_mem_pool.cu`.
const N_FANOUT_STREAMS: u64 = 4;

/// Fan-out is opt-in AND requires the real kernels (the fork/join FFI diverges on the
/// CUDA-stub host build), so on macOS this is always false and `StreamFork` is never
/// constructed — the launch stays on the legacy stream, byte-identical to pre-B′.
fn stream_fanout_enabled() -> bool {
    stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT
        && std::env::var("STWO_CUDA_STREAM_FANOUT").as_deref() == Ok("1")
}

static NEXT_FANOUT_STREAM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Round-robin pool-stream index. Pure (no device) so the rotation is unit-testable.
fn pool_stream_index(counter: u64) -> i32 {
    (counter % N_FANOUT_STREAMS) as i32
}

/// RAII fork/join around ONE witness lane's stream work. On construction it forks a
/// pool stream from the legacy stream (so the lane's kernel waits for its already-
/// enqueued inputs — pool allocations stay legacy-ordered); on drop it joins the pool
/// stream back into legacy (so every downstream consumer AND the host D2H that follows
/// wait for the lane's kernel). Correct by construction: the closing bridge always
/// runs, even on early return. Fork/join use per-call events, safe across the
/// concurrent (rayon) witness lanes. The guard is scoped to end BEFORE the host D2H.
struct StreamFork {
    stream: *mut core::ffi::c_void,
}
impl StreamFork {
    /// `None` (→ launch on the legacy stream) unless fan-out is enabled.
    fn acquire() -> Option<Self> {
        if !stream_fanout_enabled() {
            return None;
        }
        let idx = pool_stream_index(
            NEXT_FANOUT_STREAM.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        {
            use std::sync::Once;
            static ENGAGED: Once = Once::new();
            ENGAGED.call_once(|| {
                // ASCII-only marker ("B2", not "B\u{2032}"): see the A2 marker note — a
                // `B. engaged` grep matches one byte for `.` and can't span the 3-byte prime.
                eprintln!(
                    "STWO_CUDA_STREAM_FANOUT: B2 engaged - witness lanes fanning out across \
                     {N_FANOUT_STREAMS} pool streams (fork/join bridged per lane)"
                );
            });
        }
        let stream = unsafe { stwo_backend_cuda_kernels::raw::stwo_fanout_stream(idx) };
        unsafe { stwo_backend_cuda_kernels::raw::stwo_fanout_fork(stream) };
        Some(Self { stream })
    }
}
impl Drop for StreamFork {
    fn drop(&mut self) {
        unsafe { stwo_backend_cuda_kernels::raw::stwo_fanout_join(self.stream) };
    }
}

fn fork_stream_ptr(fork: &Option<StreamFork>) -> *mut core::ffi::c_void {
    fork.as_ref().map_or(core::ptr::null_mut(), |f| f.stream)
}

/// Arena-backed outputs for one recorded witness launch.  Every buffer is
/// borrowed (`BaseFieldVec::owns_memory == false`) by the resident prover and
/// must outlive the returned trace/lookup/sub handles.
#[derive(Debug)]
pub struct WitnessLaunchDestinations {
    pub trace: Vec<BaseFieldVec>,
    pub lookup: BaseFieldVec,
    pub sub: BaseFieldVec,
    pub context: crate::CudaLaunchContext,
}

type WitnessLaunchResult = (
    Vec<BaseFieldVec>,
    BaseFieldVec,
    Vec<u32>,
    BaseFieldVec,
    Vec<u32>,
);

pub fn launch_recorded_witness_for_prove(
    label: &str,
    samples: &[(u32, u32, u32)],
    n_real: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
) -> Option<WitnessLaunchResult> {
    launch_recorded_witness_for_prove_with_destinations(
        label,
        samples,
        n_real,
        tables,
        want_host_lookup,
        None,
    )
}

pub fn launch_recorded_witness_for_prove_into(
    label: &str,
    samples: &[(u32, u32, u32)],
    n_real: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    destinations: WitnessLaunchDestinations,
) -> Option<WitnessLaunchResult> {
    launch_recorded_witness_for_prove_with_destinations(
        label,
        samples,
        n_real,
        tables,
        want_host_lookup,
        Some(destinations),
    )
}

fn launch_recorded_witness_for_prove_with_destinations(
    label: &str,
    samples: &[(u32, u32, u32)],
    n_real: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    destinations: Option<WitnessLaunchDestinations>,
) -> Option<WitnessLaunchResult> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return None;
    }
    let program = super::jit_witness::recorded_program(label)?;
    let n = samples.len();
    if program.n_inputs > 4 {
        eprintln!(
            "jit_prove[{label}]: program has {} inputs (>4), falling back",
            program.n_inputs
        );
        return None;
    }

    // Input columns: pc/ap/fp + enabler (1 for real rows, 0 for padding).
    let pc_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.0)).collect());
    let ap_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.1)).collect());
    let fp_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.2)).collect());
    let enabler_col = BaseFieldVec::from_vec((0..n).map(|i| bf(u32::from(i < n_real))).collect());
    let input_ptrs: Vec<*const u32> = vec![
        pc_col.device_ptr,
        ap_col.device_ptr,
        fp_col.device_ptr,
        enabler_col.device_ptr,
    ];

    // Opcodes always keep the host sub buffer: verify_instruction (not a COUNT_RELATION)
    // is host-fed from `sub_flat`, so it can never be skipped here.
    let result = launch_witness_program_core(
        label,
        program,
        &input_ptrs,
        n,
        tables,
        want_host_lookup,
        // want_host_sub
        true,
        destinations,
    );
    // Inputs may be dropped now (the core launch is synchronous through its D2H).
    drop((pc_col, ap_col, fp_col, enabler_col));
    result
}

/// Builtin-family launch (the automated D′ lane): the CALLER provides the
/// slot-layout input columns — `[flat input words 0..K | enabler K | iota K+1 |
/// mults K+2+j]`, felt inputs pre-flattened to 28 consecutive 9-bit-limb
/// columns — as RAW u32 host columns. Raw because blake message words exceed
/// the M31 modulus and limb slices are bit-patterns: no BaseField
/// canonicalization may touch them (the kernel reads plain `unsigned`).
///
/// The column count must equal the recording's `n_inputs` EXACTLY — the layout
/// is positional, and a mismatch means the caller and the recording disagree
/// about the slot contract, so this falls back (fail-closed) rather than
/// launching a kernel that would read garbage slots.
pub fn launch_recorded_builtin_for_prove(
    label: &str,
    input_cols: &[Vec<u32>],
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_for_prove_with_destinations(
        label,
        input_cols,
        tables,
        want_host_lookup,
        want_host_sub,
        None,
    )
}

pub fn launch_recorded_builtin_for_prove_into(
    label: &str,
    input_cols: &[Vec<u32>],
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: WitnessLaunchDestinations,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_for_prove_with_destinations(
        label,
        input_cols,
        tables,
        want_host_lookup,
        want_host_sub,
        Some(destinations),
    )
}

fn launch_recorded_builtin_for_prove_with_destinations(
    label: &str,
    input_cols: &[Vec<u32>],
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: Option<WitnessLaunchDestinations>,
) -> Option<WitnessLaunchResult> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return None;
    }
    let program = super::jit_witness::recorded_program(label)?;
    if program.n_inputs as usize != input_cols.len() {
        eprintln!(
            "jit_prove[{label}]: {} input columns provided, program reads {} — falling back",
            input_cols.len(),
            program.n_inputs
        );
        return None;
    }
    let n = input_cols.first().map_or(0, Vec::len);
    if n == 0 || input_cols.iter().any(|c| c.len() != n) {
        eprintln!("jit_prove[{label}]: ragged or empty input columns — falling back");
        return None;
    }
    let uploaded: Vec<UploadedUint32Vec> = input_cols
        .iter()
        .map(|col| UploadedUint32Vec::upload(col))
        .collect();
    let input_ptrs: Vec<*const u32> = uploaded.iter().map(|u| u.as_ptr()).collect();

    let result = launch_witness_program_core(
        label,
        program,
        &input_ptrs,
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        destinations,
    );
    drop(uploaded);
    result
}

/// Builtin launch from DEVICE-resident input columns (the B3 edge path): the
/// caller owns the device buffers (e.g. gathered from a producer's sub buffer
/// via [`witness_edge_gather`]); the count/shape discipline is identical to
/// the host-column variant (trailing-slot trim, exact program extent).
pub fn launch_recorded_builtin_from_device_cols(
    label: &str,
    input_ptrs: &[*const u32],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_from_device_cols_with_destinations(
        label,
        input_ptrs,
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        None,
    )
}

pub fn launch_recorded_builtin_from_device_cols_into(
    label: &str,
    input_ptrs: &[*const u32],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: WitnessLaunchDestinations,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_from_device_cols_with_destinations(
        label,
        input_ptrs,
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        Some(destinations),
    )
}

fn launch_recorded_builtin_from_device_cols_with_destinations(
    label: &str,
    input_ptrs: &[*const u32],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: Option<WitnessLaunchDestinations>,
) -> Option<WitnessLaunchResult> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return None;
    }
    let program = super::jit_witness::recorded_program(label)?;
    let n_inputs = program.n_inputs as usize;
    if input_ptrs.len() < n_inputs {
        eprintln!(
            "jit_prove[{label}]: {} device input columns, program reads {n_inputs} — falling back",
            input_ptrs.len()
        );
        return None;
    }
    launch_witness_program_core(
        label,
        program,
        &input_ptrs[..n_inputs],
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        destinations,
    )
}

/// Builtin launch with MIXED inputs (the B3 edge consumer): leading DEVICE
/// column pointers (the gathered producer words) plus trailing HOST columns to
/// upload (enabler/iota — cheap, size-n each). Positional: device cols occupy
/// slots `0..device_ptrs.len()`, host cols follow.
pub fn launch_recorded_builtin_mixed(
    label: &str,
    device_ptrs: &[*const u32],
    host_tail_cols: &[Vec<u32>],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_mixed_with_destinations(
        label,
        device_ptrs,
        host_tail_cols,
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        None,
    )
}

pub fn launch_recorded_builtin_mixed_into(
    label: &str,
    device_ptrs: &[*const u32],
    host_tail_cols: &[Vec<u32>],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: WitnessLaunchDestinations,
) -> Option<WitnessLaunchResult> {
    launch_recorded_builtin_mixed_with_destinations(
        label,
        device_ptrs,
        host_tail_cols,
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        Some(destinations),
    )
}

fn launch_recorded_builtin_mixed_with_destinations(
    label: &str,
    device_ptrs: &[*const u32],
    host_tail_cols: &[Vec<u32>],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: Option<WitnessLaunchDestinations>,
) -> Option<WitnessLaunchResult> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return None;
    }
    let program = super::jit_witness::recorded_program(label)?;
    let uploaded: Vec<UploadedUint32Vec> = host_tail_cols
        .iter()
        .map(|col| UploadedUint32Vec::upload(col))
        .collect();
    let mut input_ptrs: Vec<*const u32> = device_ptrs.to_vec();
    input_ptrs.extend(uploaded.iter().map(|u| u.as_ptr()));
    let n_inputs = program.n_inputs as usize;
    if input_ptrs.len() < n_inputs {
        eprintln!(
            "jit_prove[{label}]: {} mixed input columns, program reads {n_inputs} — falling back",
            input_ptrs.len()
        );
        return None;
    }
    let result = launch_witness_program_core(
        label,
        program,
        &input_ptrs[..n_inputs],
        n,
        tables,
        want_host_lookup,
        want_host_sub,
        destinations,
    );
    drop(uploaded);
    result
}

/// Gather a consumer's input columns on device from a producer's word-major
/// sub buffer (witness_edge_gather.cu): allocates `words_per_instance` columns
/// of `consumer_rows`, launches the gather, returns the device columns.
/// `None` = stub build or launch failure (caller takes the host path).
pub fn witness_edge_gather(
    producer_sub: &BaseFieldVec,
    producer_rows: usize,
    word_base: usize,
    words_per_instance: usize,
    n_instances: usize,
    consumer_rows: usize,
) -> Option<Vec<BaseFieldVec>> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return None;
    }
    let cols: Vec<BaseFieldVec> = (0..words_per_instance)
        .map(|_| BaseFieldVec::new_zeroes(consumer_rows))
        .collect();
    let ptrs: Vec<*const u32> = cols.iter().map(|c| c.device_ptr).collect();
    let table = UploadedDevicePointerVec::upload(&ptrs);
    let rc = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_witness_edge_gather(
            producer_sub.device_ptr,
            producer_rows as u32,
            word_base as u32,
            words_per_instance as u32,
            n_instances as u32,
            consumer_rows as u32,
            table.as_ptr().cast::<*mut u32>(),
        )
    };
    drop(table);
    if rc != 0 {
        eprintln!("witness edge gather: launch failed (rc={rc})");
        return None;
    }
    Some(cols)
}

/// Run the device-DAG count feed (witness_feed_counts.cu) over a launch's
/// DEVICE-resident sub buffer: uploads the flat descriptors, the LUTs, and one
/// zeroed count buffer per entry of `count_sizes`, launches, then D2Hs the
/// count buffers. Returns `None` on stub builds or launch failure — the caller
/// falls back to host feeds (fail-closed). Synchronous: the returned counts
/// are complete when this returns (legacy-stream ordering after the witness
/// kernel that produced `sub_dev`).
pub fn run_witness_feed_counts(
    sub_dev: &BaseFieldVec,
    n_rows: usize,
    descs: &[u32],
    luts: &[Vec<u32>],
    count_sizes: &[usize],
) -> Option<Vec<Vec<u32>>> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT || descs.is_empty() {
        return None;
    }
    let descs_dev = UploadedUint32Vec::upload(descs);
    let lut_bufs: Vec<UploadedUint32Vec> =
        luts.iter().map(|l| UploadedUint32Vec::upload(l)).collect();
    let lut_ptrs: Vec<*const u32> = lut_bufs.iter().map(|b| b.as_ptr()).collect();
    let lut_table = UploadedDevicePointerVec::upload(&lut_ptrs);
    let count_bufs: Vec<BaseFieldVec> = count_sizes
        .iter()
        .map(|&sz| BaseFieldVec::new_zeroes(sz))
        .collect();
    let count_ptrs: Vec<*const u32> = count_bufs.iter().map(|b| b.device_ptr).collect();
    let count_table = UploadedDevicePointerVec::upload(&count_ptrs);
    let rc = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_witness_feed_counts(
            sub_dev.device_ptr,
            n_rows as u32,
            descs_dev.as_ptr(),
            // Stride 14 = witness_feed_counts.cu WFC_DESC_STRIDE (v2: kind + key
            // offset + mem-id decode small-table params).
            (descs.len() / 14) as u32,
            lut_table.as_ptr(),
            count_table.as_ptr().cast::<*mut u32>(),
        )
    };
    if rc != 0 {
        eprintln!("witness feed counts: kernel launch failed (rc={rc}) — host fallback");
        return None;
    }
    let out: Vec<Vec<u32>> = count_bufs
        .iter()
        .map(|b| b.to_vec().into_iter().map(|f| f.0).collect())
        .collect();
    drop((descs_dev, lut_bufs, lut_table, count_bufs, count_table));
    Some(out)
}

/// Component-agnostic launch core shared by the opcode and builtin entries:
/// guards (mult tables, size governor), output/lookup/sub allocation, codegen,
/// the Stage-B′ stream-forked launch, and the host D2Hs. `input_ptrs` are
/// device column pointers in the program's slot order; the caller keeps their
/// buffers alive across the call (the launch is synchronous through the D2H).
fn launch_witness_program_core(
    label: &str,
    program: &super::jit_witness::isa::WitnessProgram,
    input_ptrs: &[*const u32],
    n: usize,
    tables: &DeviceExecutionTables,
    want_host_lookup: bool,
    want_host_sub: bool,
    destinations: Option<WitnessLaunchDestinations>,
) -> Option<WitnessLaunchResult> {
    let n_cols = program.n_cols as usize;
    if program.n_mult_tables > 0 {
        // Multiplicity tables need real device columns + a host merge that this path
        // does not wire yet; launching with the selftest's 1-element dummies would be
        // an out-of-bounds write. The pilot components record none.
        eprintln!(
            "jit_prove[{label}]: program has {} mult tables (unsupported in prove lane), \
             falling back",
            program.n_mult_tables
        );
        return None;
    }
    // Size governor, fail-closed: an oversized program (partial_ec_mul-class, ~19k
    // instrs) can stall NVRTC/ptxas for tens of minutes — never risk that INSIDE a
    // prove. The warm path (`precompile_witness_kernel`) may still compile it with
    // optimization relief; raise `STWO_CUDA_WITNESS_JIT_MAX_INSTRS` deliberately to
    // let a big program through here once its compile time is proven acceptable.
    let cap = super::jit_witness::witness_prove_max_instrs();
    if program.n_instrs() > cap {
        eprintln!(
            "jit_prove[{label}]: program has {} instrs > cap {cap}, falling back \
             (precompile + raise STWO_CUDA_WITNESS_JIT_MAX_INSTRS to enable)",
            program.n_instrs()
        );
        return None;
    }

    let input_table = UploadedDevicePointerVec::upload(input_ptrs);

    let (table_ptrs, table_lens) = witness_table_pointers(tables);
    let base_table = UploadedDevicePointerVec::upload(&table_ptrs);
    let strides = UploadedUint32Vec::upload(&table_lens);

    let (out_cols, lookup_words, sub_words, resident_context) = match destinations {
        Some(destinations) => {
            if destinations.trace.len() != n_cols
                || destinations.trace.iter().any(|column| column.size != n)
                || destinations.lookup.size < (program.n_lookup_words as usize * n).max(1)
                || destinations.sub.size < (program.n_sub_words as usize * n).max(1)
                || destinations.trace.iter().any(|column| column.owns_memory)
                || destinations.lookup.owns_memory
                || destinations.sub.owns_memory
            {
                eprintln!("jit_prove[{label}]: resident destination geometry/ownership mismatch");
                return None;
            }
            (
                destinations.trace,
                destinations.lookup,
                destinations.sub,
                Some(destinations.context),
            )
        }
        None => {
            let out_cols = (0..n_cols).map(|_| BaseFieldVec::new_zeroes(n)).collect();
            let lookup_len = (program.n_lookup_words as usize * n).max(1);
            let lookup_words = BaseFieldVec::new_zeroes(lookup_len);
            let sub_len = (program.n_sub_words as usize * n).max(1);
            let sub_words = BaseFieldVec::new_zeroes(sub_len);
            (out_cols, lookup_words, sub_words, None)
        }
    };
    let out_ptrs: Vec<*const u32> = out_cols.iter().map(|c| c.device_ptr).collect();
    let out_table = UploadedDevicePointerVec::upload(&out_ptrs);

    let n_mult = program.n_mult_tables.max(1) as usize;
    let mult_cols: Vec<BaseFieldVec> = (0..n_mult).map(|_| BaseFieldVec::new_zeroes(1)).collect();
    let mult_ptrs: Vec<*const u32> = mult_cols.iter().map(|c| c.device_ptr).collect();
    let mult_table = UploadedDevicePointerVec::upload(&mult_ptrs);
    let source = codegen::compile_witness_to_cuda_source(program)?;
    let name = codegen::witness_kernel_name(program.semantic_hash());
    let cache_key = codegen::witness_jit_cache_key(program.semantic_hash());
    let c_source = std::ffi::CString::new(source).ok()?;
    let c_name = std::ffi::CString::new(name).ok()?;

    // Stage B′: the fork/join is scoped to THIS block so the closing join runs
    // before the host D2H below reads the kernel's outputs — otherwise a pool-stream
    // kernel's result would be read off the legacy stream unsynchronized. Concurrent
    // lanes (rayon) each take a different pool stream, so their kernels overlap on the
    // GPU while their host threads block on their own D2Hs. Null stream = legacy (off).
    let ok = {
        // All tables and temporary inputs above are still allocated/uploaded by
        // the legacy backend. Fence them once before an arena-stream launch;
        // the trace/lookup/sub outputs themselves never migrate.
        if resident_context.is_some() {
            crate::synchronize_legacy_stream_for_arena_handoff();
        }
        let fork = resident_context
            .is_none()
            .then(StreamFork::acquire)
            .flatten();
        let stream = resident_context.map_or_else(
            || fork_stream_ptr(&fork),
            |context| context.stream_raw().as_ptr(),
        );
        unsafe {
            stwo_backend_cuda_kernels::raw::stwo_cuda_jit_witness_launch(
                c_source.as_ptr(),
                c_name.as_ptr(),
                cache_key,
                input_table.as_ptr(),
                base_table.as_ptr(),
                strides.as_ptr(),
                out_table.as_ptr().cast::<*mut u32>(),
                mult_table.as_ptr().cast::<*mut u32>(),
                lookup_words.device_ptr.cast_mut(),
                sub_words.device_ptr.cast_mut(),
                n as u32,
                false,
                stream,
            )
        }
        // `fork` drops here → joins the pool stream into legacy before the D2H.
    };
    if !ok {
        return None;
    }
    if let Some(context) = resident_context {
        // Temporary input/table allocations are legacy-owned and may be dropped
        // when this function returns. Fence their arena-stream consumers first.
        context.sync().ok()?;
    }
    // §6a: when the device-interaction lane owns the lookup buffer, the host copy
    // (the largest D2H of the witness path) is skipped entirely.
    let lookup_host: Vec<u32> = if want_host_lookup {
        lookup_words.to_vec().into_iter().map(|f| f.0).collect()
    } else {
        Vec::new()
    };
    // The largest witness D2H (~0.7 GiB for w18): skipped for the all-count builtins
    // whose host `sub_flat` is provably unused (device count feed fully closed, no
    // edge stash). Mirrors the `want_host_lookup` gate above; the DEVICE `sub_words`
    // buffer is untouched and still feeds the counts in place. Fail-closed: the caller
    // passes `true` whenever anything might read `sub_flat`.
    let sub_host: Vec<u32> = if want_host_sub {
        sub_words.to_vec().into_iter().map(|f| f.0).collect()
    } else {
        Vec::new()
    };
    // The DEVICE sub buffer rides along for the device-DAG count feed
    // (witness_feed_counts.cu consumes it in place — no D2H on that path).
    // Tables may be dropped now (launch is synchronous through the D2H above); the
    // returned out_cols stay device-resident for the committed tree, and the DEVICE
    // lookup buffer rides along for the §6a device-interaction lane (born exactly
    // where `logup_pairs.cu` consumes it). Caller-owned input buffers outlive this
    // call by the core's contract.
    drop((
        strides,
        mult_cols,
        input_table,
        base_table,
        out_table,
        mult_table,
    ));
    Some((out_cols, lookup_words, lookup_host, sub_words, sub_host))
}

/// the committed columns (column-major, one Vec per column). `addr_to_idx` (stride 1)
/// and `inst_limbs` (stride 28) are the flat `TableLimb` LUTs.
fn launch_witness_program(
    program: &isa::WitnessProgram,
    samples: &[(u32, u32, u32)],
    tables: &DeviceExecutionTables,
) -> (Vec<Vec<u32>>, Vec<u32>, Vec<u32>) {
    let n = samples.len();
    let n_cols = program.n_cols as usize;

    // Input columns: pc, ap, fp.
    let pc_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.0)).collect());
    let ap_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.1)).collect());
    let fp_col = BaseFieldVec::from_vec(samples.iter().map(|s| bf(s.2)).collect());
    // Enabler input (slot 3): constant 1 for every sampled (real) row.
    let ones_col = BaseFieldVec::from_vec(samples.iter().map(|_| bf(1)).collect());
    let input_ptrs: Vec<*const u32> = vec![
        pc_col.device_ptr,
        ap_col.device_ptr,
        fp_col.device_ptr,
        ones_col.device_ptr,
    ];
    let input_table = UploadedDevicePointerVec::upload(&input_ptrs);

    // The REAL execution tables (§2): the kernel deduces every memory operand
    // through them — same ABI as the prove launch.
    let (table_ptrs, table_lens) = witness_table_pointers(tables);
    let base_table = UploadedDevicePointerVec::upload(&table_ptrs);
    let strides = UploadedUint32Vec::upload(&table_lens);

    // Output columns.
    let out_cols: Vec<BaseFieldVec> = (0..n_cols).map(|_| BaseFieldVec::new_zeroes(n)).collect();
    let out_ptrs: Vec<*const u32> = out_cols.iter().map(|c| c.device_ptr).collect();
    let out_table = UploadedDevicePointerVec::upload(&out_ptrs);

    // Multiplicity tables + lookup words (the recorded decode programs use neither;
    // allocate 1-element dummies so no pointer is null).
    let n_mult = program.n_mult_tables.max(1) as usize;
    let mult_cols: Vec<BaseFieldVec> = (0..n_mult).map(|_| BaseFieldVec::new_zeroes(1)).collect();
    let mult_ptrs: Vec<*const u32> = mult_cols.iter().map(|c| c.device_ptr).collect();
    let mult_table = UploadedDevicePointerVec::upload(&mult_ptrs);
    let lookup_len = (program.n_lookup_words as usize * n).max(1);
    let lookup_words = BaseFieldVec::new_zeroes(lookup_len);
    let sub_len = (program.n_sub_words as usize * n).max(1);
    let sub_words = BaseFieldVec::new_zeroes(sub_len);

    let source =
        codegen::compile_witness_to_cuda_source(program).expect("recorded program must codegen");
    let name = codegen::witness_kernel_name(program.semantic_hash());
    let cache_key = codegen::witness_jit_cache_key(program.semantic_hash());
    let c_source = std::ffi::CString::new(source).unwrap();
    let c_name = std::ffi::CString::new(name).unwrap();

    let ok = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_cuda_jit_witness_launch(
            c_source.as_ptr(),
            c_name.as_ptr(),
            cache_key,
            input_table.as_ptr(),
            base_table.as_ptr(),
            strides.as_ptr(),
            out_table.as_ptr().cast::<*mut u32>(),
            mult_table.as_ptr().cast::<*mut u32>(),
            lookup_words.device_ptr.cast_mut(),
            sub_words.device_ptr.cast_mut(),
            n as u32,
            false,
            // Selftest path (not the prove hot path): always the legacy stream.
            core::ptr::null_mut(),
        )
    };
    assert!(
        ok,
        "stwo_cuda_jit_witness_launch returned false (compile/launch failed)"
    );

    // Keep the input/table buffers alive until after the kernel result is read back.
    let cols: Vec<Vec<u32>> = out_cols
        .iter()
        .map(|c| c.to_vec().into_iter().map(|f| f.0).collect())
        .collect();
    // Word-major flats — the exact buffers the prove path consumes; the selftest
    // compares them against the interpreter so the full prove-lane data contract
    // (not just committed columns) is hardware-verified.
    let lookup_host: Vec<u32> = if program.n_lookup_words > 0 {
        lookup_words.to_vec().into_iter().map(|f| f.0).collect()
    } else {
        Vec::new()
    };
    let sub_host: Vec<u32> = if program.n_sub_words > 0 {
        sub_words.to_vec().into_iter().map(|f| f.0).collect()
    } else {
        Vec::new()
    };
    drop((
        pc_col,
        ap_col,
        fp_col,
        strides,
        lookup_words,
        sub_words,
        mult_cols,
        input_table,
        base_table,
        out_table,
        mult_table,
    ));
    (cols, lookup_host, sub_host)
}

fn bf(x: u32) -> BaseField {
    BaseField::from_u32_unchecked(x)
}

fn skipped(label: &str, why: &str) -> LegResult {
    LegResult {
        label: format!("wt:{label}"),
        n_checked: 0,
        n_mismatch: 0,
        note: format!("SKIPPED: {why}"),
    }
}

/// The full witness-JIT + device-tables self-test (the pod gate). Builds the device
/// execution tables, runs the deduce_output differential over the real memory, then
/// brings up each recorded component. Prints a structured report and returns `true` iff
/// every non-skipped leg had zero mismatches.
///
/// `components` is `(label, states)` where `states` are `(pc, ap, fp)` for that opcode.
pub fn run_witness_jit_selftest(
    addr_to_id: &[u32],
    f252_values: &[[u32; 8]],
    small_values: &[u128],
    components: &[(&str, Vec<(u32, u32, u32)>)],
    max_deduce_queries: usize,
) -> bool {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        eprintln!("WITNESS_JIT_SELFTEST: CUDA kernels not built — nothing to test.");
        return false;
    }

    if let Err(e) = isa::validate_isa_layout() {
        eprintln!("WITNESS_JIT_SELFTEST: ISA layout invalid: {e}");
        return false;
    }

    eprintln!("=== WITNESS_JIT_SELFTEST ===");
    let tables = DeviceExecutionTables::upload(addr_to_id, f252_values, small_values);
    eprintln!(
        "device_exec_tables: n_addrs={} n_big={} n_small={} big_col_len={} small_col_len={} \
         h2d_bytes={} ({:.1} MiB) build_s={:.3}",
        tables.n_addrs,
        tables.n_big,
        tables.n_small,
        tables.big_column_length,
        tables.small_column_length,
        tables.h2d_bytes,
        tables.h2d_bytes as f64 / (1024.0 * 1024.0),
        tables.build_seconds,
    );

    let mut all_ok = true;
    let mut legs: Vec<LegResult> = Vec::new();

    let t = Instant::now();
    let deduce = deduce_output_leg(
        &tables,
        f252_values,
        small_values,
        addr_to_id,
        max_deduce_queries,
    );
    eprintln!(
        "LEG {} : checked={} mismatch={} [{:.3}s] {}",
        deduce.label,
        deduce.n_checked,
        deduce.n_mismatch,
        t.elapsed().as_secs_f64(),
        deduce.note
    );
    all_ok &= deduce.ok();
    legs.push(deduce);

    for (label, samples) in components {
        let t = Instant::now();
        let leg = launch_leg(
            label,
            samples,
            addr_to_id,
            f252_values,
            small_values,
            &tables,
        );
        eprintln!(
            "LEG {} : checked={} mismatch={} [{:.3}s] {}",
            leg.label,
            leg.n_checked,
            leg.n_mismatch,
            t.elapsed().as_secs_f64(),
            leg.note
        );
        all_ok &= leg.ok();
        legs.push(leg);
    }

    let n_ok = legs
        .iter()
        .filter(|l| l.ok() && !l.note.starts_with("SKIPPED"))
        .count();
    let n_skip = legs
        .iter()
        .filter(|l| l.note.starts_with("SKIPPED"))
        .count();
    eprintln!(
        "=== SELFTEST {} : {} legs passed, {} skipped, {} failed ===",
        if all_ok { "PASS" } else { "FAIL" },
        n_ok,
        n_skip,
        legs.iter().filter(|l| !l.ok()).count(),
    );
    all_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stage B′: the witness lanes must round-robin evenly over the pool streams and
    /// never index past the pool (which would be UB in `stwo_fanout_stream`).
    #[test]
    fn pool_stream_index_rotates_within_pool() {
        let seq: Vec<i32> = (0..10).map(pool_stream_index).collect();
        assert_eq!(seq, [0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);
        for i in 0..1000u64 {
            let idx = pool_stream_index(i);
            assert!((0..N_FANOUT_STREAMS as i32).contains(&idx));
        }
        // Wrapping the atomic counter stays in range.
        assert_eq!(
            pool_stream_index(u64::MAX),
            (u64::MAX % N_FANOUT_STREAMS) as i32
        );
    }

    #[test]
    fn split_le_9bit_28_reassembles() {
        // Reassembling the 28 9-bit limbs LSB-first must recover the low 252 bits.
        let words: [u32; 8] = [
            0x1234_5678,
            0x9ABC_DEF0,
            0x0F0F_0F0F,
            0xDEAD_BEEF,
            0x0000_00FF,
            0,
            0,
            0,
        ];
        let limbs = split_le_9bit_28(&words);
        for &l in &limbs {
            assert!(l <= LIMB_MASK, "limb {l} exceeds 9 bits");
        }
        // Reassemble limb-by-limb into a u256 and compare the low words.
        let mut acc = [0u128, 0u128]; // 256-bit accumulator (lo, hi)
        for (i, &l) in limbs.iter().enumerate() {
            let bit = (i as u32) * FELT252_BITS_PER_WORD;
            if bit < 128 {
                acc[0] |= (l as u128) << bit;
                if bit + FELT252_BITS_PER_WORD > 128 {
                    acc[1] |= (l as u128) >> (128 - bit);
                }
            } else {
                acc[1] |= (l as u128) << (bit - 128);
            }
        }
        let expect_lo = words[0] as u128
            | ((words[1] as u128) << 32)
            | ((words[2] as u128) << 64)
            | ((words[3] as u128) << 96);
        assert_eq!(acc[0], expect_lo);
    }

    #[test]
    fn small_value_deduce_zero_extends() {
        // A small value's limbs 8..28 must be zero (host reference contract).
        let small = 0x00FF_1234_5678_9ABCu128; // < 2^72
        let words = [
            small as u32,
            (small >> 32) as u32,
            (small >> 64) as u32,
            (small >> 96) as u32,
            0,
            0,
            0,
            0,
        ];
        let limbs = split_le_9bit_28(&words);
        for l in &limbs[8..] {
            assert_eq!(*l, 0);
        }
    }
}
