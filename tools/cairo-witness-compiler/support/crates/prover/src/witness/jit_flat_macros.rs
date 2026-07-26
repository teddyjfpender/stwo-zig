//! Macro-generated accessors between backend-neutral word-major flat
//! buffers and each component's module-private `LookupData` / sub-input feeds.
//!
//! Invoked INSIDE a component module (the expansion references the module's
//! `LookupData`, `InteractionClaimGenerator`, `SubComponentInputs` flats,
//! `write_trace_simd`, `pack_values`, `N_TRACE_COLUMNS`, and the three state
//! types). Joining the lane is then data entry: the field list mirrors the
//! `LookupData` declaration (widths from the writer's `lw[..]` packing), and the
//! sub map is (n_addr, n_id) after the leading verify_instruction 7-word tuple.
//!
//! Layout contract: flats are word-major, `words[w * n_rows + r]`, so each 16-lane
//! `PackedM31` repack reads one contiguous 64B run.

/// Generates `interaction_gen_from_flat_lookup_words` for the enclosing module.
#[macro_export]
macro_rules! jit_lookup_accessor {
    (
        $n_lookup:expr;
        $( $field:ident : $width:tt ),+ $(,)?
    ) => {
        /// Lookup field list (name, width) in `LookupData` declaration order —
        /// the §6a descriptor builder's input (widths of `scalar` fields are 1;
        /// the trailing two scalars are `mults_0`/`mults_1`).
        #[allow(dead_code)]
        pub(crate) const JIT_LOOKUP_FIELDS: &[(&str, usize)] = &[
            $( (stringify!($field), $crate::jit_lookup_accessor!(@width $width)) ),+
        ];

        /// Rebuild the interaction generator from the device kernel's flat lookup
        /// words (word-major). Field order/widths mirror `LookupData` exactly and
        /// are regression-fenced by the prove-accessor parity gate.
        #[allow(dead_code)]
        pub(crate) fn interaction_gen_from_flat_lookup_words(
            log_size: u32,
            words: &[u32],
            n_rows: usize,
        ) -> InteractionClaimGenerator {
            use rayon::iter::{IntoParallelIterator, ParallelIterator};
            use stwo::prover::backend::simd::m31::{PackedM31, N_LANES};
            let n_vec = n_rows / N_LANES;
            assert_eq!(words.len(), $n_lookup * n_rows);
            let packed_field = |off: usize, k: usize, vi: usize| {
                PackedM31::from_array(std::array::from_fn(|l| {
                    stwo::core::fields::m31::M31::from_u32_unchecked(
                        words[(off + k) * n_rows + vi * N_LANES + l],
                    )
                }))
            };
            let mut off = 0usize;
            $(
                let $field = $crate::jit_lookup_accessor!(
                    @field packed_field, n_vec, off, $width
                );
            )+
            assert_eq!(off, $n_lookup, "lookup layout drift vs LookupData");
            InteractionClaimGenerator {
                log_size,
                lookup_data: LookupData { $( $field ),+ },
            }
        }
    };
    // Variant for modules whose `InteractionClaimGenerator` also carries the REAL
    // row count (`n_rows`, pre-padding — blake_round's enabler bound). The flats
    // are still indexed by the PADDED extent; the extra leading parameter is the
    // real count stored into the generator verbatim.
    (
        with_n_rows $n_lookup:expr;
        $( $field:ident : $width:tt ),+ $(,)?
    ) => {
        /// Lookup field list (name, width) in `LookupData` declaration order.
        #[allow(dead_code)]
        pub(crate) const JIT_LOOKUP_FIELDS: &[(&str, usize)] = &[
            $( (stringify!($field), $crate::jit_lookup_accessor!(@width $width)) ),+
        ];

        /// Rebuild the interaction generator from the device kernel's flat lookup
        /// words (word-major). `n_real` is the pre-padding row count the host
        /// writer stores as the generator's enabler bound.
        #[allow(dead_code)]
        pub(crate) fn interaction_gen_from_flat_lookup_words(
            log_size: u32,
            n_real: usize,
            words: &[u32],
            n_rows: usize,
        ) -> InteractionClaimGenerator {
            use rayon::iter::{IntoParallelIterator, ParallelIterator};
            use stwo::prover::backend::simd::m31::{PackedM31, N_LANES};
            let n_vec = n_rows / N_LANES;
            assert_eq!(words.len(), $n_lookup * n_rows);
            let packed_field = |off: usize, k: usize, vi: usize| {
                PackedM31::from_array(std::array::from_fn(|l| {
                    stwo::core::fields::m31::M31::from_u32_unchecked(
                        words[(off + k) * n_rows + vi * N_LANES + l],
                    )
                }))
            };
            let mut off = 0usize;
            $(
                let $field = $crate::jit_lookup_accessor!(
                    @field packed_field, n_vec, off, $width
                );
            )+
            assert_eq!(off, $n_lookup, "lookup layout drift vs LookupData");
            InteractionClaimGenerator {
                n_rows: n_real,
                log_size,
                lookup_data: LookupData { $( $field ),+ },
            }
        }
    };
    (@width scalar) => { 1usize };
    (@width $k:literal) => { $k as usize };
    (@field $pf:ident, $n_vec:ident, $off:ident, scalar) => {{
        let o = $off;
        $off += 1;
        (0..$n_vec)
            .into_par_iter()
            .map(|vi| $pf(o, 0, vi))
            .collect::<Vec<_>>()
    }};
    (@field $pf:ident, $n_vec:ident, $off:ident, $k:literal) => {{
        let o = $off;
        $off += $k;
        (0..$n_vec)
            .into_par_iter()
            .map(|vi| std::array::from_fn(|k| $pf(o, k, vi)))
            .collect::<Vec<_>>()
    }};
}

/// Generates `sub_inputs_from_flat`, `feed_sub_inputs_from_flat`, and
/// `shadow_compare_against_host` for the enclosing module. Sub-word order is the
/// emitted `set_sub_input_word` index order: words `0..=6` the verify_instruction
/// tuple, then `n_addr` memory addresses, then `n_id` memory ids.
#[macro_export]
macro_rules! jit_sub_accessors {
    ($n_sub:expr, n_addr = $na:expr, n_id = $ni:expr) => {
        /// Decode the flat sub-input words for ALL `n_rows` rows — padding rows
        /// included. The host writer feeds the full padded extent (every row
        /// emits its sub-relation uses with `mults_0 = 1` regardless of the
        /// enabler); truncating at the real row count is an invalid-proof bug.
        pub(crate) fn sub_inputs_from_flat(
            words: &[u32],
            n_rows: usize,
        ) -> (
            Vec<verify_instruction::InputType>,
            Vec<Vec<M31>>,
            Vec<Vec<M31>>,
        ) {
            assert_eq!(words.len(), $n_sub * n_rows, "sub layout drift");
            let w = |word: usize, r: usize| M31::from_u32_unchecked(words[word * n_rows + r]);
            let vi: Vec<verify_instruction::InputType> = (0..n_rows)
                .map(|r| {
                    (
                        w(0, r),
                        [w(1, r), w(2, r), w(3, r)],
                        [w(4, r), w(5, r)],
                        w(6, r),
                    )
                })
                .collect();
            let addrs: Vec<Vec<M31>> = (0..$na)
                .map(|j| (0..n_rows).map(|r| w(7 + j, r)).collect())
                .collect();
            let ids: Vec<Vec<M31>> = (0..$ni)
                .map(|j| (0..n_rows).map(|r| w(7 + $na + j, r)).collect())
                .collect();
            (vi, addrs, ids)
        }

        /// Feed the decoded sub-inputs into the downstream states — the same entry
        /// points, per-relation order, and full padded extent as the host writer.
        /// `device_fed` names count families already merged from device counts
        /// (B2 v2 memory families); their host loops are skipped — double
        /// feeding corrupts multiplicities.
        pub(crate) fn feed_sub_inputs_from_flat(
            words: &[u32],
            n_rows: usize,
            memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
            memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
            verify_instruction_state: &verify_instruction::ClaimGenerator,
            device_fed: &[&'static str],
        ) {
            let (vi, addrs, ids) = sub_inputs_from_flat(words, n_rows);
            for input in &vi {
                $crate::witness::utils::AddInputs::add_input(verify_instruction_state, input, 0);
            }
            if !device_fed.contains(&"memory_address_to_id_state") {
                for col in &addrs {
                    memory_address_to_id_state.add_inputs(col);
                }
            }
            if !device_fed.contains(&"memory_id_to_big_state") {
                for col in &ids {
                    memory_id_to_big_state.add_inputs(col);
                }
            }
        }

        /// PROVE-LANE SHADOW DIFF (`STWO_JIT_PROVE_SHADOW=1`): run the host SIMD
        /// writer (pure read, no feeding) beside the device lane and report the
        /// first divergences per surface with exact coordinates.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn shadow_compare_against_host(
            inputs: &[InputType],
            device_cols: &[Vec<u32>],
            lookup_flat: &[u32],
            sub_flat: &[u32],
            n_padded: usize,
            memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
            memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
            verify_instruction_state: &verify_instruction::ClaimGenerator,
        ) {
            use stwo::prover::backend::simd::m31::N_LANES;
            let n_rows = inputs.len();
            let mut padded = inputs.to_vec();
            padded.resize(n_padded, *padded.first().unwrap());
            let packed = pack_values(&padded);
            let (trace, ld, sci) = write_trace_simd(
                packed,
                n_rows,
                memory_address_to_id_state,
                memory_id_to_big_state,
                verify_instruction_state,
            );
            let n_packed_rows = n_padded / N_LANES;
            let mut bad = 0usize;
            for r in 0..n_padded {
                let host_row = trace.row_at(r);
                for c in 0..N_TRACE_COLUMNS {
                    if device_cols[c][r] != host_row[c].0 {
                        eprintln!(
                            "SHADOW trace row {r} col {c}: host {} device {} (real={})",
                            host_row[c].0,
                            device_cols[c][r],
                            r < n_rows
                        );
                        bad += 1;
                        if bad >= 8 {
                            return;
                        }
                    }
                }
            }
            let mut check_flats = |name: &str,
                                   flats: Vec<Vec<stwo::prover::backend::simd::m31::PackedM31>>,
                                   dev: &[u32]| {
                let mut w = 0usize;
                for (fi, field) in flats.iter().enumerate() {
                    let width = field.len() / n_packed_rows;
                    for k in 0..width {
                        for r in 0..n_padded {
                            let hv = field[(r / N_LANES) * width + k].to_array()[r % N_LANES].0;
                            let dv = dev[w * n_padded + r];
                            if hv != dv {
                                eprintln!(
                                    "SHADOW {name} row {r} word {w} (field {fi}+{k}): \
                                         host {hv} device {dv} (real={})",
                                    r < n_rows
                                );
                                bad += 1;
                                if bad >= 16 {
                                    return;
                                }
                            }
                        }
                        w += 1;
                    }
                }
            };
            check_flats("lookup", lookup_data_flat(&ld), lookup_flat);
            // Sub flats travel as RAW 32-bit lanes (M31 words canonical, blake u32
            // words full-width) — compare the raw words.
            let mut check_raw =
                |name: &str, flats: Vec<Vec<std::simd::Simd<u32, N_LANES>>>, dev: &[u32]| {
                    let mut w = 0usize;
                    for (fi, field) in flats.iter().enumerate() {
                        let width = field.len() / n_packed_rows;
                        for k in 0..width {
                            for r in 0..n_padded {
                                let hv = field[(r / N_LANES) * width + k].as_array()[r % N_LANES];
                                let dv = dev[w * n_padded + r];
                                if hv != dv {
                                    eprintln!(
                                        "SHADOW {name} row {r} word {w} (field {fi}+{k}): \
                                         host {hv} device {dv} (real={})",
                                        r < n_rows
                                    );
                                    bad += 1;
                                    if bad >= 16 {
                                        return;
                                    }
                                }
                            }
                            w += 1;
                        }
                    }
                };
            check_raw("sub", sub_inputs_flat(&sci), sub_flat);
            eprintln!(
                "SHADOW {}: {} divergences ({} padded rows, {} real)",
                module_path!(),
                bad,
                n_padded,
                n_rows
            );
        }
    };
}
