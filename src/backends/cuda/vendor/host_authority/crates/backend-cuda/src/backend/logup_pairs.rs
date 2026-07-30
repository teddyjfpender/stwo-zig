//! Device logup PAIR GENERATION from the witness-JIT lane's word-major lookup
//! flats (ENDGAME §6a): the interaction trace born on device, deleting the
//! lane's flats D2H + host `LookupData` repack + host `write_interaction_trace`.
//!
//! Pipeline: `stwo_logup_pairs_from_flats` (one launch: combine + fraction pairs,
//! straight from the flats the witness kernel wrote) → the PROVEN
//! `logup_finalize.cu` path (`logup_fraction_chain_dense`, claimed-sum reduction,
//! cumsum shift, prefix sums) → device-resident interaction columns.
//!
//! The DESCRIPTOR TABLE encodes the generated `write_interaction_trace` structure,
//! which is uniform across the AIR-generated opcode components: lookup fields pair
//! SEQUENTIALLY two-per-logup-column with a trailing solo column when the count is
//! odd; a field's multiplier is `mults_1` for the `opcodes` relation fields and
//! `mults_0` for every other relation; the trailing solo column is the last
//! `opcodes` field with numerator `-mults_1`. [`descriptors_for_fields`] derives
//! the table from a component's `JIT_LOOKUP_FIELDS` list (names + widths); the
//! device-interaction differential (pod gate) byte-compares the result against the
//! host writer per component before any prove uses it.

use stwo::core::fields::qm31::SecureField;

/// A fraction side's multiplier source. The generated writers use three forms
/// (surveyed exhaustively across the 27 lane components — the emitted
/// `JIT_LOGUP_DESCS` facts): a scalar column in the flats (opcode `mults_0/1`,
/// aggregator mults), the constant one (paired table lookups), or the real-row
/// enabler (builtin own-relation columns, `row < n_real`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultSrc {
    /// Word offset of a scalar column in the flats.
    Flat(u32),
    One,
    /// `1` for rows `< n_real`, else `0`.
    Enabler,
}

/// One logup column's descriptor (see `cuda/logup_pairs.cu` for the device
/// layout). Signs are EXPLICIT (`neg_*`): the generated writers negate yields in
/// arbitrary positions (aggregator mid-stream, builtins' trailing enabler solo),
/// so nothing is implicit — a solo "negated mult" column is `kind = 1` with
/// `neg_a = true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogupColDesc {
    /// 0 = pair, 1 = solo (B side ignored).
    pub kind: u32,
    pub off_a: u32,
    pub width_a: u32,
    pub mult_a: MultSrc,
    pub neg_a: bool,
    pub off_b: u32,
    pub width_b: u32,
    pub mult_b: MultSrc,
    pub neg_b: bool,
}

impl LogupColDesc {
    fn to_words(self) -> [u32; 8] {
        let (kind_a, off_ma) = match self.mult_a {
            MultSrc::Flat(o) => (0u32, o),
            MultSrc::One => (1, 0),
            MultSrc::Enabler => (2, 0),
        };
        let (kind_b, off_mb) = match self.mult_b {
            MultSrc::Flat(o) => (0u32, o),
            MultSrc::One => (1, 0),
            MultSrc::Enabler => (2, 0),
        };
        let flags =
            (self.neg_a as u32) | ((self.neg_b as u32) << 1) | (kind_a << 2) | (kind_b << 4);
        [
            self.kind,
            self.off_a,
            self.width_a,
            off_ma,
            self.off_b,
            self.width_b,
            off_mb,
            flags,
        ]
    }
}

/// Derive the descriptor table from a component's lookup field list
/// (`(name, width)` in `LookupData` declaration order, EXCLUDING the trailing
/// `mults_0`/`mults_1` scalars). Encodes the generated writers' uniform pairing:
/// sequential pairs, `opcodes*` fields take `mults_1`, everything else `mults_0`,
/// odd trailing field becomes the solo negated column.
pub fn descriptors_for_fields(
    fields: &[(&str, usize)],
    mults_0_off: u32,
    mults_1_off: u32,
) -> Vec<LogupColDesc> {
    let mult_of = |name: &str| {
        if name.starts_with("opcodes") {
            mults_1_off
        } else {
            mults_0_off
        }
    };
    let mut offs = Vec::with_capacity(fields.len());
    let mut off = 0u32;
    for (_, w) in fields {
        offs.push(off);
        off += *w as u32;
    }
    let mut descs = Vec::with_capacity(fields.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < fields.len() {
        descs.push(LogupColDesc {
            kind: 0,
            off_a: offs[i],
            width_a: fields[i].1 as u32,
            mult_a: MultSrc::Flat(mult_of(fields[i].0)),
            neg_a: false,
            off_b: offs[i + 1],
            width_b: fields[i + 1].1 as u32,
            mult_b: MultSrc::Flat(mult_of(fields[i + 1].0)),
            neg_b: false,
        });
        i += 2;
    }
    if i < fields.len() {
        // The opcode trailing solo column: numerator = -mults_1 (explicit sign).
        descs.push(LogupColDesc {
            kind: 1,
            off_a: offs[i],
            width_a: fields[i].1 as u32,
            mult_a: MultSrc::Flat(mult_of(fields[i].0)),
            neg_a: true,
            off_b: 0,
            width_b: 0,
            mult_b: MultSrc::One,
            neg_b: false,
        });
    }
    descs
}

/// Run the pair kernel over a DEVICE-resident word-major flats buffer and finalize
/// entirely on device. Returns the interaction columns (device-resident, same
/// order as the host reference: 4 coordinate columns per logup column) plus the
/// claimed sum. `alphas` must hold `alpha^0..alpha^(max_width-1)`.
///
/// Gate before any prove consumes this: the device-interaction differential
/// (byte-compare vs the host `write_interaction_trace` per component).
#[allow(clippy::type_complexity)]
pub fn device_interaction_from_flats(
    flats_device_ptr: *const u32,
    n_rows: usize,
    n_real: usize,
    descs: &[LogupColDesc],
    alphas: &[SecureField],
    z: SecureField,
) -> Option<(
    Vec<
        stwo::prover::poly::circle::CircleEvaluation<
            crate::backend::CudaBackend,
            stwo::core::fields::m31::BaseField,
            stwo::prover::poly::BitReversedOrder,
        >,
    >,
    SecureField,
)> {
    use stwo::core::fields::m31::BaseField;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::poly::circle::CircleEvaluation;

    use crate::backend::pointer_vec::UploadedDevicePointerVec;
    use crate::columns::base_field_vec::BaseFieldVec;
    use crate::columns::bindings;

    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT || descs.is_empty() {
        return None;
    }
    bindings::ensure_mem_pool_init();
    let log_size = n_rows.ilog2();
    assert_eq!(1usize << log_size, n_rows, "n_rows must be a power of two");

    let desc_words: Vec<u32> = descs.iter().flat_map(|d| d.to_words()).collect();
    let alpha_words: Vec<u32> = alphas
        .iter()
        .flat_map(|a| {
            let [x, y, zz, w] = a.to_m31_array();
            [x.0, y.0, zz.0, w.0]
        })
        .collect();
    let [z0, z1, z2, z3] = z.to_m31_array();
    let z_words = [z0.0, z1.0, z2.0, z3.0];

    // Outputs: 4 numerator coordinate columns per logup column + one dense qm31
    // denominator buffer per column (4*n_rows words).
    let num_cols: Vec<BaseFieldVec> = (0..descs.len() * 4)
        .map(|_| BaseFieldVec::new_uninitialized(n_rows))
        .collect();
    let den_bufs: Vec<BaseFieldVec> = (0..descs.len())
        .map(|_| BaseFieldVec::new_uninitialized(n_rows * 4))
        .collect();
    let num_table = UploadedDevicePointerVec::upload(
        &num_cols.iter().map(|c| c.device_ptr).collect::<Vec<_>>(),
    );
    let den_table = UploadedDevicePointerVec::upload(
        &den_bufs.iter().map(|c| c.device_ptr).collect::<Vec<_>>(),
    );

    let ok = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_logup_pairs_from_flats(
            flats_device_ptr,
            n_rows as u32,
            n_real as u32,
            desc_words.as_ptr(),
            descs.len() as u32,
            alpha_words.as_ptr(),
            alphas.len() as u32,
            z_words.as_ptr(),
            num_table.as_ptr().cast::<*mut u32>(),
            den_table.as_ptr().cast::<*mut u32>(),
        )
    };
    if !ok {
        return None;
    }

    // Fraction chain across columns (numerators updated in place), then the
    // claimed-sum / shift / prefix-sum tail — the proven finalize path.
    let mut finalized: Vec<[BaseFieldVec; 4]> = Vec::with_capacity(descs.len());
    let mut num_iter = num_cols.into_iter();
    for (ci, den) in den_bufs.iter().enumerate() {
        let coords: [BaseFieldVec; 4] = std::array::from_fn(|_| num_iter.next().unwrap());
        let prev = finalized.last();
        unsafe {
            stwo_backend_cuda_kernels::raw::logup_fraction_chain_dense(
                coords[0].device_ptr,
                coords[1].device_ptr,
                coords[2].device_ptr,
                coords[3].device_ptr,
                den.device_ptr,
                prev.map_or(std::ptr::null(), |p| p[0].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[1].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[2].device_ptr),
                prev.map_or(std::ptr::null(), |p| p[3].device_ptr),
                n_rows as u32,
            );
        }
        let _ = ci;
        finalized.push(coords);
    }

    let last = finalized.last().expect("descs is non-empty");
    let claimed_sum: SecureField = unsafe {
        bindings::logup_sum_secure_coords(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            n_rows as u32,
        )
    }
    .into();
    let cumsum_shift = claimed_sum / BaseField::from_u32_unchecked(1 << log_size);
    unsafe {
        bindings::logup_shift_secure_coords(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            cumsum_shift.into(),
            n_rows as u32,
        );
        stwo_backend_cuda_kernels::raw::inclusive_prefix_sum_x4(
            last[0].device_ptr,
            last[1].device_ptr,
            last[2].device_ptr,
            last[3].device_ptr,
            n_rows as u32,
        );
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = finalized
        .into_iter()
        .flat_map(|coords| coords.map(|col| CircleEvaluation::new(domain, col)))
        .collect();
    Some((trace, claimed_sum))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pairing rule against add_opcode's known interaction structure:
    /// fields [vi(8), addr(3), id(30), addr(3), id(30), addr(3), id(30),
    /// opc(4), opc(4)] → pairs (0,1)(2,3)(4,5)(6,7) + solo 8; mults_1 only on
    /// the opcodes fields.
    #[test]
    fn add_opcode_descriptor_structure() {
        let fields: &[(&str, usize)] = &[
            ("verify_instruction_0", 8),
            ("memory_address_to_id_1", 3),
            ("memory_id_to_big_2", 30),
            ("memory_address_to_id_3", 3),
            ("memory_id_to_big_4", 30),
            ("memory_address_to_id_5", 3),
            ("memory_id_to_big_6", 30),
            ("opcodes_7", 4),
            ("opcodes_8", 4),
        ];
        let descs = descriptors_for_fields(fields, 115, 116);
        assert_eq!(descs.len(), 5);
        assert_eq!(
            descs[0],
            LogupColDesc {
                kind: 0,
                off_a: 0,
                width_a: 8,
                mult_a: MultSrc::Flat(115),
                neg_a: false,
                off_b: 8,
                width_b: 3,
                mult_b: MultSrc::Flat(115),
                neg_b: false,
            }
        );
        // The pair holding the first opcodes field mixes mults_0 and mults_1.
        assert_eq!(descs[3].mult_a, MultSrc::Flat(115));
        assert_eq!(descs[3].mult_b, MultSrc::Flat(116));
        assert_eq!(descs[3].off_b, 8 + 3 + 30 + 3 + 30 + 3 + 30);
        // Trailing solo: the last opcodes field, EXPLICITLY negated mults_1.
        assert_eq!(
            descs[4],
            LogupColDesc {
                kind: 1,
                off_a: 111,
                width_a: 4,
                mult_a: MultSrc::Flat(116),
                neg_a: true,
                off_b: 0,
                width_b: 0,
                mult_b: MultSrc::One,
                neg_b: false,
            }
        );
    }

    /// The flags word encodes signs + mult kinds losslessly.
    #[test]
    fn desc_words_encode_flags() {
        let d = LogupColDesc {
            kind: 0,
            off_a: 1,
            width_a: 2,
            mult_a: MultSrc::Enabler,
            neg_a: true,
            off_b: 3,
            width_b: 4,
            mult_b: MultSrc::One,
            neg_b: false,
        };
        let w = d.to_words();
        // bit0 negA=1, bit1 negB=0, bits2-3 kindA=2 (enabler), bits4-5 kindB=1 (one)
        assert_eq!(w[7], 1 | (2 << 2) | (1 << 4));
    }

    /// Even field count (assert_eq-like): no solo column.
    #[test]
    fn even_field_count_has_no_solo() {
        let fields: &[(&str, usize)] = &[
            ("verify_instruction_0", 8),
            ("memory_address_to_id_1", 3),
            ("opcodes_2", 4),
            ("opcodes_3", 4),
        ];
        let descs = descriptors_for_fields(fields, 19, 20);
        assert_eq!(descs.len(), 2);
        assert!(descs.iter().all(|d| d.kind == 0));
        assert_eq!(descs[1].mult_a, MultSrc::Flat(20));
        assert_eq!(descs[1].mult_b, MultSrc::Flat(20));
    }
}
