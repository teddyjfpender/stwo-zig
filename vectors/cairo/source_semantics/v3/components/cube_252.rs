#![allow(unused_parens)]
use cairo_air::components::cube_252::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{range_check_20, range_check_9_9};
use crate::witness::prelude::*;

pub type InputType = Felt252Width27;
pub type PackedInputType = PackedFelt252Width27;

#[derive(Default)]
pub struct ClaimGenerator {
    pub packed_inputs: Mutex<Vec<PackedInputType>>,
    pub remainder_inputs: Mutex<Vec<InputType>>,
}

impl ClaimGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_trace(
        self,
        range_check_9_9_state: &range_check_9_9::ClaimGenerator,
        range_check_20_state: &range_check_20::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut packed_inputs = self.packed_inputs.into_inner().unwrap();
        assert!(!packed_inputs.is_empty());
        assert!(self.remainder_inputs.lock().unwrap().is_empty());
        let n_vec_rows = packed_inputs.len();
        let n_rows = n_vec_rows * N_LANES;
        let packed_size = n_vec_rows.next_power_of_two();
        let log_size = packed_size.ilog2() + LOG_N_LANES;
        packed_inputs.resize(packed_size, *packed_inputs.first().unwrap());

        // Decreasing this value may cause a stack-overflow during witness generation.
        // NOTE: This is not autogened, when updating the code, re-add this.
        // TODO(Ohad): remove.
        const RAYON_THREAD_STACK_SIZE: usize = 1024 * 1024 * 8;
        let pool = rayon::ThreadPoolBuilder::new()
            .stack_size(RAYON_THREAD_STACK_SIZE)
            .build()
            .unwrap();
        let (trace, lookup_data, sub_component_inputs) = pool.install(|| {
            write_trace_simd(
                packed_inputs,
                n_rows,
                range_check_9_9_state,
                range_check_20_state,
            )
        });
        for inputs in sub_component_inputs.range_check_9_9 {
            range_check_9_9_state.add_packed_inputs(&inputs, 0);
        }
        for inputs in sub_component_inputs.range_check_9_9_b {
            range_check_9_9_state.add_packed_inputs(&inputs, 1);
        }
        for inputs in sub_component_inputs.range_check_9_9_c {
            range_check_9_9_state.add_packed_inputs(&inputs, 2);
        }
        for inputs in sub_component_inputs.range_check_9_9_d {
            range_check_9_9_state.add_packed_inputs(&inputs, 3);
        }
        for inputs in sub_component_inputs.range_check_9_9_e {
            range_check_9_9_state.add_packed_inputs(&inputs, 4);
        }
        for inputs in sub_component_inputs.range_check_9_9_f {
            range_check_9_9_state.add_packed_inputs(&inputs, 5);
        }
        for inputs in sub_component_inputs.range_check_9_9_g {
            range_check_9_9_state.add_packed_inputs(&inputs, 6);
        }
        for inputs in sub_component_inputs.range_check_9_9_h {
            range_check_9_9_state.add_packed_inputs(&inputs, 7);
        }
        for inputs in sub_component_inputs.range_check_20 {
            range_check_20_state.add_packed_inputs(&inputs, 0);
        }
        for inputs in sub_component_inputs.range_check_20_b {
            range_check_20_state.add_packed_inputs(&inputs, 1);
        }
        for inputs in sub_component_inputs.range_check_20_c {
            range_check_20_state.add_packed_inputs(&inputs, 2);
        }
        for inputs in sub_component_inputs.range_check_20_d {
            range_check_20_state.add_packed_inputs(&inputs, 3);
        }
        for inputs in sub_component_inputs.range_check_20_e {
            range_check_20_state.add_packed_inputs(&inputs, 4);
        }
        for inputs in sub_component_inputs.range_check_20_f {
            range_check_20_state.add_packed_inputs(&inputs, 5);
        }
        for inputs in sub_component_inputs.range_check_20_g {
            range_check_20_state.add_packed_inputs(&inputs, 6);
        }
        for inputs in sub_component_inputs.range_check_20_h {
            range_check_20_state.add_packed_inputs(&inputs, 7);
        }

        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                n_rows,
                log_size,
                lookup_data,
            },
        )
    }
}

impl AddInputs for ClaimGenerator {
    type PackedInputType = PackedInputType;
    type InputType = InputType;

    fn add_packed_inputs(&self, inputs: &[PackedInputType], _relation_index: usize) {
        self.packed_inputs.lock().unwrap().extend(inputs);
    }
    fn add_input(&self, input: &InputType, _relation_index: usize) {
        self.remainder_inputs.lock().unwrap().push(*input);
    }
}

#[derive(Uninitialized, IterMut, ParIterMut)]
struct SubComponentInputs {
    range_check_9_9: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_b: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_c: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_d: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_e: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_f: [Vec<range_check_9_9::PackedInputType>; 6],
    range_check_9_9_g: [Vec<range_check_9_9::PackedInputType>; 3],
    range_check_9_9_h: [Vec<range_check_9_9::PackedInputType>; 3],
    range_check_20: [Vec<range_check_20::PackedInputType>; 8],
    range_check_20_b: [Vec<range_check_20::PackedInputType>; 8],
    range_check_20_c: [Vec<range_check_20::PackedInputType>; 8],
    range_check_20_d: [Vec<range_check_20::PackedInputType>; 8],
    range_check_20_e: [Vec<range_check_20::PackedInputType>; 6],
    range_check_20_f: [Vec<range_check_20::PackedInputType>; 6],
    range_check_20_g: [Vec<range_check_20::PackedInputType>; 6],
    range_check_20_h: [Vec<range_check_20::PackedInputType>; 6],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_20_state: &range_check_20::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = inputs.len().ilog2();
    let log_size = log_n_packed_rows + LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };

    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1410849886 = PackedM31::broadcast(M31::from(1410849886));
    let M31_1813904000 = PackedM31::broadcast(M31::from(1813904000));
    let M31_1830681619 = PackedM31::broadcast(M31::from(1830681619));
    let M31_1847459238 = PackedM31::broadcast(M31::from(1847459238));
    let M31_1864236857 = PackedM31::broadcast(M31::from(1864236857));
    let M31_1881014476 = PackedM31::broadcast(M31::from(1881014476));
    let M31_1897792095 = PackedM31::broadcast(M31::from(1897792095));
    let M31_1987997202 = PackedM31::broadcast(M31::from(1987997202));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_2065568285 = PackedM31::broadcast(M31::from(2065568285));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_4194304 = PackedM31::broadcast(M31::from(4194304));
    let M31_447122465 = PackedM31::broadcast(M31::from(447122465));
    let M31_463900084 = PackedM31::broadcast(M31::from(463900084));
    let M31_480677703 = PackedM31::broadcast(M31::from(480677703));
    let M31_497455322 = PackedM31::broadcast(M31::from(497455322));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_514232941 = PackedM31::broadcast(M31::from(514232941));
    let M31_517791011 = PackedM31::broadcast(M31::from(517791011));
    let M31_524288 = PackedM31::broadcast(M31::from(524288));
    let M31_531010560 = PackedM31::broadcast(M31::from(531010560));
    let M31_64 = PackedM31::broadcast(M31::from(64));
    let M31_65536 = PackedM31::broadcast(M31::from(65536));
    let M31_682009131 = PackedM31::broadcast(M31::from(682009131));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let M31_8192 = PackedM31::broadcast(M31::from(8192));
    let UInt32_131072 = PackedUInt32::broadcast(UInt32::from(131072));
    let UInt32_262143 = PackedUInt32::broadcast(UInt32::from(262143));
    let UInt32_511 = PackedUInt32::broadcast(UInt32::from(511));
    let UInt32_9 = PackedUInt32::broadcast(UInt32::from(9));
    let enabler_col = Enabler::new(n_rows);

    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, cube_252_input))| {
                let input_limb_0_col0 = cube_252_input.get_m31(0);
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = cube_252_input.get_m31(1);
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = cube_252_input.get_m31(2);
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = cube_252_input.get_m31(3);
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = cube_252_input.get_m31(4);
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = cube_252_input.get_m31(5);
                *row[5] = input_limb_5_col5;
                let input_limb_6_col6 = cube_252_input.get_m31(6);
                *row[6] = input_limb_6_col6;
                let input_limb_7_col7 = cube_252_input.get_m31(7);
                *row[7] = input_limb_7_col7;
                let input_limb_8_col8 = cube_252_input.get_m31(8);
                *row[8] = input_limb_8_col8;
                let input_limb_9_col9 = cube_252_input.get_m31(9);
                *row[9] = input_limb_9_col9;

                // Felt 252 Unpack From 27 Range Check Output.

                let input_as_felt252_tmp_fec87_0 =
                    PackedFelt252::from_packed_felt252width27(cube_252_input);
                let unpacked_limb_0_col10 = input_as_felt252_tmp_fec87_0.get_m31(0);
                *row[10] = unpacked_limb_0_col10;
                let unpacked_limb_1_col11 = input_as_felt252_tmp_fec87_0.get_m31(1);
                *row[11] = unpacked_limb_1_col11;
                let unpacked_limb_3_col12 = input_as_felt252_tmp_fec87_0.get_m31(3);
                *row[12] = unpacked_limb_3_col12;
                let unpacked_limb_4_col13 = input_as_felt252_tmp_fec87_0.get_m31(4);
                *row[13] = unpacked_limb_4_col13;
                let unpacked_limb_6_col14 = input_as_felt252_tmp_fec87_0.get_m31(6);
                *row[14] = unpacked_limb_6_col14;
                let unpacked_limb_7_col15 = input_as_felt252_tmp_fec87_0.get_m31(7);
                *row[15] = unpacked_limb_7_col15;
                let unpacked_limb_9_col16 = input_as_felt252_tmp_fec87_0.get_m31(9);
                *row[16] = unpacked_limb_9_col16;
                let unpacked_limb_10_col17 = input_as_felt252_tmp_fec87_0.get_m31(10);
                *row[17] = unpacked_limb_10_col17;
                let unpacked_limb_12_col18 = input_as_felt252_tmp_fec87_0.get_m31(12);
                *row[18] = unpacked_limb_12_col18;
                let unpacked_limb_13_col19 = input_as_felt252_tmp_fec87_0.get_m31(13);
                *row[19] = unpacked_limb_13_col19;
                let unpacked_limb_15_col20 = input_as_felt252_tmp_fec87_0.get_m31(15);
                *row[20] = unpacked_limb_15_col20;
                let unpacked_limb_16_col21 = input_as_felt252_tmp_fec87_0.get_m31(16);
                *row[21] = unpacked_limb_16_col21;
                let unpacked_limb_18_col22 = input_as_felt252_tmp_fec87_0.get_m31(18);
                *row[22] = unpacked_limb_18_col22;
                let unpacked_limb_19_col23 = input_as_felt252_tmp_fec87_0.get_m31(19);
                *row[23] = unpacked_limb_19_col23;
                let unpacked_limb_21_col24 = input_as_felt252_tmp_fec87_0.get_m31(21);
                *row[24] = unpacked_limb_21_col24;
                let unpacked_limb_22_col25 = input_as_felt252_tmp_fec87_0.get_m31(22);
                *row[25] = unpacked_limb_22_col25;
                let unpacked_limb_24_col26 = input_as_felt252_tmp_fec87_0.get_m31(24);
                *row[26] = unpacked_limb_24_col26;
                let unpacked_limb_25_col27 = input_as_felt252_tmp_fec87_0.get_m31(25);
                *row[27] = unpacked_limb_25_col27;
                let unpacked_tmp_fec87_1 = PackedFelt252::from_limbs([
                    unpacked_limb_0_col10,
                    unpacked_limb_1_col11,
                    ((((input_limb_0_col0) - (unpacked_limb_0_col10))
                        - ((unpacked_limb_1_col11) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_3_col12,
                    unpacked_limb_4_col13,
                    ((((input_limb_1_col1) - (unpacked_limb_3_col12))
                        - ((unpacked_limb_4_col13) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_6_col14,
                    unpacked_limb_7_col15,
                    ((((input_limb_2_col2) - (unpacked_limb_6_col14))
                        - ((unpacked_limb_7_col15) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_9_col16,
                    unpacked_limb_10_col17,
                    ((((input_limb_3_col3) - (unpacked_limb_9_col16))
                        - ((unpacked_limb_10_col17) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_12_col18,
                    unpacked_limb_13_col19,
                    ((((input_limb_4_col4) - (unpacked_limb_12_col18))
                        - ((unpacked_limb_13_col19) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_15_col20,
                    unpacked_limb_16_col21,
                    ((((input_limb_5_col5) - (unpacked_limb_15_col20))
                        - ((unpacked_limb_16_col21) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_18_col22,
                    unpacked_limb_19_col23,
                    ((((input_limb_6_col6) - (unpacked_limb_18_col22))
                        - ((unpacked_limb_19_col23) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_21_col24,
                    unpacked_limb_22_col25,
                    ((((input_limb_7_col7) - (unpacked_limb_21_col24))
                        - ((unpacked_limb_22_col25) * (M31_512)))
                        * (M31_8192)),
                    unpacked_limb_24_col26,
                    unpacked_limb_25_col27,
                    ((((input_limb_8_col8) - (unpacked_limb_24_col26))
                        - ((unpacked_limb_25_col27) * (M31_512)))
                        * (M31_8192)),
                    input_limb_9_col9,
                ]);

                // Range Check Mem Value N 28.

                *sub_component_inputs.range_check_9_9[0] =
                    [unpacked_limb_0_col10, unpacked_limb_1_col11];
                *lookup_data.range_check_9_9_0 =
                    [M31_517791011, unpacked_limb_0_col10, unpacked_limb_1_col11];
                *sub_component_inputs.range_check_9_9_b[0] =
                    [unpacked_tmp_fec87_1.get_m31(2), unpacked_limb_3_col12];
                *lookup_data.range_check_9_9_b_0 = [
                    M31_1897792095,
                    unpacked_tmp_fec87_1.get_m31(2),
                    unpacked_limb_3_col12,
                ];
                *sub_component_inputs.range_check_9_9_c[0] =
                    [unpacked_limb_4_col13, unpacked_tmp_fec87_1.get_m31(5)];
                *lookup_data.range_check_9_9_c_0 = [
                    M31_1881014476,
                    unpacked_limb_4_col13,
                    unpacked_tmp_fec87_1.get_m31(5),
                ];
                *sub_component_inputs.range_check_9_9_d[0] =
                    [unpacked_limb_6_col14, unpacked_limb_7_col15];
                *lookup_data.range_check_9_9_d_0 =
                    [M31_1864236857, unpacked_limb_6_col14, unpacked_limb_7_col15];
                *sub_component_inputs.range_check_9_9_e[0] =
                    [unpacked_tmp_fec87_1.get_m31(8), unpacked_limb_9_col16];
                *lookup_data.range_check_9_9_e_0 = [
                    M31_1847459238,
                    unpacked_tmp_fec87_1.get_m31(8),
                    unpacked_limb_9_col16,
                ];
                *sub_component_inputs.range_check_9_9_f[0] =
                    [unpacked_limb_10_col17, unpacked_tmp_fec87_1.get_m31(11)];
                *lookup_data.range_check_9_9_f_0 = [
                    M31_1830681619,
                    unpacked_limb_10_col17,
                    unpacked_tmp_fec87_1.get_m31(11),
                ];
                *sub_component_inputs.range_check_9_9_g[0] =
                    [unpacked_limb_12_col18, unpacked_limb_13_col19];
                *lookup_data.range_check_9_9_g_0 = [
                    M31_1813904000,
                    unpacked_limb_12_col18,
                    unpacked_limb_13_col19,
                ];
                *sub_component_inputs.range_check_9_9_h[0] =
                    [unpacked_tmp_fec87_1.get_m31(14), unpacked_limb_15_col20];
                *lookup_data.range_check_9_9_h_0 = [
                    M31_2065568285,
                    unpacked_tmp_fec87_1.get_m31(14),
                    unpacked_limb_15_col20,
                ];
                *sub_component_inputs.range_check_9_9[1] =
                    [unpacked_limb_16_col21, unpacked_tmp_fec87_1.get_m31(17)];
                *lookup_data.range_check_9_9_1 = [
                    M31_517791011,
                    unpacked_limb_16_col21,
                    unpacked_tmp_fec87_1.get_m31(17),
                ];
                *sub_component_inputs.range_check_9_9_b[1] =
                    [unpacked_limb_18_col22, unpacked_limb_19_col23];
                *lookup_data.range_check_9_9_b_1 = [
                    M31_1897792095,
                    unpacked_limb_18_col22,
                    unpacked_limb_19_col23,
                ];
                *sub_component_inputs.range_check_9_9_c[1] =
                    [unpacked_tmp_fec87_1.get_m31(20), unpacked_limb_21_col24];
                *lookup_data.range_check_9_9_c_1 = [
                    M31_1881014476,
                    unpacked_tmp_fec87_1.get_m31(20),
                    unpacked_limb_21_col24,
                ];
                *sub_component_inputs.range_check_9_9_d[1] =
                    [unpacked_limb_22_col25, unpacked_tmp_fec87_1.get_m31(23)];
                *lookup_data.range_check_9_9_d_1 = [
                    M31_1864236857,
                    unpacked_limb_22_col25,
                    unpacked_tmp_fec87_1.get_m31(23),
                ];
                *sub_component_inputs.range_check_9_9_e[1] =
                    [unpacked_limb_24_col26, unpacked_limb_25_col27];
                *lookup_data.range_check_9_9_e_1 = [
                    M31_1847459238,
                    unpacked_limb_24_col26,
                    unpacked_limb_25_col27,
                ];
                *sub_component_inputs.range_check_9_9_f[1] =
                    [unpacked_tmp_fec87_1.get_m31(26), input_limb_9_col9];
                *lookup_data.range_check_9_9_f_1 = [
                    M31_1830681619,
                    unpacked_tmp_fec87_1.get_m31(26),
                    input_limb_9_col9,
                ];

                let felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2 =
                    unpacked_tmp_fec87_1;

                // Mul 252.

                let mul_res_tmp_fec87_3 =
                    ((felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2)
                        * (felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2));
                let mul_res_limb_0_col28 = mul_res_tmp_fec87_3.get_m31(0);
                *row[28] = mul_res_limb_0_col28;
                let mul_res_limb_1_col29 = mul_res_tmp_fec87_3.get_m31(1);
                *row[29] = mul_res_limb_1_col29;
                let mul_res_limb_2_col30 = mul_res_tmp_fec87_3.get_m31(2);
                *row[30] = mul_res_limb_2_col30;
                let mul_res_limb_3_col31 = mul_res_tmp_fec87_3.get_m31(3);
                *row[31] = mul_res_limb_3_col31;
                let mul_res_limb_4_col32 = mul_res_tmp_fec87_3.get_m31(4);
                *row[32] = mul_res_limb_4_col32;
                let mul_res_limb_5_col33 = mul_res_tmp_fec87_3.get_m31(5);
                *row[33] = mul_res_limb_5_col33;
                let mul_res_limb_6_col34 = mul_res_tmp_fec87_3.get_m31(6);
                *row[34] = mul_res_limb_6_col34;
                let mul_res_limb_7_col35 = mul_res_tmp_fec87_3.get_m31(7);
                *row[35] = mul_res_limb_7_col35;
                let mul_res_limb_8_col36 = mul_res_tmp_fec87_3.get_m31(8);
                *row[36] = mul_res_limb_8_col36;
                let mul_res_limb_9_col37 = mul_res_tmp_fec87_3.get_m31(9);
                *row[37] = mul_res_limb_9_col37;
                let mul_res_limb_10_col38 = mul_res_tmp_fec87_3.get_m31(10);
                *row[38] = mul_res_limb_10_col38;
                let mul_res_limb_11_col39 = mul_res_tmp_fec87_3.get_m31(11);
                *row[39] = mul_res_limb_11_col39;
                let mul_res_limb_12_col40 = mul_res_tmp_fec87_3.get_m31(12);
                *row[40] = mul_res_limb_12_col40;
                let mul_res_limb_13_col41 = mul_res_tmp_fec87_3.get_m31(13);
                *row[41] = mul_res_limb_13_col41;
                let mul_res_limb_14_col42 = mul_res_tmp_fec87_3.get_m31(14);
                *row[42] = mul_res_limb_14_col42;
                let mul_res_limb_15_col43 = mul_res_tmp_fec87_3.get_m31(15);
                *row[43] = mul_res_limb_15_col43;
                let mul_res_limb_16_col44 = mul_res_tmp_fec87_3.get_m31(16);
                *row[44] = mul_res_limb_16_col44;
                let mul_res_limb_17_col45 = mul_res_tmp_fec87_3.get_m31(17);
                *row[45] = mul_res_limb_17_col45;
                let mul_res_limb_18_col46 = mul_res_tmp_fec87_3.get_m31(18);
                *row[46] = mul_res_limb_18_col46;
                let mul_res_limb_19_col47 = mul_res_tmp_fec87_3.get_m31(19);
                *row[47] = mul_res_limb_19_col47;
                let mul_res_limb_20_col48 = mul_res_tmp_fec87_3.get_m31(20);
                *row[48] = mul_res_limb_20_col48;
                let mul_res_limb_21_col49 = mul_res_tmp_fec87_3.get_m31(21);
                *row[49] = mul_res_limb_21_col49;
                let mul_res_limb_22_col50 = mul_res_tmp_fec87_3.get_m31(22);
                *row[50] = mul_res_limb_22_col50;
                let mul_res_limb_23_col51 = mul_res_tmp_fec87_3.get_m31(23);
                *row[51] = mul_res_limb_23_col51;
                let mul_res_limb_24_col52 = mul_res_tmp_fec87_3.get_m31(24);
                *row[52] = mul_res_limb_24_col52;
                let mul_res_limb_25_col53 = mul_res_tmp_fec87_3.get_m31(25);
                *row[53] = mul_res_limb_25_col53;
                let mul_res_limb_26_col54 = mul_res_tmp_fec87_3.get_m31(26);
                *row[54] = mul_res_limb_26_col54;
                let mul_res_limb_27_col55 = mul_res_tmp_fec87_3.get_m31(27);
                *row[55] = mul_res_limb_27_col55;

                // Range Check Mem Value N 28.

                *sub_component_inputs.range_check_9_9[2] =
                    [mul_res_limb_0_col28, mul_res_limb_1_col29];
                *lookup_data.range_check_9_9_2 =
                    [M31_517791011, mul_res_limb_0_col28, mul_res_limb_1_col29];
                *sub_component_inputs.range_check_9_9_b[2] =
                    [mul_res_limb_2_col30, mul_res_limb_3_col31];
                *lookup_data.range_check_9_9_b_2 =
                    [M31_1897792095, mul_res_limb_2_col30, mul_res_limb_3_col31];
                *sub_component_inputs.range_check_9_9_c[2] =
                    [mul_res_limb_4_col32, mul_res_limb_5_col33];
                *lookup_data.range_check_9_9_c_2 =
                    [M31_1881014476, mul_res_limb_4_col32, mul_res_limb_5_col33];
                *sub_component_inputs.range_check_9_9_d[2] =
                    [mul_res_limb_6_col34, mul_res_limb_7_col35];
                *lookup_data.range_check_9_9_d_2 =
                    [M31_1864236857, mul_res_limb_6_col34, mul_res_limb_7_col35];
                *sub_component_inputs.range_check_9_9_e[2] =
                    [mul_res_limb_8_col36, mul_res_limb_9_col37];
                *lookup_data.range_check_9_9_e_2 =
                    [M31_1847459238, mul_res_limb_8_col36, mul_res_limb_9_col37];
                *sub_component_inputs.range_check_9_9_f[2] =
                    [mul_res_limb_10_col38, mul_res_limb_11_col39];
                *lookup_data.range_check_9_9_f_2 =
                    [M31_1830681619, mul_res_limb_10_col38, mul_res_limb_11_col39];
                *sub_component_inputs.range_check_9_9_g[1] =
                    [mul_res_limb_12_col40, mul_res_limb_13_col41];
                *lookup_data.range_check_9_9_g_1 =
                    [M31_1813904000, mul_res_limb_12_col40, mul_res_limb_13_col41];
                *sub_component_inputs.range_check_9_9_h[1] =
                    [mul_res_limb_14_col42, mul_res_limb_15_col43];
                *lookup_data.range_check_9_9_h_1 =
                    [M31_2065568285, mul_res_limb_14_col42, mul_res_limb_15_col43];
                *sub_component_inputs.range_check_9_9[3] =
                    [mul_res_limb_16_col44, mul_res_limb_17_col45];
                *lookup_data.range_check_9_9_3 =
                    [M31_517791011, mul_res_limb_16_col44, mul_res_limb_17_col45];
                *sub_component_inputs.range_check_9_9_b[3] =
                    [mul_res_limb_18_col46, mul_res_limb_19_col47];
                *lookup_data.range_check_9_9_b_3 =
                    [M31_1897792095, mul_res_limb_18_col46, mul_res_limb_19_col47];
                *sub_component_inputs.range_check_9_9_c[3] =
                    [mul_res_limb_20_col48, mul_res_limb_21_col49];
                *lookup_data.range_check_9_9_c_3 =
                    [M31_1881014476, mul_res_limb_20_col48, mul_res_limb_21_col49];
                *sub_component_inputs.range_check_9_9_d[3] =
                    [mul_res_limb_22_col50, mul_res_limb_23_col51];
                *lookup_data.range_check_9_9_d_3 =
                    [M31_1864236857, mul_res_limb_22_col50, mul_res_limb_23_col51];
                *sub_component_inputs.range_check_9_9_e[3] =
                    [mul_res_limb_24_col52, mul_res_limb_25_col53];
                *lookup_data.range_check_9_9_e_3 =
                    [M31_1847459238, mul_res_limb_24_col52, mul_res_limb_25_col53];
                *sub_component_inputs.range_check_9_9_f[3] =
                    [mul_res_limb_26_col54, mul_res_limb_27_col55];
                *lookup_data.range_check_9_9_f_3 =
                    [M31_1830681619, mul_res_limb_26_col54, mul_res_limb_27_col55];

                // Verify Mul 252.

                // Double Karatsuba 1454 B.

                // Single Karatsuba N 7.

                let z0_tmp_fec87_4 = [
                    ((unpacked_limb_0_col10) * (unpacked_limb_0_col10)),
                    (((unpacked_limb_0_col10) * (unpacked_limb_1_col11))
                        + ((unpacked_limb_1_col11) * (unpacked_limb_0_col10))),
                    ((((unpacked_limb_0_col10) * (unpacked_tmp_fec87_1.get_m31(2)))
                        + ((unpacked_limb_1_col11) * (unpacked_limb_1_col11)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (unpacked_limb_0_col10))),
                    (((((unpacked_limb_0_col10) * (unpacked_limb_3_col12))
                        + ((unpacked_limb_1_col11) * (unpacked_tmp_fec87_1.get_m31(2))))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (unpacked_limb_1_col11)))
                        + ((unpacked_limb_3_col12) * (unpacked_limb_0_col10))),
                    ((((((unpacked_limb_0_col10) * (unpacked_limb_4_col13))
                        + ((unpacked_limb_1_col11) * (unpacked_limb_3_col12)))
                        + ((unpacked_tmp_fec87_1.get_m31(2))
                            * (unpacked_tmp_fec87_1.get_m31(2))))
                        + ((unpacked_limb_3_col12) * (unpacked_limb_1_col11)))
                        + ((unpacked_limb_4_col13) * (unpacked_limb_0_col10))),
                    (((((((unpacked_limb_0_col10) * (unpacked_tmp_fec87_1.get_m31(5)))
                        + ((unpacked_limb_1_col11) * (unpacked_limb_4_col13)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (unpacked_limb_3_col12)))
                        + ((unpacked_limb_3_col12) * (unpacked_tmp_fec87_1.get_m31(2))))
                        + ((unpacked_limb_4_col13) * (unpacked_limb_1_col11)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_limb_0_col10))),
                    ((((((((unpacked_limb_0_col10) * (unpacked_limb_6_col14))
                        + ((unpacked_limb_1_col11) * (unpacked_tmp_fec87_1.get_m31(5))))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (unpacked_limb_4_col13)))
                        + ((unpacked_limb_3_col12) * (unpacked_limb_3_col12)))
                        + ((unpacked_limb_4_col13) * (unpacked_tmp_fec87_1.get_m31(2))))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_limb_1_col11)))
                        + ((unpacked_limb_6_col14) * (unpacked_limb_0_col10))),
                    (((((((unpacked_limb_1_col11) * (unpacked_limb_6_col14))
                        + ((unpacked_tmp_fec87_1.get_m31(2))
                            * (unpacked_tmp_fec87_1.get_m31(5))))
                        + ((unpacked_limb_3_col12) * (unpacked_limb_4_col13)))
                        + ((unpacked_limb_4_col13) * (unpacked_limb_3_col12)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_tmp_fec87_1.get_m31(2))))
                        + ((unpacked_limb_6_col14) * (unpacked_limb_1_col11))),
                    ((((((unpacked_tmp_fec87_1.get_m31(2)) * (unpacked_limb_6_col14))
                        + ((unpacked_limb_3_col12) * (unpacked_tmp_fec87_1.get_m31(5))))
                        + ((unpacked_limb_4_col13) * (unpacked_limb_4_col13)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_limb_3_col12)))
                        + ((unpacked_limb_6_col14) * (unpacked_tmp_fec87_1.get_m31(2)))),
                    (((((unpacked_limb_3_col12) * (unpacked_limb_6_col14))
                        + ((unpacked_limb_4_col13) * (unpacked_tmp_fec87_1.get_m31(5))))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_limb_4_col13)))
                        + ((unpacked_limb_6_col14) * (unpacked_limb_3_col12))),
                    ((((unpacked_limb_4_col13) * (unpacked_limb_6_col14))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_tmp_fec87_1.get_m31(5))))
                        + ((unpacked_limb_6_col14) * (unpacked_limb_4_col13))),
                    (((unpacked_tmp_fec87_1.get_m31(5)) * (unpacked_limb_6_col14))
                        + ((unpacked_limb_6_col14) * (unpacked_tmp_fec87_1.get_m31(5)))),
                    ((unpacked_limb_6_col14) * (unpacked_limb_6_col14)),
                ];
                let z2_tmp_fec87_5 = [
                    ((unpacked_limb_7_col15) * (unpacked_limb_7_col15)),
                    (((unpacked_limb_7_col15) * (unpacked_tmp_fec87_1.get_m31(8)))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_limb_7_col15))),
                    ((((unpacked_limb_7_col15) * (unpacked_limb_9_col16))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_tmp_fec87_1.get_m31(8))))
                        + ((unpacked_limb_9_col16) * (unpacked_limb_7_col15))),
                    (((((unpacked_limb_7_col15) * (unpacked_limb_10_col17))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_limb_9_col16)))
                        + ((unpacked_limb_9_col16) * (unpacked_tmp_fec87_1.get_m31(8))))
                        + ((unpacked_limb_10_col17) * (unpacked_limb_7_col15))),
                    ((((((unpacked_limb_7_col15) * (unpacked_tmp_fec87_1.get_m31(11)))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_limb_10_col17)))
                        + ((unpacked_limb_9_col16) * (unpacked_limb_9_col16)))
                        + ((unpacked_limb_10_col17) * (unpacked_tmp_fec87_1.get_m31(8))))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (unpacked_limb_7_col15))),
                    (((((((unpacked_limb_7_col15) * (unpacked_limb_12_col18))
                        + ((unpacked_tmp_fec87_1.get_m31(8))
                            * (unpacked_tmp_fec87_1.get_m31(11))))
                        + ((unpacked_limb_9_col16) * (unpacked_limb_10_col17)))
                        + ((unpacked_limb_10_col17) * (unpacked_limb_9_col16)))
                        + ((unpacked_tmp_fec87_1.get_m31(11))
                            * (unpacked_tmp_fec87_1.get_m31(8))))
                        + ((unpacked_limb_12_col18) * (unpacked_limb_7_col15))),
                    ((((((((unpacked_limb_7_col15) * (unpacked_limb_13_col19))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_limb_12_col18)))
                        + ((unpacked_limb_9_col16) * (unpacked_tmp_fec87_1.get_m31(11))))
                        + ((unpacked_limb_10_col17) * (unpacked_limb_10_col17)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (unpacked_limb_9_col16)))
                        + ((unpacked_limb_12_col18) * (unpacked_tmp_fec87_1.get_m31(8))))
                        + ((unpacked_limb_13_col19) * (unpacked_limb_7_col15))),
                    (((((((unpacked_tmp_fec87_1.get_m31(8)) * (unpacked_limb_13_col19))
                        + ((unpacked_limb_9_col16) * (unpacked_limb_12_col18)))
                        + ((unpacked_limb_10_col17) * (unpacked_tmp_fec87_1.get_m31(11))))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (unpacked_limb_10_col17)))
                        + ((unpacked_limb_12_col18) * (unpacked_limb_9_col16)))
                        + ((unpacked_limb_13_col19) * (unpacked_tmp_fec87_1.get_m31(8)))),
                    ((((((unpacked_limb_9_col16) * (unpacked_limb_13_col19))
                        + ((unpacked_limb_10_col17) * (unpacked_limb_12_col18)))
                        + ((unpacked_tmp_fec87_1.get_m31(11))
                            * (unpacked_tmp_fec87_1.get_m31(11))))
                        + ((unpacked_limb_12_col18) * (unpacked_limb_10_col17)))
                        + ((unpacked_limb_13_col19) * (unpacked_limb_9_col16))),
                    (((((unpacked_limb_10_col17) * (unpacked_limb_13_col19))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (unpacked_limb_12_col18)))
                        + ((unpacked_limb_12_col18) * (unpacked_tmp_fec87_1.get_m31(11))))
                        + ((unpacked_limb_13_col19) * (unpacked_limb_10_col17))),
                    ((((unpacked_tmp_fec87_1.get_m31(11)) * (unpacked_limb_13_col19))
                        + ((unpacked_limb_12_col18) * (unpacked_limb_12_col18)))
                        + ((unpacked_limb_13_col19) * (unpacked_tmp_fec87_1.get_m31(11)))),
                    (((unpacked_limb_12_col18) * (unpacked_limb_13_col19))
                        + ((unpacked_limb_13_col19) * (unpacked_limb_12_col18))),
                    ((unpacked_limb_13_col19) * (unpacked_limb_13_col19)),
                ];
                let x_sum_tmp_fec87_6 = [
                    ((unpacked_limb_0_col10) + (unpacked_limb_7_col15)),
                    ((unpacked_limb_1_col11) + (unpacked_tmp_fec87_1.get_m31(8))),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_9_col16)),
                    ((unpacked_limb_3_col12) + (unpacked_limb_10_col17)),
                    ((unpacked_limb_4_col13) + (unpacked_tmp_fec87_1.get_m31(11))),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_12_col18)),
                    ((unpacked_limb_6_col14) + (unpacked_limb_13_col19)),
                ];
                let y_sum_tmp_fec87_7 = [
                    ((unpacked_limb_0_col10) + (unpacked_limb_7_col15)),
                    ((unpacked_limb_1_col11) + (unpacked_tmp_fec87_1.get_m31(8))),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_9_col16)),
                    ((unpacked_limb_3_col12) + (unpacked_limb_10_col17)),
                    ((unpacked_limb_4_col13) + (unpacked_tmp_fec87_1.get_m31(11))),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_12_col18)),
                    ((unpacked_limb_6_col14) + (unpacked_limb_13_col19)),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_8 = [
                    z0_tmp_fec87_4[0],
                    z0_tmp_fec87_4[1],
                    z0_tmp_fec87_4[2],
                    z0_tmp_fec87_4[3],
                    z0_tmp_fec87_4[4],
                    z0_tmp_fec87_4[5],
                    z0_tmp_fec87_4[6],
                    ((z0_tmp_fec87_4[7])
                        + ((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[0]))
                            - (z0_tmp_fec87_4[0]))
                            - (z2_tmp_fec87_5[0]))),
                    ((z0_tmp_fec87_4[8])
                        + (((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[1]))
                            + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[0])))
                            - (z0_tmp_fec87_4[1]))
                            - (z2_tmp_fec87_5[1]))),
                    ((z0_tmp_fec87_4[9])
                        + ((((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[2]))
                            + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[1])))
                            + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[0])))
                            - (z0_tmp_fec87_4[2]))
                            - (z2_tmp_fec87_5[2]))),
                    ((z0_tmp_fec87_4[10])
                        + (((((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[3]))
                            + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[2])))
                            + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[1])))
                            + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[0])))
                            - (z0_tmp_fec87_4[3]))
                            - (z2_tmp_fec87_5[3]))),
                    ((z0_tmp_fec87_4[11])
                        + ((((((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[4]))
                            + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[3])))
                            + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[2])))
                            + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[1])))
                            + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[0])))
                            - (z0_tmp_fec87_4[4]))
                            - (z2_tmp_fec87_5[4]))),
                    ((z0_tmp_fec87_4[12])
                        + (((((((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[5]))
                            + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[4])))
                            + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[3])))
                            + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[2])))
                            + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[1])))
                            + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[0])))
                            - (z0_tmp_fec87_4[5]))
                            - (z2_tmp_fec87_5[5]))),
                    ((((((((((x_sum_tmp_fec87_6[0]) * (y_sum_tmp_fec87_7[6]))
                        + ((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[5])))
                        + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[4])))
                        + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[3])))
                        + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[2])))
                        + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[1])))
                        + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[0])))
                        - (z0_tmp_fec87_4[6]))
                        - (z2_tmp_fec87_5[6])),
                    ((z2_tmp_fec87_5[0])
                        + (((((((((x_sum_tmp_fec87_6[1]) * (y_sum_tmp_fec87_7[6]))
                            + ((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[5])))
                            + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[4])))
                            + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[3])))
                            + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[2])))
                            + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[1])))
                            - (z0_tmp_fec87_4[7]))
                            - (z2_tmp_fec87_5[7]))),
                    ((z2_tmp_fec87_5[1])
                        + ((((((((x_sum_tmp_fec87_6[2]) * (y_sum_tmp_fec87_7[6]))
                            + ((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[5])))
                            + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[4])))
                            + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[3])))
                            + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[2])))
                            - (z0_tmp_fec87_4[8]))
                            - (z2_tmp_fec87_5[8]))),
                    ((z2_tmp_fec87_5[2])
                        + (((((((x_sum_tmp_fec87_6[3]) * (y_sum_tmp_fec87_7[6]))
                            + ((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[5])))
                            + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[4])))
                            + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[3])))
                            - (z0_tmp_fec87_4[9]))
                            - (z2_tmp_fec87_5[9]))),
                    ((z2_tmp_fec87_5[3])
                        + ((((((x_sum_tmp_fec87_6[4]) * (y_sum_tmp_fec87_7[6]))
                            + ((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[5])))
                            + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[4])))
                            - (z0_tmp_fec87_4[10]))
                            - (z2_tmp_fec87_5[10]))),
                    ((z2_tmp_fec87_5[4])
                        + (((((x_sum_tmp_fec87_6[5]) * (y_sum_tmp_fec87_7[6]))
                            + ((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[5])))
                            - (z0_tmp_fec87_4[11]))
                            - (z2_tmp_fec87_5[11]))),
                    ((z2_tmp_fec87_5[5])
                        + ((((x_sum_tmp_fec87_6[6]) * (y_sum_tmp_fec87_7[6]))
                            - (z0_tmp_fec87_4[12]))
                            - (z2_tmp_fec87_5[12]))),
                    z2_tmp_fec87_5[6],
                    z2_tmp_fec87_5[7],
                    z2_tmp_fec87_5[8],
                    z2_tmp_fec87_5[9],
                    z2_tmp_fec87_5[10],
                    z2_tmp_fec87_5[11],
                    z2_tmp_fec87_5[12],
                ];

                // Single Karatsuba N 7.

                let z0_tmp_fec87_9 = [
                    ((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_tmp_fec87_1.get_m31(14))),
                    (((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_limb_15_col20))
                        + ((unpacked_limb_15_col20) * (unpacked_tmp_fec87_1.get_m31(14)))),
                    ((((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_limb_16_col21))
                        + ((unpacked_limb_15_col20) * (unpacked_limb_15_col20)))
                        + ((unpacked_limb_16_col21) * (unpacked_tmp_fec87_1.get_m31(14)))),
                    (((((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_tmp_fec87_1.get_m31(17)))
                        + ((unpacked_limb_15_col20) * (unpacked_limb_16_col21)))
                        + ((unpacked_limb_16_col21) * (unpacked_limb_15_col20)))
                        + ((unpacked_tmp_fec87_1.get_m31(17))
                            * (unpacked_tmp_fec87_1.get_m31(14)))),
                    ((((((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_limb_18_col22))
                        + ((unpacked_limb_15_col20) * (unpacked_tmp_fec87_1.get_m31(17))))
                        + ((unpacked_limb_16_col21) * (unpacked_limb_16_col21)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (unpacked_limb_15_col20)))
                        + ((unpacked_limb_18_col22) * (unpacked_tmp_fec87_1.get_m31(14)))),
                    (((((((unpacked_tmp_fec87_1.get_m31(14)) * (unpacked_limb_19_col23))
                        + ((unpacked_limb_15_col20) * (unpacked_limb_18_col22)))
                        + ((unpacked_limb_16_col21) * (unpacked_tmp_fec87_1.get_m31(17))))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (unpacked_limb_16_col21)))
                        + ((unpacked_limb_18_col22) * (unpacked_limb_15_col20)))
                        + ((unpacked_limb_19_col23) * (unpacked_tmp_fec87_1.get_m31(14)))),
                    ((((((((unpacked_tmp_fec87_1.get_m31(14))
                        * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_limb_15_col20) * (unpacked_limb_19_col23)))
                        + ((unpacked_limb_16_col21) * (unpacked_limb_18_col22)))
                        + ((unpacked_tmp_fec87_1.get_m31(17))
                            * (unpacked_tmp_fec87_1.get_m31(17))))
                        + ((unpacked_limb_18_col22) * (unpacked_limb_16_col21)))
                        + ((unpacked_limb_19_col23) * (unpacked_limb_15_col20)))
                        + ((unpacked_tmp_fec87_1.get_m31(20))
                            * (unpacked_tmp_fec87_1.get_m31(14)))),
                    (((((((unpacked_limb_15_col20) * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_limb_16_col21) * (unpacked_limb_19_col23)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (unpacked_limb_18_col22)))
                        + ((unpacked_limb_18_col22) * (unpacked_tmp_fec87_1.get_m31(17))))
                        + ((unpacked_limb_19_col23) * (unpacked_limb_16_col21)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (unpacked_limb_15_col20))),
                    ((((((unpacked_limb_16_col21) * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (unpacked_limb_19_col23)))
                        + ((unpacked_limb_18_col22) * (unpacked_limb_18_col22)))
                        + ((unpacked_limb_19_col23) * (unpacked_tmp_fec87_1.get_m31(17))))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (unpacked_limb_16_col21))),
                    (((((unpacked_tmp_fec87_1.get_m31(17)) * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_limb_18_col22) * (unpacked_limb_19_col23)))
                        + ((unpacked_limb_19_col23) * (unpacked_limb_18_col22)))
                        + ((unpacked_tmp_fec87_1.get_m31(20))
                            * (unpacked_tmp_fec87_1.get_m31(17)))),
                    ((((unpacked_limb_18_col22) * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_limb_19_col23) * (unpacked_limb_19_col23)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (unpacked_limb_18_col22))),
                    (((unpacked_limb_19_col23) * (unpacked_tmp_fec87_1.get_m31(20)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (unpacked_limb_19_col23))),
                    ((unpacked_tmp_fec87_1.get_m31(20)) * (unpacked_tmp_fec87_1.get_m31(20))),
                ];
                let z2_tmp_fec87_10 = [
                    ((unpacked_limb_21_col24) * (unpacked_limb_21_col24)),
                    (((unpacked_limb_21_col24) * (unpacked_limb_22_col25))
                        + ((unpacked_limb_22_col25) * (unpacked_limb_21_col24))),
                    ((((unpacked_limb_21_col24) * (unpacked_tmp_fec87_1.get_m31(23)))
                        + ((unpacked_limb_22_col25) * (unpacked_limb_22_col25)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (unpacked_limb_21_col24))),
                    (((((unpacked_limb_21_col24) * (unpacked_limb_24_col26))
                        + ((unpacked_limb_22_col25) * (unpacked_tmp_fec87_1.get_m31(23))))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (unpacked_limb_22_col25)))
                        + ((unpacked_limb_24_col26) * (unpacked_limb_21_col24))),
                    ((((((unpacked_limb_21_col24) * (unpacked_limb_25_col27))
                        + ((unpacked_limb_22_col25) * (unpacked_limb_24_col26)))
                        + ((unpacked_tmp_fec87_1.get_m31(23))
                            * (unpacked_tmp_fec87_1.get_m31(23))))
                        + ((unpacked_limb_24_col26) * (unpacked_limb_22_col25)))
                        + ((unpacked_limb_25_col27) * (unpacked_limb_21_col24))),
                    (((((((unpacked_limb_21_col24) * (unpacked_tmp_fec87_1.get_m31(26)))
                        + ((unpacked_limb_22_col25) * (unpacked_limb_25_col27)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (unpacked_limb_24_col26)))
                        + ((unpacked_limb_24_col26) * (unpacked_tmp_fec87_1.get_m31(23))))
                        + ((unpacked_limb_25_col27) * (unpacked_limb_22_col25)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (unpacked_limb_21_col24))),
                    ((((((((unpacked_limb_21_col24) * (input_limb_9_col9))
                        + ((unpacked_limb_22_col25) * (unpacked_tmp_fec87_1.get_m31(26))))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (unpacked_limb_25_col27)))
                        + ((unpacked_limb_24_col26) * (unpacked_limb_24_col26)))
                        + ((unpacked_limb_25_col27) * (unpacked_tmp_fec87_1.get_m31(23))))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (unpacked_limb_22_col25)))
                        + ((input_limb_9_col9) * (unpacked_limb_21_col24))),
                    (((((((unpacked_limb_22_col25) * (input_limb_9_col9))
                        + ((unpacked_tmp_fec87_1.get_m31(23))
                            * (unpacked_tmp_fec87_1.get_m31(26))))
                        + ((unpacked_limb_24_col26) * (unpacked_limb_25_col27)))
                        + ((unpacked_limb_25_col27) * (unpacked_limb_24_col26)))
                        + ((unpacked_tmp_fec87_1.get_m31(26))
                            * (unpacked_tmp_fec87_1.get_m31(23))))
                        + ((input_limb_9_col9) * (unpacked_limb_22_col25))),
                    ((((((unpacked_tmp_fec87_1.get_m31(23)) * (input_limb_9_col9))
                        + ((unpacked_limb_24_col26) * (unpacked_tmp_fec87_1.get_m31(26))))
                        + ((unpacked_limb_25_col27) * (unpacked_limb_25_col27)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (unpacked_limb_24_col26)))
                        + ((input_limb_9_col9) * (unpacked_tmp_fec87_1.get_m31(23)))),
                    (((((unpacked_limb_24_col26) * (input_limb_9_col9))
                        + ((unpacked_limb_25_col27) * (unpacked_tmp_fec87_1.get_m31(26))))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (unpacked_limb_25_col27)))
                        + ((input_limb_9_col9) * (unpacked_limb_24_col26))),
                    ((((unpacked_limb_25_col27) * (input_limb_9_col9))
                        + ((unpacked_tmp_fec87_1.get_m31(26))
                            * (unpacked_tmp_fec87_1.get_m31(26))))
                        + ((input_limb_9_col9) * (unpacked_limb_25_col27))),
                    (((unpacked_tmp_fec87_1.get_m31(26)) * (input_limb_9_col9))
                        + ((input_limb_9_col9) * (unpacked_tmp_fec87_1.get_m31(26)))),
                    ((input_limb_9_col9) * (input_limb_9_col9)),
                ];
                let x_sum_tmp_fec87_11 = [
                    ((unpacked_tmp_fec87_1.get_m31(14)) + (unpacked_limb_21_col24)),
                    ((unpacked_limb_15_col20) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_16_col21) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_tmp_fec87_1.get_m31(17)) + (unpacked_limb_24_col26)),
                    ((unpacked_limb_18_col22) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_19_col23) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_tmp_fec87_1.get_m31(20)) + (input_limb_9_col9)),
                ];
                let y_sum_tmp_fec87_12 = [
                    ((unpacked_tmp_fec87_1.get_m31(14)) + (unpacked_limb_21_col24)),
                    ((unpacked_limb_15_col20) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_16_col21) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_tmp_fec87_1.get_m31(17)) + (unpacked_limb_24_col26)),
                    ((unpacked_limb_18_col22) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_19_col23) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_tmp_fec87_1.get_m31(20)) + (input_limb_9_col9)),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_13 = [
                    z0_tmp_fec87_9[0],
                    z0_tmp_fec87_9[1],
                    z0_tmp_fec87_9[2],
                    z0_tmp_fec87_9[3],
                    z0_tmp_fec87_9[4],
                    z0_tmp_fec87_9[5],
                    z0_tmp_fec87_9[6],
                    ((z0_tmp_fec87_9[7])
                        + ((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[0]))
                            - (z0_tmp_fec87_9[0]))
                            - (z2_tmp_fec87_10[0]))),
                    ((z0_tmp_fec87_9[8])
                        + (((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[1]))
                            + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[0])))
                            - (z0_tmp_fec87_9[1]))
                            - (z2_tmp_fec87_10[1]))),
                    ((z0_tmp_fec87_9[9])
                        + ((((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[2]))
                            + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[1])))
                            + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[0])))
                            - (z0_tmp_fec87_9[2]))
                            - (z2_tmp_fec87_10[2]))),
                    ((z0_tmp_fec87_9[10])
                        + (((((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[3]))
                            + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[2])))
                            + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[1])))
                            + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[0])))
                            - (z0_tmp_fec87_9[3]))
                            - (z2_tmp_fec87_10[3]))),
                    ((z0_tmp_fec87_9[11])
                        + ((((((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[4]))
                            + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[3])))
                            + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[2])))
                            + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[1])))
                            + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[0])))
                            - (z0_tmp_fec87_9[4]))
                            - (z2_tmp_fec87_10[4]))),
                    ((z0_tmp_fec87_9[12])
                        + (((((((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[5]))
                            + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[4])))
                            + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[3])))
                            + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[2])))
                            + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[1])))
                            + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[0])))
                            - (z0_tmp_fec87_9[5]))
                            - (z2_tmp_fec87_10[5]))),
                    ((((((((((x_sum_tmp_fec87_11[0]) * (y_sum_tmp_fec87_12[6]))
                        + ((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[5])))
                        + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[4])))
                        + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[3])))
                        + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[2])))
                        + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[1])))
                        + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[0])))
                        - (z0_tmp_fec87_9[6]))
                        - (z2_tmp_fec87_10[6])),
                    ((z2_tmp_fec87_10[0])
                        + (((((((((x_sum_tmp_fec87_11[1]) * (y_sum_tmp_fec87_12[6]))
                            + ((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[5])))
                            + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[4])))
                            + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[3])))
                            + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[2])))
                            + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[1])))
                            - (z0_tmp_fec87_9[7]))
                            - (z2_tmp_fec87_10[7]))),
                    ((z2_tmp_fec87_10[1])
                        + ((((((((x_sum_tmp_fec87_11[2]) * (y_sum_tmp_fec87_12[6]))
                            + ((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[5])))
                            + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[4])))
                            + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[3])))
                            + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[2])))
                            - (z0_tmp_fec87_9[8]))
                            - (z2_tmp_fec87_10[8]))),
                    ((z2_tmp_fec87_10[2])
                        + (((((((x_sum_tmp_fec87_11[3]) * (y_sum_tmp_fec87_12[6]))
                            + ((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[5])))
                            + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[4])))
                            + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[3])))
                            - (z0_tmp_fec87_9[9]))
                            - (z2_tmp_fec87_10[9]))),
                    ((z2_tmp_fec87_10[3])
                        + ((((((x_sum_tmp_fec87_11[4]) * (y_sum_tmp_fec87_12[6]))
                            + ((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[5])))
                            + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[4])))
                            - (z0_tmp_fec87_9[10]))
                            - (z2_tmp_fec87_10[10]))),
                    ((z2_tmp_fec87_10[4])
                        + (((((x_sum_tmp_fec87_11[5]) * (y_sum_tmp_fec87_12[6]))
                            + ((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[5])))
                            - (z0_tmp_fec87_9[11]))
                            - (z2_tmp_fec87_10[11]))),
                    ((z2_tmp_fec87_10[5])
                        + ((((x_sum_tmp_fec87_11[6]) * (y_sum_tmp_fec87_12[6]))
                            - (z0_tmp_fec87_9[12]))
                            - (z2_tmp_fec87_10[12]))),
                    z2_tmp_fec87_10[6],
                    z2_tmp_fec87_10[7],
                    z2_tmp_fec87_10[8],
                    z2_tmp_fec87_10[9],
                    z2_tmp_fec87_10[10],
                    z2_tmp_fec87_10[11],
                    z2_tmp_fec87_10[12],
                ];

                let x_sum_tmp_fec87_14 = [
                    ((unpacked_limb_0_col10) + (unpacked_tmp_fec87_1.get_m31(14))),
                    ((unpacked_limb_1_col11) + (unpacked_limb_15_col20)),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_16_col21)),
                    ((unpacked_limb_3_col12) + (unpacked_tmp_fec87_1.get_m31(17))),
                    ((unpacked_limb_4_col13) + (unpacked_limb_18_col22)),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_19_col23)),
                    ((unpacked_limb_6_col14) + (unpacked_tmp_fec87_1.get_m31(20))),
                    ((unpacked_limb_7_col15) + (unpacked_limb_21_col24)),
                    ((unpacked_tmp_fec87_1.get_m31(8)) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_9_col16) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_limb_10_col17) + (unpacked_limb_24_col26)),
                    ((unpacked_tmp_fec87_1.get_m31(11)) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_12_col18) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_limb_13_col19) + (input_limb_9_col9)),
                ];
                let y_sum_tmp_fec87_15 = [
                    ((unpacked_limb_0_col10) + (unpacked_tmp_fec87_1.get_m31(14))),
                    ((unpacked_limb_1_col11) + (unpacked_limb_15_col20)),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_16_col21)),
                    ((unpacked_limb_3_col12) + (unpacked_tmp_fec87_1.get_m31(17))),
                    ((unpacked_limb_4_col13) + (unpacked_limb_18_col22)),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_19_col23)),
                    ((unpacked_limb_6_col14) + (unpacked_tmp_fec87_1.get_m31(20))),
                    ((unpacked_limb_7_col15) + (unpacked_limb_21_col24)),
                    ((unpacked_tmp_fec87_1.get_m31(8)) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_9_col16) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_limb_10_col17) + (unpacked_limb_24_col26)),
                    ((unpacked_tmp_fec87_1.get_m31(11)) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_12_col18) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_limb_13_col19) + (input_limb_9_col9)),
                ];

                // Single Karatsuba N 7.

                let z0_tmp_fec87_16 = [
                    ((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[0])),
                    (((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[1]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[0]))),
                    ((((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[2]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[1])))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[0]))),
                    (((((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[3]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[2])))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[1])))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[0]))),
                    ((((((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[4]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[3])))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[2])))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[1])))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[0]))),
                    (((((((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[5]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[4])))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[3])))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[2])))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[1])))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[0]))),
                    ((((((((x_sum_tmp_fec87_14[0]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[5])))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[4])))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[3])))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[2])))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[1])))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[0]))),
                    (((((((x_sum_tmp_fec87_14[1]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[5])))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[4])))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[3])))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[2])))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[1]))),
                    ((((((x_sum_tmp_fec87_14[2]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[5])))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[4])))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[3])))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[2]))),
                    (((((x_sum_tmp_fec87_14[3]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[5])))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[4])))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[3]))),
                    ((((x_sum_tmp_fec87_14[4]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[5])))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[4]))),
                    (((x_sum_tmp_fec87_14[5]) * (y_sum_tmp_fec87_15[6]))
                        + ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[5]))),
                    ((x_sum_tmp_fec87_14[6]) * (y_sum_tmp_fec87_15[6])),
                ];
                let z2_tmp_fec87_17 = [
                    ((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[7])),
                    (((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[8]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[7]))),
                    ((((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[9]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[8])))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[7]))),
                    (((((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[10]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[9])))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[8])))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[7]))),
                    ((((((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[11]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[10])))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[9])))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[8])))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[7]))),
                    (((((((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[12]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[11])))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[10])))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[9])))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[8])))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[7]))),
                    ((((((((x_sum_tmp_fec87_14[7]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[12])))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[11])))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[10])))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[9])))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[8])))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[7]))),
                    (((((((x_sum_tmp_fec87_14[8]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[12])))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[11])))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[10])))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[9])))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[8]))),
                    ((((((x_sum_tmp_fec87_14[9]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[12])))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[11])))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[10])))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[9]))),
                    (((((x_sum_tmp_fec87_14[10]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[12])))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[11])))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[10]))),
                    ((((x_sum_tmp_fec87_14[11]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[12])))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[11]))),
                    (((x_sum_tmp_fec87_14[12]) * (y_sum_tmp_fec87_15[13]))
                        + ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[12]))),
                    ((x_sum_tmp_fec87_14[13]) * (y_sum_tmp_fec87_15[13])),
                ];
                let x_sum_tmp_fec87_18 = [
                    ((x_sum_tmp_fec87_14[0]) + (x_sum_tmp_fec87_14[7])),
                    ((x_sum_tmp_fec87_14[1]) + (x_sum_tmp_fec87_14[8])),
                    ((x_sum_tmp_fec87_14[2]) + (x_sum_tmp_fec87_14[9])),
                    ((x_sum_tmp_fec87_14[3]) + (x_sum_tmp_fec87_14[10])),
                    ((x_sum_tmp_fec87_14[4]) + (x_sum_tmp_fec87_14[11])),
                    ((x_sum_tmp_fec87_14[5]) + (x_sum_tmp_fec87_14[12])),
                    ((x_sum_tmp_fec87_14[6]) + (x_sum_tmp_fec87_14[13])),
                ];
                let y_sum_tmp_fec87_19 = [
                    ((y_sum_tmp_fec87_15[0]) + (y_sum_tmp_fec87_15[7])),
                    ((y_sum_tmp_fec87_15[1]) + (y_sum_tmp_fec87_15[8])),
                    ((y_sum_tmp_fec87_15[2]) + (y_sum_tmp_fec87_15[9])),
                    ((y_sum_tmp_fec87_15[3]) + (y_sum_tmp_fec87_15[10])),
                    ((y_sum_tmp_fec87_15[4]) + (y_sum_tmp_fec87_15[11])),
                    ((y_sum_tmp_fec87_15[5]) + (y_sum_tmp_fec87_15[12])),
                    ((y_sum_tmp_fec87_15[6]) + (y_sum_tmp_fec87_15[13])),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_20 = [
                    z0_tmp_fec87_16[0],
                    z0_tmp_fec87_16[1],
                    z0_tmp_fec87_16[2],
                    z0_tmp_fec87_16[3],
                    z0_tmp_fec87_16[4],
                    z0_tmp_fec87_16[5],
                    z0_tmp_fec87_16[6],
                    ((z0_tmp_fec87_16[7])
                        + ((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[0]))
                            - (z0_tmp_fec87_16[0]))
                            - (z2_tmp_fec87_17[0]))),
                    ((z0_tmp_fec87_16[8])
                        + (((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[1]))
                            + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[0])))
                            - (z0_tmp_fec87_16[1]))
                            - (z2_tmp_fec87_17[1]))),
                    ((z0_tmp_fec87_16[9])
                        + ((((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[2]))
                            + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[1])))
                            + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[0])))
                            - (z0_tmp_fec87_16[2]))
                            - (z2_tmp_fec87_17[2]))),
                    ((z0_tmp_fec87_16[10])
                        + (((((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[3]))
                            + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[2])))
                            + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[1])))
                            + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[0])))
                            - (z0_tmp_fec87_16[3]))
                            - (z2_tmp_fec87_17[3]))),
                    ((z0_tmp_fec87_16[11])
                        + ((((((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[4]))
                            + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[3])))
                            + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[2])))
                            + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[1])))
                            + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[0])))
                            - (z0_tmp_fec87_16[4]))
                            - (z2_tmp_fec87_17[4]))),
                    ((z0_tmp_fec87_16[12])
                        + (((((((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[5]))
                            + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[4])))
                            + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[3])))
                            + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[2])))
                            + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[1])))
                            + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[0])))
                            - (z0_tmp_fec87_16[5]))
                            - (z2_tmp_fec87_17[5]))),
                    ((((((((((x_sum_tmp_fec87_18[0]) * (y_sum_tmp_fec87_19[6]))
                        + ((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[5])))
                        + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[4])))
                        + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[3])))
                        + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[2])))
                        + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[1])))
                        + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[0])))
                        - (z0_tmp_fec87_16[6]))
                        - (z2_tmp_fec87_17[6])),
                    ((z2_tmp_fec87_17[0])
                        + (((((((((x_sum_tmp_fec87_18[1]) * (y_sum_tmp_fec87_19[6]))
                            + ((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[5])))
                            + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[4])))
                            + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[3])))
                            + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[2])))
                            + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[1])))
                            - (z0_tmp_fec87_16[7]))
                            - (z2_tmp_fec87_17[7]))),
                    ((z2_tmp_fec87_17[1])
                        + ((((((((x_sum_tmp_fec87_18[2]) * (y_sum_tmp_fec87_19[6]))
                            + ((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[5])))
                            + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[4])))
                            + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[3])))
                            + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[2])))
                            - (z0_tmp_fec87_16[8]))
                            - (z2_tmp_fec87_17[8]))),
                    ((z2_tmp_fec87_17[2])
                        + (((((((x_sum_tmp_fec87_18[3]) * (y_sum_tmp_fec87_19[6]))
                            + ((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[5])))
                            + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[4])))
                            + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[3])))
                            - (z0_tmp_fec87_16[9]))
                            - (z2_tmp_fec87_17[9]))),
                    ((z2_tmp_fec87_17[3])
                        + ((((((x_sum_tmp_fec87_18[4]) * (y_sum_tmp_fec87_19[6]))
                            + ((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[5])))
                            + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[4])))
                            - (z0_tmp_fec87_16[10]))
                            - (z2_tmp_fec87_17[10]))),
                    ((z2_tmp_fec87_17[4])
                        + (((((x_sum_tmp_fec87_18[5]) * (y_sum_tmp_fec87_19[6]))
                            + ((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[5])))
                            - (z0_tmp_fec87_16[11]))
                            - (z2_tmp_fec87_17[11]))),
                    ((z2_tmp_fec87_17[5])
                        + ((((x_sum_tmp_fec87_18[6]) * (y_sum_tmp_fec87_19[6]))
                            - (z0_tmp_fec87_16[12]))
                            - (z2_tmp_fec87_17[12]))),
                    z2_tmp_fec87_17[6],
                    z2_tmp_fec87_17[7],
                    z2_tmp_fec87_17[8],
                    z2_tmp_fec87_17[9],
                    z2_tmp_fec87_17[10],
                    z2_tmp_fec87_17[11],
                    z2_tmp_fec87_17[12],
                ];

                let double_karatsuba_1454b_output_tmp_fec87_21 = [
                    single_karatsuba_n_7_output_tmp_fec87_8[0],
                    single_karatsuba_n_7_output_tmp_fec87_8[1],
                    single_karatsuba_n_7_output_tmp_fec87_8[2],
                    single_karatsuba_n_7_output_tmp_fec87_8[3],
                    single_karatsuba_n_7_output_tmp_fec87_8[4],
                    single_karatsuba_n_7_output_tmp_fec87_8[5],
                    single_karatsuba_n_7_output_tmp_fec87_8[6],
                    single_karatsuba_n_7_output_tmp_fec87_8[7],
                    single_karatsuba_n_7_output_tmp_fec87_8[8],
                    single_karatsuba_n_7_output_tmp_fec87_8[9],
                    single_karatsuba_n_7_output_tmp_fec87_8[10],
                    single_karatsuba_n_7_output_tmp_fec87_8[11],
                    single_karatsuba_n_7_output_tmp_fec87_8[12],
                    single_karatsuba_n_7_output_tmp_fec87_8[13],
                    ((single_karatsuba_n_7_output_tmp_fec87_8[14])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[0])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[0]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[0]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[15])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[1])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[1]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[1]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[16])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[2])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[2]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[2]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[17])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[3])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[3]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[3]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[18])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[4])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[4]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[4]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[19])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[5])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[5]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[5]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[20])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[6])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[6]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[6]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[21])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[7])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[7]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[7]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[22])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[8])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[8]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[8]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[23])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[9])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[9]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[9]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[24])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[10])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[10]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[10]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[25])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[11])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[11]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[11]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_8[26])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[12])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[12]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[12]))),
                    (((single_karatsuba_n_7_output_tmp_fec87_20[13])
                        - (single_karatsuba_n_7_output_tmp_fec87_8[13]))
                        - (single_karatsuba_n_7_output_tmp_fec87_13[13])),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[0])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[14])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[14]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[14]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[1])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[15])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[15]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[15]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[2])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[16])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[16]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[16]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[3])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[17])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[17]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[17]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[4])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[18])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[18]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[18]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[5])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[19])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[19]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[19]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[6])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[20])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[20]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[20]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[7])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[21])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[21]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[21]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[8])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[22])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[22]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[22]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[9])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[23])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[23]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[23]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[10])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[24])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[24]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[24]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[11])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[25])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[25]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[25]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_13[12])
                        + (((single_karatsuba_n_7_output_tmp_fec87_20[26])
                            - (single_karatsuba_n_7_output_tmp_fec87_8[26]))
                            - (single_karatsuba_n_7_output_tmp_fec87_13[26]))),
                    single_karatsuba_n_7_output_tmp_fec87_13[13],
                    single_karatsuba_n_7_output_tmp_fec87_13[14],
                    single_karatsuba_n_7_output_tmp_fec87_13[15],
                    single_karatsuba_n_7_output_tmp_fec87_13[16],
                    single_karatsuba_n_7_output_tmp_fec87_13[17],
                    single_karatsuba_n_7_output_tmp_fec87_13[18],
                    single_karatsuba_n_7_output_tmp_fec87_13[19],
                    single_karatsuba_n_7_output_tmp_fec87_13[20],
                    single_karatsuba_n_7_output_tmp_fec87_13[21],
                    single_karatsuba_n_7_output_tmp_fec87_13[22],
                    single_karatsuba_n_7_output_tmp_fec87_13[23],
                    single_karatsuba_n_7_output_tmp_fec87_13[24],
                    single_karatsuba_n_7_output_tmp_fec87_13[25],
                    single_karatsuba_n_7_output_tmp_fec87_13[26],
                ];

                let conv_tmp_fec87_22 = [
                    ((double_karatsuba_1454b_output_tmp_fec87_21[0]) - (mul_res_limb_0_col28)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[1]) - (mul_res_limb_1_col29)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[2]) - (mul_res_limb_2_col30)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[3]) - (mul_res_limb_3_col31)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[4]) - (mul_res_limb_4_col32)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[5]) - (mul_res_limb_5_col33)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[6]) - (mul_res_limb_6_col34)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[7]) - (mul_res_limb_7_col35)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[8]) - (mul_res_limb_8_col36)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[9]) - (mul_res_limb_9_col37)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[10]) - (mul_res_limb_10_col38)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[11]) - (mul_res_limb_11_col39)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[12]) - (mul_res_limb_12_col40)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[13]) - (mul_res_limb_13_col41)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[14]) - (mul_res_limb_14_col42)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[15]) - (mul_res_limb_15_col43)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[16]) - (mul_res_limb_16_col44)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[17]) - (mul_res_limb_17_col45)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[18]) - (mul_res_limb_18_col46)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[19]) - (mul_res_limb_19_col47)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[20]) - (mul_res_limb_20_col48)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[21]) - (mul_res_limb_21_col49)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[22]) - (mul_res_limb_22_col50)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[23]) - (mul_res_limb_23_col51)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[24]) - (mul_res_limb_24_col52)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[25]) - (mul_res_limb_25_col53)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[26]) - (mul_res_limb_26_col54)),
                    ((double_karatsuba_1454b_output_tmp_fec87_21[27]) - (mul_res_limb_27_col55)),
                    double_karatsuba_1454b_output_tmp_fec87_21[28],
                    double_karatsuba_1454b_output_tmp_fec87_21[29],
                    double_karatsuba_1454b_output_tmp_fec87_21[30],
                    double_karatsuba_1454b_output_tmp_fec87_21[31],
                    double_karatsuba_1454b_output_tmp_fec87_21[32],
                    double_karatsuba_1454b_output_tmp_fec87_21[33],
                    double_karatsuba_1454b_output_tmp_fec87_21[34],
                    double_karatsuba_1454b_output_tmp_fec87_21[35],
                    double_karatsuba_1454b_output_tmp_fec87_21[36],
                    double_karatsuba_1454b_output_tmp_fec87_21[37],
                    double_karatsuba_1454b_output_tmp_fec87_21[38],
                    double_karatsuba_1454b_output_tmp_fec87_21[39],
                    double_karatsuba_1454b_output_tmp_fec87_21[40],
                    double_karatsuba_1454b_output_tmp_fec87_21[41],
                    double_karatsuba_1454b_output_tmp_fec87_21[42],
                    double_karatsuba_1454b_output_tmp_fec87_21[43],
                    double_karatsuba_1454b_output_tmp_fec87_21[44],
                    double_karatsuba_1454b_output_tmp_fec87_21[45],
                    double_karatsuba_1454b_output_tmp_fec87_21[46],
                    double_karatsuba_1454b_output_tmp_fec87_21[47],
                    double_karatsuba_1454b_output_tmp_fec87_21[48],
                    double_karatsuba_1454b_output_tmp_fec87_21[49],
                    double_karatsuba_1454b_output_tmp_fec87_21[50],
                    double_karatsuba_1454b_output_tmp_fec87_21[51],
                    double_karatsuba_1454b_output_tmp_fec87_21[52],
                    double_karatsuba_1454b_output_tmp_fec87_21[53],
                    double_karatsuba_1454b_output_tmp_fec87_21[54],
                ];
                let conv_mod_tmp_fec87_23 = [
                    ((((M31_32) * (conv_tmp_fec87_22[0])) - ((M31_4) * (conv_tmp_fec87_22[21])))
                        + ((M31_8) * (conv_tmp_fec87_22[49]))),
                    ((((conv_tmp_fec87_22[0]) + ((M31_32) * (conv_tmp_fec87_22[1])))
                        - ((M31_4) * (conv_tmp_fec87_22[22])))
                        + ((M31_8) * (conv_tmp_fec87_22[50]))),
                    ((((conv_tmp_fec87_22[1]) + ((M31_32) * (conv_tmp_fec87_22[2])))
                        - ((M31_4) * (conv_tmp_fec87_22[23])))
                        + ((M31_8) * (conv_tmp_fec87_22[51]))),
                    ((((conv_tmp_fec87_22[2]) + ((M31_32) * (conv_tmp_fec87_22[3])))
                        - ((M31_4) * (conv_tmp_fec87_22[24])))
                        + ((M31_8) * (conv_tmp_fec87_22[52]))),
                    ((((conv_tmp_fec87_22[3]) + ((M31_32) * (conv_tmp_fec87_22[4])))
                        - ((M31_4) * (conv_tmp_fec87_22[25])))
                        + ((M31_8) * (conv_tmp_fec87_22[53]))),
                    ((((conv_tmp_fec87_22[4]) + ((M31_32) * (conv_tmp_fec87_22[5])))
                        - ((M31_4) * (conv_tmp_fec87_22[26])))
                        + ((M31_8) * (conv_tmp_fec87_22[54]))),
                    (((conv_tmp_fec87_22[5]) + ((M31_32) * (conv_tmp_fec87_22[6])))
                        - ((M31_4) * (conv_tmp_fec87_22[27]))),
                    (((((M31_2) * (conv_tmp_fec87_22[0])) + (conv_tmp_fec87_22[6]))
                        + ((M31_32) * (conv_tmp_fec87_22[7])))
                        - ((M31_4) * (conv_tmp_fec87_22[28]))),
                    (((((M31_2) * (conv_tmp_fec87_22[1])) + (conv_tmp_fec87_22[7]))
                        + ((M31_32) * (conv_tmp_fec87_22[8])))
                        - ((M31_4) * (conv_tmp_fec87_22[29]))),
                    (((((M31_2) * (conv_tmp_fec87_22[2])) + (conv_tmp_fec87_22[8]))
                        + ((M31_32) * (conv_tmp_fec87_22[9])))
                        - ((M31_4) * (conv_tmp_fec87_22[30]))),
                    (((((M31_2) * (conv_tmp_fec87_22[3])) + (conv_tmp_fec87_22[9]))
                        + ((M31_32) * (conv_tmp_fec87_22[10])))
                        - ((M31_4) * (conv_tmp_fec87_22[31]))),
                    (((((M31_2) * (conv_tmp_fec87_22[4])) + (conv_tmp_fec87_22[10]))
                        + ((M31_32) * (conv_tmp_fec87_22[11])))
                        - ((M31_4) * (conv_tmp_fec87_22[32]))),
                    (((((M31_2) * (conv_tmp_fec87_22[5])) + (conv_tmp_fec87_22[11]))
                        + ((M31_32) * (conv_tmp_fec87_22[12])))
                        - ((M31_4) * (conv_tmp_fec87_22[33]))),
                    (((((M31_2) * (conv_tmp_fec87_22[6])) + (conv_tmp_fec87_22[12]))
                        + ((M31_32) * (conv_tmp_fec87_22[13])))
                        - ((M31_4) * (conv_tmp_fec87_22[34]))),
                    (((((M31_2) * (conv_tmp_fec87_22[7])) + (conv_tmp_fec87_22[13]))
                        + ((M31_32) * (conv_tmp_fec87_22[14])))
                        - ((M31_4) * (conv_tmp_fec87_22[35]))),
                    (((((M31_2) * (conv_tmp_fec87_22[8])) + (conv_tmp_fec87_22[14]))
                        + ((M31_32) * (conv_tmp_fec87_22[15])))
                        - ((M31_4) * (conv_tmp_fec87_22[36]))),
                    (((((M31_2) * (conv_tmp_fec87_22[9])) + (conv_tmp_fec87_22[15]))
                        + ((M31_32) * (conv_tmp_fec87_22[16])))
                        - ((M31_4) * (conv_tmp_fec87_22[37]))),
                    (((((M31_2) * (conv_tmp_fec87_22[10])) + (conv_tmp_fec87_22[16]))
                        + ((M31_32) * (conv_tmp_fec87_22[17])))
                        - ((M31_4) * (conv_tmp_fec87_22[38]))),
                    (((((M31_2) * (conv_tmp_fec87_22[11])) + (conv_tmp_fec87_22[17]))
                        + ((M31_32) * (conv_tmp_fec87_22[18])))
                        - ((M31_4) * (conv_tmp_fec87_22[39]))),
                    (((((M31_2) * (conv_tmp_fec87_22[12])) + (conv_tmp_fec87_22[18]))
                        + ((M31_32) * (conv_tmp_fec87_22[19])))
                        - ((M31_4) * (conv_tmp_fec87_22[40]))),
                    (((((M31_2) * (conv_tmp_fec87_22[13])) + (conv_tmp_fec87_22[19]))
                        + ((M31_32) * (conv_tmp_fec87_22[20])))
                        - ((M31_4) * (conv_tmp_fec87_22[41]))),
                    (((((M31_2) * (conv_tmp_fec87_22[14])) + (conv_tmp_fec87_22[20]))
                        - ((M31_4) * (conv_tmp_fec87_22[42])))
                        + ((M31_64) * (conv_tmp_fec87_22[49]))),
                    (((((M31_2) * (conv_tmp_fec87_22[15])) - ((M31_4) * (conv_tmp_fec87_22[43])))
                        + ((M31_2) * (conv_tmp_fec87_22[49])))
                        + ((M31_64) * (conv_tmp_fec87_22[50]))),
                    (((((M31_2) * (conv_tmp_fec87_22[16])) - ((M31_4) * (conv_tmp_fec87_22[44])))
                        + ((M31_2) * (conv_tmp_fec87_22[50])))
                        + ((M31_64) * (conv_tmp_fec87_22[51]))),
                    (((((M31_2) * (conv_tmp_fec87_22[17])) - ((M31_4) * (conv_tmp_fec87_22[45])))
                        + ((M31_2) * (conv_tmp_fec87_22[51])))
                        + ((M31_64) * (conv_tmp_fec87_22[52]))),
                    (((((M31_2) * (conv_tmp_fec87_22[18])) - ((M31_4) * (conv_tmp_fec87_22[46])))
                        + ((M31_2) * (conv_tmp_fec87_22[52])))
                        + ((M31_64) * (conv_tmp_fec87_22[53]))),
                    (((((M31_2) * (conv_tmp_fec87_22[19])) - ((M31_4) * (conv_tmp_fec87_22[47])))
                        + ((M31_2) * (conv_tmp_fec87_22[53])))
                        + ((M31_64) * (conv_tmp_fec87_22[54]))),
                    ((((M31_2) * (conv_tmp_fec87_22[20])) - ((M31_4) * (conv_tmp_fec87_22[48])))
                        + ((M31_2) * (conv_tmp_fec87_22[54]))),
                ];
                let k_mod_2_18_biased_tmp_fec87_24 =
                    ((((PackedUInt32::from_m31(((conv_mod_tmp_fec87_23[0]) + (M31_134217728))))
                        + (((PackedUInt32::from_m31(
                            ((conv_mod_tmp_fec87_23[1]) + (M31_134217728)),
                        )) & (UInt32_511))
                            << (UInt32_9)))
                        + (UInt32_131072))
                        & (UInt32_262143));
                let k_col56 = ((k_mod_2_18_biased_tmp_fec87_24.low().as_m31())
                    + (((k_mod_2_18_biased_tmp_fec87_24.high().as_m31()) - (M31_2)) * (M31_65536)));
                *row[56] = k_col56;
                *sub_component_inputs.range_check_20[0] = [((k_col56) + (M31_524288))];
                *lookup_data.range_check_20_0 = [M31_1410849886, ((k_col56) + (M31_524288))];
                let carry_0_col57 = (((conv_mod_tmp_fec87_23[0]) - (k_col56)) * (M31_4194304));
                *row[57] = carry_0_col57;
                *sub_component_inputs.range_check_20_b[0] = [((carry_0_col57) + (M31_524288))];
                *lookup_data.range_check_20_b_0 = [M31_514232941, ((carry_0_col57) + (M31_524288))];
                let carry_1_col58 =
                    (((conv_mod_tmp_fec87_23[1]) + (carry_0_col57)) * (M31_4194304));
                *row[58] = carry_1_col58;
                *sub_component_inputs.range_check_20_c[0] = [((carry_1_col58) + (M31_524288))];
                *lookup_data.range_check_20_c_0 = [M31_531010560, ((carry_1_col58) + (M31_524288))];
                let carry_2_col59 =
                    (((conv_mod_tmp_fec87_23[2]) + (carry_1_col58)) * (M31_4194304));
                *row[59] = carry_2_col59;
                *sub_component_inputs.range_check_20_d[0] = [((carry_2_col59) + (M31_524288))];
                *lookup_data.range_check_20_d_0 = [M31_480677703, ((carry_2_col59) + (M31_524288))];
                let carry_3_col60 =
                    (((conv_mod_tmp_fec87_23[3]) + (carry_2_col59)) * (M31_4194304));
                *row[60] = carry_3_col60;
                *sub_component_inputs.range_check_20_e[0] = [((carry_3_col60) + (M31_524288))];
                *lookup_data.range_check_20_e_0 = [M31_497455322, ((carry_3_col60) + (M31_524288))];
                let carry_4_col61 =
                    (((conv_mod_tmp_fec87_23[4]) + (carry_3_col60)) * (M31_4194304));
                *row[61] = carry_4_col61;
                *sub_component_inputs.range_check_20_f[0] = [((carry_4_col61) + (M31_524288))];
                *lookup_data.range_check_20_f_0 = [M31_447122465, ((carry_4_col61) + (M31_524288))];
                let carry_5_col62 =
                    (((conv_mod_tmp_fec87_23[5]) + (carry_4_col61)) * (M31_4194304));
                *row[62] = carry_5_col62;
                *sub_component_inputs.range_check_20_g[0] = [((carry_5_col62) + (M31_524288))];
                *lookup_data.range_check_20_g_0 = [M31_463900084, ((carry_5_col62) + (M31_524288))];
                let carry_6_col63 =
                    (((conv_mod_tmp_fec87_23[6]) + (carry_5_col62)) * (M31_4194304));
                *row[63] = carry_6_col63;
                *sub_component_inputs.range_check_20_h[0] = [((carry_6_col63) + (M31_524288))];
                *lookup_data.range_check_20_h_0 = [M31_682009131, ((carry_6_col63) + (M31_524288))];
                let carry_7_col64 =
                    (((conv_mod_tmp_fec87_23[7]) + (carry_6_col63)) * (M31_4194304));
                *row[64] = carry_7_col64;
                *sub_component_inputs.range_check_20[1] = [((carry_7_col64) + (M31_524288))];
                *lookup_data.range_check_20_1 = [M31_1410849886, ((carry_7_col64) + (M31_524288))];
                let carry_8_col65 =
                    (((conv_mod_tmp_fec87_23[8]) + (carry_7_col64)) * (M31_4194304));
                *row[65] = carry_8_col65;
                *sub_component_inputs.range_check_20_b[1] = [((carry_8_col65) + (M31_524288))];
                *lookup_data.range_check_20_b_1 = [M31_514232941, ((carry_8_col65) + (M31_524288))];
                let carry_9_col66 =
                    (((conv_mod_tmp_fec87_23[9]) + (carry_8_col65)) * (M31_4194304));
                *row[66] = carry_9_col66;
                *sub_component_inputs.range_check_20_c[1] = [((carry_9_col66) + (M31_524288))];
                *lookup_data.range_check_20_c_1 = [M31_531010560, ((carry_9_col66) + (M31_524288))];
                let carry_10_col67 =
                    (((conv_mod_tmp_fec87_23[10]) + (carry_9_col66)) * (M31_4194304));
                *row[67] = carry_10_col67;
                *sub_component_inputs.range_check_20_d[1] = [((carry_10_col67) + (M31_524288))];
                *lookup_data.range_check_20_d_1 =
                    [M31_480677703, ((carry_10_col67) + (M31_524288))];
                let carry_11_col68 =
                    (((conv_mod_tmp_fec87_23[11]) + (carry_10_col67)) * (M31_4194304));
                *row[68] = carry_11_col68;
                *sub_component_inputs.range_check_20_e[1] = [((carry_11_col68) + (M31_524288))];
                *lookup_data.range_check_20_e_1 =
                    [M31_497455322, ((carry_11_col68) + (M31_524288))];
                let carry_12_col69 =
                    (((conv_mod_tmp_fec87_23[12]) + (carry_11_col68)) * (M31_4194304));
                *row[69] = carry_12_col69;
                *sub_component_inputs.range_check_20_f[1] = [((carry_12_col69) + (M31_524288))];
                *lookup_data.range_check_20_f_1 =
                    [M31_447122465, ((carry_12_col69) + (M31_524288))];
                let carry_13_col70 =
                    (((conv_mod_tmp_fec87_23[13]) + (carry_12_col69)) * (M31_4194304));
                *row[70] = carry_13_col70;
                *sub_component_inputs.range_check_20_g[1] = [((carry_13_col70) + (M31_524288))];
                *lookup_data.range_check_20_g_1 =
                    [M31_463900084, ((carry_13_col70) + (M31_524288))];
                let carry_14_col71 =
                    (((conv_mod_tmp_fec87_23[14]) + (carry_13_col70)) * (M31_4194304));
                *row[71] = carry_14_col71;
                *sub_component_inputs.range_check_20_h[1] = [((carry_14_col71) + (M31_524288))];
                *lookup_data.range_check_20_h_1 =
                    [M31_682009131, ((carry_14_col71) + (M31_524288))];
                let carry_15_col72 =
                    (((conv_mod_tmp_fec87_23[15]) + (carry_14_col71)) * (M31_4194304));
                *row[72] = carry_15_col72;
                *sub_component_inputs.range_check_20[2] = [((carry_15_col72) + (M31_524288))];
                *lookup_data.range_check_20_2 = [M31_1410849886, ((carry_15_col72) + (M31_524288))];
                let carry_16_col73 =
                    (((conv_mod_tmp_fec87_23[16]) + (carry_15_col72)) * (M31_4194304));
                *row[73] = carry_16_col73;
                *sub_component_inputs.range_check_20_b[2] = [((carry_16_col73) + (M31_524288))];
                *lookup_data.range_check_20_b_2 =
                    [M31_514232941, ((carry_16_col73) + (M31_524288))];
                let carry_17_col74 =
                    (((conv_mod_tmp_fec87_23[17]) + (carry_16_col73)) * (M31_4194304));
                *row[74] = carry_17_col74;
                *sub_component_inputs.range_check_20_c[2] = [((carry_17_col74) + (M31_524288))];
                *lookup_data.range_check_20_c_2 =
                    [M31_531010560, ((carry_17_col74) + (M31_524288))];
                let carry_18_col75 =
                    (((conv_mod_tmp_fec87_23[18]) + (carry_17_col74)) * (M31_4194304));
                *row[75] = carry_18_col75;
                *sub_component_inputs.range_check_20_d[2] = [((carry_18_col75) + (M31_524288))];
                *lookup_data.range_check_20_d_2 =
                    [M31_480677703, ((carry_18_col75) + (M31_524288))];
                let carry_19_col76 =
                    (((conv_mod_tmp_fec87_23[19]) + (carry_18_col75)) * (M31_4194304));
                *row[76] = carry_19_col76;
                *sub_component_inputs.range_check_20_e[2] = [((carry_19_col76) + (M31_524288))];
                *lookup_data.range_check_20_e_2 =
                    [M31_497455322, ((carry_19_col76) + (M31_524288))];
                let carry_20_col77 =
                    (((conv_mod_tmp_fec87_23[20]) + (carry_19_col76)) * (M31_4194304));
                *row[77] = carry_20_col77;
                *sub_component_inputs.range_check_20_f[2] = [((carry_20_col77) + (M31_524288))];
                *lookup_data.range_check_20_f_2 =
                    [M31_447122465, ((carry_20_col77) + (M31_524288))];
                let carry_21_col78 = ((((conv_mod_tmp_fec87_23[21]) - ((M31_136) * (k_col56)))
                    + (carry_20_col77))
                    * (M31_4194304));
                *row[78] = carry_21_col78;
                *sub_component_inputs.range_check_20_g[2] = [((carry_21_col78) + (M31_524288))];
                *lookup_data.range_check_20_g_2 =
                    [M31_463900084, ((carry_21_col78) + (M31_524288))];
                let carry_22_col79 =
                    (((conv_mod_tmp_fec87_23[22]) + (carry_21_col78)) * (M31_4194304));
                *row[79] = carry_22_col79;
                *sub_component_inputs.range_check_20_h[2] = [((carry_22_col79) + (M31_524288))];
                *lookup_data.range_check_20_h_2 =
                    [M31_682009131, ((carry_22_col79) + (M31_524288))];
                let carry_23_col80 =
                    (((conv_mod_tmp_fec87_23[23]) + (carry_22_col79)) * (M31_4194304));
                *row[80] = carry_23_col80;
                *sub_component_inputs.range_check_20[3] = [((carry_23_col80) + (M31_524288))];
                *lookup_data.range_check_20_3 = [M31_1410849886, ((carry_23_col80) + (M31_524288))];
                let carry_24_col81 =
                    (((conv_mod_tmp_fec87_23[24]) + (carry_23_col80)) * (M31_4194304));
                *row[81] = carry_24_col81;
                *sub_component_inputs.range_check_20_b[3] = [((carry_24_col81) + (M31_524288))];
                *lookup_data.range_check_20_b_3 =
                    [M31_514232941, ((carry_24_col81) + (M31_524288))];
                let carry_25_col82 =
                    (((conv_mod_tmp_fec87_23[25]) + (carry_24_col81)) * (M31_4194304));
                *row[82] = carry_25_col82;
                *sub_component_inputs.range_check_20_c[3] = [((carry_25_col82) + (M31_524288))];
                *lookup_data.range_check_20_c_3 =
                    [M31_531010560, ((carry_25_col82) + (M31_524288))];
                let carry_26_col83 =
                    (((conv_mod_tmp_fec87_23[26]) + (carry_25_col82)) * (M31_4194304));
                *row[83] = carry_26_col83;
                *sub_component_inputs.range_check_20_d[3] = [((carry_26_col83) + (M31_524288))];
                *lookup_data.range_check_20_d_3 =
                    [M31_480677703, ((carry_26_col83) + (M31_524288))];

                let mul_252_output_tmp_fec87_25 = mul_res_tmp_fec87_3;

                // Mul 252.

                let mul_res_tmp_fec87_26 =
                    ((felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2)
                        * (mul_252_output_tmp_fec87_25));
                let mul_res_limb_0_col84 = mul_res_tmp_fec87_26.get_m31(0);
                *row[84] = mul_res_limb_0_col84;
                let mul_res_limb_1_col85 = mul_res_tmp_fec87_26.get_m31(1);
                *row[85] = mul_res_limb_1_col85;
                let mul_res_limb_2_col86 = mul_res_tmp_fec87_26.get_m31(2);
                *row[86] = mul_res_limb_2_col86;
                let mul_res_limb_3_col87 = mul_res_tmp_fec87_26.get_m31(3);
                *row[87] = mul_res_limb_3_col87;
                let mul_res_limb_4_col88 = mul_res_tmp_fec87_26.get_m31(4);
                *row[88] = mul_res_limb_4_col88;
                let mul_res_limb_5_col89 = mul_res_tmp_fec87_26.get_m31(5);
                *row[89] = mul_res_limb_5_col89;
                let mul_res_limb_6_col90 = mul_res_tmp_fec87_26.get_m31(6);
                *row[90] = mul_res_limb_6_col90;
                let mul_res_limb_7_col91 = mul_res_tmp_fec87_26.get_m31(7);
                *row[91] = mul_res_limb_7_col91;
                let mul_res_limb_8_col92 = mul_res_tmp_fec87_26.get_m31(8);
                *row[92] = mul_res_limb_8_col92;
                let mul_res_limb_9_col93 = mul_res_tmp_fec87_26.get_m31(9);
                *row[93] = mul_res_limb_9_col93;
                let mul_res_limb_10_col94 = mul_res_tmp_fec87_26.get_m31(10);
                *row[94] = mul_res_limb_10_col94;
                let mul_res_limb_11_col95 = mul_res_tmp_fec87_26.get_m31(11);
                *row[95] = mul_res_limb_11_col95;
                let mul_res_limb_12_col96 = mul_res_tmp_fec87_26.get_m31(12);
                *row[96] = mul_res_limb_12_col96;
                let mul_res_limb_13_col97 = mul_res_tmp_fec87_26.get_m31(13);
                *row[97] = mul_res_limb_13_col97;
                let mul_res_limb_14_col98 = mul_res_tmp_fec87_26.get_m31(14);
                *row[98] = mul_res_limb_14_col98;
                let mul_res_limb_15_col99 = mul_res_tmp_fec87_26.get_m31(15);
                *row[99] = mul_res_limb_15_col99;
                let mul_res_limb_16_col100 = mul_res_tmp_fec87_26.get_m31(16);
                *row[100] = mul_res_limb_16_col100;
                let mul_res_limb_17_col101 = mul_res_tmp_fec87_26.get_m31(17);
                *row[101] = mul_res_limb_17_col101;
                let mul_res_limb_18_col102 = mul_res_tmp_fec87_26.get_m31(18);
                *row[102] = mul_res_limb_18_col102;
                let mul_res_limb_19_col103 = mul_res_tmp_fec87_26.get_m31(19);
                *row[103] = mul_res_limb_19_col103;
                let mul_res_limb_20_col104 = mul_res_tmp_fec87_26.get_m31(20);
                *row[104] = mul_res_limb_20_col104;
                let mul_res_limb_21_col105 = mul_res_tmp_fec87_26.get_m31(21);
                *row[105] = mul_res_limb_21_col105;
                let mul_res_limb_22_col106 = mul_res_tmp_fec87_26.get_m31(22);
                *row[106] = mul_res_limb_22_col106;
                let mul_res_limb_23_col107 = mul_res_tmp_fec87_26.get_m31(23);
                *row[107] = mul_res_limb_23_col107;
                let mul_res_limb_24_col108 = mul_res_tmp_fec87_26.get_m31(24);
                *row[108] = mul_res_limb_24_col108;
                let mul_res_limb_25_col109 = mul_res_tmp_fec87_26.get_m31(25);
                *row[109] = mul_res_limb_25_col109;
                let mul_res_limb_26_col110 = mul_res_tmp_fec87_26.get_m31(26);
                *row[110] = mul_res_limb_26_col110;
                let mul_res_limb_27_col111 = mul_res_tmp_fec87_26.get_m31(27);
                *row[111] = mul_res_limb_27_col111;

                // Range Check Mem Value N 28.

                *sub_component_inputs.range_check_9_9[4] =
                    [mul_res_limb_0_col84, mul_res_limb_1_col85];
                *lookup_data.range_check_9_9_4 =
                    [M31_517791011, mul_res_limb_0_col84, mul_res_limb_1_col85];
                *sub_component_inputs.range_check_9_9_b[4] =
                    [mul_res_limb_2_col86, mul_res_limb_3_col87];
                *lookup_data.range_check_9_9_b_4 =
                    [M31_1897792095, mul_res_limb_2_col86, mul_res_limb_3_col87];
                *sub_component_inputs.range_check_9_9_c[4] =
                    [mul_res_limb_4_col88, mul_res_limb_5_col89];
                *lookup_data.range_check_9_9_c_4 =
                    [M31_1881014476, mul_res_limb_4_col88, mul_res_limb_5_col89];
                *sub_component_inputs.range_check_9_9_d[4] =
                    [mul_res_limb_6_col90, mul_res_limb_7_col91];
                *lookup_data.range_check_9_9_d_4 =
                    [M31_1864236857, mul_res_limb_6_col90, mul_res_limb_7_col91];
                *sub_component_inputs.range_check_9_9_e[4] =
                    [mul_res_limb_8_col92, mul_res_limb_9_col93];
                *lookup_data.range_check_9_9_e_4 =
                    [M31_1847459238, mul_res_limb_8_col92, mul_res_limb_9_col93];
                *sub_component_inputs.range_check_9_9_f[4] =
                    [mul_res_limb_10_col94, mul_res_limb_11_col95];
                *lookup_data.range_check_9_9_f_4 =
                    [M31_1830681619, mul_res_limb_10_col94, mul_res_limb_11_col95];
                *sub_component_inputs.range_check_9_9_g[2] =
                    [mul_res_limb_12_col96, mul_res_limb_13_col97];
                *lookup_data.range_check_9_9_g_2 =
                    [M31_1813904000, mul_res_limb_12_col96, mul_res_limb_13_col97];
                *sub_component_inputs.range_check_9_9_h[2] =
                    [mul_res_limb_14_col98, mul_res_limb_15_col99];
                *lookup_data.range_check_9_9_h_2 =
                    [M31_2065568285, mul_res_limb_14_col98, mul_res_limb_15_col99];
                *sub_component_inputs.range_check_9_9[5] =
                    [mul_res_limb_16_col100, mul_res_limb_17_col101];
                *lookup_data.range_check_9_9_5 = [
                    M31_517791011,
                    mul_res_limb_16_col100,
                    mul_res_limb_17_col101,
                ];
                *sub_component_inputs.range_check_9_9_b[5] =
                    [mul_res_limb_18_col102, mul_res_limb_19_col103];
                *lookup_data.range_check_9_9_b_5 = [
                    M31_1897792095,
                    mul_res_limb_18_col102,
                    mul_res_limb_19_col103,
                ];
                *sub_component_inputs.range_check_9_9_c[5] =
                    [mul_res_limb_20_col104, mul_res_limb_21_col105];
                *lookup_data.range_check_9_9_c_5 = [
                    M31_1881014476,
                    mul_res_limb_20_col104,
                    mul_res_limb_21_col105,
                ];
                *sub_component_inputs.range_check_9_9_d[5] =
                    [mul_res_limb_22_col106, mul_res_limb_23_col107];
                *lookup_data.range_check_9_9_d_5 = [
                    M31_1864236857,
                    mul_res_limb_22_col106,
                    mul_res_limb_23_col107,
                ];
                *sub_component_inputs.range_check_9_9_e[5] =
                    [mul_res_limb_24_col108, mul_res_limb_25_col109];
                *lookup_data.range_check_9_9_e_5 = [
                    M31_1847459238,
                    mul_res_limb_24_col108,
                    mul_res_limb_25_col109,
                ];
                *sub_component_inputs.range_check_9_9_f[5] =
                    [mul_res_limb_26_col110, mul_res_limb_27_col111];
                *lookup_data.range_check_9_9_f_5 = [
                    M31_1830681619,
                    mul_res_limb_26_col110,
                    mul_res_limb_27_col111,
                ];

                // Verify Mul 252.

                // Double Karatsuba 1454 B.

                // Single Karatsuba N 7.

                let z0_tmp_fec87_27 = [
                    ((unpacked_limb_0_col10) * (mul_res_limb_0_col28)),
                    (((unpacked_limb_0_col10) * (mul_res_limb_1_col29))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_0_col28))),
                    ((((unpacked_limb_0_col10) * (mul_res_limb_2_col30))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_1_col29)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_0_col28))),
                    (((((unpacked_limb_0_col10) * (mul_res_limb_3_col31))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_2_col30)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_1_col29)))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_0_col28))),
                    ((((((unpacked_limb_0_col10) * (mul_res_limb_4_col32))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_3_col31)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_2_col30)))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_1_col29)))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_0_col28))),
                    (((((((unpacked_limb_0_col10) * (mul_res_limb_5_col33))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_4_col32)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_3_col31)))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_2_col30)))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_1_col29)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_0_col28))),
                    ((((((((unpacked_limb_0_col10) * (mul_res_limb_6_col34))
                        + ((unpacked_limb_1_col11) * (mul_res_limb_5_col33)))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_4_col32)))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_3_col31)))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_2_col30)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_1_col29)))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_0_col28))),
                    (((((((unpacked_limb_1_col11) * (mul_res_limb_6_col34))
                        + ((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_5_col33)))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_4_col32)))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_3_col31)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_2_col30)))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_1_col29))),
                    ((((((unpacked_tmp_fec87_1.get_m31(2)) * (mul_res_limb_6_col34))
                        + ((unpacked_limb_3_col12) * (mul_res_limb_5_col33)))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_4_col32)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_3_col31)))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_2_col30))),
                    (((((unpacked_limb_3_col12) * (mul_res_limb_6_col34))
                        + ((unpacked_limb_4_col13) * (mul_res_limb_5_col33)))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_4_col32)))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_3_col31))),
                    ((((unpacked_limb_4_col13) * (mul_res_limb_6_col34))
                        + ((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_5_col33)))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_4_col32))),
                    (((unpacked_tmp_fec87_1.get_m31(5)) * (mul_res_limb_6_col34))
                        + ((unpacked_limb_6_col14) * (mul_res_limb_5_col33))),
                    ((unpacked_limb_6_col14) * (mul_res_limb_6_col34)),
                ];
                let z2_tmp_fec87_28 = [
                    ((unpacked_limb_7_col15) * (mul_res_limb_7_col35)),
                    (((unpacked_limb_7_col15) * (mul_res_limb_8_col36))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_7_col35))),
                    ((((unpacked_limb_7_col15) * (mul_res_limb_9_col37))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_8_col36)))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_7_col35))),
                    (((((unpacked_limb_7_col15) * (mul_res_limb_10_col38))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_9_col37)))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_8_col36)))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_7_col35))),
                    ((((((unpacked_limb_7_col15) * (mul_res_limb_11_col39))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_10_col38)))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_9_col37)))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_8_col36)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_7_col35))),
                    (((((((unpacked_limb_7_col15) * (mul_res_limb_12_col40))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_11_col39)))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_10_col38)))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_9_col37)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_8_col36)))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_7_col35))),
                    ((((((((unpacked_limb_7_col15) * (mul_res_limb_13_col41))
                        + ((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_12_col40)))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_11_col39)))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_10_col38)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_9_col37)))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_8_col36)))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_7_col35))),
                    (((((((unpacked_tmp_fec87_1.get_m31(8)) * (mul_res_limb_13_col41))
                        + ((unpacked_limb_9_col16) * (mul_res_limb_12_col40)))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_11_col39)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_10_col38)))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_9_col37)))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_8_col36))),
                    ((((((unpacked_limb_9_col16) * (mul_res_limb_13_col41))
                        + ((unpacked_limb_10_col17) * (mul_res_limb_12_col40)))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_11_col39)))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_10_col38)))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_9_col37))),
                    (((((unpacked_limb_10_col17) * (mul_res_limb_13_col41))
                        + ((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_12_col40)))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_11_col39)))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_10_col38))),
                    ((((unpacked_tmp_fec87_1.get_m31(11)) * (mul_res_limb_13_col41))
                        + ((unpacked_limb_12_col18) * (mul_res_limb_12_col40)))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_11_col39))),
                    (((unpacked_limb_12_col18) * (mul_res_limb_13_col41))
                        + ((unpacked_limb_13_col19) * (mul_res_limb_12_col40))),
                    ((unpacked_limb_13_col19) * (mul_res_limb_13_col41)),
                ];
                let x_sum_tmp_fec87_29 = [
                    ((unpacked_limb_0_col10) + (unpacked_limb_7_col15)),
                    ((unpacked_limb_1_col11) + (unpacked_tmp_fec87_1.get_m31(8))),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_9_col16)),
                    ((unpacked_limb_3_col12) + (unpacked_limb_10_col17)),
                    ((unpacked_limb_4_col13) + (unpacked_tmp_fec87_1.get_m31(11))),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_12_col18)),
                    ((unpacked_limb_6_col14) + (unpacked_limb_13_col19)),
                ];
                let y_sum_tmp_fec87_30 = [
                    ((mul_res_limb_0_col28) + (mul_res_limb_7_col35)),
                    ((mul_res_limb_1_col29) + (mul_res_limb_8_col36)),
                    ((mul_res_limb_2_col30) + (mul_res_limb_9_col37)),
                    ((mul_res_limb_3_col31) + (mul_res_limb_10_col38)),
                    ((mul_res_limb_4_col32) + (mul_res_limb_11_col39)),
                    ((mul_res_limb_5_col33) + (mul_res_limb_12_col40)),
                    ((mul_res_limb_6_col34) + (mul_res_limb_13_col41)),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_31 = [
                    z0_tmp_fec87_27[0],
                    z0_tmp_fec87_27[1],
                    z0_tmp_fec87_27[2],
                    z0_tmp_fec87_27[3],
                    z0_tmp_fec87_27[4],
                    z0_tmp_fec87_27[5],
                    z0_tmp_fec87_27[6],
                    ((z0_tmp_fec87_27[7])
                        + ((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[0]))
                            - (z0_tmp_fec87_27[0]))
                            - (z2_tmp_fec87_28[0]))),
                    ((z0_tmp_fec87_27[8])
                        + (((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[1]))
                            + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[0])))
                            - (z0_tmp_fec87_27[1]))
                            - (z2_tmp_fec87_28[1]))),
                    ((z0_tmp_fec87_27[9])
                        + ((((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[2]))
                            + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[1])))
                            + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[0])))
                            - (z0_tmp_fec87_27[2]))
                            - (z2_tmp_fec87_28[2]))),
                    ((z0_tmp_fec87_27[10])
                        + (((((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[3]))
                            + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[2])))
                            + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[1])))
                            + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[0])))
                            - (z0_tmp_fec87_27[3]))
                            - (z2_tmp_fec87_28[3]))),
                    ((z0_tmp_fec87_27[11])
                        + ((((((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[4]))
                            + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[3])))
                            + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[2])))
                            + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[1])))
                            + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[0])))
                            - (z0_tmp_fec87_27[4]))
                            - (z2_tmp_fec87_28[4]))),
                    ((z0_tmp_fec87_27[12])
                        + (((((((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[5]))
                            + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[4])))
                            + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[3])))
                            + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[2])))
                            + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[1])))
                            + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[0])))
                            - (z0_tmp_fec87_27[5]))
                            - (z2_tmp_fec87_28[5]))),
                    ((((((((((x_sum_tmp_fec87_29[0]) * (y_sum_tmp_fec87_30[6]))
                        + ((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[5])))
                        + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[4])))
                        + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[3])))
                        + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[2])))
                        + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[1])))
                        + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[0])))
                        - (z0_tmp_fec87_27[6]))
                        - (z2_tmp_fec87_28[6])),
                    ((z2_tmp_fec87_28[0])
                        + (((((((((x_sum_tmp_fec87_29[1]) * (y_sum_tmp_fec87_30[6]))
                            + ((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[5])))
                            + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[4])))
                            + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[3])))
                            + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[2])))
                            + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[1])))
                            - (z0_tmp_fec87_27[7]))
                            - (z2_tmp_fec87_28[7]))),
                    ((z2_tmp_fec87_28[1])
                        + ((((((((x_sum_tmp_fec87_29[2]) * (y_sum_tmp_fec87_30[6]))
                            + ((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[5])))
                            + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[4])))
                            + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[3])))
                            + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[2])))
                            - (z0_tmp_fec87_27[8]))
                            - (z2_tmp_fec87_28[8]))),
                    ((z2_tmp_fec87_28[2])
                        + (((((((x_sum_tmp_fec87_29[3]) * (y_sum_tmp_fec87_30[6]))
                            + ((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[5])))
                            + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[4])))
                            + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[3])))
                            - (z0_tmp_fec87_27[9]))
                            - (z2_tmp_fec87_28[9]))),
                    ((z2_tmp_fec87_28[3])
                        + ((((((x_sum_tmp_fec87_29[4]) * (y_sum_tmp_fec87_30[6]))
                            + ((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[5])))
                            + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[4])))
                            - (z0_tmp_fec87_27[10]))
                            - (z2_tmp_fec87_28[10]))),
                    ((z2_tmp_fec87_28[4])
                        + (((((x_sum_tmp_fec87_29[5]) * (y_sum_tmp_fec87_30[6]))
                            + ((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[5])))
                            - (z0_tmp_fec87_27[11]))
                            - (z2_tmp_fec87_28[11]))),
                    ((z2_tmp_fec87_28[5])
                        + ((((x_sum_tmp_fec87_29[6]) * (y_sum_tmp_fec87_30[6]))
                            - (z0_tmp_fec87_27[12]))
                            - (z2_tmp_fec87_28[12]))),
                    z2_tmp_fec87_28[6],
                    z2_tmp_fec87_28[7],
                    z2_tmp_fec87_28[8],
                    z2_tmp_fec87_28[9],
                    z2_tmp_fec87_28[10],
                    z2_tmp_fec87_28[11],
                    z2_tmp_fec87_28[12],
                ];

                // Single Karatsuba N 7.

                let z0_tmp_fec87_32 = [
                    ((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_14_col42)),
                    (((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_15_col43))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_14_col42))),
                    ((((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_16_col44))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_15_col43)))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_14_col42))),
                    (((((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_17_col45))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_16_col44)))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_15_col43)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_14_col42))),
                    ((((((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_18_col46))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_17_col45)))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_16_col44)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_15_col43)))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_14_col42))),
                    (((((((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_19_col47))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_18_col46)))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_17_col45)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_16_col44)))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_15_col43)))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_14_col42))),
                    ((((((((unpacked_tmp_fec87_1.get_m31(14)) * (mul_res_limb_20_col48))
                        + ((unpacked_limb_15_col20) * (mul_res_limb_19_col47)))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_18_col46)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_17_col45)))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_16_col44)))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_15_col43)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_14_col42))),
                    (((((((unpacked_limb_15_col20) * (mul_res_limb_20_col48))
                        + ((unpacked_limb_16_col21) * (mul_res_limb_19_col47)))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_18_col46)))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_17_col45)))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_16_col44)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_15_col43))),
                    ((((((unpacked_limb_16_col21) * (mul_res_limb_20_col48))
                        + ((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_19_col47)))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_18_col46)))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_17_col45)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_16_col44))),
                    (((((unpacked_tmp_fec87_1.get_m31(17)) * (mul_res_limb_20_col48))
                        + ((unpacked_limb_18_col22) * (mul_res_limb_19_col47)))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_18_col46)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_17_col45))),
                    ((((unpacked_limb_18_col22) * (mul_res_limb_20_col48))
                        + ((unpacked_limb_19_col23) * (mul_res_limb_19_col47)))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_18_col46))),
                    (((unpacked_limb_19_col23) * (mul_res_limb_20_col48))
                        + ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_19_col47))),
                    ((unpacked_tmp_fec87_1.get_m31(20)) * (mul_res_limb_20_col48)),
                ];
                let z2_tmp_fec87_33 = [
                    ((unpacked_limb_21_col24) * (mul_res_limb_21_col49)),
                    (((unpacked_limb_21_col24) * (mul_res_limb_22_col50))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_21_col49))),
                    ((((unpacked_limb_21_col24) * (mul_res_limb_23_col51))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_22_col50)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_21_col49))),
                    (((((unpacked_limb_21_col24) * (mul_res_limb_24_col52))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_23_col51)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_22_col50)))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_21_col49))),
                    ((((((unpacked_limb_21_col24) * (mul_res_limb_25_col53))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_24_col52)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_23_col51)))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_22_col50)))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_21_col49))),
                    (((((((unpacked_limb_21_col24) * (mul_res_limb_26_col54))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_25_col53)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_24_col52)))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_23_col51)))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_22_col50)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_21_col49))),
                    ((((((((unpacked_limb_21_col24) * (mul_res_limb_27_col55))
                        + ((unpacked_limb_22_col25) * (mul_res_limb_26_col54)))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_25_col53)))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_24_col52)))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_23_col51)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_22_col50)))
                        + ((input_limb_9_col9) * (mul_res_limb_21_col49))),
                    (((((((unpacked_limb_22_col25) * (mul_res_limb_27_col55))
                        + ((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_26_col54)))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_25_col53)))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_24_col52)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_23_col51)))
                        + ((input_limb_9_col9) * (mul_res_limb_22_col50))),
                    ((((((unpacked_tmp_fec87_1.get_m31(23)) * (mul_res_limb_27_col55))
                        + ((unpacked_limb_24_col26) * (mul_res_limb_26_col54)))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_25_col53)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_24_col52)))
                        + ((input_limb_9_col9) * (mul_res_limb_23_col51))),
                    (((((unpacked_limb_24_col26) * (mul_res_limb_27_col55))
                        + ((unpacked_limb_25_col27) * (mul_res_limb_26_col54)))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_25_col53)))
                        + ((input_limb_9_col9) * (mul_res_limb_24_col52))),
                    ((((unpacked_limb_25_col27) * (mul_res_limb_27_col55))
                        + ((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_26_col54)))
                        + ((input_limb_9_col9) * (mul_res_limb_25_col53))),
                    (((unpacked_tmp_fec87_1.get_m31(26)) * (mul_res_limb_27_col55))
                        + ((input_limb_9_col9) * (mul_res_limb_26_col54))),
                    ((input_limb_9_col9) * (mul_res_limb_27_col55)),
                ];
                let x_sum_tmp_fec87_34 = [
                    ((unpacked_tmp_fec87_1.get_m31(14)) + (unpacked_limb_21_col24)),
                    ((unpacked_limb_15_col20) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_16_col21) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_tmp_fec87_1.get_m31(17)) + (unpacked_limb_24_col26)),
                    ((unpacked_limb_18_col22) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_19_col23) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_tmp_fec87_1.get_m31(20)) + (input_limb_9_col9)),
                ];
                let y_sum_tmp_fec87_35 = [
                    ((mul_res_limb_14_col42) + (mul_res_limb_21_col49)),
                    ((mul_res_limb_15_col43) + (mul_res_limb_22_col50)),
                    ((mul_res_limb_16_col44) + (mul_res_limb_23_col51)),
                    ((mul_res_limb_17_col45) + (mul_res_limb_24_col52)),
                    ((mul_res_limb_18_col46) + (mul_res_limb_25_col53)),
                    ((mul_res_limb_19_col47) + (mul_res_limb_26_col54)),
                    ((mul_res_limb_20_col48) + (mul_res_limb_27_col55)),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_36 = [
                    z0_tmp_fec87_32[0],
                    z0_tmp_fec87_32[1],
                    z0_tmp_fec87_32[2],
                    z0_tmp_fec87_32[3],
                    z0_tmp_fec87_32[4],
                    z0_tmp_fec87_32[5],
                    z0_tmp_fec87_32[6],
                    ((z0_tmp_fec87_32[7])
                        + ((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[0]))
                            - (z0_tmp_fec87_32[0]))
                            - (z2_tmp_fec87_33[0]))),
                    ((z0_tmp_fec87_32[8])
                        + (((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[1]))
                            + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[0])))
                            - (z0_tmp_fec87_32[1]))
                            - (z2_tmp_fec87_33[1]))),
                    ((z0_tmp_fec87_32[9])
                        + ((((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[2]))
                            + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[1])))
                            + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[0])))
                            - (z0_tmp_fec87_32[2]))
                            - (z2_tmp_fec87_33[2]))),
                    ((z0_tmp_fec87_32[10])
                        + (((((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[3]))
                            + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[2])))
                            + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[1])))
                            + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[0])))
                            - (z0_tmp_fec87_32[3]))
                            - (z2_tmp_fec87_33[3]))),
                    ((z0_tmp_fec87_32[11])
                        + ((((((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[4]))
                            + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[3])))
                            + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[2])))
                            + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[1])))
                            + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[0])))
                            - (z0_tmp_fec87_32[4]))
                            - (z2_tmp_fec87_33[4]))),
                    ((z0_tmp_fec87_32[12])
                        + (((((((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[5]))
                            + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[4])))
                            + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[3])))
                            + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[2])))
                            + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[1])))
                            + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[0])))
                            - (z0_tmp_fec87_32[5]))
                            - (z2_tmp_fec87_33[5]))),
                    ((((((((((x_sum_tmp_fec87_34[0]) * (y_sum_tmp_fec87_35[6]))
                        + ((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[5])))
                        + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[4])))
                        + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[3])))
                        + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[2])))
                        + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[1])))
                        + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[0])))
                        - (z0_tmp_fec87_32[6]))
                        - (z2_tmp_fec87_33[6])),
                    ((z2_tmp_fec87_33[0])
                        + (((((((((x_sum_tmp_fec87_34[1]) * (y_sum_tmp_fec87_35[6]))
                            + ((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[5])))
                            + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[4])))
                            + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[3])))
                            + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[2])))
                            + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[1])))
                            - (z0_tmp_fec87_32[7]))
                            - (z2_tmp_fec87_33[7]))),
                    ((z2_tmp_fec87_33[1])
                        + ((((((((x_sum_tmp_fec87_34[2]) * (y_sum_tmp_fec87_35[6]))
                            + ((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[5])))
                            + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[4])))
                            + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[3])))
                            + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[2])))
                            - (z0_tmp_fec87_32[8]))
                            - (z2_tmp_fec87_33[8]))),
                    ((z2_tmp_fec87_33[2])
                        + (((((((x_sum_tmp_fec87_34[3]) * (y_sum_tmp_fec87_35[6]))
                            + ((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[5])))
                            + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[4])))
                            + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[3])))
                            - (z0_tmp_fec87_32[9]))
                            - (z2_tmp_fec87_33[9]))),
                    ((z2_tmp_fec87_33[3])
                        + ((((((x_sum_tmp_fec87_34[4]) * (y_sum_tmp_fec87_35[6]))
                            + ((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[5])))
                            + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[4])))
                            - (z0_tmp_fec87_32[10]))
                            - (z2_tmp_fec87_33[10]))),
                    ((z2_tmp_fec87_33[4])
                        + (((((x_sum_tmp_fec87_34[5]) * (y_sum_tmp_fec87_35[6]))
                            + ((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[5])))
                            - (z0_tmp_fec87_32[11]))
                            - (z2_tmp_fec87_33[11]))),
                    ((z2_tmp_fec87_33[5])
                        + ((((x_sum_tmp_fec87_34[6]) * (y_sum_tmp_fec87_35[6]))
                            - (z0_tmp_fec87_32[12]))
                            - (z2_tmp_fec87_33[12]))),
                    z2_tmp_fec87_33[6],
                    z2_tmp_fec87_33[7],
                    z2_tmp_fec87_33[8],
                    z2_tmp_fec87_33[9],
                    z2_tmp_fec87_33[10],
                    z2_tmp_fec87_33[11],
                    z2_tmp_fec87_33[12],
                ];

                let x_sum_tmp_fec87_37 = [
                    ((unpacked_limb_0_col10) + (unpacked_tmp_fec87_1.get_m31(14))),
                    ((unpacked_limb_1_col11) + (unpacked_limb_15_col20)),
                    ((unpacked_tmp_fec87_1.get_m31(2)) + (unpacked_limb_16_col21)),
                    ((unpacked_limb_3_col12) + (unpacked_tmp_fec87_1.get_m31(17))),
                    ((unpacked_limb_4_col13) + (unpacked_limb_18_col22)),
                    ((unpacked_tmp_fec87_1.get_m31(5)) + (unpacked_limb_19_col23)),
                    ((unpacked_limb_6_col14) + (unpacked_tmp_fec87_1.get_m31(20))),
                    ((unpacked_limb_7_col15) + (unpacked_limb_21_col24)),
                    ((unpacked_tmp_fec87_1.get_m31(8)) + (unpacked_limb_22_col25)),
                    ((unpacked_limb_9_col16) + (unpacked_tmp_fec87_1.get_m31(23))),
                    ((unpacked_limb_10_col17) + (unpacked_limb_24_col26)),
                    ((unpacked_tmp_fec87_1.get_m31(11)) + (unpacked_limb_25_col27)),
                    ((unpacked_limb_12_col18) + (unpacked_tmp_fec87_1.get_m31(26))),
                    ((unpacked_limb_13_col19) + (input_limb_9_col9)),
                ];
                let y_sum_tmp_fec87_38 = [
                    ((mul_res_limb_0_col28) + (mul_res_limb_14_col42)),
                    ((mul_res_limb_1_col29) + (mul_res_limb_15_col43)),
                    ((mul_res_limb_2_col30) + (mul_res_limb_16_col44)),
                    ((mul_res_limb_3_col31) + (mul_res_limb_17_col45)),
                    ((mul_res_limb_4_col32) + (mul_res_limb_18_col46)),
                    ((mul_res_limb_5_col33) + (mul_res_limb_19_col47)),
                    ((mul_res_limb_6_col34) + (mul_res_limb_20_col48)),
                    ((mul_res_limb_7_col35) + (mul_res_limb_21_col49)),
                    ((mul_res_limb_8_col36) + (mul_res_limb_22_col50)),
                    ((mul_res_limb_9_col37) + (mul_res_limb_23_col51)),
                    ((mul_res_limb_10_col38) + (mul_res_limb_24_col52)),
                    ((mul_res_limb_11_col39) + (mul_res_limb_25_col53)),
                    ((mul_res_limb_12_col40) + (mul_res_limb_26_col54)),
                    ((mul_res_limb_13_col41) + (mul_res_limb_27_col55)),
                ];

                // Single Karatsuba N 7.

                let z0_tmp_fec87_39 = [
                    ((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[0])),
                    (((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[1]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[0]))),
                    ((((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[2]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[1])))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[0]))),
                    (((((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[3]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[2])))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[1])))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[0]))),
                    ((((((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[4]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[3])))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[2])))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[1])))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[0]))),
                    (((((((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[5]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[4])))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[3])))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[2])))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[1])))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[0]))),
                    ((((((((x_sum_tmp_fec87_37[0]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[5])))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[4])))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[3])))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[2])))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[1])))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[0]))),
                    (((((((x_sum_tmp_fec87_37[1]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[5])))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[4])))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[3])))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[2])))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[1]))),
                    ((((((x_sum_tmp_fec87_37[2]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[5])))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[4])))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[3])))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[2]))),
                    (((((x_sum_tmp_fec87_37[3]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[5])))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[4])))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[3]))),
                    ((((x_sum_tmp_fec87_37[4]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[5])))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[4]))),
                    (((x_sum_tmp_fec87_37[5]) * (y_sum_tmp_fec87_38[6]))
                        + ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[5]))),
                    ((x_sum_tmp_fec87_37[6]) * (y_sum_tmp_fec87_38[6])),
                ];
                let z2_tmp_fec87_40 = [
                    ((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[7])),
                    (((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[8]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[7]))),
                    ((((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[9]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[8])))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[7]))),
                    (((((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[10]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[9])))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[8])))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[7]))),
                    ((((((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[11]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[10])))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[9])))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[8])))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[7]))),
                    (((((((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[12]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[11])))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[10])))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[9])))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[8])))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[7]))),
                    ((((((((x_sum_tmp_fec87_37[7]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[12])))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[11])))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[10])))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[9])))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[8])))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[7]))),
                    (((((((x_sum_tmp_fec87_37[8]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[12])))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[11])))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[10])))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[9])))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[8]))),
                    ((((((x_sum_tmp_fec87_37[9]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[12])))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[11])))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[10])))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[9]))),
                    (((((x_sum_tmp_fec87_37[10]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[12])))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[11])))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[10]))),
                    ((((x_sum_tmp_fec87_37[11]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[12])))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[11]))),
                    (((x_sum_tmp_fec87_37[12]) * (y_sum_tmp_fec87_38[13]))
                        + ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[12]))),
                    ((x_sum_tmp_fec87_37[13]) * (y_sum_tmp_fec87_38[13])),
                ];
                let x_sum_tmp_fec87_41 = [
                    ((x_sum_tmp_fec87_37[0]) + (x_sum_tmp_fec87_37[7])),
                    ((x_sum_tmp_fec87_37[1]) + (x_sum_tmp_fec87_37[8])),
                    ((x_sum_tmp_fec87_37[2]) + (x_sum_tmp_fec87_37[9])),
                    ((x_sum_tmp_fec87_37[3]) + (x_sum_tmp_fec87_37[10])),
                    ((x_sum_tmp_fec87_37[4]) + (x_sum_tmp_fec87_37[11])),
                    ((x_sum_tmp_fec87_37[5]) + (x_sum_tmp_fec87_37[12])),
                    ((x_sum_tmp_fec87_37[6]) + (x_sum_tmp_fec87_37[13])),
                ];
                let y_sum_tmp_fec87_42 = [
                    ((y_sum_tmp_fec87_38[0]) + (y_sum_tmp_fec87_38[7])),
                    ((y_sum_tmp_fec87_38[1]) + (y_sum_tmp_fec87_38[8])),
                    ((y_sum_tmp_fec87_38[2]) + (y_sum_tmp_fec87_38[9])),
                    ((y_sum_tmp_fec87_38[3]) + (y_sum_tmp_fec87_38[10])),
                    ((y_sum_tmp_fec87_38[4]) + (y_sum_tmp_fec87_38[11])),
                    ((y_sum_tmp_fec87_38[5]) + (y_sum_tmp_fec87_38[12])),
                    ((y_sum_tmp_fec87_38[6]) + (y_sum_tmp_fec87_38[13])),
                ];
                let single_karatsuba_n_7_output_tmp_fec87_43 = [
                    z0_tmp_fec87_39[0],
                    z0_tmp_fec87_39[1],
                    z0_tmp_fec87_39[2],
                    z0_tmp_fec87_39[3],
                    z0_tmp_fec87_39[4],
                    z0_tmp_fec87_39[5],
                    z0_tmp_fec87_39[6],
                    ((z0_tmp_fec87_39[7])
                        + ((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[0]))
                            - (z0_tmp_fec87_39[0]))
                            - (z2_tmp_fec87_40[0]))),
                    ((z0_tmp_fec87_39[8])
                        + (((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[1]))
                            + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[0])))
                            - (z0_tmp_fec87_39[1]))
                            - (z2_tmp_fec87_40[1]))),
                    ((z0_tmp_fec87_39[9])
                        + ((((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[2]))
                            + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[1])))
                            + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[0])))
                            - (z0_tmp_fec87_39[2]))
                            - (z2_tmp_fec87_40[2]))),
                    ((z0_tmp_fec87_39[10])
                        + (((((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[3]))
                            + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[2])))
                            + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[1])))
                            + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[0])))
                            - (z0_tmp_fec87_39[3]))
                            - (z2_tmp_fec87_40[3]))),
                    ((z0_tmp_fec87_39[11])
                        + ((((((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[4]))
                            + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[3])))
                            + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[2])))
                            + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[1])))
                            + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[0])))
                            - (z0_tmp_fec87_39[4]))
                            - (z2_tmp_fec87_40[4]))),
                    ((z0_tmp_fec87_39[12])
                        + (((((((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[5]))
                            + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[4])))
                            + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[3])))
                            + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[2])))
                            + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[1])))
                            + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[0])))
                            - (z0_tmp_fec87_39[5]))
                            - (z2_tmp_fec87_40[5]))),
                    ((((((((((x_sum_tmp_fec87_41[0]) * (y_sum_tmp_fec87_42[6]))
                        + ((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[5])))
                        + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[4])))
                        + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[3])))
                        + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[2])))
                        + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[1])))
                        + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[0])))
                        - (z0_tmp_fec87_39[6]))
                        - (z2_tmp_fec87_40[6])),
                    ((z2_tmp_fec87_40[0])
                        + (((((((((x_sum_tmp_fec87_41[1]) * (y_sum_tmp_fec87_42[6]))
                            + ((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[5])))
                            + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[4])))
                            + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[3])))
                            + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[2])))
                            + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[1])))
                            - (z0_tmp_fec87_39[7]))
                            - (z2_tmp_fec87_40[7]))),
                    ((z2_tmp_fec87_40[1])
                        + ((((((((x_sum_tmp_fec87_41[2]) * (y_sum_tmp_fec87_42[6]))
                            + ((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[5])))
                            + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[4])))
                            + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[3])))
                            + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[2])))
                            - (z0_tmp_fec87_39[8]))
                            - (z2_tmp_fec87_40[8]))),
                    ((z2_tmp_fec87_40[2])
                        + (((((((x_sum_tmp_fec87_41[3]) * (y_sum_tmp_fec87_42[6]))
                            + ((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[5])))
                            + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[4])))
                            + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[3])))
                            - (z0_tmp_fec87_39[9]))
                            - (z2_tmp_fec87_40[9]))),
                    ((z2_tmp_fec87_40[3])
                        + ((((((x_sum_tmp_fec87_41[4]) * (y_sum_tmp_fec87_42[6]))
                            + ((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[5])))
                            + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[4])))
                            - (z0_tmp_fec87_39[10]))
                            - (z2_tmp_fec87_40[10]))),
                    ((z2_tmp_fec87_40[4])
                        + (((((x_sum_tmp_fec87_41[5]) * (y_sum_tmp_fec87_42[6]))
                            + ((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[5])))
                            - (z0_tmp_fec87_39[11]))
                            - (z2_tmp_fec87_40[11]))),
                    ((z2_tmp_fec87_40[5])
                        + ((((x_sum_tmp_fec87_41[6]) * (y_sum_tmp_fec87_42[6]))
                            - (z0_tmp_fec87_39[12]))
                            - (z2_tmp_fec87_40[12]))),
                    z2_tmp_fec87_40[6],
                    z2_tmp_fec87_40[7],
                    z2_tmp_fec87_40[8],
                    z2_tmp_fec87_40[9],
                    z2_tmp_fec87_40[10],
                    z2_tmp_fec87_40[11],
                    z2_tmp_fec87_40[12],
                ];

                let double_karatsuba_1454b_output_tmp_fec87_44 = [
                    single_karatsuba_n_7_output_tmp_fec87_31[0],
                    single_karatsuba_n_7_output_tmp_fec87_31[1],
                    single_karatsuba_n_7_output_tmp_fec87_31[2],
                    single_karatsuba_n_7_output_tmp_fec87_31[3],
                    single_karatsuba_n_7_output_tmp_fec87_31[4],
                    single_karatsuba_n_7_output_tmp_fec87_31[5],
                    single_karatsuba_n_7_output_tmp_fec87_31[6],
                    single_karatsuba_n_7_output_tmp_fec87_31[7],
                    single_karatsuba_n_7_output_tmp_fec87_31[8],
                    single_karatsuba_n_7_output_tmp_fec87_31[9],
                    single_karatsuba_n_7_output_tmp_fec87_31[10],
                    single_karatsuba_n_7_output_tmp_fec87_31[11],
                    single_karatsuba_n_7_output_tmp_fec87_31[12],
                    single_karatsuba_n_7_output_tmp_fec87_31[13],
                    ((single_karatsuba_n_7_output_tmp_fec87_31[14])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[0])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[0]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[0]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[15])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[1])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[1]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[1]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[16])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[2])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[2]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[2]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[17])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[3])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[3]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[3]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[18])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[4])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[4]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[4]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[19])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[5])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[5]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[5]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[20])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[6])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[6]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[6]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[21])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[7])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[7]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[7]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[22])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[8])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[8]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[8]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[23])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[9])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[9]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[9]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[24])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[10])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[10]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[10]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[25])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[11])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[11]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[11]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_31[26])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[12])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[12]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[12]))),
                    (((single_karatsuba_n_7_output_tmp_fec87_43[13])
                        - (single_karatsuba_n_7_output_tmp_fec87_31[13]))
                        - (single_karatsuba_n_7_output_tmp_fec87_36[13])),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[0])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[14])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[14]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[14]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[1])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[15])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[15]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[15]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[2])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[16])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[16]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[16]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[3])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[17])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[17]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[17]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[4])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[18])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[18]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[18]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[5])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[19])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[19]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[19]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[6])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[20])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[20]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[20]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[7])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[21])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[21]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[21]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[8])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[22])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[22]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[22]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[9])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[23])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[23]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[23]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[10])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[24])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[24]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[24]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[11])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[25])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[25]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[25]))),
                    ((single_karatsuba_n_7_output_tmp_fec87_36[12])
                        + (((single_karatsuba_n_7_output_tmp_fec87_43[26])
                            - (single_karatsuba_n_7_output_tmp_fec87_31[26]))
                            - (single_karatsuba_n_7_output_tmp_fec87_36[26]))),
                    single_karatsuba_n_7_output_tmp_fec87_36[13],
                    single_karatsuba_n_7_output_tmp_fec87_36[14],
                    single_karatsuba_n_7_output_tmp_fec87_36[15],
                    single_karatsuba_n_7_output_tmp_fec87_36[16],
                    single_karatsuba_n_7_output_tmp_fec87_36[17],
                    single_karatsuba_n_7_output_tmp_fec87_36[18],
                    single_karatsuba_n_7_output_tmp_fec87_36[19],
                    single_karatsuba_n_7_output_tmp_fec87_36[20],
                    single_karatsuba_n_7_output_tmp_fec87_36[21],
                    single_karatsuba_n_7_output_tmp_fec87_36[22],
                    single_karatsuba_n_7_output_tmp_fec87_36[23],
                    single_karatsuba_n_7_output_tmp_fec87_36[24],
                    single_karatsuba_n_7_output_tmp_fec87_36[25],
                    single_karatsuba_n_7_output_tmp_fec87_36[26],
                ];

                let conv_tmp_fec87_45 = [
                    ((double_karatsuba_1454b_output_tmp_fec87_44[0]) - (mul_res_limb_0_col84)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[1]) - (mul_res_limb_1_col85)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[2]) - (mul_res_limb_2_col86)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[3]) - (mul_res_limb_3_col87)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[4]) - (mul_res_limb_4_col88)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[5]) - (mul_res_limb_5_col89)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[6]) - (mul_res_limb_6_col90)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[7]) - (mul_res_limb_7_col91)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[8]) - (mul_res_limb_8_col92)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[9]) - (mul_res_limb_9_col93)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[10]) - (mul_res_limb_10_col94)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[11]) - (mul_res_limb_11_col95)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[12]) - (mul_res_limb_12_col96)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[13]) - (mul_res_limb_13_col97)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[14]) - (mul_res_limb_14_col98)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[15]) - (mul_res_limb_15_col99)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[16]) - (mul_res_limb_16_col100)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[17]) - (mul_res_limb_17_col101)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[18]) - (mul_res_limb_18_col102)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[19]) - (mul_res_limb_19_col103)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[20]) - (mul_res_limb_20_col104)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[21]) - (mul_res_limb_21_col105)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[22]) - (mul_res_limb_22_col106)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[23]) - (mul_res_limb_23_col107)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[24]) - (mul_res_limb_24_col108)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[25]) - (mul_res_limb_25_col109)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[26]) - (mul_res_limb_26_col110)),
                    ((double_karatsuba_1454b_output_tmp_fec87_44[27]) - (mul_res_limb_27_col111)),
                    double_karatsuba_1454b_output_tmp_fec87_44[28],
                    double_karatsuba_1454b_output_tmp_fec87_44[29],
                    double_karatsuba_1454b_output_tmp_fec87_44[30],
                    double_karatsuba_1454b_output_tmp_fec87_44[31],
                    double_karatsuba_1454b_output_tmp_fec87_44[32],
                    double_karatsuba_1454b_output_tmp_fec87_44[33],
                    double_karatsuba_1454b_output_tmp_fec87_44[34],
                    double_karatsuba_1454b_output_tmp_fec87_44[35],
                    double_karatsuba_1454b_output_tmp_fec87_44[36],
                    double_karatsuba_1454b_output_tmp_fec87_44[37],
                    double_karatsuba_1454b_output_tmp_fec87_44[38],
                    double_karatsuba_1454b_output_tmp_fec87_44[39],
                    double_karatsuba_1454b_output_tmp_fec87_44[40],
                    double_karatsuba_1454b_output_tmp_fec87_44[41],
                    double_karatsuba_1454b_output_tmp_fec87_44[42],
                    double_karatsuba_1454b_output_tmp_fec87_44[43],
                    double_karatsuba_1454b_output_tmp_fec87_44[44],
                    double_karatsuba_1454b_output_tmp_fec87_44[45],
                    double_karatsuba_1454b_output_tmp_fec87_44[46],
                    double_karatsuba_1454b_output_tmp_fec87_44[47],
                    double_karatsuba_1454b_output_tmp_fec87_44[48],
                    double_karatsuba_1454b_output_tmp_fec87_44[49],
                    double_karatsuba_1454b_output_tmp_fec87_44[50],
                    double_karatsuba_1454b_output_tmp_fec87_44[51],
                    double_karatsuba_1454b_output_tmp_fec87_44[52],
                    double_karatsuba_1454b_output_tmp_fec87_44[53],
                    double_karatsuba_1454b_output_tmp_fec87_44[54],
                ];
                let conv_mod_tmp_fec87_46 = [
                    ((((M31_32) * (conv_tmp_fec87_45[0])) - ((M31_4) * (conv_tmp_fec87_45[21])))
                        + ((M31_8) * (conv_tmp_fec87_45[49]))),
                    ((((conv_tmp_fec87_45[0]) + ((M31_32) * (conv_tmp_fec87_45[1])))
                        - ((M31_4) * (conv_tmp_fec87_45[22])))
                        + ((M31_8) * (conv_tmp_fec87_45[50]))),
                    ((((conv_tmp_fec87_45[1]) + ((M31_32) * (conv_tmp_fec87_45[2])))
                        - ((M31_4) * (conv_tmp_fec87_45[23])))
                        + ((M31_8) * (conv_tmp_fec87_45[51]))),
                    ((((conv_tmp_fec87_45[2]) + ((M31_32) * (conv_tmp_fec87_45[3])))
                        - ((M31_4) * (conv_tmp_fec87_45[24])))
                        + ((M31_8) * (conv_tmp_fec87_45[52]))),
                    ((((conv_tmp_fec87_45[3]) + ((M31_32) * (conv_tmp_fec87_45[4])))
                        - ((M31_4) * (conv_tmp_fec87_45[25])))
                        + ((M31_8) * (conv_tmp_fec87_45[53]))),
                    ((((conv_tmp_fec87_45[4]) + ((M31_32) * (conv_tmp_fec87_45[5])))
                        - ((M31_4) * (conv_tmp_fec87_45[26])))
                        + ((M31_8) * (conv_tmp_fec87_45[54]))),
                    (((conv_tmp_fec87_45[5]) + ((M31_32) * (conv_tmp_fec87_45[6])))
                        - ((M31_4) * (conv_tmp_fec87_45[27]))),
                    (((((M31_2) * (conv_tmp_fec87_45[0])) + (conv_tmp_fec87_45[6]))
                        + ((M31_32) * (conv_tmp_fec87_45[7])))
                        - ((M31_4) * (conv_tmp_fec87_45[28]))),
                    (((((M31_2) * (conv_tmp_fec87_45[1])) + (conv_tmp_fec87_45[7]))
                        + ((M31_32) * (conv_tmp_fec87_45[8])))
                        - ((M31_4) * (conv_tmp_fec87_45[29]))),
                    (((((M31_2) * (conv_tmp_fec87_45[2])) + (conv_tmp_fec87_45[8]))
                        + ((M31_32) * (conv_tmp_fec87_45[9])))
                        - ((M31_4) * (conv_tmp_fec87_45[30]))),
                    (((((M31_2) * (conv_tmp_fec87_45[3])) + (conv_tmp_fec87_45[9]))
                        + ((M31_32) * (conv_tmp_fec87_45[10])))
                        - ((M31_4) * (conv_tmp_fec87_45[31]))),
                    (((((M31_2) * (conv_tmp_fec87_45[4])) + (conv_tmp_fec87_45[10]))
                        + ((M31_32) * (conv_tmp_fec87_45[11])))
                        - ((M31_4) * (conv_tmp_fec87_45[32]))),
                    (((((M31_2) * (conv_tmp_fec87_45[5])) + (conv_tmp_fec87_45[11]))
                        + ((M31_32) * (conv_tmp_fec87_45[12])))
                        - ((M31_4) * (conv_tmp_fec87_45[33]))),
                    (((((M31_2) * (conv_tmp_fec87_45[6])) + (conv_tmp_fec87_45[12]))
                        + ((M31_32) * (conv_tmp_fec87_45[13])))
                        - ((M31_4) * (conv_tmp_fec87_45[34]))),
                    (((((M31_2) * (conv_tmp_fec87_45[7])) + (conv_tmp_fec87_45[13]))
                        + ((M31_32) * (conv_tmp_fec87_45[14])))
                        - ((M31_4) * (conv_tmp_fec87_45[35]))),
                    (((((M31_2) * (conv_tmp_fec87_45[8])) + (conv_tmp_fec87_45[14]))
                        + ((M31_32) * (conv_tmp_fec87_45[15])))
                        - ((M31_4) * (conv_tmp_fec87_45[36]))),
                    (((((M31_2) * (conv_tmp_fec87_45[9])) + (conv_tmp_fec87_45[15]))
                        + ((M31_32) * (conv_tmp_fec87_45[16])))
                        - ((M31_4) * (conv_tmp_fec87_45[37]))),
                    (((((M31_2) * (conv_tmp_fec87_45[10])) + (conv_tmp_fec87_45[16]))
                        + ((M31_32) * (conv_tmp_fec87_45[17])))
                        - ((M31_4) * (conv_tmp_fec87_45[38]))),
                    (((((M31_2) * (conv_tmp_fec87_45[11])) + (conv_tmp_fec87_45[17]))
                        + ((M31_32) * (conv_tmp_fec87_45[18])))
                        - ((M31_4) * (conv_tmp_fec87_45[39]))),
                    (((((M31_2) * (conv_tmp_fec87_45[12])) + (conv_tmp_fec87_45[18]))
                        + ((M31_32) * (conv_tmp_fec87_45[19])))
                        - ((M31_4) * (conv_tmp_fec87_45[40]))),
                    (((((M31_2) * (conv_tmp_fec87_45[13])) + (conv_tmp_fec87_45[19]))
                        + ((M31_32) * (conv_tmp_fec87_45[20])))
                        - ((M31_4) * (conv_tmp_fec87_45[41]))),
                    (((((M31_2) * (conv_tmp_fec87_45[14])) + (conv_tmp_fec87_45[20]))
                        - ((M31_4) * (conv_tmp_fec87_45[42])))
                        + ((M31_64) * (conv_tmp_fec87_45[49]))),
                    (((((M31_2) * (conv_tmp_fec87_45[15])) - ((M31_4) * (conv_tmp_fec87_45[43])))
                        + ((M31_2) * (conv_tmp_fec87_45[49])))
                        + ((M31_64) * (conv_tmp_fec87_45[50]))),
                    (((((M31_2) * (conv_tmp_fec87_45[16])) - ((M31_4) * (conv_tmp_fec87_45[44])))
                        + ((M31_2) * (conv_tmp_fec87_45[50])))
                        + ((M31_64) * (conv_tmp_fec87_45[51]))),
                    (((((M31_2) * (conv_tmp_fec87_45[17])) - ((M31_4) * (conv_tmp_fec87_45[45])))
                        + ((M31_2) * (conv_tmp_fec87_45[51])))
                        + ((M31_64) * (conv_tmp_fec87_45[52]))),
                    (((((M31_2) * (conv_tmp_fec87_45[18])) - ((M31_4) * (conv_tmp_fec87_45[46])))
                        + ((M31_2) * (conv_tmp_fec87_45[52])))
                        + ((M31_64) * (conv_tmp_fec87_45[53]))),
                    (((((M31_2) * (conv_tmp_fec87_45[19])) - ((M31_4) * (conv_tmp_fec87_45[47])))
                        + ((M31_2) * (conv_tmp_fec87_45[53])))
                        + ((M31_64) * (conv_tmp_fec87_45[54]))),
                    ((((M31_2) * (conv_tmp_fec87_45[20])) - ((M31_4) * (conv_tmp_fec87_45[48])))
                        + ((M31_2) * (conv_tmp_fec87_45[54]))),
                ];
                let k_mod_2_18_biased_tmp_fec87_47 =
                    ((((PackedUInt32::from_m31(((conv_mod_tmp_fec87_46[0]) + (M31_134217728))))
                        + (((PackedUInt32::from_m31(
                            ((conv_mod_tmp_fec87_46[1]) + (M31_134217728)),
                        )) & (UInt32_511))
                            << (UInt32_9)))
                        + (UInt32_131072))
                        & (UInt32_262143));
                let k_col112 = ((k_mod_2_18_biased_tmp_fec87_47.low().as_m31())
                    + (((k_mod_2_18_biased_tmp_fec87_47.high().as_m31()) - (M31_2)) * (M31_65536)));
                *row[112] = k_col112;
                *sub_component_inputs.range_check_20[4] = [((k_col112) + (M31_524288))];
                *lookup_data.range_check_20_4 = [M31_1410849886, ((k_col112) + (M31_524288))];
                let carry_0_col113 = (((conv_mod_tmp_fec87_46[0]) - (k_col112)) * (M31_4194304));
                *row[113] = carry_0_col113;
                *sub_component_inputs.range_check_20_b[4] = [((carry_0_col113) + (M31_524288))];
                *lookup_data.range_check_20_b_4 =
                    [M31_514232941, ((carry_0_col113) + (M31_524288))];
                let carry_1_col114 =
                    (((conv_mod_tmp_fec87_46[1]) + (carry_0_col113)) * (M31_4194304));
                *row[114] = carry_1_col114;
                *sub_component_inputs.range_check_20_c[4] = [((carry_1_col114) + (M31_524288))];
                *lookup_data.range_check_20_c_4 =
                    [M31_531010560, ((carry_1_col114) + (M31_524288))];
                let carry_2_col115 =
                    (((conv_mod_tmp_fec87_46[2]) + (carry_1_col114)) * (M31_4194304));
                *row[115] = carry_2_col115;
                *sub_component_inputs.range_check_20_d[4] = [((carry_2_col115) + (M31_524288))];
                *lookup_data.range_check_20_d_4 =
                    [M31_480677703, ((carry_2_col115) + (M31_524288))];
                let carry_3_col116 =
                    (((conv_mod_tmp_fec87_46[3]) + (carry_2_col115)) * (M31_4194304));
                *row[116] = carry_3_col116;
                *sub_component_inputs.range_check_20_e[3] = [((carry_3_col116) + (M31_524288))];
                *lookup_data.range_check_20_e_3 =
                    [M31_497455322, ((carry_3_col116) + (M31_524288))];
                let carry_4_col117 =
                    (((conv_mod_tmp_fec87_46[4]) + (carry_3_col116)) * (M31_4194304));
                *row[117] = carry_4_col117;
                *sub_component_inputs.range_check_20_f[3] = [((carry_4_col117) + (M31_524288))];
                *lookup_data.range_check_20_f_3 =
                    [M31_447122465, ((carry_4_col117) + (M31_524288))];
                let carry_5_col118 =
                    (((conv_mod_tmp_fec87_46[5]) + (carry_4_col117)) * (M31_4194304));
                *row[118] = carry_5_col118;
                *sub_component_inputs.range_check_20_g[3] = [((carry_5_col118) + (M31_524288))];
                *lookup_data.range_check_20_g_3 =
                    [M31_463900084, ((carry_5_col118) + (M31_524288))];
                let carry_6_col119 =
                    (((conv_mod_tmp_fec87_46[6]) + (carry_5_col118)) * (M31_4194304));
                *row[119] = carry_6_col119;
                *sub_component_inputs.range_check_20_h[3] = [((carry_6_col119) + (M31_524288))];
                *lookup_data.range_check_20_h_3 =
                    [M31_682009131, ((carry_6_col119) + (M31_524288))];
                let carry_7_col120 =
                    (((conv_mod_tmp_fec87_46[7]) + (carry_6_col119)) * (M31_4194304));
                *row[120] = carry_7_col120;
                *sub_component_inputs.range_check_20[5] = [((carry_7_col120) + (M31_524288))];
                *lookup_data.range_check_20_5 = [M31_1410849886, ((carry_7_col120) + (M31_524288))];
                let carry_8_col121 =
                    (((conv_mod_tmp_fec87_46[8]) + (carry_7_col120)) * (M31_4194304));
                *row[121] = carry_8_col121;
                *sub_component_inputs.range_check_20_b[5] = [((carry_8_col121) + (M31_524288))];
                *lookup_data.range_check_20_b_5 =
                    [M31_514232941, ((carry_8_col121) + (M31_524288))];
                let carry_9_col122 =
                    (((conv_mod_tmp_fec87_46[9]) + (carry_8_col121)) * (M31_4194304));
                *row[122] = carry_9_col122;
                *sub_component_inputs.range_check_20_c[5] = [((carry_9_col122) + (M31_524288))];
                *lookup_data.range_check_20_c_5 =
                    [M31_531010560, ((carry_9_col122) + (M31_524288))];
                let carry_10_col123 =
                    (((conv_mod_tmp_fec87_46[10]) + (carry_9_col122)) * (M31_4194304));
                *row[123] = carry_10_col123;
                *sub_component_inputs.range_check_20_d[5] = [((carry_10_col123) + (M31_524288))];
                *lookup_data.range_check_20_d_5 =
                    [M31_480677703, ((carry_10_col123) + (M31_524288))];
                let carry_11_col124 =
                    (((conv_mod_tmp_fec87_46[11]) + (carry_10_col123)) * (M31_4194304));
                *row[124] = carry_11_col124;
                *sub_component_inputs.range_check_20_e[4] = [((carry_11_col124) + (M31_524288))];
                *lookup_data.range_check_20_e_4 =
                    [M31_497455322, ((carry_11_col124) + (M31_524288))];
                let carry_12_col125 =
                    (((conv_mod_tmp_fec87_46[12]) + (carry_11_col124)) * (M31_4194304));
                *row[125] = carry_12_col125;
                *sub_component_inputs.range_check_20_f[4] = [((carry_12_col125) + (M31_524288))];
                *lookup_data.range_check_20_f_4 =
                    [M31_447122465, ((carry_12_col125) + (M31_524288))];
                let carry_13_col126 =
                    (((conv_mod_tmp_fec87_46[13]) + (carry_12_col125)) * (M31_4194304));
                *row[126] = carry_13_col126;
                *sub_component_inputs.range_check_20_g[4] = [((carry_13_col126) + (M31_524288))];
                *lookup_data.range_check_20_g_4 =
                    [M31_463900084, ((carry_13_col126) + (M31_524288))];
                let carry_14_col127 =
                    (((conv_mod_tmp_fec87_46[14]) + (carry_13_col126)) * (M31_4194304));
                *row[127] = carry_14_col127;
                *sub_component_inputs.range_check_20_h[4] = [((carry_14_col127) + (M31_524288))];
                *lookup_data.range_check_20_h_4 =
                    [M31_682009131, ((carry_14_col127) + (M31_524288))];
                let carry_15_col128 =
                    (((conv_mod_tmp_fec87_46[15]) + (carry_14_col127)) * (M31_4194304));
                *row[128] = carry_15_col128;
                *sub_component_inputs.range_check_20[6] = [((carry_15_col128) + (M31_524288))];
                *lookup_data.range_check_20_6 =
                    [M31_1410849886, ((carry_15_col128) + (M31_524288))];
                let carry_16_col129 =
                    (((conv_mod_tmp_fec87_46[16]) + (carry_15_col128)) * (M31_4194304));
                *row[129] = carry_16_col129;
                *sub_component_inputs.range_check_20_b[6] = [((carry_16_col129) + (M31_524288))];
                *lookup_data.range_check_20_b_6 =
                    [M31_514232941, ((carry_16_col129) + (M31_524288))];
                let carry_17_col130 =
                    (((conv_mod_tmp_fec87_46[17]) + (carry_16_col129)) * (M31_4194304));
                *row[130] = carry_17_col130;
                *sub_component_inputs.range_check_20_c[6] = [((carry_17_col130) + (M31_524288))];
                *lookup_data.range_check_20_c_6 =
                    [M31_531010560, ((carry_17_col130) + (M31_524288))];
                let carry_18_col131 =
                    (((conv_mod_tmp_fec87_46[18]) + (carry_17_col130)) * (M31_4194304));
                *row[131] = carry_18_col131;
                *sub_component_inputs.range_check_20_d[6] = [((carry_18_col131) + (M31_524288))];
                *lookup_data.range_check_20_d_6 =
                    [M31_480677703, ((carry_18_col131) + (M31_524288))];
                let carry_19_col132 =
                    (((conv_mod_tmp_fec87_46[19]) + (carry_18_col131)) * (M31_4194304));
                *row[132] = carry_19_col132;
                *sub_component_inputs.range_check_20_e[5] = [((carry_19_col132) + (M31_524288))];
                *lookup_data.range_check_20_e_5 =
                    [M31_497455322, ((carry_19_col132) + (M31_524288))];
                let carry_20_col133 =
                    (((conv_mod_tmp_fec87_46[20]) + (carry_19_col132)) * (M31_4194304));
                *row[133] = carry_20_col133;
                *sub_component_inputs.range_check_20_f[5] = [((carry_20_col133) + (M31_524288))];
                *lookup_data.range_check_20_f_5 =
                    [M31_447122465, ((carry_20_col133) + (M31_524288))];
                let carry_21_col134 = ((((conv_mod_tmp_fec87_46[21]) - ((M31_136) * (k_col112)))
                    + (carry_20_col133))
                    * (M31_4194304));
                *row[134] = carry_21_col134;
                *sub_component_inputs.range_check_20_g[5] = [((carry_21_col134) + (M31_524288))];
                *lookup_data.range_check_20_g_5 =
                    [M31_463900084, ((carry_21_col134) + (M31_524288))];
                let carry_22_col135 =
                    (((conv_mod_tmp_fec87_46[22]) + (carry_21_col134)) * (M31_4194304));
                *row[135] = carry_22_col135;
                *sub_component_inputs.range_check_20_h[5] = [((carry_22_col135) + (M31_524288))];
                *lookup_data.range_check_20_h_5 =
                    [M31_682009131, ((carry_22_col135) + (M31_524288))];
                let carry_23_col136 =
                    (((conv_mod_tmp_fec87_46[23]) + (carry_22_col135)) * (M31_4194304));
                *row[136] = carry_23_col136;
                *sub_component_inputs.range_check_20[7] = [((carry_23_col136) + (M31_524288))];
                *lookup_data.range_check_20_7 =
                    [M31_1410849886, ((carry_23_col136) + (M31_524288))];
                let carry_24_col137 =
                    (((conv_mod_tmp_fec87_46[24]) + (carry_23_col136)) * (M31_4194304));
                *row[137] = carry_24_col137;
                *sub_component_inputs.range_check_20_b[7] = [((carry_24_col137) + (M31_524288))];
                *lookup_data.range_check_20_b_7 =
                    [M31_514232941, ((carry_24_col137) + (M31_524288))];
                let carry_25_col138 =
                    (((conv_mod_tmp_fec87_46[25]) + (carry_24_col137)) * (M31_4194304));
                *row[138] = carry_25_col138;
                *sub_component_inputs.range_check_20_c[7] = [((carry_25_col138) + (M31_524288))];
                *lookup_data.range_check_20_c_7 =
                    [M31_531010560, ((carry_25_col138) + (M31_524288))];
                let carry_26_col139 =
                    (((conv_mod_tmp_fec87_46[26]) + (carry_25_col138)) * (M31_4194304));
                *row[139] = carry_26_col139;
                *sub_component_inputs.range_check_20_d[7] = [((carry_26_col139) + (M31_524288))];
                *lookup_data.range_check_20_d_7 =
                    [M31_480677703, ((carry_26_col139) + (M31_524288))];

                let mul_252_output_tmp_fec87_48 = mul_res_tmp_fec87_26;

                *lookup_data.cube_252_0 = [
                    M31_1987997202,
                    input_limb_0_col0,
                    input_limb_1_col1,
                    input_limb_2_col2,
                    input_limb_3_col3,
                    input_limb_4_col4,
                    input_limb_5_col5,
                    input_limb_6_col6,
                    input_limb_7_col7,
                    input_limb_8_col8,
                    input_limb_9_col9,
                    (((mul_res_limb_0_col84) + ((mul_res_limb_1_col85) * (M31_512)))
                        + ((mul_res_limb_2_col86) * (M31_262144))),
                    (((mul_res_limb_3_col87) + ((mul_res_limb_4_col88) * (M31_512)))
                        + ((mul_res_limb_5_col89) * (M31_262144))),
                    (((mul_res_limb_6_col90) + ((mul_res_limb_7_col91) * (M31_512)))
                        + ((mul_res_limb_8_col92) * (M31_262144))),
                    (((mul_res_limb_9_col93) + ((mul_res_limb_10_col94) * (M31_512)))
                        + ((mul_res_limb_11_col95) * (M31_262144))),
                    (((mul_res_limb_12_col96) + ((mul_res_limb_13_col97) * (M31_512)))
                        + ((mul_res_limb_14_col98) * (M31_262144))),
                    (((mul_res_limb_15_col99) + ((mul_res_limb_16_col100) * (M31_512)))
                        + ((mul_res_limb_17_col101) * (M31_262144))),
                    (((mul_res_limb_18_col102) + ((mul_res_limb_19_col103) * (M31_512)))
                        + ((mul_res_limb_20_col104) * (M31_262144))),
                    (((mul_res_limb_21_col105) + ((mul_res_limb_22_col106) * (M31_512)))
                        + ((mul_res_limb_23_col107) * (M31_262144))),
                    (((mul_res_limb_24_col108) + ((mul_res_limb_25_col109) * (M31_512)))
                        + ((mul_res_limb_26_col110) * (M31_262144))),
                    mul_res_limb_27_col111,
                ];
                *row[140] = enabler_col.packed_at(row_index);
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `cube_252` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     cube_252_0[21] 0..20
//     range_check_20_0[2] 21..22
//     range_check_20_1[2] 23..24
//     range_check_20_2[2] 25..26
//     range_check_20_3[2] 27..28
//     range_check_20_4[2] 29..30
//     range_check_20_5[2] 31..32
//     range_check_20_6[2] 33..34
//     range_check_20_7[2] 35..36
//     range_check_20_b_0[2] 37..38
//     range_check_20_b_1[2] 39..40
//     range_check_20_b_2[2] 41..42
//     range_check_20_b_3[2] 43..44
//     range_check_20_b_4[2] 45..46
//     range_check_20_b_5[2] 47..48
//     range_check_20_b_6[2] 49..50
//     range_check_20_b_7[2] 51..52
//     range_check_20_c_0[2] 53..54
//     range_check_20_c_1[2] 55..56
//     range_check_20_c_2[2] 57..58
//     range_check_20_c_3[2] 59..60
//     range_check_20_c_4[2] 61..62
//     range_check_20_c_5[2] 63..64
//     range_check_20_c_6[2] 65..66
//     range_check_20_c_7[2] 67..68
//     range_check_20_d_0[2] 69..70
//     range_check_20_d_1[2] 71..72
//     range_check_20_d_2[2] 73..74
//     range_check_20_d_3[2] 75..76
//     range_check_20_d_4[2] 77..78
//     range_check_20_d_5[2] 79..80
//     range_check_20_d_6[2] 81..82
//     range_check_20_d_7[2] 83..84
//     range_check_20_e_0[2] 85..86
//     range_check_20_e_1[2] 87..88
//     range_check_20_e_2[2] 89..90
//     range_check_20_e_3[2] 91..92
//     range_check_20_e_4[2] 93..94
//     range_check_20_e_5[2] 95..96
//     range_check_20_f_0[2] 97..98
//     range_check_20_f_1[2] 99..100
//     range_check_20_f_2[2] 101..102
//     range_check_20_f_3[2] 103..104
//     range_check_20_f_4[2] 105..106
//     range_check_20_f_5[2] 107..108
//     range_check_20_g_0[2] 109..110
//     range_check_20_g_1[2] 111..112
//     range_check_20_g_2[2] 113..114
//     range_check_20_g_3[2] 115..116
//     range_check_20_g_4[2] 117..118
//     range_check_20_g_5[2] 119..120
//     range_check_20_h_0[2] 121..122
//     range_check_20_h_1[2] 123..124
//     range_check_20_h_2[2] 125..126
//     range_check_20_h_3[2] 127..128
//     range_check_20_h_4[2] 129..130
//     range_check_20_h_5[2] 131..132
//     range_check_9_9_0[3] 133..135
//     range_check_9_9_1[3] 136..138
//     range_check_9_9_2[3] 139..141
//     range_check_9_9_3[3] 142..144
//     range_check_9_9_4[3] 145..147
//     range_check_9_9_5[3] 148..150
//     range_check_9_9_b_0[3] 151..153
//     range_check_9_9_b_1[3] 154..156
//     range_check_9_9_b_2[3] 157..159
//     range_check_9_9_b_3[3] 160..162
//     range_check_9_9_b_4[3] 163..165
//     range_check_9_9_b_5[3] 166..168
//     range_check_9_9_c_0[3] 169..171
//     range_check_9_9_c_1[3] 172..174
//     range_check_9_9_c_2[3] 175..177
//     range_check_9_9_c_3[3] 178..180
//     range_check_9_9_c_4[3] 181..183
//     range_check_9_9_c_5[3] 184..186
//     range_check_9_9_d_0[3] 187..189
//     range_check_9_9_d_1[3] 190..192
//     range_check_9_9_d_2[3] 193..195
//     range_check_9_9_d_3[3] 196..198
//     range_check_9_9_d_4[3] 199..201
//     range_check_9_9_d_5[3] 202..204
//     range_check_9_9_e_0[3] 205..207
//     range_check_9_9_e_1[3] 208..210
//     range_check_9_9_e_2[3] 211..213
//     range_check_9_9_e_3[3] 214..216
//     range_check_9_9_e_4[3] 217..219
//     range_check_9_9_e_5[3] 220..222
//     range_check_9_9_f_0[3] 223..225
//     range_check_9_9_f_1[3] 226..228
//     range_check_9_9_f_2[3] 229..231
//     range_check_9_9_f_3[3] 232..234
//     range_check_9_9_f_4[3] 235..237
//     range_check_9_9_f_5[3] 238..240
//     range_check_9_9_g_0[3] 241..243
//     range_check_9_9_g_1[3] 244..246
//     range_check_9_9_g_2[3] 247..249
//     range_check_9_9_h_0[3] 250..252
//     range_check_9_9_h_1[3] 253..255
//     range_check_9_9_h_2[3] 256..258
//     (259 words)
//   SUB-INPUT words:
//     range_check_9_9[0] 0..1
//     range_check_9_9[1] 2..3
//     range_check_9_9[2] 4..5
//     range_check_9_9[3] 6..7
//     range_check_9_9[4] 8..9
//     range_check_9_9[5] 10..11
//     range_check_9_9_b[0] 12..13
//     range_check_9_9_b[1] 14..15
//     range_check_9_9_b[2] 16..17
//     range_check_9_9_b[3] 18..19
//     range_check_9_9_b[4] 20..21
//     range_check_9_9_b[5] 22..23
//     range_check_9_9_c[0] 24..25
//     range_check_9_9_c[1] 26..27
//     range_check_9_9_c[2] 28..29
//     range_check_9_9_c[3] 30..31
//     range_check_9_9_c[4] 32..33
//     range_check_9_9_c[5] 34..35
//     range_check_9_9_d[0] 36..37
//     range_check_9_9_d[1] 38..39
//     range_check_9_9_d[2] 40..41
//     range_check_9_9_d[3] 42..43
//     range_check_9_9_d[4] 44..45
//     range_check_9_9_d[5] 46..47
//     range_check_9_9_e[0] 48..49
//     range_check_9_9_e[1] 50..51
//     range_check_9_9_e[2] 52..53
//     range_check_9_9_e[3] 54..55
//     range_check_9_9_e[4] 56..57
//     range_check_9_9_e[5] 58..59
//     range_check_9_9_f[0] 60..61
//     range_check_9_9_f[1] 62..63
//     range_check_9_9_f[2] 64..65
//     range_check_9_9_f[3] 66..67
//     range_check_9_9_f[4] 68..69
//     range_check_9_9_f[5] 70..71
//     range_check_9_9_g[0] 72..73
//     range_check_9_9_g[1] 74..75
//     range_check_9_9_g[2] 76..77
//     range_check_9_9_h[0] 78..79
//     range_check_9_9_h[1] 80..81
//     range_check_9_9_h[2] 82..83
//     range_check_20[0] 84
//     range_check_20[1] 85
//     range_check_20[2] 86
//     range_check_20[3] 87
//     range_check_20[4] 88
//     range_check_20[5] 89
//     range_check_20[6] 90
//     range_check_20[7] 91
//     range_check_20_b[0] 92
//     range_check_20_b[1] 93
//     range_check_20_b[2] 94
//     range_check_20_b[3] 95
//     range_check_20_b[4] 96
//     range_check_20_b[5] 97
//     range_check_20_b[6] 98
//     range_check_20_b[7] 99
//     range_check_20_c[0] 100
//     range_check_20_c[1] 101
//     range_check_20_c[2] 102
//     range_check_20_c[3] 103
//     range_check_20_c[4] 104
//     range_check_20_c[5] 105
//     range_check_20_c[6] 106
//     range_check_20_c[7] 107
//     range_check_20_d[0] 108
//     range_check_20_d[1] 109
//     range_check_20_d[2] 110
//     range_check_20_d[3] 111
//     range_check_20_d[4] 112
//     range_check_20_d[5] 113
//     range_check_20_d[6] 114
//     range_check_20_d[7] 115
//     range_check_20_e[0] 116
//     range_check_20_e[1] 117
//     range_check_20_e[2] 118
//     range_check_20_e[3] 119
//     range_check_20_e[4] 120
//     range_check_20_e[5] 121
//     range_check_20_f[0] 122
//     range_check_20_f[1] 123
//     range_check_20_f[2] 124
//     range_check_20_f[3] 125
//     range_check_20_f[4] 126
//     range_check_20_f[5] 127
//     range_check_20_g[0] 128
//     range_check_20_g[1] 129
//     range_check_20_g[2] 130
//     range_check_20_g[3] 131
//     range_check_20_g[4] 132
//     range_check_20_g[5] 133
//     range_check_20_h[0] 134
//     range_check_20_h[1] 135
//     range_check_20_h[2] 136
//     range_check_20_h[3] 137
//     range_check_20_h[4] 138
//     range_check_20_h[5] 139
//     (140 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 259;
pub(crate) const N_SUB_INPUT_WORDS: usize = 140;

/// The per-row `cube_252` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn cube_252_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_2 = eval.m31_const(2);
    let m31_4 = eval.m31_const(4);
    let m31_8 = eval.m31_const(8);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_136 = eval.m31_const(136);
    let m31_512 = eval.m31_const(512);
    let m31_8192 = eval.m31_const(8192);
    let m31_65536 = eval.m31_const(65536);
    let m31_262144 = eval.m31_const(262144);
    let m31_524288 = eval.m31_const(524288);
    let m31_4194304 = eval.m31_const(4194304);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_447122465 = eval.m31_const(447122465);
    let m31_463900084 = eval.m31_const(463900084);
    let m31_480677703 = eval.m31_const(480677703);
    let m31_497455322 = eval.m31_const(497455322);
    let m31_514232941 = eval.m31_const(514232941);
    let m31_517791011 = eval.m31_const(517791011);
    let m31_531010560 = eval.m31_const(531010560);
    let m31_682009131 = eval.m31_const(682009131);
    let m31_1410849886 = eval.m31_const(1410849886);
    let m31_1813904000 = eval.m31_const(1813904000);
    let m31_1830681619 = eval.m31_const(1830681619);
    let m31_1847459238 = eval.m31_const(1847459238);
    let m31_1864236857 = eval.m31_const(1864236857);
    let m31_1881014476 = eval.m31_const(1881014476);
    let m31_1897792095 = eval.m31_const(1897792095);
    let m31_1987997202 = eval.m31_const(1987997202);
    let m31_2065568285 = eval.m31_const(2065568285);
    let wg_v0 = eval.input(0);
    let wg_v1 = eval.input(1);
    let wg_v2 = eval.input(2);
    let wg_v3 = eval.input(3);
    let wg_v4 = eval.input(4);
    let wg_v5 = eval.input(5);
    let wg_v6 = eval.input(6);
    let wg_v7 = eval.input(7);
    let wg_v8 = eval.input(8);
    let wg_v9 = eval.input(9);
    let wg_v10 = [
        wg_v0, wg_v1, wg_v2, wg_v3, wg_v4, wg_v5, wg_v6, wg_v7, wg_v8, wg_v9,
    ];
    let input_limb_0_col0 = wg_v10[0];
    eval.set_col(0, input_limb_0_col0);
    let wg_v11 = eval.input(0);
    let wg_v12 = eval.input(1);
    let wg_v13 = eval.input(2);
    let wg_v14 = eval.input(3);
    let wg_v15 = eval.input(4);
    let wg_v16 = eval.input(5);
    let wg_v17 = eval.input(6);
    let wg_v18 = eval.input(7);
    let wg_v19 = eval.input(8);
    let wg_v20 = eval.input(9);
    let wg_v21 = [
        wg_v11, wg_v12, wg_v13, wg_v14, wg_v15, wg_v16, wg_v17, wg_v18, wg_v19, wg_v20,
    ];
    let input_limb_1_col1 = wg_v21[1];
    eval.set_col(1, input_limb_1_col1);
    let wg_v22 = eval.input(0);
    let wg_v23 = eval.input(1);
    let wg_v24 = eval.input(2);
    let wg_v25 = eval.input(3);
    let wg_v26 = eval.input(4);
    let wg_v27 = eval.input(5);
    let wg_v28 = eval.input(6);
    let wg_v29 = eval.input(7);
    let wg_v30 = eval.input(8);
    let wg_v31 = eval.input(9);
    let wg_v32 = [
        wg_v22, wg_v23, wg_v24, wg_v25, wg_v26, wg_v27, wg_v28, wg_v29, wg_v30, wg_v31,
    ];
    let input_limb_2_col2 = wg_v32[2];
    eval.set_col(2, input_limb_2_col2);
    let wg_v33 = eval.input(0);
    let wg_v34 = eval.input(1);
    let wg_v35 = eval.input(2);
    let wg_v36 = eval.input(3);
    let wg_v37 = eval.input(4);
    let wg_v38 = eval.input(5);
    let wg_v39 = eval.input(6);
    let wg_v40 = eval.input(7);
    let wg_v41 = eval.input(8);
    let wg_v42 = eval.input(9);
    let wg_v43 = [
        wg_v33, wg_v34, wg_v35, wg_v36, wg_v37, wg_v38, wg_v39, wg_v40, wg_v41, wg_v42,
    ];
    let input_limb_3_col3 = wg_v43[3];
    eval.set_col(3, input_limb_3_col3);
    let wg_v44 = eval.input(0);
    let wg_v45 = eval.input(1);
    let wg_v46 = eval.input(2);
    let wg_v47 = eval.input(3);
    let wg_v48 = eval.input(4);
    let wg_v49 = eval.input(5);
    let wg_v50 = eval.input(6);
    let wg_v51 = eval.input(7);
    let wg_v52 = eval.input(8);
    let wg_v53 = eval.input(9);
    let wg_v54 = [
        wg_v44, wg_v45, wg_v46, wg_v47, wg_v48, wg_v49, wg_v50, wg_v51, wg_v52, wg_v53,
    ];
    let input_limb_4_col4 = wg_v54[4];
    eval.set_col(4, input_limb_4_col4);
    let wg_v55 = eval.input(0);
    let wg_v56 = eval.input(1);
    let wg_v57 = eval.input(2);
    let wg_v58 = eval.input(3);
    let wg_v59 = eval.input(4);
    let wg_v60 = eval.input(5);
    let wg_v61 = eval.input(6);
    let wg_v62 = eval.input(7);
    let wg_v63 = eval.input(8);
    let wg_v64 = eval.input(9);
    let wg_v65 = [
        wg_v55, wg_v56, wg_v57, wg_v58, wg_v59, wg_v60, wg_v61, wg_v62, wg_v63, wg_v64,
    ];
    let input_limb_5_col5 = wg_v65[5];
    eval.set_col(5, input_limb_5_col5);
    let wg_v66 = eval.input(0);
    let wg_v67 = eval.input(1);
    let wg_v68 = eval.input(2);
    let wg_v69 = eval.input(3);
    let wg_v70 = eval.input(4);
    let wg_v71 = eval.input(5);
    let wg_v72 = eval.input(6);
    let wg_v73 = eval.input(7);
    let wg_v74 = eval.input(8);
    let wg_v75 = eval.input(9);
    let wg_v76 = [
        wg_v66, wg_v67, wg_v68, wg_v69, wg_v70, wg_v71, wg_v72, wg_v73, wg_v74, wg_v75,
    ];
    let input_limb_6_col6 = wg_v76[6];
    eval.set_col(6, input_limb_6_col6);
    let wg_v77 = eval.input(0);
    let wg_v78 = eval.input(1);
    let wg_v79 = eval.input(2);
    let wg_v80 = eval.input(3);
    let wg_v81 = eval.input(4);
    let wg_v82 = eval.input(5);
    let wg_v83 = eval.input(6);
    let wg_v84 = eval.input(7);
    let wg_v85 = eval.input(8);
    let wg_v86 = eval.input(9);
    let wg_v87 = [
        wg_v77, wg_v78, wg_v79, wg_v80, wg_v81, wg_v82, wg_v83, wg_v84, wg_v85, wg_v86,
    ];
    let input_limb_7_col7 = wg_v87[7];
    eval.set_col(7, input_limb_7_col7);
    let wg_v88 = eval.input(0);
    let wg_v89 = eval.input(1);
    let wg_v90 = eval.input(2);
    let wg_v91 = eval.input(3);
    let wg_v92 = eval.input(4);
    let wg_v93 = eval.input(5);
    let wg_v94 = eval.input(6);
    let wg_v95 = eval.input(7);
    let wg_v96 = eval.input(8);
    let wg_v97 = eval.input(9);
    let wg_v98 = [
        wg_v88, wg_v89, wg_v90, wg_v91, wg_v92, wg_v93, wg_v94, wg_v95, wg_v96, wg_v97,
    ];
    let input_limb_8_col8 = wg_v98[8];
    eval.set_col(8, input_limb_8_col8);
    let wg_v99 = eval.input(0);
    let wg_v100 = eval.input(1);
    let wg_v101 = eval.input(2);
    let wg_v102 = eval.input(3);
    let wg_v103 = eval.input(4);
    let wg_v104 = eval.input(5);
    let wg_v105 = eval.input(6);
    let wg_v106 = eval.input(7);
    let wg_v107 = eval.input(8);
    let wg_v108 = eval.input(9);
    let wg_v109 = [
        wg_v99, wg_v100, wg_v101, wg_v102, wg_v103, wg_v104, wg_v105, wg_v106, wg_v107, wg_v108,
    ];
    let input_limb_9_col9 = wg_v109[9];
    eval.set_col(9, input_limb_9_col9);
    let wg_v110 = eval.input(0);
    let wg_v111 = eval.input(1);
    let wg_v112 = eval.input(2);
    let wg_v113 = eval.input(3);
    let wg_v114 = eval.input(4);
    let wg_v115 = eval.input(5);
    let wg_v116 = eval.input(6);
    let wg_v117 = eval.input(7);
    let wg_v118 = eval.input(8);
    let wg_v119 = eval.input(9);
    let wg_v120 = [
        wg_v110, wg_v111, wg_v112, wg_v113, wg_v114, wg_v115, wg_v116, wg_v117, wg_v118, wg_v119,
    ];
    let input_as_felt252_tmp_fec87_0 = eval.felt_from_w27_words(wg_v120);
    let unpacked_limb_0_col10 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 0);
    eval.set_col(10, unpacked_limb_0_col10);
    let unpacked_limb_1_col11 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 1);
    eval.set_col(11, unpacked_limb_1_col11);
    let unpacked_limb_3_col12 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 3);
    eval.set_col(12, unpacked_limb_3_col12);
    let unpacked_limb_4_col13 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 4);
    eval.set_col(13, unpacked_limb_4_col13);
    let unpacked_limb_6_col14 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 6);
    eval.set_col(14, unpacked_limb_6_col14);
    let unpacked_limb_7_col15 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 7);
    eval.set_col(15, unpacked_limb_7_col15);
    let unpacked_limb_9_col16 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 9);
    eval.set_col(16, unpacked_limb_9_col16);
    let unpacked_limb_10_col17 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 10);
    eval.set_col(17, unpacked_limb_10_col17);
    let unpacked_limb_12_col18 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 12);
    eval.set_col(18, unpacked_limb_12_col18);
    let unpacked_limb_13_col19 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 13);
    eval.set_col(19, unpacked_limb_13_col19);
    let unpacked_limb_15_col20 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 15);
    eval.set_col(20, unpacked_limb_15_col20);
    let unpacked_limb_16_col21 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 16);
    eval.set_col(21, unpacked_limb_16_col21);
    let unpacked_limb_18_col22 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 18);
    eval.set_col(22, unpacked_limb_18_col22);
    let unpacked_limb_19_col23 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 19);
    eval.set_col(23, unpacked_limb_19_col23);
    let unpacked_limb_21_col24 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 21);
    eval.set_col(24, unpacked_limb_21_col24);
    let unpacked_limb_22_col25 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 22);
    eval.set_col(25, unpacked_limb_22_col25);
    let unpacked_limb_24_col26 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 24);
    eval.set_col(26, unpacked_limb_24_col26);
    let unpacked_limb_25_col27 = eval.felt_get_m31(&input_as_felt252_tmp_fec87_0.clone(), 25);
    eval.set_col(27, unpacked_limb_25_col27);
    let wg_v121 = eval.m31_sub(input_limb_0_col0, unpacked_limb_0_col10);
    let wg_v122 = eval.m31_mul(unpacked_limb_1_col11, m31_512);
    let wg_v123 = eval.m31_sub(wg_v121, wg_v122);
    let wg_v124 = eval.m31_mul(wg_v123, m31_8192);
    let wg_v125 = eval.m31_sub(input_limb_1_col1, unpacked_limb_3_col12);
    let wg_v126 = eval.m31_mul(unpacked_limb_4_col13, m31_512);
    let wg_v127 = eval.m31_sub(wg_v125, wg_v126);
    let wg_v128 = eval.m31_mul(wg_v127, m31_8192);
    let wg_v129 = eval.m31_sub(input_limb_2_col2, unpacked_limb_6_col14);
    let wg_v130 = eval.m31_mul(unpacked_limb_7_col15, m31_512);
    let wg_v131 = eval.m31_sub(wg_v129, wg_v130);
    let wg_v132 = eval.m31_mul(wg_v131, m31_8192);
    let wg_v133 = eval.m31_sub(input_limb_3_col3, unpacked_limb_9_col16);
    let wg_v134 = eval.m31_mul(unpacked_limb_10_col17, m31_512);
    let wg_v135 = eval.m31_sub(wg_v133, wg_v134);
    let wg_v136 = eval.m31_mul(wg_v135, m31_8192);
    let wg_v137 = eval.m31_sub(input_limb_4_col4, unpacked_limb_12_col18);
    let wg_v138 = eval.m31_mul(unpacked_limb_13_col19, m31_512);
    let wg_v139 = eval.m31_sub(wg_v137, wg_v138);
    let wg_v140 = eval.m31_mul(wg_v139, m31_8192);
    let wg_v141 = eval.m31_sub(input_limb_5_col5, unpacked_limb_15_col20);
    let wg_v142 = eval.m31_mul(unpacked_limb_16_col21, m31_512);
    let wg_v143 = eval.m31_sub(wg_v141, wg_v142);
    let wg_v144 = eval.m31_mul(wg_v143, m31_8192);
    let wg_v145 = eval.m31_sub(input_limb_6_col6, unpacked_limb_18_col22);
    let wg_v146 = eval.m31_mul(unpacked_limb_19_col23, m31_512);
    let wg_v147 = eval.m31_sub(wg_v145, wg_v146);
    let wg_v148 = eval.m31_mul(wg_v147, m31_8192);
    let wg_v149 = eval.m31_sub(input_limb_7_col7, unpacked_limb_21_col24);
    let wg_v150 = eval.m31_mul(unpacked_limb_22_col25, m31_512);
    let wg_v151 = eval.m31_sub(wg_v149, wg_v150);
    let wg_v152 = eval.m31_mul(wg_v151, m31_8192);
    let wg_v153 = eval.m31_sub(input_limb_8_col8, unpacked_limb_24_col26);
    let wg_v154 = eval.m31_mul(unpacked_limb_25_col27, m31_512);
    let wg_v155 = eval.m31_sub(wg_v153, wg_v154);
    let wg_v156 = eval.m31_mul(wg_v155, m31_8192);
    let unpacked_tmp_fec87_1 = eval.felt_from_limbs([
        unpacked_limb_0_col10,
        unpacked_limb_1_col11,
        wg_v124,
        unpacked_limb_3_col12,
        unpacked_limb_4_col13,
        wg_v128,
        unpacked_limb_6_col14,
        unpacked_limb_7_col15,
        wg_v132,
        unpacked_limb_9_col16,
        unpacked_limb_10_col17,
        wg_v136,
        unpacked_limb_12_col18,
        unpacked_limb_13_col19,
        wg_v140,
        unpacked_limb_15_col20,
        unpacked_limb_16_col21,
        wg_v144,
        unpacked_limb_18_col22,
        unpacked_limb_19_col23,
        wg_v148,
        unpacked_limb_21_col24,
        unpacked_limb_22_col25,
        wg_v152,
        unpacked_limb_24_col26,
        unpacked_limb_25_col27,
        wg_v156,
        input_limb_9_col9,
    ]);
    eval.set_sub_input_word(0, unpacked_limb_0_col10);
    eval.set_sub_input_word(1, unpacked_limb_1_col11);
    eval.set_lookup_word(133, m31_517791011);
    eval.set_lookup_word(134, unpacked_limb_0_col10);
    eval.set_lookup_word(135, unpacked_limb_1_col11);
    let wg_v157 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    eval.set_sub_input_word(12, wg_v157);
    eval.set_sub_input_word(13, unpacked_limb_3_col12);
    eval.set_lookup_word(151, m31_1897792095);
    let wg_v158 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    eval.set_lookup_word(152, wg_v158);
    eval.set_lookup_word(153, unpacked_limb_3_col12);
    let wg_v159 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    eval.set_sub_input_word(24, unpacked_limb_4_col13);
    eval.set_sub_input_word(25, wg_v159);
    eval.set_lookup_word(169, m31_1881014476);
    eval.set_lookup_word(170, unpacked_limb_4_col13);
    let wg_v160 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    eval.set_lookup_word(171, wg_v160);
    eval.set_sub_input_word(36, unpacked_limb_6_col14);
    eval.set_sub_input_word(37, unpacked_limb_7_col15);
    eval.set_lookup_word(187, m31_1864236857);
    eval.set_lookup_word(188, unpacked_limb_6_col14);
    eval.set_lookup_word(189, unpacked_limb_7_col15);
    let wg_v161 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    eval.set_sub_input_word(48, wg_v161);
    eval.set_sub_input_word(49, unpacked_limb_9_col16);
    eval.set_lookup_word(205, m31_1847459238);
    let wg_v162 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    eval.set_lookup_word(206, wg_v162);
    eval.set_lookup_word(207, unpacked_limb_9_col16);
    let wg_v163 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    eval.set_sub_input_word(60, unpacked_limb_10_col17);
    eval.set_sub_input_word(61, wg_v163);
    eval.set_lookup_word(223, m31_1830681619);
    eval.set_lookup_word(224, unpacked_limb_10_col17);
    let wg_v164 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    eval.set_lookup_word(225, wg_v164);
    eval.set_sub_input_word(72, unpacked_limb_12_col18);
    eval.set_sub_input_word(73, unpacked_limb_13_col19);
    eval.set_lookup_word(241, m31_1813904000);
    eval.set_lookup_word(242, unpacked_limb_12_col18);
    eval.set_lookup_word(243, unpacked_limb_13_col19);
    let wg_v165 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    eval.set_sub_input_word(78, wg_v165);
    eval.set_sub_input_word(79, unpacked_limb_15_col20);
    eval.set_lookup_word(250, m31_2065568285);
    let wg_v166 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    eval.set_lookup_word(251, wg_v166);
    eval.set_lookup_word(252, unpacked_limb_15_col20);
    let wg_v167 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    eval.set_sub_input_word(2, unpacked_limb_16_col21);
    eval.set_sub_input_word(3, wg_v167);
    eval.set_lookup_word(136, m31_517791011);
    eval.set_lookup_word(137, unpacked_limb_16_col21);
    let wg_v168 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    eval.set_lookup_word(138, wg_v168);
    eval.set_sub_input_word(14, unpacked_limb_18_col22);
    eval.set_sub_input_word(15, unpacked_limb_19_col23);
    eval.set_lookup_word(154, m31_1897792095);
    eval.set_lookup_word(155, unpacked_limb_18_col22);
    eval.set_lookup_word(156, unpacked_limb_19_col23);
    let wg_v169 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    eval.set_sub_input_word(26, wg_v169);
    eval.set_sub_input_word(27, unpacked_limb_21_col24);
    eval.set_lookup_word(172, m31_1881014476);
    let wg_v170 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    eval.set_lookup_word(173, wg_v170);
    eval.set_lookup_word(174, unpacked_limb_21_col24);
    let wg_v171 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    eval.set_sub_input_word(38, unpacked_limb_22_col25);
    eval.set_sub_input_word(39, wg_v171);
    eval.set_lookup_word(190, m31_1864236857);
    eval.set_lookup_word(191, unpacked_limb_22_col25);
    let wg_v172 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    eval.set_lookup_word(192, wg_v172);
    eval.set_sub_input_word(50, unpacked_limb_24_col26);
    eval.set_sub_input_word(51, unpacked_limb_25_col27);
    eval.set_lookup_word(208, m31_1847459238);
    eval.set_lookup_word(209, unpacked_limb_24_col26);
    eval.set_lookup_word(210, unpacked_limb_25_col27);
    let wg_v173 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    eval.set_sub_input_word(62, wg_v173);
    eval.set_sub_input_word(63, input_limb_9_col9);
    eval.set_lookup_word(226, m31_1830681619);
    let wg_v174 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    eval.set_lookup_word(227, wg_v174);
    eval.set_lookup_word(228, input_limb_9_col9);
    let felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2 =
        unpacked_tmp_fec87_1.clone();
    let mul_res_tmp_fec87_3 = eval.felt_mul(
        felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2
            .clone()
            .clone(),
        felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2
            .clone()
            .clone(),
    );
    let mul_res_limb_0_col28 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 0);
    eval.set_col(28, mul_res_limb_0_col28);
    let mul_res_limb_1_col29 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 1);
    eval.set_col(29, mul_res_limb_1_col29);
    let mul_res_limb_2_col30 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 2);
    eval.set_col(30, mul_res_limb_2_col30);
    let mul_res_limb_3_col31 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 3);
    eval.set_col(31, mul_res_limb_3_col31);
    let mul_res_limb_4_col32 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 4);
    eval.set_col(32, mul_res_limb_4_col32);
    let mul_res_limb_5_col33 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 5);
    eval.set_col(33, mul_res_limb_5_col33);
    let mul_res_limb_6_col34 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 6);
    eval.set_col(34, mul_res_limb_6_col34);
    let mul_res_limb_7_col35 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 7);
    eval.set_col(35, mul_res_limb_7_col35);
    let mul_res_limb_8_col36 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 8);
    eval.set_col(36, mul_res_limb_8_col36);
    let mul_res_limb_9_col37 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 9);
    eval.set_col(37, mul_res_limb_9_col37);
    let mul_res_limb_10_col38 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 10);
    eval.set_col(38, mul_res_limb_10_col38);
    let mul_res_limb_11_col39 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 11);
    eval.set_col(39, mul_res_limb_11_col39);
    let mul_res_limb_12_col40 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 12);
    eval.set_col(40, mul_res_limb_12_col40);
    let mul_res_limb_13_col41 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 13);
    eval.set_col(41, mul_res_limb_13_col41);
    let mul_res_limb_14_col42 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 14);
    eval.set_col(42, mul_res_limb_14_col42);
    let mul_res_limb_15_col43 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 15);
    eval.set_col(43, mul_res_limb_15_col43);
    let mul_res_limb_16_col44 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 16);
    eval.set_col(44, mul_res_limb_16_col44);
    let mul_res_limb_17_col45 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 17);
    eval.set_col(45, mul_res_limb_17_col45);
    let mul_res_limb_18_col46 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 18);
    eval.set_col(46, mul_res_limb_18_col46);
    let mul_res_limb_19_col47 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 19);
    eval.set_col(47, mul_res_limb_19_col47);
    let mul_res_limb_20_col48 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 20);
    eval.set_col(48, mul_res_limb_20_col48);
    let mul_res_limb_21_col49 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 21);
    eval.set_col(49, mul_res_limb_21_col49);
    let mul_res_limb_22_col50 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 22);
    eval.set_col(50, mul_res_limb_22_col50);
    let mul_res_limb_23_col51 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 23);
    eval.set_col(51, mul_res_limb_23_col51);
    let mul_res_limb_24_col52 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 24);
    eval.set_col(52, mul_res_limb_24_col52);
    let mul_res_limb_25_col53 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 25);
    eval.set_col(53, mul_res_limb_25_col53);
    let mul_res_limb_26_col54 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 26);
    eval.set_col(54, mul_res_limb_26_col54);
    let mul_res_limb_27_col55 = eval.felt_get_m31(&mul_res_tmp_fec87_3.clone(), 27);
    eval.set_col(55, mul_res_limb_27_col55);
    eval.set_sub_input_word(4, mul_res_limb_0_col28);
    eval.set_sub_input_word(5, mul_res_limb_1_col29);
    eval.set_lookup_word(139, m31_517791011);
    eval.set_lookup_word(140, mul_res_limb_0_col28);
    eval.set_lookup_word(141, mul_res_limb_1_col29);
    eval.set_sub_input_word(16, mul_res_limb_2_col30);
    eval.set_sub_input_word(17, mul_res_limb_3_col31);
    eval.set_lookup_word(157, m31_1897792095);
    eval.set_lookup_word(158, mul_res_limb_2_col30);
    eval.set_lookup_word(159, mul_res_limb_3_col31);
    eval.set_sub_input_word(28, mul_res_limb_4_col32);
    eval.set_sub_input_word(29, mul_res_limb_5_col33);
    eval.set_lookup_word(175, m31_1881014476);
    eval.set_lookup_word(176, mul_res_limb_4_col32);
    eval.set_lookup_word(177, mul_res_limb_5_col33);
    eval.set_sub_input_word(40, mul_res_limb_6_col34);
    eval.set_sub_input_word(41, mul_res_limb_7_col35);
    eval.set_lookup_word(193, m31_1864236857);
    eval.set_lookup_word(194, mul_res_limb_6_col34);
    eval.set_lookup_word(195, mul_res_limb_7_col35);
    eval.set_sub_input_word(52, mul_res_limb_8_col36);
    eval.set_sub_input_word(53, mul_res_limb_9_col37);
    eval.set_lookup_word(211, m31_1847459238);
    eval.set_lookup_word(212, mul_res_limb_8_col36);
    eval.set_lookup_word(213, mul_res_limb_9_col37);
    eval.set_sub_input_word(64, mul_res_limb_10_col38);
    eval.set_sub_input_word(65, mul_res_limb_11_col39);
    eval.set_lookup_word(229, m31_1830681619);
    eval.set_lookup_word(230, mul_res_limb_10_col38);
    eval.set_lookup_word(231, mul_res_limb_11_col39);
    eval.set_sub_input_word(74, mul_res_limb_12_col40);
    eval.set_sub_input_word(75, mul_res_limb_13_col41);
    eval.set_lookup_word(244, m31_1813904000);
    eval.set_lookup_word(245, mul_res_limb_12_col40);
    eval.set_lookup_word(246, mul_res_limb_13_col41);
    eval.set_sub_input_word(80, mul_res_limb_14_col42);
    eval.set_sub_input_word(81, mul_res_limb_15_col43);
    eval.set_lookup_word(253, m31_2065568285);
    eval.set_lookup_word(254, mul_res_limb_14_col42);
    eval.set_lookup_word(255, mul_res_limb_15_col43);
    eval.set_sub_input_word(6, mul_res_limb_16_col44);
    eval.set_sub_input_word(7, mul_res_limb_17_col45);
    eval.set_lookup_word(142, m31_517791011);
    eval.set_lookup_word(143, mul_res_limb_16_col44);
    eval.set_lookup_word(144, mul_res_limb_17_col45);
    eval.set_sub_input_word(18, mul_res_limb_18_col46);
    eval.set_sub_input_word(19, mul_res_limb_19_col47);
    eval.set_lookup_word(160, m31_1897792095);
    eval.set_lookup_word(161, mul_res_limb_18_col46);
    eval.set_lookup_word(162, mul_res_limb_19_col47);
    eval.set_sub_input_word(30, mul_res_limb_20_col48);
    eval.set_sub_input_word(31, mul_res_limb_21_col49);
    eval.set_lookup_word(178, m31_1881014476);
    eval.set_lookup_word(179, mul_res_limb_20_col48);
    eval.set_lookup_word(180, mul_res_limb_21_col49);
    eval.set_sub_input_word(42, mul_res_limb_22_col50);
    eval.set_sub_input_word(43, mul_res_limb_23_col51);
    eval.set_lookup_word(196, m31_1864236857);
    eval.set_lookup_word(197, mul_res_limb_22_col50);
    eval.set_lookup_word(198, mul_res_limb_23_col51);
    eval.set_sub_input_word(54, mul_res_limb_24_col52);
    eval.set_sub_input_word(55, mul_res_limb_25_col53);
    eval.set_lookup_word(214, m31_1847459238);
    eval.set_lookup_word(215, mul_res_limb_24_col52);
    eval.set_lookup_word(216, mul_res_limb_25_col53);
    eval.set_sub_input_word(66, mul_res_limb_26_col54);
    eval.set_sub_input_word(67, mul_res_limb_27_col55);
    eval.set_lookup_word(232, m31_1830681619);
    eval.set_lookup_word(233, mul_res_limb_26_col54);
    eval.set_lookup_word(234, mul_res_limb_27_col55);
    let wg_v175 = eval.m31_mul(unpacked_limb_0_col10, unpacked_limb_0_col10);
    let wg_v176 = eval.m31_mul(unpacked_limb_0_col10, unpacked_limb_1_col11);
    let wg_v177 = eval.m31_mul(unpacked_limb_1_col11, unpacked_limb_0_col10);
    let wg_v178 = eval.m31_add(wg_v176, wg_v177);
    let wg_v179 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v180 = eval.m31_mul(unpacked_limb_0_col10, wg_v179);
    let wg_v181 = eval.m31_mul(unpacked_limb_1_col11, unpacked_limb_1_col11);
    let wg_v182 = eval.m31_add(wg_v180, wg_v181);
    let wg_v183 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v184 = eval.m31_mul(wg_v183, unpacked_limb_0_col10);
    let wg_v185 = eval.m31_add(wg_v182, wg_v184);
    let wg_v186 = eval.m31_mul(unpacked_limb_0_col10, unpacked_limb_3_col12);
    let wg_v187 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v188 = eval.m31_mul(unpacked_limb_1_col11, wg_v187);
    let wg_v189 = eval.m31_add(wg_v186, wg_v188);
    let wg_v190 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v191 = eval.m31_mul(wg_v190, unpacked_limb_1_col11);
    let wg_v192 = eval.m31_add(wg_v189, wg_v191);
    let wg_v193 = eval.m31_mul(unpacked_limb_3_col12, unpacked_limb_0_col10);
    let wg_v194 = eval.m31_add(wg_v192, wg_v193);
    let wg_v195 = eval.m31_mul(unpacked_limb_0_col10, unpacked_limb_4_col13);
    let wg_v196 = eval.m31_mul(unpacked_limb_1_col11, unpacked_limb_3_col12);
    let wg_v197 = eval.m31_add(wg_v195, wg_v196);
    let wg_v198 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v199 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v200 = eval.m31_mul(wg_v198, wg_v199);
    let wg_v201 = eval.m31_add(wg_v197, wg_v200);
    let wg_v202 = eval.m31_mul(unpacked_limb_3_col12, unpacked_limb_1_col11);
    let wg_v203 = eval.m31_add(wg_v201, wg_v202);
    let wg_v204 = eval.m31_mul(unpacked_limb_4_col13, unpacked_limb_0_col10);
    let wg_v205 = eval.m31_add(wg_v203, wg_v204);
    let wg_v206 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v207 = eval.m31_mul(unpacked_limb_0_col10, wg_v206);
    let wg_v208 = eval.m31_mul(unpacked_limb_1_col11, unpacked_limb_4_col13);
    let wg_v209 = eval.m31_add(wg_v207, wg_v208);
    let wg_v210 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v211 = eval.m31_mul(wg_v210, unpacked_limb_3_col12);
    let wg_v212 = eval.m31_add(wg_v209, wg_v211);
    let wg_v213 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v214 = eval.m31_mul(unpacked_limb_3_col12, wg_v213);
    let wg_v215 = eval.m31_add(wg_v212, wg_v214);
    let wg_v216 = eval.m31_mul(unpacked_limb_4_col13, unpacked_limb_1_col11);
    let wg_v217 = eval.m31_add(wg_v215, wg_v216);
    let wg_v218 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v219 = eval.m31_mul(wg_v218, unpacked_limb_0_col10);
    let wg_v220 = eval.m31_add(wg_v217, wg_v219);
    let wg_v221 = eval.m31_mul(unpacked_limb_0_col10, unpacked_limb_6_col14);
    let wg_v222 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v223 = eval.m31_mul(unpacked_limb_1_col11, wg_v222);
    let wg_v224 = eval.m31_add(wg_v221, wg_v223);
    let wg_v225 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v226 = eval.m31_mul(wg_v225, unpacked_limb_4_col13);
    let wg_v227 = eval.m31_add(wg_v224, wg_v226);
    let wg_v228 = eval.m31_mul(unpacked_limb_3_col12, unpacked_limb_3_col12);
    let wg_v229 = eval.m31_add(wg_v227, wg_v228);
    let wg_v230 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v231 = eval.m31_mul(unpacked_limb_4_col13, wg_v230);
    let wg_v232 = eval.m31_add(wg_v229, wg_v231);
    let wg_v233 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v234 = eval.m31_mul(wg_v233, unpacked_limb_1_col11);
    let wg_v235 = eval.m31_add(wg_v232, wg_v234);
    let wg_v236 = eval.m31_mul(unpacked_limb_6_col14, unpacked_limb_0_col10);
    let wg_v237 = eval.m31_add(wg_v235, wg_v236);
    let wg_v238 = eval.m31_mul(unpacked_limb_1_col11, unpacked_limb_6_col14);
    let wg_v239 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v240 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v241 = eval.m31_mul(wg_v239, wg_v240);
    let wg_v242 = eval.m31_add(wg_v238, wg_v241);
    let wg_v243 = eval.m31_mul(unpacked_limb_3_col12, unpacked_limb_4_col13);
    let wg_v244 = eval.m31_add(wg_v242, wg_v243);
    let wg_v245 = eval.m31_mul(unpacked_limb_4_col13, unpacked_limb_3_col12);
    let wg_v246 = eval.m31_add(wg_v244, wg_v245);
    let wg_v247 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v248 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v249 = eval.m31_mul(wg_v247, wg_v248);
    let wg_v250 = eval.m31_add(wg_v246, wg_v249);
    let wg_v251 = eval.m31_mul(unpacked_limb_6_col14, unpacked_limb_1_col11);
    let wg_v252 = eval.m31_add(wg_v250, wg_v251);
    let wg_v253 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v254 = eval.m31_mul(wg_v253, unpacked_limb_6_col14);
    let wg_v255 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v256 = eval.m31_mul(unpacked_limb_3_col12, wg_v255);
    let wg_v257 = eval.m31_add(wg_v254, wg_v256);
    let wg_v258 = eval.m31_mul(unpacked_limb_4_col13, unpacked_limb_4_col13);
    let wg_v259 = eval.m31_add(wg_v257, wg_v258);
    let wg_v260 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v261 = eval.m31_mul(wg_v260, unpacked_limb_3_col12);
    let wg_v262 = eval.m31_add(wg_v259, wg_v261);
    let wg_v263 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v264 = eval.m31_mul(unpacked_limb_6_col14, wg_v263);
    let wg_v265 = eval.m31_add(wg_v262, wg_v264);
    let wg_v266 = eval.m31_mul(unpacked_limb_3_col12, unpacked_limb_6_col14);
    let wg_v267 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v268 = eval.m31_mul(unpacked_limb_4_col13, wg_v267);
    let wg_v269 = eval.m31_add(wg_v266, wg_v268);
    let wg_v270 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v271 = eval.m31_mul(wg_v270, unpacked_limb_4_col13);
    let wg_v272 = eval.m31_add(wg_v269, wg_v271);
    let wg_v273 = eval.m31_mul(unpacked_limb_6_col14, unpacked_limb_3_col12);
    let wg_v274 = eval.m31_add(wg_v272, wg_v273);
    let wg_v275 = eval.m31_mul(unpacked_limb_4_col13, unpacked_limb_6_col14);
    let wg_v276 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v277 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v278 = eval.m31_mul(wg_v276, wg_v277);
    let wg_v279 = eval.m31_add(wg_v275, wg_v278);
    let wg_v280 = eval.m31_mul(unpacked_limb_6_col14, unpacked_limb_4_col13);
    let wg_v281 = eval.m31_add(wg_v279, wg_v280);
    let wg_v282 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v283 = eval.m31_mul(wg_v282, unpacked_limb_6_col14);
    let wg_v284 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v285 = eval.m31_mul(unpacked_limb_6_col14, wg_v284);
    let wg_v286 = eval.m31_add(wg_v283, wg_v285);
    let wg_v287 = eval.m31_mul(unpacked_limb_6_col14, unpacked_limb_6_col14);
    let z0_tmp_fec87_4 = [
        wg_v175, wg_v178, wg_v185, wg_v194, wg_v205, wg_v220, wg_v237, wg_v252, wg_v265, wg_v274,
        wg_v281, wg_v286, wg_v287,
    ];
    let wg_v288 = eval.m31_mul(unpacked_limb_7_col15, unpacked_limb_7_col15);
    let wg_v289 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v290 = eval.m31_mul(unpacked_limb_7_col15, wg_v289);
    let wg_v291 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v292 = eval.m31_mul(wg_v291, unpacked_limb_7_col15);
    let wg_v293 = eval.m31_add(wg_v290, wg_v292);
    let wg_v294 = eval.m31_mul(unpacked_limb_7_col15, unpacked_limb_9_col16);
    let wg_v295 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v296 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v297 = eval.m31_mul(wg_v295, wg_v296);
    let wg_v298 = eval.m31_add(wg_v294, wg_v297);
    let wg_v299 = eval.m31_mul(unpacked_limb_9_col16, unpacked_limb_7_col15);
    let wg_v300 = eval.m31_add(wg_v298, wg_v299);
    let wg_v301 = eval.m31_mul(unpacked_limb_7_col15, unpacked_limb_10_col17);
    let wg_v302 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v303 = eval.m31_mul(wg_v302, unpacked_limb_9_col16);
    let wg_v304 = eval.m31_add(wg_v301, wg_v303);
    let wg_v305 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v306 = eval.m31_mul(unpacked_limb_9_col16, wg_v305);
    let wg_v307 = eval.m31_add(wg_v304, wg_v306);
    let wg_v308 = eval.m31_mul(unpacked_limb_10_col17, unpacked_limb_7_col15);
    let wg_v309 = eval.m31_add(wg_v307, wg_v308);
    let wg_v310 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v311 = eval.m31_mul(unpacked_limb_7_col15, wg_v310);
    let wg_v312 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v313 = eval.m31_mul(wg_v312, unpacked_limb_10_col17);
    let wg_v314 = eval.m31_add(wg_v311, wg_v313);
    let wg_v315 = eval.m31_mul(unpacked_limb_9_col16, unpacked_limb_9_col16);
    let wg_v316 = eval.m31_add(wg_v314, wg_v315);
    let wg_v317 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v318 = eval.m31_mul(unpacked_limb_10_col17, wg_v317);
    let wg_v319 = eval.m31_add(wg_v316, wg_v318);
    let wg_v320 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v321 = eval.m31_mul(wg_v320, unpacked_limb_7_col15);
    let wg_v322 = eval.m31_add(wg_v319, wg_v321);
    let wg_v323 = eval.m31_mul(unpacked_limb_7_col15, unpacked_limb_12_col18);
    let wg_v324 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v325 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v326 = eval.m31_mul(wg_v324, wg_v325);
    let wg_v327 = eval.m31_add(wg_v323, wg_v326);
    let wg_v328 = eval.m31_mul(unpacked_limb_9_col16, unpacked_limb_10_col17);
    let wg_v329 = eval.m31_add(wg_v327, wg_v328);
    let wg_v330 = eval.m31_mul(unpacked_limb_10_col17, unpacked_limb_9_col16);
    let wg_v331 = eval.m31_add(wg_v329, wg_v330);
    let wg_v332 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v333 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v334 = eval.m31_mul(wg_v332, wg_v333);
    let wg_v335 = eval.m31_add(wg_v331, wg_v334);
    let wg_v336 = eval.m31_mul(unpacked_limb_12_col18, unpacked_limb_7_col15);
    let wg_v337 = eval.m31_add(wg_v335, wg_v336);
    let wg_v338 = eval.m31_mul(unpacked_limb_7_col15, unpacked_limb_13_col19);
    let wg_v339 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v340 = eval.m31_mul(wg_v339, unpacked_limb_12_col18);
    let wg_v341 = eval.m31_add(wg_v338, wg_v340);
    let wg_v342 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v343 = eval.m31_mul(unpacked_limb_9_col16, wg_v342);
    let wg_v344 = eval.m31_add(wg_v341, wg_v343);
    let wg_v345 = eval.m31_mul(unpacked_limb_10_col17, unpacked_limb_10_col17);
    let wg_v346 = eval.m31_add(wg_v344, wg_v345);
    let wg_v347 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v348 = eval.m31_mul(wg_v347, unpacked_limb_9_col16);
    let wg_v349 = eval.m31_add(wg_v346, wg_v348);
    let wg_v350 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v351 = eval.m31_mul(unpacked_limb_12_col18, wg_v350);
    let wg_v352 = eval.m31_add(wg_v349, wg_v351);
    let wg_v353 = eval.m31_mul(unpacked_limb_13_col19, unpacked_limb_7_col15);
    let wg_v354 = eval.m31_add(wg_v352, wg_v353);
    let wg_v355 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v356 = eval.m31_mul(wg_v355, unpacked_limb_13_col19);
    let wg_v357 = eval.m31_mul(unpacked_limb_9_col16, unpacked_limb_12_col18);
    let wg_v358 = eval.m31_add(wg_v356, wg_v357);
    let wg_v359 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v360 = eval.m31_mul(unpacked_limb_10_col17, wg_v359);
    let wg_v361 = eval.m31_add(wg_v358, wg_v360);
    let wg_v362 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v363 = eval.m31_mul(wg_v362, unpacked_limb_10_col17);
    let wg_v364 = eval.m31_add(wg_v361, wg_v363);
    let wg_v365 = eval.m31_mul(unpacked_limb_12_col18, unpacked_limb_9_col16);
    let wg_v366 = eval.m31_add(wg_v364, wg_v365);
    let wg_v367 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v368 = eval.m31_mul(unpacked_limb_13_col19, wg_v367);
    let wg_v369 = eval.m31_add(wg_v366, wg_v368);
    let wg_v370 = eval.m31_mul(unpacked_limb_9_col16, unpacked_limb_13_col19);
    let wg_v371 = eval.m31_mul(unpacked_limb_10_col17, unpacked_limb_12_col18);
    let wg_v372 = eval.m31_add(wg_v370, wg_v371);
    let wg_v373 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v374 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v375 = eval.m31_mul(wg_v373, wg_v374);
    let wg_v376 = eval.m31_add(wg_v372, wg_v375);
    let wg_v377 = eval.m31_mul(unpacked_limb_12_col18, unpacked_limb_10_col17);
    let wg_v378 = eval.m31_add(wg_v376, wg_v377);
    let wg_v379 = eval.m31_mul(unpacked_limb_13_col19, unpacked_limb_9_col16);
    let wg_v380 = eval.m31_add(wg_v378, wg_v379);
    let wg_v381 = eval.m31_mul(unpacked_limb_10_col17, unpacked_limb_13_col19);
    let wg_v382 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v383 = eval.m31_mul(wg_v382, unpacked_limb_12_col18);
    let wg_v384 = eval.m31_add(wg_v381, wg_v383);
    let wg_v385 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v386 = eval.m31_mul(unpacked_limb_12_col18, wg_v385);
    let wg_v387 = eval.m31_add(wg_v384, wg_v386);
    let wg_v388 = eval.m31_mul(unpacked_limb_13_col19, unpacked_limb_10_col17);
    let wg_v389 = eval.m31_add(wg_v387, wg_v388);
    let wg_v390 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v391 = eval.m31_mul(wg_v390, unpacked_limb_13_col19);
    let wg_v392 = eval.m31_mul(unpacked_limb_12_col18, unpacked_limb_12_col18);
    let wg_v393 = eval.m31_add(wg_v391, wg_v392);
    let wg_v394 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v395 = eval.m31_mul(unpacked_limb_13_col19, wg_v394);
    let wg_v396 = eval.m31_add(wg_v393, wg_v395);
    let wg_v397 = eval.m31_mul(unpacked_limb_12_col18, unpacked_limb_13_col19);
    let wg_v398 = eval.m31_mul(unpacked_limb_13_col19, unpacked_limb_12_col18);
    let wg_v399 = eval.m31_add(wg_v397, wg_v398);
    let wg_v400 = eval.m31_mul(unpacked_limb_13_col19, unpacked_limb_13_col19);
    let z2_tmp_fec87_5 = [
        wg_v288, wg_v293, wg_v300, wg_v309, wg_v322, wg_v337, wg_v354, wg_v369, wg_v380, wg_v389,
        wg_v396, wg_v399, wg_v400,
    ];
    let wg_v401 = eval.m31_add(unpacked_limb_0_col10, unpacked_limb_7_col15);
    let wg_v402 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v403 = eval.m31_add(unpacked_limb_1_col11, wg_v402);
    let wg_v404 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v405 = eval.m31_add(wg_v404, unpacked_limb_9_col16);
    let wg_v406 = eval.m31_add(unpacked_limb_3_col12, unpacked_limb_10_col17);
    let wg_v407 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v408 = eval.m31_add(unpacked_limb_4_col13, wg_v407);
    let wg_v409 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v410 = eval.m31_add(wg_v409, unpacked_limb_12_col18);
    let wg_v411 = eval.m31_add(unpacked_limb_6_col14, unpacked_limb_13_col19);
    let x_sum_tmp_fec87_6 = [
        wg_v401, wg_v403, wg_v405, wg_v406, wg_v408, wg_v410, wg_v411,
    ];
    let wg_v412 = eval.m31_add(unpacked_limb_0_col10, unpacked_limb_7_col15);
    let wg_v413 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v414 = eval.m31_add(unpacked_limb_1_col11, wg_v413);
    let wg_v415 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v416 = eval.m31_add(wg_v415, unpacked_limb_9_col16);
    let wg_v417 = eval.m31_add(unpacked_limb_3_col12, unpacked_limb_10_col17);
    let wg_v418 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v419 = eval.m31_add(unpacked_limb_4_col13, wg_v418);
    let wg_v420 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v421 = eval.m31_add(wg_v420, unpacked_limb_12_col18);
    let wg_v422 = eval.m31_add(unpacked_limb_6_col14, unpacked_limb_13_col19);
    let y_sum_tmp_fec87_7 = [
        wg_v412, wg_v414, wg_v416, wg_v417, wg_v419, wg_v421, wg_v422,
    ];
    let wg_v423 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[0]);
    let wg_v424 = eval.m31_sub(wg_v423, z0_tmp_fec87_4[0]);
    let wg_v425 = eval.m31_sub(wg_v424, z2_tmp_fec87_5[0]);
    let wg_v426 = eval.m31_add(z0_tmp_fec87_4[7], wg_v425);
    let wg_v427 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[1]);
    let wg_v428 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[0]);
    let wg_v429 = eval.m31_add(wg_v427, wg_v428);
    let wg_v430 = eval.m31_sub(wg_v429, z0_tmp_fec87_4[1]);
    let wg_v431 = eval.m31_sub(wg_v430, z2_tmp_fec87_5[1]);
    let wg_v432 = eval.m31_add(z0_tmp_fec87_4[8], wg_v431);
    let wg_v433 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[2]);
    let wg_v434 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[1]);
    let wg_v435 = eval.m31_add(wg_v433, wg_v434);
    let wg_v436 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[0]);
    let wg_v437 = eval.m31_add(wg_v435, wg_v436);
    let wg_v438 = eval.m31_sub(wg_v437, z0_tmp_fec87_4[2]);
    let wg_v439 = eval.m31_sub(wg_v438, z2_tmp_fec87_5[2]);
    let wg_v440 = eval.m31_add(z0_tmp_fec87_4[9], wg_v439);
    let wg_v441 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[3]);
    let wg_v442 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[2]);
    let wg_v443 = eval.m31_add(wg_v441, wg_v442);
    let wg_v444 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[1]);
    let wg_v445 = eval.m31_add(wg_v443, wg_v444);
    let wg_v446 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[0]);
    let wg_v447 = eval.m31_add(wg_v445, wg_v446);
    let wg_v448 = eval.m31_sub(wg_v447, z0_tmp_fec87_4[3]);
    let wg_v449 = eval.m31_sub(wg_v448, z2_tmp_fec87_5[3]);
    let wg_v450 = eval.m31_add(z0_tmp_fec87_4[10], wg_v449);
    let wg_v451 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[4]);
    let wg_v452 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[3]);
    let wg_v453 = eval.m31_add(wg_v451, wg_v452);
    let wg_v454 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[2]);
    let wg_v455 = eval.m31_add(wg_v453, wg_v454);
    let wg_v456 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[1]);
    let wg_v457 = eval.m31_add(wg_v455, wg_v456);
    let wg_v458 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[0]);
    let wg_v459 = eval.m31_add(wg_v457, wg_v458);
    let wg_v460 = eval.m31_sub(wg_v459, z0_tmp_fec87_4[4]);
    let wg_v461 = eval.m31_sub(wg_v460, z2_tmp_fec87_5[4]);
    let wg_v462 = eval.m31_add(z0_tmp_fec87_4[11], wg_v461);
    let wg_v463 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[5]);
    let wg_v464 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[4]);
    let wg_v465 = eval.m31_add(wg_v463, wg_v464);
    let wg_v466 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[3]);
    let wg_v467 = eval.m31_add(wg_v465, wg_v466);
    let wg_v468 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[2]);
    let wg_v469 = eval.m31_add(wg_v467, wg_v468);
    let wg_v470 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[1]);
    let wg_v471 = eval.m31_add(wg_v469, wg_v470);
    let wg_v472 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[0]);
    let wg_v473 = eval.m31_add(wg_v471, wg_v472);
    let wg_v474 = eval.m31_sub(wg_v473, z0_tmp_fec87_4[5]);
    let wg_v475 = eval.m31_sub(wg_v474, z2_tmp_fec87_5[5]);
    let wg_v476 = eval.m31_add(z0_tmp_fec87_4[12], wg_v475);
    let wg_v477 = eval.m31_mul(x_sum_tmp_fec87_6[0], y_sum_tmp_fec87_7[6]);
    let wg_v478 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[5]);
    let wg_v479 = eval.m31_add(wg_v477, wg_v478);
    let wg_v480 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[4]);
    let wg_v481 = eval.m31_add(wg_v479, wg_v480);
    let wg_v482 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[3]);
    let wg_v483 = eval.m31_add(wg_v481, wg_v482);
    let wg_v484 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[2]);
    let wg_v485 = eval.m31_add(wg_v483, wg_v484);
    let wg_v486 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[1]);
    let wg_v487 = eval.m31_add(wg_v485, wg_v486);
    let wg_v488 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[0]);
    let wg_v489 = eval.m31_add(wg_v487, wg_v488);
    let wg_v490 = eval.m31_sub(wg_v489, z0_tmp_fec87_4[6]);
    let wg_v491 = eval.m31_sub(wg_v490, z2_tmp_fec87_5[6]);
    let wg_v492 = eval.m31_mul(x_sum_tmp_fec87_6[1], y_sum_tmp_fec87_7[6]);
    let wg_v493 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[5]);
    let wg_v494 = eval.m31_add(wg_v492, wg_v493);
    let wg_v495 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[4]);
    let wg_v496 = eval.m31_add(wg_v494, wg_v495);
    let wg_v497 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[3]);
    let wg_v498 = eval.m31_add(wg_v496, wg_v497);
    let wg_v499 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[2]);
    let wg_v500 = eval.m31_add(wg_v498, wg_v499);
    let wg_v501 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[1]);
    let wg_v502 = eval.m31_add(wg_v500, wg_v501);
    let wg_v503 = eval.m31_sub(wg_v502, z0_tmp_fec87_4[7]);
    let wg_v504 = eval.m31_sub(wg_v503, z2_tmp_fec87_5[7]);
    let wg_v505 = eval.m31_add(z2_tmp_fec87_5[0], wg_v504);
    let wg_v506 = eval.m31_mul(x_sum_tmp_fec87_6[2], y_sum_tmp_fec87_7[6]);
    let wg_v507 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[5]);
    let wg_v508 = eval.m31_add(wg_v506, wg_v507);
    let wg_v509 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[4]);
    let wg_v510 = eval.m31_add(wg_v508, wg_v509);
    let wg_v511 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[3]);
    let wg_v512 = eval.m31_add(wg_v510, wg_v511);
    let wg_v513 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[2]);
    let wg_v514 = eval.m31_add(wg_v512, wg_v513);
    let wg_v515 = eval.m31_sub(wg_v514, z0_tmp_fec87_4[8]);
    let wg_v516 = eval.m31_sub(wg_v515, z2_tmp_fec87_5[8]);
    let wg_v517 = eval.m31_add(z2_tmp_fec87_5[1], wg_v516);
    let wg_v518 = eval.m31_mul(x_sum_tmp_fec87_6[3], y_sum_tmp_fec87_7[6]);
    let wg_v519 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[5]);
    let wg_v520 = eval.m31_add(wg_v518, wg_v519);
    let wg_v521 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[4]);
    let wg_v522 = eval.m31_add(wg_v520, wg_v521);
    let wg_v523 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[3]);
    let wg_v524 = eval.m31_add(wg_v522, wg_v523);
    let wg_v525 = eval.m31_sub(wg_v524, z0_tmp_fec87_4[9]);
    let wg_v526 = eval.m31_sub(wg_v525, z2_tmp_fec87_5[9]);
    let wg_v527 = eval.m31_add(z2_tmp_fec87_5[2], wg_v526);
    let wg_v528 = eval.m31_mul(x_sum_tmp_fec87_6[4], y_sum_tmp_fec87_7[6]);
    let wg_v529 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[5]);
    let wg_v530 = eval.m31_add(wg_v528, wg_v529);
    let wg_v531 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[4]);
    let wg_v532 = eval.m31_add(wg_v530, wg_v531);
    let wg_v533 = eval.m31_sub(wg_v532, z0_tmp_fec87_4[10]);
    let wg_v534 = eval.m31_sub(wg_v533, z2_tmp_fec87_5[10]);
    let wg_v535 = eval.m31_add(z2_tmp_fec87_5[3], wg_v534);
    let wg_v536 = eval.m31_mul(x_sum_tmp_fec87_6[5], y_sum_tmp_fec87_7[6]);
    let wg_v537 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[5]);
    let wg_v538 = eval.m31_add(wg_v536, wg_v537);
    let wg_v539 = eval.m31_sub(wg_v538, z0_tmp_fec87_4[11]);
    let wg_v540 = eval.m31_sub(wg_v539, z2_tmp_fec87_5[11]);
    let wg_v541 = eval.m31_add(z2_tmp_fec87_5[4], wg_v540);
    let wg_v542 = eval.m31_mul(x_sum_tmp_fec87_6[6], y_sum_tmp_fec87_7[6]);
    let wg_v543 = eval.m31_sub(wg_v542, z0_tmp_fec87_4[12]);
    let wg_v544 = eval.m31_sub(wg_v543, z2_tmp_fec87_5[12]);
    let wg_v545 = eval.m31_add(z2_tmp_fec87_5[5], wg_v544);
    let single_karatsuba_n_7_output_tmp_fec87_8 = [
        z0_tmp_fec87_4[0],
        z0_tmp_fec87_4[1],
        z0_tmp_fec87_4[2],
        z0_tmp_fec87_4[3],
        z0_tmp_fec87_4[4],
        z0_tmp_fec87_4[5],
        z0_tmp_fec87_4[6],
        wg_v426,
        wg_v432,
        wg_v440,
        wg_v450,
        wg_v462,
        wg_v476,
        wg_v491,
        wg_v505,
        wg_v517,
        wg_v527,
        wg_v535,
        wg_v541,
        wg_v545,
        z2_tmp_fec87_5[6],
        z2_tmp_fec87_5[7],
        z2_tmp_fec87_5[8],
        z2_tmp_fec87_5[9],
        z2_tmp_fec87_5[10],
        z2_tmp_fec87_5[11],
        z2_tmp_fec87_5[12],
    ];
    let wg_v546 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v547 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v548 = eval.m31_mul(wg_v546, wg_v547);
    let wg_v549 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v550 = eval.m31_mul(wg_v549, unpacked_limb_15_col20);
    let wg_v551 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v552 = eval.m31_mul(unpacked_limb_15_col20, wg_v551);
    let wg_v553 = eval.m31_add(wg_v550, wg_v552);
    let wg_v554 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v555 = eval.m31_mul(wg_v554, unpacked_limb_16_col21);
    let wg_v556 = eval.m31_mul(unpacked_limb_15_col20, unpacked_limb_15_col20);
    let wg_v557 = eval.m31_add(wg_v555, wg_v556);
    let wg_v558 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v559 = eval.m31_mul(unpacked_limb_16_col21, wg_v558);
    let wg_v560 = eval.m31_add(wg_v557, wg_v559);
    let wg_v561 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v562 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v563 = eval.m31_mul(wg_v561, wg_v562);
    let wg_v564 = eval.m31_mul(unpacked_limb_15_col20, unpacked_limb_16_col21);
    let wg_v565 = eval.m31_add(wg_v563, wg_v564);
    let wg_v566 = eval.m31_mul(unpacked_limb_16_col21, unpacked_limb_15_col20);
    let wg_v567 = eval.m31_add(wg_v565, wg_v566);
    let wg_v568 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v569 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v570 = eval.m31_mul(wg_v568, wg_v569);
    let wg_v571 = eval.m31_add(wg_v567, wg_v570);
    let wg_v572 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v573 = eval.m31_mul(wg_v572, unpacked_limb_18_col22);
    let wg_v574 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v575 = eval.m31_mul(unpacked_limb_15_col20, wg_v574);
    let wg_v576 = eval.m31_add(wg_v573, wg_v575);
    let wg_v577 = eval.m31_mul(unpacked_limb_16_col21, unpacked_limb_16_col21);
    let wg_v578 = eval.m31_add(wg_v576, wg_v577);
    let wg_v579 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v580 = eval.m31_mul(wg_v579, unpacked_limb_15_col20);
    let wg_v581 = eval.m31_add(wg_v578, wg_v580);
    let wg_v582 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v583 = eval.m31_mul(unpacked_limb_18_col22, wg_v582);
    let wg_v584 = eval.m31_add(wg_v581, wg_v583);
    let wg_v585 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v586 = eval.m31_mul(wg_v585, unpacked_limb_19_col23);
    let wg_v587 = eval.m31_mul(unpacked_limb_15_col20, unpacked_limb_18_col22);
    let wg_v588 = eval.m31_add(wg_v586, wg_v587);
    let wg_v589 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v590 = eval.m31_mul(unpacked_limb_16_col21, wg_v589);
    let wg_v591 = eval.m31_add(wg_v588, wg_v590);
    let wg_v592 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v593 = eval.m31_mul(wg_v592, unpacked_limb_16_col21);
    let wg_v594 = eval.m31_add(wg_v591, wg_v593);
    let wg_v595 = eval.m31_mul(unpacked_limb_18_col22, unpacked_limb_15_col20);
    let wg_v596 = eval.m31_add(wg_v594, wg_v595);
    let wg_v597 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v598 = eval.m31_mul(unpacked_limb_19_col23, wg_v597);
    let wg_v599 = eval.m31_add(wg_v596, wg_v598);
    let wg_v600 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v601 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v602 = eval.m31_mul(wg_v600, wg_v601);
    let wg_v603 = eval.m31_mul(unpacked_limb_15_col20, unpacked_limb_19_col23);
    let wg_v604 = eval.m31_add(wg_v602, wg_v603);
    let wg_v605 = eval.m31_mul(unpacked_limb_16_col21, unpacked_limb_18_col22);
    let wg_v606 = eval.m31_add(wg_v604, wg_v605);
    let wg_v607 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v608 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v609 = eval.m31_mul(wg_v607, wg_v608);
    let wg_v610 = eval.m31_add(wg_v606, wg_v609);
    let wg_v611 = eval.m31_mul(unpacked_limb_18_col22, unpacked_limb_16_col21);
    let wg_v612 = eval.m31_add(wg_v610, wg_v611);
    let wg_v613 = eval.m31_mul(unpacked_limb_19_col23, unpacked_limb_15_col20);
    let wg_v614 = eval.m31_add(wg_v612, wg_v613);
    let wg_v615 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v616 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v617 = eval.m31_mul(wg_v615, wg_v616);
    let wg_v618 = eval.m31_add(wg_v614, wg_v617);
    let wg_v619 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v620 = eval.m31_mul(unpacked_limb_15_col20, wg_v619);
    let wg_v621 = eval.m31_mul(unpacked_limb_16_col21, unpacked_limb_19_col23);
    let wg_v622 = eval.m31_add(wg_v620, wg_v621);
    let wg_v623 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v624 = eval.m31_mul(wg_v623, unpacked_limb_18_col22);
    let wg_v625 = eval.m31_add(wg_v622, wg_v624);
    let wg_v626 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v627 = eval.m31_mul(unpacked_limb_18_col22, wg_v626);
    let wg_v628 = eval.m31_add(wg_v625, wg_v627);
    let wg_v629 = eval.m31_mul(unpacked_limb_19_col23, unpacked_limb_16_col21);
    let wg_v630 = eval.m31_add(wg_v628, wg_v629);
    let wg_v631 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v632 = eval.m31_mul(wg_v631, unpacked_limb_15_col20);
    let wg_v633 = eval.m31_add(wg_v630, wg_v632);
    let wg_v634 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v635 = eval.m31_mul(unpacked_limb_16_col21, wg_v634);
    let wg_v636 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v637 = eval.m31_mul(wg_v636, unpacked_limb_19_col23);
    let wg_v638 = eval.m31_add(wg_v635, wg_v637);
    let wg_v639 = eval.m31_mul(unpacked_limb_18_col22, unpacked_limb_18_col22);
    let wg_v640 = eval.m31_add(wg_v638, wg_v639);
    let wg_v641 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v642 = eval.m31_mul(unpacked_limb_19_col23, wg_v641);
    let wg_v643 = eval.m31_add(wg_v640, wg_v642);
    let wg_v644 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v645 = eval.m31_mul(wg_v644, unpacked_limb_16_col21);
    let wg_v646 = eval.m31_add(wg_v643, wg_v645);
    let wg_v647 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v648 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v649 = eval.m31_mul(wg_v647, wg_v648);
    let wg_v650 = eval.m31_mul(unpacked_limb_18_col22, unpacked_limb_19_col23);
    let wg_v651 = eval.m31_add(wg_v649, wg_v650);
    let wg_v652 = eval.m31_mul(unpacked_limb_19_col23, unpacked_limb_18_col22);
    let wg_v653 = eval.m31_add(wg_v651, wg_v652);
    let wg_v654 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v655 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v656 = eval.m31_mul(wg_v654, wg_v655);
    let wg_v657 = eval.m31_add(wg_v653, wg_v656);
    let wg_v658 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v659 = eval.m31_mul(unpacked_limb_18_col22, wg_v658);
    let wg_v660 = eval.m31_mul(unpacked_limb_19_col23, unpacked_limb_19_col23);
    let wg_v661 = eval.m31_add(wg_v659, wg_v660);
    let wg_v662 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v663 = eval.m31_mul(wg_v662, unpacked_limb_18_col22);
    let wg_v664 = eval.m31_add(wg_v661, wg_v663);
    let wg_v665 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v666 = eval.m31_mul(unpacked_limb_19_col23, wg_v665);
    let wg_v667 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v668 = eval.m31_mul(wg_v667, unpacked_limb_19_col23);
    let wg_v669 = eval.m31_add(wg_v666, wg_v668);
    let wg_v670 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v671 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v672 = eval.m31_mul(wg_v670, wg_v671);
    let z0_tmp_fec87_9 = [
        wg_v548, wg_v553, wg_v560, wg_v571, wg_v584, wg_v599, wg_v618, wg_v633, wg_v646, wg_v657,
        wg_v664, wg_v669, wg_v672,
    ];
    let wg_v673 = eval.m31_mul(unpacked_limb_21_col24, unpacked_limb_21_col24);
    let wg_v674 = eval.m31_mul(unpacked_limb_21_col24, unpacked_limb_22_col25);
    let wg_v675 = eval.m31_mul(unpacked_limb_22_col25, unpacked_limb_21_col24);
    let wg_v676 = eval.m31_add(wg_v674, wg_v675);
    let wg_v677 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v678 = eval.m31_mul(unpacked_limb_21_col24, wg_v677);
    let wg_v679 = eval.m31_mul(unpacked_limb_22_col25, unpacked_limb_22_col25);
    let wg_v680 = eval.m31_add(wg_v678, wg_v679);
    let wg_v681 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v682 = eval.m31_mul(wg_v681, unpacked_limb_21_col24);
    let wg_v683 = eval.m31_add(wg_v680, wg_v682);
    let wg_v684 = eval.m31_mul(unpacked_limb_21_col24, unpacked_limb_24_col26);
    let wg_v685 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v686 = eval.m31_mul(unpacked_limb_22_col25, wg_v685);
    let wg_v687 = eval.m31_add(wg_v684, wg_v686);
    let wg_v688 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v689 = eval.m31_mul(wg_v688, unpacked_limb_22_col25);
    let wg_v690 = eval.m31_add(wg_v687, wg_v689);
    let wg_v691 = eval.m31_mul(unpacked_limb_24_col26, unpacked_limb_21_col24);
    let wg_v692 = eval.m31_add(wg_v690, wg_v691);
    let wg_v693 = eval.m31_mul(unpacked_limb_21_col24, unpacked_limb_25_col27);
    let wg_v694 = eval.m31_mul(unpacked_limb_22_col25, unpacked_limb_24_col26);
    let wg_v695 = eval.m31_add(wg_v693, wg_v694);
    let wg_v696 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v697 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v698 = eval.m31_mul(wg_v696, wg_v697);
    let wg_v699 = eval.m31_add(wg_v695, wg_v698);
    let wg_v700 = eval.m31_mul(unpacked_limb_24_col26, unpacked_limb_22_col25);
    let wg_v701 = eval.m31_add(wg_v699, wg_v700);
    let wg_v702 = eval.m31_mul(unpacked_limb_25_col27, unpacked_limb_21_col24);
    let wg_v703 = eval.m31_add(wg_v701, wg_v702);
    let wg_v704 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v705 = eval.m31_mul(unpacked_limb_21_col24, wg_v704);
    let wg_v706 = eval.m31_mul(unpacked_limb_22_col25, unpacked_limb_25_col27);
    let wg_v707 = eval.m31_add(wg_v705, wg_v706);
    let wg_v708 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v709 = eval.m31_mul(wg_v708, unpacked_limb_24_col26);
    let wg_v710 = eval.m31_add(wg_v707, wg_v709);
    let wg_v711 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v712 = eval.m31_mul(unpacked_limb_24_col26, wg_v711);
    let wg_v713 = eval.m31_add(wg_v710, wg_v712);
    let wg_v714 = eval.m31_mul(unpacked_limb_25_col27, unpacked_limb_22_col25);
    let wg_v715 = eval.m31_add(wg_v713, wg_v714);
    let wg_v716 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v717 = eval.m31_mul(wg_v716, unpacked_limb_21_col24);
    let wg_v718 = eval.m31_add(wg_v715, wg_v717);
    let wg_v719 = eval.m31_mul(unpacked_limb_21_col24, input_limb_9_col9);
    let wg_v720 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v721 = eval.m31_mul(unpacked_limb_22_col25, wg_v720);
    let wg_v722 = eval.m31_add(wg_v719, wg_v721);
    let wg_v723 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v724 = eval.m31_mul(wg_v723, unpacked_limb_25_col27);
    let wg_v725 = eval.m31_add(wg_v722, wg_v724);
    let wg_v726 = eval.m31_mul(unpacked_limb_24_col26, unpacked_limb_24_col26);
    let wg_v727 = eval.m31_add(wg_v725, wg_v726);
    let wg_v728 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v729 = eval.m31_mul(unpacked_limb_25_col27, wg_v728);
    let wg_v730 = eval.m31_add(wg_v727, wg_v729);
    let wg_v731 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v732 = eval.m31_mul(wg_v731, unpacked_limb_22_col25);
    let wg_v733 = eval.m31_add(wg_v730, wg_v732);
    let wg_v734 = eval.m31_mul(input_limb_9_col9, unpacked_limb_21_col24);
    let wg_v735 = eval.m31_add(wg_v733, wg_v734);
    let wg_v736 = eval.m31_mul(unpacked_limb_22_col25, input_limb_9_col9);
    let wg_v737 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v738 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v739 = eval.m31_mul(wg_v737, wg_v738);
    let wg_v740 = eval.m31_add(wg_v736, wg_v739);
    let wg_v741 = eval.m31_mul(unpacked_limb_24_col26, unpacked_limb_25_col27);
    let wg_v742 = eval.m31_add(wg_v740, wg_v741);
    let wg_v743 = eval.m31_mul(unpacked_limb_25_col27, unpacked_limb_24_col26);
    let wg_v744 = eval.m31_add(wg_v742, wg_v743);
    let wg_v745 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v746 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v747 = eval.m31_mul(wg_v745, wg_v746);
    let wg_v748 = eval.m31_add(wg_v744, wg_v747);
    let wg_v749 = eval.m31_mul(input_limb_9_col9, unpacked_limb_22_col25);
    let wg_v750 = eval.m31_add(wg_v748, wg_v749);
    let wg_v751 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v752 = eval.m31_mul(wg_v751, input_limb_9_col9);
    let wg_v753 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v754 = eval.m31_mul(unpacked_limb_24_col26, wg_v753);
    let wg_v755 = eval.m31_add(wg_v752, wg_v754);
    let wg_v756 = eval.m31_mul(unpacked_limb_25_col27, unpacked_limb_25_col27);
    let wg_v757 = eval.m31_add(wg_v755, wg_v756);
    let wg_v758 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v759 = eval.m31_mul(wg_v758, unpacked_limb_24_col26);
    let wg_v760 = eval.m31_add(wg_v757, wg_v759);
    let wg_v761 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v762 = eval.m31_mul(input_limb_9_col9, wg_v761);
    let wg_v763 = eval.m31_add(wg_v760, wg_v762);
    let wg_v764 = eval.m31_mul(unpacked_limb_24_col26, input_limb_9_col9);
    let wg_v765 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v766 = eval.m31_mul(unpacked_limb_25_col27, wg_v765);
    let wg_v767 = eval.m31_add(wg_v764, wg_v766);
    let wg_v768 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v769 = eval.m31_mul(wg_v768, unpacked_limb_25_col27);
    let wg_v770 = eval.m31_add(wg_v767, wg_v769);
    let wg_v771 = eval.m31_mul(input_limb_9_col9, unpacked_limb_24_col26);
    let wg_v772 = eval.m31_add(wg_v770, wg_v771);
    let wg_v773 = eval.m31_mul(unpacked_limb_25_col27, input_limb_9_col9);
    let wg_v774 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v775 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v776 = eval.m31_mul(wg_v774, wg_v775);
    let wg_v777 = eval.m31_add(wg_v773, wg_v776);
    let wg_v778 = eval.m31_mul(input_limb_9_col9, unpacked_limb_25_col27);
    let wg_v779 = eval.m31_add(wg_v777, wg_v778);
    let wg_v780 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v781 = eval.m31_mul(wg_v780, input_limb_9_col9);
    let wg_v782 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v783 = eval.m31_mul(input_limb_9_col9, wg_v782);
    let wg_v784 = eval.m31_add(wg_v781, wg_v783);
    let wg_v785 = eval.m31_mul(input_limb_9_col9, input_limb_9_col9);
    let z2_tmp_fec87_10 = [
        wg_v673, wg_v676, wg_v683, wg_v692, wg_v703, wg_v718, wg_v735, wg_v750, wg_v763, wg_v772,
        wg_v779, wg_v784, wg_v785,
    ];
    let wg_v786 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v787 = eval.m31_add(wg_v786, unpacked_limb_21_col24);
    let wg_v788 = eval.m31_add(unpacked_limb_15_col20, unpacked_limb_22_col25);
    let wg_v789 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v790 = eval.m31_add(unpacked_limb_16_col21, wg_v789);
    let wg_v791 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v792 = eval.m31_add(wg_v791, unpacked_limb_24_col26);
    let wg_v793 = eval.m31_add(unpacked_limb_18_col22, unpacked_limb_25_col27);
    let wg_v794 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v795 = eval.m31_add(unpacked_limb_19_col23, wg_v794);
    let wg_v796 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v797 = eval.m31_add(wg_v796, input_limb_9_col9);
    let x_sum_tmp_fec87_11 = [
        wg_v787, wg_v788, wg_v790, wg_v792, wg_v793, wg_v795, wg_v797,
    ];
    let wg_v798 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v799 = eval.m31_add(wg_v798, unpacked_limb_21_col24);
    let wg_v800 = eval.m31_add(unpacked_limb_15_col20, unpacked_limb_22_col25);
    let wg_v801 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v802 = eval.m31_add(unpacked_limb_16_col21, wg_v801);
    let wg_v803 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v804 = eval.m31_add(wg_v803, unpacked_limb_24_col26);
    let wg_v805 = eval.m31_add(unpacked_limb_18_col22, unpacked_limb_25_col27);
    let wg_v806 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v807 = eval.m31_add(unpacked_limb_19_col23, wg_v806);
    let wg_v808 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v809 = eval.m31_add(wg_v808, input_limb_9_col9);
    let y_sum_tmp_fec87_12 = [
        wg_v799, wg_v800, wg_v802, wg_v804, wg_v805, wg_v807, wg_v809,
    ];
    let wg_v810 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[0]);
    let wg_v811 = eval.m31_sub(wg_v810, z0_tmp_fec87_9[0]);
    let wg_v812 = eval.m31_sub(wg_v811, z2_tmp_fec87_10[0]);
    let wg_v813 = eval.m31_add(z0_tmp_fec87_9[7], wg_v812);
    let wg_v814 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[1]);
    let wg_v815 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[0]);
    let wg_v816 = eval.m31_add(wg_v814, wg_v815);
    let wg_v817 = eval.m31_sub(wg_v816, z0_tmp_fec87_9[1]);
    let wg_v818 = eval.m31_sub(wg_v817, z2_tmp_fec87_10[1]);
    let wg_v819 = eval.m31_add(z0_tmp_fec87_9[8], wg_v818);
    let wg_v820 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[2]);
    let wg_v821 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[1]);
    let wg_v822 = eval.m31_add(wg_v820, wg_v821);
    let wg_v823 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[0]);
    let wg_v824 = eval.m31_add(wg_v822, wg_v823);
    let wg_v825 = eval.m31_sub(wg_v824, z0_tmp_fec87_9[2]);
    let wg_v826 = eval.m31_sub(wg_v825, z2_tmp_fec87_10[2]);
    let wg_v827 = eval.m31_add(z0_tmp_fec87_9[9], wg_v826);
    let wg_v828 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[3]);
    let wg_v829 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[2]);
    let wg_v830 = eval.m31_add(wg_v828, wg_v829);
    let wg_v831 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[1]);
    let wg_v832 = eval.m31_add(wg_v830, wg_v831);
    let wg_v833 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[0]);
    let wg_v834 = eval.m31_add(wg_v832, wg_v833);
    let wg_v835 = eval.m31_sub(wg_v834, z0_tmp_fec87_9[3]);
    let wg_v836 = eval.m31_sub(wg_v835, z2_tmp_fec87_10[3]);
    let wg_v837 = eval.m31_add(z0_tmp_fec87_9[10], wg_v836);
    let wg_v838 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[4]);
    let wg_v839 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[3]);
    let wg_v840 = eval.m31_add(wg_v838, wg_v839);
    let wg_v841 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[2]);
    let wg_v842 = eval.m31_add(wg_v840, wg_v841);
    let wg_v843 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[1]);
    let wg_v844 = eval.m31_add(wg_v842, wg_v843);
    let wg_v845 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[0]);
    let wg_v846 = eval.m31_add(wg_v844, wg_v845);
    let wg_v847 = eval.m31_sub(wg_v846, z0_tmp_fec87_9[4]);
    let wg_v848 = eval.m31_sub(wg_v847, z2_tmp_fec87_10[4]);
    let wg_v849 = eval.m31_add(z0_tmp_fec87_9[11], wg_v848);
    let wg_v850 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[5]);
    let wg_v851 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[4]);
    let wg_v852 = eval.m31_add(wg_v850, wg_v851);
    let wg_v853 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[3]);
    let wg_v854 = eval.m31_add(wg_v852, wg_v853);
    let wg_v855 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[2]);
    let wg_v856 = eval.m31_add(wg_v854, wg_v855);
    let wg_v857 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[1]);
    let wg_v858 = eval.m31_add(wg_v856, wg_v857);
    let wg_v859 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[0]);
    let wg_v860 = eval.m31_add(wg_v858, wg_v859);
    let wg_v861 = eval.m31_sub(wg_v860, z0_tmp_fec87_9[5]);
    let wg_v862 = eval.m31_sub(wg_v861, z2_tmp_fec87_10[5]);
    let wg_v863 = eval.m31_add(z0_tmp_fec87_9[12], wg_v862);
    let wg_v864 = eval.m31_mul(x_sum_tmp_fec87_11[0], y_sum_tmp_fec87_12[6]);
    let wg_v865 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[5]);
    let wg_v866 = eval.m31_add(wg_v864, wg_v865);
    let wg_v867 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[4]);
    let wg_v868 = eval.m31_add(wg_v866, wg_v867);
    let wg_v869 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[3]);
    let wg_v870 = eval.m31_add(wg_v868, wg_v869);
    let wg_v871 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[2]);
    let wg_v872 = eval.m31_add(wg_v870, wg_v871);
    let wg_v873 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[1]);
    let wg_v874 = eval.m31_add(wg_v872, wg_v873);
    let wg_v875 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[0]);
    let wg_v876 = eval.m31_add(wg_v874, wg_v875);
    let wg_v877 = eval.m31_sub(wg_v876, z0_tmp_fec87_9[6]);
    let wg_v878 = eval.m31_sub(wg_v877, z2_tmp_fec87_10[6]);
    let wg_v879 = eval.m31_mul(x_sum_tmp_fec87_11[1], y_sum_tmp_fec87_12[6]);
    let wg_v880 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[5]);
    let wg_v881 = eval.m31_add(wg_v879, wg_v880);
    let wg_v882 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[4]);
    let wg_v883 = eval.m31_add(wg_v881, wg_v882);
    let wg_v884 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[3]);
    let wg_v885 = eval.m31_add(wg_v883, wg_v884);
    let wg_v886 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[2]);
    let wg_v887 = eval.m31_add(wg_v885, wg_v886);
    let wg_v888 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[1]);
    let wg_v889 = eval.m31_add(wg_v887, wg_v888);
    let wg_v890 = eval.m31_sub(wg_v889, z0_tmp_fec87_9[7]);
    let wg_v891 = eval.m31_sub(wg_v890, z2_tmp_fec87_10[7]);
    let wg_v892 = eval.m31_add(z2_tmp_fec87_10[0], wg_v891);
    let wg_v893 = eval.m31_mul(x_sum_tmp_fec87_11[2], y_sum_tmp_fec87_12[6]);
    let wg_v894 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[5]);
    let wg_v895 = eval.m31_add(wg_v893, wg_v894);
    let wg_v896 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[4]);
    let wg_v897 = eval.m31_add(wg_v895, wg_v896);
    let wg_v898 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[3]);
    let wg_v899 = eval.m31_add(wg_v897, wg_v898);
    let wg_v900 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[2]);
    let wg_v901 = eval.m31_add(wg_v899, wg_v900);
    let wg_v902 = eval.m31_sub(wg_v901, z0_tmp_fec87_9[8]);
    let wg_v903 = eval.m31_sub(wg_v902, z2_tmp_fec87_10[8]);
    let wg_v904 = eval.m31_add(z2_tmp_fec87_10[1], wg_v903);
    let wg_v905 = eval.m31_mul(x_sum_tmp_fec87_11[3], y_sum_tmp_fec87_12[6]);
    let wg_v906 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[5]);
    let wg_v907 = eval.m31_add(wg_v905, wg_v906);
    let wg_v908 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[4]);
    let wg_v909 = eval.m31_add(wg_v907, wg_v908);
    let wg_v910 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[3]);
    let wg_v911 = eval.m31_add(wg_v909, wg_v910);
    let wg_v912 = eval.m31_sub(wg_v911, z0_tmp_fec87_9[9]);
    let wg_v913 = eval.m31_sub(wg_v912, z2_tmp_fec87_10[9]);
    let wg_v914 = eval.m31_add(z2_tmp_fec87_10[2], wg_v913);
    let wg_v915 = eval.m31_mul(x_sum_tmp_fec87_11[4], y_sum_tmp_fec87_12[6]);
    let wg_v916 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[5]);
    let wg_v917 = eval.m31_add(wg_v915, wg_v916);
    let wg_v918 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[4]);
    let wg_v919 = eval.m31_add(wg_v917, wg_v918);
    let wg_v920 = eval.m31_sub(wg_v919, z0_tmp_fec87_9[10]);
    let wg_v921 = eval.m31_sub(wg_v920, z2_tmp_fec87_10[10]);
    let wg_v922 = eval.m31_add(z2_tmp_fec87_10[3], wg_v921);
    let wg_v923 = eval.m31_mul(x_sum_tmp_fec87_11[5], y_sum_tmp_fec87_12[6]);
    let wg_v924 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[5]);
    let wg_v925 = eval.m31_add(wg_v923, wg_v924);
    let wg_v926 = eval.m31_sub(wg_v925, z0_tmp_fec87_9[11]);
    let wg_v927 = eval.m31_sub(wg_v926, z2_tmp_fec87_10[11]);
    let wg_v928 = eval.m31_add(z2_tmp_fec87_10[4], wg_v927);
    let wg_v929 = eval.m31_mul(x_sum_tmp_fec87_11[6], y_sum_tmp_fec87_12[6]);
    let wg_v930 = eval.m31_sub(wg_v929, z0_tmp_fec87_9[12]);
    let wg_v931 = eval.m31_sub(wg_v930, z2_tmp_fec87_10[12]);
    let wg_v932 = eval.m31_add(z2_tmp_fec87_10[5], wg_v931);
    let single_karatsuba_n_7_output_tmp_fec87_13 = [
        z0_tmp_fec87_9[0],
        z0_tmp_fec87_9[1],
        z0_tmp_fec87_9[2],
        z0_tmp_fec87_9[3],
        z0_tmp_fec87_9[4],
        z0_tmp_fec87_9[5],
        z0_tmp_fec87_9[6],
        wg_v813,
        wg_v819,
        wg_v827,
        wg_v837,
        wg_v849,
        wg_v863,
        wg_v878,
        wg_v892,
        wg_v904,
        wg_v914,
        wg_v922,
        wg_v928,
        wg_v932,
        z2_tmp_fec87_10[6],
        z2_tmp_fec87_10[7],
        z2_tmp_fec87_10[8],
        z2_tmp_fec87_10[9],
        z2_tmp_fec87_10[10],
        z2_tmp_fec87_10[11],
        z2_tmp_fec87_10[12],
    ];
    let wg_v933 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v934 = eval.m31_add(unpacked_limb_0_col10, wg_v933);
    let wg_v935 = eval.m31_add(unpacked_limb_1_col11, unpacked_limb_15_col20);
    let wg_v936 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v937 = eval.m31_add(wg_v936, unpacked_limb_16_col21);
    let wg_v938 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v939 = eval.m31_add(unpacked_limb_3_col12, wg_v938);
    let wg_v940 = eval.m31_add(unpacked_limb_4_col13, unpacked_limb_18_col22);
    let wg_v941 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v942 = eval.m31_add(wg_v941, unpacked_limb_19_col23);
    let wg_v943 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v944 = eval.m31_add(unpacked_limb_6_col14, wg_v943);
    let wg_v945 = eval.m31_add(unpacked_limb_7_col15, unpacked_limb_21_col24);
    let wg_v946 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v947 = eval.m31_add(wg_v946, unpacked_limb_22_col25);
    let wg_v948 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v949 = eval.m31_add(unpacked_limb_9_col16, wg_v948);
    let wg_v950 = eval.m31_add(unpacked_limb_10_col17, unpacked_limb_24_col26);
    let wg_v951 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v952 = eval.m31_add(wg_v951, unpacked_limb_25_col27);
    let wg_v953 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v954 = eval.m31_add(unpacked_limb_12_col18, wg_v953);
    let wg_v955 = eval.m31_add(unpacked_limb_13_col19, input_limb_9_col9);
    let x_sum_tmp_fec87_14 = [
        wg_v934, wg_v935, wg_v937, wg_v939, wg_v940, wg_v942, wg_v944, wg_v945, wg_v947, wg_v949,
        wg_v950, wg_v952, wg_v954, wg_v955,
    ];
    let wg_v956 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v957 = eval.m31_add(unpacked_limb_0_col10, wg_v956);
    let wg_v958 = eval.m31_add(unpacked_limb_1_col11, unpacked_limb_15_col20);
    let wg_v959 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v960 = eval.m31_add(wg_v959, unpacked_limb_16_col21);
    let wg_v961 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v962 = eval.m31_add(unpacked_limb_3_col12, wg_v961);
    let wg_v963 = eval.m31_add(unpacked_limb_4_col13, unpacked_limb_18_col22);
    let wg_v964 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v965 = eval.m31_add(wg_v964, unpacked_limb_19_col23);
    let wg_v966 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v967 = eval.m31_add(unpacked_limb_6_col14, wg_v966);
    let wg_v968 = eval.m31_add(unpacked_limb_7_col15, unpacked_limb_21_col24);
    let wg_v969 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v970 = eval.m31_add(wg_v969, unpacked_limb_22_col25);
    let wg_v971 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v972 = eval.m31_add(unpacked_limb_9_col16, wg_v971);
    let wg_v973 = eval.m31_add(unpacked_limb_10_col17, unpacked_limb_24_col26);
    let wg_v974 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v975 = eval.m31_add(wg_v974, unpacked_limb_25_col27);
    let wg_v976 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v977 = eval.m31_add(unpacked_limb_12_col18, wg_v976);
    let wg_v978 = eval.m31_add(unpacked_limb_13_col19, input_limb_9_col9);
    let y_sum_tmp_fec87_15 = [
        wg_v957, wg_v958, wg_v960, wg_v962, wg_v963, wg_v965, wg_v967, wg_v968, wg_v970, wg_v972,
        wg_v973, wg_v975, wg_v977, wg_v978,
    ];
    let wg_v979 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[0]);
    let wg_v980 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[1]);
    let wg_v981 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[0]);
    let wg_v982 = eval.m31_add(wg_v980, wg_v981);
    let wg_v983 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[2]);
    let wg_v984 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[1]);
    let wg_v985 = eval.m31_add(wg_v983, wg_v984);
    let wg_v986 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[0]);
    let wg_v987 = eval.m31_add(wg_v985, wg_v986);
    let wg_v988 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[3]);
    let wg_v989 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[2]);
    let wg_v990 = eval.m31_add(wg_v988, wg_v989);
    let wg_v991 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[1]);
    let wg_v992 = eval.m31_add(wg_v990, wg_v991);
    let wg_v993 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[0]);
    let wg_v994 = eval.m31_add(wg_v992, wg_v993);
    let wg_v995 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[4]);
    let wg_v996 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[3]);
    let wg_v997 = eval.m31_add(wg_v995, wg_v996);
    let wg_v998 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[2]);
    let wg_v999 = eval.m31_add(wg_v997, wg_v998);
    let wg_v1000 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[1]);
    let wg_v1001 = eval.m31_add(wg_v999, wg_v1000);
    let wg_v1002 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[0]);
    let wg_v1003 = eval.m31_add(wg_v1001, wg_v1002);
    let wg_v1004 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[5]);
    let wg_v1005 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[4]);
    let wg_v1006 = eval.m31_add(wg_v1004, wg_v1005);
    let wg_v1007 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[3]);
    let wg_v1008 = eval.m31_add(wg_v1006, wg_v1007);
    let wg_v1009 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[2]);
    let wg_v1010 = eval.m31_add(wg_v1008, wg_v1009);
    let wg_v1011 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[1]);
    let wg_v1012 = eval.m31_add(wg_v1010, wg_v1011);
    let wg_v1013 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[0]);
    let wg_v1014 = eval.m31_add(wg_v1012, wg_v1013);
    let wg_v1015 = eval.m31_mul(x_sum_tmp_fec87_14[0], y_sum_tmp_fec87_15[6]);
    let wg_v1016 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[5]);
    let wg_v1017 = eval.m31_add(wg_v1015, wg_v1016);
    let wg_v1018 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[4]);
    let wg_v1019 = eval.m31_add(wg_v1017, wg_v1018);
    let wg_v1020 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[3]);
    let wg_v1021 = eval.m31_add(wg_v1019, wg_v1020);
    let wg_v1022 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[2]);
    let wg_v1023 = eval.m31_add(wg_v1021, wg_v1022);
    let wg_v1024 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[1]);
    let wg_v1025 = eval.m31_add(wg_v1023, wg_v1024);
    let wg_v1026 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[0]);
    let wg_v1027 = eval.m31_add(wg_v1025, wg_v1026);
    let wg_v1028 = eval.m31_mul(x_sum_tmp_fec87_14[1], y_sum_tmp_fec87_15[6]);
    let wg_v1029 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[5]);
    let wg_v1030 = eval.m31_add(wg_v1028, wg_v1029);
    let wg_v1031 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[4]);
    let wg_v1032 = eval.m31_add(wg_v1030, wg_v1031);
    let wg_v1033 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[3]);
    let wg_v1034 = eval.m31_add(wg_v1032, wg_v1033);
    let wg_v1035 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[2]);
    let wg_v1036 = eval.m31_add(wg_v1034, wg_v1035);
    let wg_v1037 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[1]);
    let wg_v1038 = eval.m31_add(wg_v1036, wg_v1037);
    let wg_v1039 = eval.m31_mul(x_sum_tmp_fec87_14[2], y_sum_tmp_fec87_15[6]);
    let wg_v1040 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[5]);
    let wg_v1041 = eval.m31_add(wg_v1039, wg_v1040);
    let wg_v1042 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[4]);
    let wg_v1043 = eval.m31_add(wg_v1041, wg_v1042);
    let wg_v1044 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[3]);
    let wg_v1045 = eval.m31_add(wg_v1043, wg_v1044);
    let wg_v1046 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[2]);
    let wg_v1047 = eval.m31_add(wg_v1045, wg_v1046);
    let wg_v1048 = eval.m31_mul(x_sum_tmp_fec87_14[3], y_sum_tmp_fec87_15[6]);
    let wg_v1049 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[5]);
    let wg_v1050 = eval.m31_add(wg_v1048, wg_v1049);
    let wg_v1051 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[4]);
    let wg_v1052 = eval.m31_add(wg_v1050, wg_v1051);
    let wg_v1053 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[3]);
    let wg_v1054 = eval.m31_add(wg_v1052, wg_v1053);
    let wg_v1055 = eval.m31_mul(x_sum_tmp_fec87_14[4], y_sum_tmp_fec87_15[6]);
    let wg_v1056 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[5]);
    let wg_v1057 = eval.m31_add(wg_v1055, wg_v1056);
    let wg_v1058 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[4]);
    let wg_v1059 = eval.m31_add(wg_v1057, wg_v1058);
    let wg_v1060 = eval.m31_mul(x_sum_tmp_fec87_14[5], y_sum_tmp_fec87_15[6]);
    let wg_v1061 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[5]);
    let wg_v1062 = eval.m31_add(wg_v1060, wg_v1061);
    let wg_v1063 = eval.m31_mul(x_sum_tmp_fec87_14[6], y_sum_tmp_fec87_15[6]);
    let z0_tmp_fec87_16 = [
        wg_v979, wg_v982, wg_v987, wg_v994, wg_v1003, wg_v1014, wg_v1027, wg_v1038, wg_v1047,
        wg_v1054, wg_v1059, wg_v1062, wg_v1063,
    ];
    let wg_v1064 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[7]);
    let wg_v1065 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[8]);
    let wg_v1066 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[7]);
    let wg_v1067 = eval.m31_add(wg_v1065, wg_v1066);
    let wg_v1068 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[9]);
    let wg_v1069 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[8]);
    let wg_v1070 = eval.m31_add(wg_v1068, wg_v1069);
    let wg_v1071 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[7]);
    let wg_v1072 = eval.m31_add(wg_v1070, wg_v1071);
    let wg_v1073 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[10]);
    let wg_v1074 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[9]);
    let wg_v1075 = eval.m31_add(wg_v1073, wg_v1074);
    let wg_v1076 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[8]);
    let wg_v1077 = eval.m31_add(wg_v1075, wg_v1076);
    let wg_v1078 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[7]);
    let wg_v1079 = eval.m31_add(wg_v1077, wg_v1078);
    let wg_v1080 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[11]);
    let wg_v1081 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[10]);
    let wg_v1082 = eval.m31_add(wg_v1080, wg_v1081);
    let wg_v1083 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[9]);
    let wg_v1084 = eval.m31_add(wg_v1082, wg_v1083);
    let wg_v1085 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[8]);
    let wg_v1086 = eval.m31_add(wg_v1084, wg_v1085);
    let wg_v1087 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[7]);
    let wg_v1088 = eval.m31_add(wg_v1086, wg_v1087);
    let wg_v1089 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[12]);
    let wg_v1090 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[11]);
    let wg_v1091 = eval.m31_add(wg_v1089, wg_v1090);
    let wg_v1092 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[10]);
    let wg_v1093 = eval.m31_add(wg_v1091, wg_v1092);
    let wg_v1094 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[9]);
    let wg_v1095 = eval.m31_add(wg_v1093, wg_v1094);
    let wg_v1096 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[8]);
    let wg_v1097 = eval.m31_add(wg_v1095, wg_v1096);
    let wg_v1098 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[7]);
    let wg_v1099 = eval.m31_add(wg_v1097, wg_v1098);
    let wg_v1100 = eval.m31_mul(x_sum_tmp_fec87_14[7], y_sum_tmp_fec87_15[13]);
    let wg_v1101 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[12]);
    let wg_v1102 = eval.m31_add(wg_v1100, wg_v1101);
    let wg_v1103 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[11]);
    let wg_v1104 = eval.m31_add(wg_v1102, wg_v1103);
    let wg_v1105 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[10]);
    let wg_v1106 = eval.m31_add(wg_v1104, wg_v1105);
    let wg_v1107 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[9]);
    let wg_v1108 = eval.m31_add(wg_v1106, wg_v1107);
    let wg_v1109 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[8]);
    let wg_v1110 = eval.m31_add(wg_v1108, wg_v1109);
    let wg_v1111 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[7]);
    let wg_v1112 = eval.m31_add(wg_v1110, wg_v1111);
    let wg_v1113 = eval.m31_mul(x_sum_tmp_fec87_14[8], y_sum_tmp_fec87_15[13]);
    let wg_v1114 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[12]);
    let wg_v1115 = eval.m31_add(wg_v1113, wg_v1114);
    let wg_v1116 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[11]);
    let wg_v1117 = eval.m31_add(wg_v1115, wg_v1116);
    let wg_v1118 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[10]);
    let wg_v1119 = eval.m31_add(wg_v1117, wg_v1118);
    let wg_v1120 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[9]);
    let wg_v1121 = eval.m31_add(wg_v1119, wg_v1120);
    let wg_v1122 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[8]);
    let wg_v1123 = eval.m31_add(wg_v1121, wg_v1122);
    let wg_v1124 = eval.m31_mul(x_sum_tmp_fec87_14[9], y_sum_tmp_fec87_15[13]);
    let wg_v1125 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[12]);
    let wg_v1126 = eval.m31_add(wg_v1124, wg_v1125);
    let wg_v1127 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[11]);
    let wg_v1128 = eval.m31_add(wg_v1126, wg_v1127);
    let wg_v1129 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[10]);
    let wg_v1130 = eval.m31_add(wg_v1128, wg_v1129);
    let wg_v1131 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[9]);
    let wg_v1132 = eval.m31_add(wg_v1130, wg_v1131);
    let wg_v1133 = eval.m31_mul(x_sum_tmp_fec87_14[10], y_sum_tmp_fec87_15[13]);
    let wg_v1134 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[12]);
    let wg_v1135 = eval.m31_add(wg_v1133, wg_v1134);
    let wg_v1136 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[11]);
    let wg_v1137 = eval.m31_add(wg_v1135, wg_v1136);
    let wg_v1138 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[10]);
    let wg_v1139 = eval.m31_add(wg_v1137, wg_v1138);
    let wg_v1140 = eval.m31_mul(x_sum_tmp_fec87_14[11], y_sum_tmp_fec87_15[13]);
    let wg_v1141 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[12]);
    let wg_v1142 = eval.m31_add(wg_v1140, wg_v1141);
    let wg_v1143 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[11]);
    let wg_v1144 = eval.m31_add(wg_v1142, wg_v1143);
    let wg_v1145 = eval.m31_mul(x_sum_tmp_fec87_14[12], y_sum_tmp_fec87_15[13]);
    let wg_v1146 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[12]);
    let wg_v1147 = eval.m31_add(wg_v1145, wg_v1146);
    let wg_v1148 = eval.m31_mul(x_sum_tmp_fec87_14[13], y_sum_tmp_fec87_15[13]);
    let z2_tmp_fec87_17 = [
        wg_v1064, wg_v1067, wg_v1072, wg_v1079, wg_v1088, wg_v1099, wg_v1112, wg_v1123, wg_v1132,
        wg_v1139, wg_v1144, wg_v1147, wg_v1148,
    ];
    let wg_v1149 = eval.m31_add(x_sum_tmp_fec87_14[0], x_sum_tmp_fec87_14[7]);
    let wg_v1150 = eval.m31_add(x_sum_tmp_fec87_14[1], x_sum_tmp_fec87_14[8]);
    let wg_v1151 = eval.m31_add(x_sum_tmp_fec87_14[2], x_sum_tmp_fec87_14[9]);
    let wg_v1152 = eval.m31_add(x_sum_tmp_fec87_14[3], x_sum_tmp_fec87_14[10]);
    let wg_v1153 = eval.m31_add(x_sum_tmp_fec87_14[4], x_sum_tmp_fec87_14[11]);
    let wg_v1154 = eval.m31_add(x_sum_tmp_fec87_14[5], x_sum_tmp_fec87_14[12]);
    let wg_v1155 = eval.m31_add(x_sum_tmp_fec87_14[6], x_sum_tmp_fec87_14[13]);
    let x_sum_tmp_fec87_18 = [
        wg_v1149, wg_v1150, wg_v1151, wg_v1152, wg_v1153, wg_v1154, wg_v1155,
    ];
    let wg_v1156 = eval.m31_add(y_sum_tmp_fec87_15[0], y_sum_tmp_fec87_15[7]);
    let wg_v1157 = eval.m31_add(y_sum_tmp_fec87_15[1], y_sum_tmp_fec87_15[8]);
    let wg_v1158 = eval.m31_add(y_sum_tmp_fec87_15[2], y_sum_tmp_fec87_15[9]);
    let wg_v1159 = eval.m31_add(y_sum_tmp_fec87_15[3], y_sum_tmp_fec87_15[10]);
    let wg_v1160 = eval.m31_add(y_sum_tmp_fec87_15[4], y_sum_tmp_fec87_15[11]);
    let wg_v1161 = eval.m31_add(y_sum_tmp_fec87_15[5], y_sum_tmp_fec87_15[12]);
    let wg_v1162 = eval.m31_add(y_sum_tmp_fec87_15[6], y_sum_tmp_fec87_15[13]);
    let y_sum_tmp_fec87_19 = [
        wg_v1156, wg_v1157, wg_v1158, wg_v1159, wg_v1160, wg_v1161, wg_v1162,
    ];
    let wg_v1163 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[0]);
    let wg_v1164 = eval.m31_sub(wg_v1163, z0_tmp_fec87_16[0]);
    let wg_v1165 = eval.m31_sub(wg_v1164, z2_tmp_fec87_17[0]);
    let wg_v1166 = eval.m31_add(z0_tmp_fec87_16[7], wg_v1165);
    let wg_v1167 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[1]);
    let wg_v1168 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[0]);
    let wg_v1169 = eval.m31_add(wg_v1167, wg_v1168);
    let wg_v1170 = eval.m31_sub(wg_v1169, z0_tmp_fec87_16[1]);
    let wg_v1171 = eval.m31_sub(wg_v1170, z2_tmp_fec87_17[1]);
    let wg_v1172 = eval.m31_add(z0_tmp_fec87_16[8], wg_v1171);
    let wg_v1173 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[2]);
    let wg_v1174 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[1]);
    let wg_v1175 = eval.m31_add(wg_v1173, wg_v1174);
    let wg_v1176 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[0]);
    let wg_v1177 = eval.m31_add(wg_v1175, wg_v1176);
    let wg_v1178 = eval.m31_sub(wg_v1177, z0_tmp_fec87_16[2]);
    let wg_v1179 = eval.m31_sub(wg_v1178, z2_tmp_fec87_17[2]);
    let wg_v1180 = eval.m31_add(z0_tmp_fec87_16[9], wg_v1179);
    let wg_v1181 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[3]);
    let wg_v1182 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[2]);
    let wg_v1183 = eval.m31_add(wg_v1181, wg_v1182);
    let wg_v1184 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[1]);
    let wg_v1185 = eval.m31_add(wg_v1183, wg_v1184);
    let wg_v1186 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[0]);
    let wg_v1187 = eval.m31_add(wg_v1185, wg_v1186);
    let wg_v1188 = eval.m31_sub(wg_v1187, z0_tmp_fec87_16[3]);
    let wg_v1189 = eval.m31_sub(wg_v1188, z2_tmp_fec87_17[3]);
    let wg_v1190 = eval.m31_add(z0_tmp_fec87_16[10], wg_v1189);
    let wg_v1191 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[4]);
    let wg_v1192 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[3]);
    let wg_v1193 = eval.m31_add(wg_v1191, wg_v1192);
    let wg_v1194 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[2]);
    let wg_v1195 = eval.m31_add(wg_v1193, wg_v1194);
    let wg_v1196 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[1]);
    let wg_v1197 = eval.m31_add(wg_v1195, wg_v1196);
    let wg_v1198 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[0]);
    let wg_v1199 = eval.m31_add(wg_v1197, wg_v1198);
    let wg_v1200 = eval.m31_sub(wg_v1199, z0_tmp_fec87_16[4]);
    let wg_v1201 = eval.m31_sub(wg_v1200, z2_tmp_fec87_17[4]);
    let wg_v1202 = eval.m31_add(z0_tmp_fec87_16[11], wg_v1201);
    let wg_v1203 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[5]);
    let wg_v1204 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[4]);
    let wg_v1205 = eval.m31_add(wg_v1203, wg_v1204);
    let wg_v1206 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[3]);
    let wg_v1207 = eval.m31_add(wg_v1205, wg_v1206);
    let wg_v1208 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[2]);
    let wg_v1209 = eval.m31_add(wg_v1207, wg_v1208);
    let wg_v1210 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[1]);
    let wg_v1211 = eval.m31_add(wg_v1209, wg_v1210);
    let wg_v1212 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[0]);
    let wg_v1213 = eval.m31_add(wg_v1211, wg_v1212);
    let wg_v1214 = eval.m31_sub(wg_v1213, z0_tmp_fec87_16[5]);
    let wg_v1215 = eval.m31_sub(wg_v1214, z2_tmp_fec87_17[5]);
    let wg_v1216 = eval.m31_add(z0_tmp_fec87_16[12], wg_v1215);
    let wg_v1217 = eval.m31_mul(x_sum_tmp_fec87_18[0], y_sum_tmp_fec87_19[6]);
    let wg_v1218 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[5]);
    let wg_v1219 = eval.m31_add(wg_v1217, wg_v1218);
    let wg_v1220 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[4]);
    let wg_v1221 = eval.m31_add(wg_v1219, wg_v1220);
    let wg_v1222 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[3]);
    let wg_v1223 = eval.m31_add(wg_v1221, wg_v1222);
    let wg_v1224 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[2]);
    let wg_v1225 = eval.m31_add(wg_v1223, wg_v1224);
    let wg_v1226 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[1]);
    let wg_v1227 = eval.m31_add(wg_v1225, wg_v1226);
    let wg_v1228 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[0]);
    let wg_v1229 = eval.m31_add(wg_v1227, wg_v1228);
    let wg_v1230 = eval.m31_sub(wg_v1229, z0_tmp_fec87_16[6]);
    let wg_v1231 = eval.m31_sub(wg_v1230, z2_tmp_fec87_17[6]);
    let wg_v1232 = eval.m31_mul(x_sum_tmp_fec87_18[1], y_sum_tmp_fec87_19[6]);
    let wg_v1233 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[5]);
    let wg_v1234 = eval.m31_add(wg_v1232, wg_v1233);
    let wg_v1235 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[4]);
    let wg_v1236 = eval.m31_add(wg_v1234, wg_v1235);
    let wg_v1237 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[3]);
    let wg_v1238 = eval.m31_add(wg_v1236, wg_v1237);
    let wg_v1239 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[2]);
    let wg_v1240 = eval.m31_add(wg_v1238, wg_v1239);
    let wg_v1241 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[1]);
    let wg_v1242 = eval.m31_add(wg_v1240, wg_v1241);
    let wg_v1243 = eval.m31_sub(wg_v1242, z0_tmp_fec87_16[7]);
    let wg_v1244 = eval.m31_sub(wg_v1243, z2_tmp_fec87_17[7]);
    let wg_v1245 = eval.m31_add(z2_tmp_fec87_17[0], wg_v1244);
    let wg_v1246 = eval.m31_mul(x_sum_tmp_fec87_18[2], y_sum_tmp_fec87_19[6]);
    let wg_v1247 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[5]);
    let wg_v1248 = eval.m31_add(wg_v1246, wg_v1247);
    let wg_v1249 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[4]);
    let wg_v1250 = eval.m31_add(wg_v1248, wg_v1249);
    let wg_v1251 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[3]);
    let wg_v1252 = eval.m31_add(wg_v1250, wg_v1251);
    let wg_v1253 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[2]);
    let wg_v1254 = eval.m31_add(wg_v1252, wg_v1253);
    let wg_v1255 = eval.m31_sub(wg_v1254, z0_tmp_fec87_16[8]);
    let wg_v1256 = eval.m31_sub(wg_v1255, z2_tmp_fec87_17[8]);
    let wg_v1257 = eval.m31_add(z2_tmp_fec87_17[1], wg_v1256);
    let wg_v1258 = eval.m31_mul(x_sum_tmp_fec87_18[3], y_sum_tmp_fec87_19[6]);
    let wg_v1259 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[5]);
    let wg_v1260 = eval.m31_add(wg_v1258, wg_v1259);
    let wg_v1261 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[4]);
    let wg_v1262 = eval.m31_add(wg_v1260, wg_v1261);
    let wg_v1263 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[3]);
    let wg_v1264 = eval.m31_add(wg_v1262, wg_v1263);
    let wg_v1265 = eval.m31_sub(wg_v1264, z0_tmp_fec87_16[9]);
    let wg_v1266 = eval.m31_sub(wg_v1265, z2_tmp_fec87_17[9]);
    let wg_v1267 = eval.m31_add(z2_tmp_fec87_17[2], wg_v1266);
    let wg_v1268 = eval.m31_mul(x_sum_tmp_fec87_18[4], y_sum_tmp_fec87_19[6]);
    let wg_v1269 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[5]);
    let wg_v1270 = eval.m31_add(wg_v1268, wg_v1269);
    let wg_v1271 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[4]);
    let wg_v1272 = eval.m31_add(wg_v1270, wg_v1271);
    let wg_v1273 = eval.m31_sub(wg_v1272, z0_tmp_fec87_16[10]);
    let wg_v1274 = eval.m31_sub(wg_v1273, z2_tmp_fec87_17[10]);
    let wg_v1275 = eval.m31_add(z2_tmp_fec87_17[3], wg_v1274);
    let wg_v1276 = eval.m31_mul(x_sum_tmp_fec87_18[5], y_sum_tmp_fec87_19[6]);
    let wg_v1277 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[5]);
    let wg_v1278 = eval.m31_add(wg_v1276, wg_v1277);
    let wg_v1279 = eval.m31_sub(wg_v1278, z0_tmp_fec87_16[11]);
    let wg_v1280 = eval.m31_sub(wg_v1279, z2_tmp_fec87_17[11]);
    let wg_v1281 = eval.m31_add(z2_tmp_fec87_17[4], wg_v1280);
    let wg_v1282 = eval.m31_mul(x_sum_tmp_fec87_18[6], y_sum_tmp_fec87_19[6]);
    let wg_v1283 = eval.m31_sub(wg_v1282, z0_tmp_fec87_16[12]);
    let wg_v1284 = eval.m31_sub(wg_v1283, z2_tmp_fec87_17[12]);
    let wg_v1285 = eval.m31_add(z2_tmp_fec87_17[5], wg_v1284);
    let single_karatsuba_n_7_output_tmp_fec87_20 = [
        z0_tmp_fec87_16[0],
        z0_tmp_fec87_16[1],
        z0_tmp_fec87_16[2],
        z0_tmp_fec87_16[3],
        z0_tmp_fec87_16[4],
        z0_tmp_fec87_16[5],
        z0_tmp_fec87_16[6],
        wg_v1166,
        wg_v1172,
        wg_v1180,
        wg_v1190,
        wg_v1202,
        wg_v1216,
        wg_v1231,
        wg_v1245,
        wg_v1257,
        wg_v1267,
        wg_v1275,
        wg_v1281,
        wg_v1285,
        z2_tmp_fec87_17[6],
        z2_tmp_fec87_17[7],
        z2_tmp_fec87_17[8],
        z2_tmp_fec87_17[9],
        z2_tmp_fec87_17[10],
        z2_tmp_fec87_17[11],
        z2_tmp_fec87_17[12],
    ];
    let wg_v1286 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[0],
        single_karatsuba_n_7_output_tmp_fec87_8[0],
    );
    let wg_v1287 = eval.m31_sub(wg_v1286, single_karatsuba_n_7_output_tmp_fec87_13[0]);
    let wg_v1288 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[14], wg_v1287);
    let wg_v1289 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[1],
        single_karatsuba_n_7_output_tmp_fec87_8[1],
    );
    let wg_v1290 = eval.m31_sub(wg_v1289, single_karatsuba_n_7_output_tmp_fec87_13[1]);
    let wg_v1291 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[15], wg_v1290);
    let wg_v1292 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[2],
        single_karatsuba_n_7_output_tmp_fec87_8[2],
    );
    let wg_v1293 = eval.m31_sub(wg_v1292, single_karatsuba_n_7_output_tmp_fec87_13[2]);
    let wg_v1294 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[16], wg_v1293);
    let wg_v1295 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[3],
        single_karatsuba_n_7_output_tmp_fec87_8[3],
    );
    let wg_v1296 = eval.m31_sub(wg_v1295, single_karatsuba_n_7_output_tmp_fec87_13[3]);
    let wg_v1297 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[17], wg_v1296);
    let wg_v1298 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[4],
        single_karatsuba_n_7_output_tmp_fec87_8[4],
    );
    let wg_v1299 = eval.m31_sub(wg_v1298, single_karatsuba_n_7_output_tmp_fec87_13[4]);
    let wg_v1300 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[18], wg_v1299);
    let wg_v1301 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[5],
        single_karatsuba_n_7_output_tmp_fec87_8[5],
    );
    let wg_v1302 = eval.m31_sub(wg_v1301, single_karatsuba_n_7_output_tmp_fec87_13[5]);
    let wg_v1303 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[19], wg_v1302);
    let wg_v1304 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[6],
        single_karatsuba_n_7_output_tmp_fec87_8[6],
    );
    let wg_v1305 = eval.m31_sub(wg_v1304, single_karatsuba_n_7_output_tmp_fec87_13[6]);
    let wg_v1306 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[20], wg_v1305);
    let wg_v1307 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[7],
        single_karatsuba_n_7_output_tmp_fec87_8[7],
    );
    let wg_v1308 = eval.m31_sub(wg_v1307, single_karatsuba_n_7_output_tmp_fec87_13[7]);
    let wg_v1309 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[21], wg_v1308);
    let wg_v1310 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[8],
        single_karatsuba_n_7_output_tmp_fec87_8[8],
    );
    let wg_v1311 = eval.m31_sub(wg_v1310, single_karatsuba_n_7_output_tmp_fec87_13[8]);
    let wg_v1312 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[22], wg_v1311);
    let wg_v1313 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[9],
        single_karatsuba_n_7_output_tmp_fec87_8[9],
    );
    let wg_v1314 = eval.m31_sub(wg_v1313, single_karatsuba_n_7_output_tmp_fec87_13[9]);
    let wg_v1315 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[23], wg_v1314);
    let wg_v1316 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[10],
        single_karatsuba_n_7_output_tmp_fec87_8[10],
    );
    let wg_v1317 = eval.m31_sub(wg_v1316, single_karatsuba_n_7_output_tmp_fec87_13[10]);
    let wg_v1318 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[24], wg_v1317);
    let wg_v1319 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[11],
        single_karatsuba_n_7_output_tmp_fec87_8[11],
    );
    let wg_v1320 = eval.m31_sub(wg_v1319, single_karatsuba_n_7_output_tmp_fec87_13[11]);
    let wg_v1321 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[25], wg_v1320);
    let wg_v1322 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[12],
        single_karatsuba_n_7_output_tmp_fec87_8[12],
    );
    let wg_v1323 = eval.m31_sub(wg_v1322, single_karatsuba_n_7_output_tmp_fec87_13[12]);
    let wg_v1324 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_8[26], wg_v1323);
    let wg_v1325 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[13],
        single_karatsuba_n_7_output_tmp_fec87_8[13],
    );
    let wg_v1326 = eval.m31_sub(wg_v1325, single_karatsuba_n_7_output_tmp_fec87_13[13]);
    let wg_v1327 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[14],
        single_karatsuba_n_7_output_tmp_fec87_8[14],
    );
    let wg_v1328 = eval.m31_sub(wg_v1327, single_karatsuba_n_7_output_tmp_fec87_13[14]);
    let wg_v1329 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[0], wg_v1328);
    let wg_v1330 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[15],
        single_karatsuba_n_7_output_tmp_fec87_8[15],
    );
    let wg_v1331 = eval.m31_sub(wg_v1330, single_karatsuba_n_7_output_tmp_fec87_13[15]);
    let wg_v1332 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[1], wg_v1331);
    let wg_v1333 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[16],
        single_karatsuba_n_7_output_tmp_fec87_8[16],
    );
    let wg_v1334 = eval.m31_sub(wg_v1333, single_karatsuba_n_7_output_tmp_fec87_13[16]);
    let wg_v1335 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[2], wg_v1334);
    let wg_v1336 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[17],
        single_karatsuba_n_7_output_tmp_fec87_8[17],
    );
    let wg_v1337 = eval.m31_sub(wg_v1336, single_karatsuba_n_7_output_tmp_fec87_13[17]);
    let wg_v1338 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[3], wg_v1337);
    let wg_v1339 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[18],
        single_karatsuba_n_7_output_tmp_fec87_8[18],
    );
    let wg_v1340 = eval.m31_sub(wg_v1339, single_karatsuba_n_7_output_tmp_fec87_13[18]);
    let wg_v1341 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[4], wg_v1340);
    let wg_v1342 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[19],
        single_karatsuba_n_7_output_tmp_fec87_8[19],
    );
    let wg_v1343 = eval.m31_sub(wg_v1342, single_karatsuba_n_7_output_tmp_fec87_13[19]);
    let wg_v1344 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[5], wg_v1343);
    let wg_v1345 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[20],
        single_karatsuba_n_7_output_tmp_fec87_8[20],
    );
    let wg_v1346 = eval.m31_sub(wg_v1345, single_karatsuba_n_7_output_tmp_fec87_13[20]);
    let wg_v1347 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[6], wg_v1346);
    let wg_v1348 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[21],
        single_karatsuba_n_7_output_tmp_fec87_8[21],
    );
    let wg_v1349 = eval.m31_sub(wg_v1348, single_karatsuba_n_7_output_tmp_fec87_13[21]);
    let wg_v1350 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[7], wg_v1349);
    let wg_v1351 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[22],
        single_karatsuba_n_7_output_tmp_fec87_8[22],
    );
    let wg_v1352 = eval.m31_sub(wg_v1351, single_karatsuba_n_7_output_tmp_fec87_13[22]);
    let wg_v1353 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[8], wg_v1352);
    let wg_v1354 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[23],
        single_karatsuba_n_7_output_tmp_fec87_8[23],
    );
    let wg_v1355 = eval.m31_sub(wg_v1354, single_karatsuba_n_7_output_tmp_fec87_13[23]);
    let wg_v1356 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[9], wg_v1355);
    let wg_v1357 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[24],
        single_karatsuba_n_7_output_tmp_fec87_8[24],
    );
    let wg_v1358 = eval.m31_sub(wg_v1357, single_karatsuba_n_7_output_tmp_fec87_13[24]);
    let wg_v1359 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[10], wg_v1358);
    let wg_v1360 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[25],
        single_karatsuba_n_7_output_tmp_fec87_8[25],
    );
    let wg_v1361 = eval.m31_sub(wg_v1360, single_karatsuba_n_7_output_tmp_fec87_13[25]);
    let wg_v1362 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[11], wg_v1361);
    let wg_v1363 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_20[26],
        single_karatsuba_n_7_output_tmp_fec87_8[26],
    );
    let wg_v1364 = eval.m31_sub(wg_v1363, single_karatsuba_n_7_output_tmp_fec87_13[26]);
    let wg_v1365 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_13[12], wg_v1364);
    let double_karatsuba_1454b_output_tmp_fec87_21 = [
        single_karatsuba_n_7_output_tmp_fec87_8[0],
        single_karatsuba_n_7_output_tmp_fec87_8[1],
        single_karatsuba_n_7_output_tmp_fec87_8[2],
        single_karatsuba_n_7_output_tmp_fec87_8[3],
        single_karatsuba_n_7_output_tmp_fec87_8[4],
        single_karatsuba_n_7_output_tmp_fec87_8[5],
        single_karatsuba_n_7_output_tmp_fec87_8[6],
        single_karatsuba_n_7_output_tmp_fec87_8[7],
        single_karatsuba_n_7_output_tmp_fec87_8[8],
        single_karatsuba_n_7_output_tmp_fec87_8[9],
        single_karatsuba_n_7_output_tmp_fec87_8[10],
        single_karatsuba_n_7_output_tmp_fec87_8[11],
        single_karatsuba_n_7_output_tmp_fec87_8[12],
        single_karatsuba_n_7_output_tmp_fec87_8[13],
        wg_v1288,
        wg_v1291,
        wg_v1294,
        wg_v1297,
        wg_v1300,
        wg_v1303,
        wg_v1306,
        wg_v1309,
        wg_v1312,
        wg_v1315,
        wg_v1318,
        wg_v1321,
        wg_v1324,
        wg_v1326,
        wg_v1329,
        wg_v1332,
        wg_v1335,
        wg_v1338,
        wg_v1341,
        wg_v1344,
        wg_v1347,
        wg_v1350,
        wg_v1353,
        wg_v1356,
        wg_v1359,
        wg_v1362,
        wg_v1365,
        single_karatsuba_n_7_output_tmp_fec87_13[13],
        single_karatsuba_n_7_output_tmp_fec87_13[14],
        single_karatsuba_n_7_output_tmp_fec87_13[15],
        single_karatsuba_n_7_output_tmp_fec87_13[16],
        single_karatsuba_n_7_output_tmp_fec87_13[17],
        single_karatsuba_n_7_output_tmp_fec87_13[18],
        single_karatsuba_n_7_output_tmp_fec87_13[19],
        single_karatsuba_n_7_output_tmp_fec87_13[20],
        single_karatsuba_n_7_output_tmp_fec87_13[21],
        single_karatsuba_n_7_output_tmp_fec87_13[22],
        single_karatsuba_n_7_output_tmp_fec87_13[23],
        single_karatsuba_n_7_output_tmp_fec87_13[24],
        single_karatsuba_n_7_output_tmp_fec87_13[25],
        single_karatsuba_n_7_output_tmp_fec87_13[26],
    ];
    let wg_v1366 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[0],
        mul_res_limb_0_col28,
    );
    let wg_v1367 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[1],
        mul_res_limb_1_col29,
    );
    let wg_v1368 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[2],
        mul_res_limb_2_col30,
    );
    let wg_v1369 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[3],
        mul_res_limb_3_col31,
    );
    let wg_v1370 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[4],
        mul_res_limb_4_col32,
    );
    let wg_v1371 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[5],
        mul_res_limb_5_col33,
    );
    let wg_v1372 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[6],
        mul_res_limb_6_col34,
    );
    let wg_v1373 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[7],
        mul_res_limb_7_col35,
    );
    let wg_v1374 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[8],
        mul_res_limb_8_col36,
    );
    let wg_v1375 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[9],
        mul_res_limb_9_col37,
    );
    let wg_v1376 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[10],
        mul_res_limb_10_col38,
    );
    let wg_v1377 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[11],
        mul_res_limb_11_col39,
    );
    let wg_v1378 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[12],
        mul_res_limb_12_col40,
    );
    let wg_v1379 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[13],
        mul_res_limb_13_col41,
    );
    let wg_v1380 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[14],
        mul_res_limb_14_col42,
    );
    let wg_v1381 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[15],
        mul_res_limb_15_col43,
    );
    let wg_v1382 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[16],
        mul_res_limb_16_col44,
    );
    let wg_v1383 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[17],
        mul_res_limb_17_col45,
    );
    let wg_v1384 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[18],
        mul_res_limb_18_col46,
    );
    let wg_v1385 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[19],
        mul_res_limb_19_col47,
    );
    let wg_v1386 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[20],
        mul_res_limb_20_col48,
    );
    let wg_v1387 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[21],
        mul_res_limb_21_col49,
    );
    let wg_v1388 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[22],
        mul_res_limb_22_col50,
    );
    let wg_v1389 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[23],
        mul_res_limb_23_col51,
    );
    let wg_v1390 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[24],
        mul_res_limb_24_col52,
    );
    let wg_v1391 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[25],
        mul_res_limb_25_col53,
    );
    let wg_v1392 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[26],
        mul_res_limb_26_col54,
    );
    let wg_v1393 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_21[27],
        mul_res_limb_27_col55,
    );
    let conv_tmp_fec87_22 = [
        wg_v1366,
        wg_v1367,
        wg_v1368,
        wg_v1369,
        wg_v1370,
        wg_v1371,
        wg_v1372,
        wg_v1373,
        wg_v1374,
        wg_v1375,
        wg_v1376,
        wg_v1377,
        wg_v1378,
        wg_v1379,
        wg_v1380,
        wg_v1381,
        wg_v1382,
        wg_v1383,
        wg_v1384,
        wg_v1385,
        wg_v1386,
        wg_v1387,
        wg_v1388,
        wg_v1389,
        wg_v1390,
        wg_v1391,
        wg_v1392,
        wg_v1393,
        double_karatsuba_1454b_output_tmp_fec87_21[28],
        double_karatsuba_1454b_output_tmp_fec87_21[29],
        double_karatsuba_1454b_output_tmp_fec87_21[30],
        double_karatsuba_1454b_output_tmp_fec87_21[31],
        double_karatsuba_1454b_output_tmp_fec87_21[32],
        double_karatsuba_1454b_output_tmp_fec87_21[33],
        double_karatsuba_1454b_output_tmp_fec87_21[34],
        double_karatsuba_1454b_output_tmp_fec87_21[35],
        double_karatsuba_1454b_output_tmp_fec87_21[36],
        double_karatsuba_1454b_output_tmp_fec87_21[37],
        double_karatsuba_1454b_output_tmp_fec87_21[38],
        double_karatsuba_1454b_output_tmp_fec87_21[39],
        double_karatsuba_1454b_output_tmp_fec87_21[40],
        double_karatsuba_1454b_output_tmp_fec87_21[41],
        double_karatsuba_1454b_output_tmp_fec87_21[42],
        double_karatsuba_1454b_output_tmp_fec87_21[43],
        double_karatsuba_1454b_output_tmp_fec87_21[44],
        double_karatsuba_1454b_output_tmp_fec87_21[45],
        double_karatsuba_1454b_output_tmp_fec87_21[46],
        double_karatsuba_1454b_output_tmp_fec87_21[47],
        double_karatsuba_1454b_output_tmp_fec87_21[48],
        double_karatsuba_1454b_output_tmp_fec87_21[49],
        double_karatsuba_1454b_output_tmp_fec87_21[50],
        double_karatsuba_1454b_output_tmp_fec87_21[51],
        double_karatsuba_1454b_output_tmp_fec87_21[52],
        double_karatsuba_1454b_output_tmp_fec87_21[53],
        double_karatsuba_1454b_output_tmp_fec87_21[54],
    ];
    let wg_v1394 = eval.m31_mul(m31_32, conv_tmp_fec87_22[0]);
    let wg_v1395 = eval.m31_mul(m31_4, conv_tmp_fec87_22[21]);
    let wg_v1396 = eval.m31_sub(wg_v1394, wg_v1395);
    let wg_v1397 = eval.m31_mul(m31_8, conv_tmp_fec87_22[49]);
    let wg_v1398 = eval.m31_add(wg_v1396, wg_v1397);
    let wg_v1399 = eval.m31_mul(m31_32, conv_tmp_fec87_22[1]);
    let wg_v1400 = eval.m31_add(conv_tmp_fec87_22[0], wg_v1399);
    let wg_v1401 = eval.m31_mul(m31_4, conv_tmp_fec87_22[22]);
    let wg_v1402 = eval.m31_sub(wg_v1400, wg_v1401);
    let wg_v1403 = eval.m31_mul(m31_8, conv_tmp_fec87_22[50]);
    let wg_v1404 = eval.m31_add(wg_v1402, wg_v1403);
    let wg_v1405 = eval.m31_mul(m31_32, conv_tmp_fec87_22[2]);
    let wg_v1406 = eval.m31_add(conv_tmp_fec87_22[1], wg_v1405);
    let wg_v1407 = eval.m31_mul(m31_4, conv_tmp_fec87_22[23]);
    let wg_v1408 = eval.m31_sub(wg_v1406, wg_v1407);
    let wg_v1409 = eval.m31_mul(m31_8, conv_tmp_fec87_22[51]);
    let wg_v1410 = eval.m31_add(wg_v1408, wg_v1409);
    let wg_v1411 = eval.m31_mul(m31_32, conv_tmp_fec87_22[3]);
    let wg_v1412 = eval.m31_add(conv_tmp_fec87_22[2], wg_v1411);
    let wg_v1413 = eval.m31_mul(m31_4, conv_tmp_fec87_22[24]);
    let wg_v1414 = eval.m31_sub(wg_v1412, wg_v1413);
    let wg_v1415 = eval.m31_mul(m31_8, conv_tmp_fec87_22[52]);
    let wg_v1416 = eval.m31_add(wg_v1414, wg_v1415);
    let wg_v1417 = eval.m31_mul(m31_32, conv_tmp_fec87_22[4]);
    let wg_v1418 = eval.m31_add(conv_tmp_fec87_22[3], wg_v1417);
    let wg_v1419 = eval.m31_mul(m31_4, conv_tmp_fec87_22[25]);
    let wg_v1420 = eval.m31_sub(wg_v1418, wg_v1419);
    let wg_v1421 = eval.m31_mul(m31_8, conv_tmp_fec87_22[53]);
    let wg_v1422 = eval.m31_add(wg_v1420, wg_v1421);
    let wg_v1423 = eval.m31_mul(m31_32, conv_tmp_fec87_22[5]);
    let wg_v1424 = eval.m31_add(conv_tmp_fec87_22[4], wg_v1423);
    let wg_v1425 = eval.m31_mul(m31_4, conv_tmp_fec87_22[26]);
    let wg_v1426 = eval.m31_sub(wg_v1424, wg_v1425);
    let wg_v1427 = eval.m31_mul(m31_8, conv_tmp_fec87_22[54]);
    let wg_v1428 = eval.m31_add(wg_v1426, wg_v1427);
    let wg_v1429 = eval.m31_mul(m31_32, conv_tmp_fec87_22[6]);
    let wg_v1430 = eval.m31_add(conv_tmp_fec87_22[5], wg_v1429);
    let wg_v1431 = eval.m31_mul(m31_4, conv_tmp_fec87_22[27]);
    let wg_v1432 = eval.m31_sub(wg_v1430, wg_v1431);
    let wg_v1433 = eval.m31_mul(m31_2, conv_tmp_fec87_22[0]);
    let wg_v1434 = eval.m31_add(wg_v1433, conv_tmp_fec87_22[6]);
    let wg_v1435 = eval.m31_mul(m31_32, conv_tmp_fec87_22[7]);
    let wg_v1436 = eval.m31_add(wg_v1434, wg_v1435);
    let wg_v1437 = eval.m31_mul(m31_4, conv_tmp_fec87_22[28]);
    let wg_v1438 = eval.m31_sub(wg_v1436, wg_v1437);
    let wg_v1439 = eval.m31_mul(m31_2, conv_tmp_fec87_22[1]);
    let wg_v1440 = eval.m31_add(wg_v1439, conv_tmp_fec87_22[7]);
    let wg_v1441 = eval.m31_mul(m31_32, conv_tmp_fec87_22[8]);
    let wg_v1442 = eval.m31_add(wg_v1440, wg_v1441);
    let wg_v1443 = eval.m31_mul(m31_4, conv_tmp_fec87_22[29]);
    let wg_v1444 = eval.m31_sub(wg_v1442, wg_v1443);
    let wg_v1445 = eval.m31_mul(m31_2, conv_tmp_fec87_22[2]);
    let wg_v1446 = eval.m31_add(wg_v1445, conv_tmp_fec87_22[8]);
    let wg_v1447 = eval.m31_mul(m31_32, conv_tmp_fec87_22[9]);
    let wg_v1448 = eval.m31_add(wg_v1446, wg_v1447);
    let wg_v1449 = eval.m31_mul(m31_4, conv_tmp_fec87_22[30]);
    let wg_v1450 = eval.m31_sub(wg_v1448, wg_v1449);
    let wg_v1451 = eval.m31_mul(m31_2, conv_tmp_fec87_22[3]);
    let wg_v1452 = eval.m31_add(wg_v1451, conv_tmp_fec87_22[9]);
    let wg_v1453 = eval.m31_mul(m31_32, conv_tmp_fec87_22[10]);
    let wg_v1454 = eval.m31_add(wg_v1452, wg_v1453);
    let wg_v1455 = eval.m31_mul(m31_4, conv_tmp_fec87_22[31]);
    let wg_v1456 = eval.m31_sub(wg_v1454, wg_v1455);
    let wg_v1457 = eval.m31_mul(m31_2, conv_tmp_fec87_22[4]);
    let wg_v1458 = eval.m31_add(wg_v1457, conv_tmp_fec87_22[10]);
    let wg_v1459 = eval.m31_mul(m31_32, conv_tmp_fec87_22[11]);
    let wg_v1460 = eval.m31_add(wg_v1458, wg_v1459);
    let wg_v1461 = eval.m31_mul(m31_4, conv_tmp_fec87_22[32]);
    let wg_v1462 = eval.m31_sub(wg_v1460, wg_v1461);
    let wg_v1463 = eval.m31_mul(m31_2, conv_tmp_fec87_22[5]);
    let wg_v1464 = eval.m31_add(wg_v1463, conv_tmp_fec87_22[11]);
    let wg_v1465 = eval.m31_mul(m31_32, conv_tmp_fec87_22[12]);
    let wg_v1466 = eval.m31_add(wg_v1464, wg_v1465);
    let wg_v1467 = eval.m31_mul(m31_4, conv_tmp_fec87_22[33]);
    let wg_v1468 = eval.m31_sub(wg_v1466, wg_v1467);
    let wg_v1469 = eval.m31_mul(m31_2, conv_tmp_fec87_22[6]);
    let wg_v1470 = eval.m31_add(wg_v1469, conv_tmp_fec87_22[12]);
    let wg_v1471 = eval.m31_mul(m31_32, conv_tmp_fec87_22[13]);
    let wg_v1472 = eval.m31_add(wg_v1470, wg_v1471);
    let wg_v1473 = eval.m31_mul(m31_4, conv_tmp_fec87_22[34]);
    let wg_v1474 = eval.m31_sub(wg_v1472, wg_v1473);
    let wg_v1475 = eval.m31_mul(m31_2, conv_tmp_fec87_22[7]);
    let wg_v1476 = eval.m31_add(wg_v1475, conv_tmp_fec87_22[13]);
    let wg_v1477 = eval.m31_mul(m31_32, conv_tmp_fec87_22[14]);
    let wg_v1478 = eval.m31_add(wg_v1476, wg_v1477);
    let wg_v1479 = eval.m31_mul(m31_4, conv_tmp_fec87_22[35]);
    let wg_v1480 = eval.m31_sub(wg_v1478, wg_v1479);
    let wg_v1481 = eval.m31_mul(m31_2, conv_tmp_fec87_22[8]);
    let wg_v1482 = eval.m31_add(wg_v1481, conv_tmp_fec87_22[14]);
    let wg_v1483 = eval.m31_mul(m31_32, conv_tmp_fec87_22[15]);
    let wg_v1484 = eval.m31_add(wg_v1482, wg_v1483);
    let wg_v1485 = eval.m31_mul(m31_4, conv_tmp_fec87_22[36]);
    let wg_v1486 = eval.m31_sub(wg_v1484, wg_v1485);
    let wg_v1487 = eval.m31_mul(m31_2, conv_tmp_fec87_22[9]);
    let wg_v1488 = eval.m31_add(wg_v1487, conv_tmp_fec87_22[15]);
    let wg_v1489 = eval.m31_mul(m31_32, conv_tmp_fec87_22[16]);
    let wg_v1490 = eval.m31_add(wg_v1488, wg_v1489);
    let wg_v1491 = eval.m31_mul(m31_4, conv_tmp_fec87_22[37]);
    let wg_v1492 = eval.m31_sub(wg_v1490, wg_v1491);
    let wg_v1493 = eval.m31_mul(m31_2, conv_tmp_fec87_22[10]);
    let wg_v1494 = eval.m31_add(wg_v1493, conv_tmp_fec87_22[16]);
    let wg_v1495 = eval.m31_mul(m31_32, conv_tmp_fec87_22[17]);
    let wg_v1496 = eval.m31_add(wg_v1494, wg_v1495);
    let wg_v1497 = eval.m31_mul(m31_4, conv_tmp_fec87_22[38]);
    let wg_v1498 = eval.m31_sub(wg_v1496, wg_v1497);
    let wg_v1499 = eval.m31_mul(m31_2, conv_tmp_fec87_22[11]);
    let wg_v1500 = eval.m31_add(wg_v1499, conv_tmp_fec87_22[17]);
    let wg_v1501 = eval.m31_mul(m31_32, conv_tmp_fec87_22[18]);
    let wg_v1502 = eval.m31_add(wg_v1500, wg_v1501);
    let wg_v1503 = eval.m31_mul(m31_4, conv_tmp_fec87_22[39]);
    let wg_v1504 = eval.m31_sub(wg_v1502, wg_v1503);
    let wg_v1505 = eval.m31_mul(m31_2, conv_tmp_fec87_22[12]);
    let wg_v1506 = eval.m31_add(wg_v1505, conv_tmp_fec87_22[18]);
    let wg_v1507 = eval.m31_mul(m31_32, conv_tmp_fec87_22[19]);
    let wg_v1508 = eval.m31_add(wg_v1506, wg_v1507);
    let wg_v1509 = eval.m31_mul(m31_4, conv_tmp_fec87_22[40]);
    let wg_v1510 = eval.m31_sub(wg_v1508, wg_v1509);
    let wg_v1511 = eval.m31_mul(m31_2, conv_tmp_fec87_22[13]);
    let wg_v1512 = eval.m31_add(wg_v1511, conv_tmp_fec87_22[19]);
    let wg_v1513 = eval.m31_mul(m31_32, conv_tmp_fec87_22[20]);
    let wg_v1514 = eval.m31_add(wg_v1512, wg_v1513);
    let wg_v1515 = eval.m31_mul(m31_4, conv_tmp_fec87_22[41]);
    let wg_v1516 = eval.m31_sub(wg_v1514, wg_v1515);
    let wg_v1517 = eval.m31_mul(m31_2, conv_tmp_fec87_22[14]);
    let wg_v1518 = eval.m31_add(wg_v1517, conv_tmp_fec87_22[20]);
    let wg_v1519 = eval.m31_mul(m31_4, conv_tmp_fec87_22[42]);
    let wg_v1520 = eval.m31_sub(wg_v1518, wg_v1519);
    let wg_v1521 = eval.m31_mul(m31_64, conv_tmp_fec87_22[49]);
    let wg_v1522 = eval.m31_add(wg_v1520, wg_v1521);
    let wg_v1523 = eval.m31_mul(m31_2, conv_tmp_fec87_22[15]);
    let wg_v1524 = eval.m31_mul(m31_4, conv_tmp_fec87_22[43]);
    let wg_v1525 = eval.m31_sub(wg_v1523, wg_v1524);
    let wg_v1526 = eval.m31_mul(m31_2, conv_tmp_fec87_22[49]);
    let wg_v1527 = eval.m31_add(wg_v1525, wg_v1526);
    let wg_v1528 = eval.m31_mul(m31_64, conv_tmp_fec87_22[50]);
    let wg_v1529 = eval.m31_add(wg_v1527, wg_v1528);
    let wg_v1530 = eval.m31_mul(m31_2, conv_tmp_fec87_22[16]);
    let wg_v1531 = eval.m31_mul(m31_4, conv_tmp_fec87_22[44]);
    let wg_v1532 = eval.m31_sub(wg_v1530, wg_v1531);
    let wg_v1533 = eval.m31_mul(m31_2, conv_tmp_fec87_22[50]);
    let wg_v1534 = eval.m31_add(wg_v1532, wg_v1533);
    let wg_v1535 = eval.m31_mul(m31_64, conv_tmp_fec87_22[51]);
    let wg_v1536 = eval.m31_add(wg_v1534, wg_v1535);
    let wg_v1537 = eval.m31_mul(m31_2, conv_tmp_fec87_22[17]);
    let wg_v1538 = eval.m31_mul(m31_4, conv_tmp_fec87_22[45]);
    let wg_v1539 = eval.m31_sub(wg_v1537, wg_v1538);
    let wg_v1540 = eval.m31_mul(m31_2, conv_tmp_fec87_22[51]);
    let wg_v1541 = eval.m31_add(wg_v1539, wg_v1540);
    let wg_v1542 = eval.m31_mul(m31_64, conv_tmp_fec87_22[52]);
    let wg_v1543 = eval.m31_add(wg_v1541, wg_v1542);
    let wg_v1544 = eval.m31_mul(m31_2, conv_tmp_fec87_22[18]);
    let wg_v1545 = eval.m31_mul(m31_4, conv_tmp_fec87_22[46]);
    let wg_v1546 = eval.m31_sub(wg_v1544, wg_v1545);
    let wg_v1547 = eval.m31_mul(m31_2, conv_tmp_fec87_22[52]);
    let wg_v1548 = eval.m31_add(wg_v1546, wg_v1547);
    let wg_v1549 = eval.m31_mul(m31_64, conv_tmp_fec87_22[53]);
    let wg_v1550 = eval.m31_add(wg_v1548, wg_v1549);
    let wg_v1551 = eval.m31_mul(m31_2, conv_tmp_fec87_22[19]);
    let wg_v1552 = eval.m31_mul(m31_4, conv_tmp_fec87_22[47]);
    let wg_v1553 = eval.m31_sub(wg_v1551, wg_v1552);
    let wg_v1554 = eval.m31_mul(m31_2, conv_tmp_fec87_22[53]);
    let wg_v1555 = eval.m31_add(wg_v1553, wg_v1554);
    let wg_v1556 = eval.m31_mul(m31_64, conv_tmp_fec87_22[54]);
    let wg_v1557 = eval.m31_add(wg_v1555, wg_v1556);
    let wg_v1558 = eval.m31_mul(m31_2, conv_tmp_fec87_22[20]);
    let wg_v1559 = eval.m31_mul(m31_4, conv_tmp_fec87_22[48]);
    let wg_v1560 = eval.m31_sub(wg_v1558, wg_v1559);
    let wg_v1561 = eval.m31_mul(m31_2, conv_tmp_fec87_22[54]);
    let wg_v1562 = eval.m31_add(wg_v1560, wg_v1561);
    let conv_mod_tmp_fec87_23 = [
        wg_v1398, wg_v1404, wg_v1410, wg_v1416, wg_v1422, wg_v1428, wg_v1432, wg_v1438, wg_v1444,
        wg_v1450, wg_v1456, wg_v1462, wg_v1468, wg_v1474, wg_v1480, wg_v1486, wg_v1492, wg_v1498,
        wg_v1504, wg_v1510, wg_v1516, wg_v1522, wg_v1529, wg_v1536, wg_v1543, wg_v1550, wg_v1557,
        wg_v1562,
    ];
    let wg_v1563 = eval.m31_add(conv_mod_tmp_fec87_23[0], m31_134217728);
    let wg_v1564 = eval.u32_from_m31(wg_v1563);
    let wg_v1565 = eval.m31_add(conv_mod_tmp_fec87_23[1], m31_134217728);
    let wg_v1566 = eval.u32_from_m31(wg_v1565);
    let wg_v1567 = eval.u32_and_imm(wg_v1566, 511);
    let wg_v1568 = eval.u32_shl_imm(wg_v1567, 9);
    let wg_v1569 = eval.u32_add(wg_v1564, wg_v1568);
    let wg_v1570 = eval.u32_const(131072);
    let wg_v1571 = eval.u32_add(wg_v1569, wg_v1570);
    let k_mod_2_18_biased_tmp_fec87_24 = eval.u32_and_imm(wg_v1571, 262143);
    let wg_v1572 = eval.u32_low(k_mod_2_18_biased_tmp_fec87_24);
    let wg_v1573 = eval.u16_as_m31(wg_v1572);
    let wg_v1574 = eval.u32_high(k_mod_2_18_biased_tmp_fec87_24);
    let wg_v1575 = eval.u16_as_m31(wg_v1574);
    let wg_v1576 = eval.m31_sub(wg_v1575, m31_2);
    let wg_v1577 = eval.m31_mul(wg_v1576, m31_65536);
    let k_col56 = eval.m31_add(wg_v1573, wg_v1577);
    eval.set_col(56, k_col56);
    let wg_v1578 = eval.m31_add(k_col56, m31_524288);
    eval.set_sub_input_word(84, wg_v1578);
    eval.set_lookup_word(21, m31_1410849886);
    let wg_v1579 = eval.m31_add(k_col56, m31_524288);
    eval.set_lookup_word(22, wg_v1579);
    let wg_v1580 = eval.m31_sub(conv_mod_tmp_fec87_23[0], k_col56);
    let carry_0_col57 = eval.m31_mul(wg_v1580, m31_4194304);
    eval.set_col(57, carry_0_col57);
    let wg_v1581 = eval.m31_add(carry_0_col57, m31_524288);
    eval.set_sub_input_word(92, wg_v1581);
    eval.set_lookup_word(37, m31_514232941);
    let wg_v1582 = eval.m31_add(carry_0_col57, m31_524288);
    eval.set_lookup_word(38, wg_v1582);
    let wg_v1583 = eval.m31_add(conv_mod_tmp_fec87_23[1], carry_0_col57);
    let carry_1_col58 = eval.m31_mul(wg_v1583, m31_4194304);
    eval.set_col(58, carry_1_col58);
    let wg_v1584 = eval.m31_add(carry_1_col58, m31_524288);
    eval.set_sub_input_word(100, wg_v1584);
    eval.set_lookup_word(53, m31_531010560);
    let wg_v1585 = eval.m31_add(carry_1_col58, m31_524288);
    eval.set_lookup_word(54, wg_v1585);
    let wg_v1586 = eval.m31_add(conv_mod_tmp_fec87_23[2], carry_1_col58);
    let carry_2_col59 = eval.m31_mul(wg_v1586, m31_4194304);
    eval.set_col(59, carry_2_col59);
    let wg_v1587 = eval.m31_add(carry_2_col59, m31_524288);
    eval.set_sub_input_word(108, wg_v1587);
    eval.set_lookup_word(69, m31_480677703);
    let wg_v1588 = eval.m31_add(carry_2_col59, m31_524288);
    eval.set_lookup_word(70, wg_v1588);
    let wg_v1589 = eval.m31_add(conv_mod_tmp_fec87_23[3], carry_2_col59);
    let carry_3_col60 = eval.m31_mul(wg_v1589, m31_4194304);
    eval.set_col(60, carry_3_col60);
    let wg_v1590 = eval.m31_add(carry_3_col60, m31_524288);
    eval.set_sub_input_word(116, wg_v1590);
    eval.set_lookup_word(85, m31_497455322);
    let wg_v1591 = eval.m31_add(carry_3_col60, m31_524288);
    eval.set_lookup_word(86, wg_v1591);
    let wg_v1592 = eval.m31_add(conv_mod_tmp_fec87_23[4], carry_3_col60);
    let carry_4_col61 = eval.m31_mul(wg_v1592, m31_4194304);
    eval.set_col(61, carry_4_col61);
    let wg_v1593 = eval.m31_add(carry_4_col61, m31_524288);
    eval.set_sub_input_word(122, wg_v1593);
    eval.set_lookup_word(97, m31_447122465);
    let wg_v1594 = eval.m31_add(carry_4_col61, m31_524288);
    eval.set_lookup_word(98, wg_v1594);
    let wg_v1595 = eval.m31_add(conv_mod_tmp_fec87_23[5], carry_4_col61);
    let carry_5_col62 = eval.m31_mul(wg_v1595, m31_4194304);
    eval.set_col(62, carry_5_col62);
    let wg_v1596 = eval.m31_add(carry_5_col62, m31_524288);
    eval.set_sub_input_word(128, wg_v1596);
    eval.set_lookup_word(109, m31_463900084);
    let wg_v1597 = eval.m31_add(carry_5_col62, m31_524288);
    eval.set_lookup_word(110, wg_v1597);
    let wg_v1598 = eval.m31_add(conv_mod_tmp_fec87_23[6], carry_5_col62);
    let carry_6_col63 = eval.m31_mul(wg_v1598, m31_4194304);
    eval.set_col(63, carry_6_col63);
    let wg_v1599 = eval.m31_add(carry_6_col63, m31_524288);
    eval.set_sub_input_word(134, wg_v1599);
    eval.set_lookup_word(121, m31_682009131);
    let wg_v1600 = eval.m31_add(carry_6_col63, m31_524288);
    eval.set_lookup_word(122, wg_v1600);
    let wg_v1601 = eval.m31_add(conv_mod_tmp_fec87_23[7], carry_6_col63);
    let carry_7_col64 = eval.m31_mul(wg_v1601, m31_4194304);
    eval.set_col(64, carry_7_col64);
    let wg_v1602 = eval.m31_add(carry_7_col64, m31_524288);
    eval.set_sub_input_word(85, wg_v1602);
    eval.set_lookup_word(23, m31_1410849886);
    let wg_v1603 = eval.m31_add(carry_7_col64, m31_524288);
    eval.set_lookup_word(24, wg_v1603);
    let wg_v1604 = eval.m31_add(conv_mod_tmp_fec87_23[8], carry_7_col64);
    let carry_8_col65 = eval.m31_mul(wg_v1604, m31_4194304);
    eval.set_col(65, carry_8_col65);
    let wg_v1605 = eval.m31_add(carry_8_col65, m31_524288);
    eval.set_sub_input_word(93, wg_v1605);
    eval.set_lookup_word(39, m31_514232941);
    let wg_v1606 = eval.m31_add(carry_8_col65, m31_524288);
    eval.set_lookup_word(40, wg_v1606);
    let wg_v1607 = eval.m31_add(conv_mod_tmp_fec87_23[9], carry_8_col65);
    let carry_9_col66 = eval.m31_mul(wg_v1607, m31_4194304);
    eval.set_col(66, carry_9_col66);
    let wg_v1608 = eval.m31_add(carry_9_col66, m31_524288);
    eval.set_sub_input_word(101, wg_v1608);
    eval.set_lookup_word(55, m31_531010560);
    let wg_v1609 = eval.m31_add(carry_9_col66, m31_524288);
    eval.set_lookup_word(56, wg_v1609);
    let wg_v1610 = eval.m31_add(conv_mod_tmp_fec87_23[10], carry_9_col66);
    let carry_10_col67 = eval.m31_mul(wg_v1610, m31_4194304);
    eval.set_col(67, carry_10_col67);
    let wg_v1611 = eval.m31_add(carry_10_col67, m31_524288);
    eval.set_sub_input_word(109, wg_v1611);
    eval.set_lookup_word(71, m31_480677703);
    let wg_v1612 = eval.m31_add(carry_10_col67, m31_524288);
    eval.set_lookup_word(72, wg_v1612);
    let wg_v1613 = eval.m31_add(conv_mod_tmp_fec87_23[11], carry_10_col67);
    let carry_11_col68 = eval.m31_mul(wg_v1613, m31_4194304);
    eval.set_col(68, carry_11_col68);
    let wg_v1614 = eval.m31_add(carry_11_col68, m31_524288);
    eval.set_sub_input_word(117, wg_v1614);
    eval.set_lookup_word(87, m31_497455322);
    let wg_v1615 = eval.m31_add(carry_11_col68, m31_524288);
    eval.set_lookup_word(88, wg_v1615);
    let wg_v1616 = eval.m31_add(conv_mod_tmp_fec87_23[12], carry_11_col68);
    let carry_12_col69 = eval.m31_mul(wg_v1616, m31_4194304);
    eval.set_col(69, carry_12_col69);
    let wg_v1617 = eval.m31_add(carry_12_col69, m31_524288);
    eval.set_sub_input_word(123, wg_v1617);
    eval.set_lookup_word(99, m31_447122465);
    let wg_v1618 = eval.m31_add(carry_12_col69, m31_524288);
    eval.set_lookup_word(100, wg_v1618);
    let wg_v1619 = eval.m31_add(conv_mod_tmp_fec87_23[13], carry_12_col69);
    let carry_13_col70 = eval.m31_mul(wg_v1619, m31_4194304);
    eval.set_col(70, carry_13_col70);
    let wg_v1620 = eval.m31_add(carry_13_col70, m31_524288);
    eval.set_sub_input_word(129, wg_v1620);
    eval.set_lookup_word(111, m31_463900084);
    let wg_v1621 = eval.m31_add(carry_13_col70, m31_524288);
    eval.set_lookup_word(112, wg_v1621);
    let wg_v1622 = eval.m31_add(conv_mod_tmp_fec87_23[14], carry_13_col70);
    let carry_14_col71 = eval.m31_mul(wg_v1622, m31_4194304);
    eval.set_col(71, carry_14_col71);
    let wg_v1623 = eval.m31_add(carry_14_col71, m31_524288);
    eval.set_sub_input_word(135, wg_v1623);
    eval.set_lookup_word(123, m31_682009131);
    let wg_v1624 = eval.m31_add(carry_14_col71, m31_524288);
    eval.set_lookup_word(124, wg_v1624);
    let wg_v1625 = eval.m31_add(conv_mod_tmp_fec87_23[15], carry_14_col71);
    let carry_15_col72 = eval.m31_mul(wg_v1625, m31_4194304);
    eval.set_col(72, carry_15_col72);
    let wg_v1626 = eval.m31_add(carry_15_col72, m31_524288);
    eval.set_sub_input_word(86, wg_v1626);
    eval.set_lookup_word(25, m31_1410849886);
    let wg_v1627 = eval.m31_add(carry_15_col72, m31_524288);
    eval.set_lookup_word(26, wg_v1627);
    let wg_v1628 = eval.m31_add(conv_mod_tmp_fec87_23[16], carry_15_col72);
    let carry_16_col73 = eval.m31_mul(wg_v1628, m31_4194304);
    eval.set_col(73, carry_16_col73);
    let wg_v1629 = eval.m31_add(carry_16_col73, m31_524288);
    eval.set_sub_input_word(94, wg_v1629);
    eval.set_lookup_word(41, m31_514232941);
    let wg_v1630 = eval.m31_add(carry_16_col73, m31_524288);
    eval.set_lookup_word(42, wg_v1630);
    let wg_v1631 = eval.m31_add(conv_mod_tmp_fec87_23[17], carry_16_col73);
    let carry_17_col74 = eval.m31_mul(wg_v1631, m31_4194304);
    eval.set_col(74, carry_17_col74);
    let wg_v1632 = eval.m31_add(carry_17_col74, m31_524288);
    eval.set_sub_input_word(102, wg_v1632);
    eval.set_lookup_word(57, m31_531010560);
    let wg_v1633 = eval.m31_add(carry_17_col74, m31_524288);
    eval.set_lookup_word(58, wg_v1633);
    let wg_v1634 = eval.m31_add(conv_mod_tmp_fec87_23[18], carry_17_col74);
    let carry_18_col75 = eval.m31_mul(wg_v1634, m31_4194304);
    eval.set_col(75, carry_18_col75);
    let wg_v1635 = eval.m31_add(carry_18_col75, m31_524288);
    eval.set_sub_input_word(110, wg_v1635);
    eval.set_lookup_word(73, m31_480677703);
    let wg_v1636 = eval.m31_add(carry_18_col75, m31_524288);
    eval.set_lookup_word(74, wg_v1636);
    let wg_v1637 = eval.m31_add(conv_mod_tmp_fec87_23[19], carry_18_col75);
    let carry_19_col76 = eval.m31_mul(wg_v1637, m31_4194304);
    eval.set_col(76, carry_19_col76);
    let wg_v1638 = eval.m31_add(carry_19_col76, m31_524288);
    eval.set_sub_input_word(118, wg_v1638);
    eval.set_lookup_word(89, m31_497455322);
    let wg_v1639 = eval.m31_add(carry_19_col76, m31_524288);
    eval.set_lookup_word(90, wg_v1639);
    let wg_v1640 = eval.m31_add(conv_mod_tmp_fec87_23[20], carry_19_col76);
    let carry_20_col77 = eval.m31_mul(wg_v1640, m31_4194304);
    eval.set_col(77, carry_20_col77);
    let wg_v1641 = eval.m31_add(carry_20_col77, m31_524288);
    eval.set_sub_input_word(124, wg_v1641);
    eval.set_lookup_word(101, m31_447122465);
    let wg_v1642 = eval.m31_add(carry_20_col77, m31_524288);
    eval.set_lookup_word(102, wg_v1642);
    let wg_v1643 = eval.m31_mul(m31_136, k_col56);
    let wg_v1644 = eval.m31_sub(conv_mod_tmp_fec87_23[21], wg_v1643);
    let wg_v1645 = eval.m31_add(wg_v1644, carry_20_col77);
    let carry_21_col78 = eval.m31_mul(wg_v1645, m31_4194304);
    eval.set_col(78, carry_21_col78);
    let wg_v1646 = eval.m31_add(carry_21_col78, m31_524288);
    eval.set_sub_input_word(130, wg_v1646);
    eval.set_lookup_word(113, m31_463900084);
    let wg_v1647 = eval.m31_add(carry_21_col78, m31_524288);
    eval.set_lookup_word(114, wg_v1647);
    let wg_v1648 = eval.m31_add(conv_mod_tmp_fec87_23[22], carry_21_col78);
    let carry_22_col79 = eval.m31_mul(wg_v1648, m31_4194304);
    eval.set_col(79, carry_22_col79);
    let wg_v1649 = eval.m31_add(carry_22_col79, m31_524288);
    eval.set_sub_input_word(136, wg_v1649);
    eval.set_lookup_word(125, m31_682009131);
    let wg_v1650 = eval.m31_add(carry_22_col79, m31_524288);
    eval.set_lookup_word(126, wg_v1650);
    let wg_v1651 = eval.m31_add(conv_mod_tmp_fec87_23[23], carry_22_col79);
    let carry_23_col80 = eval.m31_mul(wg_v1651, m31_4194304);
    eval.set_col(80, carry_23_col80);
    let wg_v1652 = eval.m31_add(carry_23_col80, m31_524288);
    eval.set_sub_input_word(87, wg_v1652);
    eval.set_lookup_word(27, m31_1410849886);
    let wg_v1653 = eval.m31_add(carry_23_col80, m31_524288);
    eval.set_lookup_word(28, wg_v1653);
    let wg_v1654 = eval.m31_add(conv_mod_tmp_fec87_23[24], carry_23_col80);
    let carry_24_col81 = eval.m31_mul(wg_v1654, m31_4194304);
    eval.set_col(81, carry_24_col81);
    let wg_v1655 = eval.m31_add(carry_24_col81, m31_524288);
    eval.set_sub_input_word(95, wg_v1655);
    eval.set_lookup_word(43, m31_514232941);
    let wg_v1656 = eval.m31_add(carry_24_col81, m31_524288);
    eval.set_lookup_word(44, wg_v1656);
    let wg_v1657 = eval.m31_add(conv_mod_tmp_fec87_23[25], carry_24_col81);
    let carry_25_col82 = eval.m31_mul(wg_v1657, m31_4194304);
    eval.set_col(82, carry_25_col82);
    let wg_v1658 = eval.m31_add(carry_25_col82, m31_524288);
    eval.set_sub_input_word(103, wg_v1658);
    eval.set_lookup_word(59, m31_531010560);
    let wg_v1659 = eval.m31_add(carry_25_col82, m31_524288);
    eval.set_lookup_word(60, wg_v1659);
    let wg_v1660 = eval.m31_add(conv_mod_tmp_fec87_23[26], carry_25_col82);
    let carry_26_col83 = eval.m31_mul(wg_v1660, m31_4194304);
    eval.set_col(83, carry_26_col83);
    let wg_v1661 = eval.m31_add(carry_26_col83, m31_524288);
    eval.set_sub_input_word(111, wg_v1661);
    eval.set_lookup_word(75, m31_480677703);
    let wg_v1662 = eval.m31_add(carry_26_col83, m31_524288);
    eval.set_lookup_word(76, wg_v1662);
    let mul_252_output_tmp_fec87_25 = mul_res_tmp_fec87_3.clone();
    let mul_res_tmp_fec87_26 = eval.felt_mul(
        felt_252_unpack_from_27_range_check_output_output_tmp_fec87_2
            .clone()
            .clone(),
        mul_252_output_tmp_fec87_25.clone().clone(),
    );
    let mul_res_limb_0_col84 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 0);
    eval.set_col(84, mul_res_limb_0_col84);
    let mul_res_limb_1_col85 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 1);
    eval.set_col(85, mul_res_limb_1_col85);
    let mul_res_limb_2_col86 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 2);
    eval.set_col(86, mul_res_limb_2_col86);
    let mul_res_limb_3_col87 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 3);
    eval.set_col(87, mul_res_limb_3_col87);
    let mul_res_limb_4_col88 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 4);
    eval.set_col(88, mul_res_limb_4_col88);
    let mul_res_limb_5_col89 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 5);
    eval.set_col(89, mul_res_limb_5_col89);
    let mul_res_limb_6_col90 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 6);
    eval.set_col(90, mul_res_limb_6_col90);
    let mul_res_limb_7_col91 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 7);
    eval.set_col(91, mul_res_limb_7_col91);
    let mul_res_limb_8_col92 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 8);
    eval.set_col(92, mul_res_limb_8_col92);
    let mul_res_limb_9_col93 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 9);
    eval.set_col(93, mul_res_limb_9_col93);
    let mul_res_limb_10_col94 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 10);
    eval.set_col(94, mul_res_limb_10_col94);
    let mul_res_limb_11_col95 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 11);
    eval.set_col(95, mul_res_limb_11_col95);
    let mul_res_limb_12_col96 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 12);
    eval.set_col(96, mul_res_limb_12_col96);
    let mul_res_limb_13_col97 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 13);
    eval.set_col(97, mul_res_limb_13_col97);
    let mul_res_limb_14_col98 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 14);
    eval.set_col(98, mul_res_limb_14_col98);
    let mul_res_limb_15_col99 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 15);
    eval.set_col(99, mul_res_limb_15_col99);
    let mul_res_limb_16_col100 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 16);
    eval.set_col(100, mul_res_limb_16_col100);
    let mul_res_limb_17_col101 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 17);
    eval.set_col(101, mul_res_limb_17_col101);
    let mul_res_limb_18_col102 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 18);
    eval.set_col(102, mul_res_limb_18_col102);
    let mul_res_limb_19_col103 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 19);
    eval.set_col(103, mul_res_limb_19_col103);
    let mul_res_limb_20_col104 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 20);
    eval.set_col(104, mul_res_limb_20_col104);
    let mul_res_limb_21_col105 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 21);
    eval.set_col(105, mul_res_limb_21_col105);
    let mul_res_limb_22_col106 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 22);
    eval.set_col(106, mul_res_limb_22_col106);
    let mul_res_limb_23_col107 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 23);
    eval.set_col(107, mul_res_limb_23_col107);
    let mul_res_limb_24_col108 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 24);
    eval.set_col(108, mul_res_limb_24_col108);
    let mul_res_limb_25_col109 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 25);
    eval.set_col(109, mul_res_limb_25_col109);
    let mul_res_limb_26_col110 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 26);
    eval.set_col(110, mul_res_limb_26_col110);
    let mul_res_limb_27_col111 = eval.felt_get_m31(&mul_res_tmp_fec87_26.clone(), 27);
    eval.set_col(111, mul_res_limb_27_col111);
    eval.set_sub_input_word(8, mul_res_limb_0_col84);
    eval.set_sub_input_word(9, mul_res_limb_1_col85);
    eval.set_lookup_word(145, m31_517791011);
    eval.set_lookup_word(146, mul_res_limb_0_col84);
    eval.set_lookup_word(147, mul_res_limb_1_col85);
    eval.set_sub_input_word(20, mul_res_limb_2_col86);
    eval.set_sub_input_word(21, mul_res_limb_3_col87);
    eval.set_lookup_word(163, m31_1897792095);
    eval.set_lookup_word(164, mul_res_limb_2_col86);
    eval.set_lookup_word(165, mul_res_limb_3_col87);
    eval.set_sub_input_word(32, mul_res_limb_4_col88);
    eval.set_sub_input_word(33, mul_res_limb_5_col89);
    eval.set_lookup_word(181, m31_1881014476);
    eval.set_lookup_word(182, mul_res_limb_4_col88);
    eval.set_lookup_word(183, mul_res_limb_5_col89);
    eval.set_sub_input_word(44, mul_res_limb_6_col90);
    eval.set_sub_input_word(45, mul_res_limb_7_col91);
    eval.set_lookup_word(199, m31_1864236857);
    eval.set_lookup_word(200, mul_res_limb_6_col90);
    eval.set_lookup_word(201, mul_res_limb_7_col91);
    eval.set_sub_input_word(56, mul_res_limb_8_col92);
    eval.set_sub_input_word(57, mul_res_limb_9_col93);
    eval.set_lookup_word(217, m31_1847459238);
    eval.set_lookup_word(218, mul_res_limb_8_col92);
    eval.set_lookup_word(219, mul_res_limb_9_col93);
    eval.set_sub_input_word(68, mul_res_limb_10_col94);
    eval.set_sub_input_word(69, mul_res_limb_11_col95);
    eval.set_lookup_word(235, m31_1830681619);
    eval.set_lookup_word(236, mul_res_limb_10_col94);
    eval.set_lookup_word(237, mul_res_limb_11_col95);
    eval.set_sub_input_word(76, mul_res_limb_12_col96);
    eval.set_sub_input_word(77, mul_res_limb_13_col97);
    eval.set_lookup_word(247, m31_1813904000);
    eval.set_lookup_word(248, mul_res_limb_12_col96);
    eval.set_lookup_word(249, mul_res_limb_13_col97);
    eval.set_sub_input_word(82, mul_res_limb_14_col98);
    eval.set_sub_input_word(83, mul_res_limb_15_col99);
    eval.set_lookup_word(256, m31_2065568285);
    eval.set_lookup_word(257, mul_res_limb_14_col98);
    eval.set_lookup_word(258, mul_res_limb_15_col99);
    eval.set_sub_input_word(10, mul_res_limb_16_col100);
    eval.set_sub_input_word(11, mul_res_limb_17_col101);
    eval.set_lookup_word(148, m31_517791011);
    eval.set_lookup_word(149, mul_res_limb_16_col100);
    eval.set_lookup_word(150, mul_res_limb_17_col101);
    eval.set_sub_input_word(22, mul_res_limb_18_col102);
    eval.set_sub_input_word(23, mul_res_limb_19_col103);
    eval.set_lookup_word(166, m31_1897792095);
    eval.set_lookup_word(167, mul_res_limb_18_col102);
    eval.set_lookup_word(168, mul_res_limb_19_col103);
    eval.set_sub_input_word(34, mul_res_limb_20_col104);
    eval.set_sub_input_word(35, mul_res_limb_21_col105);
    eval.set_lookup_word(184, m31_1881014476);
    eval.set_lookup_word(185, mul_res_limb_20_col104);
    eval.set_lookup_word(186, mul_res_limb_21_col105);
    eval.set_sub_input_word(46, mul_res_limb_22_col106);
    eval.set_sub_input_word(47, mul_res_limb_23_col107);
    eval.set_lookup_word(202, m31_1864236857);
    eval.set_lookup_word(203, mul_res_limb_22_col106);
    eval.set_lookup_word(204, mul_res_limb_23_col107);
    eval.set_sub_input_word(58, mul_res_limb_24_col108);
    eval.set_sub_input_word(59, mul_res_limb_25_col109);
    eval.set_lookup_word(220, m31_1847459238);
    eval.set_lookup_word(221, mul_res_limb_24_col108);
    eval.set_lookup_word(222, mul_res_limb_25_col109);
    eval.set_sub_input_word(70, mul_res_limb_26_col110);
    eval.set_sub_input_word(71, mul_res_limb_27_col111);
    eval.set_lookup_word(238, m31_1830681619);
    eval.set_lookup_word(239, mul_res_limb_26_col110);
    eval.set_lookup_word(240, mul_res_limb_27_col111);
    let wg_v1663 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_0_col28);
    let wg_v1664 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_1_col29);
    let wg_v1665 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_0_col28);
    let wg_v1666 = eval.m31_add(wg_v1664, wg_v1665);
    let wg_v1667 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_2_col30);
    let wg_v1668 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_1_col29);
    let wg_v1669 = eval.m31_add(wg_v1667, wg_v1668);
    let wg_v1670 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1671 = eval.m31_mul(wg_v1670, mul_res_limb_0_col28);
    let wg_v1672 = eval.m31_add(wg_v1669, wg_v1671);
    let wg_v1673 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_3_col31);
    let wg_v1674 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_2_col30);
    let wg_v1675 = eval.m31_add(wg_v1673, wg_v1674);
    let wg_v1676 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1677 = eval.m31_mul(wg_v1676, mul_res_limb_1_col29);
    let wg_v1678 = eval.m31_add(wg_v1675, wg_v1677);
    let wg_v1679 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_0_col28);
    let wg_v1680 = eval.m31_add(wg_v1678, wg_v1679);
    let wg_v1681 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_4_col32);
    let wg_v1682 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_3_col31);
    let wg_v1683 = eval.m31_add(wg_v1681, wg_v1682);
    let wg_v1684 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1685 = eval.m31_mul(wg_v1684, mul_res_limb_2_col30);
    let wg_v1686 = eval.m31_add(wg_v1683, wg_v1685);
    let wg_v1687 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_1_col29);
    let wg_v1688 = eval.m31_add(wg_v1686, wg_v1687);
    let wg_v1689 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_0_col28);
    let wg_v1690 = eval.m31_add(wg_v1688, wg_v1689);
    let wg_v1691 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_5_col33);
    let wg_v1692 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_4_col32);
    let wg_v1693 = eval.m31_add(wg_v1691, wg_v1692);
    let wg_v1694 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1695 = eval.m31_mul(wg_v1694, mul_res_limb_3_col31);
    let wg_v1696 = eval.m31_add(wg_v1693, wg_v1695);
    let wg_v1697 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_2_col30);
    let wg_v1698 = eval.m31_add(wg_v1696, wg_v1697);
    let wg_v1699 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_1_col29);
    let wg_v1700 = eval.m31_add(wg_v1698, wg_v1699);
    let wg_v1701 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1702 = eval.m31_mul(wg_v1701, mul_res_limb_0_col28);
    let wg_v1703 = eval.m31_add(wg_v1700, wg_v1702);
    let wg_v1704 = eval.m31_mul(unpacked_limb_0_col10, mul_res_limb_6_col34);
    let wg_v1705 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_5_col33);
    let wg_v1706 = eval.m31_add(wg_v1704, wg_v1705);
    let wg_v1707 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1708 = eval.m31_mul(wg_v1707, mul_res_limb_4_col32);
    let wg_v1709 = eval.m31_add(wg_v1706, wg_v1708);
    let wg_v1710 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_3_col31);
    let wg_v1711 = eval.m31_add(wg_v1709, wg_v1710);
    let wg_v1712 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_2_col30);
    let wg_v1713 = eval.m31_add(wg_v1711, wg_v1712);
    let wg_v1714 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1715 = eval.m31_mul(wg_v1714, mul_res_limb_1_col29);
    let wg_v1716 = eval.m31_add(wg_v1713, wg_v1715);
    let wg_v1717 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_0_col28);
    let wg_v1718 = eval.m31_add(wg_v1716, wg_v1717);
    let wg_v1719 = eval.m31_mul(unpacked_limb_1_col11, mul_res_limb_6_col34);
    let wg_v1720 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1721 = eval.m31_mul(wg_v1720, mul_res_limb_5_col33);
    let wg_v1722 = eval.m31_add(wg_v1719, wg_v1721);
    let wg_v1723 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_4_col32);
    let wg_v1724 = eval.m31_add(wg_v1722, wg_v1723);
    let wg_v1725 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_3_col31);
    let wg_v1726 = eval.m31_add(wg_v1724, wg_v1725);
    let wg_v1727 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1728 = eval.m31_mul(wg_v1727, mul_res_limb_2_col30);
    let wg_v1729 = eval.m31_add(wg_v1726, wg_v1728);
    let wg_v1730 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_1_col29);
    let wg_v1731 = eval.m31_add(wg_v1729, wg_v1730);
    let wg_v1732 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1733 = eval.m31_mul(wg_v1732, mul_res_limb_6_col34);
    let wg_v1734 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_5_col33);
    let wg_v1735 = eval.m31_add(wg_v1733, wg_v1734);
    let wg_v1736 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_4_col32);
    let wg_v1737 = eval.m31_add(wg_v1735, wg_v1736);
    let wg_v1738 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1739 = eval.m31_mul(wg_v1738, mul_res_limb_3_col31);
    let wg_v1740 = eval.m31_add(wg_v1737, wg_v1739);
    let wg_v1741 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_2_col30);
    let wg_v1742 = eval.m31_add(wg_v1740, wg_v1741);
    let wg_v1743 = eval.m31_mul(unpacked_limb_3_col12, mul_res_limb_6_col34);
    let wg_v1744 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_5_col33);
    let wg_v1745 = eval.m31_add(wg_v1743, wg_v1744);
    let wg_v1746 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1747 = eval.m31_mul(wg_v1746, mul_res_limb_4_col32);
    let wg_v1748 = eval.m31_add(wg_v1745, wg_v1747);
    let wg_v1749 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_3_col31);
    let wg_v1750 = eval.m31_add(wg_v1748, wg_v1749);
    let wg_v1751 = eval.m31_mul(unpacked_limb_4_col13, mul_res_limb_6_col34);
    let wg_v1752 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1753 = eval.m31_mul(wg_v1752, mul_res_limb_5_col33);
    let wg_v1754 = eval.m31_add(wg_v1751, wg_v1753);
    let wg_v1755 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_4_col32);
    let wg_v1756 = eval.m31_add(wg_v1754, wg_v1755);
    let wg_v1757 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1758 = eval.m31_mul(wg_v1757, mul_res_limb_6_col34);
    let wg_v1759 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_5_col33);
    let wg_v1760 = eval.m31_add(wg_v1758, wg_v1759);
    let wg_v1761 = eval.m31_mul(unpacked_limb_6_col14, mul_res_limb_6_col34);
    let z0_tmp_fec87_27 = [
        wg_v1663, wg_v1666, wg_v1672, wg_v1680, wg_v1690, wg_v1703, wg_v1718, wg_v1731, wg_v1742,
        wg_v1750, wg_v1756, wg_v1760, wg_v1761,
    ];
    let wg_v1762 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_7_col35);
    let wg_v1763 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_8_col36);
    let wg_v1764 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1765 = eval.m31_mul(wg_v1764, mul_res_limb_7_col35);
    let wg_v1766 = eval.m31_add(wg_v1763, wg_v1765);
    let wg_v1767 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_9_col37);
    let wg_v1768 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1769 = eval.m31_mul(wg_v1768, mul_res_limb_8_col36);
    let wg_v1770 = eval.m31_add(wg_v1767, wg_v1769);
    let wg_v1771 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_7_col35);
    let wg_v1772 = eval.m31_add(wg_v1770, wg_v1771);
    let wg_v1773 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_10_col38);
    let wg_v1774 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1775 = eval.m31_mul(wg_v1774, mul_res_limb_9_col37);
    let wg_v1776 = eval.m31_add(wg_v1773, wg_v1775);
    let wg_v1777 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_8_col36);
    let wg_v1778 = eval.m31_add(wg_v1776, wg_v1777);
    let wg_v1779 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_7_col35);
    let wg_v1780 = eval.m31_add(wg_v1778, wg_v1779);
    let wg_v1781 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_11_col39);
    let wg_v1782 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1783 = eval.m31_mul(wg_v1782, mul_res_limb_10_col38);
    let wg_v1784 = eval.m31_add(wg_v1781, wg_v1783);
    let wg_v1785 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_9_col37);
    let wg_v1786 = eval.m31_add(wg_v1784, wg_v1785);
    let wg_v1787 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_8_col36);
    let wg_v1788 = eval.m31_add(wg_v1786, wg_v1787);
    let wg_v1789 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1790 = eval.m31_mul(wg_v1789, mul_res_limb_7_col35);
    let wg_v1791 = eval.m31_add(wg_v1788, wg_v1790);
    let wg_v1792 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_12_col40);
    let wg_v1793 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1794 = eval.m31_mul(wg_v1793, mul_res_limb_11_col39);
    let wg_v1795 = eval.m31_add(wg_v1792, wg_v1794);
    let wg_v1796 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_10_col38);
    let wg_v1797 = eval.m31_add(wg_v1795, wg_v1796);
    let wg_v1798 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_9_col37);
    let wg_v1799 = eval.m31_add(wg_v1797, wg_v1798);
    let wg_v1800 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1801 = eval.m31_mul(wg_v1800, mul_res_limb_8_col36);
    let wg_v1802 = eval.m31_add(wg_v1799, wg_v1801);
    let wg_v1803 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_7_col35);
    let wg_v1804 = eval.m31_add(wg_v1802, wg_v1803);
    let wg_v1805 = eval.m31_mul(unpacked_limb_7_col15, mul_res_limb_13_col41);
    let wg_v1806 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1807 = eval.m31_mul(wg_v1806, mul_res_limb_12_col40);
    let wg_v1808 = eval.m31_add(wg_v1805, wg_v1807);
    let wg_v1809 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_11_col39);
    let wg_v1810 = eval.m31_add(wg_v1808, wg_v1809);
    let wg_v1811 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_10_col38);
    let wg_v1812 = eval.m31_add(wg_v1810, wg_v1811);
    let wg_v1813 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1814 = eval.m31_mul(wg_v1813, mul_res_limb_9_col37);
    let wg_v1815 = eval.m31_add(wg_v1812, wg_v1814);
    let wg_v1816 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_8_col36);
    let wg_v1817 = eval.m31_add(wg_v1815, wg_v1816);
    let wg_v1818 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_7_col35);
    let wg_v1819 = eval.m31_add(wg_v1817, wg_v1818);
    let wg_v1820 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1821 = eval.m31_mul(wg_v1820, mul_res_limb_13_col41);
    let wg_v1822 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_12_col40);
    let wg_v1823 = eval.m31_add(wg_v1821, wg_v1822);
    let wg_v1824 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_11_col39);
    let wg_v1825 = eval.m31_add(wg_v1823, wg_v1824);
    let wg_v1826 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1827 = eval.m31_mul(wg_v1826, mul_res_limb_10_col38);
    let wg_v1828 = eval.m31_add(wg_v1825, wg_v1827);
    let wg_v1829 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_9_col37);
    let wg_v1830 = eval.m31_add(wg_v1828, wg_v1829);
    let wg_v1831 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_8_col36);
    let wg_v1832 = eval.m31_add(wg_v1830, wg_v1831);
    let wg_v1833 = eval.m31_mul(unpacked_limb_9_col16, mul_res_limb_13_col41);
    let wg_v1834 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_12_col40);
    let wg_v1835 = eval.m31_add(wg_v1833, wg_v1834);
    let wg_v1836 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1837 = eval.m31_mul(wg_v1836, mul_res_limb_11_col39);
    let wg_v1838 = eval.m31_add(wg_v1835, wg_v1837);
    let wg_v1839 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_10_col38);
    let wg_v1840 = eval.m31_add(wg_v1838, wg_v1839);
    let wg_v1841 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_9_col37);
    let wg_v1842 = eval.m31_add(wg_v1840, wg_v1841);
    let wg_v1843 = eval.m31_mul(unpacked_limb_10_col17, mul_res_limb_13_col41);
    let wg_v1844 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1845 = eval.m31_mul(wg_v1844, mul_res_limb_12_col40);
    let wg_v1846 = eval.m31_add(wg_v1843, wg_v1845);
    let wg_v1847 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_11_col39);
    let wg_v1848 = eval.m31_add(wg_v1846, wg_v1847);
    let wg_v1849 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_10_col38);
    let wg_v1850 = eval.m31_add(wg_v1848, wg_v1849);
    let wg_v1851 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1852 = eval.m31_mul(wg_v1851, mul_res_limb_13_col41);
    let wg_v1853 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_12_col40);
    let wg_v1854 = eval.m31_add(wg_v1852, wg_v1853);
    let wg_v1855 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_11_col39);
    let wg_v1856 = eval.m31_add(wg_v1854, wg_v1855);
    let wg_v1857 = eval.m31_mul(unpacked_limb_12_col18, mul_res_limb_13_col41);
    let wg_v1858 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_12_col40);
    let wg_v1859 = eval.m31_add(wg_v1857, wg_v1858);
    let wg_v1860 = eval.m31_mul(unpacked_limb_13_col19, mul_res_limb_13_col41);
    let z2_tmp_fec87_28 = [
        wg_v1762, wg_v1766, wg_v1772, wg_v1780, wg_v1791, wg_v1804, wg_v1819, wg_v1832, wg_v1842,
        wg_v1850, wg_v1856, wg_v1859, wg_v1860,
    ];
    let wg_v1861 = eval.m31_add(unpacked_limb_0_col10, unpacked_limb_7_col15);
    let wg_v1862 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v1863 = eval.m31_add(unpacked_limb_1_col11, wg_v1862);
    let wg_v1864 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v1865 = eval.m31_add(wg_v1864, unpacked_limb_9_col16);
    let wg_v1866 = eval.m31_add(unpacked_limb_3_col12, unpacked_limb_10_col17);
    let wg_v1867 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v1868 = eval.m31_add(unpacked_limb_4_col13, wg_v1867);
    let wg_v1869 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v1870 = eval.m31_add(wg_v1869, unpacked_limb_12_col18);
    let wg_v1871 = eval.m31_add(unpacked_limb_6_col14, unpacked_limb_13_col19);
    let x_sum_tmp_fec87_29 = [
        wg_v1861, wg_v1863, wg_v1865, wg_v1866, wg_v1868, wg_v1870, wg_v1871,
    ];
    let wg_v1872 = eval.m31_add(mul_res_limb_0_col28, mul_res_limb_7_col35);
    let wg_v1873 = eval.m31_add(mul_res_limb_1_col29, mul_res_limb_8_col36);
    let wg_v1874 = eval.m31_add(mul_res_limb_2_col30, mul_res_limb_9_col37);
    let wg_v1875 = eval.m31_add(mul_res_limb_3_col31, mul_res_limb_10_col38);
    let wg_v1876 = eval.m31_add(mul_res_limb_4_col32, mul_res_limb_11_col39);
    let wg_v1877 = eval.m31_add(mul_res_limb_5_col33, mul_res_limb_12_col40);
    let wg_v1878 = eval.m31_add(mul_res_limb_6_col34, mul_res_limb_13_col41);
    let y_sum_tmp_fec87_30 = [
        wg_v1872, wg_v1873, wg_v1874, wg_v1875, wg_v1876, wg_v1877, wg_v1878,
    ];
    let wg_v1879 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[0]);
    let wg_v1880 = eval.m31_sub(wg_v1879, z0_tmp_fec87_27[0]);
    let wg_v1881 = eval.m31_sub(wg_v1880, z2_tmp_fec87_28[0]);
    let wg_v1882 = eval.m31_add(z0_tmp_fec87_27[7], wg_v1881);
    let wg_v1883 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[1]);
    let wg_v1884 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[0]);
    let wg_v1885 = eval.m31_add(wg_v1883, wg_v1884);
    let wg_v1886 = eval.m31_sub(wg_v1885, z0_tmp_fec87_27[1]);
    let wg_v1887 = eval.m31_sub(wg_v1886, z2_tmp_fec87_28[1]);
    let wg_v1888 = eval.m31_add(z0_tmp_fec87_27[8], wg_v1887);
    let wg_v1889 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[2]);
    let wg_v1890 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[1]);
    let wg_v1891 = eval.m31_add(wg_v1889, wg_v1890);
    let wg_v1892 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[0]);
    let wg_v1893 = eval.m31_add(wg_v1891, wg_v1892);
    let wg_v1894 = eval.m31_sub(wg_v1893, z0_tmp_fec87_27[2]);
    let wg_v1895 = eval.m31_sub(wg_v1894, z2_tmp_fec87_28[2]);
    let wg_v1896 = eval.m31_add(z0_tmp_fec87_27[9], wg_v1895);
    let wg_v1897 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[3]);
    let wg_v1898 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[2]);
    let wg_v1899 = eval.m31_add(wg_v1897, wg_v1898);
    let wg_v1900 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[1]);
    let wg_v1901 = eval.m31_add(wg_v1899, wg_v1900);
    let wg_v1902 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[0]);
    let wg_v1903 = eval.m31_add(wg_v1901, wg_v1902);
    let wg_v1904 = eval.m31_sub(wg_v1903, z0_tmp_fec87_27[3]);
    let wg_v1905 = eval.m31_sub(wg_v1904, z2_tmp_fec87_28[3]);
    let wg_v1906 = eval.m31_add(z0_tmp_fec87_27[10], wg_v1905);
    let wg_v1907 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[4]);
    let wg_v1908 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[3]);
    let wg_v1909 = eval.m31_add(wg_v1907, wg_v1908);
    let wg_v1910 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[2]);
    let wg_v1911 = eval.m31_add(wg_v1909, wg_v1910);
    let wg_v1912 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[1]);
    let wg_v1913 = eval.m31_add(wg_v1911, wg_v1912);
    let wg_v1914 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[0]);
    let wg_v1915 = eval.m31_add(wg_v1913, wg_v1914);
    let wg_v1916 = eval.m31_sub(wg_v1915, z0_tmp_fec87_27[4]);
    let wg_v1917 = eval.m31_sub(wg_v1916, z2_tmp_fec87_28[4]);
    let wg_v1918 = eval.m31_add(z0_tmp_fec87_27[11], wg_v1917);
    let wg_v1919 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[5]);
    let wg_v1920 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[4]);
    let wg_v1921 = eval.m31_add(wg_v1919, wg_v1920);
    let wg_v1922 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[3]);
    let wg_v1923 = eval.m31_add(wg_v1921, wg_v1922);
    let wg_v1924 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[2]);
    let wg_v1925 = eval.m31_add(wg_v1923, wg_v1924);
    let wg_v1926 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[1]);
    let wg_v1927 = eval.m31_add(wg_v1925, wg_v1926);
    let wg_v1928 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[0]);
    let wg_v1929 = eval.m31_add(wg_v1927, wg_v1928);
    let wg_v1930 = eval.m31_sub(wg_v1929, z0_tmp_fec87_27[5]);
    let wg_v1931 = eval.m31_sub(wg_v1930, z2_tmp_fec87_28[5]);
    let wg_v1932 = eval.m31_add(z0_tmp_fec87_27[12], wg_v1931);
    let wg_v1933 = eval.m31_mul(x_sum_tmp_fec87_29[0], y_sum_tmp_fec87_30[6]);
    let wg_v1934 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[5]);
    let wg_v1935 = eval.m31_add(wg_v1933, wg_v1934);
    let wg_v1936 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[4]);
    let wg_v1937 = eval.m31_add(wg_v1935, wg_v1936);
    let wg_v1938 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[3]);
    let wg_v1939 = eval.m31_add(wg_v1937, wg_v1938);
    let wg_v1940 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[2]);
    let wg_v1941 = eval.m31_add(wg_v1939, wg_v1940);
    let wg_v1942 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[1]);
    let wg_v1943 = eval.m31_add(wg_v1941, wg_v1942);
    let wg_v1944 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[0]);
    let wg_v1945 = eval.m31_add(wg_v1943, wg_v1944);
    let wg_v1946 = eval.m31_sub(wg_v1945, z0_tmp_fec87_27[6]);
    let wg_v1947 = eval.m31_sub(wg_v1946, z2_tmp_fec87_28[6]);
    let wg_v1948 = eval.m31_mul(x_sum_tmp_fec87_29[1], y_sum_tmp_fec87_30[6]);
    let wg_v1949 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[5]);
    let wg_v1950 = eval.m31_add(wg_v1948, wg_v1949);
    let wg_v1951 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[4]);
    let wg_v1952 = eval.m31_add(wg_v1950, wg_v1951);
    let wg_v1953 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[3]);
    let wg_v1954 = eval.m31_add(wg_v1952, wg_v1953);
    let wg_v1955 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[2]);
    let wg_v1956 = eval.m31_add(wg_v1954, wg_v1955);
    let wg_v1957 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[1]);
    let wg_v1958 = eval.m31_add(wg_v1956, wg_v1957);
    let wg_v1959 = eval.m31_sub(wg_v1958, z0_tmp_fec87_27[7]);
    let wg_v1960 = eval.m31_sub(wg_v1959, z2_tmp_fec87_28[7]);
    let wg_v1961 = eval.m31_add(z2_tmp_fec87_28[0], wg_v1960);
    let wg_v1962 = eval.m31_mul(x_sum_tmp_fec87_29[2], y_sum_tmp_fec87_30[6]);
    let wg_v1963 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[5]);
    let wg_v1964 = eval.m31_add(wg_v1962, wg_v1963);
    let wg_v1965 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[4]);
    let wg_v1966 = eval.m31_add(wg_v1964, wg_v1965);
    let wg_v1967 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[3]);
    let wg_v1968 = eval.m31_add(wg_v1966, wg_v1967);
    let wg_v1969 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[2]);
    let wg_v1970 = eval.m31_add(wg_v1968, wg_v1969);
    let wg_v1971 = eval.m31_sub(wg_v1970, z0_tmp_fec87_27[8]);
    let wg_v1972 = eval.m31_sub(wg_v1971, z2_tmp_fec87_28[8]);
    let wg_v1973 = eval.m31_add(z2_tmp_fec87_28[1], wg_v1972);
    let wg_v1974 = eval.m31_mul(x_sum_tmp_fec87_29[3], y_sum_tmp_fec87_30[6]);
    let wg_v1975 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[5]);
    let wg_v1976 = eval.m31_add(wg_v1974, wg_v1975);
    let wg_v1977 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[4]);
    let wg_v1978 = eval.m31_add(wg_v1976, wg_v1977);
    let wg_v1979 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[3]);
    let wg_v1980 = eval.m31_add(wg_v1978, wg_v1979);
    let wg_v1981 = eval.m31_sub(wg_v1980, z0_tmp_fec87_27[9]);
    let wg_v1982 = eval.m31_sub(wg_v1981, z2_tmp_fec87_28[9]);
    let wg_v1983 = eval.m31_add(z2_tmp_fec87_28[2], wg_v1982);
    let wg_v1984 = eval.m31_mul(x_sum_tmp_fec87_29[4], y_sum_tmp_fec87_30[6]);
    let wg_v1985 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[5]);
    let wg_v1986 = eval.m31_add(wg_v1984, wg_v1985);
    let wg_v1987 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[4]);
    let wg_v1988 = eval.m31_add(wg_v1986, wg_v1987);
    let wg_v1989 = eval.m31_sub(wg_v1988, z0_tmp_fec87_27[10]);
    let wg_v1990 = eval.m31_sub(wg_v1989, z2_tmp_fec87_28[10]);
    let wg_v1991 = eval.m31_add(z2_tmp_fec87_28[3], wg_v1990);
    let wg_v1992 = eval.m31_mul(x_sum_tmp_fec87_29[5], y_sum_tmp_fec87_30[6]);
    let wg_v1993 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[5]);
    let wg_v1994 = eval.m31_add(wg_v1992, wg_v1993);
    let wg_v1995 = eval.m31_sub(wg_v1994, z0_tmp_fec87_27[11]);
    let wg_v1996 = eval.m31_sub(wg_v1995, z2_tmp_fec87_28[11]);
    let wg_v1997 = eval.m31_add(z2_tmp_fec87_28[4], wg_v1996);
    let wg_v1998 = eval.m31_mul(x_sum_tmp_fec87_29[6], y_sum_tmp_fec87_30[6]);
    let wg_v1999 = eval.m31_sub(wg_v1998, z0_tmp_fec87_27[12]);
    let wg_v2000 = eval.m31_sub(wg_v1999, z2_tmp_fec87_28[12]);
    let wg_v2001 = eval.m31_add(z2_tmp_fec87_28[5], wg_v2000);
    let single_karatsuba_n_7_output_tmp_fec87_31 = [
        z0_tmp_fec87_27[0],
        z0_tmp_fec87_27[1],
        z0_tmp_fec87_27[2],
        z0_tmp_fec87_27[3],
        z0_tmp_fec87_27[4],
        z0_tmp_fec87_27[5],
        z0_tmp_fec87_27[6],
        wg_v1882,
        wg_v1888,
        wg_v1896,
        wg_v1906,
        wg_v1918,
        wg_v1932,
        wg_v1947,
        wg_v1961,
        wg_v1973,
        wg_v1983,
        wg_v1991,
        wg_v1997,
        wg_v2001,
        z2_tmp_fec87_28[6],
        z2_tmp_fec87_28[7],
        z2_tmp_fec87_28[8],
        z2_tmp_fec87_28[9],
        z2_tmp_fec87_28[10],
        z2_tmp_fec87_28[11],
        z2_tmp_fec87_28[12],
    ];
    let wg_v2002 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2003 = eval.m31_mul(wg_v2002, mul_res_limb_14_col42);
    let wg_v2004 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2005 = eval.m31_mul(wg_v2004, mul_res_limb_15_col43);
    let wg_v2006 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_14_col42);
    let wg_v2007 = eval.m31_add(wg_v2005, wg_v2006);
    let wg_v2008 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2009 = eval.m31_mul(wg_v2008, mul_res_limb_16_col44);
    let wg_v2010 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_15_col43);
    let wg_v2011 = eval.m31_add(wg_v2009, wg_v2010);
    let wg_v2012 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_14_col42);
    let wg_v2013 = eval.m31_add(wg_v2011, wg_v2012);
    let wg_v2014 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2015 = eval.m31_mul(wg_v2014, mul_res_limb_17_col45);
    let wg_v2016 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_16_col44);
    let wg_v2017 = eval.m31_add(wg_v2015, wg_v2016);
    let wg_v2018 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_15_col43);
    let wg_v2019 = eval.m31_add(wg_v2017, wg_v2018);
    let wg_v2020 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2021 = eval.m31_mul(wg_v2020, mul_res_limb_14_col42);
    let wg_v2022 = eval.m31_add(wg_v2019, wg_v2021);
    let wg_v2023 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2024 = eval.m31_mul(wg_v2023, mul_res_limb_18_col46);
    let wg_v2025 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_17_col45);
    let wg_v2026 = eval.m31_add(wg_v2024, wg_v2025);
    let wg_v2027 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_16_col44);
    let wg_v2028 = eval.m31_add(wg_v2026, wg_v2027);
    let wg_v2029 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2030 = eval.m31_mul(wg_v2029, mul_res_limb_15_col43);
    let wg_v2031 = eval.m31_add(wg_v2028, wg_v2030);
    let wg_v2032 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_14_col42);
    let wg_v2033 = eval.m31_add(wg_v2031, wg_v2032);
    let wg_v2034 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2035 = eval.m31_mul(wg_v2034, mul_res_limb_19_col47);
    let wg_v2036 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_18_col46);
    let wg_v2037 = eval.m31_add(wg_v2035, wg_v2036);
    let wg_v2038 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_17_col45);
    let wg_v2039 = eval.m31_add(wg_v2037, wg_v2038);
    let wg_v2040 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2041 = eval.m31_mul(wg_v2040, mul_res_limb_16_col44);
    let wg_v2042 = eval.m31_add(wg_v2039, wg_v2041);
    let wg_v2043 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_15_col43);
    let wg_v2044 = eval.m31_add(wg_v2042, wg_v2043);
    let wg_v2045 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_14_col42);
    let wg_v2046 = eval.m31_add(wg_v2044, wg_v2045);
    let wg_v2047 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2048 = eval.m31_mul(wg_v2047, mul_res_limb_20_col48);
    let wg_v2049 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_19_col47);
    let wg_v2050 = eval.m31_add(wg_v2048, wg_v2049);
    let wg_v2051 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_18_col46);
    let wg_v2052 = eval.m31_add(wg_v2050, wg_v2051);
    let wg_v2053 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2054 = eval.m31_mul(wg_v2053, mul_res_limb_17_col45);
    let wg_v2055 = eval.m31_add(wg_v2052, wg_v2054);
    let wg_v2056 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_16_col44);
    let wg_v2057 = eval.m31_add(wg_v2055, wg_v2056);
    let wg_v2058 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_15_col43);
    let wg_v2059 = eval.m31_add(wg_v2057, wg_v2058);
    let wg_v2060 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2061 = eval.m31_mul(wg_v2060, mul_res_limb_14_col42);
    let wg_v2062 = eval.m31_add(wg_v2059, wg_v2061);
    let wg_v2063 = eval.m31_mul(unpacked_limb_15_col20, mul_res_limb_20_col48);
    let wg_v2064 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_19_col47);
    let wg_v2065 = eval.m31_add(wg_v2063, wg_v2064);
    let wg_v2066 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2067 = eval.m31_mul(wg_v2066, mul_res_limb_18_col46);
    let wg_v2068 = eval.m31_add(wg_v2065, wg_v2067);
    let wg_v2069 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_17_col45);
    let wg_v2070 = eval.m31_add(wg_v2068, wg_v2069);
    let wg_v2071 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_16_col44);
    let wg_v2072 = eval.m31_add(wg_v2070, wg_v2071);
    let wg_v2073 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2074 = eval.m31_mul(wg_v2073, mul_res_limb_15_col43);
    let wg_v2075 = eval.m31_add(wg_v2072, wg_v2074);
    let wg_v2076 = eval.m31_mul(unpacked_limb_16_col21, mul_res_limb_20_col48);
    let wg_v2077 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2078 = eval.m31_mul(wg_v2077, mul_res_limb_19_col47);
    let wg_v2079 = eval.m31_add(wg_v2076, wg_v2078);
    let wg_v2080 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_18_col46);
    let wg_v2081 = eval.m31_add(wg_v2079, wg_v2080);
    let wg_v2082 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_17_col45);
    let wg_v2083 = eval.m31_add(wg_v2081, wg_v2082);
    let wg_v2084 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2085 = eval.m31_mul(wg_v2084, mul_res_limb_16_col44);
    let wg_v2086 = eval.m31_add(wg_v2083, wg_v2085);
    let wg_v2087 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2088 = eval.m31_mul(wg_v2087, mul_res_limb_20_col48);
    let wg_v2089 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_19_col47);
    let wg_v2090 = eval.m31_add(wg_v2088, wg_v2089);
    let wg_v2091 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_18_col46);
    let wg_v2092 = eval.m31_add(wg_v2090, wg_v2091);
    let wg_v2093 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2094 = eval.m31_mul(wg_v2093, mul_res_limb_17_col45);
    let wg_v2095 = eval.m31_add(wg_v2092, wg_v2094);
    let wg_v2096 = eval.m31_mul(unpacked_limb_18_col22, mul_res_limb_20_col48);
    let wg_v2097 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_19_col47);
    let wg_v2098 = eval.m31_add(wg_v2096, wg_v2097);
    let wg_v2099 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2100 = eval.m31_mul(wg_v2099, mul_res_limb_18_col46);
    let wg_v2101 = eval.m31_add(wg_v2098, wg_v2100);
    let wg_v2102 = eval.m31_mul(unpacked_limb_19_col23, mul_res_limb_20_col48);
    let wg_v2103 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2104 = eval.m31_mul(wg_v2103, mul_res_limb_19_col47);
    let wg_v2105 = eval.m31_add(wg_v2102, wg_v2104);
    let wg_v2106 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2107 = eval.m31_mul(wg_v2106, mul_res_limb_20_col48);
    let z0_tmp_fec87_32 = [
        wg_v2003, wg_v2007, wg_v2013, wg_v2022, wg_v2033, wg_v2046, wg_v2062, wg_v2075, wg_v2086,
        wg_v2095, wg_v2101, wg_v2105, wg_v2107,
    ];
    let wg_v2108 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_21_col49);
    let wg_v2109 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_22_col50);
    let wg_v2110 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_21_col49);
    let wg_v2111 = eval.m31_add(wg_v2109, wg_v2110);
    let wg_v2112 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_23_col51);
    let wg_v2113 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_22_col50);
    let wg_v2114 = eval.m31_add(wg_v2112, wg_v2113);
    let wg_v2115 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2116 = eval.m31_mul(wg_v2115, mul_res_limb_21_col49);
    let wg_v2117 = eval.m31_add(wg_v2114, wg_v2116);
    let wg_v2118 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_24_col52);
    let wg_v2119 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_23_col51);
    let wg_v2120 = eval.m31_add(wg_v2118, wg_v2119);
    let wg_v2121 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2122 = eval.m31_mul(wg_v2121, mul_res_limb_22_col50);
    let wg_v2123 = eval.m31_add(wg_v2120, wg_v2122);
    let wg_v2124 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_21_col49);
    let wg_v2125 = eval.m31_add(wg_v2123, wg_v2124);
    let wg_v2126 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_25_col53);
    let wg_v2127 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_24_col52);
    let wg_v2128 = eval.m31_add(wg_v2126, wg_v2127);
    let wg_v2129 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2130 = eval.m31_mul(wg_v2129, mul_res_limb_23_col51);
    let wg_v2131 = eval.m31_add(wg_v2128, wg_v2130);
    let wg_v2132 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_22_col50);
    let wg_v2133 = eval.m31_add(wg_v2131, wg_v2132);
    let wg_v2134 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_21_col49);
    let wg_v2135 = eval.m31_add(wg_v2133, wg_v2134);
    let wg_v2136 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_26_col54);
    let wg_v2137 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_25_col53);
    let wg_v2138 = eval.m31_add(wg_v2136, wg_v2137);
    let wg_v2139 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2140 = eval.m31_mul(wg_v2139, mul_res_limb_24_col52);
    let wg_v2141 = eval.m31_add(wg_v2138, wg_v2140);
    let wg_v2142 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_23_col51);
    let wg_v2143 = eval.m31_add(wg_v2141, wg_v2142);
    let wg_v2144 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_22_col50);
    let wg_v2145 = eval.m31_add(wg_v2143, wg_v2144);
    let wg_v2146 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2147 = eval.m31_mul(wg_v2146, mul_res_limb_21_col49);
    let wg_v2148 = eval.m31_add(wg_v2145, wg_v2147);
    let wg_v2149 = eval.m31_mul(unpacked_limb_21_col24, mul_res_limb_27_col55);
    let wg_v2150 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_26_col54);
    let wg_v2151 = eval.m31_add(wg_v2149, wg_v2150);
    let wg_v2152 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2153 = eval.m31_mul(wg_v2152, mul_res_limb_25_col53);
    let wg_v2154 = eval.m31_add(wg_v2151, wg_v2153);
    let wg_v2155 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_24_col52);
    let wg_v2156 = eval.m31_add(wg_v2154, wg_v2155);
    let wg_v2157 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_23_col51);
    let wg_v2158 = eval.m31_add(wg_v2156, wg_v2157);
    let wg_v2159 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2160 = eval.m31_mul(wg_v2159, mul_res_limb_22_col50);
    let wg_v2161 = eval.m31_add(wg_v2158, wg_v2160);
    let wg_v2162 = eval.m31_mul(input_limb_9_col9, mul_res_limb_21_col49);
    let wg_v2163 = eval.m31_add(wg_v2161, wg_v2162);
    let wg_v2164 = eval.m31_mul(unpacked_limb_22_col25, mul_res_limb_27_col55);
    let wg_v2165 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2166 = eval.m31_mul(wg_v2165, mul_res_limb_26_col54);
    let wg_v2167 = eval.m31_add(wg_v2164, wg_v2166);
    let wg_v2168 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_25_col53);
    let wg_v2169 = eval.m31_add(wg_v2167, wg_v2168);
    let wg_v2170 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_24_col52);
    let wg_v2171 = eval.m31_add(wg_v2169, wg_v2170);
    let wg_v2172 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2173 = eval.m31_mul(wg_v2172, mul_res_limb_23_col51);
    let wg_v2174 = eval.m31_add(wg_v2171, wg_v2173);
    let wg_v2175 = eval.m31_mul(input_limb_9_col9, mul_res_limb_22_col50);
    let wg_v2176 = eval.m31_add(wg_v2174, wg_v2175);
    let wg_v2177 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2178 = eval.m31_mul(wg_v2177, mul_res_limb_27_col55);
    let wg_v2179 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_26_col54);
    let wg_v2180 = eval.m31_add(wg_v2178, wg_v2179);
    let wg_v2181 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_25_col53);
    let wg_v2182 = eval.m31_add(wg_v2180, wg_v2181);
    let wg_v2183 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2184 = eval.m31_mul(wg_v2183, mul_res_limb_24_col52);
    let wg_v2185 = eval.m31_add(wg_v2182, wg_v2184);
    let wg_v2186 = eval.m31_mul(input_limb_9_col9, mul_res_limb_23_col51);
    let wg_v2187 = eval.m31_add(wg_v2185, wg_v2186);
    let wg_v2188 = eval.m31_mul(unpacked_limb_24_col26, mul_res_limb_27_col55);
    let wg_v2189 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_26_col54);
    let wg_v2190 = eval.m31_add(wg_v2188, wg_v2189);
    let wg_v2191 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2192 = eval.m31_mul(wg_v2191, mul_res_limb_25_col53);
    let wg_v2193 = eval.m31_add(wg_v2190, wg_v2192);
    let wg_v2194 = eval.m31_mul(input_limb_9_col9, mul_res_limb_24_col52);
    let wg_v2195 = eval.m31_add(wg_v2193, wg_v2194);
    let wg_v2196 = eval.m31_mul(unpacked_limb_25_col27, mul_res_limb_27_col55);
    let wg_v2197 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2198 = eval.m31_mul(wg_v2197, mul_res_limb_26_col54);
    let wg_v2199 = eval.m31_add(wg_v2196, wg_v2198);
    let wg_v2200 = eval.m31_mul(input_limb_9_col9, mul_res_limb_25_col53);
    let wg_v2201 = eval.m31_add(wg_v2199, wg_v2200);
    let wg_v2202 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2203 = eval.m31_mul(wg_v2202, mul_res_limb_27_col55);
    let wg_v2204 = eval.m31_mul(input_limb_9_col9, mul_res_limb_26_col54);
    let wg_v2205 = eval.m31_add(wg_v2203, wg_v2204);
    let wg_v2206 = eval.m31_mul(input_limb_9_col9, mul_res_limb_27_col55);
    let z2_tmp_fec87_33 = [
        wg_v2108, wg_v2111, wg_v2117, wg_v2125, wg_v2135, wg_v2148, wg_v2163, wg_v2176, wg_v2187,
        wg_v2195, wg_v2201, wg_v2205, wg_v2206,
    ];
    let wg_v2207 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2208 = eval.m31_add(wg_v2207, unpacked_limb_21_col24);
    let wg_v2209 = eval.m31_add(unpacked_limb_15_col20, unpacked_limb_22_col25);
    let wg_v2210 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2211 = eval.m31_add(unpacked_limb_16_col21, wg_v2210);
    let wg_v2212 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2213 = eval.m31_add(wg_v2212, unpacked_limb_24_col26);
    let wg_v2214 = eval.m31_add(unpacked_limb_18_col22, unpacked_limb_25_col27);
    let wg_v2215 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2216 = eval.m31_add(unpacked_limb_19_col23, wg_v2215);
    let wg_v2217 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2218 = eval.m31_add(wg_v2217, input_limb_9_col9);
    let x_sum_tmp_fec87_34 = [
        wg_v2208, wg_v2209, wg_v2211, wg_v2213, wg_v2214, wg_v2216, wg_v2218,
    ];
    let wg_v2219 = eval.m31_add(mul_res_limb_14_col42, mul_res_limb_21_col49);
    let wg_v2220 = eval.m31_add(mul_res_limb_15_col43, mul_res_limb_22_col50);
    let wg_v2221 = eval.m31_add(mul_res_limb_16_col44, mul_res_limb_23_col51);
    let wg_v2222 = eval.m31_add(mul_res_limb_17_col45, mul_res_limb_24_col52);
    let wg_v2223 = eval.m31_add(mul_res_limb_18_col46, mul_res_limb_25_col53);
    let wg_v2224 = eval.m31_add(mul_res_limb_19_col47, mul_res_limb_26_col54);
    let wg_v2225 = eval.m31_add(mul_res_limb_20_col48, mul_res_limb_27_col55);
    let y_sum_tmp_fec87_35 = [
        wg_v2219, wg_v2220, wg_v2221, wg_v2222, wg_v2223, wg_v2224, wg_v2225,
    ];
    let wg_v2226 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[0]);
    let wg_v2227 = eval.m31_sub(wg_v2226, z0_tmp_fec87_32[0]);
    let wg_v2228 = eval.m31_sub(wg_v2227, z2_tmp_fec87_33[0]);
    let wg_v2229 = eval.m31_add(z0_tmp_fec87_32[7], wg_v2228);
    let wg_v2230 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[1]);
    let wg_v2231 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[0]);
    let wg_v2232 = eval.m31_add(wg_v2230, wg_v2231);
    let wg_v2233 = eval.m31_sub(wg_v2232, z0_tmp_fec87_32[1]);
    let wg_v2234 = eval.m31_sub(wg_v2233, z2_tmp_fec87_33[1]);
    let wg_v2235 = eval.m31_add(z0_tmp_fec87_32[8], wg_v2234);
    let wg_v2236 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[2]);
    let wg_v2237 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[1]);
    let wg_v2238 = eval.m31_add(wg_v2236, wg_v2237);
    let wg_v2239 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[0]);
    let wg_v2240 = eval.m31_add(wg_v2238, wg_v2239);
    let wg_v2241 = eval.m31_sub(wg_v2240, z0_tmp_fec87_32[2]);
    let wg_v2242 = eval.m31_sub(wg_v2241, z2_tmp_fec87_33[2]);
    let wg_v2243 = eval.m31_add(z0_tmp_fec87_32[9], wg_v2242);
    let wg_v2244 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[3]);
    let wg_v2245 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[2]);
    let wg_v2246 = eval.m31_add(wg_v2244, wg_v2245);
    let wg_v2247 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[1]);
    let wg_v2248 = eval.m31_add(wg_v2246, wg_v2247);
    let wg_v2249 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[0]);
    let wg_v2250 = eval.m31_add(wg_v2248, wg_v2249);
    let wg_v2251 = eval.m31_sub(wg_v2250, z0_tmp_fec87_32[3]);
    let wg_v2252 = eval.m31_sub(wg_v2251, z2_tmp_fec87_33[3]);
    let wg_v2253 = eval.m31_add(z0_tmp_fec87_32[10], wg_v2252);
    let wg_v2254 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[4]);
    let wg_v2255 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[3]);
    let wg_v2256 = eval.m31_add(wg_v2254, wg_v2255);
    let wg_v2257 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[2]);
    let wg_v2258 = eval.m31_add(wg_v2256, wg_v2257);
    let wg_v2259 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[1]);
    let wg_v2260 = eval.m31_add(wg_v2258, wg_v2259);
    let wg_v2261 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[0]);
    let wg_v2262 = eval.m31_add(wg_v2260, wg_v2261);
    let wg_v2263 = eval.m31_sub(wg_v2262, z0_tmp_fec87_32[4]);
    let wg_v2264 = eval.m31_sub(wg_v2263, z2_tmp_fec87_33[4]);
    let wg_v2265 = eval.m31_add(z0_tmp_fec87_32[11], wg_v2264);
    let wg_v2266 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[5]);
    let wg_v2267 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[4]);
    let wg_v2268 = eval.m31_add(wg_v2266, wg_v2267);
    let wg_v2269 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[3]);
    let wg_v2270 = eval.m31_add(wg_v2268, wg_v2269);
    let wg_v2271 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[2]);
    let wg_v2272 = eval.m31_add(wg_v2270, wg_v2271);
    let wg_v2273 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[1]);
    let wg_v2274 = eval.m31_add(wg_v2272, wg_v2273);
    let wg_v2275 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[0]);
    let wg_v2276 = eval.m31_add(wg_v2274, wg_v2275);
    let wg_v2277 = eval.m31_sub(wg_v2276, z0_tmp_fec87_32[5]);
    let wg_v2278 = eval.m31_sub(wg_v2277, z2_tmp_fec87_33[5]);
    let wg_v2279 = eval.m31_add(z0_tmp_fec87_32[12], wg_v2278);
    let wg_v2280 = eval.m31_mul(x_sum_tmp_fec87_34[0], y_sum_tmp_fec87_35[6]);
    let wg_v2281 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[5]);
    let wg_v2282 = eval.m31_add(wg_v2280, wg_v2281);
    let wg_v2283 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[4]);
    let wg_v2284 = eval.m31_add(wg_v2282, wg_v2283);
    let wg_v2285 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[3]);
    let wg_v2286 = eval.m31_add(wg_v2284, wg_v2285);
    let wg_v2287 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[2]);
    let wg_v2288 = eval.m31_add(wg_v2286, wg_v2287);
    let wg_v2289 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[1]);
    let wg_v2290 = eval.m31_add(wg_v2288, wg_v2289);
    let wg_v2291 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[0]);
    let wg_v2292 = eval.m31_add(wg_v2290, wg_v2291);
    let wg_v2293 = eval.m31_sub(wg_v2292, z0_tmp_fec87_32[6]);
    let wg_v2294 = eval.m31_sub(wg_v2293, z2_tmp_fec87_33[6]);
    let wg_v2295 = eval.m31_mul(x_sum_tmp_fec87_34[1], y_sum_tmp_fec87_35[6]);
    let wg_v2296 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[5]);
    let wg_v2297 = eval.m31_add(wg_v2295, wg_v2296);
    let wg_v2298 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[4]);
    let wg_v2299 = eval.m31_add(wg_v2297, wg_v2298);
    let wg_v2300 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[3]);
    let wg_v2301 = eval.m31_add(wg_v2299, wg_v2300);
    let wg_v2302 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[2]);
    let wg_v2303 = eval.m31_add(wg_v2301, wg_v2302);
    let wg_v2304 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[1]);
    let wg_v2305 = eval.m31_add(wg_v2303, wg_v2304);
    let wg_v2306 = eval.m31_sub(wg_v2305, z0_tmp_fec87_32[7]);
    let wg_v2307 = eval.m31_sub(wg_v2306, z2_tmp_fec87_33[7]);
    let wg_v2308 = eval.m31_add(z2_tmp_fec87_33[0], wg_v2307);
    let wg_v2309 = eval.m31_mul(x_sum_tmp_fec87_34[2], y_sum_tmp_fec87_35[6]);
    let wg_v2310 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[5]);
    let wg_v2311 = eval.m31_add(wg_v2309, wg_v2310);
    let wg_v2312 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[4]);
    let wg_v2313 = eval.m31_add(wg_v2311, wg_v2312);
    let wg_v2314 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[3]);
    let wg_v2315 = eval.m31_add(wg_v2313, wg_v2314);
    let wg_v2316 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[2]);
    let wg_v2317 = eval.m31_add(wg_v2315, wg_v2316);
    let wg_v2318 = eval.m31_sub(wg_v2317, z0_tmp_fec87_32[8]);
    let wg_v2319 = eval.m31_sub(wg_v2318, z2_tmp_fec87_33[8]);
    let wg_v2320 = eval.m31_add(z2_tmp_fec87_33[1], wg_v2319);
    let wg_v2321 = eval.m31_mul(x_sum_tmp_fec87_34[3], y_sum_tmp_fec87_35[6]);
    let wg_v2322 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[5]);
    let wg_v2323 = eval.m31_add(wg_v2321, wg_v2322);
    let wg_v2324 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[4]);
    let wg_v2325 = eval.m31_add(wg_v2323, wg_v2324);
    let wg_v2326 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[3]);
    let wg_v2327 = eval.m31_add(wg_v2325, wg_v2326);
    let wg_v2328 = eval.m31_sub(wg_v2327, z0_tmp_fec87_32[9]);
    let wg_v2329 = eval.m31_sub(wg_v2328, z2_tmp_fec87_33[9]);
    let wg_v2330 = eval.m31_add(z2_tmp_fec87_33[2], wg_v2329);
    let wg_v2331 = eval.m31_mul(x_sum_tmp_fec87_34[4], y_sum_tmp_fec87_35[6]);
    let wg_v2332 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[5]);
    let wg_v2333 = eval.m31_add(wg_v2331, wg_v2332);
    let wg_v2334 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[4]);
    let wg_v2335 = eval.m31_add(wg_v2333, wg_v2334);
    let wg_v2336 = eval.m31_sub(wg_v2335, z0_tmp_fec87_32[10]);
    let wg_v2337 = eval.m31_sub(wg_v2336, z2_tmp_fec87_33[10]);
    let wg_v2338 = eval.m31_add(z2_tmp_fec87_33[3], wg_v2337);
    let wg_v2339 = eval.m31_mul(x_sum_tmp_fec87_34[5], y_sum_tmp_fec87_35[6]);
    let wg_v2340 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[5]);
    let wg_v2341 = eval.m31_add(wg_v2339, wg_v2340);
    let wg_v2342 = eval.m31_sub(wg_v2341, z0_tmp_fec87_32[11]);
    let wg_v2343 = eval.m31_sub(wg_v2342, z2_tmp_fec87_33[11]);
    let wg_v2344 = eval.m31_add(z2_tmp_fec87_33[4], wg_v2343);
    let wg_v2345 = eval.m31_mul(x_sum_tmp_fec87_34[6], y_sum_tmp_fec87_35[6]);
    let wg_v2346 = eval.m31_sub(wg_v2345, z0_tmp_fec87_32[12]);
    let wg_v2347 = eval.m31_sub(wg_v2346, z2_tmp_fec87_33[12]);
    let wg_v2348 = eval.m31_add(z2_tmp_fec87_33[5], wg_v2347);
    let single_karatsuba_n_7_output_tmp_fec87_36 = [
        z0_tmp_fec87_32[0],
        z0_tmp_fec87_32[1],
        z0_tmp_fec87_32[2],
        z0_tmp_fec87_32[3],
        z0_tmp_fec87_32[4],
        z0_tmp_fec87_32[5],
        z0_tmp_fec87_32[6],
        wg_v2229,
        wg_v2235,
        wg_v2243,
        wg_v2253,
        wg_v2265,
        wg_v2279,
        wg_v2294,
        wg_v2308,
        wg_v2320,
        wg_v2330,
        wg_v2338,
        wg_v2344,
        wg_v2348,
        z2_tmp_fec87_33[6],
        z2_tmp_fec87_33[7],
        z2_tmp_fec87_33[8],
        z2_tmp_fec87_33[9],
        z2_tmp_fec87_33[10],
        z2_tmp_fec87_33[11],
        z2_tmp_fec87_33[12],
    ];
    let wg_v2349 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 14);
    let wg_v2350 = eval.m31_add(unpacked_limb_0_col10, wg_v2349);
    let wg_v2351 = eval.m31_add(unpacked_limb_1_col11, unpacked_limb_15_col20);
    let wg_v2352 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 2);
    let wg_v2353 = eval.m31_add(wg_v2352, unpacked_limb_16_col21);
    let wg_v2354 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 17);
    let wg_v2355 = eval.m31_add(unpacked_limb_3_col12, wg_v2354);
    let wg_v2356 = eval.m31_add(unpacked_limb_4_col13, unpacked_limb_18_col22);
    let wg_v2357 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 5);
    let wg_v2358 = eval.m31_add(wg_v2357, unpacked_limb_19_col23);
    let wg_v2359 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 20);
    let wg_v2360 = eval.m31_add(unpacked_limb_6_col14, wg_v2359);
    let wg_v2361 = eval.m31_add(unpacked_limb_7_col15, unpacked_limb_21_col24);
    let wg_v2362 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 8);
    let wg_v2363 = eval.m31_add(wg_v2362, unpacked_limb_22_col25);
    let wg_v2364 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 23);
    let wg_v2365 = eval.m31_add(unpacked_limb_9_col16, wg_v2364);
    let wg_v2366 = eval.m31_add(unpacked_limb_10_col17, unpacked_limb_24_col26);
    let wg_v2367 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 11);
    let wg_v2368 = eval.m31_add(wg_v2367, unpacked_limb_25_col27);
    let wg_v2369 = eval.felt_get_m31(&unpacked_tmp_fec87_1.clone(), 26);
    let wg_v2370 = eval.m31_add(unpacked_limb_12_col18, wg_v2369);
    let wg_v2371 = eval.m31_add(unpacked_limb_13_col19, input_limb_9_col9);
    let x_sum_tmp_fec87_37 = [
        wg_v2350, wg_v2351, wg_v2353, wg_v2355, wg_v2356, wg_v2358, wg_v2360, wg_v2361, wg_v2363,
        wg_v2365, wg_v2366, wg_v2368, wg_v2370, wg_v2371,
    ];
    let wg_v2372 = eval.m31_add(mul_res_limb_0_col28, mul_res_limb_14_col42);
    let wg_v2373 = eval.m31_add(mul_res_limb_1_col29, mul_res_limb_15_col43);
    let wg_v2374 = eval.m31_add(mul_res_limb_2_col30, mul_res_limb_16_col44);
    let wg_v2375 = eval.m31_add(mul_res_limb_3_col31, mul_res_limb_17_col45);
    let wg_v2376 = eval.m31_add(mul_res_limb_4_col32, mul_res_limb_18_col46);
    let wg_v2377 = eval.m31_add(mul_res_limb_5_col33, mul_res_limb_19_col47);
    let wg_v2378 = eval.m31_add(mul_res_limb_6_col34, mul_res_limb_20_col48);
    let wg_v2379 = eval.m31_add(mul_res_limb_7_col35, mul_res_limb_21_col49);
    let wg_v2380 = eval.m31_add(mul_res_limb_8_col36, mul_res_limb_22_col50);
    let wg_v2381 = eval.m31_add(mul_res_limb_9_col37, mul_res_limb_23_col51);
    let wg_v2382 = eval.m31_add(mul_res_limb_10_col38, mul_res_limb_24_col52);
    let wg_v2383 = eval.m31_add(mul_res_limb_11_col39, mul_res_limb_25_col53);
    let wg_v2384 = eval.m31_add(mul_res_limb_12_col40, mul_res_limb_26_col54);
    let wg_v2385 = eval.m31_add(mul_res_limb_13_col41, mul_res_limb_27_col55);
    let y_sum_tmp_fec87_38 = [
        wg_v2372, wg_v2373, wg_v2374, wg_v2375, wg_v2376, wg_v2377, wg_v2378, wg_v2379, wg_v2380,
        wg_v2381, wg_v2382, wg_v2383, wg_v2384, wg_v2385,
    ];
    let wg_v2386 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[0]);
    let wg_v2387 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[1]);
    let wg_v2388 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[0]);
    let wg_v2389 = eval.m31_add(wg_v2387, wg_v2388);
    let wg_v2390 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[2]);
    let wg_v2391 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[1]);
    let wg_v2392 = eval.m31_add(wg_v2390, wg_v2391);
    let wg_v2393 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[0]);
    let wg_v2394 = eval.m31_add(wg_v2392, wg_v2393);
    let wg_v2395 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[3]);
    let wg_v2396 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[2]);
    let wg_v2397 = eval.m31_add(wg_v2395, wg_v2396);
    let wg_v2398 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[1]);
    let wg_v2399 = eval.m31_add(wg_v2397, wg_v2398);
    let wg_v2400 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[0]);
    let wg_v2401 = eval.m31_add(wg_v2399, wg_v2400);
    let wg_v2402 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[4]);
    let wg_v2403 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[3]);
    let wg_v2404 = eval.m31_add(wg_v2402, wg_v2403);
    let wg_v2405 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[2]);
    let wg_v2406 = eval.m31_add(wg_v2404, wg_v2405);
    let wg_v2407 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[1]);
    let wg_v2408 = eval.m31_add(wg_v2406, wg_v2407);
    let wg_v2409 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[0]);
    let wg_v2410 = eval.m31_add(wg_v2408, wg_v2409);
    let wg_v2411 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[5]);
    let wg_v2412 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[4]);
    let wg_v2413 = eval.m31_add(wg_v2411, wg_v2412);
    let wg_v2414 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[3]);
    let wg_v2415 = eval.m31_add(wg_v2413, wg_v2414);
    let wg_v2416 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[2]);
    let wg_v2417 = eval.m31_add(wg_v2415, wg_v2416);
    let wg_v2418 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[1]);
    let wg_v2419 = eval.m31_add(wg_v2417, wg_v2418);
    let wg_v2420 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[0]);
    let wg_v2421 = eval.m31_add(wg_v2419, wg_v2420);
    let wg_v2422 = eval.m31_mul(x_sum_tmp_fec87_37[0], y_sum_tmp_fec87_38[6]);
    let wg_v2423 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[5]);
    let wg_v2424 = eval.m31_add(wg_v2422, wg_v2423);
    let wg_v2425 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[4]);
    let wg_v2426 = eval.m31_add(wg_v2424, wg_v2425);
    let wg_v2427 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[3]);
    let wg_v2428 = eval.m31_add(wg_v2426, wg_v2427);
    let wg_v2429 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[2]);
    let wg_v2430 = eval.m31_add(wg_v2428, wg_v2429);
    let wg_v2431 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[1]);
    let wg_v2432 = eval.m31_add(wg_v2430, wg_v2431);
    let wg_v2433 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[0]);
    let wg_v2434 = eval.m31_add(wg_v2432, wg_v2433);
    let wg_v2435 = eval.m31_mul(x_sum_tmp_fec87_37[1], y_sum_tmp_fec87_38[6]);
    let wg_v2436 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[5]);
    let wg_v2437 = eval.m31_add(wg_v2435, wg_v2436);
    let wg_v2438 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[4]);
    let wg_v2439 = eval.m31_add(wg_v2437, wg_v2438);
    let wg_v2440 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[3]);
    let wg_v2441 = eval.m31_add(wg_v2439, wg_v2440);
    let wg_v2442 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[2]);
    let wg_v2443 = eval.m31_add(wg_v2441, wg_v2442);
    let wg_v2444 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[1]);
    let wg_v2445 = eval.m31_add(wg_v2443, wg_v2444);
    let wg_v2446 = eval.m31_mul(x_sum_tmp_fec87_37[2], y_sum_tmp_fec87_38[6]);
    let wg_v2447 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[5]);
    let wg_v2448 = eval.m31_add(wg_v2446, wg_v2447);
    let wg_v2449 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[4]);
    let wg_v2450 = eval.m31_add(wg_v2448, wg_v2449);
    let wg_v2451 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[3]);
    let wg_v2452 = eval.m31_add(wg_v2450, wg_v2451);
    let wg_v2453 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[2]);
    let wg_v2454 = eval.m31_add(wg_v2452, wg_v2453);
    let wg_v2455 = eval.m31_mul(x_sum_tmp_fec87_37[3], y_sum_tmp_fec87_38[6]);
    let wg_v2456 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[5]);
    let wg_v2457 = eval.m31_add(wg_v2455, wg_v2456);
    let wg_v2458 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[4]);
    let wg_v2459 = eval.m31_add(wg_v2457, wg_v2458);
    let wg_v2460 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[3]);
    let wg_v2461 = eval.m31_add(wg_v2459, wg_v2460);
    let wg_v2462 = eval.m31_mul(x_sum_tmp_fec87_37[4], y_sum_tmp_fec87_38[6]);
    let wg_v2463 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[5]);
    let wg_v2464 = eval.m31_add(wg_v2462, wg_v2463);
    let wg_v2465 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[4]);
    let wg_v2466 = eval.m31_add(wg_v2464, wg_v2465);
    let wg_v2467 = eval.m31_mul(x_sum_tmp_fec87_37[5], y_sum_tmp_fec87_38[6]);
    let wg_v2468 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[5]);
    let wg_v2469 = eval.m31_add(wg_v2467, wg_v2468);
    let wg_v2470 = eval.m31_mul(x_sum_tmp_fec87_37[6], y_sum_tmp_fec87_38[6]);
    let z0_tmp_fec87_39 = [
        wg_v2386, wg_v2389, wg_v2394, wg_v2401, wg_v2410, wg_v2421, wg_v2434, wg_v2445, wg_v2454,
        wg_v2461, wg_v2466, wg_v2469, wg_v2470,
    ];
    let wg_v2471 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[7]);
    let wg_v2472 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[8]);
    let wg_v2473 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[7]);
    let wg_v2474 = eval.m31_add(wg_v2472, wg_v2473);
    let wg_v2475 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[9]);
    let wg_v2476 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[8]);
    let wg_v2477 = eval.m31_add(wg_v2475, wg_v2476);
    let wg_v2478 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[7]);
    let wg_v2479 = eval.m31_add(wg_v2477, wg_v2478);
    let wg_v2480 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[10]);
    let wg_v2481 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[9]);
    let wg_v2482 = eval.m31_add(wg_v2480, wg_v2481);
    let wg_v2483 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[8]);
    let wg_v2484 = eval.m31_add(wg_v2482, wg_v2483);
    let wg_v2485 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[7]);
    let wg_v2486 = eval.m31_add(wg_v2484, wg_v2485);
    let wg_v2487 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[11]);
    let wg_v2488 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[10]);
    let wg_v2489 = eval.m31_add(wg_v2487, wg_v2488);
    let wg_v2490 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[9]);
    let wg_v2491 = eval.m31_add(wg_v2489, wg_v2490);
    let wg_v2492 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[8]);
    let wg_v2493 = eval.m31_add(wg_v2491, wg_v2492);
    let wg_v2494 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[7]);
    let wg_v2495 = eval.m31_add(wg_v2493, wg_v2494);
    let wg_v2496 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[12]);
    let wg_v2497 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[11]);
    let wg_v2498 = eval.m31_add(wg_v2496, wg_v2497);
    let wg_v2499 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[10]);
    let wg_v2500 = eval.m31_add(wg_v2498, wg_v2499);
    let wg_v2501 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[9]);
    let wg_v2502 = eval.m31_add(wg_v2500, wg_v2501);
    let wg_v2503 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[8]);
    let wg_v2504 = eval.m31_add(wg_v2502, wg_v2503);
    let wg_v2505 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[7]);
    let wg_v2506 = eval.m31_add(wg_v2504, wg_v2505);
    let wg_v2507 = eval.m31_mul(x_sum_tmp_fec87_37[7], y_sum_tmp_fec87_38[13]);
    let wg_v2508 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[12]);
    let wg_v2509 = eval.m31_add(wg_v2507, wg_v2508);
    let wg_v2510 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[11]);
    let wg_v2511 = eval.m31_add(wg_v2509, wg_v2510);
    let wg_v2512 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[10]);
    let wg_v2513 = eval.m31_add(wg_v2511, wg_v2512);
    let wg_v2514 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[9]);
    let wg_v2515 = eval.m31_add(wg_v2513, wg_v2514);
    let wg_v2516 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[8]);
    let wg_v2517 = eval.m31_add(wg_v2515, wg_v2516);
    let wg_v2518 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[7]);
    let wg_v2519 = eval.m31_add(wg_v2517, wg_v2518);
    let wg_v2520 = eval.m31_mul(x_sum_tmp_fec87_37[8], y_sum_tmp_fec87_38[13]);
    let wg_v2521 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[12]);
    let wg_v2522 = eval.m31_add(wg_v2520, wg_v2521);
    let wg_v2523 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[11]);
    let wg_v2524 = eval.m31_add(wg_v2522, wg_v2523);
    let wg_v2525 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[10]);
    let wg_v2526 = eval.m31_add(wg_v2524, wg_v2525);
    let wg_v2527 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[9]);
    let wg_v2528 = eval.m31_add(wg_v2526, wg_v2527);
    let wg_v2529 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[8]);
    let wg_v2530 = eval.m31_add(wg_v2528, wg_v2529);
    let wg_v2531 = eval.m31_mul(x_sum_tmp_fec87_37[9], y_sum_tmp_fec87_38[13]);
    let wg_v2532 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[12]);
    let wg_v2533 = eval.m31_add(wg_v2531, wg_v2532);
    let wg_v2534 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[11]);
    let wg_v2535 = eval.m31_add(wg_v2533, wg_v2534);
    let wg_v2536 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[10]);
    let wg_v2537 = eval.m31_add(wg_v2535, wg_v2536);
    let wg_v2538 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[9]);
    let wg_v2539 = eval.m31_add(wg_v2537, wg_v2538);
    let wg_v2540 = eval.m31_mul(x_sum_tmp_fec87_37[10], y_sum_tmp_fec87_38[13]);
    let wg_v2541 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[12]);
    let wg_v2542 = eval.m31_add(wg_v2540, wg_v2541);
    let wg_v2543 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[11]);
    let wg_v2544 = eval.m31_add(wg_v2542, wg_v2543);
    let wg_v2545 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[10]);
    let wg_v2546 = eval.m31_add(wg_v2544, wg_v2545);
    let wg_v2547 = eval.m31_mul(x_sum_tmp_fec87_37[11], y_sum_tmp_fec87_38[13]);
    let wg_v2548 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[12]);
    let wg_v2549 = eval.m31_add(wg_v2547, wg_v2548);
    let wg_v2550 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[11]);
    let wg_v2551 = eval.m31_add(wg_v2549, wg_v2550);
    let wg_v2552 = eval.m31_mul(x_sum_tmp_fec87_37[12], y_sum_tmp_fec87_38[13]);
    let wg_v2553 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[12]);
    let wg_v2554 = eval.m31_add(wg_v2552, wg_v2553);
    let wg_v2555 = eval.m31_mul(x_sum_tmp_fec87_37[13], y_sum_tmp_fec87_38[13]);
    let z2_tmp_fec87_40 = [
        wg_v2471, wg_v2474, wg_v2479, wg_v2486, wg_v2495, wg_v2506, wg_v2519, wg_v2530, wg_v2539,
        wg_v2546, wg_v2551, wg_v2554, wg_v2555,
    ];
    let wg_v2556 = eval.m31_add(x_sum_tmp_fec87_37[0], x_sum_tmp_fec87_37[7]);
    let wg_v2557 = eval.m31_add(x_sum_tmp_fec87_37[1], x_sum_tmp_fec87_37[8]);
    let wg_v2558 = eval.m31_add(x_sum_tmp_fec87_37[2], x_sum_tmp_fec87_37[9]);
    let wg_v2559 = eval.m31_add(x_sum_tmp_fec87_37[3], x_sum_tmp_fec87_37[10]);
    let wg_v2560 = eval.m31_add(x_sum_tmp_fec87_37[4], x_sum_tmp_fec87_37[11]);
    let wg_v2561 = eval.m31_add(x_sum_tmp_fec87_37[5], x_sum_tmp_fec87_37[12]);
    let wg_v2562 = eval.m31_add(x_sum_tmp_fec87_37[6], x_sum_tmp_fec87_37[13]);
    let x_sum_tmp_fec87_41 = [
        wg_v2556, wg_v2557, wg_v2558, wg_v2559, wg_v2560, wg_v2561, wg_v2562,
    ];
    let wg_v2563 = eval.m31_add(y_sum_tmp_fec87_38[0], y_sum_tmp_fec87_38[7]);
    let wg_v2564 = eval.m31_add(y_sum_tmp_fec87_38[1], y_sum_tmp_fec87_38[8]);
    let wg_v2565 = eval.m31_add(y_sum_tmp_fec87_38[2], y_sum_tmp_fec87_38[9]);
    let wg_v2566 = eval.m31_add(y_sum_tmp_fec87_38[3], y_sum_tmp_fec87_38[10]);
    let wg_v2567 = eval.m31_add(y_sum_tmp_fec87_38[4], y_sum_tmp_fec87_38[11]);
    let wg_v2568 = eval.m31_add(y_sum_tmp_fec87_38[5], y_sum_tmp_fec87_38[12]);
    let wg_v2569 = eval.m31_add(y_sum_tmp_fec87_38[6], y_sum_tmp_fec87_38[13]);
    let y_sum_tmp_fec87_42 = [
        wg_v2563, wg_v2564, wg_v2565, wg_v2566, wg_v2567, wg_v2568, wg_v2569,
    ];
    let wg_v2570 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[0]);
    let wg_v2571 = eval.m31_sub(wg_v2570, z0_tmp_fec87_39[0]);
    let wg_v2572 = eval.m31_sub(wg_v2571, z2_tmp_fec87_40[0]);
    let wg_v2573 = eval.m31_add(z0_tmp_fec87_39[7], wg_v2572);
    let wg_v2574 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[1]);
    let wg_v2575 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[0]);
    let wg_v2576 = eval.m31_add(wg_v2574, wg_v2575);
    let wg_v2577 = eval.m31_sub(wg_v2576, z0_tmp_fec87_39[1]);
    let wg_v2578 = eval.m31_sub(wg_v2577, z2_tmp_fec87_40[1]);
    let wg_v2579 = eval.m31_add(z0_tmp_fec87_39[8], wg_v2578);
    let wg_v2580 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[2]);
    let wg_v2581 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[1]);
    let wg_v2582 = eval.m31_add(wg_v2580, wg_v2581);
    let wg_v2583 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[0]);
    let wg_v2584 = eval.m31_add(wg_v2582, wg_v2583);
    let wg_v2585 = eval.m31_sub(wg_v2584, z0_tmp_fec87_39[2]);
    let wg_v2586 = eval.m31_sub(wg_v2585, z2_tmp_fec87_40[2]);
    let wg_v2587 = eval.m31_add(z0_tmp_fec87_39[9], wg_v2586);
    let wg_v2588 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[3]);
    let wg_v2589 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[2]);
    let wg_v2590 = eval.m31_add(wg_v2588, wg_v2589);
    let wg_v2591 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[1]);
    let wg_v2592 = eval.m31_add(wg_v2590, wg_v2591);
    let wg_v2593 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[0]);
    let wg_v2594 = eval.m31_add(wg_v2592, wg_v2593);
    let wg_v2595 = eval.m31_sub(wg_v2594, z0_tmp_fec87_39[3]);
    let wg_v2596 = eval.m31_sub(wg_v2595, z2_tmp_fec87_40[3]);
    let wg_v2597 = eval.m31_add(z0_tmp_fec87_39[10], wg_v2596);
    let wg_v2598 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[4]);
    let wg_v2599 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[3]);
    let wg_v2600 = eval.m31_add(wg_v2598, wg_v2599);
    let wg_v2601 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[2]);
    let wg_v2602 = eval.m31_add(wg_v2600, wg_v2601);
    let wg_v2603 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[1]);
    let wg_v2604 = eval.m31_add(wg_v2602, wg_v2603);
    let wg_v2605 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[0]);
    let wg_v2606 = eval.m31_add(wg_v2604, wg_v2605);
    let wg_v2607 = eval.m31_sub(wg_v2606, z0_tmp_fec87_39[4]);
    let wg_v2608 = eval.m31_sub(wg_v2607, z2_tmp_fec87_40[4]);
    let wg_v2609 = eval.m31_add(z0_tmp_fec87_39[11], wg_v2608);
    let wg_v2610 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[5]);
    let wg_v2611 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[4]);
    let wg_v2612 = eval.m31_add(wg_v2610, wg_v2611);
    let wg_v2613 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[3]);
    let wg_v2614 = eval.m31_add(wg_v2612, wg_v2613);
    let wg_v2615 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[2]);
    let wg_v2616 = eval.m31_add(wg_v2614, wg_v2615);
    let wg_v2617 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[1]);
    let wg_v2618 = eval.m31_add(wg_v2616, wg_v2617);
    let wg_v2619 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[0]);
    let wg_v2620 = eval.m31_add(wg_v2618, wg_v2619);
    let wg_v2621 = eval.m31_sub(wg_v2620, z0_tmp_fec87_39[5]);
    let wg_v2622 = eval.m31_sub(wg_v2621, z2_tmp_fec87_40[5]);
    let wg_v2623 = eval.m31_add(z0_tmp_fec87_39[12], wg_v2622);
    let wg_v2624 = eval.m31_mul(x_sum_tmp_fec87_41[0], y_sum_tmp_fec87_42[6]);
    let wg_v2625 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[5]);
    let wg_v2626 = eval.m31_add(wg_v2624, wg_v2625);
    let wg_v2627 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[4]);
    let wg_v2628 = eval.m31_add(wg_v2626, wg_v2627);
    let wg_v2629 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[3]);
    let wg_v2630 = eval.m31_add(wg_v2628, wg_v2629);
    let wg_v2631 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[2]);
    let wg_v2632 = eval.m31_add(wg_v2630, wg_v2631);
    let wg_v2633 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[1]);
    let wg_v2634 = eval.m31_add(wg_v2632, wg_v2633);
    let wg_v2635 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[0]);
    let wg_v2636 = eval.m31_add(wg_v2634, wg_v2635);
    let wg_v2637 = eval.m31_sub(wg_v2636, z0_tmp_fec87_39[6]);
    let wg_v2638 = eval.m31_sub(wg_v2637, z2_tmp_fec87_40[6]);
    let wg_v2639 = eval.m31_mul(x_sum_tmp_fec87_41[1], y_sum_tmp_fec87_42[6]);
    let wg_v2640 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[5]);
    let wg_v2641 = eval.m31_add(wg_v2639, wg_v2640);
    let wg_v2642 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[4]);
    let wg_v2643 = eval.m31_add(wg_v2641, wg_v2642);
    let wg_v2644 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[3]);
    let wg_v2645 = eval.m31_add(wg_v2643, wg_v2644);
    let wg_v2646 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[2]);
    let wg_v2647 = eval.m31_add(wg_v2645, wg_v2646);
    let wg_v2648 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[1]);
    let wg_v2649 = eval.m31_add(wg_v2647, wg_v2648);
    let wg_v2650 = eval.m31_sub(wg_v2649, z0_tmp_fec87_39[7]);
    let wg_v2651 = eval.m31_sub(wg_v2650, z2_tmp_fec87_40[7]);
    let wg_v2652 = eval.m31_add(z2_tmp_fec87_40[0], wg_v2651);
    let wg_v2653 = eval.m31_mul(x_sum_tmp_fec87_41[2], y_sum_tmp_fec87_42[6]);
    let wg_v2654 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[5]);
    let wg_v2655 = eval.m31_add(wg_v2653, wg_v2654);
    let wg_v2656 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[4]);
    let wg_v2657 = eval.m31_add(wg_v2655, wg_v2656);
    let wg_v2658 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[3]);
    let wg_v2659 = eval.m31_add(wg_v2657, wg_v2658);
    let wg_v2660 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[2]);
    let wg_v2661 = eval.m31_add(wg_v2659, wg_v2660);
    let wg_v2662 = eval.m31_sub(wg_v2661, z0_tmp_fec87_39[8]);
    let wg_v2663 = eval.m31_sub(wg_v2662, z2_tmp_fec87_40[8]);
    let wg_v2664 = eval.m31_add(z2_tmp_fec87_40[1], wg_v2663);
    let wg_v2665 = eval.m31_mul(x_sum_tmp_fec87_41[3], y_sum_tmp_fec87_42[6]);
    let wg_v2666 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[5]);
    let wg_v2667 = eval.m31_add(wg_v2665, wg_v2666);
    let wg_v2668 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[4]);
    let wg_v2669 = eval.m31_add(wg_v2667, wg_v2668);
    let wg_v2670 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[3]);
    let wg_v2671 = eval.m31_add(wg_v2669, wg_v2670);
    let wg_v2672 = eval.m31_sub(wg_v2671, z0_tmp_fec87_39[9]);
    let wg_v2673 = eval.m31_sub(wg_v2672, z2_tmp_fec87_40[9]);
    let wg_v2674 = eval.m31_add(z2_tmp_fec87_40[2], wg_v2673);
    let wg_v2675 = eval.m31_mul(x_sum_tmp_fec87_41[4], y_sum_tmp_fec87_42[6]);
    let wg_v2676 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[5]);
    let wg_v2677 = eval.m31_add(wg_v2675, wg_v2676);
    let wg_v2678 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[4]);
    let wg_v2679 = eval.m31_add(wg_v2677, wg_v2678);
    let wg_v2680 = eval.m31_sub(wg_v2679, z0_tmp_fec87_39[10]);
    let wg_v2681 = eval.m31_sub(wg_v2680, z2_tmp_fec87_40[10]);
    let wg_v2682 = eval.m31_add(z2_tmp_fec87_40[3], wg_v2681);
    let wg_v2683 = eval.m31_mul(x_sum_tmp_fec87_41[5], y_sum_tmp_fec87_42[6]);
    let wg_v2684 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[5]);
    let wg_v2685 = eval.m31_add(wg_v2683, wg_v2684);
    let wg_v2686 = eval.m31_sub(wg_v2685, z0_tmp_fec87_39[11]);
    let wg_v2687 = eval.m31_sub(wg_v2686, z2_tmp_fec87_40[11]);
    let wg_v2688 = eval.m31_add(z2_tmp_fec87_40[4], wg_v2687);
    let wg_v2689 = eval.m31_mul(x_sum_tmp_fec87_41[6], y_sum_tmp_fec87_42[6]);
    let wg_v2690 = eval.m31_sub(wg_v2689, z0_tmp_fec87_39[12]);
    let wg_v2691 = eval.m31_sub(wg_v2690, z2_tmp_fec87_40[12]);
    let wg_v2692 = eval.m31_add(z2_tmp_fec87_40[5], wg_v2691);
    let single_karatsuba_n_7_output_tmp_fec87_43 = [
        z0_tmp_fec87_39[0],
        z0_tmp_fec87_39[1],
        z0_tmp_fec87_39[2],
        z0_tmp_fec87_39[3],
        z0_tmp_fec87_39[4],
        z0_tmp_fec87_39[5],
        z0_tmp_fec87_39[6],
        wg_v2573,
        wg_v2579,
        wg_v2587,
        wg_v2597,
        wg_v2609,
        wg_v2623,
        wg_v2638,
        wg_v2652,
        wg_v2664,
        wg_v2674,
        wg_v2682,
        wg_v2688,
        wg_v2692,
        z2_tmp_fec87_40[6],
        z2_tmp_fec87_40[7],
        z2_tmp_fec87_40[8],
        z2_tmp_fec87_40[9],
        z2_tmp_fec87_40[10],
        z2_tmp_fec87_40[11],
        z2_tmp_fec87_40[12],
    ];
    let wg_v2693 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[0],
        single_karatsuba_n_7_output_tmp_fec87_31[0],
    );
    let wg_v2694 = eval.m31_sub(wg_v2693, single_karatsuba_n_7_output_tmp_fec87_36[0]);
    let wg_v2695 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[14], wg_v2694);
    let wg_v2696 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[1],
        single_karatsuba_n_7_output_tmp_fec87_31[1],
    );
    let wg_v2697 = eval.m31_sub(wg_v2696, single_karatsuba_n_7_output_tmp_fec87_36[1]);
    let wg_v2698 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[15], wg_v2697);
    let wg_v2699 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[2],
        single_karatsuba_n_7_output_tmp_fec87_31[2],
    );
    let wg_v2700 = eval.m31_sub(wg_v2699, single_karatsuba_n_7_output_tmp_fec87_36[2]);
    let wg_v2701 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[16], wg_v2700);
    let wg_v2702 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[3],
        single_karatsuba_n_7_output_tmp_fec87_31[3],
    );
    let wg_v2703 = eval.m31_sub(wg_v2702, single_karatsuba_n_7_output_tmp_fec87_36[3]);
    let wg_v2704 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[17], wg_v2703);
    let wg_v2705 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[4],
        single_karatsuba_n_7_output_tmp_fec87_31[4],
    );
    let wg_v2706 = eval.m31_sub(wg_v2705, single_karatsuba_n_7_output_tmp_fec87_36[4]);
    let wg_v2707 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[18], wg_v2706);
    let wg_v2708 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[5],
        single_karatsuba_n_7_output_tmp_fec87_31[5],
    );
    let wg_v2709 = eval.m31_sub(wg_v2708, single_karatsuba_n_7_output_tmp_fec87_36[5]);
    let wg_v2710 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[19], wg_v2709);
    let wg_v2711 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[6],
        single_karatsuba_n_7_output_tmp_fec87_31[6],
    );
    let wg_v2712 = eval.m31_sub(wg_v2711, single_karatsuba_n_7_output_tmp_fec87_36[6]);
    let wg_v2713 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[20], wg_v2712);
    let wg_v2714 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[7],
        single_karatsuba_n_7_output_tmp_fec87_31[7],
    );
    let wg_v2715 = eval.m31_sub(wg_v2714, single_karatsuba_n_7_output_tmp_fec87_36[7]);
    let wg_v2716 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[21], wg_v2715);
    let wg_v2717 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[8],
        single_karatsuba_n_7_output_tmp_fec87_31[8],
    );
    let wg_v2718 = eval.m31_sub(wg_v2717, single_karatsuba_n_7_output_tmp_fec87_36[8]);
    let wg_v2719 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[22], wg_v2718);
    let wg_v2720 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[9],
        single_karatsuba_n_7_output_tmp_fec87_31[9],
    );
    let wg_v2721 = eval.m31_sub(wg_v2720, single_karatsuba_n_7_output_tmp_fec87_36[9]);
    let wg_v2722 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[23], wg_v2721);
    let wg_v2723 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[10],
        single_karatsuba_n_7_output_tmp_fec87_31[10],
    );
    let wg_v2724 = eval.m31_sub(wg_v2723, single_karatsuba_n_7_output_tmp_fec87_36[10]);
    let wg_v2725 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[24], wg_v2724);
    let wg_v2726 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[11],
        single_karatsuba_n_7_output_tmp_fec87_31[11],
    );
    let wg_v2727 = eval.m31_sub(wg_v2726, single_karatsuba_n_7_output_tmp_fec87_36[11]);
    let wg_v2728 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[25], wg_v2727);
    let wg_v2729 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[12],
        single_karatsuba_n_7_output_tmp_fec87_31[12],
    );
    let wg_v2730 = eval.m31_sub(wg_v2729, single_karatsuba_n_7_output_tmp_fec87_36[12]);
    let wg_v2731 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_31[26], wg_v2730);
    let wg_v2732 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[13],
        single_karatsuba_n_7_output_tmp_fec87_31[13],
    );
    let wg_v2733 = eval.m31_sub(wg_v2732, single_karatsuba_n_7_output_tmp_fec87_36[13]);
    let wg_v2734 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[14],
        single_karatsuba_n_7_output_tmp_fec87_31[14],
    );
    let wg_v2735 = eval.m31_sub(wg_v2734, single_karatsuba_n_7_output_tmp_fec87_36[14]);
    let wg_v2736 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[0], wg_v2735);
    let wg_v2737 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[15],
        single_karatsuba_n_7_output_tmp_fec87_31[15],
    );
    let wg_v2738 = eval.m31_sub(wg_v2737, single_karatsuba_n_7_output_tmp_fec87_36[15]);
    let wg_v2739 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[1], wg_v2738);
    let wg_v2740 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[16],
        single_karatsuba_n_7_output_tmp_fec87_31[16],
    );
    let wg_v2741 = eval.m31_sub(wg_v2740, single_karatsuba_n_7_output_tmp_fec87_36[16]);
    let wg_v2742 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[2], wg_v2741);
    let wg_v2743 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[17],
        single_karatsuba_n_7_output_tmp_fec87_31[17],
    );
    let wg_v2744 = eval.m31_sub(wg_v2743, single_karatsuba_n_7_output_tmp_fec87_36[17]);
    let wg_v2745 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[3], wg_v2744);
    let wg_v2746 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[18],
        single_karatsuba_n_7_output_tmp_fec87_31[18],
    );
    let wg_v2747 = eval.m31_sub(wg_v2746, single_karatsuba_n_7_output_tmp_fec87_36[18]);
    let wg_v2748 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[4], wg_v2747);
    let wg_v2749 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[19],
        single_karatsuba_n_7_output_tmp_fec87_31[19],
    );
    let wg_v2750 = eval.m31_sub(wg_v2749, single_karatsuba_n_7_output_tmp_fec87_36[19]);
    let wg_v2751 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[5], wg_v2750);
    let wg_v2752 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[20],
        single_karatsuba_n_7_output_tmp_fec87_31[20],
    );
    let wg_v2753 = eval.m31_sub(wg_v2752, single_karatsuba_n_7_output_tmp_fec87_36[20]);
    let wg_v2754 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[6], wg_v2753);
    let wg_v2755 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[21],
        single_karatsuba_n_7_output_tmp_fec87_31[21],
    );
    let wg_v2756 = eval.m31_sub(wg_v2755, single_karatsuba_n_7_output_tmp_fec87_36[21]);
    let wg_v2757 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[7], wg_v2756);
    let wg_v2758 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[22],
        single_karatsuba_n_7_output_tmp_fec87_31[22],
    );
    let wg_v2759 = eval.m31_sub(wg_v2758, single_karatsuba_n_7_output_tmp_fec87_36[22]);
    let wg_v2760 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[8], wg_v2759);
    let wg_v2761 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[23],
        single_karatsuba_n_7_output_tmp_fec87_31[23],
    );
    let wg_v2762 = eval.m31_sub(wg_v2761, single_karatsuba_n_7_output_tmp_fec87_36[23]);
    let wg_v2763 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[9], wg_v2762);
    let wg_v2764 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[24],
        single_karatsuba_n_7_output_tmp_fec87_31[24],
    );
    let wg_v2765 = eval.m31_sub(wg_v2764, single_karatsuba_n_7_output_tmp_fec87_36[24]);
    let wg_v2766 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[10], wg_v2765);
    let wg_v2767 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[25],
        single_karatsuba_n_7_output_tmp_fec87_31[25],
    );
    let wg_v2768 = eval.m31_sub(wg_v2767, single_karatsuba_n_7_output_tmp_fec87_36[25]);
    let wg_v2769 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[11], wg_v2768);
    let wg_v2770 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_fec87_43[26],
        single_karatsuba_n_7_output_tmp_fec87_31[26],
    );
    let wg_v2771 = eval.m31_sub(wg_v2770, single_karatsuba_n_7_output_tmp_fec87_36[26]);
    let wg_v2772 = eval.m31_add(single_karatsuba_n_7_output_tmp_fec87_36[12], wg_v2771);
    let double_karatsuba_1454b_output_tmp_fec87_44 = [
        single_karatsuba_n_7_output_tmp_fec87_31[0],
        single_karatsuba_n_7_output_tmp_fec87_31[1],
        single_karatsuba_n_7_output_tmp_fec87_31[2],
        single_karatsuba_n_7_output_tmp_fec87_31[3],
        single_karatsuba_n_7_output_tmp_fec87_31[4],
        single_karatsuba_n_7_output_tmp_fec87_31[5],
        single_karatsuba_n_7_output_tmp_fec87_31[6],
        single_karatsuba_n_7_output_tmp_fec87_31[7],
        single_karatsuba_n_7_output_tmp_fec87_31[8],
        single_karatsuba_n_7_output_tmp_fec87_31[9],
        single_karatsuba_n_7_output_tmp_fec87_31[10],
        single_karatsuba_n_7_output_tmp_fec87_31[11],
        single_karatsuba_n_7_output_tmp_fec87_31[12],
        single_karatsuba_n_7_output_tmp_fec87_31[13],
        wg_v2695,
        wg_v2698,
        wg_v2701,
        wg_v2704,
        wg_v2707,
        wg_v2710,
        wg_v2713,
        wg_v2716,
        wg_v2719,
        wg_v2722,
        wg_v2725,
        wg_v2728,
        wg_v2731,
        wg_v2733,
        wg_v2736,
        wg_v2739,
        wg_v2742,
        wg_v2745,
        wg_v2748,
        wg_v2751,
        wg_v2754,
        wg_v2757,
        wg_v2760,
        wg_v2763,
        wg_v2766,
        wg_v2769,
        wg_v2772,
        single_karatsuba_n_7_output_tmp_fec87_36[13],
        single_karatsuba_n_7_output_tmp_fec87_36[14],
        single_karatsuba_n_7_output_tmp_fec87_36[15],
        single_karatsuba_n_7_output_tmp_fec87_36[16],
        single_karatsuba_n_7_output_tmp_fec87_36[17],
        single_karatsuba_n_7_output_tmp_fec87_36[18],
        single_karatsuba_n_7_output_tmp_fec87_36[19],
        single_karatsuba_n_7_output_tmp_fec87_36[20],
        single_karatsuba_n_7_output_tmp_fec87_36[21],
        single_karatsuba_n_7_output_tmp_fec87_36[22],
        single_karatsuba_n_7_output_tmp_fec87_36[23],
        single_karatsuba_n_7_output_tmp_fec87_36[24],
        single_karatsuba_n_7_output_tmp_fec87_36[25],
        single_karatsuba_n_7_output_tmp_fec87_36[26],
    ];
    let wg_v2773 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[0],
        mul_res_limb_0_col84,
    );
    let wg_v2774 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[1],
        mul_res_limb_1_col85,
    );
    let wg_v2775 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[2],
        mul_res_limb_2_col86,
    );
    let wg_v2776 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[3],
        mul_res_limb_3_col87,
    );
    let wg_v2777 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[4],
        mul_res_limb_4_col88,
    );
    let wg_v2778 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[5],
        mul_res_limb_5_col89,
    );
    let wg_v2779 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[6],
        mul_res_limb_6_col90,
    );
    let wg_v2780 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[7],
        mul_res_limb_7_col91,
    );
    let wg_v2781 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[8],
        mul_res_limb_8_col92,
    );
    let wg_v2782 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[9],
        mul_res_limb_9_col93,
    );
    let wg_v2783 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[10],
        mul_res_limb_10_col94,
    );
    let wg_v2784 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[11],
        mul_res_limb_11_col95,
    );
    let wg_v2785 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[12],
        mul_res_limb_12_col96,
    );
    let wg_v2786 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[13],
        mul_res_limb_13_col97,
    );
    let wg_v2787 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[14],
        mul_res_limb_14_col98,
    );
    let wg_v2788 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[15],
        mul_res_limb_15_col99,
    );
    let wg_v2789 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[16],
        mul_res_limb_16_col100,
    );
    let wg_v2790 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[17],
        mul_res_limb_17_col101,
    );
    let wg_v2791 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[18],
        mul_res_limb_18_col102,
    );
    let wg_v2792 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[19],
        mul_res_limb_19_col103,
    );
    let wg_v2793 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[20],
        mul_res_limb_20_col104,
    );
    let wg_v2794 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[21],
        mul_res_limb_21_col105,
    );
    let wg_v2795 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[22],
        mul_res_limb_22_col106,
    );
    let wg_v2796 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[23],
        mul_res_limb_23_col107,
    );
    let wg_v2797 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[24],
        mul_res_limb_24_col108,
    );
    let wg_v2798 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[25],
        mul_res_limb_25_col109,
    );
    let wg_v2799 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[26],
        mul_res_limb_26_col110,
    );
    let wg_v2800 = eval.m31_sub(
        double_karatsuba_1454b_output_tmp_fec87_44[27],
        mul_res_limb_27_col111,
    );
    let conv_tmp_fec87_45 = [
        wg_v2773,
        wg_v2774,
        wg_v2775,
        wg_v2776,
        wg_v2777,
        wg_v2778,
        wg_v2779,
        wg_v2780,
        wg_v2781,
        wg_v2782,
        wg_v2783,
        wg_v2784,
        wg_v2785,
        wg_v2786,
        wg_v2787,
        wg_v2788,
        wg_v2789,
        wg_v2790,
        wg_v2791,
        wg_v2792,
        wg_v2793,
        wg_v2794,
        wg_v2795,
        wg_v2796,
        wg_v2797,
        wg_v2798,
        wg_v2799,
        wg_v2800,
        double_karatsuba_1454b_output_tmp_fec87_44[28],
        double_karatsuba_1454b_output_tmp_fec87_44[29],
        double_karatsuba_1454b_output_tmp_fec87_44[30],
        double_karatsuba_1454b_output_tmp_fec87_44[31],
        double_karatsuba_1454b_output_tmp_fec87_44[32],
        double_karatsuba_1454b_output_tmp_fec87_44[33],
        double_karatsuba_1454b_output_tmp_fec87_44[34],
        double_karatsuba_1454b_output_tmp_fec87_44[35],
        double_karatsuba_1454b_output_tmp_fec87_44[36],
        double_karatsuba_1454b_output_tmp_fec87_44[37],
        double_karatsuba_1454b_output_tmp_fec87_44[38],
        double_karatsuba_1454b_output_tmp_fec87_44[39],
        double_karatsuba_1454b_output_tmp_fec87_44[40],
        double_karatsuba_1454b_output_tmp_fec87_44[41],
        double_karatsuba_1454b_output_tmp_fec87_44[42],
        double_karatsuba_1454b_output_tmp_fec87_44[43],
        double_karatsuba_1454b_output_tmp_fec87_44[44],
        double_karatsuba_1454b_output_tmp_fec87_44[45],
        double_karatsuba_1454b_output_tmp_fec87_44[46],
        double_karatsuba_1454b_output_tmp_fec87_44[47],
        double_karatsuba_1454b_output_tmp_fec87_44[48],
        double_karatsuba_1454b_output_tmp_fec87_44[49],
        double_karatsuba_1454b_output_tmp_fec87_44[50],
        double_karatsuba_1454b_output_tmp_fec87_44[51],
        double_karatsuba_1454b_output_tmp_fec87_44[52],
        double_karatsuba_1454b_output_tmp_fec87_44[53],
        double_karatsuba_1454b_output_tmp_fec87_44[54],
    ];
    let wg_v2801 = eval.m31_mul(m31_32, conv_tmp_fec87_45[0]);
    let wg_v2802 = eval.m31_mul(m31_4, conv_tmp_fec87_45[21]);
    let wg_v2803 = eval.m31_sub(wg_v2801, wg_v2802);
    let wg_v2804 = eval.m31_mul(m31_8, conv_tmp_fec87_45[49]);
    let wg_v2805 = eval.m31_add(wg_v2803, wg_v2804);
    let wg_v2806 = eval.m31_mul(m31_32, conv_tmp_fec87_45[1]);
    let wg_v2807 = eval.m31_add(conv_tmp_fec87_45[0], wg_v2806);
    let wg_v2808 = eval.m31_mul(m31_4, conv_tmp_fec87_45[22]);
    let wg_v2809 = eval.m31_sub(wg_v2807, wg_v2808);
    let wg_v2810 = eval.m31_mul(m31_8, conv_tmp_fec87_45[50]);
    let wg_v2811 = eval.m31_add(wg_v2809, wg_v2810);
    let wg_v2812 = eval.m31_mul(m31_32, conv_tmp_fec87_45[2]);
    let wg_v2813 = eval.m31_add(conv_tmp_fec87_45[1], wg_v2812);
    let wg_v2814 = eval.m31_mul(m31_4, conv_tmp_fec87_45[23]);
    let wg_v2815 = eval.m31_sub(wg_v2813, wg_v2814);
    let wg_v2816 = eval.m31_mul(m31_8, conv_tmp_fec87_45[51]);
    let wg_v2817 = eval.m31_add(wg_v2815, wg_v2816);
    let wg_v2818 = eval.m31_mul(m31_32, conv_tmp_fec87_45[3]);
    let wg_v2819 = eval.m31_add(conv_tmp_fec87_45[2], wg_v2818);
    let wg_v2820 = eval.m31_mul(m31_4, conv_tmp_fec87_45[24]);
    let wg_v2821 = eval.m31_sub(wg_v2819, wg_v2820);
    let wg_v2822 = eval.m31_mul(m31_8, conv_tmp_fec87_45[52]);
    let wg_v2823 = eval.m31_add(wg_v2821, wg_v2822);
    let wg_v2824 = eval.m31_mul(m31_32, conv_tmp_fec87_45[4]);
    let wg_v2825 = eval.m31_add(conv_tmp_fec87_45[3], wg_v2824);
    let wg_v2826 = eval.m31_mul(m31_4, conv_tmp_fec87_45[25]);
    let wg_v2827 = eval.m31_sub(wg_v2825, wg_v2826);
    let wg_v2828 = eval.m31_mul(m31_8, conv_tmp_fec87_45[53]);
    let wg_v2829 = eval.m31_add(wg_v2827, wg_v2828);
    let wg_v2830 = eval.m31_mul(m31_32, conv_tmp_fec87_45[5]);
    let wg_v2831 = eval.m31_add(conv_tmp_fec87_45[4], wg_v2830);
    let wg_v2832 = eval.m31_mul(m31_4, conv_tmp_fec87_45[26]);
    let wg_v2833 = eval.m31_sub(wg_v2831, wg_v2832);
    let wg_v2834 = eval.m31_mul(m31_8, conv_tmp_fec87_45[54]);
    let wg_v2835 = eval.m31_add(wg_v2833, wg_v2834);
    let wg_v2836 = eval.m31_mul(m31_32, conv_tmp_fec87_45[6]);
    let wg_v2837 = eval.m31_add(conv_tmp_fec87_45[5], wg_v2836);
    let wg_v2838 = eval.m31_mul(m31_4, conv_tmp_fec87_45[27]);
    let wg_v2839 = eval.m31_sub(wg_v2837, wg_v2838);
    let wg_v2840 = eval.m31_mul(m31_2, conv_tmp_fec87_45[0]);
    let wg_v2841 = eval.m31_add(wg_v2840, conv_tmp_fec87_45[6]);
    let wg_v2842 = eval.m31_mul(m31_32, conv_tmp_fec87_45[7]);
    let wg_v2843 = eval.m31_add(wg_v2841, wg_v2842);
    let wg_v2844 = eval.m31_mul(m31_4, conv_tmp_fec87_45[28]);
    let wg_v2845 = eval.m31_sub(wg_v2843, wg_v2844);
    let wg_v2846 = eval.m31_mul(m31_2, conv_tmp_fec87_45[1]);
    let wg_v2847 = eval.m31_add(wg_v2846, conv_tmp_fec87_45[7]);
    let wg_v2848 = eval.m31_mul(m31_32, conv_tmp_fec87_45[8]);
    let wg_v2849 = eval.m31_add(wg_v2847, wg_v2848);
    let wg_v2850 = eval.m31_mul(m31_4, conv_tmp_fec87_45[29]);
    let wg_v2851 = eval.m31_sub(wg_v2849, wg_v2850);
    let wg_v2852 = eval.m31_mul(m31_2, conv_tmp_fec87_45[2]);
    let wg_v2853 = eval.m31_add(wg_v2852, conv_tmp_fec87_45[8]);
    let wg_v2854 = eval.m31_mul(m31_32, conv_tmp_fec87_45[9]);
    let wg_v2855 = eval.m31_add(wg_v2853, wg_v2854);
    let wg_v2856 = eval.m31_mul(m31_4, conv_tmp_fec87_45[30]);
    let wg_v2857 = eval.m31_sub(wg_v2855, wg_v2856);
    let wg_v2858 = eval.m31_mul(m31_2, conv_tmp_fec87_45[3]);
    let wg_v2859 = eval.m31_add(wg_v2858, conv_tmp_fec87_45[9]);
    let wg_v2860 = eval.m31_mul(m31_32, conv_tmp_fec87_45[10]);
    let wg_v2861 = eval.m31_add(wg_v2859, wg_v2860);
    let wg_v2862 = eval.m31_mul(m31_4, conv_tmp_fec87_45[31]);
    let wg_v2863 = eval.m31_sub(wg_v2861, wg_v2862);
    let wg_v2864 = eval.m31_mul(m31_2, conv_tmp_fec87_45[4]);
    let wg_v2865 = eval.m31_add(wg_v2864, conv_tmp_fec87_45[10]);
    let wg_v2866 = eval.m31_mul(m31_32, conv_tmp_fec87_45[11]);
    let wg_v2867 = eval.m31_add(wg_v2865, wg_v2866);
    let wg_v2868 = eval.m31_mul(m31_4, conv_tmp_fec87_45[32]);
    let wg_v2869 = eval.m31_sub(wg_v2867, wg_v2868);
    let wg_v2870 = eval.m31_mul(m31_2, conv_tmp_fec87_45[5]);
    let wg_v2871 = eval.m31_add(wg_v2870, conv_tmp_fec87_45[11]);
    let wg_v2872 = eval.m31_mul(m31_32, conv_tmp_fec87_45[12]);
    let wg_v2873 = eval.m31_add(wg_v2871, wg_v2872);
    let wg_v2874 = eval.m31_mul(m31_4, conv_tmp_fec87_45[33]);
    let wg_v2875 = eval.m31_sub(wg_v2873, wg_v2874);
    let wg_v2876 = eval.m31_mul(m31_2, conv_tmp_fec87_45[6]);
    let wg_v2877 = eval.m31_add(wg_v2876, conv_tmp_fec87_45[12]);
    let wg_v2878 = eval.m31_mul(m31_32, conv_tmp_fec87_45[13]);
    let wg_v2879 = eval.m31_add(wg_v2877, wg_v2878);
    let wg_v2880 = eval.m31_mul(m31_4, conv_tmp_fec87_45[34]);
    let wg_v2881 = eval.m31_sub(wg_v2879, wg_v2880);
    let wg_v2882 = eval.m31_mul(m31_2, conv_tmp_fec87_45[7]);
    let wg_v2883 = eval.m31_add(wg_v2882, conv_tmp_fec87_45[13]);
    let wg_v2884 = eval.m31_mul(m31_32, conv_tmp_fec87_45[14]);
    let wg_v2885 = eval.m31_add(wg_v2883, wg_v2884);
    let wg_v2886 = eval.m31_mul(m31_4, conv_tmp_fec87_45[35]);
    let wg_v2887 = eval.m31_sub(wg_v2885, wg_v2886);
    let wg_v2888 = eval.m31_mul(m31_2, conv_tmp_fec87_45[8]);
    let wg_v2889 = eval.m31_add(wg_v2888, conv_tmp_fec87_45[14]);
    let wg_v2890 = eval.m31_mul(m31_32, conv_tmp_fec87_45[15]);
    let wg_v2891 = eval.m31_add(wg_v2889, wg_v2890);
    let wg_v2892 = eval.m31_mul(m31_4, conv_tmp_fec87_45[36]);
    let wg_v2893 = eval.m31_sub(wg_v2891, wg_v2892);
    let wg_v2894 = eval.m31_mul(m31_2, conv_tmp_fec87_45[9]);
    let wg_v2895 = eval.m31_add(wg_v2894, conv_tmp_fec87_45[15]);
    let wg_v2896 = eval.m31_mul(m31_32, conv_tmp_fec87_45[16]);
    let wg_v2897 = eval.m31_add(wg_v2895, wg_v2896);
    let wg_v2898 = eval.m31_mul(m31_4, conv_tmp_fec87_45[37]);
    let wg_v2899 = eval.m31_sub(wg_v2897, wg_v2898);
    let wg_v2900 = eval.m31_mul(m31_2, conv_tmp_fec87_45[10]);
    let wg_v2901 = eval.m31_add(wg_v2900, conv_tmp_fec87_45[16]);
    let wg_v2902 = eval.m31_mul(m31_32, conv_tmp_fec87_45[17]);
    let wg_v2903 = eval.m31_add(wg_v2901, wg_v2902);
    let wg_v2904 = eval.m31_mul(m31_4, conv_tmp_fec87_45[38]);
    let wg_v2905 = eval.m31_sub(wg_v2903, wg_v2904);
    let wg_v2906 = eval.m31_mul(m31_2, conv_tmp_fec87_45[11]);
    let wg_v2907 = eval.m31_add(wg_v2906, conv_tmp_fec87_45[17]);
    let wg_v2908 = eval.m31_mul(m31_32, conv_tmp_fec87_45[18]);
    let wg_v2909 = eval.m31_add(wg_v2907, wg_v2908);
    let wg_v2910 = eval.m31_mul(m31_4, conv_tmp_fec87_45[39]);
    let wg_v2911 = eval.m31_sub(wg_v2909, wg_v2910);
    let wg_v2912 = eval.m31_mul(m31_2, conv_tmp_fec87_45[12]);
    let wg_v2913 = eval.m31_add(wg_v2912, conv_tmp_fec87_45[18]);
    let wg_v2914 = eval.m31_mul(m31_32, conv_tmp_fec87_45[19]);
    let wg_v2915 = eval.m31_add(wg_v2913, wg_v2914);
    let wg_v2916 = eval.m31_mul(m31_4, conv_tmp_fec87_45[40]);
    let wg_v2917 = eval.m31_sub(wg_v2915, wg_v2916);
    let wg_v2918 = eval.m31_mul(m31_2, conv_tmp_fec87_45[13]);
    let wg_v2919 = eval.m31_add(wg_v2918, conv_tmp_fec87_45[19]);
    let wg_v2920 = eval.m31_mul(m31_32, conv_tmp_fec87_45[20]);
    let wg_v2921 = eval.m31_add(wg_v2919, wg_v2920);
    let wg_v2922 = eval.m31_mul(m31_4, conv_tmp_fec87_45[41]);
    let wg_v2923 = eval.m31_sub(wg_v2921, wg_v2922);
    let wg_v2924 = eval.m31_mul(m31_2, conv_tmp_fec87_45[14]);
    let wg_v2925 = eval.m31_add(wg_v2924, conv_tmp_fec87_45[20]);
    let wg_v2926 = eval.m31_mul(m31_4, conv_tmp_fec87_45[42]);
    let wg_v2927 = eval.m31_sub(wg_v2925, wg_v2926);
    let wg_v2928 = eval.m31_mul(m31_64, conv_tmp_fec87_45[49]);
    let wg_v2929 = eval.m31_add(wg_v2927, wg_v2928);
    let wg_v2930 = eval.m31_mul(m31_2, conv_tmp_fec87_45[15]);
    let wg_v2931 = eval.m31_mul(m31_4, conv_tmp_fec87_45[43]);
    let wg_v2932 = eval.m31_sub(wg_v2930, wg_v2931);
    let wg_v2933 = eval.m31_mul(m31_2, conv_tmp_fec87_45[49]);
    let wg_v2934 = eval.m31_add(wg_v2932, wg_v2933);
    let wg_v2935 = eval.m31_mul(m31_64, conv_tmp_fec87_45[50]);
    let wg_v2936 = eval.m31_add(wg_v2934, wg_v2935);
    let wg_v2937 = eval.m31_mul(m31_2, conv_tmp_fec87_45[16]);
    let wg_v2938 = eval.m31_mul(m31_4, conv_tmp_fec87_45[44]);
    let wg_v2939 = eval.m31_sub(wg_v2937, wg_v2938);
    let wg_v2940 = eval.m31_mul(m31_2, conv_tmp_fec87_45[50]);
    let wg_v2941 = eval.m31_add(wg_v2939, wg_v2940);
    let wg_v2942 = eval.m31_mul(m31_64, conv_tmp_fec87_45[51]);
    let wg_v2943 = eval.m31_add(wg_v2941, wg_v2942);
    let wg_v2944 = eval.m31_mul(m31_2, conv_tmp_fec87_45[17]);
    let wg_v2945 = eval.m31_mul(m31_4, conv_tmp_fec87_45[45]);
    let wg_v2946 = eval.m31_sub(wg_v2944, wg_v2945);
    let wg_v2947 = eval.m31_mul(m31_2, conv_tmp_fec87_45[51]);
    let wg_v2948 = eval.m31_add(wg_v2946, wg_v2947);
    let wg_v2949 = eval.m31_mul(m31_64, conv_tmp_fec87_45[52]);
    let wg_v2950 = eval.m31_add(wg_v2948, wg_v2949);
    let wg_v2951 = eval.m31_mul(m31_2, conv_tmp_fec87_45[18]);
    let wg_v2952 = eval.m31_mul(m31_4, conv_tmp_fec87_45[46]);
    let wg_v2953 = eval.m31_sub(wg_v2951, wg_v2952);
    let wg_v2954 = eval.m31_mul(m31_2, conv_tmp_fec87_45[52]);
    let wg_v2955 = eval.m31_add(wg_v2953, wg_v2954);
    let wg_v2956 = eval.m31_mul(m31_64, conv_tmp_fec87_45[53]);
    let wg_v2957 = eval.m31_add(wg_v2955, wg_v2956);
    let wg_v2958 = eval.m31_mul(m31_2, conv_tmp_fec87_45[19]);
    let wg_v2959 = eval.m31_mul(m31_4, conv_tmp_fec87_45[47]);
    let wg_v2960 = eval.m31_sub(wg_v2958, wg_v2959);
    let wg_v2961 = eval.m31_mul(m31_2, conv_tmp_fec87_45[53]);
    let wg_v2962 = eval.m31_add(wg_v2960, wg_v2961);
    let wg_v2963 = eval.m31_mul(m31_64, conv_tmp_fec87_45[54]);
    let wg_v2964 = eval.m31_add(wg_v2962, wg_v2963);
    let wg_v2965 = eval.m31_mul(m31_2, conv_tmp_fec87_45[20]);
    let wg_v2966 = eval.m31_mul(m31_4, conv_tmp_fec87_45[48]);
    let wg_v2967 = eval.m31_sub(wg_v2965, wg_v2966);
    let wg_v2968 = eval.m31_mul(m31_2, conv_tmp_fec87_45[54]);
    let wg_v2969 = eval.m31_add(wg_v2967, wg_v2968);
    let conv_mod_tmp_fec87_46 = [
        wg_v2805, wg_v2811, wg_v2817, wg_v2823, wg_v2829, wg_v2835, wg_v2839, wg_v2845, wg_v2851,
        wg_v2857, wg_v2863, wg_v2869, wg_v2875, wg_v2881, wg_v2887, wg_v2893, wg_v2899, wg_v2905,
        wg_v2911, wg_v2917, wg_v2923, wg_v2929, wg_v2936, wg_v2943, wg_v2950, wg_v2957, wg_v2964,
        wg_v2969,
    ];
    let wg_v2970 = eval.m31_add(conv_mod_tmp_fec87_46[0], m31_134217728);
    let wg_v2971 = eval.u32_from_m31(wg_v2970);
    let wg_v2972 = eval.m31_add(conv_mod_tmp_fec87_46[1], m31_134217728);
    let wg_v2973 = eval.u32_from_m31(wg_v2972);
    let wg_v2974 = eval.u32_and_imm(wg_v2973, 511);
    let wg_v2975 = eval.u32_shl_imm(wg_v2974, 9);
    let wg_v2976 = eval.u32_add(wg_v2971, wg_v2975);
    let wg_v2977 = eval.u32_const(131072);
    let wg_v2978 = eval.u32_add(wg_v2976, wg_v2977);
    let k_mod_2_18_biased_tmp_fec87_47 = eval.u32_and_imm(wg_v2978, 262143);
    let wg_v2979 = eval.u32_low(k_mod_2_18_biased_tmp_fec87_47);
    let wg_v2980 = eval.u16_as_m31(wg_v2979);
    let wg_v2981 = eval.u32_high(k_mod_2_18_biased_tmp_fec87_47);
    let wg_v2982 = eval.u16_as_m31(wg_v2981);
    let wg_v2983 = eval.m31_sub(wg_v2982, m31_2);
    let wg_v2984 = eval.m31_mul(wg_v2983, m31_65536);
    let k_col112 = eval.m31_add(wg_v2980, wg_v2984);
    eval.set_col(112, k_col112);
    let wg_v2985 = eval.m31_add(k_col112, m31_524288);
    eval.set_sub_input_word(88, wg_v2985);
    eval.set_lookup_word(29, m31_1410849886);
    let wg_v2986 = eval.m31_add(k_col112, m31_524288);
    eval.set_lookup_word(30, wg_v2986);
    let wg_v2987 = eval.m31_sub(conv_mod_tmp_fec87_46[0], k_col112);
    let carry_0_col113 = eval.m31_mul(wg_v2987, m31_4194304);
    eval.set_col(113, carry_0_col113);
    let wg_v2988 = eval.m31_add(carry_0_col113, m31_524288);
    eval.set_sub_input_word(96, wg_v2988);
    eval.set_lookup_word(45, m31_514232941);
    let wg_v2989 = eval.m31_add(carry_0_col113, m31_524288);
    eval.set_lookup_word(46, wg_v2989);
    let wg_v2990 = eval.m31_add(conv_mod_tmp_fec87_46[1], carry_0_col113);
    let carry_1_col114 = eval.m31_mul(wg_v2990, m31_4194304);
    eval.set_col(114, carry_1_col114);
    let wg_v2991 = eval.m31_add(carry_1_col114, m31_524288);
    eval.set_sub_input_word(104, wg_v2991);
    eval.set_lookup_word(61, m31_531010560);
    let wg_v2992 = eval.m31_add(carry_1_col114, m31_524288);
    eval.set_lookup_word(62, wg_v2992);
    let wg_v2993 = eval.m31_add(conv_mod_tmp_fec87_46[2], carry_1_col114);
    let carry_2_col115 = eval.m31_mul(wg_v2993, m31_4194304);
    eval.set_col(115, carry_2_col115);
    let wg_v2994 = eval.m31_add(carry_2_col115, m31_524288);
    eval.set_sub_input_word(112, wg_v2994);
    eval.set_lookup_word(77, m31_480677703);
    let wg_v2995 = eval.m31_add(carry_2_col115, m31_524288);
    eval.set_lookup_word(78, wg_v2995);
    let wg_v2996 = eval.m31_add(conv_mod_tmp_fec87_46[3], carry_2_col115);
    let carry_3_col116 = eval.m31_mul(wg_v2996, m31_4194304);
    eval.set_col(116, carry_3_col116);
    let wg_v2997 = eval.m31_add(carry_3_col116, m31_524288);
    eval.set_sub_input_word(119, wg_v2997);
    eval.set_lookup_word(91, m31_497455322);
    let wg_v2998 = eval.m31_add(carry_3_col116, m31_524288);
    eval.set_lookup_word(92, wg_v2998);
    let wg_v2999 = eval.m31_add(conv_mod_tmp_fec87_46[4], carry_3_col116);
    let carry_4_col117 = eval.m31_mul(wg_v2999, m31_4194304);
    eval.set_col(117, carry_4_col117);
    let wg_v3000 = eval.m31_add(carry_4_col117, m31_524288);
    eval.set_sub_input_word(125, wg_v3000);
    eval.set_lookup_word(103, m31_447122465);
    let wg_v3001 = eval.m31_add(carry_4_col117, m31_524288);
    eval.set_lookup_word(104, wg_v3001);
    let wg_v3002 = eval.m31_add(conv_mod_tmp_fec87_46[5], carry_4_col117);
    let carry_5_col118 = eval.m31_mul(wg_v3002, m31_4194304);
    eval.set_col(118, carry_5_col118);
    let wg_v3003 = eval.m31_add(carry_5_col118, m31_524288);
    eval.set_sub_input_word(131, wg_v3003);
    eval.set_lookup_word(115, m31_463900084);
    let wg_v3004 = eval.m31_add(carry_5_col118, m31_524288);
    eval.set_lookup_word(116, wg_v3004);
    let wg_v3005 = eval.m31_add(conv_mod_tmp_fec87_46[6], carry_5_col118);
    let carry_6_col119 = eval.m31_mul(wg_v3005, m31_4194304);
    eval.set_col(119, carry_6_col119);
    let wg_v3006 = eval.m31_add(carry_6_col119, m31_524288);
    eval.set_sub_input_word(137, wg_v3006);
    eval.set_lookup_word(127, m31_682009131);
    let wg_v3007 = eval.m31_add(carry_6_col119, m31_524288);
    eval.set_lookup_word(128, wg_v3007);
    let wg_v3008 = eval.m31_add(conv_mod_tmp_fec87_46[7], carry_6_col119);
    let carry_7_col120 = eval.m31_mul(wg_v3008, m31_4194304);
    eval.set_col(120, carry_7_col120);
    let wg_v3009 = eval.m31_add(carry_7_col120, m31_524288);
    eval.set_sub_input_word(89, wg_v3009);
    eval.set_lookup_word(31, m31_1410849886);
    let wg_v3010 = eval.m31_add(carry_7_col120, m31_524288);
    eval.set_lookup_word(32, wg_v3010);
    let wg_v3011 = eval.m31_add(conv_mod_tmp_fec87_46[8], carry_7_col120);
    let carry_8_col121 = eval.m31_mul(wg_v3011, m31_4194304);
    eval.set_col(121, carry_8_col121);
    let wg_v3012 = eval.m31_add(carry_8_col121, m31_524288);
    eval.set_sub_input_word(97, wg_v3012);
    eval.set_lookup_word(47, m31_514232941);
    let wg_v3013 = eval.m31_add(carry_8_col121, m31_524288);
    eval.set_lookup_word(48, wg_v3013);
    let wg_v3014 = eval.m31_add(conv_mod_tmp_fec87_46[9], carry_8_col121);
    let carry_9_col122 = eval.m31_mul(wg_v3014, m31_4194304);
    eval.set_col(122, carry_9_col122);
    let wg_v3015 = eval.m31_add(carry_9_col122, m31_524288);
    eval.set_sub_input_word(105, wg_v3015);
    eval.set_lookup_word(63, m31_531010560);
    let wg_v3016 = eval.m31_add(carry_9_col122, m31_524288);
    eval.set_lookup_word(64, wg_v3016);
    let wg_v3017 = eval.m31_add(conv_mod_tmp_fec87_46[10], carry_9_col122);
    let carry_10_col123 = eval.m31_mul(wg_v3017, m31_4194304);
    eval.set_col(123, carry_10_col123);
    let wg_v3018 = eval.m31_add(carry_10_col123, m31_524288);
    eval.set_sub_input_word(113, wg_v3018);
    eval.set_lookup_word(79, m31_480677703);
    let wg_v3019 = eval.m31_add(carry_10_col123, m31_524288);
    eval.set_lookup_word(80, wg_v3019);
    let wg_v3020 = eval.m31_add(conv_mod_tmp_fec87_46[11], carry_10_col123);
    let carry_11_col124 = eval.m31_mul(wg_v3020, m31_4194304);
    eval.set_col(124, carry_11_col124);
    let wg_v3021 = eval.m31_add(carry_11_col124, m31_524288);
    eval.set_sub_input_word(120, wg_v3021);
    eval.set_lookup_word(93, m31_497455322);
    let wg_v3022 = eval.m31_add(carry_11_col124, m31_524288);
    eval.set_lookup_word(94, wg_v3022);
    let wg_v3023 = eval.m31_add(conv_mod_tmp_fec87_46[12], carry_11_col124);
    let carry_12_col125 = eval.m31_mul(wg_v3023, m31_4194304);
    eval.set_col(125, carry_12_col125);
    let wg_v3024 = eval.m31_add(carry_12_col125, m31_524288);
    eval.set_sub_input_word(126, wg_v3024);
    eval.set_lookup_word(105, m31_447122465);
    let wg_v3025 = eval.m31_add(carry_12_col125, m31_524288);
    eval.set_lookup_word(106, wg_v3025);
    let wg_v3026 = eval.m31_add(conv_mod_tmp_fec87_46[13], carry_12_col125);
    let carry_13_col126 = eval.m31_mul(wg_v3026, m31_4194304);
    eval.set_col(126, carry_13_col126);
    let wg_v3027 = eval.m31_add(carry_13_col126, m31_524288);
    eval.set_sub_input_word(132, wg_v3027);
    eval.set_lookup_word(117, m31_463900084);
    let wg_v3028 = eval.m31_add(carry_13_col126, m31_524288);
    eval.set_lookup_word(118, wg_v3028);
    let wg_v3029 = eval.m31_add(conv_mod_tmp_fec87_46[14], carry_13_col126);
    let carry_14_col127 = eval.m31_mul(wg_v3029, m31_4194304);
    eval.set_col(127, carry_14_col127);
    let wg_v3030 = eval.m31_add(carry_14_col127, m31_524288);
    eval.set_sub_input_word(138, wg_v3030);
    eval.set_lookup_word(129, m31_682009131);
    let wg_v3031 = eval.m31_add(carry_14_col127, m31_524288);
    eval.set_lookup_word(130, wg_v3031);
    let wg_v3032 = eval.m31_add(conv_mod_tmp_fec87_46[15], carry_14_col127);
    let carry_15_col128 = eval.m31_mul(wg_v3032, m31_4194304);
    eval.set_col(128, carry_15_col128);
    let wg_v3033 = eval.m31_add(carry_15_col128, m31_524288);
    eval.set_sub_input_word(90, wg_v3033);
    eval.set_lookup_word(33, m31_1410849886);
    let wg_v3034 = eval.m31_add(carry_15_col128, m31_524288);
    eval.set_lookup_word(34, wg_v3034);
    let wg_v3035 = eval.m31_add(conv_mod_tmp_fec87_46[16], carry_15_col128);
    let carry_16_col129 = eval.m31_mul(wg_v3035, m31_4194304);
    eval.set_col(129, carry_16_col129);
    let wg_v3036 = eval.m31_add(carry_16_col129, m31_524288);
    eval.set_sub_input_word(98, wg_v3036);
    eval.set_lookup_word(49, m31_514232941);
    let wg_v3037 = eval.m31_add(carry_16_col129, m31_524288);
    eval.set_lookup_word(50, wg_v3037);
    let wg_v3038 = eval.m31_add(conv_mod_tmp_fec87_46[17], carry_16_col129);
    let carry_17_col130 = eval.m31_mul(wg_v3038, m31_4194304);
    eval.set_col(130, carry_17_col130);
    let wg_v3039 = eval.m31_add(carry_17_col130, m31_524288);
    eval.set_sub_input_word(106, wg_v3039);
    eval.set_lookup_word(65, m31_531010560);
    let wg_v3040 = eval.m31_add(carry_17_col130, m31_524288);
    eval.set_lookup_word(66, wg_v3040);
    let wg_v3041 = eval.m31_add(conv_mod_tmp_fec87_46[18], carry_17_col130);
    let carry_18_col131 = eval.m31_mul(wg_v3041, m31_4194304);
    eval.set_col(131, carry_18_col131);
    let wg_v3042 = eval.m31_add(carry_18_col131, m31_524288);
    eval.set_sub_input_word(114, wg_v3042);
    eval.set_lookup_word(81, m31_480677703);
    let wg_v3043 = eval.m31_add(carry_18_col131, m31_524288);
    eval.set_lookup_word(82, wg_v3043);
    let wg_v3044 = eval.m31_add(conv_mod_tmp_fec87_46[19], carry_18_col131);
    let carry_19_col132 = eval.m31_mul(wg_v3044, m31_4194304);
    eval.set_col(132, carry_19_col132);
    let wg_v3045 = eval.m31_add(carry_19_col132, m31_524288);
    eval.set_sub_input_word(121, wg_v3045);
    eval.set_lookup_word(95, m31_497455322);
    let wg_v3046 = eval.m31_add(carry_19_col132, m31_524288);
    eval.set_lookup_word(96, wg_v3046);
    let wg_v3047 = eval.m31_add(conv_mod_tmp_fec87_46[20], carry_19_col132);
    let carry_20_col133 = eval.m31_mul(wg_v3047, m31_4194304);
    eval.set_col(133, carry_20_col133);
    let wg_v3048 = eval.m31_add(carry_20_col133, m31_524288);
    eval.set_sub_input_word(127, wg_v3048);
    eval.set_lookup_word(107, m31_447122465);
    let wg_v3049 = eval.m31_add(carry_20_col133, m31_524288);
    eval.set_lookup_word(108, wg_v3049);
    let wg_v3050 = eval.m31_mul(m31_136, k_col112);
    let wg_v3051 = eval.m31_sub(conv_mod_tmp_fec87_46[21], wg_v3050);
    let wg_v3052 = eval.m31_add(wg_v3051, carry_20_col133);
    let carry_21_col134 = eval.m31_mul(wg_v3052, m31_4194304);
    eval.set_col(134, carry_21_col134);
    let wg_v3053 = eval.m31_add(carry_21_col134, m31_524288);
    eval.set_sub_input_word(133, wg_v3053);
    eval.set_lookup_word(119, m31_463900084);
    let wg_v3054 = eval.m31_add(carry_21_col134, m31_524288);
    eval.set_lookup_word(120, wg_v3054);
    let wg_v3055 = eval.m31_add(conv_mod_tmp_fec87_46[22], carry_21_col134);
    let carry_22_col135 = eval.m31_mul(wg_v3055, m31_4194304);
    eval.set_col(135, carry_22_col135);
    let wg_v3056 = eval.m31_add(carry_22_col135, m31_524288);
    eval.set_sub_input_word(139, wg_v3056);
    eval.set_lookup_word(131, m31_682009131);
    let wg_v3057 = eval.m31_add(carry_22_col135, m31_524288);
    eval.set_lookup_word(132, wg_v3057);
    let wg_v3058 = eval.m31_add(conv_mod_tmp_fec87_46[23], carry_22_col135);
    let carry_23_col136 = eval.m31_mul(wg_v3058, m31_4194304);
    eval.set_col(136, carry_23_col136);
    let wg_v3059 = eval.m31_add(carry_23_col136, m31_524288);
    eval.set_sub_input_word(91, wg_v3059);
    eval.set_lookup_word(35, m31_1410849886);
    let wg_v3060 = eval.m31_add(carry_23_col136, m31_524288);
    eval.set_lookup_word(36, wg_v3060);
    let wg_v3061 = eval.m31_add(conv_mod_tmp_fec87_46[24], carry_23_col136);
    let carry_24_col137 = eval.m31_mul(wg_v3061, m31_4194304);
    eval.set_col(137, carry_24_col137);
    let wg_v3062 = eval.m31_add(carry_24_col137, m31_524288);
    eval.set_sub_input_word(99, wg_v3062);
    eval.set_lookup_word(51, m31_514232941);
    let wg_v3063 = eval.m31_add(carry_24_col137, m31_524288);
    eval.set_lookup_word(52, wg_v3063);
    let wg_v3064 = eval.m31_add(conv_mod_tmp_fec87_46[25], carry_24_col137);
    let carry_25_col138 = eval.m31_mul(wg_v3064, m31_4194304);
    eval.set_col(138, carry_25_col138);
    let wg_v3065 = eval.m31_add(carry_25_col138, m31_524288);
    eval.set_sub_input_word(107, wg_v3065);
    eval.set_lookup_word(67, m31_531010560);
    let wg_v3066 = eval.m31_add(carry_25_col138, m31_524288);
    eval.set_lookup_word(68, wg_v3066);
    let wg_v3067 = eval.m31_add(conv_mod_tmp_fec87_46[26], carry_25_col138);
    let carry_26_col139 = eval.m31_mul(wg_v3067, m31_4194304);
    eval.set_col(139, carry_26_col139);
    let wg_v3068 = eval.m31_add(carry_26_col139, m31_524288);
    eval.set_sub_input_word(115, wg_v3068);
    eval.set_lookup_word(83, m31_480677703);
    let wg_v3069 = eval.m31_add(carry_26_col139, m31_524288);
    eval.set_lookup_word(84, wg_v3069);
    let mul_252_output_tmp_fec87_48 = mul_res_tmp_fec87_26.clone();
    eval.set_lookup_word(0, m31_1987997202);
    eval.set_lookup_word(1, input_limb_0_col0);
    eval.set_lookup_word(2, input_limb_1_col1);
    eval.set_lookup_word(3, input_limb_2_col2);
    eval.set_lookup_word(4, input_limb_3_col3);
    eval.set_lookup_word(5, input_limb_4_col4);
    eval.set_lookup_word(6, input_limb_5_col5);
    eval.set_lookup_word(7, input_limb_6_col6);
    eval.set_lookup_word(8, input_limb_7_col7);
    eval.set_lookup_word(9, input_limb_8_col8);
    eval.set_lookup_word(10, input_limb_9_col9);
    let wg_v3070 = eval.m31_mul(mul_res_limb_1_col85, m31_512);
    let wg_v3071 = eval.m31_add(mul_res_limb_0_col84, wg_v3070);
    let wg_v3072 = eval.m31_mul(mul_res_limb_2_col86, m31_262144);
    let wg_v3073 = eval.m31_add(wg_v3071, wg_v3072);
    eval.set_lookup_word(11, wg_v3073);
    let wg_v3074 = eval.m31_mul(mul_res_limb_4_col88, m31_512);
    let wg_v3075 = eval.m31_add(mul_res_limb_3_col87, wg_v3074);
    let wg_v3076 = eval.m31_mul(mul_res_limb_5_col89, m31_262144);
    let wg_v3077 = eval.m31_add(wg_v3075, wg_v3076);
    eval.set_lookup_word(12, wg_v3077);
    let wg_v3078 = eval.m31_mul(mul_res_limb_7_col91, m31_512);
    let wg_v3079 = eval.m31_add(mul_res_limb_6_col90, wg_v3078);
    let wg_v3080 = eval.m31_mul(mul_res_limb_8_col92, m31_262144);
    let wg_v3081 = eval.m31_add(wg_v3079, wg_v3080);
    eval.set_lookup_word(13, wg_v3081);
    let wg_v3082 = eval.m31_mul(mul_res_limb_10_col94, m31_512);
    let wg_v3083 = eval.m31_add(mul_res_limb_9_col93, wg_v3082);
    let wg_v3084 = eval.m31_mul(mul_res_limb_11_col95, m31_262144);
    let wg_v3085 = eval.m31_add(wg_v3083, wg_v3084);
    eval.set_lookup_word(14, wg_v3085);
    let wg_v3086 = eval.m31_mul(mul_res_limb_13_col97, m31_512);
    let wg_v3087 = eval.m31_add(mul_res_limb_12_col96, wg_v3086);
    let wg_v3088 = eval.m31_mul(mul_res_limb_14_col98, m31_262144);
    let wg_v3089 = eval.m31_add(wg_v3087, wg_v3088);
    eval.set_lookup_word(15, wg_v3089);
    let wg_v3090 = eval.m31_mul(mul_res_limb_16_col100, m31_512);
    let wg_v3091 = eval.m31_add(mul_res_limb_15_col99, wg_v3090);
    let wg_v3092 = eval.m31_mul(mul_res_limb_17_col101, m31_262144);
    let wg_v3093 = eval.m31_add(wg_v3091, wg_v3092);
    eval.set_lookup_word(16, wg_v3093);
    let wg_v3094 = eval.m31_mul(mul_res_limb_19_col103, m31_512);
    let wg_v3095 = eval.m31_add(mul_res_limb_18_col102, wg_v3094);
    let wg_v3096 = eval.m31_mul(mul_res_limb_20_col104, m31_262144);
    let wg_v3097 = eval.m31_add(wg_v3095, wg_v3096);
    eval.set_lookup_word(17, wg_v3097);
    let wg_v3098 = eval.m31_mul(mul_res_limb_22_col106, m31_512);
    let wg_v3099 = eval.m31_add(mul_res_limb_21_col105, wg_v3098);
    let wg_v3100 = eval.m31_mul(mul_res_limb_23_col107, m31_262144);
    let wg_v3101 = eval.m31_add(wg_v3099, wg_v3100);
    eval.set_lookup_word(18, wg_v3101);
    let wg_v3102 = eval.m31_mul(mul_res_limb_25_col109, m31_512);
    let wg_v3103 = eval.m31_add(mul_res_limb_24_col108, wg_v3102);
    let wg_v3104 = eval.m31_mul(mul_res_limb_26_col110, m31_262144);
    let wg_v3105 = eval.m31_add(wg_v3103, wg_v3104);
    eval.set_lookup_word(19, wg_v3105);
    eval.set_lookup_word(20, mul_res_limb_27_col111);
    let wg_v3106 = eval.enabler();
    eval.set_col(140, wg_v3106);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `cube_252_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_20_state: &range_check_20::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = inputs.len().ilog2();
    let log_size = log_n_packed_rows + LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };
    let enabler_col = Enabler::new(n_rows);
    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, cube_252_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    None,
                    vec![
                        cube_252_input.get_m31(0).into_simd(),
                        cube_252_input.get_m31(1).into_simd(),
                        cube_252_input.get_m31(2).into_simd(),
                        cube_252_input.get_m31(3).into_simd(),
                        cube_252_input.get_m31(4).into_simd(),
                        cube_252_input.get_m31(5).into_simd(),
                        cube_252_input.get_m31(6).into_simd(),
                        cube_252_input.get_m31(7).into_simd(),
                        cube_252_input.get_m31(8).into_simd(),
                        cube_252_input.get_m31(9).into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                cube_252_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.cube_252_0 = [
                    lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10],
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                ];
                *lookup_data.range_check_20_0 = [lw[21], lw[22]];
                *lookup_data.range_check_20_1 = [lw[23], lw[24]];
                *lookup_data.range_check_20_2 = [lw[25], lw[26]];
                *lookup_data.range_check_20_3 = [lw[27], lw[28]];
                *lookup_data.range_check_20_4 = [lw[29], lw[30]];
                *lookup_data.range_check_20_5 = [lw[31], lw[32]];
                *lookup_data.range_check_20_6 = [lw[33], lw[34]];
                *lookup_data.range_check_20_7 = [lw[35], lw[36]];
                *lookup_data.range_check_20_b_0 = [lw[37], lw[38]];
                *lookup_data.range_check_20_b_1 = [lw[39], lw[40]];
                *lookup_data.range_check_20_b_2 = [lw[41], lw[42]];
                *lookup_data.range_check_20_b_3 = [lw[43], lw[44]];
                *lookup_data.range_check_20_b_4 = [lw[45], lw[46]];
                *lookup_data.range_check_20_b_5 = [lw[47], lw[48]];
                *lookup_data.range_check_20_b_6 = [lw[49], lw[50]];
                *lookup_data.range_check_20_b_7 = [lw[51], lw[52]];
                *lookup_data.range_check_20_c_0 = [lw[53], lw[54]];
                *lookup_data.range_check_20_c_1 = [lw[55], lw[56]];
                *lookup_data.range_check_20_c_2 = [lw[57], lw[58]];
                *lookup_data.range_check_20_c_3 = [lw[59], lw[60]];
                *lookup_data.range_check_20_c_4 = [lw[61], lw[62]];
                *lookup_data.range_check_20_c_5 = [lw[63], lw[64]];
                *lookup_data.range_check_20_c_6 = [lw[65], lw[66]];
                *lookup_data.range_check_20_c_7 = [lw[67], lw[68]];
                *lookup_data.range_check_20_d_0 = [lw[69], lw[70]];
                *lookup_data.range_check_20_d_1 = [lw[71], lw[72]];
                *lookup_data.range_check_20_d_2 = [lw[73], lw[74]];
                *lookup_data.range_check_20_d_3 = [lw[75], lw[76]];
                *lookup_data.range_check_20_d_4 = [lw[77], lw[78]];
                *lookup_data.range_check_20_d_5 = [lw[79], lw[80]];
                *lookup_data.range_check_20_d_6 = [lw[81], lw[82]];
                *lookup_data.range_check_20_d_7 = [lw[83], lw[84]];
                *lookup_data.range_check_20_e_0 = [lw[85], lw[86]];
                *lookup_data.range_check_20_e_1 = [lw[87], lw[88]];
                *lookup_data.range_check_20_e_2 = [lw[89], lw[90]];
                *lookup_data.range_check_20_e_3 = [lw[91], lw[92]];
                *lookup_data.range_check_20_e_4 = [lw[93], lw[94]];
                *lookup_data.range_check_20_e_5 = [lw[95], lw[96]];
                *lookup_data.range_check_20_f_0 = [lw[97], lw[98]];
                *lookup_data.range_check_20_f_1 = [lw[99], lw[100]];
                *lookup_data.range_check_20_f_2 = [lw[101], lw[102]];
                *lookup_data.range_check_20_f_3 = [lw[103], lw[104]];
                *lookup_data.range_check_20_f_4 = [lw[105], lw[106]];
                *lookup_data.range_check_20_f_5 = [lw[107], lw[108]];
                *lookup_data.range_check_20_g_0 = [lw[109], lw[110]];
                *lookup_data.range_check_20_g_1 = [lw[111], lw[112]];
                *lookup_data.range_check_20_g_2 = [lw[113], lw[114]];
                *lookup_data.range_check_20_g_3 = [lw[115], lw[116]];
                *lookup_data.range_check_20_g_4 = [lw[117], lw[118]];
                *lookup_data.range_check_20_g_5 = [lw[119], lw[120]];
                *lookup_data.range_check_20_h_0 = [lw[121], lw[122]];
                *lookup_data.range_check_20_h_1 = [lw[123], lw[124]];
                *lookup_data.range_check_20_h_2 = [lw[125], lw[126]];
                *lookup_data.range_check_20_h_3 = [lw[127], lw[128]];
                *lookup_data.range_check_20_h_4 = [lw[129], lw[130]];
                *lookup_data.range_check_20_h_5 = [lw[131], lw[132]];
                *lookup_data.range_check_9_9_0 = [lw[133], lw[134], lw[135]];
                *lookup_data.range_check_9_9_1 = [lw[136], lw[137], lw[138]];
                *lookup_data.range_check_9_9_2 = [lw[139], lw[140], lw[141]];
                *lookup_data.range_check_9_9_3 = [lw[142], lw[143], lw[144]];
                *lookup_data.range_check_9_9_4 = [lw[145], lw[146], lw[147]];
                *lookup_data.range_check_9_9_5 = [lw[148], lw[149], lw[150]];
                *lookup_data.range_check_9_9_b_0 = [lw[151], lw[152], lw[153]];
                *lookup_data.range_check_9_9_b_1 = [lw[154], lw[155], lw[156]];
                *lookup_data.range_check_9_9_b_2 = [lw[157], lw[158], lw[159]];
                *lookup_data.range_check_9_9_b_3 = [lw[160], lw[161], lw[162]];
                *lookup_data.range_check_9_9_b_4 = [lw[163], lw[164], lw[165]];
                *lookup_data.range_check_9_9_b_5 = [lw[166], lw[167], lw[168]];
                *lookup_data.range_check_9_9_c_0 = [lw[169], lw[170], lw[171]];
                *lookup_data.range_check_9_9_c_1 = [lw[172], lw[173], lw[174]];
                *lookup_data.range_check_9_9_c_2 = [lw[175], lw[176], lw[177]];
                *lookup_data.range_check_9_9_c_3 = [lw[178], lw[179], lw[180]];
                *lookup_data.range_check_9_9_c_4 = [lw[181], lw[182], lw[183]];
                *lookup_data.range_check_9_9_c_5 = [lw[184], lw[185], lw[186]];
                *lookup_data.range_check_9_9_d_0 = [lw[187], lw[188], lw[189]];
                *lookup_data.range_check_9_9_d_1 = [lw[190], lw[191], lw[192]];
                *lookup_data.range_check_9_9_d_2 = [lw[193], lw[194], lw[195]];
                *lookup_data.range_check_9_9_d_3 = [lw[196], lw[197], lw[198]];
                *lookup_data.range_check_9_9_d_4 = [lw[199], lw[200], lw[201]];
                *lookup_data.range_check_9_9_d_5 = [lw[202], lw[203], lw[204]];
                *lookup_data.range_check_9_9_e_0 = [lw[205], lw[206], lw[207]];
                *lookup_data.range_check_9_9_e_1 = [lw[208], lw[209], lw[210]];
                *lookup_data.range_check_9_9_e_2 = [lw[211], lw[212], lw[213]];
                *lookup_data.range_check_9_9_e_3 = [lw[214], lw[215], lw[216]];
                *lookup_data.range_check_9_9_e_4 = [lw[217], lw[218], lw[219]];
                *lookup_data.range_check_9_9_e_5 = [lw[220], lw[221], lw[222]];
                *lookup_data.range_check_9_9_f_0 = [lw[223], lw[224], lw[225]];
                *lookup_data.range_check_9_9_f_1 = [lw[226], lw[227], lw[228]];
                *lookup_data.range_check_9_9_f_2 = [lw[229], lw[230], lw[231]];
                *lookup_data.range_check_9_9_f_3 = [lw[232], lw[233], lw[234]];
                *lookup_data.range_check_9_9_f_4 = [lw[235], lw[236], lw[237]];
                *lookup_data.range_check_9_9_f_5 = [lw[238], lw[239], lw[240]];
                *lookup_data.range_check_9_9_g_0 = [lw[241], lw[242], lw[243]];
                *lookup_data.range_check_9_9_g_1 = [lw[244], lw[245], lw[246]];
                *lookup_data.range_check_9_9_g_2 = [lw[247], lw[248], lw[249]];
                *lookup_data.range_check_9_9_h_0 = [lw[250], lw[251], lw[252]];
                *lookup_data.range_check_9_9_h_1 = [lw[253], lw[254], lw[255]];
                *lookup_data.range_check_9_9_h_2 = [lw[256], lw[257], lw[258]];
                let sw = eval.sub_scratch();
                *sub_component_inputs.range_check_9_9[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[0]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[1])
                    }];
                *sub_component_inputs.range_check_9_9[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[2]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[3])
                    }];
                *sub_component_inputs.range_check_9_9[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[4]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[5])
                    }];
                *sub_component_inputs.range_check_9_9[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[6]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[7])
                    }];
                *sub_component_inputs.range_check_9_9[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[8]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[9])
                    }];
                *sub_component_inputs.range_check_9_9[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[10]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[11])
                    }];
                *sub_component_inputs.range_check_9_9_b[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[12]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[13])
                    }];
                *sub_component_inputs.range_check_9_9_b[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[14]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[15])
                    }];
                *sub_component_inputs.range_check_9_9_b[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[16]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[17])
                    }];
                *sub_component_inputs.range_check_9_9_b[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[18]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[19])
                    }];
                *sub_component_inputs.range_check_9_9_b[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[20]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[21])
                    }];
                *sub_component_inputs.range_check_9_9_b[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[22]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[23])
                    }];
                *sub_component_inputs.range_check_9_9_c[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[24]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[25])
                    }];
                *sub_component_inputs.range_check_9_9_c[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[26]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[27])
                    }];
                *sub_component_inputs.range_check_9_9_c[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[28]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[29])
                    }];
                *sub_component_inputs.range_check_9_9_c[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[30]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[31])
                    }];
                *sub_component_inputs.range_check_9_9_c[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[32]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[33])
                    }];
                *sub_component_inputs.range_check_9_9_c[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[34]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[35])
                    }];
                *sub_component_inputs.range_check_9_9_d[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[36]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[37])
                    }];
                *sub_component_inputs.range_check_9_9_d[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[38]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[39])
                    }];
                *sub_component_inputs.range_check_9_9_d[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[40]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[41])
                    }];
                *sub_component_inputs.range_check_9_9_d[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[42]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[43])
                    }];
                *sub_component_inputs.range_check_9_9_d[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[44]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[45])
                    }];
                *sub_component_inputs.range_check_9_9_d[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[46]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[47])
                    }];
                *sub_component_inputs.range_check_9_9_e[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[48]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[49])
                    }];
                *sub_component_inputs.range_check_9_9_e[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[50]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[51])
                    }];
                *sub_component_inputs.range_check_9_9_e[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[52]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[53])
                    }];
                *sub_component_inputs.range_check_9_9_e[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[54]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[55])
                    }];
                *sub_component_inputs.range_check_9_9_e[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[56]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[57])
                    }];
                *sub_component_inputs.range_check_9_9_e[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[58]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[59])
                    }];
                *sub_component_inputs.range_check_9_9_f[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[60]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[61])
                    }];
                *sub_component_inputs.range_check_9_9_f[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[62]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[63])
                    }];
                *sub_component_inputs.range_check_9_9_f[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[64]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[65])
                    }];
                *sub_component_inputs.range_check_9_9_f[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[66]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[67])
                    }];
                *sub_component_inputs.range_check_9_9_f[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[68]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[69])
                    }];
                *sub_component_inputs.range_check_9_9_f[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[70]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[71])
                    }];
                *sub_component_inputs.range_check_9_9_g[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[72]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[73])
                    }];
                *sub_component_inputs.range_check_9_9_g[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[74]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[75])
                    }];
                *sub_component_inputs.range_check_9_9_g[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[76]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[77])
                    }];
                *sub_component_inputs.range_check_9_9_h[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[78]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[79])
                    }];
                *sub_component_inputs.range_check_9_9_h[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[80]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[81])
                    }];
                *sub_component_inputs.range_check_9_9_h[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[82]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[83])
                    }];
                *sub_component_inputs.range_check_20[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[84]) }];
                *sub_component_inputs.range_check_20[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[85]) }];
                *sub_component_inputs.range_check_20[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[86]) }];
                *sub_component_inputs.range_check_20[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[87]) }];
                *sub_component_inputs.range_check_20[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[88]) }];
                *sub_component_inputs.range_check_20[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[89]) }];
                *sub_component_inputs.range_check_20[6] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[90]) }];
                *sub_component_inputs.range_check_20[7] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[91]) }];
                *sub_component_inputs.range_check_20_b[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[92]) }];
                *sub_component_inputs.range_check_20_b[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[93]) }];
                *sub_component_inputs.range_check_20_b[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[94]) }];
                *sub_component_inputs.range_check_20_b[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[95]) }];
                *sub_component_inputs.range_check_20_b[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[96]) }];
                *sub_component_inputs.range_check_20_b[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[97]) }];
                *sub_component_inputs.range_check_20_b[6] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[98]) }];
                *sub_component_inputs.range_check_20_b[7] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[99]) }];
                *sub_component_inputs.range_check_20_c[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[100]) }];
                *sub_component_inputs.range_check_20_c[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[101]) }];
                *sub_component_inputs.range_check_20_c[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[102]) }];
                *sub_component_inputs.range_check_20_c[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[103]) }];
                *sub_component_inputs.range_check_20_c[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[104]) }];
                *sub_component_inputs.range_check_20_c[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[105]) }];
                *sub_component_inputs.range_check_20_c[6] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[106]) }];
                *sub_component_inputs.range_check_20_c[7] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[107]) }];
                *sub_component_inputs.range_check_20_d[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[108]) }];
                *sub_component_inputs.range_check_20_d[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[109]) }];
                *sub_component_inputs.range_check_20_d[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[110]) }];
                *sub_component_inputs.range_check_20_d[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[111]) }];
                *sub_component_inputs.range_check_20_d[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[112]) }];
                *sub_component_inputs.range_check_20_d[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[113]) }];
                *sub_component_inputs.range_check_20_d[6] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[114]) }];
                *sub_component_inputs.range_check_20_d[7] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[115]) }];
                *sub_component_inputs.range_check_20_e[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[116]) }];
                *sub_component_inputs.range_check_20_e[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[117]) }];
                *sub_component_inputs.range_check_20_e[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[118]) }];
                *sub_component_inputs.range_check_20_e[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[119]) }];
                *sub_component_inputs.range_check_20_e[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[120]) }];
                *sub_component_inputs.range_check_20_e[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[121]) }];
                *sub_component_inputs.range_check_20_f[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[122]) }];
                *sub_component_inputs.range_check_20_f[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[123]) }];
                *sub_component_inputs.range_check_20_f[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[124]) }];
                *sub_component_inputs.range_check_20_f[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[125]) }];
                *sub_component_inputs.range_check_20_f[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[126]) }];
                *sub_component_inputs.range_check_20_f[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[127]) }];
                *sub_component_inputs.range_check_20_g[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[128]) }];
                *sub_component_inputs.range_check_20_g[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[129]) }];
                *sub_component_inputs.range_check_20_g[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[130]) }];
                *sub_component_inputs.range_check_20_g[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[131]) }];
                *sub_component_inputs.range_check_20_g[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[132]) }];
                *sub_component_inputs.range_check_20_g[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[133]) }];
                *sub_component_inputs.range_check_20_h[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[134]) }];
                *sub_component_inputs.range_check_20_h[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[135]) }];
                *sub_component_inputs.range_check_20_h[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[136]) }];
                *sub_component_inputs.range_check_20_h[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[137]) }];
                *sub_component_inputs.range_check_20_h[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[138]) }];
                *sub_component_inputs.range_check_20_h[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[139]) }];
            },
        );
    (trace, lookup_data, sub_component_inputs)
}

impl ClaimGenerator {
    /// Generic-path counterpart of [`ClaimGenerator::write_trace`]: identical shape, but
    /// the base trace is produced by `write_trace_generic_simd`.
    #[allow(dead_code)]
    pub(crate) fn write_trace_generic(
        self,
        range_check_9_9_state: &range_check_9_9::ClaimGenerator,
        range_check_20_state: &range_check_20::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut packed_inputs = self.packed_inputs.into_inner().unwrap();
        assert!(!packed_inputs.is_empty());
        assert!(self.remainder_inputs.lock().unwrap().is_empty());
        let n_vec_rows = packed_inputs.len();
        let n_rows = n_vec_rows * N_LANES;
        let packed_size = n_vec_rows.next_power_of_two();
        let log_size = packed_size.ilog2() + LOG_N_LANES;
        packed_inputs.resize(packed_size, *packed_inputs.first().unwrap());
        const RAYON_THREAD_STACK_SIZE: usize = 1024 * 1024 * 8;
        let pool = rayon::ThreadPoolBuilder::new()
            .stack_size(RAYON_THREAD_STACK_SIZE)
            .build()
            .unwrap();
        let (trace, lookup_data, sub_component_inputs) = pool.install(|| {
            write_trace_generic_simd(
                packed_inputs,
                n_rows,
                range_check_9_9_state,
                range_check_20_state,
            )
        });
        for inputs in sub_component_inputs.range_check_9_9 {
            range_check_9_9_state.add_packed_inputs(&inputs, 0);
        }
        for inputs in sub_component_inputs.range_check_9_9_b {
            range_check_9_9_state.add_packed_inputs(&inputs, 1);
        }
        for inputs in sub_component_inputs.range_check_9_9_c {
            range_check_9_9_state.add_packed_inputs(&inputs, 2);
        }
        for inputs in sub_component_inputs.range_check_9_9_d {
            range_check_9_9_state.add_packed_inputs(&inputs, 3);
        }
        for inputs in sub_component_inputs.range_check_9_9_e {
            range_check_9_9_state.add_packed_inputs(&inputs, 4);
        }
        for inputs in sub_component_inputs.range_check_9_9_f {
            range_check_9_9_state.add_packed_inputs(&inputs, 5);
        }
        for inputs in sub_component_inputs.range_check_9_9_g {
            range_check_9_9_state.add_packed_inputs(&inputs, 6);
        }
        for inputs in sub_component_inputs.range_check_9_9_h {
            range_check_9_9_state.add_packed_inputs(&inputs, 7);
        }
        for inputs in sub_component_inputs.range_check_20 {
            range_check_20_state.add_packed_inputs(&inputs, 0);
        }
        for inputs in sub_component_inputs.range_check_20_b {
            range_check_20_state.add_packed_inputs(&inputs, 1);
        }
        for inputs in sub_component_inputs.range_check_20_c {
            range_check_20_state.add_packed_inputs(&inputs, 2);
        }
        for inputs in sub_component_inputs.range_check_20_d {
            range_check_20_state.add_packed_inputs(&inputs, 3);
        }
        for inputs in sub_component_inputs.range_check_20_e {
            range_check_20_state.add_packed_inputs(&inputs, 4);
        }
        for inputs in sub_component_inputs.range_check_20_f {
            range_check_20_state.add_packed_inputs(&inputs, 5);
        }
        for inputs in sub_component_inputs.range_check_20_g {
            range_check_20_state.add_packed_inputs(&inputs, 6);
        }
        for inputs in sub_component_inputs.range_check_20_h {
            range_check_20_state.add_packed_inputs(&inputs, 7);
        }
        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                n_rows,
                log_size,
                lookup_data,
            },
        )
    }
}

/// Record the `cube_252` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_cube_252() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("cube_252", 10, Some(11));
    cube_252_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    with_n_rows 259;
    cube_252_0: 21,
    range_check_20_0: 2,
    range_check_20_1: 2,
    range_check_20_2: 2,
    range_check_20_3: 2,
    range_check_20_4: 2,
    range_check_20_5: 2,
    range_check_20_6: 2,
    range_check_20_7: 2,
    range_check_20_b_0: 2,
    range_check_20_b_1: 2,
    range_check_20_b_2: 2,
    range_check_20_b_3: 2,
    range_check_20_b_4: 2,
    range_check_20_b_5: 2,
    range_check_20_b_6: 2,
    range_check_20_b_7: 2,
    range_check_20_c_0: 2,
    range_check_20_c_1: 2,
    range_check_20_c_2: 2,
    range_check_20_c_3: 2,
    range_check_20_c_4: 2,
    range_check_20_c_5: 2,
    range_check_20_c_6: 2,
    range_check_20_c_7: 2,
    range_check_20_d_0: 2,
    range_check_20_d_1: 2,
    range_check_20_d_2: 2,
    range_check_20_d_3: 2,
    range_check_20_d_4: 2,
    range_check_20_d_5: 2,
    range_check_20_d_6: 2,
    range_check_20_d_7: 2,
    range_check_20_e_0: 2,
    range_check_20_e_1: 2,
    range_check_20_e_2: 2,
    range_check_20_e_3: 2,
    range_check_20_e_4: 2,
    range_check_20_e_5: 2,
    range_check_20_f_0: 2,
    range_check_20_f_1: 2,
    range_check_20_f_2: 2,
    range_check_20_f_3: 2,
    range_check_20_f_4: 2,
    range_check_20_f_5: 2,
    range_check_20_g_0: 2,
    range_check_20_g_1: 2,
    range_check_20_g_2: 2,
    range_check_20_g_3: 2,
    range_check_20_g_4: 2,
    range_check_20_g_5: 2,
    range_check_20_h_0: 2,
    range_check_20_h_1: 2,
    range_check_20_h_2: 2,
    range_check_20_h_3: 2,
    range_check_20_h_4: 2,
    range_check_20_h_5: 2,
    range_check_9_9_0: 3,
    range_check_9_9_1: 3,
    range_check_9_9_2: 3,
    range_check_9_9_3: 3,
    range_check_9_9_4: 3,
    range_check_9_9_5: 3,
    range_check_9_9_b_0: 3,
    range_check_9_9_b_1: 3,
    range_check_9_9_b_2: 3,
    range_check_9_9_b_3: 3,
    range_check_9_9_b_4: 3,
    range_check_9_9_b_5: 3,
    range_check_9_9_c_0: 3,
    range_check_9_9_c_1: 3,
    range_check_9_9_c_2: 3,
    range_check_9_9_c_3: 3,
    range_check_9_9_c_4: 3,
    range_check_9_9_c_5: 3,
    range_check_9_9_d_0: 3,
    range_check_9_9_d_1: 3,
    range_check_9_9_d_2: 3,
    range_check_9_9_d_3: 3,
    range_check_9_9_d_4: 3,
    range_check_9_9_d_5: 3,
    range_check_9_9_e_0: 3,
    range_check_9_9_e_1: 3,
    range_check_9_9_e_2: 3,
    range_check_9_9_e_3: 3,
    range_check_9_9_e_4: 3,
    range_check_9_9_e_5: 3,
    range_check_9_9_f_0: 3,
    range_check_9_9_f_1: 3,
    range_check_9_9_f_2: 3,
    range_check_9_9_f_3: 3,
    range_check_9_9_f_4: 3,
    range_check_9_9_f_5: 3,
    range_check_9_9_g_0: 3,
    range_check_9_9_g_1: 3,
    range_check_9_9_g_2: 3,
    range_check_9_9_h_0: 3,
    range_check_9_9_h_1: 3,
    range_check_9_9_h_2: 3,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 0, 2),
    ("range_check_9_9", 1, "range_check_9_9_state", 0, 2, 2),
    ("range_check_9_9", 2, "range_check_9_9_state", 0, 4, 2),
    ("range_check_9_9", 3, "range_check_9_9_state", 0, 6, 2),
    ("range_check_9_9", 4, "range_check_9_9_state", 0, 8, 2),
    ("range_check_9_9", 5, "range_check_9_9_state", 0, 10, 2),
    ("range_check_9_9_b", 0, "range_check_9_9_state", 1, 12, 2),
    ("range_check_9_9_b", 1, "range_check_9_9_state", 1, 14, 2),
    ("range_check_9_9_b", 2, "range_check_9_9_state", 1, 16, 2),
    ("range_check_9_9_b", 3, "range_check_9_9_state", 1, 18, 2),
    ("range_check_9_9_b", 4, "range_check_9_9_state", 1, 20, 2),
    ("range_check_9_9_b", 5, "range_check_9_9_state", 1, 22, 2),
    ("range_check_9_9_c", 0, "range_check_9_9_state", 2, 24, 2),
    ("range_check_9_9_c", 1, "range_check_9_9_state", 2, 26, 2),
    ("range_check_9_9_c", 2, "range_check_9_9_state", 2, 28, 2),
    ("range_check_9_9_c", 3, "range_check_9_9_state", 2, 30, 2),
    ("range_check_9_9_c", 4, "range_check_9_9_state", 2, 32, 2),
    ("range_check_9_9_c", 5, "range_check_9_9_state", 2, 34, 2),
    ("range_check_9_9_d", 0, "range_check_9_9_state", 3, 36, 2),
    ("range_check_9_9_d", 1, "range_check_9_9_state", 3, 38, 2),
    ("range_check_9_9_d", 2, "range_check_9_9_state", 3, 40, 2),
    ("range_check_9_9_d", 3, "range_check_9_9_state", 3, 42, 2),
    ("range_check_9_9_d", 4, "range_check_9_9_state", 3, 44, 2),
    ("range_check_9_9_d", 5, "range_check_9_9_state", 3, 46, 2),
    ("range_check_9_9_e", 0, "range_check_9_9_state", 4, 48, 2),
    ("range_check_9_9_e", 1, "range_check_9_9_state", 4, 50, 2),
    ("range_check_9_9_e", 2, "range_check_9_9_state", 4, 52, 2),
    ("range_check_9_9_e", 3, "range_check_9_9_state", 4, 54, 2),
    ("range_check_9_9_e", 4, "range_check_9_9_state", 4, 56, 2),
    ("range_check_9_9_e", 5, "range_check_9_9_state", 4, 58, 2),
    ("range_check_9_9_f", 0, "range_check_9_9_state", 5, 60, 2),
    ("range_check_9_9_f", 1, "range_check_9_9_state", 5, 62, 2),
    ("range_check_9_9_f", 2, "range_check_9_9_state", 5, 64, 2),
    ("range_check_9_9_f", 3, "range_check_9_9_state", 5, 66, 2),
    ("range_check_9_9_f", 4, "range_check_9_9_state", 5, 68, 2),
    ("range_check_9_9_f", 5, "range_check_9_9_state", 5, 70, 2),
    ("range_check_9_9_g", 0, "range_check_9_9_state", 6, 72, 2),
    ("range_check_9_9_g", 1, "range_check_9_9_state", 6, 74, 2),
    ("range_check_9_9_g", 2, "range_check_9_9_state", 6, 76, 2),
    ("range_check_9_9_h", 0, "range_check_9_9_state", 7, 78, 2),
    ("range_check_9_9_h", 1, "range_check_9_9_state", 7, 80, 2),
    ("range_check_9_9_h", 2, "range_check_9_9_state", 7, 82, 2),
    ("range_check_20", 0, "range_check_20_state", 0, 84, 1),
    ("range_check_20", 1, "range_check_20_state", 0, 85, 1),
    ("range_check_20", 2, "range_check_20_state", 0, 86, 1),
    ("range_check_20", 3, "range_check_20_state", 0, 87, 1),
    ("range_check_20", 4, "range_check_20_state", 0, 88, 1),
    ("range_check_20", 5, "range_check_20_state", 0, 89, 1),
    ("range_check_20", 6, "range_check_20_state", 0, 90, 1),
    ("range_check_20", 7, "range_check_20_state", 0, 91, 1),
    ("range_check_20_b", 0, "range_check_20_state", 1, 92, 1),
    ("range_check_20_b", 1, "range_check_20_state", 1, 93, 1),
    ("range_check_20_b", 2, "range_check_20_state", 1, 94, 1),
    ("range_check_20_b", 3, "range_check_20_state", 1, 95, 1),
    ("range_check_20_b", 4, "range_check_20_state", 1, 96, 1),
    ("range_check_20_b", 5, "range_check_20_state", 1, 97, 1),
    ("range_check_20_b", 6, "range_check_20_state", 1, 98, 1),
    ("range_check_20_b", 7, "range_check_20_state", 1, 99, 1),
    ("range_check_20_c", 0, "range_check_20_state", 2, 100, 1),
    ("range_check_20_c", 1, "range_check_20_state", 2, 101, 1),
    ("range_check_20_c", 2, "range_check_20_state", 2, 102, 1),
    ("range_check_20_c", 3, "range_check_20_state", 2, 103, 1),
    ("range_check_20_c", 4, "range_check_20_state", 2, 104, 1),
    ("range_check_20_c", 5, "range_check_20_state", 2, 105, 1),
    ("range_check_20_c", 6, "range_check_20_state", 2, 106, 1),
    ("range_check_20_c", 7, "range_check_20_state", 2, 107, 1),
    ("range_check_20_d", 0, "range_check_20_state", 3, 108, 1),
    ("range_check_20_d", 1, "range_check_20_state", 3, 109, 1),
    ("range_check_20_d", 2, "range_check_20_state", 3, 110, 1),
    ("range_check_20_d", 3, "range_check_20_state", 3, 111, 1),
    ("range_check_20_d", 4, "range_check_20_state", 3, 112, 1),
    ("range_check_20_d", 5, "range_check_20_state", 3, 113, 1),
    ("range_check_20_d", 6, "range_check_20_state", 3, 114, 1),
    ("range_check_20_d", 7, "range_check_20_state", 3, 115, 1),
    ("range_check_20_e", 0, "range_check_20_state", 4, 116, 1),
    ("range_check_20_e", 1, "range_check_20_state", 4, 117, 1),
    ("range_check_20_e", 2, "range_check_20_state", 4, 118, 1),
    ("range_check_20_e", 3, "range_check_20_state", 4, 119, 1),
    ("range_check_20_e", 4, "range_check_20_state", 4, 120, 1),
    ("range_check_20_e", 5, "range_check_20_state", 4, 121, 1),
    ("range_check_20_f", 0, "range_check_20_state", 5, 122, 1),
    ("range_check_20_f", 1, "range_check_20_state", 5, 123, 1),
    ("range_check_20_f", 2, "range_check_20_state", 5, 124, 1),
    ("range_check_20_f", 3, "range_check_20_state", 5, 125, 1),
    ("range_check_20_f", 4, "range_check_20_state", 5, 126, 1),
    ("range_check_20_f", 5, "range_check_20_state", 5, 127, 1),
    ("range_check_20_g", 0, "range_check_20_state", 6, 128, 1),
    ("range_check_20_g", 1, "range_check_20_state", 6, 129, 1),
    ("range_check_20_g", 2, "range_check_20_state", 6, 130, 1),
    ("range_check_20_g", 3, "range_check_20_state", 6, 131, 1),
    ("range_check_20_g", 4, "range_check_20_state", 6, 132, 1),
    ("range_check_20_g", 5, "range_check_20_state", 6, 133, 1),
    ("range_check_20_h", 0, "range_check_20_state", 7, 134, 1),
    ("range_check_20_h", 1, "range_check_20_state", 7, 135, 1),
    ("range_check_20_h", 2, "range_check_20_state", 7, 136, 1),
    ("range_check_20_h", 3, "range_check_20_state", 7, 137, 1),
    ("range_check_20_h", 4, "range_check_20_state", 7, 138, 1),
    ("range_check_20_h", 5, "range_check_20_state", 7, 139, 1),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "range_check_9_9_0",
        "1",
        false,
        "range_check_9_9_b_0",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_0",
        "1",
        false,
        "range_check_9_9_d_0",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_0",
        "1",
        false,
        "range_check_9_9_f_0",
        "1",
        false,
    ),
    (
        "range_check_9_9_g_0",
        "1",
        false,
        "range_check_9_9_h_0",
        "1",
        false,
    ),
    (
        "range_check_9_9_1",
        "1",
        false,
        "range_check_9_9_b_1",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_1",
        "1",
        false,
        "range_check_9_9_d_1",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_1",
        "1",
        false,
        "range_check_9_9_f_1",
        "1",
        false,
    ),
    (
        "range_check_9_9_2",
        "1",
        false,
        "range_check_9_9_b_2",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_2",
        "1",
        false,
        "range_check_9_9_d_2",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_2",
        "1",
        false,
        "range_check_9_9_f_2",
        "1",
        false,
    ),
    (
        "range_check_9_9_g_1",
        "1",
        false,
        "range_check_9_9_h_1",
        "1",
        false,
    ),
    (
        "range_check_9_9_3",
        "1",
        false,
        "range_check_9_9_b_3",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_3",
        "1",
        false,
        "range_check_9_9_d_3",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_3",
        "1",
        false,
        "range_check_9_9_f_3",
        "1",
        false,
    ),
    (
        "range_check_20_0",
        "1",
        false,
        "range_check_20_b_0",
        "1",
        false,
    ),
    (
        "range_check_20_c_0",
        "1",
        false,
        "range_check_20_d_0",
        "1",
        false,
    ),
    (
        "range_check_20_e_0",
        "1",
        false,
        "range_check_20_f_0",
        "1",
        false,
    ),
    (
        "range_check_20_g_0",
        "1",
        false,
        "range_check_20_h_0",
        "1",
        false,
    ),
    (
        "range_check_20_1",
        "1",
        false,
        "range_check_20_b_1",
        "1",
        false,
    ),
    (
        "range_check_20_c_1",
        "1",
        false,
        "range_check_20_d_1",
        "1",
        false,
    ),
    (
        "range_check_20_e_1",
        "1",
        false,
        "range_check_20_f_1",
        "1",
        false,
    ),
    (
        "range_check_20_g_1",
        "1",
        false,
        "range_check_20_h_1",
        "1",
        false,
    ),
    (
        "range_check_20_2",
        "1",
        false,
        "range_check_20_b_2",
        "1",
        false,
    ),
    (
        "range_check_20_c_2",
        "1",
        false,
        "range_check_20_d_2",
        "1",
        false,
    ),
    (
        "range_check_20_e_2",
        "1",
        false,
        "range_check_20_f_2",
        "1",
        false,
    ),
    (
        "range_check_20_g_2",
        "1",
        false,
        "range_check_20_h_2",
        "1",
        false,
    ),
    (
        "range_check_20_3",
        "1",
        false,
        "range_check_20_b_3",
        "1",
        false,
    ),
    (
        "range_check_20_c_3",
        "1",
        false,
        "range_check_20_d_3",
        "1",
        false,
    ),
    (
        "range_check_9_9_4",
        "1",
        false,
        "range_check_9_9_b_4",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_4",
        "1",
        false,
        "range_check_9_9_d_4",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_4",
        "1",
        false,
        "range_check_9_9_f_4",
        "1",
        false,
    ),
    (
        "range_check_9_9_g_2",
        "1",
        false,
        "range_check_9_9_h_2",
        "1",
        false,
    ),
    (
        "range_check_9_9_5",
        "1",
        false,
        "range_check_9_9_b_5",
        "1",
        false,
    ),
    (
        "range_check_9_9_c_5",
        "1",
        false,
        "range_check_9_9_d_5",
        "1",
        false,
    ),
    (
        "range_check_9_9_e_5",
        "1",
        false,
        "range_check_9_9_f_5",
        "1",
        false,
    ),
    (
        "range_check_20_4",
        "1",
        false,
        "range_check_20_b_4",
        "1",
        false,
    ),
    (
        "range_check_20_c_4",
        "1",
        false,
        "range_check_20_d_4",
        "1",
        false,
    ),
    (
        "range_check_20_e_3",
        "1",
        false,
        "range_check_20_f_3",
        "1",
        false,
    ),
    (
        "range_check_20_g_3",
        "1",
        false,
        "range_check_20_h_3",
        "1",
        false,
    ),
    (
        "range_check_20_5",
        "1",
        false,
        "range_check_20_b_5",
        "1",
        false,
    ),
    (
        "range_check_20_c_5",
        "1",
        false,
        "range_check_20_d_5",
        "1",
        false,
    ),
    (
        "range_check_20_e_4",
        "1",
        false,
        "range_check_20_f_4",
        "1",
        false,
    ),
    (
        "range_check_20_g_4",
        "1",
        false,
        "range_check_20_h_4",
        "1",
        false,
    ),
    (
        "range_check_20_6",
        "1",
        false,
        "range_check_20_b_6",
        "1",
        false,
    ),
    (
        "range_check_20_c_6",
        "1",
        false,
        "range_check_20_d_6",
        "1",
        false,
    ),
    (
        "range_check_20_e_5",
        "1",
        false,
        "range_check_20_f_5",
        "1",
        false,
    ),
    (
        "range_check_20_g_5",
        "1",
        false,
        "range_check_20_h_5",
        "1",
        false,
    ),
    (
        "range_check_20_7",
        "1",
        false,
        "range_check_20_b_7",
        "1",
        false,
    ),
    (
        "range_check_20_c_7",
        "1",
        false,
        "range_check_20_d_7",
        "1",
        false,
    ),
    ("cube_252_0", "enabler", true, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.cube_252_0.iter().flatten().copied().collect(),
        ld.range_check_20_0.iter().flatten().copied().collect(),
        ld.range_check_20_1.iter().flatten().copied().collect(),
        ld.range_check_20_2.iter().flatten().copied().collect(),
        ld.range_check_20_3.iter().flatten().copied().collect(),
        ld.range_check_20_4.iter().flatten().copied().collect(),
        ld.range_check_20_5.iter().flatten().copied().collect(),
        ld.range_check_20_6.iter().flatten().copied().collect(),
        ld.range_check_20_7.iter().flatten().copied().collect(),
        ld.range_check_20_b_0.iter().flatten().copied().collect(),
        ld.range_check_20_b_1.iter().flatten().copied().collect(),
        ld.range_check_20_b_2.iter().flatten().copied().collect(),
        ld.range_check_20_b_3.iter().flatten().copied().collect(),
        ld.range_check_20_b_4.iter().flatten().copied().collect(),
        ld.range_check_20_b_5.iter().flatten().copied().collect(),
        ld.range_check_20_b_6.iter().flatten().copied().collect(),
        ld.range_check_20_b_7.iter().flatten().copied().collect(),
        ld.range_check_20_c_0.iter().flatten().copied().collect(),
        ld.range_check_20_c_1.iter().flatten().copied().collect(),
        ld.range_check_20_c_2.iter().flatten().copied().collect(),
        ld.range_check_20_c_3.iter().flatten().copied().collect(),
        ld.range_check_20_c_4.iter().flatten().copied().collect(),
        ld.range_check_20_c_5.iter().flatten().copied().collect(),
        ld.range_check_20_c_6.iter().flatten().copied().collect(),
        ld.range_check_20_c_7.iter().flatten().copied().collect(),
        ld.range_check_20_d_0.iter().flatten().copied().collect(),
        ld.range_check_20_d_1.iter().flatten().copied().collect(),
        ld.range_check_20_d_2.iter().flatten().copied().collect(),
        ld.range_check_20_d_3.iter().flatten().copied().collect(),
        ld.range_check_20_d_4.iter().flatten().copied().collect(),
        ld.range_check_20_d_5.iter().flatten().copied().collect(),
        ld.range_check_20_d_6.iter().flatten().copied().collect(),
        ld.range_check_20_d_7.iter().flatten().copied().collect(),
        ld.range_check_20_e_0.iter().flatten().copied().collect(),
        ld.range_check_20_e_1.iter().flatten().copied().collect(),
        ld.range_check_20_e_2.iter().flatten().copied().collect(),
        ld.range_check_20_e_3.iter().flatten().copied().collect(),
        ld.range_check_20_e_4.iter().flatten().copied().collect(),
        ld.range_check_20_e_5.iter().flatten().copied().collect(),
        ld.range_check_20_f_0.iter().flatten().copied().collect(),
        ld.range_check_20_f_1.iter().flatten().copied().collect(),
        ld.range_check_20_f_2.iter().flatten().copied().collect(),
        ld.range_check_20_f_3.iter().flatten().copied().collect(),
        ld.range_check_20_f_4.iter().flatten().copied().collect(),
        ld.range_check_20_f_5.iter().flatten().copied().collect(),
        ld.range_check_20_g_0.iter().flatten().copied().collect(),
        ld.range_check_20_g_1.iter().flatten().copied().collect(),
        ld.range_check_20_g_2.iter().flatten().copied().collect(),
        ld.range_check_20_g_3.iter().flatten().copied().collect(),
        ld.range_check_20_g_4.iter().flatten().copied().collect(),
        ld.range_check_20_g_5.iter().flatten().copied().collect(),
        ld.range_check_20_h_0.iter().flatten().copied().collect(),
        ld.range_check_20_h_1.iter().flatten().copied().collect(),
        ld.range_check_20_h_2.iter().flatten().copied().collect(),
        ld.range_check_20_h_3.iter().flatten().copied().collect(),
        ld.range_check_20_h_4.iter().flatten().copied().collect(),
        ld.range_check_20_h_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_3.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_4.iter().flatten().copied().collect(),
        ld.range_check_9_9_f_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_g_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_g_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_g_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_h_0.iter().flatten().copied().collect(),
        ld.range_check_9_9_h_1.iter().flatten().copied().collect(),
        ld.range_check_9_9_h_2.iter().flatten().copied().collect(),
    ]
}

#[cfg(test)]
pub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator) -> Vec<Vec<PackedM31>> {
    lookup_data_flat(&ig.lookup_data)
}

fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
    vec![
        sci.range_check_9_9[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_f[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_g[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_g[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_g[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_h[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_h[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_h[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
    ]
}

/// Byte-comparison bundle (only public types cross the module boundary).
#[cfg(test)]
pub(crate) struct GenericSimdDiff {
    pub log_size: u32,
    pub orig_rows: Vec<[M31; N_TRACE_COLUMNS]>,
    pub gen_rows: Vec<[M31; N_TRACE_COLUMNS]>,
    pub orig_lookup: Vec<Vec<PackedM31>>,
    pub gen_lookup: Vec<Vec<PackedM31>>,
    pub orig_sub: Vec<Vec<Simd<u32, N_LANES>>>,
    pub gen_sub: Vec<Vec<Simd<u32, N_LANES>>>,
    pub orig_interaction_cols: Vec<Vec<M31>>,
    pub gen_interaction_cols: Vec<Vec<M31>>,
    pub orig_claimed_sum: SecureField,
    pub gen_claimed_sum: SecureField,
}

/// Run BOTH SIMD writers on the same (pure-read) states and return public compare data.
#[cfg(test)]
pub(crate) fn generic_simd_diff(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_20_state: &range_check_20::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        range_check_9_9_state,
        range_check_20_state,
    );
    let (trace_g, ld_g, sci_g) =
        write_trace_generic_simd(inputs, n_rows, range_check_9_9_state, range_check_20_state);
    let log_size = trace_o.log_size();
    let orig_rows = (0..(1usize << log_size))
        .map(|r| trace_o.row_at(r))
        .collect();
    let gen_rows = (0..(1usize << log_size))
        .map(|r| trace_g.row_at(r))
        .collect();
    let orig_lookup = lookup_data_flat(&ld_o);
    let gen_lookup = lookup_data_flat(&ld_g);
    let orig_sub = sub_inputs_flat(&sci_o);
    let gen_sub = sub_inputs_flat(&sci_g);
    let common = relations::CommonLookupElements::dummy();
    let (raw_o, _) = InteractionClaimGenerator {
        log_size,
        n_rows,
        lookup_data: ld_o,
    }
    .write_interaction_trace(&common);
    let (raw_g, _) = InteractionClaimGenerator {
        log_size,
        n_rows,
        lookup_data: ld_g,
    }
    .write_interaction_trace(&common);
    let (cols_o, orig_claimed_sum) = raw_o.finalize_on_simd();
    let (cols_g, gen_claimed_sum) = raw_g.finalize_on_simd();
    let orig_interaction_cols = cols_o.iter().map(|c| c.values.to_cpu()).collect();
    let gen_interaction_cols = cols_g.iter().map(|c| c.values.to_cpu()).collect();
    GenericSimdDiff {
        log_size,
        orig_rows,
        gen_rows,
        orig_lookup,
        gen_lookup,
        orig_sub,
        gen_sub,
        orig_interaction_cols,
        gen_interaction_cols,
        orig_claimed_sum,
        gen_claimed_sum,
    }
}
// === END witness_genericize ===

#[derive(Uninitialized, IterMut, ParIterMut)]
struct LookupData {
    cube_252_0: Vec<[PackedM31; 21]>,
    range_check_20_0: Vec<[PackedM31; 2]>,
    range_check_20_1: Vec<[PackedM31; 2]>,
    range_check_20_2: Vec<[PackedM31; 2]>,
    range_check_20_3: Vec<[PackedM31; 2]>,
    range_check_20_4: Vec<[PackedM31; 2]>,
    range_check_20_5: Vec<[PackedM31; 2]>,
    range_check_20_6: Vec<[PackedM31; 2]>,
    range_check_20_7: Vec<[PackedM31; 2]>,
    range_check_20_b_0: Vec<[PackedM31; 2]>,
    range_check_20_b_1: Vec<[PackedM31; 2]>,
    range_check_20_b_2: Vec<[PackedM31; 2]>,
    range_check_20_b_3: Vec<[PackedM31; 2]>,
    range_check_20_b_4: Vec<[PackedM31; 2]>,
    range_check_20_b_5: Vec<[PackedM31; 2]>,
    range_check_20_b_6: Vec<[PackedM31; 2]>,
    range_check_20_b_7: Vec<[PackedM31; 2]>,
    range_check_20_c_0: Vec<[PackedM31; 2]>,
    range_check_20_c_1: Vec<[PackedM31; 2]>,
    range_check_20_c_2: Vec<[PackedM31; 2]>,
    range_check_20_c_3: Vec<[PackedM31; 2]>,
    range_check_20_c_4: Vec<[PackedM31; 2]>,
    range_check_20_c_5: Vec<[PackedM31; 2]>,
    range_check_20_c_6: Vec<[PackedM31; 2]>,
    range_check_20_c_7: Vec<[PackedM31; 2]>,
    range_check_20_d_0: Vec<[PackedM31; 2]>,
    range_check_20_d_1: Vec<[PackedM31; 2]>,
    range_check_20_d_2: Vec<[PackedM31; 2]>,
    range_check_20_d_3: Vec<[PackedM31; 2]>,
    range_check_20_d_4: Vec<[PackedM31; 2]>,
    range_check_20_d_5: Vec<[PackedM31; 2]>,
    range_check_20_d_6: Vec<[PackedM31; 2]>,
    range_check_20_d_7: Vec<[PackedM31; 2]>,
    range_check_20_e_0: Vec<[PackedM31; 2]>,
    range_check_20_e_1: Vec<[PackedM31; 2]>,
    range_check_20_e_2: Vec<[PackedM31; 2]>,
    range_check_20_e_3: Vec<[PackedM31; 2]>,
    range_check_20_e_4: Vec<[PackedM31; 2]>,
    range_check_20_e_5: Vec<[PackedM31; 2]>,
    range_check_20_f_0: Vec<[PackedM31; 2]>,
    range_check_20_f_1: Vec<[PackedM31; 2]>,
    range_check_20_f_2: Vec<[PackedM31; 2]>,
    range_check_20_f_3: Vec<[PackedM31; 2]>,
    range_check_20_f_4: Vec<[PackedM31; 2]>,
    range_check_20_f_5: Vec<[PackedM31; 2]>,
    range_check_20_g_0: Vec<[PackedM31; 2]>,
    range_check_20_g_1: Vec<[PackedM31; 2]>,
    range_check_20_g_2: Vec<[PackedM31; 2]>,
    range_check_20_g_3: Vec<[PackedM31; 2]>,
    range_check_20_g_4: Vec<[PackedM31; 2]>,
    range_check_20_g_5: Vec<[PackedM31; 2]>,
    range_check_20_h_0: Vec<[PackedM31; 2]>,
    range_check_20_h_1: Vec<[PackedM31; 2]>,
    range_check_20_h_2: Vec<[PackedM31; 2]>,
    range_check_20_h_3: Vec<[PackedM31; 2]>,
    range_check_20_h_4: Vec<[PackedM31; 2]>,
    range_check_20_h_5: Vec<[PackedM31; 2]>,
    range_check_9_9_0: Vec<[PackedM31; 3]>,
    range_check_9_9_1: Vec<[PackedM31; 3]>,
    range_check_9_9_2: Vec<[PackedM31; 3]>,
    range_check_9_9_3: Vec<[PackedM31; 3]>,
    range_check_9_9_4: Vec<[PackedM31; 3]>,
    range_check_9_9_5: Vec<[PackedM31; 3]>,
    range_check_9_9_b_0: Vec<[PackedM31; 3]>,
    range_check_9_9_b_1: Vec<[PackedM31; 3]>,
    range_check_9_9_b_2: Vec<[PackedM31; 3]>,
    range_check_9_9_b_3: Vec<[PackedM31; 3]>,
    range_check_9_9_b_4: Vec<[PackedM31; 3]>,
    range_check_9_9_b_5: Vec<[PackedM31; 3]>,
    range_check_9_9_c_0: Vec<[PackedM31; 3]>,
    range_check_9_9_c_1: Vec<[PackedM31; 3]>,
    range_check_9_9_c_2: Vec<[PackedM31; 3]>,
    range_check_9_9_c_3: Vec<[PackedM31; 3]>,
    range_check_9_9_c_4: Vec<[PackedM31; 3]>,
    range_check_9_9_c_5: Vec<[PackedM31; 3]>,
    range_check_9_9_d_0: Vec<[PackedM31; 3]>,
    range_check_9_9_d_1: Vec<[PackedM31; 3]>,
    range_check_9_9_d_2: Vec<[PackedM31; 3]>,
    range_check_9_9_d_3: Vec<[PackedM31; 3]>,
    range_check_9_9_d_4: Vec<[PackedM31; 3]>,
    range_check_9_9_d_5: Vec<[PackedM31; 3]>,
    range_check_9_9_e_0: Vec<[PackedM31; 3]>,
    range_check_9_9_e_1: Vec<[PackedM31; 3]>,
    range_check_9_9_e_2: Vec<[PackedM31; 3]>,
    range_check_9_9_e_3: Vec<[PackedM31; 3]>,
    range_check_9_9_e_4: Vec<[PackedM31; 3]>,
    range_check_9_9_e_5: Vec<[PackedM31; 3]>,
    range_check_9_9_f_0: Vec<[PackedM31; 3]>,
    range_check_9_9_f_1: Vec<[PackedM31; 3]>,
    range_check_9_9_f_2: Vec<[PackedM31; 3]>,
    range_check_9_9_f_3: Vec<[PackedM31; 3]>,
    range_check_9_9_f_4: Vec<[PackedM31; 3]>,
    range_check_9_9_f_5: Vec<[PackedM31; 3]>,
    range_check_9_9_g_0: Vec<[PackedM31; 3]>,
    range_check_9_9_g_1: Vec<[PackedM31; 3]>,
    range_check_9_9_g_2: Vec<[PackedM31; 3]>,
    range_check_9_9_h_0: Vec<[PackedM31; 3]>,
    range_check_9_9_h_1: Vec<[PackedM31; 3]>,
    range_check_9_9_h_2: Vec<[PackedM31; 3]>,
}

pub struct InteractionClaimGenerator {
    n_rows: usize,
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    cube_252_0: 21,
    range_check_20_0: 2,
    range_check_20_1: 2,
    range_check_20_2: 2,
    range_check_20_3: 2,
    range_check_20_4: 2,
    range_check_20_5: 2,
    range_check_20_6: 2,
    range_check_20_7: 2,
    range_check_20_b_0: 2,
    range_check_20_b_1: 2,
    range_check_20_b_2: 2,
    range_check_20_b_3: 2,
    range_check_20_b_4: 2,
    range_check_20_b_5: 2,
    range_check_20_b_6: 2,
    range_check_20_b_7: 2,
    range_check_20_c_0: 2,
    range_check_20_c_1: 2,
    range_check_20_c_2: 2,
    range_check_20_c_3: 2,
    range_check_20_c_4: 2,
    range_check_20_c_5: 2,
    range_check_20_c_6: 2,
    range_check_20_c_7: 2,
    range_check_20_d_0: 2,
    range_check_20_d_1: 2,
    range_check_20_d_2: 2,
    range_check_20_d_3: 2,
    range_check_20_d_4: 2,
    range_check_20_d_5: 2,
    range_check_20_d_6: 2,
    range_check_20_d_7: 2,
    range_check_20_e_0: 2,
    range_check_20_e_1: 2,
    range_check_20_e_2: 2,
    range_check_20_e_3: 2,
    range_check_20_e_4: 2,
    range_check_20_e_5: 2,
    range_check_20_f_0: 2,
    range_check_20_f_1: 2,
    range_check_20_f_2: 2,
    range_check_20_f_3: 2,
    range_check_20_f_4: 2,
    range_check_20_f_5: 2,
    range_check_20_g_0: 2,
    range_check_20_g_1: 2,
    range_check_20_g_2: 2,
    range_check_20_g_3: 2,
    range_check_20_g_4: 2,
    range_check_20_g_5: 2,
    range_check_20_h_0: 2,
    range_check_20_h_1: 2,
    range_check_20_h_2: 2,
    range_check_20_h_3: 2,
    range_check_20_h_4: 2,
    range_check_20_h_5: 2,
    range_check_9_9_0: 3,
    range_check_9_9_1: 3,
    range_check_9_9_2: 3,
    range_check_9_9_3: 3,
    range_check_9_9_4: 3,
    range_check_9_9_5: 3,
    range_check_9_9_b_0: 3,
    range_check_9_9_b_1: 3,
    range_check_9_9_b_2: 3,
    range_check_9_9_b_3: 3,
    range_check_9_9_b_4: 3,
    range_check_9_9_b_5: 3,
    range_check_9_9_c_0: 3,
    range_check_9_9_c_1: 3,
    range_check_9_9_c_2: 3,
    range_check_9_9_c_3: 3,
    range_check_9_9_c_4: 3,
    range_check_9_9_c_5: 3,
    range_check_9_9_d_0: 3,
    range_check_9_9_d_1: 3,
    range_check_9_9_d_2: 3,
    range_check_9_9_d_3: 3,
    range_check_9_9_d_4: 3,
    range_check_9_9_d_5: 3,
    range_check_9_9_e_0: 3,
    range_check_9_9_e_1: 3,
    range_check_9_9_e_2: 3,
    range_check_9_9_e_3: 3,
    range_check_9_9_e_4: 3,
    range_check_9_9_e_5: 3,
    range_check_9_9_f_0: 3,
    range_check_9_9_f_1: 3,
    range_check_9_9_f_2: 3,
    range_check_9_9_f_3: 3,
    range_check_9_9_f_4: 3,
    range_check_9_9_f_5: 3,
    range_check_9_9_g_0: 3,
    range_check_9_9_g_1: 3,
    range_check_9_9_g_2: 3,
    range_check_9_9_h_0: 3,
    range_check_9_9_h_1: 3,
    range_check_9_9_h_2: 3,
}
// === END relation_lookup_source_codegen ===
impl InteractionClaimGenerator {
    pub fn write_interaction_trace(
        self,
        common_lookup_elements: &relations::CommonLookupElements,
    ) -> (RawLogupTrace, impl FnOnce(SecureField) -> InteractionClaim) {
        let enabler_col = Enabler::new(self.n_rows);
        let mut logup_gen = unsafe { RawLogupTraceGenerator::uninitialized(self.log_size) };

        // Sum logup terms in pairs.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_0,
            &self.lookup_data.range_check_9_9_b_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_0,
            &self.lookup_data.range_check_9_9_d_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_0,
            &self.lookup_data.range_check_9_9_f_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_g_0,
            &self.lookup_data.range_check_9_9_h_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_1,
            &self.lookup_data.range_check_9_9_b_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_1,
            &self.lookup_data.range_check_9_9_d_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_1,
            &self.lookup_data.range_check_9_9_f_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_2,
            &self.lookup_data.range_check_9_9_b_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_2,
            &self.lookup_data.range_check_9_9_d_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_2,
            &self.lookup_data.range_check_9_9_f_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_g_1,
            &self.lookup_data.range_check_9_9_h_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_3,
            &self.lookup_data.range_check_9_9_b_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_3,
            &self.lookup_data.range_check_9_9_d_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_3,
            &self.lookup_data.range_check_9_9_f_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_0,
            &self.lookup_data.range_check_20_b_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_0,
            &self.lookup_data.range_check_20_d_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_0,
            &self.lookup_data.range_check_20_f_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_0,
            &self.lookup_data.range_check_20_h_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_1,
            &self.lookup_data.range_check_20_b_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_1,
            &self.lookup_data.range_check_20_d_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_1,
            &self.lookup_data.range_check_20_f_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_1,
            &self.lookup_data.range_check_20_h_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_2,
            &self.lookup_data.range_check_20_b_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_2,
            &self.lookup_data.range_check_20_d_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_2,
            &self.lookup_data.range_check_20_f_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_2,
            &self.lookup_data.range_check_20_h_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_3,
            &self.lookup_data.range_check_20_b_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_3,
            &self.lookup_data.range_check_20_d_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_4,
            &self.lookup_data.range_check_9_9_b_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_4,
            &self.lookup_data.range_check_9_9_d_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_4,
            &self.lookup_data.range_check_9_9_f_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_g_2,
            &self.lookup_data.range_check_9_9_h_2,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_5,
            &self.lookup_data.range_check_9_9_b_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_c_5,
            &self.lookup_data.range_check_9_9_d_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_9_9_e_5,
            &self.lookup_data.range_check_9_9_f_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_4,
            &self.lookup_data.range_check_20_b_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_4,
            &self.lookup_data.range_check_20_d_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_3,
            &self.lookup_data.range_check_20_f_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_3,
            &self.lookup_data.range_check_20_h_3,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_5,
            &self.lookup_data.range_check_20_b_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_5,
            &self.lookup_data.range_check_20_d_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_4,
            &self.lookup_data.range_check_20_f_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_4,
            &self.lookup_data.range_check_20_h_4,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_6,
            &self.lookup_data.range_check_20_b_6,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_6,
            &self.lookup_data.range_check_20_d_6,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_e_5,
            &self.lookup_data.range_check_20_f_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_g_5,
            &self.lookup_data.range_check_20_h_5,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_7,
            &self.lookup_data.range_check_20_b_7,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_20_c_7,
            &self.lookup_data.range_check_20_d_7,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (col_gen.par_iter_mut(), &self.lookup_data.cube_252_0)
            .into_par_iter()
            .enumerate()
            .for_each(|(i, (writer, values))| {
                let denom = common_lookup_elements.combine(values);
                writer.write_frac(-PackedQM31::one() * enabler_col.packed_at(i), denom);
            });
        col_gen.finalize_col();

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
