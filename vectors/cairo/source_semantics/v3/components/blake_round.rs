#![allow(unused_parens)]
use cairo_air::components::blake_round::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_cairo_adapter::memory::Memory;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    blake_g, blake_round_sigma, memory_address_to_id, memory_id_to_big, range_check_7_2_5,
};
use crate::witness::prelude::*;

pub type InputType = (M31, M31, ([UInt32; 16], M31));
pub type PackedInputType = (PackedM31, PackedM31, ([PackedUInt32; 16], PackedM31));

pub struct ClaimGenerator {
    state: BlakeRound,
    pub packed_inputs: Mutex<Vec<PackedInputType>>,
    pub remainder_inputs: Mutex<Vec<InputType>>,
}

impl ClaimGenerator {
    pub fn new(memory: Arc<Memory>) -> Self {
        let state = BlakeRound::new(memory);
        Self {
            packed_inputs: Mutex::new(vec![]),
            remainder_inputs: Mutex::new(vec![]),
            state,
        }
    }

    pub fn write_trace(
        self,
        blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        blake_g_state: &blake_g::ClaimGenerator,
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

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            packed_inputs,
            n_rows,
            blake_round_sigma_state,
            memory_address_to_id_state,
            memory_id_to_big_state,
            range_check_7_2_5_state,
            blake_g_state,
        );
        sub_component_inputs
            .blake_round_sigma
            .iter()
            .for_each(|inputs| {
                blake_round_sigma_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .range_check_7_2_5
            .iter()
            .for_each(|inputs| {
                range_check_7_2_5_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .memory_address_to_id
            .iter()
            .for_each(|inputs| {
                memory_address_to_id_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .memory_id_to_big
            .iter()
            .for_each(|inputs| {
                memory_id_to_big_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs.blake_g.iter().for_each(|inputs| {
            blake_g_state.add_packed_inputs(inputs, 0);
        });

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

    pub fn deduce_output(
        &self,
        input: (PackedM31, PackedM31, ([PackedUInt32; 16], PackedM31)),
    ) -> (PackedM31, PackedM31, ([PackedUInt32; 16], PackedM31)) {
        self.state.deduce_output(input.0, input.1, input.2)
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
    blake_round_sigma: [Vec<blake_round_sigma::PackedInputType>; 1],
    range_check_7_2_5: [Vec<range_check_7_2_5::PackedInputType>; 16],
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 16],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 16],
    blake_g: [Vec<blake_g::PackedInputType>; 8],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    blake_g_state: &blake_g::ClaimGenerator,
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

    let M31_0 = PackedM31::broadcast(M31::from(0));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1139985212 = PackedM31::broadcast(M31::from(1139985212));
    let M31_128 = PackedM31::broadcast(M31::from(128));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1805967942 = PackedM31::broadcast(M31::from(1805967942));
    let M31_2048 = PackedM31::broadcast(M31::from(2048));
    let M31_371240602 = PackedM31::broadcast(M31::from(371240602));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_40528774 = PackedM31::broadcast(M31::from(40528774));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_7 = PackedUInt16::broadcast(UInt16::from(7));
    let UInt16_9 = PackedUInt16::broadcast(UInt16::from(9));
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
            |(row_index, (row, lookup_data, sub_component_inputs, blake_round_input))| {
                let input_limb_0_col0 = blake_round_input.0;
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = blake_round_input.1;
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = blake_round_input.2 .0[0].low().as_m31();
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = blake_round_input.2 .0[0].high().as_m31();
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = blake_round_input.2 .0[1].low().as_m31();
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = blake_round_input.2 .0[1].high().as_m31();
                *row[5] = input_limb_5_col5;
                let input_limb_6_col6 = blake_round_input.2 .0[2].low().as_m31();
                *row[6] = input_limb_6_col6;
                let input_limb_7_col7 = blake_round_input.2 .0[2].high().as_m31();
                *row[7] = input_limb_7_col7;
                let input_limb_8_col8 = blake_round_input.2 .0[3].low().as_m31();
                *row[8] = input_limb_8_col8;
                let input_limb_9_col9 = blake_round_input.2 .0[3].high().as_m31();
                *row[9] = input_limb_9_col9;
                let input_limb_10_col10 = blake_round_input.2 .0[4].low().as_m31();
                *row[10] = input_limb_10_col10;
                let input_limb_11_col11 = blake_round_input.2 .0[4].high().as_m31();
                *row[11] = input_limb_11_col11;
                let input_limb_12_col12 = blake_round_input.2 .0[5].low().as_m31();
                *row[12] = input_limb_12_col12;
                let input_limb_13_col13 = blake_round_input.2 .0[5].high().as_m31();
                *row[13] = input_limb_13_col13;
                let input_limb_14_col14 = blake_round_input.2 .0[6].low().as_m31();
                *row[14] = input_limb_14_col14;
                let input_limb_15_col15 = blake_round_input.2 .0[6].high().as_m31();
                *row[15] = input_limb_15_col15;
                let input_limb_16_col16 = blake_round_input.2 .0[7].low().as_m31();
                *row[16] = input_limb_16_col16;
                let input_limb_17_col17 = blake_round_input.2 .0[7].high().as_m31();
                *row[17] = input_limb_17_col17;
                let input_limb_18_col18 = blake_round_input.2 .0[8].low().as_m31();
                *row[18] = input_limb_18_col18;
                let input_limb_19_col19 = blake_round_input.2 .0[8].high().as_m31();
                *row[19] = input_limb_19_col19;
                let input_limb_20_col20 = blake_round_input.2 .0[9].low().as_m31();
                *row[20] = input_limb_20_col20;
                let input_limb_21_col21 = blake_round_input.2 .0[9].high().as_m31();
                *row[21] = input_limb_21_col21;
                let input_limb_22_col22 = blake_round_input.2 .0[10].low().as_m31();
                *row[22] = input_limb_22_col22;
                let input_limb_23_col23 = blake_round_input.2 .0[10].high().as_m31();
                *row[23] = input_limb_23_col23;
                let input_limb_24_col24 = blake_round_input.2 .0[11].low().as_m31();
                *row[24] = input_limb_24_col24;
                let input_limb_25_col25 = blake_round_input.2 .0[11].high().as_m31();
                *row[25] = input_limb_25_col25;
                let input_limb_26_col26 = blake_round_input.2 .0[12].low().as_m31();
                *row[26] = input_limb_26_col26;
                let input_limb_27_col27 = blake_round_input.2 .0[12].high().as_m31();
                *row[27] = input_limb_27_col27;
                let input_limb_28_col28 = blake_round_input.2 .0[13].low().as_m31();
                *row[28] = input_limb_28_col28;
                let input_limb_29_col29 = blake_round_input.2 .0[13].high().as_m31();
                *row[29] = input_limb_29_col29;
                let input_limb_30_col30 = blake_round_input.2 .0[14].low().as_m31();
                *row[30] = input_limb_30_col30;
                let input_limb_31_col31 = blake_round_input.2 .0[14].high().as_m31();
                *row[31] = input_limb_31_col31;
                let input_limb_32_col32 = blake_round_input.2 .0[15].low().as_m31();
                *row[32] = input_limb_32_col32;
                let input_limb_33_col33 = blake_round_input.2 .0[15].high().as_m31();
                *row[33] = input_limb_33_col33;
                let input_limb_34_col34 = blake_round_input.2 .1;
                *row[34] = input_limb_34_col34;
                *sub_component_inputs.blake_round_sigma[0] = [input_limb_1_col1];
                let blake_round_sigma_output_tmp_92ff8_0 =
                    PackedBlakeRoundSigma::deduce_output(input_limb_1_col1);
                let blake_round_sigma_output_limb_0_col35 = blake_round_sigma_output_tmp_92ff8_0[0];
                *row[35] = blake_round_sigma_output_limb_0_col35;
                let blake_round_sigma_output_limb_1_col36 = blake_round_sigma_output_tmp_92ff8_0[1];
                *row[36] = blake_round_sigma_output_limb_1_col36;
                let blake_round_sigma_output_limb_2_col37 = blake_round_sigma_output_tmp_92ff8_0[2];
                *row[37] = blake_round_sigma_output_limb_2_col37;
                let blake_round_sigma_output_limb_3_col38 = blake_round_sigma_output_tmp_92ff8_0[3];
                *row[38] = blake_round_sigma_output_limb_3_col38;
                let blake_round_sigma_output_limb_4_col39 = blake_round_sigma_output_tmp_92ff8_0[4];
                *row[39] = blake_round_sigma_output_limb_4_col39;
                let blake_round_sigma_output_limb_5_col40 = blake_round_sigma_output_tmp_92ff8_0[5];
                *row[40] = blake_round_sigma_output_limb_5_col40;
                let blake_round_sigma_output_limb_6_col41 = blake_round_sigma_output_tmp_92ff8_0[6];
                *row[41] = blake_round_sigma_output_limb_6_col41;
                let blake_round_sigma_output_limb_7_col42 = blake_round_sigma_output_tmp_92ff8_0[7];
                *row[42] = blake_round_sigma_output_limb_7_col42;
                let blake_round_sigma_output_limb_8_col43 = blake_round_sigma_output_tmp_92ff8_0[8];
                *row[43] = blake_round_sigma_output_limb_8_col43;
                let blake_round_sigma_output_limb_9_col44 = blake_round_sigma_output_tmp_92ff8_0[9];
                *row[44] = blake_round_sigma_output_limb_9_col44;
                let blake_round_sigma_output_limb_10_col45 =
                    blake_round_sigma_output_tmp_92ff8_0[10];
                *row[45] = blake_round_sigma_output_limb_10_col45;
                let blake_round_sigma_output_limb_11_col46 =
                    blake_round_sigma_output_tmp_92ff8_0[11];
                *row[46] = blake_round_sigma_output_limb_11_col46;
                let blake_round_sigma_output_limb_12_col47 =
                    blake_round_sigma_output_tmp_92ff8_0[12];
                *row[47] = blake_round_sigma_output_limb_12_col47;
                let blake_round_sigma_output_limb_13_col48 =
                    blake_round_sigma_output_tmp_92ff8_0[13];
                *row[48] = blake_round_sigma_output_limb_13_col48;
                let blake_round_sigma_output_limb_14_col49 =
                    blake_round_sigma_output_tmp_92ff8_0[14];
                *row[49] = blake_round_sigma_output_limb_14_col49;
                let blake_round_sigma_output_limb_15_col50 =
                    blake_round_sigma_output_tmp_92ff8_0[15];
                *row[50] = blake_round_sigma_output_limb_15_col50;
                *lookup_data.blake_round_sigma_0 = [
                    M31_1805967942,
                    input_limb_1_col1,
                    blake_round_sigma_output_limb_0_col35,
                    blake_round_sigma_output_limb_1_col36,
                    blake_round_sigma_output_limb_2_col37,
                    blake_round_sigma_output_limb_3_col38,
                    blake_round_sigma_output_limb_4_col39,
                    blake_round_sigma_output_limb_5_col40,
                    blake_round_sigma_output_limb_6_col41,
                    blake_round_sigma_output_limb_7_col42,
                    blake_round_sigma_output_limb_8_col43,
                    blake_round_sigma_output_limb_9_col44,
                    blake_round_sigma_output_limb_10_col45,
                    blake_round_sigma_output_limb_11_col46,
                    blake_round_sigma_output_limb_12_col47,
                    blake_round_sigma_output_limb_13_col48,
                    blake_round_sigma_output_limb_14_col49,
                    blake_round_sigma_output_limb_15_col50,
                ];

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_1 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_0_col35)),
                    );
                let memory_id_to_big_value_tmp_92ff8_2 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_1);
                let tmp_92ff8_3 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_2.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col51 = ((((memory_id_to_big_value_tmp_92ff8_2.get_m31(1))
                    - ((tmp_92ff8_3.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_2.get_m31(0)));
                *row[51] = low_16_bits_col51;
                let high_16_bits_col52 = ((((memory_id_to_big_value_tmp_92ff8_2.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_2.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_3.as_m31()));
                *row[52] = high_16_bits_col52;
                let expected_word_tmp_92ff8_4 =
                    PackedUInt32::from_limbs([low_16_bits_col51, high_16_bits_col52]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_5 = ((expected_word_tmp_92ff8_4.low()) >> (UInt16_9));
                let low_7_ms_bits_col53 = low_7_ms_bits_tmp_92ff8_5.as_m31();
                *row[53] = low_7_ms_bits_col53;
                let high_14_ms_bits_tmp_92ff8_6 =
                    ((expected_word_tmp_92ff8_4.high()) >> (UInt16_2));
                let high_14_ms_bits_col54 = high_14_ms_bits_tmp_92ff8_6.as_m31();
                *row[54] = high_14_ms_bits_col54;
                let high_2_ls_bits_tmp_92ff8_7 =
                    ((high_16_bits_col52) - ((high_14_ms_bits_col54) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_8 = ((high_14_ms_bits_tmp_92ff8_6) >> (UInt16_9));
                let high_5_ms_bits_col55 = high_5_ms_bits_tmp_92ff8_8.as_m31();
                *row[55] = high_5_ms_bits_col55;
                *sub_component_inputs.range_check_7_2_5[0] = [
                    low_7_ms_bits_col53,
                    high_2_ls_bits_tmp_92ff8_7,
                    high_5_ms_bits_col55,
                ];
                *lookup_data.range_check_7_2_5_0 = [
                    M31_371240602,
                    low_7_ms_bits_col53,
                    high_2_ls_bits_tmp_92ff8_7,
                    high_5_ms_bits_col55,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_9 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_0_col35)),
                    );
                let message_word_0_id_col56 = memory_address_to_id_value_tmp_92ff8_9;
                *row[56] = message_word_0_id_col56;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_0_col35));
                *lookup_data.memory_address_to_id_0 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_0_col35)),
                    message_word_0_id_col56,
                ];

                *sub_component_inputs.memory_id_to_big[0] = message_word_0_id_col56;
                *lookup_data.memory_id_to_big_0 = [
                    M31_1662111297,
                    message_word_0_id_col56,
                    ((low_16_bits_col51) - ((low_7_ms_bits_col53) * (M31_512))),
                    ((low_7_ms_bits_col53) + ((high_2_ls_bits_tmp_92ff8_7) * (M31_128))),
                    ((high_14_ms_bits_col54) - ((high_5_ms_bits_col55) * (M31_512))),
                    high_5_ms_bits_col55,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_11 = expected_word_tmp_92ff8_4;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_12 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_1_col36)),
                    );
                let memory_id_to_big_value_tmp_92ff8_13 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_12);
                let tmp_92ff8_14 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_13.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col57 = ((((memory_id_to_big_value_tmp_92ff8_13.get_m31(1))
                    - ((tmp_92ff8_14.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_13.get_m31(0)));
                *row[57] = low_16_bits_col57;
                let high_16_bits_col58 = ((((memory_id_to_big_value_tmp_92ff8_13.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_13.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_14.as_m31()));
                *row[58] = high_16_bits_col58;
                let expected_word_tmp_92ff8_15 =
                    PackedUInt32::from_limbs([low_16_bits_col57, high_16_bits_col58]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_16 = ((expected_word_tmp_92ff8_15.low()) >> (UInt16_9));
                let low_7_ms_bits_col59 = low_7_ms_bits_tmp_92ff8_16.as_m31();
                *row[59] = low_7_ms_bits_col59;
                let high_14_ms_bits_tmp_92ff8_17 =
                    ((expected_word_tmp_92ff8_15.high()) >> (UInt16_2));
                let high_14_ms_bits_col60 = high_14_ms_bits_tmp_92ff8_17.as_m31();
                *row[60] = high_14_ms_bits_col60;
                let high_2_ls_bits_tmp_92ff8_18 =
                    ((high_16_bits_col58) - ((high_14_ms_bits_col60) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_19 = ((high_14_ms_bits_tmp_92ff8_17) >> (UInt16_9));
                let high_5_ms_bits_col61 = high_5_ms_bits_tmp_92ff8_19.as_m31();
                *row[61] = high_5_ms_bits_col61;
                *sub_component_inputs.range_check_7_2_5[1] = [
                    low_7_ms_bits_col59,
                    high_2_ls_bits_tmp_92ff8_18,
                    high_5_ms_bits_col61,
                ];
                *lookup_data.range_check_7_2_5_1 = [
                    M31_371240602,
                    low_7_ms_bits_col59,
                    high_2_ls_bits_tmp_92ff8_18,
                    high_5_ms_bits_col61,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_20 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_1_col36)),
                    );
                let message_word_1_id_col62 = memory_address_to_id_value_tmp_92ff8_20;
                *row[62] = message_word_1_id_col62;
                *sub_component_inputs.memory_address_to_id[1] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_1_col36));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_1_col36)),
                    message_word_1_id_col62,
                ];

                *sub_component_inputs.memory_id_to_big[1] = message_word_1_id_col62;
                *lookup_data.memory_id_to_big_1 = [
                    M31_1662111297,
                    message_word_1_id_col62,
                    ((low_16_bits_col57) - ((low_7_ms_bits_col59) * (M31_512))),
                    ((low_7_ms_bits_col59) + ((high_2_ls_bits_tmp_92ff8_18) * (M31_128))),
                    ((high_14_ms_bits_col60) - ((high_5_ms_bits_col61) * (M31_512))),
                    high_5_ms_bits_col61,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_22 = expected_word_tmp_92ff8_15;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_23 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_2_col37)),
                    );
                let memory_id_to_big_value_tmp_92ff8_24 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_23);
                let tmp_92ff8_25 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_24.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col63 = ((((memory_id_to_big_value_tmp_92ff8_24.get_m31(1))
                    - ((tmp_92ff8_25.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_24.get_m31(0)));
                *row[63] = low_16_bits_col63;
                let high_16_bits_col64 = ((((memory_id_to_big_value_tmp_92ff8_24.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_24.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_25.as_m31()));
                *row[64] = high_16_bits_col64;
                let expected_word_tmp_92ff8_26 =
                    PackedUInt32::from_limbs([low_16_bits_col63, high_16_bits_col64]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_27 = ((expected_word_tmp_92ff8_26.low()) >> (UInt16_9));
                let low_7_ms_bits_col65 = low_7_ms_bits_tmp_92ff8_27.as_m31();
                *row[65] = low_7_ms_bits_col65;
                let high_14_ms_bits_tmp_92ff8_28 =
                    ((expected_word_tmp_92ff8_26.high()) >> (UInt16_2));
                let high_14_ms_bits_col66 = high_14_ms_bits_tmp_92ff8_28.as_m31();
                *row[66] = high_14_ms_bits_col66;
                let high_2_ls_bits_tmp_92ff8_29 =
                    ((high_16_bits_col64) - ((high_14_ms_bits_col66) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_30 = ((high_14_ms_bits_tmp_92ff8_28) >> (UInt16_9));
                let high_5_ms_bits_col67 = high_5_ms_bits_tmp_92ff8_30.as_m31();
                *row[67] = high_5_ms_bits_col67;
                *sub_component_inputs.range_check_7_2_5[2] = [
                    low_7_ms_bits_col65,
                    high_2_ls_bits_tmp_92ff8_29,
                    high_5_ms_bits_col67,
                ];
                *lookup_data.range_check_7_2_5_2 = [
                    M31_371240602,
                    low_7_ms_bits_col65,
                    high_2_ls_bits_tmp_92ff8_29,
                    high_5_ms_bits_col67,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_31 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_2_col37)),
                    );
                let message_word_2_id_col68 = memory_address_to_id_value_tmp_92ff8_31;
                *row[68] = message_word_2_id_col68;
                *sub_component_inputs.memory_address_to_id[2] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_2_col37));
                *lookup_data.memory_address_to_id_2 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_2_col37)),
                    message_word_2_id_col68,
                ];

                *sub_component_inputs.memory_id_to_big[2] = message_word_2_id_col68;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    message_word_2_id_col68,
                    ((low_16_bits_col63) - ((low_7_ms_bits_col65) * (M31_512))),
                    ((low_7_ms_bits_col65) + ((high_2_ls_bits_tmp_92ff8_29) * (M31_128))),
                    ((high_14_ms_bits_col66) - ((high_5_ms_bits_col67) * (M31_512))),
                    high_5_ms_bits_col67,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_33 = expected_word_tmp_92ff8_26;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_34 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_3_col38)),
                    );
                let memory_id_to_big_value_tmp_92ff8_35 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_34);
                let tmp_92ff8_36 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_35.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col69 = ((((memory_id_to_big_value_tmp_92ff8_35.get_m31(1))
                    - ((tmp_92ff8_36.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_35.get_m31(0)));
                *row[69] = low_16_bits_col69;
                let high_16_bits_col70 = ((((memory_id_to_big_value_tmp_92ff8_35.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_35.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_36.as_m31()));
                *row[70] = high_16_bits_col70;
                let expected_word_tmp_92ff8_37 =
                    PackedUInt32::from_limbs([low_16_bits_col69, high_16_bits_col70]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_38 = ((expected_word_tmp_92ff8_37.low()) >> (UInt16_9));
                let low_7_ms_bits_col71 = low_7_ms_bits_tmp_92ff8_38.as_m31();
                *row[71] = low_7_ms_bits_col71;
                let high_14_ms_bits_tmp_92ff8_39 =
                    ((expected_word_tmp_92ff8_37.high()) >> (UInt16_2));
                let high_14_ms_bits_col72 = high_14_ms_bits_tmp_92ff8_39.as_m31();
                *row[72] = high_14_ms_bits_col72;
                let high_2_ls_bits_tmp_92ff8_40 =
                    ((high_16_bits_col70) - ((high_14_ms_bits_col72) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_41 = ((high_14_ms_bits_tmp_92ff8_39) >> (UInt16_9));
                let high_5_ms_bits_col73 = high_5_ms_bits_tmp_92ff8_41.as_m31();
                *row[73] = high_5_ms_bits_col73;
                *sub_component_inputs.range_check_7_2_5[3] = [
                    low_7_ms_bits_col71,
                    high_2_ls_bits_tmp_92ff8_40,
                    high_5_ms_bits_col73,
                ];
                *lookup_data.range_check_7_2_5_3 = [
                    M31_371240602,
                    low_7_ms_bits_col71,
                    high_2_ls_bits_tmp_92ff8_40,
                    high_5_ms_bits_col73,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_42 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_3_col38)),
                    );
                let message_word_3_id_col74 = memory_address_to_id_value_tmp_92ff8_42;
                *row[74] = message_word_3_id_col74;
                *sub_component_inputs.memory_address_to_id[3] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_3_col38));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_3_col38)),
                    message_word_3_id_col74,
                ];

                *sub_component_inputs.memory_id_to_big[3] = message_word_3_id_col74;
                *lookup_data.memory_id_to_big_3 = [
                    M31_1662111297,
                    message_word_3_id_col74,
                    ((low_16_bits_col69) - ((low_7_ms_bits_col71) * (M31_512))),
                    ((low_7_ms_bits_col71) + ((high_2_ls_bits_tmp_92ff8_40) * (M31_128))),
                    ((high_14_ms_bits_col72) - ((high_5_ms_bits_col73) * (M31_512))),
                    high_5_ms_bits_col73,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_44 = expected_word_tmp_92ff8_37;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_45 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_4_col39)),
                    );
                let memory_id_to_big_value_tmp_92ff8_46 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_45);
                let tmp_92ff8_47 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_46.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col75 = ((((memory_id_to_big_value_tmp_92ff8_46.get_m31(1))
                    - ((tmp_92ff8_47.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_46.get_m31(0)));
                *row[75] = low_16_bits_col75;
                let high_16_bits_col76 = ((((memory_id_to_big_value_tmp_92ff8_46.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_46.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_47.as_m31()));
                *row[76] = high_16_bits_col76;
                let expected_word_tmp_92ff8_48 =
                    PackedUInt32::from_limbs([low_16_bits_col75, high_16_bits_col76]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_49 = ((expected_word_tmp_92ff8_48.low()) >> (UInt16_9));
                let low_7_ms_bits_col77 = low_7_ms_bits_tmp_92ff8_49.as_m31();
                *row[77] = low_7_ms_bits_col77;
                let high_14_ms_bits_tmp_92ff8_50 =
                    ((expected_word_tmp_92ff8_48.high()) >> (UInt16_2));
                let high_14_ms_bits_col78 = high_14_ms_bits_tmp_92ff8_50.as_m31();
                *row[78] = high_14_ms_bits_col78;
                let high_2_ls_bits_tmp_92ff8_51 =
                    ((high_16_bits_col76) - ((high_14_ms_bits_col78) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_52 = ((high_14_ms_bits_tmp_92ff8_50) >> (UInt16_9));
                let high_5_ms_bits_col79 = high_5_ms_bits_tmp_92ff8_52.as_m31();
                *row[79] = high_5_ms_bits_col79;
                *sub_component_inputs.range_check_7_2_5[4] = [
                    low_7_ms_bits_col77,
                    high_2_ls_bits_tmp_92ff8_51,
                    high_5_ms_bits_col79,
                ];
                *lookup_data.range_check_7_2_5_4 = [
                    M31_371240602,
                    low_7_ms_bits_col77,
                    high_2_ls_bits_tmp_92ff8_51,
                    high_5_ms_bits_col79,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_53 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_4_col39)),
                    );
                let message_word_4_id_col80 = memory_address_to_id_value_tmp_92ff8_53;
                *row[80] = message_word_4_id_col80;
                *sub_component_inputs.memory_address_to_id[4] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_4_col39));
                *lookup_data.memory_address_to_id_4 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_4_col39)),
                    message_word_4_id_col80,
                ];

                *sub_component_inputs.memory_id_to_big[4] = message_word_4_id_col80;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    message_word_4_id_col80,
                    ((low_16_bits_col75) - ((low_7_ms_bits_col77) * (M31_512))),
                    ((low_7_ms_bits_col77) + ((high_2_ls_bits_tmp_92ff8_51) * (M31_128))),
                    ((high_14_ms_bits_col78) - ((high_5_ms_bits_col79) * (M31_512))),
                    high_5_ms_bits_col79,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_55 = expected_word_tmp_92ff8_48;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_56 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_5_col40)),
                    );
                let memory_id_to_big_value_tmp_92ff8_57 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_56);
                let tmp_92ff8_58 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_57.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col81 = ((((memory_id_to_big_value_tmp_92ff8_57.get_m31(1))
                    - ((tmp_92ff8_58.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_57.get_m31(0)));
                *row[81] = low_16_bits_col81;
                let high_16_bits_col82 = ((((memory_id_to_big_value_tmp_92ff8_57.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_57.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_58.as_m31()));
                *row[82] = high_16_bits_col82;
                let expected_word_tmp_92ff8_59 =
                    PackedUInt32::from_limbs([low_16_bits_col81, high_16_bits_col82]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_60 = ((expected_word_tmp_92ff8_59.low()) >> (UInt16_9));
                let low_7_ms_bits_col83 = low_7_ms_bits_tmp_92ff8_60.as_m31();
                *row[83] = low_7_ms_bits_col83;
                let high_14_ms_bits_tmp_92ff8_61 =
                    ((expected_word_tmp_92ff8_59.high()) >> (UInt16_2));
                let high_14_ms_bits_col84 = high_14_ms_bits_tmp_92ff8_61.as_m31();
                *row[84] = high_14_ms_bits_col84;
                let high_2_ls_bits_tmp_92ff8_62 =
                    ((high_16_bits_col82) - ((high_14_ms_bits_col84) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_63 = ((high_14_ms_bits_tmp_92ff8_61) >> (UInt16_9));
                let high_5_ms_bits_col85 = high_5_ms_bits_tmp_92ff8_63.as_m31();
                *row[85] = high_5_ms_bits_col85;
                *sub_component_inputs.range_check_7_2_5[5] = [
                    low_7_ms_bits_col83,
                    high_2_ls_bits_tmp_92ff8_62,
                    high_5_ms_bits_col85,
                ];
                *lookup_data.range_check_7_2_5_5 = [
                    M31_371240602,
                    low_7_ms_bits_col83,
                    high_2_ls_bits_tmp_92ff8_62,
                    high_5_ms_bits_col85,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_64 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_5_col40)),
                    );
                let message_word_5_id_col86 = memory_address_to_id_value_tmp_92ff8_64;
                *row[86] = message_word_5_id_col86;
                *sub_component_inputs.memory_address_to_id[5] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_5_col40));
                *lookup_data.memory_address_to_id_5 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_5_col40)),
                    message_word_5_id_col86,
                ];

                *sub_component_inputs.memory_id_to_big[5] = message_word_5_id_col86;
                *lookup_data.memory_id_to_big_5 = [
                    M31_1662111297,
                    message_word_5_id_col86,
                    ((low_16_bits_col81) - ((low_7_ms_bits_col83) * (M31_512))),
                    ((low_7_ms_bits_col83) + ((high_2_ls_bits_tmp_92ff8_62) * (M31_128))),
                    ((high_14_ms_bits_col84) - ((high_5_ms_bits_col85) * (M31_512))),
                    high_5_ms_bits_col85,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_66 = expected_word_tmp_92ff8_59;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_67 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_6_col41)),
                    );
                let memory_id_to_big_value_tmp_92ff8_68 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_67);
                let tmp_92ff8_69 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_68.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col87 = ((((memory_id_to_big_value_tmp_92ff8_68.get_m31(1))
                    - ((tmp_92ff8_69.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_68.get_m31(0)));
                *row[87] = low_16_bits_col87;
                let high_16_bits_col88 = ((((memory_id_to_big_value_tmp_92ff8_68.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_68.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_69.as_m31()));
                *row[88] = high_16_bits_col88;
                let expected_word_tmp_92ff8_70 =
                    PackedUInt32::from_limbs([low_16_bits_col87, high_16_bits_col88]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_71 = ((expected_word_tmp_92ff8_70.low()) >> (UInt16_9));
                let low_7_ms_bits_col89 = low_7_ms_bits_tmp_92ff8_71.as_m31();
                *row[89] = low_7_ms_bits_col89;
                let high_14_ms_bits_tmp_92ff8_72 =
                    ((expected_word_tmp_92ff8_70.high()) >> (UInt16_2));
                let high_14_ms_bits_col90 = high_14_ms_bits_tmp_92ff8_72.as_m31();
                *row[90] = high_14_ms_bits_col90;
                let high_2_ls_bits_tmp_92ff8_73 =
                    ((high_16_bits_col88) - ((high_14_ms_bits_col90) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_74 = ((high_14_ms_bits_tmp_92ff8_72) >> (UInt16_9));
                let high_5_ms_bits_col91 = high_5_ms_bits_tmp_92ff8_74.as_m31();
                *row[91] = high_5_ms_bits_col91;
                *sub_component_inputs.range_check_7_2_5[6] = [
                    low_7_ms_bits_col89,
                    high_2_ls_bits_tmp_92ff8_73,
                    high_5_ms_bits_col91,
                ];
                *lookup_data.range_check_7_2_5_6 = [
                    M31_371240602,
                    low_7_ms_bits_col89,
                    high_2_ls_bits_tmp_92ff8_73,
                    high_5_ms_bits_col91,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_75 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_6_col41)),
                    );
                let message_word_6_id_col92 = memory_address_to_id_value_tmp_92ff8_75;
                *row[92] = message_word_6_id_col92;
                *sub_component_inputs.memory_address_to_id[6] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_6_col41));
                *lookup_data.memory_address_to_id_6 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_6_col41)),
                    message_word_6_id_col92,
                ];

                *sub_component_inputs.memory_id_to_big[6] = message_word_6_id_col92;
                *lookup_data.memory_id_to_big_6 = [
                    M31_1662111297,
                    message_word_6_id_col92,
                    ((low_16_bits_col87) - ((low_7_ms_bits_col89) * (M31_512))),
                    ((low_7_ms_bits_col89) + ((high_2_ls_bits_tmp_92ff8_73) * (M31_128))),
                    ((high_14_ms_bits_col90) - ((high_5_ms_bits_col91) * (M31_512))),
                    high_5_ms_bits_col91,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_77 = expected_word_tmp_92ff8_70;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_78 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_7_col42)),
                    );
                let memory_id_to_big_value_tmp_92ff8_79 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_78);
                let tmp_92ff8_80 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_79.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col93 = ((((memory_id_to_big_value_tmp_92ff8_79.get_m31(1))
                    - ((tmp_92ff8_80.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_79.get_m31(0)));
                *row[93] = low_16_bits_col93;
                let high_16_bits_col94 = ((((memory_id_to_big_value_tmp_92ff8_79.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_79.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_80.as_m31()));
                *row[94] = high_16_bits_col94;
                let expected_word_tmp_92ff8_81 =
                    PackedUInt32::from_limbs([low_16_bits_col93, high_16_bits_col94]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_82 = ((expected_word_tmp_92ff8_81.low()) >> (UInt16_9));
                let low_7_ms_bits_col95 = low_7_ms_bits_tmp_92ff8_82.as_m31();
                *row[95] = low_7_ms_bits_col95;
                let high_14_ms_bits_tmp_92ff8_83 =
                    ((expected_word_tmp_92ff8_81.high()) >> (UInt16_2));
                let high_14_ms_bits_col96 = high_14_ms_bits_tmp_92ff8_83.as_m31();
                *row[96] = high_14_ms_bits_col96;
                let high_2_ls_bits_tmp_92ff8_84 =
                    ((high_16_bits_col94) - ((high_14_ms_bits_col96) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_85 = ((high_14_ms_bits_tmp_92ff8_83) >> (UInt16_9));
                let high_5_ms_bits_col97 = high_5_ms_bits_tmp_92ff8_85.as_m31();
                *row[97] = high_5_ms_bits_col97;
                *sub_component_inputs.range_check_7_2_5[7] = [
                    low_7_ms_bits_col95,
                    high_2_ls_bits_tmp_92ff8_84,
                    high_5_ms_bits_col97,
                ];
                *lookup_data.range_check_7_2_5_7 = [
                    M31_371240602,
                    low_7_ms_bits_col95,
                    high_2_ls_bits_tmp_92ff8_84,
                    high_5_ms_bits_col97,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_86 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_7_col42)),
                    );
                let message_word_7_id_col98 = memory_address_to_id_value_tmp_92ff8_86;
                *row[98] = message_word_7_id_col98;
                *sub_component_inputs.memory_address_to_id[7] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_7_col42));
                *lookup_data.memory_address_to_id_7 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_7_col42)),
                    message_word_7_id_col98,
                ];

                *sub_component_inputs.memory_id_to_big[7] = message_word_7_id_col98;
                *lookup_data.memory_id_to_big_7 = [
                    M31_1662111297,
                    message_word_7_id_col98,
                    ((low_16_bits_col93) - ((low_7_ms_bits_col95) * (M31_512))),
                    ((low_7_ms_bits_col95) + ((high_2_ls_bits_tmp_92ff8_84) * (M31_128))),
                    ((high_14_ms_bits_col96) - ((high_5_ms_bits_col97) * (M31_512))),
                    high_5_ms_bits_col97,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_88 = expected_word_tmp_92ff8_81;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_89 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_8_col43)),
                    );
                let memory_id_to_big_value_tmp_92ff8_90 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_89);
                let tmp_92ff8_91 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_90.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col99 = ((((memory_id_to_big_value_tmp_92ff8_90.get_m31(1))
                    - ((tmp_92ff8_91.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_90.get_m31(0)));
                *row[99] = low_16_bits_col99;
                let high_16_bits_col100 = ((((memory_id_to_big_value_tmp_92ff8_90.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_90.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_91.as_m31()));
                *row[100] = high_16_bits_col100;
                let expected_word_tmp_92ff8_92 =
                    PackedUInt32::from_limbs([low_16_bits_col99, high_16_bits_col100]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_93 = ((expected_word_tmp_92ff8_92.low()) >> (UInt16_9));
                let low_7_ms_bits_col101 = low_7_ms_bits_tmp_92ff8_93.as_m31();
                *row[101] = low_7_ms_bits_col101;
                let high_14_ms_bits_tmp_92ff8_94 =
                    ((expected_word_tmp_92ff8_92.high()) >> (UInt16_2));
                let high_14_ms_bits_col102 = high_14_ms_bits_tmp_92ff8_94.as_m31();
                *row[102] = high_14_ms_bits_col102;
                let high_2_ls_bits_tmp_92ff8_95 =
                    ((high_16_bits_col100) - ((high_14_ms_bits_col102) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_96 = ((high_14_ms_bits_tmp_92ff8_94) >> (UInt16_9));
                let high_5_ms_bits_col103 = high_5_ms_bits_tmp_92ff8_96.as_m31();
                *row[103] = high_5_ms_bits_col103;
                *sub_component_inputs.range_check_7_2_5[8] = [
                    low_7_ms_bits_col101,
                    high_2_ls_bits_tmp_92ff8_95,
                    high_5_ms_bits_col103,
                ];
                *lookup_data.range_check_7_2_5_8 = [
                    M31_371240602,
                    low_7_ms_bits_col101,
                    high_2_ls_bits_tmp_92ff8_95,
                    high_5_ms_bits_col103,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_97 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_8_col43)),
                    );
                let message_word_8_id_col104 = memory_address_to_id_value_tmp_92ff8_97;
                *row[104] = message_word_8_id_col104;
                *sub_component_inputs.memory_address_to_id[8] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_8_col43));
                *lookup_data.memory_address_to_id_8 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_8_col43)),
                    message_word_8_id_col104,
                ];

                *sub_component_inputs.memory_id_to_big[8] = message_word_8_id_col104;
                *lookup_data.memory_id_to_big_8 = [
                    M31_1662111297,
                    message_word_8_id_col104,
                    ((low_16_bits_col99) - ((low_7_ms_bits_col101) * (M31_512))),
                    ((low_7_ms_bits_col101) + ((high_2_ls_bits_tmp_92ff8_95) * (M31_128))),
                    ((high_14_ms_bits_col102) - ((high_5_ms_bits_col103) * (M31_512))),
                    high_5_ms_bits_col103,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_99 = expected_word_tmp_92ff8_92;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_100 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_9_col44)),
                    );
                let memory_id_to_big_value_tmp_92ff8_101 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_100);
                let tmp_92ff8_102 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_101.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col105 = ((((memory_id_to_big_value_tmp_92ff8_101.get_m31(1))
                    - ((tmp_92ff8_102.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_101.get_m31(0)));
                *row[105] = low_16_bits_col105;
                let high_16_bits_col106 = ((((memory_id_to_big_value_tmp_92ff8_101.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_101.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_102.as_m31()));
                *row[106] = high_16_bits_col106;
                let expected_word_tmp_92ff8_103 =
                    PackedUInt32::from_limbs([low_16_bits_col105, high_16_bits_col106]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_104 =
                    ((expected_word_tmp_92ff8_103.low()) >> (UInt16_9));
                let low_7_ms_bits_col107 = low_7_ms_bits_tmp_92ff8_104.as_m31();
                *row[107] = low_7_ms_bits_col107;
                let high_14_ms_bits_tmp_92ff8_105 =
                    ((expected_word_tmp_92ff8_103.high()) >> (UInt16_2));
                let high_14_ms_bits_col108 = high_14_ms_bits_tmp_92ff8_105.as_m31();
                *row[108] = high_14_ms_bits_col108;
                let high_2_ls_bits_tmp_92ff8_106 =
                    ((high_16_bits_col106) - ((high_14_ms_bits_col108) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_107 = ((high_14_ms_bits_tmp_92ff8_105) >> (UInt16_9));
                let high_5_ms_bits_col109 = high_5_ms_bits_tmp_92ff8_107.as_m31();
                *row[109] = high_5_ms_bits_col109;
                *sub_component_inputs.range_check_7_2_5[9] = [
                    low_7_ms_bits_col107,
                    high_2_ls_bits_tmp_92ff8_106,
                    high_5_ms_bits_col109,
                ];
                *lookup_data.range_check_7_2_5_9 = [
                    M31_371240602,
                    low_7_ms_bits_col107,
                    high_2_ls_bits_tmp_92ff8_106,
                    high_5_ms_bits_col109,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_108 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_9_col44)),
                    );
                let message_word_9_id_col110 = memory_address_to_id_value_tmp_92ff8_108;
                *row[110] = message_word_9_id_col110;
                *sub_component_inputs.memory_address_to_id[9] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_9_col44));
                *lookup_data.memory_address_to_id_9 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_9_col44)),
                    message_word_9_id_col110,
                ];

                *sub_component_inputs.memory_id_to_big[9] = message_word_9_id_col110;
                *lookup_data.memory_id_to_big_9 = [
                    M31_1662111297,
                    message_word_9_id_col110,
                    ((low_16_bits_col105) - ((low_7_ms_bits_col107) * (M31_512))),
                    ((low_7_ms_bits_col107) + ((high_2_ls_bits_tmp_92ff8_106) * (M31_128))),
                    ((high_14_ms_bits_col108) - ((high_5_ms_bits_col109) * (M31_512))),
                    high_5_ms_bits_col109,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_110 = expected_word_tmp_92ff8_103;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_111 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_10_col45)),
                    );
                let memory_id_to_big_value_tmp_92ff8_112 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_111);
                let tmp_92ff8_113 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_112.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col111 = ((((memory_id_to_big_value_tmp_92ff8_112.get_m31(1))
                    - ((tmp_92ff8_113.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_112.get_m31(0)));
                *row[111] = low_16_bits_col111;
                let high_16_bits_col112 = ((((memory_id_to_big_value_tmp_92ff8_112.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_112.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_113.as_m31()));
                *row[112] = high_16_bits_col112;
                let expected_word_tmp_92ff8_114 =
                    PackedUInt32::from_limbs([low_16_bits_col111, high_16_bits_col112]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_115 =
                    ((expected_word_tmp_92ff8_114.low()) >> (UInt16_9));
                let low_7_ms_bits_col113 = low_7_ms_bits_tmp_92ff8_115.as_m31();
                *row[113] = low_7_ms_bits_col113;
                let high_14_ms_bits_tmp_92ff8_116 =
                    ((expected_word_tmp_92ff8_114.high()) >> (UInt16_2));
                let high_14_ms_bits_col114 = high_14_ms_bits_tmp_92ff8_116.as_m31();
                *row[114] = high_14_ms_bits_col114;
                let high_2_ls_bits_tmp_92ff8_117 =
                    ((high_16_bits_col112) - ((high_14_ms_bits_col114) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_118 = ((high_14_ms_bits_tmp_92ff8_116) >> (UInt16_9));
                let high_5_ms_bits_col115 = high_5_ms_bits_tmp_92ff8_118.as_m31();
                *row[115] = high_5_ms_bits_col115;
                *sub_component_inputs.range_check_7_2_5[10] = [
                    low_7_ms_bits_col113,
                    high_2_ls_bits_tmp_92ff8_117,
                    high_5_ms_bits_col115,
                ];
                *lookup_data.range_check_7_2_5_10 = [
                    M31_371240602,
                    low_7_ms_bits_col113,
                    high_2_ls_bits_tmp_92ff8_117,
                    high_5_ms_bits_col115,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_119 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_10_col45)),
                    );
                let message_word_10_id_col116 = memory_address_to_id_value_tmp_92ff8_119;
                *row[116] = message_word_10_id_col116;
                *sub_component_inputs.memory_address_to_id[10] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_10_col45));
                *lookup_data.memory_address_to_id_10 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_10_col45)),
                    message_word_10_id_col116,
                ];

                *sub_component_inputs.memory_id_to_big[10] = message_word_10_id_col116;
                *lookup_data.memory_id_to_big_10 = [
                    M31_1662111297,
                    message_word_10_id_col116,
                    ((low_16_bits_col111) - ((low_7_ms_bits_col113) * (M31_512))),
                    ((low_7_ms_bits_col113) + ((high_2_ls_bits_tmp_92ff8_117) * (M31_128))),
                    ((high_14_ms_bits_col114) - ((high_5_ms_bits_col115) * (M31_512))),
                    high_5_ms_bits_col115,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_121 = expected_word_tmp_92ff8_114;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_122 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_11_col46)),
                    );
                let memory_id_to_big_value_tmp_92ff8_123 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_122);
                let tmp_92ff8_124 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_123.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col117 = ((((memory_id_to_big_value_tmp_92ff8_123.get_m31(1))
                    - ((tmp_92ff8_124.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_123.get_m31(0)));
                *row[117] = low_16_bits_col117;
                let high_16_bits_col118 = ((((memory_id_to_big_value_tmp_92ff8_123.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_123.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_124.as_m31()));
                *row[118] = high_16_bits_col118;
                let expected_word_tmp_92ff8_125 =
                    PackedUInt32::from_limbs([low_16_bits_col117, high_16_bits_col118]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_126 =
                    ((expected_word_tmp_92ff8_125.low()) >> (UInt16_9));
                let low_7_ms_bits_col119 = low_7_ms_bits_tmp_92ff8_126.as_m31();
                *row[119] = low_7_ms_bits_col119;
                let high_14_ms_bits_tmp_92ff8_127 =
                    ((expected_word_tmp_92ff8_125.high()) >> (UInt16_2));
                let high_14_ms_bits_col120 = high_14_ms_bits_tmp_92ff8_127.as_m31();
                *row[120] = high_14_ms_bits_col120;
                let high_2_ls_bits_tmp_92ff8_128 =
                    ((high_16_bits_col118) - ((high_14_ms_bits_col120) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_129 = ((high_14_ms_bits_tmp_92ff8_127) >> (UInt16_9));
                let high_5_ms_bits_col121 = high_5_ms_bits_tmp_92ff8_129.as_m31();
                *row[121] = high_5_ms_bits_col121;
                *sub_component_inputs.range_check_7_2_5[11] = [
                    low_7_ms_bits_col119,
                    high_2_ls_bits_tmp_92ff8_128,
                    high_5_ms_bits_col121,
                ];
                *lookup_data.range_check_7_2_5_11 = [
                    M31_371240602,
                    low_7_ms_bits_col119,
                    high_2_ls_bits_tmp_92ff8_128,
                    high_5_ms_bits_col121,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_130 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_11_col46)),
                    );
                let message_word_11_id_col122 = memory_address_to_id_value_tmp_92ff8_130;
                *row[122] = message_word_11_id_col122;
                *sub_component_inputs.memory_address_to_id[11] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_11_col46));
                *lookup_data.memory_address_to_id_11 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_11_col46)),
                    message_word_11_id_col122,
                ];

                *sub_component_inputs.memory_id_to_big[11] = message_word_11_id_col122;
                *lookup_data.memory_id_to_big_11 = [
                    M31_1662111297,
                    message_word_11_id_col122,
                    ((low_16_bits_col117) - ((low_7_ms_bits_col119) * (M31_512))),
                    ((low_7_ms_bits_col119) + ((high_2_ls_bits_tmp_92ff8_128) * (M31_128))),
                    ((high_14_ms_bits_col120) - ((high_5_ms_bits_col121) * (M31_512))),
                    high_5_ms_bits_col121,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_132 = expected_word_tmp_92ff8_125;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_133 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_12_col47)),
                    );
                let memory_id_to_big_value_tmp_92ff8_134 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_133);
                let tmp_92ff8_135 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_134.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col123 = ((((memory_id_to_big_value_tmp_92ff8_134.get_m31(1))
                    - ((tmp_92ff8_135.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_134.get_m31(0)));
                *row[123] = low_16_bits_col123;
                let high_16_bits_col124 = ((((memory_id_to_big_value_tmp_92ff8_134.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_134.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_135.as_m31()));
                *row[124] = high_16_bits_col124;
                let expected_word_tmp_92ff8_136 =
                    PackedUInt32::from_limbs([low_16_bits_col123, high_16_bits_col124]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_137 =
                    ((expected_word_tmp_92ff8_136.low()) >> (UInt16_9));
                let low_7_ms_bits_col125 = low_7_ms_bits_tmp_92ff8_137.as_m31();
                *row[125] = low_7_ms_bits_col125;
                let high_14_ms_bits_tmp_92ff8_138 =
                    ((expected_word_tmp_92ff8_136.high()) >> (UInt16_2));
                let high_14_ms_bits_col126 = high_14_ms_bits_tmp_92ff8_138.as_m31();
                *row[126] = high_14_ms_bits_col126;
                let high_2_ls_bits_tmp_92ff8_139 =
                    ((high_16_bits_col124) - ((high_14_ms_bits_col126) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_140 = ((high_14_ms_bits_tmp_92ff8_138) >> (UInt16_9));
                let high_5_ms_bits_col127 = high_5_ms_bits_tmp_92ff8_140.as_m31();
                *row[127] = high_5_ms_bits_col127;
                *sub_component_inputs.range_check_7_2_5[12] = [
                    low_7_ms_bits_col125,
                    high_2_ls_bits_tmp_92ff8_139,
                    high_5_ms_bits_col127,
                ];
                *lookup_data.range_check_7_2_5_12 = [
                    M31_371240602,
                    low_7_ms_bits_col125,
                    high_2_ls_bits_tmp_92ff8_139,
                    high_5_ms_bits_col127,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_141 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_12_col47)),
                    );
                let message_word_12_id_col128 = memory_address_to_id_value_tmp_92ff8_141;
                *row[128] = message_word_12_id_col128;
                *sub_component_inputs.memory_address_to_id[12] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_12_col47));
                *lookup_data.memory_address_to_id_12 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_12_col47)),
                    message_word_12_id_col128,
                ];

                *sub_component_inputs.memory_id_to_big[12] = message_word_12_id_col128;
                *lookup_data.memory_id_to_big_12 = [
                    M31_1662111297,
                    message_word_12_id_col128,
                    ((low_16_bits_col123) - ((low_7_ms_bits_col125) * (M31_512))),
                    ((low_7_ms_bits_col125) + ((high_2_ls_bits_tmp_92ff8_139) * (M31_128))),
                    ((high_14_ms_bits_col126) - ((high_5_ms_bits_col127) * (M31_512))),
                    high_5_ms_bits_col127,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_143 = expected_word_tmp_92ff8_136;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_144 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_13_col48)),
                    );
                let memory_id_to_big_value_tmp_92ff8_145 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_144);
                let tmp_92ff8_146 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_145.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col129 = ((((memory_id_to_big_value_tmp_92ff8_145.get_m31(1))
                    - ((tmp_92ff8_146.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_145.get_m31(0)));
                *row[129] = low_16_bits_col129;
                let high_16_bits_col130 = ((((memory_id_to_big_value_tmp_92ff8_145.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_145.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_146.as_m31()));
                *row[130] = high_16_bits_col130;
                let expected_word_tmp_92ff8_147 =
                    PackedUInt32::from_limbs([low_16_bits_col129, high_16_bits_col130]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_148 =
                    ((expected_word_tmp_92ff8_147.low()) >> (UInt16_9));
                let low_7_ms_bits_col131 = low_7_ms_bits_tmp_92ff8_148.as_m31();
                *row[131] = low_7_ms_bits_col131;
                let high_14_ms_bits_tmp_92ff8_149 =
                    ((expected_word_tmp_92ff8_147.high()) >> (UInt16_2));
                let high_14_ms_bits_col132 = high_14_ms_bits_tmp_92ff8_149.as_m31();
                *row[132] = high_14_ms_bits_col132;
                let high_2_ls_bits_tmp_92ff8_150 =
                    ((high_16_bits_col130) - ((high_14_ms_bits_col132) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_151 = ((high_14_ms_bits_tmp_92ff8_149) >> (UInt16_9));
                let high_5_ms_bits_col133 = high_5_ms_bits_tmp_92ff8_151.as_m31();
                *row[133] = high_5_ms_bits_col133;
                *sub_component_inputs.range_check_7_2_5[13] = [
                    low_7_ms_bits_col131,
                    high_2_ls_bits_tmp_92ff8_150,
                    high_5_ms_bits_col133,
                ];
                *lookup_data.range_check_7_2_5_13 = [
                    M31_371240602,
                    low_7_ms_bits_col131,
                    high_2_ls_bits_tmp_92ff8_150,
                    high_5_ms_bits_col133,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_152 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_13_col48)),
                    );
                let message_word_13_id_col134 = memory_address_to_id_value_tmp_92ff8_152;
                *row[134] = message_word_13_id_col134;
                *sub_component_inputs.memory_address_to_id[13] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_13_col48));
                *lookup_data.memory_address_to_id_13 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_13_col48)),
                    message_word_13_id_col134,
                ];

                *sub_component_inputs.memory_id_to_big[13] = message_word_13_id_col134;
                *lookup_data.memory_id_to_big_13 = [
                    M31_1662111297,
                    message_word_13_id_col134,
                    ((low_16_bits_col129) - ((low_7_ms_bits_col131) * (M31_512))),
                    ((low_7_ms_bits_col131) + ((high_2_ls_bits_tmp_92ff8_150) * (M31_128))),
                    ((high_14_ms_bits_col132) - ((high_5_ms_bits_col133) * (M31_512))),
                    high_5_ms_bits_col133,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_154 = expected_word_tmp_92ff8_147;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_155 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_14_col49)),
                    );
                let memory_id_to_big_value_tmp_92ff8_156 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_155);
                let tmp_92ff8_157 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_156.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col135 = ((((memory_id_to_big_value_tmp_92ff8_156.get_m31(1))
                    - ((tmp_92ff8_157.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_156.get_m31(0)));
                *row[135] = low_16_bits_col135;
                let high_16_bits_col136 = ((((memory_id_to_big_value_tmp_92ff8_156.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_156.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_157.as_m31()));
                *row[136] = high_16_bits_col136;
                let expected_word_tmp_92ff8_158 =
                    PackedUInt32::from_limbs([low_16_bits_col135, high_16_bits_col136]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_159 =
                    ((expected_word_tmp_92ff8_158.low()) >> (UInt16_9));
                let low_7_ms_bits_col137 = low_7_ms_bits_tmp_92ff8_159.as_m31();
                *row[137] = low_7_ms_bits_col137;
                let high_14_ms_bits_tmp_92ff8_160 =
                    ((expected_word_tmp_92ff8_158.high()) >> (UInt16_2));
                let high_14_ms_bits_col138 = high_14_ms_bits_tmp_92ff8_160.as_m31();
                *row[138] = high_14_ms_bits_col138;
                let high_2_ls_bits_tmp_92ff8_161 =
                    ((high_16_bits_col136) - ((high_14_ms_bits_col138) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_162 = ((high_14_ms_bits_tmp_92ff8_160) >> (UInt16_9));
                let high_5_ms_bits_col139 = high_5_ms_bits_tmp_92ff8_162.as_m31();
                *row[139] = high_5_ms_bits_col139;
                *sub_component_inputs.range_check_7_2_5[14] = [
                    low_7_ms_bits_col137,
                    high_2_ls_bits_tmp_92ff8_161,
                    high_5_ms_bits_col139,
                ];
                *lookup_data.range_check_7_2_5_14 = [
                    M31_371240602,
                    low_7_ms_bits_col137,
                    high_2_ls_bits_tmp_92ff8_161,
                    high_5_ms_bits_col139,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_163 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_14_col49)),
                    );
                let message_word_14_id_col140 = memory_address_to_id_value_tmp_92ff8_163;
                *row[140] = message_word_14_id_col140;
                *sub_component_inputs.memory_address_to_id[14] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_14_col49));
                *lookup_data.memory_address_to_id_14 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_14_col49)),
                    message_word_14_id_col140,
                ];

                *sub_component_inputs.memory_id_to_big[14] = message_word_14_id_col140;
                *lookup_data.memory_id_to_big_14 = [
                    M31_1662111297,
                    message_word_14_id_col140,
                    ((low_16_bits_col135) - ((low_7_ms_bits_col137) * (M31_512))),
                    ((low_7_ms_bits_col137) + ((high_2_ls_bits_tmp_92ff8_161) * (M31_128))),
                    ((high_14_ms_bits_col138) - ((high_5_ms_bits_col139) * (M31_512))),
                    high_5_ms_bits_col139,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_165 = expected_word_tmp_92ff8_158;

                // Read U 32.

                let memory_address_to_id_value_tmp_92ff8_166 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_15_col50)),
                    );
                let memory_id_to_big_value_tmp_92ff8_167 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_92ff8_166);
                let tmp_92ff8_168 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_92ff8_167.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col141 = ((((memory_id_to_big_value_tmp_92ff8_167.get_m31(1))
                    - ((tmp_92ff8_168.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_92ff8_167.get_m31(0)));
                *row[141] = low_16_bits_col141;
                let high_16_bits_col142 = ((((memory_id_to_big_value_tmp_92ff8_167.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_92ff8_167.get_m31(2)) * (M31_4)))
                    + (tmp_92ff8_168.as_m31()));
                *row[142] = high_16_bits_col142;
                let expected_word_tmp_92ff8_169 =
                    PackedUInt32::from_limbs([low_16_bits_col141, high_16_bits_col142]);

                // Verify U 32.

                let low_7_ms_bits_tmp_92ff8_170 =
                    ((expected_word_tmp_92ff8_169.low()) >> (UInt16_9));
                let low_7_ms_bits_col143 = low_7_ms_bits_tmp_92ff8_170.as_m31();
                *row[143] = low_7_ms_bits_col143;
                let high_14_ms_bits_tmp_92ff8_171 =
                    ((expected_word_tmp_92ff8_169.high()) >> (UInt16_2));
                let high_14_ms_bits_col144 = high_14_ms_bits_tmp_92ff8_171.as_m31();
                *row[144] = high_14_ms_bits_col144;
                let high_2_ls_bits_tmp_92ff8_172 =
                    ((high_16_bits_col142) - ((high_14_ms_bits_col144) * (M31_4)));
                let high_5_ms_bits_tmp_92ff8_173 = ((high_14_ms_bits_tmp_92ff8_171) >> (UInt16_9));
                let high_5_ms_bits_col145 = high_5_ms_bits_tmp_92ff8_173.as_m31();
                *row[145] = high_5_ms_bits_col145;
                *sub_component_inputs.range_check_7_2_5[15] = [
                    low_7_ms_bits_col143,
                    high_2_ls_bits_tmp_92ff8_172,
                    high_5_ms_bits_col145,
                ];
                *lookup_data.range_check_7_2_5_15 = [
                    M31_371240602,
                    low_7_ms_bits_col143,
                    high_2_ls_bits_tmp_92ff8_172,
                    high_5_ms_bits_col145,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_92ff8_174 = memory_address_to_id_state
                    .deduce_output(
                        ((input_limb_34_col34) + (blake_round_sigma_output_limb_15_col50)),
                    );
                let message_word_15_id_col146 = memory_address_to_id_value_tmp_92ff8_174;
                *row[146] = message_word_15_id_col146;
                *sub_component_inputs.memory_address_to_id[15] =
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_15_col50));
                *lookup_data.memory_address_to_id_15 = [
                    M31_1444891767,
                    ((input_limb_34_col34) + (blake_round_sigma_output_limb_15_col50)),
                    message_word_15_id_col146,
                ];

                *sub_component_inputs.memory_id_to_big[15] = message_word_15_id_col146;
                *lookup_data.memory_id_to_big_15 = [
                    M31_1662111297,
                    message_word_15_id_col146,
                    ((low_16_bits_col141) - ((low_7_ms_bits_col143) * (M31_512))),
                    ((low_7_ms_bits_col143) + ((high_2_ls_bits_tmp_92ff8_172) * (M31_128))),
                    ((high_14_ms_bits_col144) - ((high_5_ms_bits_col145) * (M31_512))),
                    high_5_ms_bits_col145,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_92ff8_176 = expected_word_tmp_92ff8_169;

                *sub_component_inputs.blake_g[0] = [
                    blake_round_input.2 .0[0],
                    blake_round_input.2 .0[4],
                    blake_round_input.2 .0[8],
                    blake_round_input.2 .0[12],
                    read_u_32_output_tmp_92ff8_11,
                    read_u_32_output_tmp_92ff8_22,
                ];
                let blake_g_output_tmp_92ff8_177 = PackedBlakeG::deduce_output([
                    blake_round_input.2 .0[0],
                    blake_round_input.2 .0[4],
                    blake_round_input.2 .0[8],
                    blake_round_input.2 .0[12],
                    read_u_32_output_tmp_92ff8_11,
                    read_u_32_output_tmp_92ff8_22,
                ]);
                let blake_g_output_limb_0_col147 = blake_g_output_tmp_92ff8_177[0].low().as_m31();
                *row[147] = blake_g_output_limb_0_col147;
                let blake_g_output_limb_1_col148 = blake_g_output_tmp_92ff8_177[0].high().as_m31();
                *row[148] = blake_g_output_limb_1_col148;
                let blake_g_output_limb_2_col149 = blake_g_output_tmp_92ff8_177[1].low().as_m31();
                *row[149] = blake_g_output_limb_2_col149;
                let blake_g_output_limb_3_col150 = blake_g_output_tmp_92ff8_177[1].high().as_m31();
                *row[150] = blake_g_output_limb_3_col150;
                let blake_g_output_limb_4_col151 = blake_g_output_tmp_92ff8_177[2].low().as_m31();
                *row[151] = blake_g_output_limb_4_col151;
                let blake_g_output_limb_5_col152 = blake_g_output_tmp_92ff8_177[2].high().as_m31();
                *row[152] = blake_g_output_limb_5_col152;
                let blake_g_output_limb_6_col153 = blake_g_output_tmp_92ff8_177[3].low().as_m31();
                *row[153] = blake_g_output_limb_6_col153;
                let blake_g_output_limb_7_col154 = blake_g_output_tmp_92ff8_177[3].high().as_m31();
                *row[154] = blake_g_output_limb_7_col154;
                *lookup_data.blake_g_0 = [
                    M31_1139985212,
                    input_limb_2_col2,
                    input_limb_3_col3,
                    input_limb_10_col10,
                    input_limb_11_col11,
                    input_limb_18_col18,
                    input_limb_19_col19,
                    input_limb_26_col26,
                    input_limb_27_col27,
                    low_16_bits_col51,
                    high_16_bits_col52,
                    low_16_bits_col57,
                    high_16_bits_col58,
                    blake_g_output_limb_0_col147,
                    blake_g_output_limb_1_col148,
                    blake_g_output_limb_2_col149,
                    blake_g_output_limb_3_col150,
                    blake_g_output_limb_4_col151,
                    blake_g_output_limb_5_col152,
                    blake_g_output_limb_6_col153,
                    blake_g_output_limb_7_col154,
                ];
                *sub_component_inputs.blake_g[1] = [
                    blake_round_input.2 .0[1],
                    blake_round_input.2 .0[5],
                    blake_round_input.2 .0[9],
                    blake_round_input.2 .0[13],
                    read_u_32_output_tmp_92ff8_33,
                    read_u_32_output_tmp_92ff8_44,
                ];
                let blake_g_output_tmp_92ff8_178 = PackedBlakeG::deduce_output([
                    blake_round_input.2 .0[1],
                    blake_round_input.2 .0[5],
                    blake_round_input.2 .0[9],
                    blake_round_input.2 .0[13],
                    read_u_32_output_tmp_92ff8_33,
                    read_u_32_output_tmp_92ff8_44,
                ]);
                let blake_g_output_limb_0_col155 = blake_g_output_tmp_92ff8_178[0].low().as_m31();
                *row[155] = blake_g_output_limb_0_col155;
                let blake_g_output_limb_1_col156 = blake_g_output_tmp_92ff8_178[0].high().as_m31();
                *row[156] = blake_g_output_limb_1_col156;
                let blake_g_output_limb_2_col157 = blake_g_output_tmp_92ff8_178[1].low().as_m31();
                *row[157] = blake_g_output_limb_2_col157;
                let blake_g_output_limb_3_col158 = blake_g_output_tmp_92ff8_178[1].high().as_m31();
                *row[158] = blake_g_output_limb_3_col158;
                let blake_g_output_limb_4_col159 = blake_g_output_tmp_92ff8_178[2].low().as_m31();
                *row[159] = blake_g_output_limb_4_col159;
                let blake_g_output_limb_5_col160 = blake_g_output_tmp_92ff8_178[2].high().as_m31();
                *row[160] = blake_g_output_limb_5_col160;
                let blake_g_output_limb_6_col161 = blake_g_output_tmp_92ff8_178[3].low().as_m31();
                *row[161] = blake_g_output_limb_6_col161;
                let blake_g_output_limb_7_col162 = blake_g_output_tmp_92ff8_178[3].high().as_m31();
                *row[162] = blake_g_output_limb_7_col162;
                *lookup_data.blake_g_1 = [
                    M31_1139985212,
                    input_limb_4_col4,
                    input_limb_5_col5,
                    input_limb_12_col12,
                    input_limb_13_col13,
                    input_limb_20_col20,
                    input_limb_21_col21,
                    input_limb_28_col28,
                    input_limb_29_col29,
                    low_16_bits_col63,
                    high_16_bits_col64,
                    low_16_bits_col69,
                    high_16_bits_col70,
                    blake_g_output_limb_0_col155,
                    blake_g_output_limb_1_col156,
                    blake_g_output_limb_2_col157,
                    blake_g_output_limb_3_col158,
                    blake_g_output_limb_4_col159,
                    blake_g_output_limb_5_col160,
                    blake_g_output_limb_6_col161,
                    blake_g_output_limb_7_col162,
                ];
                *sub_component_inputs.blake_g[2] = [
                    blake_round_input.2 .0[2],
                    blake_round_input.2 .0[6],
                    blake_round_input.2 .0[10],
                    blake_round_input.2 .0[14],
                    read_u_32_output_tmp_92ff8_55,
                    read_u_32_output_tmp_92ff8_66,
                ];
                let blake_g_output_tmp_92ff8_179 = PackedBlakeG::deduce_output([
                    blake_round_input.2 .0[2],
                    blake_round_input.2 .0[6],
                    blake_round_input.2 .0[10],
                    blake_round_input.2 .0[14],
                    read_u_32_output_tmp_92ff8_55,
                    read_u_32_output_tmp_92ff8_66,
                ]);
                let blake_g_output_limb_0_col163 = blake_g_output_tmp_92ff8_179[0].low().as_m31();
                *row[163] = blake_g_output_limb_0_col163;
                let blake_g_output_limb_1_col164 = blake_g_output_tmp_92ff8_179[0].high().as_m31();
                *row[164] = blake_g_output_limb_1_col164;
                let blake_g_output_limb_2_col165 = blake_g_output_tmp_92ff8_179[1].low().as_m31();
                *row[165] = blake_g_output_limb_2_col165;
                let blake_g_output_limb_3_col166 = blake_g_output_tmp_92ff8_179[1].high().as_m31();
                *row[166] = blake_g_output_limb_3_col166;
                let blake_g_output_limb_4_col167 = blake_g_output_tmp_92ff8_179[2].low().as_m31();
                *row[167] = blake_g_output_limb_4_col167;
                let blake_g_output_limb_5_col168 = blake_g_output_tmp_92ff8_179[2].high().as_m31();
                *row[168] = blake_g_output_limb_5_col168;
                let blake_g_output_limb_6_col169 = blake_g_output_tmp_92ff8_179[3].low().as_m31();
                *row[169] = blake_g_output_limb_6_col169;
                let blake_g_output_limb_7_col170 = blake_g_output_tmp_92ff8_179[3].high().as_m31();
                *row[170] = blake_g_output_limb_7_col170;
                *lookup_data.blake_g_2 = [
                    M31_1139985212,
                    input_limb_6_col6,
                    input_limb_7_col7,
                    input_limb_14_col14,
                    input_limb_15_col15,
                    input_limb_22_col22,
                    input_limb_23_col23,
                    input_limb_30_col30,
                    input_limb_31_col31,
                    low_16_bits_col75,
                    high_16_bits_col76,
                    low_16_bits_col81,
                    high_16_bits_col82,
                    blake_g_output_limb_0_col163,
                    blake_g_output_limb_1_col164,
                    blake_g_output_limb_2_col165,
                    blake_g_output_limb_3_col166,
                    blake_g_output_limb_4_col167,
                    blake_g_output_limb_5_col168,
                    blake_g_output_limb_6_col169,
                    blake_g_output_limb_7_col170,
                ];
                *sub_component_inputs.blake_g[3] = [
                    blake_round_input.2 .0[3],
                    blake_round_input.2 .0[7],
                    blake_round_input.2 .0[11],
                    blake_round_input.2 .0[15],
                    read_u_32_output_tmp_92ff8_77,
                    read_u_32_output_tmp_92ff8_88,
                ];
                let blake_g_output_tmp_92ff8_180 = PackedBlakeG::deduce_output([
                    blake_round_input.2 .0[3],
                    blake_round_input.2 .0[7],
                    blake_round_input.2 .0[11],
                    blake_round_input.2 .0[15],
                    read_u_32_output_tmp_92ff8_77,
                    read_u_32_output_tmp_92ff8_88,
                ]);
                let blake_g_output_limb_0_col171 = blake_g_output_tmp_92ff8_180[0].low().as_m31();
                *row[171] = blake_g_output_limb_0_col171;
                let blake_g_output_limb_1_col172 = blake_g_output_tmp_92ff8_180[0].high().as_m31();
                *row[172] = blake_g_output_limb_1_col172;
                let blake_g_output_limb_2_col173 = blake_g_output_tmp_92ff8_180[1].low().as_m31();
                *row[173] = blake_g_output_limb_2_col173;
                let blake_g_output_limb_3_col174 = blake_g_output_tmp_92ff8_180[1].high().as_m31();
                *row[174] = blake_g_output_limb_3_col174;
                let blake_g_output_limb_4_col175 = blake_g_output_tmp_92ff8_180[2].low().as_m31();
                *row[175] = blake_g_output_limb_4_col175;
                let blake_g_output_limb_5_col176 = blake_g_output_tmp_92ff8_180[2].high().as_m31();
                *row[176] = blake_g_output_limb_5_col176;
                let blake_g_output_limb_6_col177 = blake_g_output_tmp_92ff8_180[3].low().as_m31();
                *row[177] = blake_g_output_limb_6_col177;
                let blake_g_output_limb_7_col178 = blake_g_output_tmp_92ff8_180[3].high().as_m31();
                *row[178] = blake_g_output_limb_7_col178;
                *lookup_data.blake_g_3 = [
                    M31_1139985212,
                    input_limb_8_col8,
                    input_limb_9_col9,
                    input_limb_16_col16,
                    input_limb_17_col17,
                    input_limb_24_col24,
                    input_limb_25_col25,
                    input_limb_32_col32,
                    input_limb_33_col33,
                    low_16_bits_col87,
                    high_16_bits_col88,
                    low_16_bits_col93,
                    high_16_bits_col94,
                    blake_g_output_limb_0_col171,
                    blake_g_output_limb_1_col172,
                    blake_g_output_limb_2_col173,
                    blake_g_output_limb_3_col174,
                    blake_g_output_limb_4_col175,
                    blake_g_output_limb_5_col176,
                    blake_g_output_limb_6_col177,
                    blake_g_output_limb_7_col178,
                ];
                *sub_component_inputs.blake_g[4] = [
                    blake_g_output_tmp_92ff8_177[0],
                    blake_g_output_tmp_92ff8_178[1],
                    blake_g_output_tmp_92ff8_179[2],
                    blake_g_output_tmp_92ff8_180[3],
                    read_u_32_output_tmp_92ff8_99,
                    read_u_32_output_tmp_92ff8_110,
                ];
                let blake_g_output_tmp_92ff8_181 = PackedBlakeG::deduce_output([
                    blake_g_output_tmp_92ff8_177[0],
                    blake_g_output_tmp_92ff8_178[1],
                    blake_g_output_tmp_92ff8_179[2],
                    blake_g_output_tmp_92ff8_180[3],
                    read_u_32_output_tmp_92ff8_99,
                    read_u_32_output_tmp_92ff8_110,
                ]);
                let blake_g_output_limb_0_col179 = blake_g_output_tmp_92ff8_181[0].low().as_m31();
                *row[179] = blake_g_output_limb_0_col179;
                let blake_g_output_limb_1_col180 = blake_g_output_tmp_92ff8_181[0].high().as_m31();
                *row[180] = blake_g_output_limb_1_col180;
                let blake_g_output_limb_2_col181 = blake_g_output_tmp_92ff8_181[1].low().as_m31();
                *row[181] = blake_g_output_limb_2_col181;
                let blake_g_output_limb_3_col182 = blake_g_output_tmp_92ff8_181[1].high().as_m31();
                *row[182] = blake_g_output_limb_3_col182;
                let blake_g_output_limb_4_col183 = blake_g_output_tmp_92ff8_181[2].low().as_m31();
                *row[183] = blake_g_output_limb_4_col183;
                let blake_g_output_limb_5_col184 = blake_g_output_tmp_92ff8_181[2].high().as_m31();
                *row[184] = blake_g_output_limb_5_col184;
                let blake_g_output_limb_6_col185 = blake_g_output_tmp_92ff8_181[3].low().as_m31();
                *row[185] = blake_g_output_limb_6_col185;
                let blake_g_output_limb_7_col186 = blake_g_output_tmp_92ff8_181[3].high().as_m31();
                *row[186] = blake_g_output_limb_7_col186;
                *lookup_data.blake_g_4 = [
                    M31_1139985212,
                    blake_g_output_limb_0_col147,
                    blake_g_output_limb_1_col148,
                    blake_g_output_limb_2_col157,
                    blake_g_output_limb_3_col158,
                    blake_g_output_limb_4_col167,
                    blake_g_output_limb_5_col168,
                    blake_g_output_limb_6_col177,
                    blake_g_output_limb_7_col178,
                    low_16_bits_col99,
                    high_16_bits_col100,
                    low_16_bits_col105,
                    high_16_bits_col106,
                    blake_g_output_limb_0_col179,
                    blake_g_output_limb_1_col180,
                    blake_g_output_limb_2_col181,
                    blake_g_output_limb_3_col182,
                    blake_g_output_limb_4_col183,
                    blake_g_output_limb_5_col184,
                    blake_g_output_limb_6_col185,
                    blake_g_output_limb_7_col186,
                ];
                *sub_component_inputs.blake_g[5] = [
                    blake_g_output_tmp_92ff8_178[0],
                    blake_g_output_tmp_92ff8_179[1],
                    blake_g_output_tmp_92ff8_180[2],
                    blake_g_output_tmp_92ff8_177[3],
                    read_u_32_output_tmp_92ff8_121,
                    read_u_32_output_tmp_92ff8_132,
                ];
                let blake_g_output_tmp_92ff8_182 = PackedBlakeG::deduce_output([
                    blake_g_output_tmp_92ff8_178[0],
                    blake_g_output_tmp_92ff8_179[1],
                    blake_g_output_tmp_92ff8_180[2],
                    blake_g_output_tmp_92ff8_177[3],
                    read_u_32_output_tmp_92ff8_121,
                    read_u_32_output_tmp_92ff8_132,
                ]);
                let blake_g_output_limb_0_col187 = blake_g_output_tmp_92ff8_182[0].low().as_m31();
                *row[187] = blake_g_output_limb_0_col187;
                let blake_g_output_limb_1_col188 = blake_g_output_tmp_92ff8_182[0].high().as_m31();
                *row[188] = blake_g_output_limb_1_col188;
                let blake_g_output_limb_2_col189 = blake_g_output_tmp_92ff8_182[1].low().as_m31();
                *row[189] = blake_g_output_limb_2_col189;
                let blake_g_output_limb_3_col190 = blake_g_output_tmp_92ff8_182[1].high().as_m31();
                *row[190] = blake_g_output_limb_3_col190;
                let blake_g_output_limb_4_col191 = blake_g_output_tmp_92ff8_182[2].low().as_m31();
                *row[191] = blake_g_output_limb_4_col191;
                let blake_g_output_limb_5_col192 = blake_g_output_tmp_92ff8_182[2].high().as_m31();
                *row[192] = blake_g_output_limb_5_col192;
                let blake_g_output_limb_6_col193 = blake_g_output_tmp_92ff8_182[3].low().as_m31();
                *row[193] = blake_g_output_limb_6_col193;
                let blake_g_output_limb_7_col194 = blake_g_output_tmp_92ff8_182[3].high().as_m31();
                *row[194] = blake_g_output_limb_7_col194;
                *lookup_data.blake_g_5 = [
                    M31_1139985212,
                    blake_g_output_limb_0_col155,
                    blake_g_output_limb_1_col156,
                    blake_g_output_limb_2_col165,
                    blake_g_output_limb_3_col166,
                    blake_g_output_limb_4_col175,
                    blake_g_output_limb_5_col176,
                    blake_g_output_limb_6_col153,
                    blake_g_output_limb_7_col154,
                    low_16_bits_col111,
                    high_16_bits_col112,
                    low_16_bits_col117,
                    high_16_bits_col118,
                    blake_g_output_limb_0_col187,
                    blake_g_output_limb_1_col188,
                    blake_g_output_limb_2_col189,
                    blake_g_output_limb_3_col190,
                    blake_g_output_limb_4_col191,
                    blake_g_output_limb_5_col192,
                    blake_g_output_limb_6_col193,
                    blake_g_output_limb_7_col194,
                ];
                *sub_component_inputs.blake_g[6] = [
                    blake_g_output_tmp_92ff8_179[0],
                    blake_g_output_tmp_92ff8_180[1],
                    blake_g_output_tmp_92ff8_177[2],
                    blake_g_output_tmp_92ff8_178[3],
                    read_u_32_output_tmp_92ff8_143,
                    read_u_32_output_tmp_92ff8_154,
                ];
                let blake_g_output_tmp_92ff8_183 = PackedBlakeG::deduce_output([
                    blake_g_output_tmp_92ff8_179[0],
                    blake_g_output_tmp_92ff8_180[1],
                    blake_g_output_tmp_92ff8_177[2],
                    blake_g_output_tmp_92ff8_178[3],
                    read_u_32_output_tmp_92ff8_143,
                    read_u_32_output_tmp_92ff8_154,
                ]);
                let blake_g_output_limb_0_col195 = blake_g_output_tmp_92ff8_183[0].low().as_m31();
                *row[195] = blake_g_output_limb_0_col195;
                let blake_g_output_limb_1_col196 = blake_g_output_tmp_92ff8_183[0].high().as_m31();
                *row[196] = blake_g_output_limb_1_col196;
                let blake_g_output_limb_2_col197 = blake_g_output_tmp_92ff8_183[1].low().as_m31();
                *row[197] = blake_g_output_limb_2_col197;
                let blake_g_output_limb_3_col198 = blake_g_output_tmp_92ff8_183[1].high().as_m31();
                *row[198] = blake_g_output_limb_3_col198;
                let blake_g_output_limb_4_col199 = blake_g_output_tmp_92ff8_183[2].low().as_m31();
                *row[199] = blake_g_output_limb_4_col199;
                let blake_g_output_limb_5_col200 = blake_g_output_tmp_92ff8_183[2].high().as_m31();
                *row[200] = blake_g_output_limb_5_col200;
                let blake_g_output_limb_6_col201 = blake_g_output_tmp_92ff8_183[3].low().as_m31();
                *row[201] = blake_g_output_limb_6_col201;
                let blake_g_output_limb_7_col202 = blake_g_output_tmp_92ff8_183[3].high().as_m31();
                *row[202] = blake_g_output_limb_7_col202;
                *lookup_data.blake_g_6 = [
                    M31_1139985212,
                    blake_g_output_limb_0_col163,
                    blake_g_output_limb_1_col164,
                    blake_g_output_limb_2_col173,
                    blake_g_output_limb_3_col174,
                    blake_g_output_limb_4_col151,
                    blake_g_output_limb_5_col152,
                    blake_g_output_limb_6_col161,
                    blake_g_output_limb_7_col162,
                    low_16_bits_col123,
                    high_16_bits_col124,
                    low_16_bits_col129,
                    high_16_bits_col130,
                    blake_g_output_limb_0_col195,
                    blake_g_output_limb_1_col196,
                    blake_g_output_limb_2_col197,
                    blake_g_output_limb_3_col198,
                    blake_g_output_limb_4_col199,
                    blake_g_output_limb_5_col200,
                    blake_g_output_limb_6_col201,
                    blake_g_output_limb_7_col202,
                ];
                *sub_component_inputs.blake_g[7] = [
                    blake_g_output_tmp_92ff8_180[0],
                    blake_g_output_tmp_92ff8_177[1],
                    blake_g_output_tmp_92ff8_178[2],
                    blake_g_output_tmp_92ff8_179[3],
                    read_u_32_output_tmp_92ff8_165,
                    read_u_32_output_tmp_92ff8_176,
                ];
                let blake_g_output_tmp_92ff8_184 = PackedBlakeG::deduce_output([
                    blake_g_output_tmp_92ff8_180[0],
                    blake_g_output_tmp_92ff8_177[1],
                    blake_g_output_tmp_92ff8_178[2],
                    blake_g_output_tmp_92ff8_179[3],
                    read_u_32_output_tmp_92ff8_165,
                    read_u_32_output_tmp_92ff8_176,
                ]);
                let blake_g_output_limb_0_col203 = blake_g_output_tmp_92ff8_184[0].low().as_m31();
                *row[203] = blake_g_output_limb_0_col203;
                let blake_g_output_limb_1_col204 = blake_g_output_tmp_92ff8_184[0].high().as_m31();
                *row[204] = blake_g_output_limb_1_col204;
                let blake_g_output_limb_2_col205 = blake_g_output_tmp_92ff8_184[1].low().as_m31();
                *row[205] = blake_g_output_limb_2_col205;
                let blake_g_output_limb_3_col206 = blake_g_output_tmp_92ff8_184[1].high().as_m31();
                *row[206] = blake_g_output_limb_3_col206;
                let blake_g_output_limb_4_col207 = blake_g_output_tmp_92ff8_184[2].low().as_m31();
                *row[207] = blake_g_output_limb_4_col207;
                let blake_g_output_limb_5_col208 = blake_g_output_tmp_92ff8_184[2].high().as_m31();
                *row[208] = blake_g_output_limb_5_col208;
                let blake_g_output_limb_6_col209 = blake_g_output_tmp_92ff8_184[3].low().as_m31();
                *row[209] = blake_g_output_limb_6_col209;
                let blake_g_output_limb_7_col210 = blake_g_output_tmp_92ff8_184[3].high().as_m31();
                *row[210] = blake_g_output_limb_7_col210;
                *lookup_data.blake_g_7 = [
                    M31_1139985212,
                    blake_g_output_limb_0_col171,
                    blake_g_output_limb_1_col172,
                    blake_g_output_limb_2_col149,
                    blake_g_output_limb_3_col150,
                    blake_g_output_limb_4_col159,
                    blake_g_output_limb_5_col160,
                    blake_g_output_limb_6_col169,
                    blake_g_output_limb_7_col170,
                    low_16_bits_col135,
                    high_16_bits_col136,
                    low_16_bits_col141,
                    high_16_bits_col142,
                    blake_g_output_limb_0_col203,
                    blake_g_output_limb_1_col204,
                    blake_g_output_limb_2_col205,
                    blake_g_output_limb_3_col206,
                    blake_g_output_limb_4_col207,
                    blake_g_output_limb_5_col208,
                    blake_g_output_limb_6_col209,
                    blake_g_output_limb_7_col210,
                ];
                *lookup_data.blake_round_0 = [
                    M31_40528774,
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
                    input_limb_10_col10,
                    input_limb_11_col11,
                    input_limb_12_col12,
                    input_limb_13_col13,
                    input_limb_14_col14,
                    input_limb_15_col15,
                    input_limb_16_col16,
                    input_limb_17_col17,
                    input_limb_18_col18,
                    input_limb_19_col19,
                    input_limb_20_col20,
                    input_limb_21_col21,
                    input_limb_22_col22,
                    input_limb_23_col23,
                    input_limb_24_col24,
                    input_limb_25_col25,
                    input_limb_26_col26,
                    input_limb_27_col27,
                    input_limb_28_col28,
                    input_limb_29_col29,
                    input_limb_30_col30,
                    input_limb_31_col31,
                    input_limb_32_col32,
                    input_limb_33_col33,
                    input_limb_34_col34,
                ];
                *lookup_data.blake_round_1 = [
                    M31_40528774,
                    input_limb_0_col0,
                    ((input_limb_1_col1) + (M31_1)),
                    blake_g_output_limb_0_col179,
                    blake_g_output_limb_1_col180,
                    blake_g_output_limb_0_col187,
                    blake_g_output_limb_1_col188,
                    blake_g_output_limb_0_col195,
                    blake_g_output_limb_1_col196,
                    blake_g_output_limb_0_col203,
                    blake_g_output_limb_1_col204,
                    blake_g_output_limb_2_col205,
                    blake_g_output_limb_3_col206,
                    blake_g_output_limb_2_col181,
                    blake_g_output_limb_3_col182,
                    blake_g_output_limb_2_col189,
                    blake_g_output_limb_3_col190,
                    blake_g_output_limb_2_col197,
                    blake_g_output_limb_3_col198,
                    blake_g_output_limb_4_col199,
                    blake_g_output_limb_5_col200,
                    blake_g_output_limb_4_col207,
                    blake_g_output_limb_5_col208,
                    blake_g_output_limb_4_col183,
                    blake_g_output_limb_5_col184,
                    blake_g_output_limb_4_col191,
                    blake_g_output_limb_5_col192,
                    blake_g_output_limb_6_col193,
                    blake_g_output_limb_7_col194,
                    blake_g_output_limb_6_col201,
                    blake_g_output_limb_7_col202,
                    blake_g_output_limb_6_col209,
                    blake_g_output_limb_7_col210,
                    blake_g_output_limb_6_col185,
                    blake_g_output_limb_7_col186,
                    input_limb_34_col34,
                ];
                *row[211] = enabler_col.packed_at(row_index);
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `blake_round` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     blake_g_0[21] 0..20
//     blake_g_1[21] 21..41
//     blake_g_2[21] 42..62
//     blake_g_3[21] 63..83
//     blake_g_4[21] 84..104
//     blake_g_5[21] 105..125
//     blake_g_6[21] 126..146
//     blake_g_7[21] 147..167
//     blake_round_0[36] 168..203
//     blake_round_1[36] 204..239
//     blake_round_sigma_0[18] 240..257
//     memory_address_to_id_0[3] 258..260
//     memory_address_to_id_1[3] 261..263
//     memory_address_to_id_2[3] 264..266
//     memory_address_to_id_3[3] 267..269
//     memory_address_to_id_4[3] 270..272
//     memory_address_to_id_5[3] 273..275
//     memory_address_to_id_6[3] 276..278
//     memory_address_to_id_7[3] 279..281
//     memory_address_to_id_8[3] 282..284
//     memory_address_to_id_9[3] 285..287
//     memory_address_to_id_10[3] 288..290
//     memory_address_to_id_11[3] 291..293
//     memory_address_to_id_12[3] 294..296
//     memory_address_to_id_13[3] 297..299
//     memory_address_to_id_14[3] 300..302
//     memory_address_to_id_15[3] 303..305
//     memory_id_to_big_0[30] 306..335
//     memory_id_to_big_1[30] 336..365
//     memory_id_to_big_2[30] 366..395
//     memory_id_to_big_3[30] 396..425
//     memory_id_to_big_4[30] 426..455
//     memory_id_to_big_5[30] 456..485
//     memory_id_to_big_6[30] 486..515
//     memory_id_to_big_7[30] 516..545
//     memory_id_to_big_8[30] 546..575
//     memory_id_to_big_9[30] 576..605
//     memory_id_to_big_10[30] 606..635
//     memory_id_to_big_11[30] 636..665
//     memory_id_to_big_12[30] 666..695
//     memory_id_to_big_13[30] 696..725
//     memory_id_to_big_14[30] 726..755
//     memory_id_to_big_15[30] 756..785
//     range_check_7_2_5_0[4] 786..789
//     range_check_7_2_5_1[4] 790..793
//     range_check_7_2_5_2[4] 794..797
//     range_check_7_2_5_3[4] 798..801
//     range_check_7_2_5_4[4] 802..805
//     range_check_7_2_5_5[4] 806..809
//     range_check_7_2_5_6[4] 810..813
//     range_check_7_2_5_7[4] 814..817
//     range_check_7_2_5_8[4] 818..821
//     range_check_7_2_5_9[4] 822..825
//     range_check_7_2_5_10[4] 826..829
//     range_check_7_2_5_11[4] 830..833
//     range_check_7_2_5_12[4] 834..837
//     range_check_7_2_5_13[4] 838..841
//     range_check_7_2_5_14[4] 842..845
//     range_check_7_2_5_15[4] 846..849
//     (850 words)
//   SUB-INPUT words:
//     blake_round_sigma[0] 0
//     range_check_7_2_5[0] 1..3
//     range_check_7_2_5[1] 4..6
//     range_check_7_2_5[2] 7..9
//     range_check_7_2_5[3] 10..12
//     range_check_7_2_5[4] 13..15
//     range_check_7_2_5[5] 16..18
//     range_check_7_2_5[6] 19..21
//     range_check_7_2_5[7] 22..24
//     range_check_7_2_5[8] 25..27
//     range_check_7_2_5[9] 28..30
//     range_check_7_2_5[10] 31..33
//     range_check_7_2_5[11] 34..36
//     range_check_7_2_5[12] 37..39
//     range_check_7_2_5[13] 40..42
//     range_check_7_2_5[14] 43..45
//     range_check_7_2_5[15] 46..48
//     memory_address_to_id[0] 49
//     memory_address_to_id[1] 50
//     memory_address_to_id[2] 51
//     memory_address_to_id[3] 52
//     memory_address_to_id[4] 53
//     memory_address_to_id[5] 54
//     memory_address_to_id[6] 55
//     memory_address_to_id[7] 56
//     memory_address_to_id[8] 57
//     memory_address_to_id[9] 58
//     memory_address_to_id[10] 59
//     memory_address_to_id[11] 60
//     memory_address_to_id[12] 61
//     memory_address_to_id[13] 62
//     memory_address_to_id[14] 63
//     memory_address_to_id[15] 64
//     memory_id_to_big[0] 65
//     memory_id_to_big[1] 66
//     memory_id_to_big[2] 67
//     memory_id_to_big[3] 68
//     memory_id_to_big[4] 69
//     memory_id_to_big[5] 70
//     memory_id_to_big[6] 71
//     memory_id_to_big[7] 72
//     memory_id_to_big[8] 73
//     memory_id_to_big[9] 74
//     memory_id_to_big[10] 75
//     memory_id_to_big[11] 76
//     memory_id_to_big[12] 77
//     memory_id_to_big[13] 78
//     memory_id_to_big[14] 79
//     memory_id_to_big[15] 80
//     blake_g[0] 81..86
//     blake_g[1] 87..92
//     blake_g[2] 93..98
//     blake_g[3] 99..104
//     blake_g[4] 105..110
//     blake_g[5] 111..116
//     blake_g[6] 117..122
//     blake_g[7] 123..128
//     (129 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 850;
pub(crate) const N_SUB_INPUT_WORDS: usize = 129;

/// The per-row `blake_round` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn blake_round_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_4 = eval.m31_const(4);
    let m31_128 = eval.m31_const(128);
    let m31_512 = eval.m31_const(512);
    let m31_2048 = eval.m31_const(2048);
    let m31_40528774 = eval.m31_const(40528774);
    let m31_371240602 = eval.m31_const(371240602);
    let m31_1139985212 = eval.m31_const(1139985212);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1805967942 = eval.m31_const(1805967942);
    let input_limb_0_col0 = eval.input(0);
    eval.set_col(0, input_limb_0_col0);
    let input_limb_1_col1 = eval.input(1);
    eval.set_col(1, input_limb_1_col1);
    let wg_v0 = eval.input_u32(2);
    let wg_v1 = eval.u32_low(wg_v0);
    let input_limb_2_col2 = eval.u16_as_m31(wg_v1);
    eval.set_col(2, input_limb_2_col2);
    let wg_v2 = eval.input_u32(2);
    let wg_v3 = eval.u32_high(wg_v2);
    let input_limb_3_col3 = eval.u16_as_m31(wg_v3);
    eval.set_col(3, input_limb_3_col3);
    let wg_v4 = eval.input_u32(3);
    let wg_v5 = eval.u32_low(wg_v4);
    let input_limb_4_col4 = eval.u16_as_m31(wg_v5);
    eval.set_col(4, input_limb_4_col4);
    let wg_v6 = eval.input_u32(3);
    let wg_v7 = eval.u32_high(wg_v6);
    let input_limb_5_col5 = eval.u16_as_m31(wg_v7);
    eval.set_col(5, input_limb_5_col5);
    let wg_v8 = eval.input_u32(4);
    let wg_v9 = eval.u32_low(wg_v8);
    let input_limb_6_col6 = eval.u16_as_m31(wg_v9);
    eval.set_col(6, input_limb_6_col6);
    let wg_v10 = eval.input_u32(4);
    let wg_v11 = eval.u32_high(wg_v10);
    let input_limb_7_col7 = eval.u16_as_m31(wg_v11);
    eval.set_col(7, input_limb_7_col7);
    let wg_v12 = eval.input_u32(5);
    let wg_v13 = eval.u32_low(wg_v12);
    let input_limb_8_col8 = eval.u16_as_m31(wg_v13);
    eval.set_col(8, input_limb_8_col8);
    let wg_v14 = eval.input_u32(5);
    let wg_v15 = eval.u32_high(wg_v14);
    let input_limb_9_col9 = eval.u16_as_m31(wg_v15);
    eval.set_col(9, input_limb_9_col9);
    let wg_v16 = eval.input_u32(6);
    let wg_v17 = eval.u32_low(wg_v16);
    let input_limb_10_col10 = eval.u16_as_m31(wg_v17);
    eval.set_col(10, input_limb_10_col10);
    let wg_v18 = eval.input_u32(6);
    let wg_v19 = eval.u32_high(wg_v18);
    let input_limb_11_col11 = eval.u16_as_m31(wg_v19);
    eval.set_col(11, input_limb_11_col11);
    let wg_v20 = eval.input_u32(7);
    let wg_v21 = eval.u32_low(wg_v20);
    let input_limb_12_col12 = eval.u16_as_m31(wg_v21);
    eval.set_col(12, input_limb_12_col12);
    let wg_v22 = eval.input_u32(7);
    let wg_v23 = eval.u32_high(wg_v22);
    let input_limb_13_col13 = eval.u16_as_m31(wg_v23);
    eval.set_col(13, input_limb_13_col13);
    let wg_v24 = eval.input_u32(8);
    let wg_v25 = eval.u32_low(wg_v24);
    let input_limb_14_col14 = eval.u16_as_m31(wg_v25);
    eval.set_col(14, input_limb_14_col14);
    let wg_v26 = eval.input_u32(8);
    let wg_v27 = eval.u32_high(wg_v26);
    let input_limb_15_col15 = eval.u16_as_m31(wg_v27);
    eval.set_col(15, input_limb_15_col15);
    let wg_v28 = eval.input_u32(9);
    let wg_v29 = eval.u32_low(wg_v28);
    let input_limb_16_col16 = eval.u16_as_m31(wg_v29);
    eval.set_col(16, input_limb_16_col16);
    let wg_v30 = eval.input_u32(9);
    let wg_v31 = eval.u32_high(wg_v30);
    let input_limb_17_col17 = eval.u16_as_m31(wg_v31);
    eval.set_col(17, input_limb_17_col17);
    let wg_v32 = eval.input_u32(10);
    let wg_v33 = eval.u32_low(wg_v32);
    let input_limb_18_col18 = eval.u16_as_m31(wg_v33);
    eval.set_col(18, input_limb_18_col18);
    let wg_v34 = eval.input_u32(10);
    let wg_v35 = eval.u32_high(wg_v34);
    let input_limb_19_col19 = eval.u16_as_m31(wg_v35);
    eval.set_col(19, input_limb_19_col19);
    let wg_v36 = eval.input_u32(11);
    let wg_v37 = eval.u32_low(wg_v36);
    let input_limb_20_col20 = eval.u16_as_m31(wg_v37);
    eval.set_col(20, input_limb_20_col20);
    let wg_v38 = eval.input_u32(11);
    let wg_v39 = eval.u32_high(wg_v38);
    let input_limb_21_col21 = eval.u16_as_m31(wg_v39);
    eval.set_col(21, input_limb_21_col21);
    let wg_v40 = eval.input_u32(12);
    let wg_v41 = eval.u32_low(wg_v40);
    let input_limb_22_col22 = eval.u16_as_m31(wg_v41);
    eval.set_col(22, input_limb_22_col22);
    let wg_v42 = eval.input_u32(12);
    let wg_v43 = eval.u32_high(wg_v42);
    let input_limb_23_col23 = eval.u16_as_m31(wg_v43);
    eval.set_col(23, input_limb_23_col23);
    let wg_v44 = eval.input_u32(13);
    let wg_v45 = eval.u32_low(wg_v44);
    let input_limb_24_col24 = eval.u16_as_m31(wg_v45);
    eval.set_col(24, input_limb_24_col24);
    let wg_v46 = eval.input_u32(13);
    let wg_v47 = eval.u32_high(wg_v46);
    let input_limb_25_col25 = eval.u16_as_m31(wg_v47);
    eval.set_col(25, input_limb_25_col25);
    let wg_v48 = eval.input_u32(14);
    let wg_v49 = eval.u32_low(wg_v48);
    let input_limb_26_col26 = eval.u16_as_m31(wg_v49);
    eval.set_col(26, input_limb_26_col26);
    let wg_v50 = eval.input_u32(14);
    let wg_v51 = eval.u32_high(wg_v50);
    let input_limb_27_col27 = eval.u16_as_m31(wg_v51);
    eval.set_col(27, input_limb_27_col27);
    let wg_v52 = eval.input_u32(15);
    let wg_v53 = eval.u32_low(wg_v52);
    let input_limb_28_col28 = eval.u16_as_m31(wg_v53);
    eval.set_col(28, input_limb_28_col28);
    let wg_v54 = eval.input_u32(15);
    let wg_v55 = eval.u32_high(wg_v54);
    let input_limb_29_col29 = eval.u16_as_m31(wg_v55);
    eval.set_col(29, input_limb_29_col29);
    let wg_v56 = eval.input_u32(16);
    let wg_v57 = eval.u32_low(wg_v56);
    let input_limb_30_col30 = eval.u16_as_m31(wg_v57);
    eval.set_col(30, input_limb_30_col30);
    let wg_v58 = eval.input_u32(16);
    let wg_v59 = eval.u32_high(wg_v58);
    let input_limb_31_col31 = eval.u16_as_m31(wg_v59);
    eval.set_col(31, input_limb_31_col31);
    let wg_v60 = eval.input_u32(17);
    let wg_v61 = eval.u32_low(wg_v60);
    let input_limb_32_col32 = eval.u16_as_m31(wg_v61);
    eval.set_col(32, input_limb_32_col32);
    let wg_v62 = eval.input_u32(17);
    let wg_v63 = eval.u32_high(wg_v62);
    let input_limb_33_col33 = eval.u16_as_m31(wg_v63);
    eval.set_col(33, input_limb_33_col33);
    let input_limb_34_col34 = eval.input(18);
    eval.set_col(34, input_limb_34_col34);
    eval.set_sub_input_word(0, input_limb_1_col1);
    let blake_round_sigma_output_tmp_92ff8_0 = eval.deduce_blake_round_sigma(input_limb_1_col1);
    let blake_round_sigma_output_limb_0_col35 = blake_round_sigma_output_tmp_92ff8_0[0];
    eval.set_col(35, blake_round_sigma_output_limb_0_col35);
    let blake_round_sigma_output_limb_1_col36 = blake_round_sigma_output_tmp_92ff8_0[1];
    eval.set_col(36, blake_round_sigma_output_limb_1_col36);
    let blake_round_sigma_output_limb_2_col37 = blake_round_sigma_output_tmp_92ff8_0[2];
    eval.set_col(37, blake_round_sigma_output_limb_2_col37);
    let blake_round_sigma_output_limb_3_col38 = blake_round_sigma_output_tmp_92ff8_0[3];
    eval.set_col(38, blake_round_sigma_output_limb_3_col38);
    let blake_round_sigma_output_limb_4_col39 = blake_round_sigma_output_tmp_92ff8_0[4];
    eval.set_col(39, blake_round_sigma_output_limb_4_col39);
    let blake_round_sigma_output_limb_5_col40 = blake_round_sigma_output_tmp_92ff8_0[5];
    eval.set_col(40, blake_round_sigma_output_limb_5_col40);
    let blake_round_sigma_output_limb_6_col41 = blake_round_sigma_output_tmp_92ff8_0[6];
    eval.set_col(41, blake_round_sigma_output_limb_6_col41);
    let blake_round_sigma_output_limb_7_col42 = blake_round_sigma_output_tmp_92ff8_0[7];
    eval.set_col(42, blake_round_sigma_output_limb_7_col42);
    let blake_round_sigma_output_limb_8_col43 = blake_round_sigma_output_tmp_92ff8_0[8];
    eval.set_col(43, blake_round_sigma_output_limb_8_col43);
    let blake_round_sigma_output_limb_9_col44 = blake_round_sigma_output_tmp_92ff8_0[9];
    eval.set_col(44, blake_round_sigma_output_limb_9_col44);
    let blake_round_sigma_output_limb_10_col45 = blake_round_sigma_output_tmp_92ff8_0[10];
    eval.set_col(45, blake_round_sigma_output_limb_10_col45);
    let blake_round_sigma_output_limb_11_col46 = blake_round_sigma_output_tmp_92ff8_0[11];
    eval.set_col(46, blake_round_sigma_output_limb_11_col46);
    let blake_round_sigma_output_limb_12_col47 = blake_round_sigma_output_tmp_92ff8_0[12];
    eval.set_col(47, blake_round_sigma_output_limb_12_col47);
    let blake_round_sigma_output_limb_13_col48 = blake_round_sigma_output_tmp_92ff8_0[13];
    eval.set_col(48, blake_round_sigma_output_limb_13_col48);
    let blake_round_sigma_output_limb_14_col49 = blake_round_sigma_output_tmp_92ff8_0[14];
    eval.set_col(49, blake_round_sigma_output_limb_14_col49);
    let blake_round_sigma_output_limb_15_col50 = blake_round_sigma_output_tmp_92ff8_0[15];
    eval.set_col(50, blake_round_sigma_output_limb_15_col50);
    eval.set_lookup_word(240, m31_1805967942);
    eval.set_lookup_word(241, input_limb_1_col1);
    eval.set_lookup_word(242, blake_round_sigma_output_limb_0_col35);
    eval.set_lookup_word(243, blake_round_sigma_output_limb_1_col36);
    eval.set_lookup_word(244, blake_round_sigma_output_limb_2_col37);
    eval.set_lookup_word(245, blake_round_sigma_output_limb_3_col38);
    eval.set_lookup_word(246, blake_round_sigma_output_limb_4_col39);
    eval.set_lookup_word(247, blake_round_sigma_output_limb_5_col40);
    eval.set_lookup_word(248, blake_round_sigma_output_limb_6_col41);
    eval.set_lookup_word(249, blake_round_sigma_output_limb_7_col42);
    eval.set_lookup_word(250, blake_round_sigma_output_limb_8_col43);
    eval.set_lookup_word(251, blake_round_sigma_output_limb_9_col44);
    eval.set_lookup_word(252, blake_round_sigma_output_limb_10_col45);
    eval.set_lookup_word(253, blake_round_sigma_output_limb_11_col46);
    eval.set_lookup_word(254, blake_round_sigma_output_limb_12_col47);
    eval.set_lookup_word(255, blake_round_sigma_output_limb_13_col48);
    eval.set_lookup_word(256, blake_round_sigma_output_limb_14_col49);
    eval.set_lookup_word(257, blake_round_sigma_output_limb_15_col50);
    let wg_v64 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_0_col35);
    let memory_address_to_id_value_tmp_92ff8_1 = eval.mem_addr_to_id(wg_v64);
    let memory_id_to_big_value_tmp_92ff8_2 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_1);
    let wg_v65 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_2.clone(), 1);
    let wg_v66 = eval.u16_from_m31(wg_v65);
    let tmp_92ff8_3 = eval.u16_shr(wg_v66, 7);
    let wg_v67 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_2.clone(), 1);
    let wg_v68 = eval.u16_as_m31(tmp_92ff8_3);
    let wg_v69 = eval.m31_mul(wg_v68, m31_128);
    let wg_v70 = eval.m31_sub(wg_v67, wg_v69);
    let wg_v71 = eval.m31_mul(wg_v70, m31_512);
    let wg_v72 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_2.clone(), 0);
    let low_16_bits_col51 = eval.m31_add(wg_v71, wg_v72);
    eval.set_col(51, low_16_bits_col51);
    let wg_v73 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_2.clone(), 3);
    let wg_v74 = eval.m31_mul(wg_v73, m31_2048);
    let wg_v75 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_2.clone(), 2);
    let wg_v76 = eval.m31_mul(wg_v75, m31_4);
    let wg_v77 = eval.m31_add(wg_v74, wg_v76);
    let wg_v78 = eval.u16_as_m31(tmp_92ff8_3);
    let high_16_bits_col52 = eval.m31_add(wg_v77, wg_v78);
    eval.set_col(52, high_16_bits_col52);
    let expected_word_tmp_92ff8_4 = eval.u32_from_limbs(low_16_bits_col51, high_16_bits_col52);
    let wg_v79 = eval.u32_low(expected_word_tmp_92ff8_4);
    let low_7_ms_bits_tmp_92ff8_5 = eval.u16_shr(wg_v79, 9);
    let low_7_ms_bits_col53 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_5);
    eval.set_col(53, low_7_ms_bits_col53);
    let wg_v80 = eval.u32_high(expected_word_tmp_92ff8_4);
    let high_14_ms_bits_tmp_92ff8_6 = eval.u16_shr(wg_v80, 2);
    let high_14_ms_bits_col54 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_6);
    eval.set_col(54, high_14_ms_bits_col54);
    let wg_v81 = eval.m31_mul(high_14_ms_bits_col54, m31_4);
    let high_2_ls_bits_tmp_92ff8_7 = eval.m31_sub(high_16_bits_col52, wg_v81);
    let high_5_ms_bits_tmp_92ff8_8 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_6, 9);
    let high_5_ms_bits_col55 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_8);
    eval.set_col(55, high_5_ms_bits_col55);
    eval.set_sub_input_word(1, low_7_ms_bits_col53);
    eval.set_sub_input_word(2, high_2_ls_bits_tmp_92ff8_7);
    eval.set_sub_input_word(3, high_5_ms_bits_col55);
    eval.set_lookup_word(786, m31_371240602);
    eval.set_lookup_word(787, low_7_ms_bits_col53);
    eval.set_lookup_word(788, high_2_ls_bits_tmp_92ff8_7);
    eval.set_lookup_word(789, high_5_ms_bits_col55);
    let wg_v82 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_0_col35);
    let memory_address_to_id_value_tmp_92ff8_9 = eval.mem_addr_to_id(wg_v82);
    let message_word_0_id_col56 = memory_address_to_id_value_tmp_92ff8_9;
    eval.set_col(56, message_word_0_id_col56);
    let wg_v83 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_0_col35);
    eval.set_sub_input_word(49, wg_v83);
    eval.set_lookup_word(258, m31_1444891767);
    let wg_v84 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_0_col35);
    eval.set_lookup_word(259, wg_v84);
    eval.set_lookup_word(260, message_word_0_id_col56);
    eval.set_sub_input_word(65, message_word_0_id_col56);
    eval.set_lookup_word(306, m31_1662111297);
    eval.set_lookup_word(307, message_word_0_id_col56);
    let wg_v85 = eval.m31_mul(low_7_ms_bits_col53, m31_512);
    let wg_v86 = eval.m31_sub(low_16_bits_col51, wg_v85);
    eval.set_lookup_word(308, wg_v86);
    let wg_v87 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_7, m31_128);
    let wg_v88 = eval.m31_add(low_7_ms_bits_col53, wg_v87);
    eval.set_lookup_word(309, wg_v88);
    let wg_v89 = eval.m31_mul(high_5_ms_bits_col55, m31_512);
    let wg_v90 = eval.m31_sub(high_14_ms_bits_col54, wg_v89);
    eval.set_lookup_word(310, wg_v90);
    eval.set_lookup_word(311, high_5_ms_bits_col55);
    eval.set_lookup_word(312, m31_0);
    eval.set_lookup_word(313, m31_0);
    eval.set_lookup_word(314, m31_0);
    eval.set_lookup_word(315, m31_0);
    eval.set_lookup_word(316, m31_0);
    eval.set_lookup_word(317, m31_0);
    eval.set_lookup_word(318, m31_0);
    eval.set_lookup_word(319, m31_0);
    eval.set_lookup_word(320, m31_0);
    eval.set_lookup_word(321, m31_0);
    eval.set_lookup_word(322, m31_0);
    eval.set_lookup_word(323, m31_0);
    eval.set_lookup_word(324, m31_0);
    eval.set_lookup_word(325, m31_0);
    eval.set_lookup_word(326, m31_0);
    eval.set_lookup_word(327, m31_0);
    eval.set_lookup_word(328, m31_0);
    eval.set_lookup_word(329, m31_0);
    eval.set_lookup_word(330, m31_0);
    eval.set_lookup_word(331, m31_0);
    eval.set_lookup_word(332, m31_0);
    eval.set_lookup_word(333, m31_0);
    eval.set_lookup_word(334, m31_0);
    eval.set_lookup_word(335, m31_0);
    let read_u_32_output_tmp_92ff8_11 = expected_word_tmp_92ff8_4;
    let wg_v91 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_1_col36);
    let memory_address_to_id_value_tmp_92ff8_12 = eval.mem_addr_to_id(wg_v91);
    let memory_id_to_big_value_tmp_92ff8_13 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_12);
    let wg_v92 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_13.clone(), 1);
    let wg_v93 = eval.u16_from_m31(wg_v92);
    let tmp_92ff8_14 = eval.u16_shr(wg_v93, 7);
    let wg_v94 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_13.clone(), 1);
    let wg_v95 = eval.u16_as_m31(tmp_92ff8_14);
    let wg_v96 = eval.m31_mul(wg_v95, m31_128);
    let wg_v97 = eval.m31_sub(wg_v94, wg_v96);
    let wg_v98 = eval.m31_mul(wg_v97, m31_512);
    let wg_v99 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_13.clone(), 0);
    let low_16_bits_col57 = eval.m31_add(wg_v98, wg_v99);
    eval.set_col(57, low_16_bits_col57);
    let wg_v100 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_13.clone(), 3);
    let wg_v101 = eval.m31_mul(wg_v100, m31_2048);
    let wg_v102 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_13.clone(), 2);
    let wg_v103 = eval.m31_mul(wg_v102, m31_4);
    let wg_v104 = eval.m31_add(wg_v101, wg_v103);
    let wg_v105 = eval.u16_as_m31(tmp_92ff8_14);
    let high_16_bits_col58 = eval.m31_add(wg_v104, wg_v105);
    eval.set_col(58, high_16_bits_col58);
    let expected_word_tmp_92ff8_15 = eval.u32_from_limbs(low_16_bits_col57, high_16_bits_col58);
    let wg_v106 = eval.u32_low(expected_word_tmp_92ff8_15);
    let low_7_ms_bits_tmp_92ff8_16 = eval.u16_shr(wg_v106, 9);
    let low_7_ms_bits_col59 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_16);
    eval.set_col(59, low_7_ms_bits_col59);
    let wg_v107 = eval.u32_high(expected_word_tmp_92ff8_15);
    let high_14_ms_bits_tmp_92ff8_17 = eval.u16_shr(wg_v107, 2);
    let high_14_ms_bits_col60 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_17);
    eval.set_col(60, high_14_ms_bits_col60);
    let wg_v108 = eval.m31_mul(high_14_ms_bits_col60, m31_4);
    let high_2_ls_bits_tmp_92ff8_18 = eval.m31_sub(high_16_bits_col58, wg_v108);
    let high_5_ms_bits_tmp_92ff8_19 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_17, 9);
    let high_5_ms_bits_col61 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_19);
    eval.set_col(61, high_5_ms_bits_col61);
    eval.set_sub_input_word(4, low_7_ms_bits_col59);
    eval.set_sub_input_word(5, high_2_ls_bits_tmp_92ff8_18);
    eval.set_sub_input_word(6, high_5_ms_bits_col61);
    eval.set_lookup_word(790, m31_371240602);
    eval.set_lookup_word(791, low_7_ms_bits_col59);
    eval.set_lookup_word(792, high_2_ls_bits_tmp_92ff8_18);
    eval.set_lookup_word(793, high_5_ms_bits_col61);
    let wg_v109 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_1_col36);
    let memory_address_to_id_value_tmp_92ff8_20 = eval.mem_addr_to_id(wg_v109);
    let message_word_1_id_col62 = memory_address_to_id_value_tmp_92ff8_20;
    eval.set_col(62, message_word_1_id_col62);
    let wg_v110 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_1_col36);
    eval.set_sub_input_word(50, wg_v110);
    eval.set_lookup_word(261, m31_1444891767);
    let wg_v111 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_1_col36);
    eval.set_lookup_word(262, wg_v111);
    eval.set_lookup_word(263, message_word_1_id_col62);
    eval.set_sub_input_word(66, message_word_1_id_col62);
    eval.set_lookup_word(336, m31_1662111297);
    eval.set_lookup_word(337, message_word_1_id_col62);
    let wg_v112 = eval.m31_mul(low_7_ms_bits_col59, m31_512);
    let wg_v113 = eval.m31_sub(low_16_bits_col57, wg_v112);
    eval.set_lookup_word(338, wg_v113);
    let wg_v114 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_18, m31_128);
    let wg_v115 = eval.m31_add(low_7_ms_bits_col59, wg_v114);
    eval.set_lookup_word(339, wg_v115);
    let wg_v116 = eval.m31_mul(high_5_ms_bits_col61, m31_512);
    let wg_v117 = eval.m31_sub(high_14_ms_bits_col60, wg_v116);
    eval.set_lookup_word(340, wg_v117);
    eval.set_lookup_word(341, high_5_ms_bits_col61);
    eval.set_lookup_word(342, m31_0);
    eval.set_lookup_word(343, m31_0);
    eval.set_lookup_word(344, m31_0);
    eval.set_lookup_word(345, m31_0);
    eval.set_lookup_word(346, m31_0);
    eval.set_lookup_word(347, m31_0);
    eval.set_lookup_word(348, m31_0);
    eval.set_lookup_word(349, m31_0);
    eval.set_lookup_word(350, m31_0);
    eval.set_lookup_word(351, m31_0);
    eval.set_lookup_word(352, m31_0);
    eval.set_lookup_word(353, m31_0);
    eval.set_lookup_word(354, m31_0);
    eval.set_lookup_word(355, m31_0);
    eval.set_lookup_word(356, m31_0);
    eval.set_lookup_word(357, m31_0);
    eval.set_lookup_word(358, m31_0);
    eval.set_lookup_word(359, m31_0);
    eval.set_lookup_word(360, m31_0);
    eval.set_lookup_word(361, m31_0);
    eval.set_lookup_word(362, m31_0);
    eval.set_lookup_word(363, m31_0);
    eval.set_lookup_word(364, m31_0);
    eval.set_lookup_word(365, m31_0);
    let read_u_32_output_tmp_92ff8_22 = expected_word_tmp_92ff8_15;
    let wg_v118 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_2_col37);
    let memory_address_to_id_value_tmp_92ff8_23 = eval.mem_addr_to_id(wg_v118);
    let memory_id_to_big_value_tmp_92ff8_24 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_23);
    let wg_v119 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_24.clone(), 1);
    let wg_v120 = eval.u16_from_m31(wg_v119);
    let tmp_92ff8_25 = eval.u16_shr(wg_v120, 7);
    let wg_v121 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_24.clone(), 1);
    let wg_v122 = eval.u16_as_m31(tmp_92ff8_25);
    let wg_v123 = eval.m31_mul(wg_v122, m31_128);
    let wg_v124 = eval.m31_sub(wg_v121, wg_v123);
    let wg_v125 = eval.m31_mul(wg_v124, m31_512);
    let wg_v126 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_24.clone(), 0);
    let low_16_bits_col63 = eval.m31_add(wg_v125, wg_v126);
    eval.set_col(63, low_16_bits_col63);
    let wg_v127 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_24.clone(), 3);
    let wg_v128 = eval.m31_mul(wg_v127, m31_2048);
    let wg_v129 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_24.clone(), 2);
    let wg_v130 = eval.m31_mul(wg_v129, m31_4);
    let wg_v131 = eval.m31_add(wg_v128, wg_v130);
    let wg_v132 = eval.u16_as_m31(tmp_92ff8_25);
    let high_16_bits_col64 = eval.m31_add(wg_v131, wg_v132);
    eval.set_col(64, high_16_bits_col64);
    let expected_word_tmp_92ff8_26 = eval.u32_from_limbs(low_16_bits_col63, high_16_bits_col64);
    let wg_v133 = eval.u32_low(expected_word_tmp_92ff8_26);
    let low_7_ms_bits_tmp_92ff8_27 = eval.u16_shr(wg_v133, 9);
    let low_7_ms_bits_col65 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_27);
    eval.set_col(65, low_7_ms_bits_col65);
    let wg_v134 = eval.u32_high(expected_word_tmp_92ff8_26);
    let high_14_ms_bits_tmp_92ff8_28 = eval.u16_shr(wg_v134, 2);
    let high_14_ms_bits_col66 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_28);
    eval.set_col(66, high_14_ms_bits_col66);
    let wg_v135 = eval.m31_mul(high_14_ms_bits_col66, m31_4);
    let high_2_ls_bits_tmp_92ff8_29 = eval.m31_sub(high_16_bits_col64, wg_v135);
    let high_5_ms_bits_tmp_92ff8_30 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_28, 9);
    let high_5_ms_bits_col67 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_30);
    eval.set_col(67, high_5_ms_bits_col67);
    eval.set_sub_input_word(7, low_7_ms_bits_col65);
    eval.set_sub_input_word(8, high_2_ls_bits_tmp_92ff8_29);
    eval.set_sub_input_word(9, high_5_ms_bits_col67);
    eval.set_lookup_word(794, m31_371240602);
    eval.set_lookup_word(795, low_7_ms_bits_col65);
    eval.set_lookup_word(796, high_2_ls_bits_tmp_92ff8_29);
    eval.set_lookup_word(797, high_5_ms_bits_col67);
    let wg_v136 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_2_col37);
    let memory_address_to_id_value_tmp_92ff8_31 = eval.mem_addr_to_id(wg_v136);
    let message_word_2_id_col68 = memory_address_to_id_value_tmp_92ff8_31;
    eval.set_col(68, message_word_2_id_col68);
    let wg_v137 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_2_col37);
    eval.set_sub_input_word(51, wg_v137);
    eval.set_lookup_word(264, m31_1444891767);
    let wg_v138 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_2_col37);
    eval.set_lookup_word(265, wg_v138);
    eval.set_lookup_word(266, message_word_2_id_col68);
    eval.set_sub_input_word(67, message_word_2_id_col68);
    eval.set_lookup_word(366, m31_1662111297);
    eval.set_lookup_word(367, message_word_2_id_col68);
    let wg_v139 = eval.m31_mul(low_7_ms_bits_col65, m31_512);
    let wg_v140 = eval.m31_sub(low_16_bits_col63, wg_v139);
    eval.set_lookup_word(368, wg_v140);
    let wg_v141 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_29, m31_128);
    let wg_v142 = eval.m31_add(low_7_ms_bits_col65, wg_v141);
    eval.set_lookup_word(369, wg_v142);
    let wg_v143 = eval.m31_mul(high_5_ms_bits_col67, m31_512);
    let wg_v144 = eval.m31_sub(high_14_ms_bits_col66, wg_v143);
    eval.set_lookup_word(370, wg_v144);
    eval.set_lookup_word(371, high_5_ms_bits_col67);
    eval.set_lookup_word(372, m31_0);
    eval.set_lookup_word(373, m31_0);
    eval.set_lookup_word(374, m31_0);
    eval.set_lookup_word(375, m31_0);
    eval.set_lookup_word(376, m31_0);
    eval.set_lookup_word(377, m31_0);
    eval.set_lookup_word(378, m31_0);
    eval.set_lookup_word(379, m31_0);
    eval.set_lookup_word(380, m31_0);
    eval.set_lookup_word(381, m31_0);
    eval.set_lookup_word(382, m31_0);
    eval.set_lookup_word(383, m31_0);
    eval.set_lookup_word(384, m31_0);
    eval.set_lookup_word(385, m31_0);
    eval.set_lookup_word(386, m31_0);
    eval.set_lookup_word(387, m31_0);
    eval.set_lookup_word(388, m31_0);
    eval.set_lookup_word(389, m31_0);
    eval.set_lookup_word(390, m31_0);
    eval.set_lookup_word(391, m31_0);
    eval.set_lookup_word(392, m31_0);
    eval.set_lookup_word(393, m31_0);
    eval.set_lookup_word(394, m31_0);
    eval.set_lookup_word(395, m31_0);
    let read_u_32_output_tmp_92ff8_33 = expected_word_tmp_92ff8_26;
    let wg_v145 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_3_col38);
    let memory_address_to_id_value_tmp_92ff8_34 = eval.mem_addr_to_id(wg_v145);
    let memory_id_to_big_value_tmp_92ff8_35 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_34);
    let wg_v146 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_35.clone(), 1);
    let wg_v147 = eval.u16_from_m31(wg_v146);
    let tmp_92ff8_36 = eval.u16_shr(wg_v147, 7);
    let wg_v148 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_35.clone(), 1);
    let wg_v149 = eval.u16_as_m31(tmp_92ff8_36);
    let wg_v150 = eval.m31_mul(wg_v149, m31_128);
    let wg_v151 = eval.m31_sub(wg_v148, wg_v150);
    let wg_v152 = eval.m31_mul(wg_v151, m31_512);
    let wg_v153 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_35.clone(), 0);
    let low_16_bits_col69 = eval.m31_add(wg_v152, wg_v153);
    eval.set_col(69, low_16_bits_col69);
    let wg_v154 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_35.clone(), 3);
    let wg_v155 = eval.m31_mul(wg_v154, m31_2048);
    let wg_v156 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_35.clone(), 2);
    let wg_v157 = eval.m31_mul(wg_v156, m31_4);
    let wg_v158 = eval.m31_add(wg_v155, wg_v157);
    let wg_v159 = eval.u16_as_m31(tmp_92ff8_36);
    let high_16_bits_col70 = eval.m31_add(wg_v158, wg_v159);
    eval.set_col(70, high_16_bits_col70);
    let expected_word_tmp_92ff8_37 = eval.u32_from_limbs(low_16_bits_col69, high_16_bits_col70);
    let wg_v160 = eval.u32_low(expected_word_tmp_92ff8_37);
    let low_7_ms_bits_tmp_92ff8_38 = eval.u16_shr(wg_v160, 9);
    let low_7_ms_bits_col71 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_38);
    eval.set_col(71, low_7_ms_bits_col71);
    let wg_v161 = eval.u32_high(expected_word_tmp_92ff8_37);
    let high_14_ms_bits_tmp_92ff8_39 = eval.u16_shr(wg_v161, 2);
    let high_14_ms_bits_col72 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_39);
    eval.set_col(72, high_14_ms_bits_col72);
    let wg_v162 = eval.m31_mul(high_14_ms_bits_col72, m31_4);
    let high_2_ls_bits_tmp_92ff8_40 = eval.m31_sub(high_16_bits_col70, wg_v162);
    let high_5_ms_bits_tmp_92ff8_41 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_39, 9);
    let high_5_ms_bits_col73 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_41);
    eval.set_col(73, high_5_ms_bits_col73);
    eval.set_sub_input_word(10, low_7_ms_bits_col71);
    eval.set_sub_input_word(11, high_2_ls_bits_tmp_92ff8_40);
    eval.set_sub_input_word(12, high_5_ms_bits_col73);
    eval.set_lookup_word(798, m31_371240602);
    eval.set_lookup_word(799, low_7_ms_bits_col71);
    eval.set_lookup_word(800, high_2_ls_bits_tmp_92ff8_40);
    eval.set_lookup_word(801, high_5_ms_bits_col73);
    let wg_v163 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_3_col38);
    let memory_address_to_id_value_tmp_92ff8_42 = eval.mem_addr_to_id(wg_v163);
    let message_word_3_id_col74 = memory_address_to_id_value_tmp_92ff8_42;
    eval.set_col(74, message_word_3_id_col74);
    let wg_v164 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_3_col38);
    eval.set_sub_input_word(52, wg_v164);
    eval.set_lookup_word(267, m31_1444891767);
    let wg_v165 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_3_col38);
    eval.set_lookup_word(268, wg_v165);
    eval.set_lookup_word(269, message_word_3_id_col74);
    eval.set_sub_input_word(68, message_word_3_id_col74);
    eval.set_lookup_word(396, m31_1662111297);
    eval.set_lookup_word(397, message_word_3_id_col74);
    let wg_v166 = eval.m31_mul(low_7_ms_bits_col71, m31_512);
    let wg_v167 = eval.m31_sub(low_16_bits_col69, wg_v166);
    eval.set_lookup_word(398, wg_v167);
    let wg_v168 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_40, m31_128);
    let wg_v169 = eval.m31_add(low_7_ms_bits_col71, wg_v168);
    eval.set_lookup_word(399, wg_v169);
    let wg_v170 = eval.m31_mul(high_5_ms_bits_col73, m31_512);
    let wg_v171 = eval.m31_sub(high_14_ms_bits_col72, wg_v170);
    eval.set_lookup_word(400, wg_v171);
    eval.set_lookup_word(401, high_5_ms_bits_col73);
    eval.set_lookup_word(402, m31_0);
    eval.set_lookup_word(403, m31_0);
    eval.set_lookup_word(404, m31_0);
    eval.set_lookup_word(405, m31_0);
    eval.set_lookup_word(406, m31_0);
    eval.set_lookup_word(407, m31_0);
    eval.set_lookup_word(408, m31_0);
    eval.set_lookup_word(409, m31_0);
    eval.set_lookup_word(410, m31_0);
    eval.set_lookup_word(411, m31_0);
    eval.set_lookup_word(412, m31_0);
    eval.set_lookup_word(413, m31_0);
    eval.set_lookup_word(414, m31_0);
    eval.set_lookup_word(415, m31_0);
    eval.set_lookup_word(416, m31_0);
    eval.set_lookup_word(417, m31_0);
    eval.set_lookup_word(418, m31_0);
    eval.set_lookup_word(419, m31_0);
    eval.set_lookup_word(420, m31_0);
    eval.set_lookup_word(421, m31_0);
    eval.set_lookup_word(422, m31_0);
    eval.set_lookup_word(423, m31_0);
    eval.set_lookup_word(424, m31_0);
    eval.set_lookup_word(425, m31_0);
    let read_u_32_output_tmp_92ff8_44 = expected_word_tmp_92ff8_37;
    let wg_v172 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_4_col39);
    let memory_address_to_id_value_tmp_92ff8_45 = eval.mem_addr_to_id(wg_v172);
    let memory_id_to_big_value_tmp_92ff8_46 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_45);
    let wg_v173 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_46.clone(), 1);
    let wg_v174 = eval.u16_from_m31(wg_v173);
    let tmp_92ff8_47 = eval.u16_shr(wg_v174, 7);
    let wg_v175 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_46.clone(), 1);
    let wg_v176 = eval.u16_as_m31(tmp_92ff8_47);
    let wg_v177 = eval.m31_mul(wg_v176, m31_128);
    let wg_v178 = eval.m31_sub(wg_v175, wg_v177);
    let wg_v179 = eval.m31_mul(wg_v178, m31_512);
    let wg_v180 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_46.clone(), 0);
    let low_16_bits_col75 = eval.m31_add(wg_v179, wg_v180);
    eval.set_col(75, low_16_bits_col75);
    let wg_v181 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_46.clone(), 3);
    let wg_v182 = eval.m31_mul(wg_v181, m31_2048);
    let wg_v183 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_46.clone(), 2);
    let wg_v184 = eval.m31_mul(wg_v183, m31_4);
    let wg_v185 = eval.m31_add(wg_v182, wg_v184);
    let wg_v186 = eval.u16_as_m31(tmp_92ff8_47);
    let high_16_bits_col76 = eval.m31_add(wg_v185, wg_v186);
    eval.set_col(76, high_16_bits_col76);
    let expected_word_tmp_92ff8_48 = eval.u32_from_limbs(low_16_bits_col75, high_16_bits_col76);
    let wg_v187 = eval.u32_low(expected_word_tmp_92ff8_48);
    let low_7_ms_bits_tmp_92ff8_49 = eval.u16_shr(wg_v187, 9);
    let low_7_ms_bits_col77 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_49);
    eval.set_col(77, low_7_ms_bits_col77);
    let wg_v188 = eval.u32_high(expected_word_tmp_92ff8_48);
    let high_14_ms_bits_tmp_92ff8_50 = eval.u16_shr(wg_v188, 2);
    let high_14_ms_bits_col78 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_50);
    eval.set_col(78, high_14_ms_bits_col78);
    let wg_v189 = eval.m31_mul(high_14_ms_bits_col78, m31_4);
    let high_2_ls_bits_tmp_92ff8_51 = eval.m31_sub(high_16_bits_col76, wg_v189);
    let high_5_ms_bits_tmp_92ff8_52 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_50, 9);
    let high_5_ms_bits_col79 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_52);
    eval.set_col(79, high_5_ms_bits_col79);
    eval.set_sub_input_word(13, low_7_ms_bits_col77);
    eval.set_sub_input_word(14, high_2_ls_bits_tmp_92ff8_51);
    eval.set_sub_input_word(15, high_5_ms_bits_col79);
    eval.set_lookup_word(802, m31_371240602);
    eval.set_lookup_word(803, low_7_ms_bits_col77);
    eval.set_lookup_word(804, high_2_ls_bits_tmp_92ff8_51);
    eval.set_lookup_word(805, high_5_ms_bits_col79);
    let wg_v190 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_4_col39);
    let memory_address_to_id_value_tmp_92ff8_53 = eval.mem_addr_to_id(wg_v190);
    let message_word_4_id_col80 = memory_address_to_id_value_tmp_92ff8_53;
    eval.set_col(80, message_word_4_id_col80);
    let wg_v191 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_4_col39);
    eval.set_sub_input_word(53, wg_v191);
    eval.set_lookup_word(270, m31_1444891767);
    let wg_v192 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_4_col39);
    eval.set_lookup_word(271, wg_v192);
    eval.set_lookup_word(272, message_word_4_id_col80);
    eval.set_sub_input_word(69, message_word_4_id_col80);
    eval.set_lookup_word(426, m31_1662111297);
    eval.set_lookup_word(427, message_word_4_id_col80);
    let wg_v193 = eval.m31_mul(low_7_ms_bits_col77, m31_512);
    let wg_v194 = eval.m31_sub(low_16_bits_col75, wg_v193);
    eval.set_lookup_word(428, wg_v194);
    let wg_v195 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_51, m31_128);
    let wg_v196 = eval.m31_add(low_7_ms_bits_col77, wg_v195);
    eval.set_lookup_word(429, wg_v196);
    let wg_v197 = eval.m31_mul(high_5_ms_bits_col79, m31_512);
    let wg_v198 = eval.m31_sub(high_14_ms_bits_col78, wg_v197);
    eval.set_lookup_word(430, wg_v198);
    eval.set_lookup_word(431, high_5_ms_bits_col79);
    eval.set_lookup_word(432, m31_0);
    eval.set_lookup_word(433, m31_0);
    eval.set_lookup_word(434, m31_0);
    eval.set_lookup_word(435, m31_0);
    eval.set_lookup_word(436, m31_0);
    eval.set_lookup_word(437, m31_0);
    eval.set_lookup_word(438, m31_0);
    eval.set_lookup_word(439, m31_0);
    eval.set_lookup_word(440, m31_0);
    eval.set_lookup_word(441, m31_0);
    eval.set_lookup_word(442, m31_0);
    eval.set_lookup_word(443, m31_0);
    eval.set_lookup_word(444, m31_0);
    eval.set_lookup_word(445, m31_0);
    eval.set_lookup_word(446, m31_0);
    eval.set_lookup_word(447, m31_0);
    eval.set_lookup_word(448, m31_0);
    eval.set_lookup_word(449, m31_0);
    eval.set_lookup_word(450, m31_0);
    eval.set_lookup_word(451, m31_0);
    eval.set_lookup_word(452, m31_0);
    eval.set_lookup_word(453, m31_0);
    eval.set_lookup_word(454, m31_0);
    eval.set_lookup_word(455, m31_0);
    let read_u_32_output_tmp_92ff8_55 = expected_word_tmp_92ff8_48;
    let wg_v199 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_5_col40);
    let memory_address_to_id_value_tmp_92ff8_56 = eval.mem_addr_to_id(wg_v199);
    let memory_id_to_big_value_tmp_92ff8_57 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_56);
    let wg_v200 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_57.clone(), 1);
    let wg_v201 = eval.u16_from_m31(wg_v200);
    let tmp_92ff8_58 = eval.u16_shr(wg_v201, 7);
    let wg_v202 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_57.clone(), 1);
    let wg_v203 = eval.u16_as_m31(tmp_92ff8_58);
    let wg_v204 = eval.m31_mul(wg_v203, m31_128);
    let wg_v205 = eval.m31_sub(wg_v202, wg_v204);
    let wg_v206 = eval.m31_mul(wg_v205, m31_512);
    let wg_v207 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_57.clone(), 0);
    let low_16_bits_col81 = eval.m31_add(wg_v206, wg_v207);
    eval.set_col(81, low_16_bits_col81);
    let wg_v208 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_57.clone(), 3);
    let wg_v209 = eval.m31_mul(wg_v208, m31_2048);
    let wg_v210 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_57.clone(), 2);
    let wg_v211 = eval.m31_mul(wg_v210, m31_4);
    let wg_v212 = eval.m31_add(wg_v209, wg_v211);
    let wg_v213 = eval.u16_as_m31(tmp_92ff8_58);
    let high_16_bits_col82 = eval.m31_add(wg_v212, wg_v213);
    eval.set_col(82, high_16_bits_col82);
    let expected_word_tmp_92ff8_59 = eval.u32_from_limbs(low_16_bits_col81, high_16_bits_col82);
    let wg_v214 = eval.u32_low(expected_word_tmp_92ff8_59);
    let low_7_ms_bits_tmp_92ff8_60 = eval.u16_shr(wg_v214, 9);
    let low_7_ms_bits_col83 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_60);
    eval.set_col(83, low_7_ms_bits_col83);
    let wg_v215 = eval.u32_high(expected_word_tmp_92ff8_59);
    let high_14_ms_bits_tmp_92ff8_61 = eval.u16_shr(wg_v215, 2);
    let high_14_ms_bits_col84 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_61);
    eval.set_col(84, high_14_ms_bits_col84);
    let wg_v216 = eval.m31_mul(high_14_ms_bits_col84, m31_4);
    let high_2_ls_bits_tmp_92ff8_62 = eval.m31_sub(high_16_bits_col82, wg_v216);
    let high_5_ms_bits_tmp_92ff8_63 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_61, 9);
    let high_5_ms_bits_col85 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_63);
    eval.set_col(85, high_5_ms_bits_col85);
    eval.set_sub_input_word(16, low_7_ms_bits_col83);
    eval.set_sub_input_word(17, high_2_ls_bits_tmp_92ff8_62);
    eval.set_sub_input_word(18, high_5_ms_bits_col85);
    eval.set_lookup_word(806, m31_371240602);
    eval.set_lookup_word(807, low_7_ms_bits_col83);
    eval.set_lookup_word(808, high_2_ls_bits_tmp_92ff8_62);
    eval.set_lookup_word(809, high_5_ms_bits_col85);
    let wg_v217 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_5_col40);
    let memory_address_to_id_value_tmp_92ff8_64 = eval.mem_addr_to_id(wg_v217);
    let message_word_5_id_col86 = memory_address_to_id_value_tmp_92ff8_64;
    eval.set_col(86, message_word_5_id_col86);
    let wg_v218 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_5_col40);
    eval.set_sub_input_word(54, wg_v218);
    eval.set_lookup_word(273, m31_1444891767);
    let wg_v219 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_5_col40);
    eval.set_lookup_word(274, wg_v219);
    eval.set_lookup_word(275, message_word_5_id_col86);
    eval.set_sub_input_word(70, message_word_5_id_col86);
    eval.set_lookup_word(456, m31_1662111297);
    eval.set_lookup_word(457, message_word_5_id_col86);
    let wg_v220 = eval.m31_mul(low_7_ms_bits_col83, m31_512);
    let wg_v221 = eval.m31_sub(low_16_bits_col81, wg_v220);
    eval.set_lookup_word(458, wg_v221);
    let wg_v222 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_62, m31_128);
    let wg_v223 = eval.m31_add(low_7_ms_bits_col83, wg_v222);
    eval.set_lookup_word(459, wg_v223);
    let wg_v224 = eval.m31_mul(high_5_ms_bits_col85, m31_512);
    let wg_v225 = eval.m31_sub(high_14_ms_bits_col84, wg_v224);
    eval.set_lookup_word(460, wg_v225);
    eval.set_lookup_word(461, high_5_ms_bits_col85);
    eval.set_lookup_word(462, m31_0);
    eval.set_lookup_word(463, m31_0);
    eval.set_lookup_word(464, m31_0);
    eval.set_lookup_word(465, m31_0);
    eval.set_lookup_word(466, m31_0);
    eval.set_lookup_word(467, m31_0);
    eval.set_lookup_word(468, m31_0);
    eval.set_lookup_word(469, m31_0);
    eval.set_lookup_word(470, m31_0);
    eval.set_lookup_word(471, m31_0);
    eval.set_lookup_word(472, m31_0);
    eval.set_lookup_word(473, m31_0);
    eval.set_lookup_word(474, m31_0);
    eval.set_lookup_word(475, m31_0);
    eval.set_lookup_word(476, m31_0);
    eval.set_lookup_word(477, m31_0);
    eval.set_lookup_word(478, m31_0);
    eval.set_lookup_word(479, m31_0);
    eval.set_lookup_word(480, m31_0);
    eval.set_lookup_word(481, m31_0);
    eval.set_lookup_word(482, m31_0);
    eval.set_lookup_word(483, m31_0);
    eval.set_lookup_word(484, m31_0);
    eval.set_lookup_word(485, m31_0);
    let read_u_32_output_tmp_92ff8_66 = expected_word_tmp_92ff8_59;
    let wg_v226 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_6_col41);
    let memory_address_to_id_value_tmp_92ff8_67 = eval.mem_addr_to_id(wg_v226);
    let memory_id_to_big_value_tmp_92ff8_68 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_67);
    let wg_v227 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_68.clone(), 1);
    let wg_v228 = eval.u16_from_m31(wg_v227);
    let tmp_92ff8_69 = eval.u16_shr(wg_v228, 7);
    let wg_v229 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_68.clone(), 1);
    let wg_v230 = eval.u16_as_m31(tmp_92ff8_69);
    let wg_v231 = eval.m31_mul(wg_v230, m31_128);
    let wg_v232 = eval.m31_sub(wg_v229, wg_v231);
    let wg_v233 = eval.m31_mul(wg_v232, m31_512);
    let wg_v234 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_68.clone(), 0);
    let low_16_bits_col87 = eval.m31_add(wg_v233, wg_v234);
    eval.set_col(87, low_16_bits_col87);
    let wg_v235 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_68.clone(), 3);
    let wg_v236 = eval.m31_mul(wg_v235, m31_2048);
    let wg_v237 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_68.clone(), 2);
    let wg_v238 = eval.m31_mul(wg_v237, m31_4);
    let wg_v239 = eval.m31_add(wg_v236, wg_v238);
    let wg_v240 = eval.u16_as_m31(tmp_92ff8_69);
    let high_16_bits_col88 = eval.m31_add(wg_v239, wg_v240);
    eval.set_col(88, high_16_bits_col88);
    let expected_word_tmp_92ff8_70 = eval.u32_from_limbs(low_16_bits_col87, high_16_bits_col88);
    let wg_v241 = eval.u32_low(expected_word_tmp_92ff8_70);
    let low_7_ms_bits_tmp_92ff8_71 = eval.u16_shr(wg_v241, 9);
    let low_7_ms_bits_col89 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_71);
    eval.set_col(89, low_7_ms_bits_col89);
    let wg_v242 = eval.u32_high(expected_word_tmp_92ff8_70);
    let high_14_ms_bits_tmp_92ff8_72 = eval.u16_shr(wg_v242, 2);
    let high_14_ms_bits_col90 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_72);
    eval.set_col(90, high_14_ms_bits_col90);
    let wg_v243 = eval.m31_mul(high_14_ms_bits_col90, m31_4);
    let high_2_ls_bits_tmp_92ff8_73 = eval.m31_sub(high_16_bits_col88, wg_v243);
    let high_5_ms_bits_tmp_92ff8_74 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_72, 9);
    let high_5_ms_bits_col91 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_74);
    eval.set_col(91, high_5_ms_bits_col91);
    eval.set_sub_input_word(19, low_7_ms_bits_col89);
    eval.set_sub_input_word(20, high_2_ls_bits_tmp_92ff8_73);
    eval.set_sub_input_word(21, high_5_ms_bits_col91);
    eval.set_lookup_word(810, m31_371240602);
    eval.set_lookup_word(811, low_7_ms_bits_col89);
    eval.set_lookup_word(812, high_2_ls_bits_tmp_92ff8_73);
    eval.set_lookup_word(813, high_5_ms_bits_col91);
    let wg_v244 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_6_col41);
    let memory_address_to_id_value_tmp_92ff8_75 = eval.mem_addr_to_id(wg_v244);
    let message_word_6_id_col92 = memory_address_to_id_value_tmp_92ff8_75;
    eval.set_col(92, message_word_6_id_col92);
    let wg_v245 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_6_col41);
    eval.set_sub_input_word(55, wg_v245);
    eval.set_lookup_word(276, m31_1444891767);
    let wg_v246 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_6_col41);
    eval.set_lookup_word(277, wg_v246);
    eval.set_lookup_word(278, message_word_6_id_col92);
    eval.set_sub_input_word(71, message_word_6_id_col92);
    eval.set_lookup_word(486, m31_1662111297);
    eval.set_lookup_word(487, message_word_6_id_col92);
    let wg_v247 = eval.m31_mul(low_7_ms_bits_col89, m31_512);
    let wg_v248 = eval.m31_sub(low_16_bits_col87, wg_v247);
    eval.set_lookup_word(488, wg_v248);
    let wg_v249 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_73, m31_128);
    let wg_v250 = eval.m31_add(low_7_ms_bits_col89, wg_v249);
    eval.set_lookup_word(489, wg_v250);
    let wg_v251 = eval.m31_mul(high_5_ms_bits_col91, m31_512);
    let wg_v252 = eval.m31_sub(high_14_ms_bits_col90, wg_v251);
    eval.set_lookup_word(490, wg_v252);
    eval.set_lookup_word(491, high_5_ms_bits_col91);
    eval.set_lookup_word(492, m31_0);
    eval.set_lookup_word(493, m31_0);
    eval.set_lookup_word(494, m31_0);
    eval.set_lookup_word(495, m31_0);
    eval.set_lookup_word(496, m31_0);
    eval.set_lookup_word(497, m31_0);
    eval.set_lookup_word(498, m31_0);
    eval.set_lookup_word(499, m31_0);
    eval.set_lookup_word(500, m31_0);
    eval.set_lookup_word(501, m31_0);
    eval.set_lookup_word(502, m31_0);
    eval.set_lookup_word(503, m31_0);
    eval.set_lookup_word(504, m31_0);
    eval.set_lookup_word(505, m31_0);
    eval.set_lookup_word(506, m31_0);
    eval.set_lookup_word(507, m31_0);
    eval.set_lookup_word(508, m31_0);
    eval.set_lookup_word(509, m31_0);
    eval.set_lookup_word(510, m31_0);
    eval.set_lookup_word(511, m31_0);
    eval.set_lookup_word(512, m31_0);
    eval.set_lookup_word(513, m31_0);
    eval.set_lookup_word(514, m31_0);
    eval.set_lookup_word(515, m31_0);
    let read_u_32_output_tmp_92ff8_77 = expected_word_tmp_92ff8_70;
    let wg_v253 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_7_col42);
    let memory_address_to_id_value_tmp_92ff8_78 = eval.mem_addr_to_id(wg_v253);
    let memory_id_to_big_value_tmp_92ff8_79 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_78);
    let wg_v254 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_79.clone(), 1);
    let wg_v255 = eval.u16_from_m31(wg_v254);
    let tmp_92ff8_80 = eval.u16_shr(wg_v255, 7);
    let wg_v256 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_79.clone(), 1);
    let wg_v257 = eval.u16_as_m31(tmp_92ff8_80);
    let wg_v258 = eval.m31_mul(wg_v257, m31_128);
    let wg_v259 = eval.m31_sub(wg_v256, wg_v258);
    let wg_v260 = eval.m31_mul(wg_v259, m31_512);
    let wg_v261 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_79.clone(), 0);
    let low_16_bits_col93 = eval.m31_add(wg_v260, wg_v261);
    eval.set_col(93, low_16_bits_col93);
    let wg_v262 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_79.clone(), 3);
    let wg_v263 = eval.m31_mul(wg_v262, m31_2048);
    let wg_v264 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_79.clone(), 2);
    let wg_v265 = eval.m31_mul(wg_v264, m31_4);
    let wg_v266 = eval.m31_add(wg_v263, wg_v265);
    let wg_v267 = eval.u16_as_m31(tmp_92ff8_80);
    let high_16_bits_col94 = eval.m31_add(wg_v266, wg_v267);
    eval.set_col(94, high_16_bits_col94);
    let expected_word_tmp_92ff8_81 = eval.u32_from_limbs(low_16_bits_col93, high_16_bits_col94);
    let wg_v268 = eval.u32_low(expected_word_tmp_92ff8_81);
    let low_7_ms_bits_tmp_92ff8_82 = eval.u16_shr(wg_v268, 9);
    let low_7_ms_bits_col95 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_82);
    eval.set_col(95, low_7_ms_bits_col95);
    let wg_v269 = eval.u32_high(expected_word_tmp_92ff8_81);
    let high_14_ms_bits_tmp_92ff8_83 = eval.u16_shr(wg_v269, 2);
    let high_14_ms_bits_col96 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_83);
    eval.set_col(96, high_14_ms_bits_col96);
    let wg_v270 = eval.m31_mul(high_14_ms_bits_col96, m31_4);
    let high_2_ls_bits_tmp_92ff8_84 = eval.m31_sub(high_16_bits_col94, wg_v270);
    let high_5_ms_bits_tmp_92ff8_85 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_83, 9);
    let high_5_ms_bits_col97 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_85);
    eval.set_col(97, high_5_ms_bits_col97);
    eval.set_sub_input_word(22, low_7_ms_bits_col95);
    eval.set_sub_input_word(23, high_2_ls_bits_tmp_92ff8_84);
    eval.set_sub_input_word(24, high_5_ms_bits_col97);
    eval.set_lookup_word(814, m31_371240602);
    eval.set_lookup_word(815, low_7_ms_bits_col95);
    eval.set_lookup_word(816, high_2_ls_bits_tmp_92ff8_84);
    eval.set_lookup_word(817, high_5_ms_bits_col97);
    let wg_v271 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_7_col42);
    let memory_address_to_id_value_tmp_92ff8_86 = eval.mem_addr_to_id(wg_v271);
    let message_word_7_id_col98 = memory_address_to_id_value_tmp_92ff8_86;
    eval.set_col(98, message_word_7_id_col98);
    let wg_v272 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_7_col42);
    eval.set_sub_input_word(56, wg_v272);
    eval.set_lookup_word(279, m31_1444891767);
    let wg_v273 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_7_col42);
    eval.set_lookup_word(280, wg_v273);
    eval.set_lookup_word(281, message_word_7_id_col98);
    eval.set_sub_input_word(72, message_word_7_id_col98);
    eval.set_lookup_word(516, m31_1662111297);
    eval.set_lookup_word(517, message_word_7_id_col98);
    let wg_v274 = eval.m31_mul(low_7_ms_bits_col95, m31_512);
    let wg_v275 = eval.m31_sub(low_16_bits_col93, wg_v274);
    eval.set_lookup_word(518, wg_v275);
    let wg_v276 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_84, m31_128);
    let wg_v277 = eval.m31_add(low_7_ms_bits_col95, wg_v276);
    eval.set_lookup_word(519, wg_v277);
    let wg_v278 = eval.m31_mul(high_5_ms_bits_col97, m31_512);
    let wg_v279 = eval.m31_sub(high_14_ms_bits_col96, wg_v278);
    eval.set_lookup_word(520, wg_v279);
    eval.set_lookup_word(521, high_5_ms_bits_col97);
    eval.set_lookup_word(522, m31_0);
    eval.set_lookup_word(523, m31_0);
    eval.set_lookup_word(524, m31_0);
    eval.set_lookup_word(525, m31_0);
    eval.set_lookup_word(526, m31_0);
    eval.set_lookup_word(527, m31_0);
    eval.set_lookup_word(528, m31_0);
    eval.set_lookup_word(529, m31_0);
    eval.set_lookup_word(530, m31_0);
    eval.set_lookup_word(531, m31_0);
    eval.set_lookup_word(532, m31_0);
    eval.set_lookup_word(533, m31_0);
    eval.set_lookup_word(534, m31_0);
    eval.set_lookup_word(535, m31_0);
    eval.set_lookup_word(536, m31_0);
    eval.set_lookup_word(537, m31_0);
    eval.set_lookup_word(538, m31_0);
    eval.set_lookup_word(539, m31_0);
    eval.set_lookup_word(540, m31_0);
    eval.set_lookup_word(541, m31_0);
    eval.set_lookup_word(542, m31_0);
    eval.set_lookup_word(543, m31_0);
    eval.set_lookup_word(544, m31_0);
    eval.set_lookup_word(545, m31_0);
    let read_u_32_output_tmp_92ff8_88 = expected_word_tmp_92ff8_81;
    let wg_v280 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_8_col43);
    let memory_address_to_id_value_tmp_92ff8_89 = eval.mem_addr_to_id(wg_v280);
    let memory_id_to_big_value_tmp_92ff8_90 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_89);
    let wg_v281 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_90.clone(), 1);
    let wg_v282 = eval.u16_from_m31(wg_v281);
    let tmp_92ff8_91 = eval.u16_shr(wg_v282, 7);
    let wg_v283 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_90.clone(), 1);
    let wg_v284 = eval.u16_as_m31(tmp_92ff8_91);
    let wg_v285 = eval.m31_mul(wg_v284, m31_128);
    let wg_v286 = eval.m31_sub(wg_v283, wg_v285);
    let wg_v287 = eval.m31_mul(wg_v286, m31_512);
    let wg_v288 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_90.clone(), 0);
    let low_16_bits_col99 = eval.m31_add(wg_v287, wg_v288);
    eval.set_col(99, low_16_bits_col99);
    let wg_v289 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_90.clone(), 3);
    let wg_v290 = eval.m31_mul(wg_v289, m31_2048);
    let wg_v291 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_90.clone(), 2);
    let wg_v292 = eval.m31_mul(wg_v291, m31_4);
    let wg_v293 = eval.m31_add(wg_v290, wg_v292);
    let wg_v294 = eval.u16_as_m31(tmp_92ff8_91);
    let high_16_bits_col100 = eval.m31_add(wg_v293, wg_v294);
    eval.set_col(100, high_16_bits_col100);
    let expected_word_tmp_92ff8_92 = eval.u32_from_limbs(low_16_bits_col99, high_16_bits_col100);
    let wg_v295 = eval.u32_low(expected_word_tmp_92ff8_92);
    let low_7_ms_bits_tmp_92ff8_93 = eval.u16_shr(wg_v295, 9);
    let low_7_ms_bits_col101 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_93);
    eval.set_col(101, low_7_ms_bits_col101);
    let wg_v296 = eval.u32_high(expected_word_tmp_92ff8_92);
    let high_14_ms_bits_tmp_92ff8_94 = eval.u16_shr(wg_v296, 2);
    let high_14_ms_bits_col102 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_94);
    eval.set_col(102, high_14_ms_bits_col102);
    let wg_v297 = eval.m31_mul(high_14_ms_bits_col102, m31_4);
    let high_2_ls_bits_tmp_92ff8_95 = eval.m31_sub(high_16_bits_col100, wg_v297);
    let high_5_ms_bits_tmp_92ff8_96 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_94, 9);
    let high_5_ms_bits_col103 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_96);
    eval.set_col(103, high_5_ms_bits_col103);
    eval.set_sub_input_word(25, low_7_ms_bits_col101);
    eval.set_sub_input_word(26, high_2_ls_bits_tmp_92ff8_95);
    eval.set_sub_input_word(27, high_5_ms_bits_col103);
    eval.set_lookup_word(818, m31_371240602);
    eval.set_lookup_word(819, low_7_ms_bits_col101);
    eval.set_lookup_word(820, high_2_ls_bits_tmp_92ff8_95);
    eval.set_lookup_word(821, high_5_ms_bits_col103);
    let wg_v298 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_8_col43);
    let memory_address_to_id_value_tmp_92ff8_97 = eval.mem_addr_to_id(wg_v298);
    let message_word_8_id_col104 = memory_address_to_id_value_tmp_92ff8_97;
    eval.set_col(104, message_word_8_id_col104);
    let wg_v299 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_8_col43);
    eval.set_sub_input_word(57, wg_v299);
    eval.set_lookup_word(282, m31_1444891767);
    let wg_v300 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_8_col43);
    eval.set_lookup_word(283, wg_v300);
    eval.set_lookup_word(284, message_word_8_id_col104);
    eval.set_sub_input_word(73, message_word_8_id_col104);
    eval.set_lookup_word(546, m31_1662111297);
    eval.set_lookup_word(547, message_word_8_id_col104);
    let wg_v301 = eval.m31_mul(low_7_ms_bits_col101, m31_512);
    let wg_v302 = eval.m31_sub(low_16_bits_col99, wg_v301);
    eval.set_lookup_word(548, wg_v302);
    let wg_v303 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_95, m31_128);
    let wg_v304 = eval.m31_add(low_7_ms_bits_col101, wg_v303);
    eval.set_lookup_word(549, wg_v304);
    let wg_v305 = eval.m31_mul(high_5_ms_bits_col103, m31_512);
    let wg_v306 = eval.m31_sub(high_14_ms_bits_col102, wg_v305);
    eval.set_lookup_word(550, wg_v306);
    eval.set_lookup_word(551, high_5_ms_bits_col103);
    eval.set_lookup_word(552, m31_0);
    eval.set_lookup_word(553, m31_0);
    eval.set_lookup_word(554, m31_0);
    eval.set_lookup_word(555, m31_0);
    eval.set_lookup_word(556, m31_0);
    eval.set_lookup_word(557, m31_0);
    eval.set_lookup_word(558, m31_0);
    eval.set_lookup_word(559, m31_0);
    eval.set_lookup_word(560, m31_0);
    eval.set_lookup_word(561, m31_0);
    eval.set_lookup_word(562, m31_0);
    eval.set_lookup_word(563, m31_0);
    eval.set_lookup_word(564, m31_0);
    eval.set_lookup_word(565, m31_0);
    eval.set_lookup_word(566, m31_0);
    eval.set_lookup_word(567, m31_0);
    eval.set_lookup_word(568, m31_0);
    eval.set_lookup_word(569, m31_0);
    eval.set_lookup_word(570, m31_0);
    eval.set_lookup_word(571, m31_0);
    eval.set_lookup_word(572, m31_0);
    eval.set_lookup_word(573, m31_0);
    eval.set_lookup_word(574, m31_0);
    eval.set_lookup_word(575, m31_0);
    let read_u_32_output_tmp_92ff8_99 = expected_word_tmp_92ff8_92;
    let wg_v307 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_9_col44);
    let memory_address_to_id_value_tmp_92ff8_100 = eval.mem_addr_to_id(wg_v307);
    let memory_id_to_big_value_tmp_92ff8_101 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_100);
    let wg_v308 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_101.clone(), 1);
    let wg_v309 = eval.u16_from_m31(wg_v308);
    let tmp_92ff8_102 = eval.u16_shr(wg_v309, 7);
    let wg_v310 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_101.clone(), 1);
    let wg_v311 = eval.u16_as_m31(tmp_92ff8_102);
    let wg_v312 = eval.m31_mul(wg_v311, m31_128);
    let wg_v313 = eval.m31_sub(wg_v310, wg_v312);
    let wg_v314 = eval.m31_mul(wg_v313, m31_512);
    let wg_v315 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_101.clone(), 0);
    let low_16_bits_col105 = eval.m31_add(wg_v314, wg_v315);
    eval.set_col(105, low_16_bits_col105);
    let wg_v316 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_101.clone(), 3);
    let wg_v317 = eval.m31_mul(wg_v316, m31_2048);
    let wg_v318 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_101.clone(), 2);
    let wg_v319 = eval.m31_mul(wg_v318, m31_4);
    let wg_v320 = eval.m31_add(wg_v317, wg_v319);
    let wg_v321 = eval.u16_as_m31(tmp_92ff8_102);
    let high_16_bits_col106 = eval.m31_add(wg_v320, wg_v321);
    eval.set_col(106, high_16_bits_col106);
    let expected_word_tmp_92ff8_103 = eval.u32_from_limbs(low_16_bits_col105, high_16_bits_col106);
    let wg_v322 = eval.u32_low(expected_word_tmp_92ff8_103);
    let low_7_ms_bits_tmp_92ff8_104 = eval.u16_shr(wg_v322, 9);
    let low_7_ms_bits_col107 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_104);
    eval.set_col(107, low_7_ms_bits_col107);
    let wg_v323 = eval.u32_high(expected_word_tmp_92ff8_103);
    let high_14_ms_bits_tmp_92ff8_105 = eval.u16_shr(wg_v323, 2);
    let high_14_ms_bits_col108 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_105);
    eval.set_col(108, high_14_ms_bits_col108);
    let wg_v324 = eval.m31_mul(high_14_ms_bits_col108, m31_4);
    let high_2_ls_bits_tmp_92ff8_106 = eval.m31_sub(high_16_bits_col106, wg_v324);
    let high_5_ms_bits_tmp_92ff8_107 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_105, 9);
    let high_5_ms_bits_col109 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_107);
    eval.set_col(109, high_5_ms_bits_col109);
    eval.set_sub_input_word(28, low_7_ms_bits_col107);
    eval.set_sub_input_word(29, high_2_ls_bits_tmp_92ff8_106);
    eval.set_sub_input_word(30, high_5_ms_bits_col109);
    eval.set_lookup_word(822, m31_371240602);
    eval.set_lookup_word(823, low_7_ms_bits_col107);
    eval.set_lookup_word(824, high_2_ls_bits_tmp_92ff8_106);
    eval.set_lookup_word(825, high_5_ms_bits_col109);
    let wg_v325 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_9_col44);
    let memory_address_to_id_value_tmp_92ff8_108 = eval.mem_addr_to_id(wg_v325);
    let message_word_9_id_col110 = memory_address_to_id_value_tmp_92ff8_108;
    eval.set_col(110, message_word_9_id_col110);
    let wg_v326 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_9_col44);
    eval.set_sub_input_word(58, wg_v326);
    eval.set_lookup_word(285, m31_1444891767);
    let wg_v327 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_9_col44);
    eval.set_lookup_word(286, wg_v327);
    eval.set_lookup_word(287, message_word_9_id_col110);
    eval.set_sub_input_word(74, message_word_9_id_col110);
    eval.set_lookup_word(576, m31_1662111297);
    eval.set_lookup_word(577, message_word_9_id_col110);
    let wg_v328 = eval.m31_mul(low_7_ms_bits_col107, m31_512);
    let wg_v329 = eval.m31_sub(low_16_bits_col105, wg_v328);
    eval.set_lookup_word(578, wg_v329);
    let wg_v330 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_106, m31_128);
    let wg_v331 = eval.m31_add(low_7_ms_bits_col107, wg_v330);
    eval.set_lookup_word(579, wg_v331);
    let wg_v332 = eval.m31_mul(high_5_ms_bits_col109, m31_512);
    let wg_v333 = eval.m31_sub(high_14_ms_bits_col108, wg_v332);
    eval.set_lookup_word(580, wg_v333);
    eval.set_lookup_word(581, high_5_ms_bits_col109);
    eval.set_lookup_word(582, m31_0);
    eval.set_lookup_word(583, m31_0);
    eval.set_lookup_word(584, m31_0);
    eval.set_lookup_word(585, m31_0);
    eval.set_lookup_word(586, m31_0);
    eval.set_lookup_word(587, m31_0);
    eval.set_lookup_word(588, m31_0);
    eval.set_lookup_word(589, m31_0);
    eval.set_lookup_word(590, m31_0);
    eval.set_lookup_word(591, m31_0);
    eval.set_lookup_word(592, m31_0);
    eval.set_lookup_word(593, m31_0);
    eval.set_lookup_word(594, m31_0);
    eval.set_lookup_word(595, m31_0);
    eval.set_lookup_word(596, m31_0);
    eval.set_lookup_word(597, m31_0);
    eval.set_lookup_word(598, m31_0);
    eval.set_lookup_word(599, m31_0);
    eval.set_lookup_word(600, m31_0);
    eval.set_lookup_word(601, m31_0);
    eval.set_lookup_word(602, m31_0);
    eval.set_lookup_word(603, m31_0);
    eval.set_lookup_word(604, m31_0);
    eval.set_lookup_word(605, m31_0);
    let read_u_32_output_tmp_92ff8_110 = expected_word_tmp_92ff8_103;
    let wg_v334 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_10_col45);
    let memory_address_to_id_value_tmp_92ff8_111 = eval.mem_addr_to_id(wg_v334);
    let memory_id_to_big_value_tmp_92ff8_112 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_111);
    let wg_v335 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_112.clone(), 1);
    let wg_v336 = eval.u16_from_m31(wg_v335);
    let tmp_92ff8_113 = eval.u16_shr(wg_v336, 7);
    let wg_v337 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_112.clone(), 1);
    let wg_v338 = eval.u16_as_m31(tmp_92ff8_113);
    let wg_v339 = eval.m31_mul(wg_v338, m31_128);
    let wg_v340 = eval.m31_sub(wg_v337, wg_v339);
    let wg_v341 = eval.m31_mul(wg_v340, m31_512);
    let wg_v342 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_112.clone(), 0);
    let low_16_bits_col111 = eval.m31_add(wg_v341, wg_v342);
    eval.set_col(111, low_16_bits_col111);
    let wg_v343 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_112.clone(), 3);
    let wg_v344 = eval.m31_mul(wg_v343, m31_2048);
    let wg_v345 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_112.clone(), 2);
    let wg_v346 = eval.m31_mul(wg_v345, m31_4);
    let wg_v347 = eval.m31_add(wg_v344, wg_v346);
    let wg_v348 = eval.u16_as_m31(tmp_92ff8_113);
    let high_16_bits_col112 = eval.m31_add(wg_v347, wg_v348);
    eval.set_col(112, high_16_bits_col112);
    let expected_word_tmp_92ff8_114 = eval.u32_from_limbs(low_16_bits_col111, high_16_bits_col112);
    let wg_v349 = eval.u32_low(expected_word_tmp_92ff8_114);
    let low_7_ms_bits_tmp_92ff8_115 = eval.u16_shr(wg_v349, 9);
    let low_7_ms_bits_col113 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_115);
    eval.set_col(113, low_7_ms_bits_col113);
    let wg_v350 = eval.u32_high(expected_word_tmp_92ff8_114);
    let high_14_ms_bits_tmp_92ff8_116 = eval.u16_shr(wg_v350, 2);
    let high_14_ms_bits_col114 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_116);
    eval.set_col(114, high_14_ms_bits_col114);
    let wg_v351 = eval.m31_mul(high_14_ms_bits_col114, m31_4);
    let high_2_ls_bits_tmp_92ff8_117 = eval.m31_sub(high_16_bits_col112, wg_v351);
    let high_5_ms_bits_tmp_92ff8_118 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_116, 9);
    let high_5_ms_bits_col115 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_118);
    eval.set_col(115, high_5_ms_bits_col115);
    eval.set_sub_input_word(31, low_7_ms_bits_col113);
    eval.set_sub_input_word(32, high_2_ls_bits_tmp_92ff8_117);
    eval.set_sub_input_word(33, high_5_ms_bits_col115);
    eval.set_lookup_word(826, m31_371240602);
    eval.set_lookup_word(827, low_7_ms_bits_col113);
    eval.set_lookup_word(828, high_2_ls_bits_tmp_92ff8_117);
    eval.set_lookup_word(829, high_5_ms_bits_col115);
    let wg_v352 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_10_col45);
    let memory_address_to_id_value_tmp_92ff8_119 = eval.mem_addr_to_id(wg_v352);
    let message_word_10_id_col116 = memory_address_to_id_value_tmp_92ff8_119;
    eval.set_col(116, message_word_10_id_col116);
    let wg_v353 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_10_col45);
    eval.set_sub_input_word(59, wg_v353);
    eval.set_lookup_word(288, m31_1444891767);
    let wg_v354 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_10_col45);
    eval.set_lookup_word(289, wg_v354);
    eval.set_lookup_word(290, message_word_10_id_col116);
    eval.set_sub_input_word(75, message_word_10_id_col116);
    eval.set_lookup_word(606, m31_1662111297);
    eval.set_lookup_word(607, message_word_10_id_col116);
    let wg_v355 = eval.m31_mul(low_7_ms_bits_col113, m31_512);
    let wg_v356 = eval.m31_sub(low_16_bits_col111, wg_v355);
    eval.set_lookup_word(608, wg_v356);
    let wg_v357 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_117, m31_128);
    let wg_v358 = eval.m31_add(low_7_ms_bits_col113, wg_v357);
    eval.set_lookup_word(609, wg_v358);
    let wg_v359 = eval.m31_mul(high_5_ms_bits_col115, m31_512);
    let wg_v360 = eval.m31_sub(high_14_ms_bits_col114, wg_v359);
    eval.set_lookup_word(610, wg_v360);
    eval.set_lookup_word(611, high_5_ms_bits_col115);
    eval.set_lookup_word(612, m31_0);
    eval.set_lookup_word(613, m31_0);
    eval.set_lookup_word(614, m31_0);
    eval.set_lookup_word(615, m31_0);
    eval.set_lookup_word(616, m31_0);
    eval.set_lookup_word(617, m31_0);
    eval.set_lookup_word(618, m31_0);
    eval.set_lookup_word(619, m31_0);
    eval.set_lookup_word(620, m31_0);
    eval.set_lookup_word(621, m31_0);
    eval.set_lookup_word(622, m31_0);
    eval.set_lookup_word(623, m31_0);
    eval.set_lookup_word(624, m31_0);
    eval.set_lookup_word(625, m31_0);
    eval.set_lookup_word(626, m31_0);
    eval.set_lookup_word(627, m31_0);
    eval.set_lookup_word(628, m31_0);
    eval.set_lookup_word(629, m31_0);
    eval.set_lookup_word(630, m31_0);
    eval.set_lookup_word(631, m31_0);
    eval.set_lookup_word(632, m31_0);
    eval.set_lookup_word(633, m31_0);
    eval.set_lookup_word(634, m31_0);
    eval.set_lookup_word(635, m31_0);
    let read_u_32_output_tmp_92ff8_121 = expected_word_tmp_92ff8_114;
    let wg_v361 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_11_col46);
    let memory_address_to_id_value_tmp_92ff8_122 = eval.mem_addr_to_id(wg_v361);
    let memory_id_to_big_value_tmp_92ff8_123 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_122);
    let wg_v362 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_123.clone(), 1);
    let wg_v363 = eval.u16_from_m31(wg_v362);
    let tmp_92ff8_124 = eval.u16_shr(wg_v363, 7);
    let wg_v364 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_123.clone(), 1);
    let wg_v365 = eval.u16_as_m31(tmp_92ff8_124);
    let wg_v366 = eval.m31_mul(wg_v365, m31_128);
    let wg_v367 = eval.m31_sub(wg_v364, wg_v366);
    let wg_v368 = eval.m31_mul(wg_v367, m31_512);
    let wg_v369 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_123.clone(), 0);
    let low_16_bits_col117 = eval.m31_add(wg_v368, wg_v369);
    eval.set_col(117, low_16_bits_col117);
    let wg_v370 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_123.clone(), 3);
    let wg_v371 = eval.m31_mul(wg_v370, m31_2048);
    let wg_v372 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_123.clone(), 2);
    let wg_v373 = eval.m31_mul(wg_v372, m31_4);
    let wg_v374 = eval.m31_add(wg_v371, wg_v373);
    let wg_v375 = eval.u16_as_m31(tmp_92ff8_124);
    let high_16_bits_col118 = eval.m31_add(wg_v374, wg_v375);
    eval.set_col(118, high_16_bits_col118);
    let expected_word_tmp_92ff8_125 = eval.u32_from_limbs(low_16_bits_col117, high_16_bits_col118);
    let wg_v376 = eval.u32_low(expected_word_tmp_92ff8_125);
    let low_7_ms_bits_tmp_92ff8_126 = eval.u16_shr(wg_v376, 9);
    let low_7_ms_bits_col119 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_126);
    eval.set_col(119, low_7_ms_bits_col119);
    let wg_v377 = eval.u32_high(expected_word_tmp_92ff8_125);
    let high_14_ms_bits_tmp_92ff8_127 = eval.u16_shr(wg_v377, 2);
    let high_14_ms_bits_col120 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_127);
    eval.set_col(120, high_14_ms_bits_col120);
    let wg_v378 = eval.m31_mul(high_14_ms_bits_col120, m31_4);
    let high_2_ls_bits_tmp_92ff8_128 = eval.m31_sub(high_16_bits_col118, wg_v378);
    let high_5_ms_bits_tmp_92ff8_129 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_127, 9);
    let high_5_ms_bits_col121 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_129);
    eval.set_col(121, high_5_ms_bits_col121);
    eval.set_sub_input_word(34, low_7_ms_bits_col119);
    eval.set_sub_input_word(35, high_2_ls_bits_tmp_92ff8_128);
    eval.set_sub_input_word(36, high_5_ms_bits_col121);
    eval.set_lookup_word(830, m31_371240602);
    eval.set_lookup_word(831, low_7_ms_bits_col119);
    eval.set_lookup_word(832, high_2_ls_bits_tmp_92ff8_128);
    eval.set_lookup_word(833, high_5_ms_bits_col121);
    let wg_v379 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_11_col46);
    let memory_address_to_id_value_tmp_92ff8_130 = eval.mem_addr_to_id(wg_v379);
    let message_word_11_id_col122 = memory_address_to_id_value_tmp_92ff8_130;
    eval.set_col(122, message_word_11_id_col122);
    let wg_v380 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_11_col46);
    eval.set_sub_input_word(60, wg_v380);
    eval.set_lookup_word(291, m31_1444891767);
    let wg_v381 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_11_col46);
    eval.set_lookup_word(292, wg_v381);
    eval.set_lookup_word(293, message_word_11_id_col122);
    eval.set_sub_input_word(76, message_word_11_id_col122);
    eval.set_lookup_word(636, m31_1662111297);
    eval.set_lookup_word(637, message_word_11_id_col122);
    let wg_v382 = eval.m31_mul(low_7_ms_bits_col119, m31_512);
    let wg_v383 = eval.m31_sub(low_16_bits_col117, wg_v382);
    eval.set_lookup_word(638, wg_v383);
    let wg_v384 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_128, m31_128);
    let wg_v385 = eval.m31_add(low_7_ms_bits_col119, wg_v384);
    eval.set_lookup_word(639, wg_v385);
    let wg_v386 = eval.m31_mul(high_5_ms_bits_col121, m31_512);
    let wg_v387 = eval.m31_sub(high_14_ms_bits_col120, wg_v386);
    eval.set_lookup_word(640, wg_v387);
    eval.set_lookup_word(641, high_5_ms_bits_col121);
    eval.set_lookup_word(642, m31_0);
    eval.set_lookup_word(643, m31_0);
    eval.set_lookup_word(644, m31_0);
    eval.set_lookup_word(645, m31_0);
    eval.set_lookup_word(646, m31_0);
    eval.set_lookup_word(647, m31_0);
    eval.set_lookup_word(648, m31_0);
    eval.set_lookup_word(649, m31_0);
    eval.set_lookup_word(650, m31_0);
    eval.set_lookup_word(651, m31_0);
    eval.set_lookup_word(652, m31_0);
    eval.set_lookup_word(653, m31_0);
    eval.set_lookup_word(654, m31_0);
    eval.set_lookup_word(655, m31_0);
    eval.set_lookup_word(656, m31_0);
    eval.set_lookup_word(657, m31_0);
    eval.set_lookup_word(658, m31_0);
    eval.set_lookup_word(659, m31_0);
    eval.set_lookup_word(660, m31_0);
    eval.set_lookup_word(661, m31_0);
    eval.set_lookup_word(662, m31_0);
    eval.set_lookup_word(663, m31_0);
    eval.set_lookup_word(664, m31_0);
    eval.set_lookup_word(665, m31_0);
    let read_u_32_output_tmp_92ff8_132 = expected_word_tmp_92ff8_125;
    let wg_v388 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_12_col47);
    let memory_address_to_id_value_tmp_92ff8_133 = eval.mem_addr_to_id(wg_v388);
    let memory_id_to_big_value_tmp_92ff8_134 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_133);
    let wg_v389 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_134.clone(), 1);
    let wg_v390 = eval.u16_from_m31(wg_v389);
    let tmp_92ff8_135 = eval.u16_shr(wg_v390, 7);
    let wg_v391 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_134.clone(), 1);
    let wg_v392 = eval.u16_as_m31(tmp_92ff8_135);
    let wg_v393 = eval.m31_mul(wg_v392, m31_128);
    let wg_v394 = eval.m31_sub(wg_v391, wg_v393);
    let wg_v395 = eval.m31_mul(wg_v394, m31_512);
    let wg_v396 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_134.clone(), 0);
    let low_16_bits_col123 = eval.m31_add(wg_v395, wg_v396);
    eval.set_col(123, low_16_bits_col123);
    let wg_v397 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_134.clone(), 3);
    let wg_v398 = eval.m31_mul(wg_v397, m31_2048);
    let wg_v399 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_134.clone(), 2);
    let wg_v400 = eval.m31_mul(wg_v399, m31_4);
    let wg_v401 = eval.m31_add(wg_v398, wg_v400);
    let wg_v402 = eval.u16_as_m31(tmp_92ff8_135);
    let high_16_bits_col124 = eval.m31_add(wg_v401, wg_v402);
    eval.set_col(124, high_16_bits_col124);
    let expected_word_tmp_92ff8_136 = eval.u32_from_limbs(low_16_bits_col123, high_16_bits_col124);
    let wg_v403 = eval.u32_low(expected_word_tmp_92ff8_136);
    let low_7_ms_bits_tmp_92ff8_137 = eval.u16_shr(wg_v403, 9);
    let low_7_ms_bits_col125 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_137);
    eval.set_col(125, low_7_ms_bits_col125);
    let wg_v404 = eval.u32_high(expected_word_tmp_92ff8_136);
    let high_14_ms_bits_tmp_92ff8_138 = eval.u16_shr(wg_v404, 2);
    let high_14_ms_bits_col126 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_138);
    eval.set_col(126, high_14_ms_bits_col126);
    let wg_v405 = eval.m31_mul(high_14_ms_bits_col126, m31_4);
    let high_2_ls_bits_tmp_92ff8_139 = eval.m31_sub(high_16_bits_col124, wg_v405);
    let high_5_ms_bits_tmp_92ff8_140 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_138, 9);
    let high_5_ms_bits_col127 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_140);
    eval.set_col(127, high_5_ms_bits_col127);
    eval.set_sub_input_word(37, low_7_ms_bits_col125);
    eval.set_sub_input_word(38, high_2_ls_bits_tmp_92ff8_139);
    eval.set_sub_input_word(39, high_5_ms_bits_col127);
    eval.set_lookup_word(834, m31_371240602);
    eval.set_lookup_word(835, low_7_ms_bits_col125);
    eval.set_lookup_word(836, high_2_ls_bits_tmp_92ff8_139);
    eval.set_lookup_word(837, high_5_ms_bits_col127);
    let wg_v406 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_12_col47);
    let memory_address_to_id_value_tmp_92ff8_141 = eval.mem_addr_to_id(wg_v406);
    let message_word_12_id_col128 = memory_address_to_id_value_tmp_92ff8_141;
    eval.set_col(128, message_word_12_id_col128);
    let wg_v407 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_12_col47);
    eval.set_sub_input_word(61, wg_v407);
    eval.set_lookup_word(294, m31_1444891767);
    let wg_v408 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_12_col47);
    eval.set_lookup_word(295, wg_v408);
    eval.set_lookup_word(296, message_word_12_id_col128);
    eval.set_sub_input_word(77, message_word_12_id_col128);
    eval.set_lookup_word(666, m31_1662111297);
    eval.set_lookup_word(667, message_word_12_id_col128);
    let wg_v409 = eval.m31_mul(low_7_ms_bits_col125, m31_512);
    let wg_v410 = eval.m31_sub(low_16_bits_col123, wg_v409);
    eval.set_lookup_word(668, wg_v410);
    let wg_v411 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_139, m31_128);
    let wg_v412 = eval.m31_add(low_7_ms_bits_col125, wg_v411);
    eval.set_lookup_word(669, wg_v412);
    let wg_v413 = eval.m31_mul(high_5_ms_bits_col127, m31_512);
    let wg_v414 = eval.m31_sub(high_14_ms_bits_col126, wg_v413);
    eval.set_lookup_word(670, wg_v414);
    eval.set_lookup_word(671, high_5_ms_bits_col127);
    eval.set_lookup_word(672, m31_0);
    eval.set_lookup_word(673, m31_0);
    eval.set_lookup_word(674, m31_0);
    eval.set_lookup_word(675, m31_0);
    eval.set_lookup_word(676, m31_0);
    eval.set_lookup_word(677, m31_0);
    eval.set_lookup_word(678, m31_0);
    eval.set_lookup_word(679, m31_0);
    eval.set_lookup_word(680, m31_0);
    eval.set_lookup_word(681, m31_0);
    eval.set_lookup_word(682, m31_0);
    eval.set_lookup_word(683, m31_0);
    eval.set_lookup_word(684, m31_0);
    eval.set_lookup_word(685, m31_0);
    eval.set_lookup_word(686, m31_0);
    eval.set_lookup_word(687, m31_0);
    eval.set_lookup_word(688, m31_0);
    eval.set_lookup_word(689, m31_0);
    eval.set_lookup_word(690, m31_0);
    eval.set_lookup_word(691, m31_0);
    eval.set_lookup_word(692, m31_0);
    eval.set_lookup_word(693, m31_0);
    eval.set_lookup_word(694, m31_0);
    eval.set_lookup_word(695, m31_0);
    let read_u_32_output_tmp_92ff8_143 = expected_word_tmp_92ff8_136;
    let wg_v415 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_13_col48);
    let memory_address_to_id_value_tmp_92ff8_144 = eval.mem_addr_to_id(wg_v415);
    let memory_id_to_big_value_tmp_92ff8_145 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_144);
    let wg_v416 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_145.clone(), 1);
    let wg_v417 = eval.u16_from_m31(wg_v416);
    let tmp_92ff8_146 = eval.u16_shr(wg_v417, 7);
    let wg_v418 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_145.clone(), 1);
    let wg_v419 = eval.u16_as_m31(tmp_92ff8_146);
    let wg_v420 = eval.m31_mul(wg_v419, m31_128);
    let wg_v421 = eval.m31_sub(wg_v418, wg_v420);
    let wg_v422 = eval.m31_mul(wg_v421, m31_512);
    let wg_v423 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_145.clone(), 0);
    let low_16_bits_col129 = eval.m31_add(wg_v422, wg_v423);
    eval.set_col(129, low_16_bits_col129);
    let wg_v424 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_145.clone(), 3);
    let wg_v425 = eval.m31_mul(wg_v424, m31_2048);
    let wg_v426 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_145.clone(), 2);
    let wg_v427 = eval.m31_mul(wg_v426, m31_4);
    let wg_v428 = eval.m31_add(wg_v425, wg_v427);
    let wg_v429 = eval.u16_as_m31(tmp_92ff8_146);
    let high_16_bits_col130 = eval.m31_add(wg_v428, wg_v429);
    eval.set_col(130, high_16_bits_col130);
    let expected_word_tmp_92ff8_147 = eval.u32_from_limbs(low_16_bits_col129, high_16_bits_col130);
    let wg_v430 = eval.u32_low(expected_word_tmp_92ff8_147);
    let low_7_ms_bits_tmp_92ff8_148 = eval.u16_shr(wg_v430, 9);
    let low_7_ms_bits_col131 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_148);
    eval.set_col(131, low_7_ms_bits_col131);
    let wg_v431 = eval.u32_high(expected_word_tmp_92ff8_147);
    let high_14_ms_bits_tmp_92ff8_149 = eval.u16_shr(wg_v431, 2);
    let high_14_ms_bits_col132 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_149);
    eval.set_col(132, high_14_ms_bits_col132);
    let wg_v432 = eval.m31_mul(high_14_ms_bits_col132, m31_4);
    let high_2_ls_bits_tmp_92ff8_150 = eval.m31_sub(high_16_bits_col130, wg_v432);
    let high_5_ms_bits_tmp_92ff8_151 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_149, 9);
    let high_5_ms_bits_col133 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_151);
    eval.set_col(133, high_5_ms_bits_col133);
    eval.set_sub_input_word(40, low_7_ms_bits_col131);
    eval.set_sub_input_word(41, high_2_ls_bits_tmp_92ff8_150);
    eval.set_sub_input_word(42, high_5_ms_bits_col133);
    eval.set_lookup_word(838, m31_371240602);
    eval.set_lookup_word(839, low_7_ms_bits_col131);
    eval.set_lookup_word(840, high_2_ls_bits_tmp_92ff8_150);
    eval.set_lookup_word(841, high_5_ms_bits_col133);
    let wg_v433 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_13_col48);
    let memory_address_to_id_value_tmp_92ff8_152 = eval.mem_addr_to_id(wg_v433);
    let message_word_13_id_col134 = memory_address_to_id_value_tmp_92ff8_152;
    eval.set_col(134, message_word_13_id_col134);
    let wg_v434 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_13_col48);
    eval.set_sub_input_word(62, wg_v434);
    eval.set_lookup_word(297, m31_1444891767);
    let wg_v435 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_13_col48);
    eval.set_lookup_word(298, wg_v435);
    eval.set_lookup_word(299, message_word_13_id_col134);
    eval.set_sub_input_word(78, message_word_13_id_col134);
    eval.set_lookup_word(696, m31_1662111297);
    eval.set_lookup_word(697, message_word_13_id_col134);
    let wg_v436 = eval.m31_mul(low_7_ms_bits_col131, m31_512);
    let wg_v437 = eval.m31_sub(low_16_bits_col129, wg_v436);
    eval.set_lookup_word(698, wg_v437);
    let wg_v438 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_150, m31_128);
    let wg_v439 = eval.m31_add(low_7_ms_bits_col131, wg_v438);
    eval.set_lookup_word(699, wg_v439);
    let wg_v440 = eval.m31_mul(high_5_ms_bits_col133, m31_512);
    let wg_v441 = eval.m31_sub(high_14_ms_bits_col132, wg_v440);
    eval.set_lookup_word(700, wg_v441);
    eval.set_lookup_word(701, high_5_ms_bits_col133);
    eval.set_lookup_word(702, m31_0);
    eval.set_lookup_word(703, m31_0);
    eval.set_lookup_word(704, m31_0);
    eval.set_lookup_word(705, m31_0);
    eval.set_lookup_word(706, m31_0);
    eval.set_lookup_word(707, m31_0);
    eval.set_lookup_word(708, m31_0);
    eval.set_lookup_word(709, m31_0);
    eval.set_lookup_word(710, m31_0);
    eval.set_lookup_word(711, m31_0);
    eval.set_lookup_word(712, m31_0);
    eval.set_lookup_word(713, m31_0);
    eval.set_lookup_word(714, m31_0);
    eval.set_lookup_word(715, m31_0);
    eval.set_lookup_word(716, m31_0);
    eval.set_lookup_word(717, m31_0);
    eval.set_lookup_word(718, m31_0);
    eval.set_lookup_word(719, m31_0);
    eval.set_lookup_word(720, m31_0);
    eval.set_lookup_word(721, m31_0);
    eval.set_lookup_word(722, m31_0);
    eval.set_lookup_word(723, m31_0);
    eval.set_lookup_word(724, m31_0);
    eval.set_lookup_word(725, m31_0);
    let read_u_32_output_tmp_92ff8_154 = expected_word_tmp_92ff8_147;
    let wg_v442 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_14_col49);
    let memory_address_to_id_value_tmp_92ff8_155 = eval.mem_addr_to_id(wg_v442);
    let memory_id_to_big_value_tmp_92ff8_156 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_155);
    let wg_v443 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_156.clone(), 1);
    let wg_v444 = eval.u16_from_m31(wg_v443);
    let tmp_92ff8_157 = eval.u16_shr(wg_v444, 7);
    let wg_v445 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_156.clone(), 1);
    let wg_v446 = eval.u16_as_m31(tmp_92ff8_157);
    let wg_v447 = eval.m31_mul(wg_v446, m31_128);
    let wg_v448 = eval.m31_sub(wg_v445, wg_v447);
    let wg_v449 = eval.m31_mul(wg_v448, m31_512);
    let wg_v450 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_156.clone(), 0);
    let low_16_bits_col135 = eval.m31_add(wg_v449, wg_v450);
    eval.set_col(135, low_16_bits_col135);
    let wg_v451 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_156.clone(), 3);
    let wg_v452 = eval.m31_mul(wg_v451, m31_2048);
    let wg_v453 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_156.clone(), 2);
    let wg_v454 = eval.m31_mul(wg_v453, m31_4);
    let wg_v455 = eval.m31_add(wg_v452, wg_v454);
    let wg_v456 = eval.u16_as_m31(tmp_92ff8_157);
    let high_16_bits_col136 = eval.m31_add(wg_v455, wg_v456);
    eval.set_col(136, high_16_bits_col136);
    let expected_word_tmp_92ff8_158 = eval.u32_from_limbs(low_16_bits_col135, high_16_bits_col136);
    let wg_v457 = eval.u32_low(expected_word_tmp_92ff8_158);
    let low_7_ms_bits_tmp_92ff8_159 = eval.u16_shr(wg_v457, 9);
    let low_7_ms_bits_col137 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_159);
    eval.set_col(137, low_7_ms_bits_col137);
    let wg_v458 = eval.u32_high(expected_word_tmp_92ff8_158);
    let high_14_ms_bits_tmp_92ff8_160 = eval.u16_shr(wg_v458, 2);
    let high_14_ms_bits_col138 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_160);
    eval.set_col(138, high_14_ms_bits_col138);
    let wg_v459 = eval.m31_mul(high_14_ms_bits_col138, m31_4);
    let high_2_ls_bits_tmp_92ff8_161 = eval.m31_sub(high_16_bits_col136, wg_v459);
    let high_5_ms_bits_tmp_92ff8_162 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_160, 9);
    let high_5_ms_bits_col139 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_162);
    eval.set_col(139, high_5_ms_bits_col139);
    eval.set_sub_input_word(43, low_7_ms_bits_col137);
    eval.set_sub_input_word(44, high_2_ls_bits_tmp_92ff8_161);
    eval.set_sub_input_word(45, high_5_ms_bits_col139);
    eval.set_lookup_word(842, m31_371240602);
    eval.set_lookup_word(843, low_7_ms_bits_col137);
    eval.set_lookup_word(844, high_2_ls_bits_tmp_92ff8_161);
    eval.set_lookup_word(845, high_5_ms_bits_col139);
    let wg_v460 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_14_col49);
    let memory_address_to_id_value_tmp_92ff8_163 = eval.mem_addr_to_id(wg_v460);
    let message_word_14_id_col140 = memory_address_to_id_value_tmp_92ff8_163;
    eval.set_col(140, message_word_14_id_col140);
    let wg_v461 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_14_col49);
    eval.set_sub_input_word(63, wg_v461);
    eval.set_lookup_word(300, m31_1444891767);
    let wg_v462 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_14_col49);
    eval.set_lookup_word(301, wg_v462);
    eval.set_lookup_word(302, message_word_14_id_col140);
    eval.set_sub_input_word(79, message_word_14_id_col140);
    eval.set_lookup_word(726, m31_1662111297);
    eval.set_lookup_word(727, message_word_14_id_col140);
    let wg_v463 = eval.m31_mul(low_7_ms_bits_col137, m31_512);
    let wg_v464 = eval.m31_sub(low_16_bits_col135, wg_v463);
    eval.set_lookup_word(728, wg_v464);
    let wg_v465 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_161, m31_128);
    let wg_v466 = eval.m31_add(low_7_ms_bits_col137, wg_v465);
    eval.set_lookup_word(729, wg_v466);
    let wg_v467 = eval.m31_mul(high_5_ms_bits_col139, m31_512);
    let wg_v468 = eval.m31_sub(high_14_ms_bits_col138, wg_v467);
    eval.set_lookup_word(730, wg_v468);
    eval.set_lookup_word(731, high_5_ms_bits_col139);
    eval.set_lookup_word(732, m31_0);
    eval.set_lookup_word(733, m31_0);
    eval.set_lookup_word(734, m31_0);
    eval.set_lookup_word(735, m31_0);
    eval.set_lookup_word(736, m31_0);
    eval.set_lookup_word(737, m31_0);
    eval.set_lookup_word(738, m31_0);
    eval.set_lookup_word(739, m31_0);
    eval.set_lookup_word(740, m31_0);
    eval.set_lookup_word(741, m31_0);
    eval.set_lookup_word(742, m31_0);
    eval.set_lookup_word(743, m31_0);
    eval.set_lookup_word(744, m31_0);
    eval.set_lookup_word(745, m31_0);
    eval.set_lookup_word(746, m31_0);
    eval.set_lookup_word(747, m31_0);
    eval.set_lookup_word(748, m31_0);
    eval.set_lookup_word(749, m31_0);
    eval.set_lookup_word(750, m31_0);
    eval.set_lookup_word(751, m31_0);
    eval.set_lookup_word(752, m31_0);
    eval.set_lookup_word(753, m31_0);
    eval.set_lookup_word(754, m31_0);
    eval.set_lookup_word(755, m31_0);
    let read_u_32_output_tmp_92ff8_165 = expected_word_tmp_92ff8_158;
    let wg_v469 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_15_col50);
    let memory_address_to_id_value_tmp_92ff8_166 = eval.mem_addr_to_id(wg_v469);
    let memory_id_to_big_value_tmp_92ff8_167 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_92ff8_166);
    let wg_v470 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_167.clone(), 1);
    let wg_v471 = eval.u16_from_m31(wg_v470);
    let tmp_92ff8_168 = eval.u16_shr(wg_v471, 7);
    let wg_v472 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_167.clone(), 1);
    let wg_v473 = eval.u16_as_m31(tmp_92ff8_168);
    let wg_v474 = eval.m31_mul(wg_v473, m31_128);
    let wg_v475 = eval.m31_sub(wg_v472, wg_v474);
    let wg_v476 = eval.m31_mul(wg_v475, m31_512);
    let wg_v477 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_167.clone(), 0);
    let low_16_bits_col141 = eval.m31_add(wg_v476, wg_v477);
    eval.set_col(141, low_16_bits_col141);
    let wg_v478 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_167.clone(), 3);
    let wg_v479 = eval.m31_mul(wg_v478, m31_2048);
    let wg_v480 = eval.felt_get_m31(&memory_id_to_big_value_tmp_92ff8_167.clone(), 2);
    let wg_v481 = eval.m31_mul(wg_v480, m31_4);
    let wg_v482 = eval.m31_add(wg_v479, wg_v481);
    let wg_v483 = eval.u16_as_m31(tmp_92ff8_168);
    let high_16_bits_col142 = eval.m31_add(wg_v482, wg_v483);
    eval.set_col(142, high_16_bits_col142);
    let expected_word_tmp_92ff8_169 = eval.u32_from_limbs(low_16_bits_col141, high_16_bits_col142);
    let wg_v484 = eval.u32_low(expected_word_tmp_92ff8_169);
    let low_7_ms_bits_tmp_92ff8_170 = eval.u16_shr(wg_v484, 9);
    let low_7_ms_bits_col143 = eval.u16_as_m31(low_7_ms_bits_tmp_92ff8_170);
    eval.set_col(143, low_7_ms_bits_col143);
    let wg_v485 = eval.u32_high(expected_word_tmp_92ff8_169);
    let high_14_ms_bits_tmp_92ff8_171 = eval.u16_shr(wg_v485, 2);
    let high_14_ms_bits_col144 = eval.u16_as_m31(high_14_ms_bits_tmp_92ff8_171);
    eval.set_col(144, high_14_ms_bits_col144);
    let wg_v486 = eval.m31_mul(high_14_ms_bits_col144, m31_4);
    let high_2_ls_bits_tmp_92ff8_172 = eval.m31_sub(high_16_bits_col142, wg_v486);
    let high_5_ms_bits_tmp_92ff8_173 = eval.u16_shr(high_14_ms_bits_tmp_92ff8_171, 9);
    let high_5_ms_bits_col145 = eval.u16_as_m31(high_5_ms_bits_tmp_92ff8_173);
    eval.set_col(145, high_5_ms_bits_col145);
    eval.set_sub_input_word(46, low_7_ms_bits_col143);
    eval.set_sub_input_word(47, high_2_ls_bits_tmp_92ff8_172);
    eval.set_sub_input_word(48, high_5_ms_bits_col145);
    eval.set_lookup_word(846, m31_371240602);
    eval.set_lookup_word(847, low_7_ms_bits_col143);
    eval.set_lookup_word(848, high_2_ls_bits_tmp_92ff8_172);
    eval.set_lookup_word(849, high_5_ms_bits_col145);
    let wg_v487 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_15_col50);
    let memory_address_to_id_value_tmp_92ff8_174 = eval.mem_addr_to_id(wg_v487);
    let message_word_15_id_col146 = memory_address_to_id_value_tmp_92ff8_174;
    eval.set_col(146, message_word_15_id_col146);
    let wg_v488 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_15_col50);
    eval.set_sub_input_word(64, wg_v488);
    eval.set_lookup_word(303, m31_1444891767);
    let wg_v489 = eval.m31_add(input_limb_34_col34, blake_round_sigma_output_limb_15_col50);
    eval.set_lookup_word(304, wg_v489);
    eval.set_lookup_word(305, message_word_15_id_col146);
    eval.set_sub_input_word(80, message_word_15_id_col146);
    eval.set_lookup_word(756, m31_1662111297);
    eval.set_lookup_word(757, message_word_15_id_col146);
    let wg_v490 = eval.m31_mul(low_7_ms_bits_col143, m31_512);
    let wg_v491 = eval.m31_sub(low_16_bits_col141, wg_v490);
    eval.set_lookup_word(758, wg_v491);
    let wg_v492 = eval.m31_mul(high_2_ls_bits_tmp_92ff8_172, m31_128);
    let wg_v493 = eval.m31_add(low_7_ms_bits_col143, wg_v492);
    eval.set_lookup_word(759, wg_v493);
    let wg_v494 = eval.m31_mul(high_5_ms_bits_col145, m31_512);
    let wg_v495 = eval.m31_sub(high_14_ms_bits_col144, wg_v494);
    eval.set_lookup_word(760, wg_v495);
    eval.set_lookup_word(761, high_5_ms_bits_col145);
    eval.set_lookup_word(762, m31_0);
    eval.set_lookup_word(763, m31_0);
    eval.set_lookup_word(764, m31_0);
    eval.set_lookup_word(765, m31_0);
    eval.set_lookup_word(766, m31_0);
    eval.set_lookup_word(767, m31_0);
    eval.set_lookup_word(768, m31_0);
    eval.set_lookup_word(769, m31_0);
    eval.set_lookup_word(770, m31_0);
    eval.set_lookup_word(771, m31_0);
    eval.set_lookup_word(772, m31_0);
    eval.set_lookup_word(773, m31_0);
    eval.set_lookup_word(774, m31_0);
    eval.set_lookup_word(775, m31_0);
    eval.set_lookup_word(776, m31_0);
    eval.set_lookup_word(777, m31_0);
    eval.set_lookup_word(778, m31_0);
    eval.set_lookup_word(779, m31_0);
    eval.set_lookup_word(780, m31_0);
    eval.set_lookup_word(781, m31_0);
    eval.set_lookup_word(782, m31_0);
    eval.set_lookup_word(783, m31_0);
    eval.set_lookup_word(784, m31_0);
    eval.set_lookup_word(785, m31_0);
    let read_u_32_output_tmp_92ff8_176 = expected_word_tmp_92ff8_169;
    let wg_v496 = eval.input_u32(2);
    let wg_v497 = eval.input_u32(6);
    let wg_v498 = eval.input_u32(10);
    let wg_v499 = eval.input_u32(14);
    eval.set_sub_input_word_u32(81, wg_v496);
    eval.set_sub_input_word_u32(82, wg_v497);
    eval.set_sub_input_word_u32(83, wg_v498);
    eval.set_sub_input_word_u32(84, wg_v499);
    eval.set_sub_input_word_u32(85, read_u_32_output_tmp_92ff8_11);
    eval.set_sub_input_word_u32(86, read_u_32_output_tmp_92ff8_22);
    let wg_v500 = eval.input_u32(2);
    let wg_v501 = eval.input_u32(6);
    let wg_v502 = eval.input_u32(10);
    let wg_v503 = eval.input_u32(14);
    let blake_g_output_tmp_92ff8_177 = eval.deduce_blake_g([
        wg_v500,
        wg_v501,
        wg_v502,
        wg_v503,
        read_u_32_output_tmp_92ff8_11,
        read_u_32_output_tmp_92ff8_22,
    ]);
    let wg_v504 = eval.u32_low(blake_g_output_tmp_92ff8_177[0]);
    let blake_g_output_limb_0_col147 = eval.u16_as_m31(wg_v504);
    eval.set_col(147, blake_g_output_limb_0_col147);
    let wg_v505 = eval.u32_high(blake_g_output_tmp_92ff8_177[0]);
    let blake_g_output_limb_1_col148 = eval.u16_as_m31(wg_v505);
    eval.set_col(148, blake_g_output_limb_1_col148);
    let wg_v506 = eval.u32_low(blake_g_output_tmp_92ff8_177[1]);
    let blake_g_output_limb_2_col149 = eval.u16_as_m31(wg_v506);
    eval.set_col(149, blake_g_output_limb_2_col149);
    let wg_v507 = eval.u32_high(blake_g_output_tmp_92ff8_177[1]);
    let blake_g_output_limb_3_col150 = eval.u16_as_m31(wg_v507);
    eval.set_col(150, blake_g_output_limb_3_col150);
    let wg_v508 = eval.u32_low(blake_g_output_tmp_92ff8_177[2]);
    let blake_g_output_limb_4_col151 = eval.u16_as_m31(wg_v508);
    eval.set_col(151, blake_g_output_limb_4_col151);
    let wg_v509 = eval.u32_high(blake_g_output_tmp_92ff8_177[2]);
    let blake_g_output_limb_5_col152 = eval.u16_as_m31(wg_v509);
    eval.set_col(152, blake_g_output_limb_5_col152);
    let wg_v510 = eval.u32_low(blake_g_output_tmp_92ff8_177[3]);
    let blake_g_output_limb_6_col153 = eval.u16_as_m31(wg_v510);
    eval.set_col(153, blake_g_output_limb_6_col153);
    let wg_v511 = eval.u32_high(blake_g_output_tmp_92ff8_177[3]);
    let blake_g_output_limb_7_col154 = eval.u16_as_m31(wg_v511);
    eval.set_col(154, blake_g_output_limb_7_col154);
    eval.set_lookup_word(0, m31_1139985212);
    eval.set_lookup_word(1, input_limb_2_col2);
    eval.set_lookup_word(2, input_limb_3_col3);
    eval.set_lookup_word(3, input_limb_10_col10);
    eval.set_lookup_word(4, input_limb_11_col11);
    eval.set_lookup_word(5, input_limb_18_col18);
    eval.set_lookup_word(6, input_limb_19_col19);
    eval.set_lookup_word(7, input_limb_26_col26);
    eval.set_lookup_word(8, input_limb_27_col27);
    eval.set_lookup_word(9, low_16_bits_col51);
    eval.set_lookup_word(10, high_16_bits_col52);
    eval.set_lookup_word(11, low_16_bits_col57);
    eval.set_lookup_word(12, high_16_bits_col58);
    eval.set_lookup_word(13, blake_g_output_limb_0_col147);
    eval.set_lookup_word(14, blake_g_output_limb_1_col148);
    eval.set_lookup_word(15, blake_g_output_limb_2_col149);
    eval.set_lookup_word(16, blake_g_output_limb_3_col150);
    eval.set_lookup_word(17, blake_g_output_limb_4_col151);
    eval.set_lookup_word(18, blake_g_output_limb_5_col152);
    eval.set_lookup_word(19, blake_g_output_limb_6_col153);
    eval.set_lookup_word(20, blake_g_output_limb_7_col154);
    let wg_v512 = eval.input_u32(3);
    let wg_v513 = eval.input_u32(7);
    let wg_v514 = eval.input_u32(11);
    let wg_v515 = eval.input_u32(15);
    eval.set_sub_input_word_u32(87, wg_v512);
    eval.set_sub_input_word_u32(88, wg_v513);
    eval.set_sub_input_word_u32(89, wg_v514);
    eval.set_sub_input_word_u32(90, wg_v515);
    eval.set_sub_input_word_u32(91, read_u_32_output_tmp_92ff8_33);
    eval.set_sub_input_word_u32(92, read_u_32_output_tmp_92ff8_44);
    let wg_v516 = eval.input_u32(3);
    let wg_v517 = eval.input_u32(7);
    let wg_v518 = eval.input_u32(11);
    let wg_v519 = eval.input_u32(15);
    let blake_g_output_tmp_92ff8_178 = eval.deduce_blake_g([
        wg_v516,
        wg_v517,
        wg_v518,
        wg_v519,
        read_u_32_output_tmp_92ff8_33,
        read_u_32_output_tmp_92ff8_44,
    ]);
    let wg_v520 = eval.u32_low(blake_g_output_tmp_92ff8_178[0]);
    let blake_g_output_limb_0_col155 = eval.u16_as_m31(wg_v520);
    eval.set_col(155, blake_g_output_limb_0_col155);
    let wg_v521 = eval.u32_high(blake_g_output_tmp_92ff8_178[0]);
    let blake_g_output_limb_1_col156 = eval.u16_as_m31(wg_v521);
    eval.set_col(156, blake_g_output_limb_1_col156);
    let wg_v522 = eval.u32_low(blake_g_output_tmp_92ff8_178[1]);
    let blake_g_output_limb_2_col157 = eval.u16_as_m31(wg_v522);
    eval.set_col(157, blake_g_output_limb_2_col157);
    let wg_v523 = eval.u32_high(blake_g_output_tmp_92ff8_178[1]);
    let blake_g_output_limb_3_col158 = eval.u16_as_m31(wg_v523);
    eval.set_col(158, blake_g_output_limb_3_col158);
    let wg_v524 = eval.u32_low(blake_g_output_tmp_92ff8_178[2]);
    let blake_g_output_limb_4_col159 = eval.u16_as_m31(wg_v524);
    eval.set_col(159, blake_g_output_limb_4_col159);
    let wg_v525 = eval.u32_high(blake_g_output_tmp_92ff8_178[2]);
    let blake_g_output_limb_5_col160 = eval.u16_as_m31(wg_v525);
    eval.set_col(160, blake_g_output_limb_5_col160);
    let wg_v526 = eval.u32_low(blake_g_output_tmp_92ff8_178[3]);
    let blake_g_output_limb_6_col161 = eval.u16_as_m31(wg_v526);
    eval.set_col(161, blake_g_output_limb_6_col161);
    let wg_v527 = eval.u32_high(blake_g_output_tmp_92ff8_178[3]);
    let blake_g_output_limb_7_col162 = eval.u16_as_m31(wg_v527);
    eval.set_col(162, blake_g_output_limb_7_col162);
    eval.set_lookup_word(21, m31_1139985212);
    eval.set_lookup_word(22, input_limb_4_col4);
    eval.set_lookup_word(23, input_limb_5_col5);
    eval.set_lookup_word(24, input_limb_12_col12);
    eval.set_lookup_word(25, input_limb_13_col13);
    eval.set_lookup_word(26, input_limb_20_col20);
    eval.set_lookup_word(27, input_limb_21_col21);
    eval.set_lookup_word(28, input_limb_28_col28);
    eval.set_lookup_word(29, input_limb_29_col29);
    eval.set_lookup_word(30, low_16_bits_col63);
    eval.set_lookup_word(31, high_16_bits_col64);
    eval.set_lookup_word(32, low_16_bits_col69);
    eval.set_lookup_word(33, high_16_bits_col70);
    eval.set_lookup_word(34, blake_g_output_limb_0_col155);
    eval.set_lookup_word(35, blake_g_output_limb_1_col156);
    eval.set_lookup_word(36, blake_g_output_limb_2_col157);
    eval.set_lookup_word(37, blake_g_output_limb_3_col158);
    eval.set_lookup_word(38, blake_g_output_limb_4_col159);
    eval.set_lookup_word(39, blake_g_output_limb_5_col160);
    eval.set_lookup_word(40, blake_g_output_limb_6_col161);
    eval.set_lookup_word(41, blake_g_output_limb_7_col162);
    let wg_v528 = eval.input_u32(4);
    let wg_v529 = eval.input_u32(8);
    let wg_v530 = eval.input_u32(12);
    let wg_v531 = eval.input_u32(16);
    eval.set_sub_input_word_u32(93, wg_v528);
    eval.set_sub_input_word_u32(94, wg_v529);
    eval.set_sub_input_word_u32(95, wg_v530);
    eval.set_sub_input_word_u32(96, wg_v531);
    eval.set_sub_input_word_u32(97, read_u_32_output_tmp_92ff8_55);
    eval.set_sub_input_word_u32(98, read_u_32_output_tmp_92ff8_66);
    let wg_v532 = eval.input_u32(4);
    let wg_v533 = eval.input_u32(8);
    let wg_v534 = eval.input_u32(12);
    let wg_v535 = eval.input_u32(16);
    let blake_g_output_tmp_92ff8_179 = eval.deduce_blake_g([
        wg_v532,
        wg_v533,
        wg_v534,
        wg_v535,
        read_u_32_output_tmp_92ff8_55,
        read_u_32_output_tmp_92ff8_66,
    ]);
    let wg_v536 = eval.u32_low(blake_g_output_tmp_92ff8_179[0]);
    let blake_g_output_limb_0_col163 = eval.u16_as_m31(wg_v536);
    eval.set_col(163, blake_g_output_limb_0_col163);
    let wg_v537 = eval.u32_high(blake_g_output_tmp_92ff8_179[0]);
    let blake_g_output_limb_1_col164 = eval.u16_as_m31(wg_v537);
    eval.set_col(164, blake_g_output_limb_1_col164);
    let wg_v538 = eval.u32_low(blake_g_output_tmp_92ff8_179[1]);
    let blake_g_output_limb_2_col165 = eval.u16_as_m31(wg_v538);
    eval.set_col(165, blake_g_output_limb_2_col165);
    let wg_v539 = eval.u32_high(blake_g_output_tmp_92ff8_179[1]);
    let blake_g_output_limb_3_col166 = eval.u16_as_m31(wg_v539);
    eval.set_col(166, blake_g_output_limb_3_col166);
    let wg_v540 = eval.u32_low(blake_g_output_tmp_92ff8_179[2]);
    let blake_g_output_limb_4_col167 = eval.u16_as_m31(wg_v540);
    eval.set_col(167, blake_g_output_limb_4_col167);
    let wg_v541 = eval.u32_high(blake_g_output_tmp_92ff8_179[2]);
    let blake_g_output_limb_5_col168 = eval.u16_as_m31(wg_v541);
    eval.set_col(168, blake_g_output_limb_5_col168);
    let wg_v542 = eval.u32_low(blake_g_output_tmp_92ff8_179[3]);
    let blake_g_output_limb_6_col169 = eval.u16_as_m31(wg_v542);
    eval.set_col(169, blake_g_output_limb_6_col169);
    let wg_v543 = eval.u32_high(blake_g_output_tmp_92ff8_179[3]);
    let blake_g_output_limb_7_col170 = eval.u16_as_m31(wg_v543);
    eval.set_col(170, blake_g_output_limb_7_col170);
    eval.set_lookup_word(42, m31_1139985212);
    eval.set_lookup_word(43, input_limb_6_col6);
    eval.set_lookup_word(44, input_limb_7_col7);
    eval.set_lookup_word(45, input_limb_14_col14);
    eval.set_lookup_word(46, input_limb_15_col15);
    eval.set_lookup_word(47, input_limb_22_col22);
    eval.set_lookup_word(48, input_limb_23_col23);
    eval.set_lookup_word(49, input_limb_30_col30);
    eval.set_lookup_word(50, input_limb_31_col31);
    eval.set_lookup_word(51, low_16_bits_col75);
    eval.set_lookup_word(52, high_16_bits_col76);
    eval.set_lookup_word(53, low_16_bits_col81);
    eval.set_lookup_word(54, high_16_bits_col82);
    eval.set_lookup_word(55, blake_g_output_limb_0_col163);
    eval.set_lookup_word(56, blake_g_output_limb_1_col164);
    eval.set_lookup_word(57, blake_g_output_limb_2_col165);
    eval.set_lookup_word(58, blake_g_output_limb_3_col166);
    eval.set_lookup_word(59, blake_g_output_limb_4_col167);
    eval.set_lookup_word(60, blake_g_output_limb_5_col168);
    eval.set_lookup_word(61, blake_g_output_limb_6_col169);
    eval.set_lookup_word(62, blake_g_output_limb_7_col170);
    let wg_v544 = eval.input_u32(5);
    let wg_v545 = eval.input_u32(9);
    let wg_v546 = eval.input_u32(13);
    let wg_v547 = eval.input_u32(17);
    eval.set_sub_input_word_u32(99, wg_v544);
    eval.set_sub_input_word_u32(100, wg_v545);
    eval.set_sub_input_word_u32(101, wg_v546);
    eval.set_sub_input_word_u32(102, wg_v547);
    eval.set_sub_input_word_u32(103, read_u_32_output_tmp_92ff8_77);
    eval.set_sub_input_word_u32(104, read_u_32_output_tmp_92ff8_88);
    let wg_v548 = eval.input_u32(5);
    let wg_v549 = eval.input_u32(9);
    let wg_v550 = eval.input_u32(13);
    let wg_v551 = eval.input_u32(17);
    let blake_g_output_tmp_92ff8_180 = eval.deduce_blake_g([
        wg_v548,
        wg_v549,
        wg_v550,
        wg_v551,
        read_u_32_output_tmp_92ff8_77,
        read_u_32_output_tmp_92ff8_88,
    ]);
    let wg_v552 = eval.u32_low(blake_g_output_tmp_92ff8_180[0]);
    let blake_g_output_limb_0_col171 = eval.u16_as_m31(wg_v552);
    eval.set_col(171, blake_g_output_limb_0_col171);
    let wg_v553 = eval.u32_high(blake_g_output_tmp_92ff8_180[0]);
    let blake_g_output_limb_1_col172 = eval.u16_as_m31(wg_v553);
    eval.set_col(172, blake_g_output_limb_1_col172);
    let wg_v554 = eval.u32_low(blake_g_output_tmp_92ff8_180[1]);
    let blake_g_output_limb_2_col173 = eval.u16_as_m31(wg_v554);
    eval.set_col(173, blake_g_output_limb_2_col173);
    let wg_v555 = eval.u32_high(blake_g_output_tmp_92ff8_180[1]);
    let blake_g_output_limb_3_col174 = eval.u16_as_m31(wg_v555);
    eval.set_col(174, blake_g_output_limb_3_col174);
    let wg_v556 = eval.u32_low(blake_g_output_tmp_92ff8_180[2]);
    let blake_g_output_limb_4_col175 = eval.u16_as_m31(wg_v556);
    eval.set_col(175, blake_g_output_limb_4_col175);
    let wg_v557 = eval.u32_high(blake_g_output_tmp_92ff8_180[2]);
    let blake_g_output_limb_5_col176 = eval.u16_as_m31(wg_v557);
    eval.set_col(176, blake_g_output_limb_5_col176);
    let wg_v558 = eval.u32_low(blake_g_output_tmp_92ff8_180[3]);
    let blake_g_output_limb_6_col177 = eval.u16_as_m31(wg_v558);
    eval.set_col(177, blake_g_output_limb_6_col177);
    let wg_v559 = eval.u32_high(blake_g_output_tmp_92ff8_180[3]);
    let blake_g_output_limb_7_col178 = eval.u16_as_m31(wg_v559);
    eval.set_col(178, blake_g_output_limb_7_col178);
    eval.set_lookup_word(63, m31_1139985212);
    eval.set_lookup_word(64, input_limb_8_col8);
    eval.set_lookup_word(65, input_limb_9_col9);
    eval.set_lookup_word(66, input_limb_16_col16);
    eval.set_lookup_word(67, input_limb_17_col17);
    eval.set_lookup_word(68, input_limb_24_col24);
    eval.set_lookup_word(69, input_limb_25_col25);
    eval.set_lookup_word(70, input_limb_32_col32);
    eval.set_lookup_word(71, input_limb_33_col33);
    eval.set_lookup_word(72, low_16_bits_col87);
    eval.set_lookup_word(73, high_16_bits_col88);
    eval.set_lookup_word(74, low_16_bits_col93);
    eval.set_lookup_word(75, high_16_bits_col94);
    eval.set_lookup_word(76, blake_g_output_limb_0_col171);
    eval.set_lookup_word(77, blake_g_output_limb_1_col172);
    eval.set_lookup_word(78, blake_g_output_limb_2_col173);
    eval.set_lookup_word(79, blake_g_output_limb_3_col174);
    eval.set_lookup_word(80, blake_g_output_limb_4_col175);
    eval.set_lookup_word(81, blake_g_output_limb_5_col176);
    eval.set_lookup_word(82, blake_g_output_limb_6_col177);
    eval.set_lookup_word(83, blake_g_output_limb_7_col178);
    eval.set_sub_input_word_u32(105, blake_g_output_tmp_92ff8_177[0]);
    eval.set_sub_input_word_u32(106, blake_g_output_tmp_92ff8_178[1]);
    eval.set_sub_input_word_u32(107, blake_g_output_tmp_92ff8_179[2]);
    eval.set_sub_input_word_u32(108, blake_g_output_tmp_92ff8_180[3]);
    eval.set_sub_input_word_u32(109, read_u_32_output_tmp_92ff8_99);
    eval.set_sub_input_word_u32(110, read_u_32_output_tmp_92ff8_110);
    let blake_g_output_tmp_92ff8_181 = eval.deduce_blake_g([
        blake_g_output_tmp_92ff8_177[0],
        blake_g_output_tmp_92ff8_178[1],
        blake_g_output_tmp_92ff8_179[2],
        blake_g_output_tmp_92ff8_180[3],
        read_u_32_output_tmp_92ff8_99,
        read_u_32_output_tmp_92ff8_110,
    ]);
    let wg_v560 = eval.u32_low(blake_g_output_tmp_92ff8_181[0]);
    let blake_g_output_limb_0_col179 = eval.u16_as_m31(wg_v560);
    eval.set_col(179, blake_g_output_limb_0_col179);
    let wg_v561 = eval.u32_high(blake_g_output_tmp_92ff8_181[0]);
    let blake_g_output_limb_1_col180 = eval.u16_as_m31(wg_v561);
    eval.set_col(180, blake_g_output_limb_1_col180);
    let wg_v562 = eval.u32_low(blake_g_output_tmp_92ff8_181[1]);
    let blake_g_output_limb_2_col181 = eval.u16_as_m31(wg_v562);
    eval.set_col(181, blake_g_output_limb_2_col181);
    let wg_v563 = eval.u32_high(blake_g_output_tmp_92ff8_181[1]);
    let blake_g_output_limb_3_col182 = eval.u16_as_m31(wg_v563);
    eval.set_col(182, blake_g_output_limb_3_col182);
    let wg_v564 = eval.u32_low(blake_g_output_tmp_92ff8_181[2]);
    let blake_g_output_limb_4_col183 = eval.u16_as_m31(wg_v564);
    eval.set_col(183, blake_g_output_limb_4_col183);
    let wg_v565 = eval.u32_high(blake_g_output_tmp_92ff8_181[2]);
    let blake_g_output_limb_5_col184 = eval.u16_as_m31(wg_v565);
    eval.set_col(184, blake_g_output_limb_5_col184);
    let wg_v566 = eval.u32_low(blake_g_output_tmp_92ff8_181[3]);
    let blake_g_output_limb_6_col185 = eval.u16_as_m31(wg_v566);
    eval.set_col(185, blake_g_output_limb_6_col185);
    let wg_v567 = eval.u32_high(blake_g_output_tmp_92ff8_181[3]);
    let blake_g_output_limb_7_col186 = eval.u16_as_m31(wg_v567);
    eval.set_col(186, blake_g_output_limb_7_col186);
    eval.set_lookup_word(84, m31_1139985212);
    eval.set_lookup_word(85, blake_g_output_limb_0_col147);
    eval.set_lookup_word(86, blake_g_output_limb_1_col148);
    eval.set_lookup_word(87, blake_g_output_limb_2_col157);
    eval.set_lookup_word(88, blake_g_output_limb_3_col158);
    eval.set_lookup_word(89, blake_g_output_limb_4_col167);
    eval.set_lookup_word(90, blake_g_output_limb_5_col168);
    eval.set_lookup_word(91, blake_g_output_limb_6_col177);
    eval.set_lookup_word(92, blake_g_output_limb_7_col178);
    eval.set_lookup_word(93, low_16_bits_col99);
    eval.set_lookup_word(94, high_16_bits_col100);
    eval.set_lookup_word(95, low_16_bits_col105);
    eval.set_lookup_word(96, high_16_bits_col106);
    eval.set_lookup_word(97, blake_g_output_limb_0_col179);
    eval.set_lookup_word(98, blake_g_output_limb_1_col180);
    eval.set_lookup_word(99, blake_g_output_limb_2_col181);
    eval.set_lookup_word(100, blake_g_output_limb_3_col182);
    eval.set_lookup_word(101, blake_g_output_limb_4_col183);
    eval.set_lookup_word(102, blake_g_output_limb_5_col184);
    eval.set_lookup_word(103, blake_g_output_limb_6_col185);
    eval.set_lookup_word(104, blake_g_output_limb_7_col186);
    eval.set_sub_input_word_u32(111, blake_g_output_tmp_92ff8_178[0]);
    eval.set_sub_input_word_u32(112, blake_g_output_tmp_92ff8_179[1]);
    eval.set_sub_input_word_u32(113, blake_g_output_tmp_92ff8_180[2]);
    eval.set_sub_input_word_u32(114, blake_g_output_tmp_92ff8_177[3]);
    eval.set_sub_input_word_u32(115, read_u_32_output_tmp_92ff8_121);
    eval.set_sub_input_word_u32(116, read_u_32_output_tmp_92ff8_132);
    let blake_g_output_tmp_92ff8_182 = eval.deduce_blake_g([
        blake_g_output_tmp_92ff8_178[0],
        blake_g_output_tmp_92ff8_179[1],
        blake_g_output_tmp_92ff8_180[2],
        blake_g_output_tmp_92ff8_177[3],
        read_u_32_output_tmp_92ff8_121,
        read_u_32_output_tmp_92ff8_132,
    ]);
    let wg_v568 = eval.u32_low(blake_g_output_tmp_92ff8_182[0]);
    let blake_g_output_limb_0_col187 = eval.u16_as_m31(wg_v568);
    eval.set_col(187, blake_g_output_limb_0_col187);
    let wg_v569 = eval.u32_high(blake_g_output_tmp_92ff8_182[0]);
    let blake_g_output_limb_1_col188 = eval.u16_as_m31(wg_v569);
    eval.set_col(188, blake_g_output_limb_1_col188);
    let wg_v570 = eval.u32_low(blake_g_output_tmp_92ff8_182[1]);
    let blake_g_output_limb_2_col189 = eval.u16_as_m31(wg_v570);
    eval.set_col(189, blake_g_output_limb_2_col189);
    let wg_v571 = eval.u32_high(blake_g_output_tmp_92ff8_182[1]);
    let blake_g_output_limb_3_col190 = eval.u16_as_m31(wg_v571);
    eval.set_col(190, blake_g_output_limb_3_col190);
    let wg_v572 = eval.u32_low(blake_g_output_tmp_92ff8_182[2]);
    let blake_g_output_limb_4_col191 = eval.u16_as_m31(wg_v572);
    eval.set_col(191, blake_g_output_limb_4_col191);
    let wg_v573 = eval.u32_high(blake_g_output_tmp_92ff8_182[2]);
    let blake_g_output_limb_5_col192 = eval.u16_as_m31(wg_v573);
    eval.set_col(192, blake_g_output_limb_5_col192);
    let wg_v574 = eval.u32_low(blake_g_output_tmp_92ff8_182[3]);
    let blake_g_output_limb_6_col193 = eval.u16_as_m31(wg_v574);
    eval.set_col(193, blake_g_output_limb_6_col193);
    let wg_v575 = eval.u32_high(blake_g_output_tmp_92ff8_182[3]);
    let blake_g_output_limb_7_col194 = eval.u16_as_m31(wg_v575);
    eval.set_col(194, blake_g_output_limb_7_col194);
    eval.set_lookup_word(105, m31_1139985212);
    eval.set_lookup_word(106, blake_g_output_limb_0_col155);
    eval.set_lookup_word(107, blake_g_output_limb_1_col156);
    eval.set_lookup_word(108, blake_g_output_limb_2_col165);
    eval.set_lookup_word(109, blake_g_output_limb_3_col166);
    eval.set_lookup_word(110, blake_g_output_limb_4_col175);
    eval.set_lookup_word(111, blake_g_output_limb_5_col176);
    eval.set_lookup_word(112, blake_g_output_limb_6_col153);
    eval.set_lookup_word(113, blake_g_output_limb_7_col154);
    eval.set_lookup_word(114, low_16_bits_col111);
    eval.set_lookup_word(115, high_16_bits_col112);
    eval.set_lookup_word(116, low_16_bits_col117);
    eval.set_lookup_word(117, high_16_bits_col118);
    eval.set_lookup_word(118, blake_g_output_limb_0_col187);
    eval.set_lookup_word(119, blake_g_output_limb_1_col188);
    eval.set_lookup_word(120, blake_g_output_limb_2_col189);
    eval.set_lookup_word(121, blake_g_output_limb_3_col190);
    eval.set_lookup_word(122, blake_g_output_limb_4_col191);
    eval.set_lookup_word(123, blake_g_output_limb_5_col192);
    eval.set_lookup_word(124, blake_g_output_limb_6_col193);
    eval.set_lookup_word(125, blake_g_output_limb_7_col194);
    eval.set_sub_input_word_u32(117, blake_g_output_tmp_92ff8_179[0]);
    eval.set_sub_input_word_u32(118, blake_g_output_tmp_92ff8_180[1]);
    eval.set_sub_input_word_u32(119, blake_g_output_tmp_92ff8_177[2]);
    eval.set_sub_input_word_u32(120, blake_g_output_tmp_92ff8_178[3]);
    eval.set_sub_input_word_u32(121, read_u_32_output_tmp_92ff8_143);
    eval.set_sub_input_word_u32(122, read_u_32_output_tmp_92ff8_154);
    let blake_g_output_tmp_92ff8_183 = eval.deduce_blake_g([
        blake_g_output_tmp_92ff8_179[0],
        blake_g_output_tmp_92ff8_180[1],
        blake_g_output_tmp_92ff8_177[2],
        blake_g_output_tmp_92ff8_178[3],
        read_u_32_output_tmp_92ff8_143,
        read_u_32_output_tmp_92ff8_154,
    ]);
    let wg_v576 = eval.u32_low(blake_g_output_tmp_92ff8_183[0]);
    let blake_g_output_limb_0_col195 = eval.u16_as_m31(wg_v576);
    eval.set_col(195, blake_g_output_limb_0_col195);
    let wg_v577 = eval.u32_high(blake_g_output_tmp_92ff8_183[0]);
    let blake_g_output_limb_1_col196 = eval.u16_as_m31(wg_v577);
    eval.set_col(196, blake_g_output_limb_1_col196);
    let wg_v578 = eval.u32_low(blake_g_output_tmp_92ff8_183[1]);
    let blake_g_output_limb_2_col197 = eval.u16_as_m31(wg_v578);
    eval.set_col(197, blake_g_output_limb_2_col197);
    let wg_v579 = eval.u32_high(blake_g_output_tmp_92ff8_183[1]);
    let blake_g_output_limb_3_col198 = eval.u16_as_m31(wg_v579);
    eval.set_col(198, blake_g_output_limb_3_col198);
    let wg_v580 = eval.u32_low(blake_g_output_tmp_92ff8_183[2]);
    let blake_g_output_limb_4_col199 = eval.u16_as_m31(wg_v580);
    eval.set_col(199, blake_g_output_limb_4_col199);
    let wg_v581 = eval.u32_high(blake_g_output_tmp_92ff8_183[2]);
    let blake_g_output_limb_5_col200 = eval.u16_as_m31(wg_v581);
    eval.set_col(200, blake_g_output_limb_5_col200);
    let wg_v582 = eval.u32_low(blake_g_output_tmp_92ff8_183[3]);
    let blake_g_output_limb_6_col201 = eval.u16_as_m31(wg_v582);
    eval.set_col(201, blake_g_output_limb_6_col201);
    let wg_v583 = eval.u32_high(blake_g_output_tmp_92ff8_183[3]);
    let blake_g_output_limb_7_col202 = eval.u16_as_m31(wg_v583);
    eval.set_col(202, blake_g_output_limb_7_col202);
    eval.set_lookup_word(126, m31_1139985212);
    eval.set_lookup_word(127, blake_g_output_limb_0_col163);
    eval.set_lookup_word(128, blake_g_output_limb_1_col164);
    eval.set_lookup_word(129, blake_g_output_limb_2_col173);
    eval.set_lookup_word(130, blake_g_output_limb_3_col174);
    eval.set_lookup_word(131, blake_g_output_limb_4_col151);
    eval.set_lookup_word(132, blake_g_output_limb_5_col152);
    eval.set_lookup_word(133, blake_g_output_limb_6_col161);
    eval.set_lookup_word(134, blake_g_output_limb_7_col162);
    eval.set_lookup_word(135, low_16_bits_col123);
    eval.set_lookup_word(136, high_16_bits_col124);
    eval.set_lookup_word(137, low_16_bits_col129);
    eval.set_lookup_word(138, high_16_bits_col130);
    eval.set_lookup_word(139, blake_g_output_limb_0_col195);
    eval.set_lookup_word(140, blake_g_output_limb_1_col196);
    eval.set_lookup_word(141, blake_g_output_limb_2_col197);
    eval.set_lookup_word(142, blake_g_output_limb_3_col198);
    eval.set_lookup_word(143, blake_g_output_limb_4_col199);
    eval.set_lookup_word(144, blake_g_output_limb_5_col200);
    eval.set_lookup_word(145, blake_g_output_limb_6_col201);
    eval.set_lookup_word(146, blake_g_output_limb_7_col202);
    eval.set_sub_input_word_u32(123, blake_g_output_tmp_92ff8_180[0]);
    eval.set_sub_input_word_u32(124, blake_g_output_tmp_92ff8_177[1]);
    eval.set_sub_input_word_u32(125, blake_g_output_tmp_92ff8_178[2]);
    eval.set_sub_input_word_u32(126, blake_g_output_tmp_92ff8_179[3]);
    eval.set_sub_input_word_u32(127, read_u_32_output_tmp_92ff8_165);
    eval.set_sub_input_word_u32(128, read_u_32_output_tmp_92ff8_176);
    let blake_g_output_tmp_92ff8_184 = eval.deduce_blake_g([
        blake_g_output_tmp_92ff8_180[0],
        blake_g_output_tmp_92ff8_177[1],
        blake_g_output_tmp_92ff8_178[2],
        blake_g_output_tmp_92ff8_179[3],
        read_u_32_output_tmp_92ff8_165,
        read_u_32_output_tmp_92ff8_176,
    ]);
    let wg_v584 = eval.u32_low(blake_g_output_tmp_92ff8_184[0]);
    let blake_g_output_limb_0_col203 = eval.u16_as_m31(wg_v584);
    eval.set_col(203, blake_g_output_limb_0_col203);
    let wg_v585 = eval.u32_high(blake_g_output_tmp_92ff8_184[0]);
    let blake_g_output_limb_1_col204 = eval.u16_as_m31(wg_v585);
    eval.set_col(204, blake_g_output_limb_1_col204);
    let wg_v586 = eval.u32_low(blake_g_output_tmp_92ff8_184[1]);
    let blake_g_output_limb_2_col205 = eval.u16_as_m31(wg_v586);
    eval.set_col(205, blake_g_output_limb_2_col205);
    let wg_v587 = eval.u32_high(blake_g_output_tmp_92ff8_184[1]);
    let blake_g_output_limb_3_col206 = eval.u16_as_m31(wg_v587);
    eval.set_col(206, blake_g_output_limb_3_col206);
    let wg_v588 = eval.u32_low(blake_g_output_tmp_92ff8_184[2]);
    let blake_g_output_limb_4_col207 = eval.u16_as_m31(wg_v588);
    eval.set_col(207, blake_g_output_limb_4_col207);
    let wg_v589 = eval.u32_high(blake_g_output_tmp_92ff8_184[2]);
    let blake_g_output_limb_5_col208 = eval.u16_as_m31(wg_v589);
    eval.set_col(208, blake_g_output_limb_5_col208);
    let wg_v590 = eval.u32_low(blake_g_output_tmp_92ff8_184[3]);
    let blake_g_output_limb_6_col209 = eval.u16_as_m31(wg_v590);
    eval.set_col(209, blake_g_output_limb_6_col209);
    let wg_v591 = eval.u32_high(blake_g_output_tmp_92ff8_184[3]);
    let blake_g_output_limb_7_col210 = eval.u16_as_m31(wg_v591);
    eval.set_col(210, blake_g_output_limb_7_col210);
    eval.set_lookup_word(147, m31_1139985212);
    eval.set_lookup_word(148, blake_g_output_limb_0_col171);
    eval.set_lookup_word(149, blake_g_output_limb_1_col172);
    eval.set_lookup_word(150, blake_g_output_limb_2_col149);
    eval.set_lookup_word(151, blake_g_output_limb_3_col150);
    eval.set_lookup_word(152, blake_g_output_limb_4_col159);
    eval.set_lookup_word(153, blake_g_output_limb_5_col160);
    eval.set_lookup_word(154, blake_g_output_limb_6_col169);
    eval.set_lookup_word(155, blake_g_output_limb_7_col170);
    eval.set_lookup_word(156, low_16_bits_col135);
    eval.set_lookup_word(157, high_16_bits_col136);
    eval.set_lookup_word(158, low_16_bits_col141);
    eval.set_lookup_word(159, high_16_bits_col142);
    eval.set_lookup_word(160, blake_g_output_limb_0_col203);
    eval.set_lookup_word(161, blake_g_output_limb_1_col204);
    eval.set_lookup_word(162, blake_g_output_limb_2_col205);
    eval.set_lookup_word(163, blake_g_output_limb_3_col206);
    eval.set_lookup_word(164, blake_g_output_limb_4_col207);
    eval.set_lookup_word(165, blake_g_output_limb_5_col208);
    eval.set_lookup_word(166, blake_g_output_limb_6_col209);
    eval.set_lookup_word(167, blake_g_output_limb_7_col210);
    eval.set_lookup_word(168, m31_40528774);
    eval.set_lookup_word(169, input_limb_0_col0);
    eval.set_lookup_word(170, input_limb_1_col1);
    eval.set_lookup_word(171, input_limb_2_col2);
    eval.set_lookup_word(172, input_limb_3_col3);
    eval.set_lookup_word(173, input_limb_4_col4);
    eval.set_lookup_word(174, input_limb_5_col5);
    eval.set_lookup_word(175, input_limb_6_col6);
    eval.set_lookup_word(176, input_limb_7_col7);
    eval.set_lookup_word(177, input_limb_8_col8);
    eval.set_lookup_word(178, input_limb_9_col9);
    eval.set_lookup_word(179, input_limb_10_col10);
    eval.set_lookup_word(180, input_limb_11_col11);
    eval.set_lookup_word(181, input_limb_12_col12);
    eval.set_lookup_word(182, input_limb_13_col13);
    eval.set_lookup_word(183, input_limb_14_col14);
    eval.set_lookup_word(184, input_limb_15_col15);
    eval.set_lookup_word(185, input_limb_16_col16);
    eval.set_lookup_word(186, input_limb_17_col17);
    eval.set_lookup_word(187, input_limb_18_col18);
    eval.set_lookup_word(188, input_limb_19_col19);
    eval.set_lookup_word(189, input_limb_20_col20);
    eval.set_lookup_word(190, input_limb_21_col21);
    eval.set_lookup_word(191, input_limb_22_col22);
    eval.set_lookup_word(192, input_limb_23_col23);
    eval.set_lookup_word(193, input_limb_24_col24);
    eval.set_lookup_word(194, input_limb_25_col25);
    eval.set_lookup_word(195, input_limb_26_col26);
    eval.set_lookup_word(196, input_limb_27_col27);
    eval.set_lookup_word(197, input_limb_28_col28);
    eval.set_lookup_word(198, input_limb_29_col29);
    eval.set_lookup_word(199, input_limb_30_col30);
    eval.set_lookup_word(200, input_limb_31_col31);
    eval.set_lookup_word(201, input_limb_32_col32);
    eval.set_lookup_word(202, input_limb_33_col33);
    eval.set_lookup_word(203, input_limb_34_col34);
    eval.set_lookup_word(204, m31_40528774);
    eval.set_lookup_word(205, input_limb_0_col0);
    let wg_v592 = eval.m31_add(input_limb_1_col1, m31_1);
    eval.set_lookup_word(206, wg_v592);
    eval.set_lookup_word(207, blake_g_output_limb_0_col179);
    eval.set_lookup_word(208, blake_g_output_limb_1_col180);
    eval.set_lookup_word(209, blake_g_output_limb_0_col187);
    eval.set_lookup_word(210, blake_g_output_limb_1_col188);
    eval.set_lookup_word(211, blake_g_output_limb_0_col195);
    eval.set_lookup_word(212, blake_g_output_limb_1_col196);
    eval.set_lookup_word(213, blake_g_output_limb_0_col203);
    eval.set_lookup_word(214, blake_g_output_limb_1_col204);
    eval.set_lookup_word(215, blake_g_output_limb_2_col205);
    eval.set_lookup_word(216, blake_g_output_limb_3_col206);
    eval.set_lookup_word(217, blake_g_output_limb_2_col181);
    eval.set_lookup_word(218, blake_g_output_limb_3_col182);
    eval.set_lookup_word(219, blake_g_output_limb_2_col189);
    eval.set_lookup_word(220, blake_g_output_limb_3_col190);
    eval.set_lookup_word(221, blake_g_output_limb_2_col197);
    eval.set_lookup_word(222, blake_g_output_limb_3_col198);
    eval.set_lookup_word(223, blake_g_output_limb_4_col199);
    eval.set_lookup_word(224, blake_g_output_limb_5_col200);
    eval.set_lookup_word(225, blake_g_output_limb_4_col207);
    eval.set_lookup_word(226, blake_g_output_limb_5_col208);
    eval.set_lookup_word(227, blake_g_output_limb_4_col183);
    eval.set_lookup_word(228, blake_g_output_limb_5_col184);
    eval.set_lookup_word(229, blake_g_output_limb_4_col191);
    eval.set_lookup_word(230, blake_g_output_limb_5_col192);
    eval.set_lookup_word(231, blake_g_output_limb_6_col193);
    eval.set_lookup_word(232, blake_g_output_limb_7_col194);
    eval.set_lookup_word(233, blake_g_output_limb_6_col201);
    eval.set_lookup_word(234, blake_g_output_limb_7_col202);
    eval.set_lookup_word(235, blake_g_output_limb_6_col209);
    eval.set_lookup_word(236, blake_g_output_limb_7_col210);
    eval.set_lookup_word(237, blake_g_output_limb_6_col185);
    eval.set_lookup_word(238, blake_g_output_limb_7_col186);
    eval.set_lookup_word(239, input_limb_34_col34);
    let wg_v593 = eval.enabler();
    eval.set_col(211, wg_v593);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `blake_round_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
    blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    blake_g_state: &blake_g::ClaimGenerator,
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
            |(row_index, (row, lookup_data, sub_component_inputs, blake_round_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    vec![
                        blake_round_input.0.into_simd(),
                        blake_round_input.1.into_simd(),
                        blake_round_input.2 .0[0].simd,
                        blake_round_input.2 .0[1].simd,
                        blake_round_input.2 .0[2].simd,
                        blake_round_input.2 .0[3].simd,
                        blake_round_input.2 .0[4].simd,
                        blake_round_input.2 .0[5].simd,
                        blake_round_input.2 .0[6].simd,
                        blake_round_input.2 .0[7].simd,
                        blake_round_input.2 .0[8].simd,
                        blake_round_input.2 .0[9].simd,
                        blake_round_input.2 .0[10].simd,
                        blake_round_input.2 .0[11].simd,
                        blake_round_input.2 .0[12].simd,
                        blake_round_input.2 .0[13].simd,
                        blake_round_input.2 .0[14].simd,
                        blake_round_input.2 .0[15].simd,
                        blake_round_input.2 .1.into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                blake_round_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.blake_g_0 = [
                    lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10],
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                ];
                *lookup_data.blake_g_1 = [
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30],
                    lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40],
                    lw[41],
                ];
                *lookup_data.blake_g_2 = [
                    lw[42], lw[43], lw[44], lw[45], lw[46], lw[47], lw[48], lw[49], lw[50], lw[51],
                    lw[52], lw[53], lw[54], lw[55], lw[56], lw[57], lw[58], lw[59], lw[60], lw[61],
                    lw[62],
                ];
                *lookup_data.blake_g_3 = [
                    lw[63], lw[64], lw[65], lw[66], lw[67], lw[68], lw[69], lw[70], lw[71], lw[72],
                    lw[73], lw[74], lw[75], lw[76], lw[77], lw[78], lw[79], lw[80], lw[81], lw[82],
                    lw[83],
                ];
                *lookup_data.blake_g_4 = [
                    lw[84], lw[85], lw[86], lw[87], lw[88], lw[89], lw[90], lw[91], lw[92], lw[93],
                    lw[94], lw[95], lw[96], lw[97], lw[98], lw[99], lw[100], lw[101], lw[102],
                    lw[103], lw[104],
                ];
                *lookup_data.blake_g_5 = [
                    lw[105], lw[106], lw[107], lw[108], lw[109], lw[110], lw[111], lw[112],
                    lw[113], lw[114], lw[115], lw[116], lw[117], lw[118], lw[119], lw[120],
                    lw[121], lw[122], lw[123], lw[124], lw[125],
                ];
                *lookup_data.blake_g_6 = [
                    lw[126], lw[127], lw[128], lw[129], lw[130], lw[131], lw[132], lw[133],
                    lw[134], lw[135], lw[136], lw[137], lw[138], lw[139], lw[140], lw[141],
                    lw[142], lw[143], lw[144], lw[145], lw[146],
                ];
                *lookup_data.blake_g_7 = [
                    lw[147], lw[148], lw[149], lw[150], lw[151], lw[152], lw[153], lw[154],
                    lw[155], lw[156], lw[157], lw[158], lw[159], lw[160], lw[161], lw[162],
                    lw[163], lw[164], lw[165], lw[166], lw[167],
                ];
                *lookup_data.blake_round_0 = [
                    lw[168], lw[169], lw[170], lw[171], lw[172], lw[173], lw[174], lw[175],
                    lw[176], lw[177], lw[178], lw[179], lw[180], lw[181], lw[182], lw[183],
                    lw[184], lw[185], lw[186], lw[187], lw[188], lw[189], lw[190], lw[191],
                    lw[192], lw[193], lw[194], lw[195], lw[196], lw[197], lw[198], lw[199],
                    lw[200], lw[201], lw[202], lw[203],
                ];
                *lookup_data.blake_round_1 = [
                    lw[204], lw[205], lw[206], lw[207], lw[208], lw[209], lw[210], lw[211],
                    lw[212], lw[213], lw[214], lw[215], lw[216], lw[217], lw[218], lw[219],
                    lw[220], lw[221], lw[222], lw[223], lw[224], lw[225], lw[226], lw[227],
                    lw[228], lw[229], lw[230], lw[231], lw[232], lw[233], lw[234], lw[235],
                    lw[236], lw[237], lw[238], lw[239],
                ];
                *lookup_data.blake_round_sigma_0 = [
                    lw[240], lw[241], lw[242], lw[243], lw[244], lw[245], lw[246], lw[247],
                    lw[248], lw[249], lw[250], lw[251], lw[252], lw[253], lw[254], lw[255],
                    lw[256], lw[257],
                ];
                *lookup_data.memory_address_to_id_0 = [lw[258], lw[259], lw[260]];
                *lookup_data.memory_address_to_id_1 = [lw[261], lw[262], lw[263]];
                *lookup_data.memory_address_to_id_2 = [lw[264], lw[265], lw[266]];
                *lookup_data.memory_address_to_id_3 = [lw[267], lw[268], lw[269]];
                *lookup_data.memory_address_to_id_4 = [lw[270], lw[271], lw[272]];
                *lookup_data.memory_address_to_id_5 = [lw[273], lw[274], lw[275]];
                *lookup_data.memory_address_to_id_6 = [lw[276], lw[277], lw[278]];
                *lookup_data.memory_address_to_id_7 = [lw[279], lw[280], lw[281]];
                *lookup_data.memory_address_to_id_8 = [lw[282], lw[283], lw[284]];
                *lookup_data.memory_address_to_id_9 = [lw[285], lw[286], lw[287]];
                *lookup_data.memory_address_to_id_10 = [lw[288], lw[289], lw[290]];
                *lookup_data.memory_address_to_id_11 = [lw[291], lw[292], lw[293]];
                *lookup_data.memory_address_to_id_12 = [lw[294], lw[295], lw[296]];
                *lookup_data.memory_address_to_id_13 = [lw[297], lw[298], lw[299]];
                *lookup_data.memory_address_to_id_14 = [lw[300], lw[301], lw[302]];
                *lookup_data.memory_address_to_id_15 = [lw[303], lw[304], lw[305]];
                *lookup_data.memory_id_to_big_0 = [
                    lw[306], lw[307], lw[308], lw[309], lw[310], lw[311], lw[312], lw[313],
                    lw[314], lw[315], lw[316], lw[317], lw[318], lw[319], lw[320], lw[321],
                    lw[322], lw[323], lw[324], lw[325], lw[326], lw[327], lw[328], lw[329],
                    lw[330], lw[331], lw[332], lw[333], lw[334], lw[335],
                ];
                *lookup_data.memory_id_to_big_1 = [
                    lw[336], lw[337], lw[338], lw[339], lw[340], lw[341], lw[342], lw[343],
                    lw[344], lw[345], lw[346], lw[347], lw[348], lw[349], lw[350], lw[351],
                    lw[352], lw[353], lw[354], lw[355], lw[356], lw[357], lw[358], lw[359],
                    lw[360], lw[361], lw[362], lw[363], lw[364], lw[365],
                ];
                *lookup_data.memory_id_to_big_2 = [
                    lw[366], lw[367], lw[368], lw[369], lw[370], lw[371], lw[372], lw[373],
                    lw[374], lw[375], lw[376], lw[377], lw[378], lw[379], lw[380], lw[381],
                    lw[382], lw[383], lw[384], lw[385], lw[386], lw[387], lw[388], lw[389],
                    lw[390], lw[391], lw[392], lw[393], lw[394], lw[395],
                ];
                *lookup_data.memory_id_to_big_3 = [
                    lw[396], lw[397], lw[398], lw[399], lw[400], lw[401], lw[402], lw[403],
                    lw[404], lw[405], lw[406], lw[407], lw[408], lw[409], lw[410], lw[411],
                    lw[412], lw[413], lw[414], lw[415], lw[416], lw[417], lw[418], lw[419],
                    lw[420], lw[421], lw[422], lw[423], lw[424], lw[425],
                ];
                *lookup_data.memory_id_to_big_4 = [
                    lw[426], lw[427], lw[428], lw[429], lw[430], lw[431], lw[432], lw[433],
                    lw[434], lw[435], lw[436], lw[437], lw[438], lw[439], lw[440], lw[441],
                    lw[442], lw[443], lw[444], lw[445], lw[446], lw[447], lw[448], lw[449],
                    lw[450], lw[451], lw[452], lw[453], lw[454], lw[455],
                ];
                *lookup_data.memory_id_to_big_5 = [
                    lw[456], lw[457], lw[458], lw[459], lw[460], lw[461], lw[462], lw[463],
                    lw[464], lw[465], lw[466], lw[467], lw[468], lw[469], lw[470], lw[471],
                    lw[472], lw[473], lw[474], lw[475], lw[476], lw[477], lw[478], lw[479],
                    lw[480], lw[481], lw[482], lw[483], lw[484], lw[485],
                ];
                *lookup_data.memory_id_to_big_6 = [
                    lw[486], lw[487], lw[488], lw[489], lw[490], lw[491], lw[492], lw[493],
                    lw[494], lw[495], lw[496], lw[497], lw[498], lw[499], lw[500], lw[501],
                    lw[502], lw[503], lw[504], lw[505], lw[506], lw[507], lw[508], lw[509],
                    lw[510], lw[511], lw[512], lw[513], lw[514], lw[515],
                ];
                *lookup_data.memory_id_to_big_7 = [
                    lw[516], lw[517], lw[518], lw[519], lw[520], lw[521], lw[522], lw[523],
                    lw[524], lw[525], lw[526], lw[527], lw[528], lw[529], lw[530], lw[531],
                    lw[532], lw[533], lw[534], lw[535], lw[536], lw[537], lw[538], lw[539],
                    lw[540], lw[541], lw[542], lw[543], lw[544], lw[545],
                ];
                *lookup_data.memory_id_to_big_8 = [
                    lw[546], lw[547], lw[548], lw[549], lw[550], lw[551], lw[552], lw[553],
                    lw[554], lw[555], lw[556], lw[557], lw[558], lw[559], lw[560], lw[561],
                    lw[562], lw[563], lw[564], lw[565], lw[566], lw[567], lw[568], lw[569],
                    lw[570], lw[571], lw[572], lw[573], lw[574], lw[575],
                ];
                *lookup_data.memory_id_to_big_9 = [
                    lw[576], lw[577], lw[578], lw[579], lw[580], lw[581], lw[582], lw[583],
                    lw[584], lw[585], lw[586], lw[587], lw[588], lw[589], lw[590], lw[591],
                    lw[592], lw[593], lw[594], lw[595], lw[596], lw[597], lw[598], lw[599],
                    lw[600], lw[601], lw[602], lw[603], lw[604], lw[605],
                ];
                *lookup_data.memory_id_to_big_10 = [
                    lw[606], lw[607], lw[608], lw[609], lw[610], lw[611], lw[612], lw[613],
                    lw[614], lw[615], lw[616], lw[617], lw[618], lw[619], lw[620], lw[621],
                    lw[622], lw[623], lw[624], lw[625], lw[626], lw[627], lw[628], lw[629],
                    lw[630], lw[631], lw[632], lw[633], lw[634], lw[635],
                ];
                *lookup_data.memory_id_to_big_11 = [
                    lw[636], lw[637], lw[638], lw[639], lw[640], lw[641], lw[642], lw[643],
                    lw[644], lw[645], lw[646], lw[647], lw[648], lw[649], lw[650], lw[651],
                    lw[652], lw[653], lw[654], lw[655], lw[656], lw[657], lw[658], lw[659],
                    lw[660], lw[661], lw[662], lw[663], lw[664], lw[665],
                ];
                *lookup_data.memory_id_to_big_12 = [
                    lw[666], lw[667], lw[668], lw[669], lw[670], lw[671], lw[672], lw[673],
                    lw[674], lw[675], lw[676], lw[677], lw[678], lw[679], lw[680], lw[681],
                    lw[682], lw[683], lw[684], lw[685], lw[686], lw[687], lw[688], lw[689],
                    lw[690], lw[691], lw[692], lw[693], lw[694], lw[695],
                ];
                *lookup_data.memory_id_to_big_13 = [
                    lw[696], lw[697], lw[698], lw[699], lw[700], lw[701], lw[702], lw[703],
                    lw[704], lw[705], lw[706], lw[707], lw[708], lw[709], lw[710], lw[711],
                    lw[712], lw[713], lw[714], lw[715], lw[716], lw[717], lw[718], lw[719],
                    lw[720], lw[721], lw[722], lw[723], lw[724], lw[725],
                ];
                *lookup_data.memory_id_to_big_14 = [
                    lw[726], lw[727], lw[728], lw[729], lw[730], lw[731], lw[732], lw[733],
                    lw[734], lw[735], lw[736], lw[737], lw[738], lw[739], lw[740], lw[741],
                    lw[742], lw[743], lw[744], lw[745], lw[746], lw[747], lw[748], lw[749],
                    lw[750], lw[751], lw[752], lw[753], lw[754], lw[755],
                ];
                *lookup_data.memory_id_to_big_15 = [
                    lw[756], lw[757], lw[758], lw[759], lw[760], lw[761], lw[762], lw[763],
                    lw[764], lw[765], lw[766], lw[767], lw[768], lw[769], lw[770], lw[771],
                    lw[772], lw[773], lw[774], lw[775], lw[776], lw[777], lw[778], lw[779],
                    lw[780], lw[781], lw[782], lw[783], lw[784], lw[785],
                ];
                *lookup_data.range_check_7_2_5_0 = [lw[786], lw[787], lw[788], lw[789]];
                *lookup_data.range_check_7_2_5_1 = [lw[790], lw[791], lw[792], lw[793]];
                *lookup_data.range_check_7_2_5_2 = [lw[794], lw[795], lw[796], lw[797]];
                *lookup_data.range_check_7_2_5_3 = [lw[798], lw[799], lw[800], lw[801]];
                *lookup_data.range_check_7_2_5_4 = [lw[802], lw[803], lw[804], lw[805]];
                *lookup_data.range_check_7_2_5_5 = [lw[806], lw[807], lw[808], lw[809]];
                *lookup_data.range_check_7_2_5_6 = [lw[810], lw[811], lw[812], lw[813]];
                *lookup_data.range_check_7_2_5_7 = [lw[814], lw[815], lw[816], lw[817]];
                *lookup_data.range_check_7_2_5_8 = [lw[818], lw[819], lw[820], lw[821]];
                *lookup_data.range_check_7_2_5_9 = [lw[822], lw[823], lw[824], lw[825]];
                *lookup_data.range_check_7_2_5_10 = [lw[826], lw[827], lw[828], lw[829]];
                *lookup_data.range_check_7_2_5_11 = [lw[830], lw[831], lw[832], lw[833]];
                *lookup_data.range_check_7_2_5_12 = [lw[834], lw[835], lw[836], lw[837]];
                *lookup_data.range_check_7_2_5_13 = [lw[838], lw[839], lw[840], lw[841]];
                *lookup_data.range_check_7_2_5_14 = [lw[842], lw[843], lw[844], lw[845]];
                *lookup_data.range_check_7_2_5_15 = [lw[846], lw[847], lw[848], lw[849]];
                let sw = eval.sub_scratch();
                *sub_component_inputs.blake_round_sigma[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[0]) }];
                *sub_component_inputs.range_check_7_2_5[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[3]) },
                ];
                *sub_component_inputs.range_check_7_2_5[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[4]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                ];
                *sub_component_inputs.range_check_7_2_5[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                ];
                *sub_component_inputs.range_check_7_2_5[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) },
                ];
                *sub_component_inputs.range_check_7_2_5[4] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[15]) },
                ];
                *sub_component_inputs.range_check_7_2_5[5] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[18]) },
                ];
                *sub_component_inputs.range_check_7_2_5[6] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[21]) },
                ];
                *sub_component_inputs.range_check_7_2_5[7] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[23]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[24]) },
                ];
                *sub_component_inputs.range_check_7_2_5[8] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[25]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[26]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[27]) },
                ];
                *sub_component_inputs.range_check_7_2_5[9] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[28]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[29]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[30]) },
                ];
                *sub_component_inputs.range_check_7_2_5[10] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[31]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[32]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[33]) },
                ];
                *sub_component_inputs.range_check_7_2_5[11] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[34]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[35]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[36]) },
                ];
                *sub_component_inputs.range_check_7_2_5[12] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[37]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[38]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[39]) },
                ];
                *sub_component_inputs.range_check_7_2_5[13] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[40]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[41]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[42]) },
                ];
                *sub_component_inputs.range_check_7_2_5[14] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[43]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[44]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[45]) },
                ];
                *sub_component_inputs.range_check_7_2_5[15] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[46]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[48]) },
                ];
                *sub_component_inputs.memory_address_to_id[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[49]) };
                *sub_component_inputs.memory_address_to_id[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[50]) };
                *sub_component_inputs.memory_address_to_id[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[51]) };
                *sub_component_inputs.memory_address_to_id[3] =
                    unsafe { PackedM31::from_simd_unchecked(sw[52]) };
                *sub_component_inputs.memory_address_to_id[4] =
                    unsafe { PackedM31::from_simd_unchecked(sw[53]) };
                *sub_component_inputs.memory_address_to_id[5] =
                    unsafe { PackedM31::from_simd_unchecked(sw[54]) };
                *sub_component_inputs.memory_address_to_id[6] =
                    unsafe { PackedM31::from_simd_unchecked(sw[55]) };
                *sub_component_inputs.memory_address_to_id[7] =
                    unsafe { PackedM31::from_simd_unchecked(sw[56]) };
                *sub_component_inputs.memory_address_to_id[8] =
                    unsafe { PackedM31::from_simd_unchecked(sw[57]) };
                *sub_component_inputs.memory_address_to_id[9] =
                    unsafe { PackedM31::from_simd_unchecked(sw[58]) };
                *sub_component_inputs.memory_address_to_id[10] =
                    unsafe { PackedM31::from_simd_unchecked(sw[59]) };
                *sub_component_inputs.memory_address_to_id[11] =
                    unsafe { PackedM31::from_simd_unchecked(sw[60]) };
                *sub_component_inputs.memory_address_to_id[12] =
                    unsafe { PackedM31::from_simd_unchecked(sw[61]) };
                *sub_component_inputs.memory_address_to_id[13] =
                    unsafe { PackedM31::from_simd_unchecked(sw[62]) };
                *sub_component_inputs.memory_address_to_id[14] =
                    unsafe { PackedM31::from_simd_unchecked(sw[63]) };
                *sub_component_inputs.memory_address_to_id[15] =
                    unsafe { PackedM31::from_simd_unchecked(sw[64]) };
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[65]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[66]) };
                *sub_component_inputs.memory_id_to_big[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[67]) };
                *sub_component_inputs.memory_id_to_big[3] =
                    unsafe { PackedM31::from_simd_unchecked(sw[68]) };
                *sub_component_inputs.memory_id_to_big[4] =
                    unsafe { PackedM31::from_simd_unchecked(sw[69]) };
                *sub_component_inputs.memory_id_to_big[5] =
                    unsafe { PackedM31::from_simd_unchecked(sw[70]) };
                *sub_component_inputs.memory_id_to_big[6] =
                    unsafe { PackedM31::from_simd_unchecked(sw[71]) };
                *sub_component_inputs.memory_id_to_big[7] =
                    unsafe { PackedM31::from_simd_unchecked(sw[72]) };
                *sub_component_inputs.memory_id_to_big[8] =
                    unsafe { PackedM31::from_simd_unchecked(sw[73]) };
                *sub_component_inputs.memory_id_to_big[9] =
                    unsafe { PackedM31::from_simd_unchecked(sw[74]) };
                *sub_component_inputs.memory_id_to_big[10] =
                    unsafe { PackedM31::from_simd_unchecked(sw[75]) };
                *sub_component_inputs.memory_id_to_big[11] =
                    unsafe { PackedM31::from_simd_unchecked(sw[76]) };
                *sub_component_inputs.memory_id_to_big[12] =
                    unsafe { PackedM31::from_simd_unchecked(sw[77]) };
                *sub_component_inputs.memory_id_to_big[13] =
                    unsafe { PackedM31::from_simd_unchecked(sw[78]) };
                *sub_component_inputs.memory_id_to_big[14] =
                    unsafe { PackedM31::from_simd_unchecked(sw[79]) };
                *sub_component_inputs.memory_id_to_big[15] =
                    unsafe { PackedM31::from_simd_unchecked(sw[80]) };
                *sub_component_inputs.blake_g[0] = [
                    PackedUInt32::from_simd(sw[81]),
                    PackedUInt32::from_simd(sw[82]),
                    PackedUInt32::from_simd(sw[83]),
                    PackedUInt32::from_simd(sw[84]),
                    PackedUInt32::from_simd(sw[85]),
                    PackedUInt32::from_simd(sw[86]),
                ];
                *sub_component_inputs.blake_g[1] = [
                    PackedUInt32::from_simd(sw[87]),
                    PackedUInt32::from_simd(sw[88]),
                    PackedUInt32::from_simd(sw[89]),
                    PackedUInt32::from_simd(sw[90]),
                    PackedUInt32::from_simd(sw[91]),
                    PackedUInt32::from_simd(sw[92]),
                ];
                *sub_component_inputs.blake_g[2] = [
                    PackedUInt32::from_simd(sw[93]),
                    PackedUInt32::from_simd(sw[94]),
                    PackedUInt32::from_simd(sw[95]),
                    PackedUInt32::from_simd(sw[96]),
                    PackedUInt32::from_simd(sw[97]),
                    PackedUInt32::from_simd(sw[98]),
                ];
                *sub_component_inputs.blake_g[3] = [
                    PackedUInt32::from_simd(sw[99]),
                    PackedUInt32::from_simd(sw[100]),
                    PackedUInt32::from_simd(sw[101]),
                    PackedUInt32::from_simd(sw[102]),
                    PackedUInt32::from_simd(sw[103]),
                    PackedUInt32::from_simd(sw[104]),
                ];
                *sub_component_inputs.blake_g[4] = [
                    PackedUInt32::from_simd(sw[105]),
                    PackedUInt32::from_simd(sw[106]),
                    PackedUInt32::from_simd(sw[107]),
                    PackedUInt32::from_simd(sw[108]),
                    PackedUInt32::from_simd(sw[109]),
                    PackedUInt32::from_simd(sw[110]),
                ];
                *sub_component_inputs.blake_g[5] = [
                    PackedUInt32::from_simd(sw[111]),
                    PackedUInt32::from_simd(sw[112]),
                    PackedUInt32::from_simd(sw[113]),
                    PackedUInt32::from_simd(sw[114]),
                    PackedUInt32::from_simd(sw[115]),
                    PackedUInt32::from_simd(sw[116]),
                ];
                *sub_component_inputs.blake_g[6] = [
                    PackedUInt32::from_simd(sw[117]),
                    PackedUInt32::from_simd(sw[118]),
                    PackedUInt32::from_simd(sw[119]),
                    PackedUInt32::from_simd(sw[120]),
                    PackedUInt32::from_simd(sw[121]),
                    PackedUInt32::from_simd(sw[122]),
                ];
                *sub_component_inputs.blake_g[7] = [
                    PackedUInt32::from_simd(sw[123]),
                    PackedUInt32::from_simd(sw[124]),
                    PackedUInt32::from_simd(sw[125]),
                    PackedUInt32::from_simd(sw[126]),
                    PackedUInt32::from_simd(sw[127]),
                    PackedUInt32::from_simd(sw[128]),
                ];
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
        blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        blake_g_state: &blake_g::ClaimGenerator,
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
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            packed_inputs,
            n_rows,
            blake_round_sigma_state,
            memory_address_to_id_state,
            memory_id_to_big_state,
            range_check_7_2_5_state,
            blake_g_state,
        );
        sub_component_inputs
            .blake_round_sigma
            .iter()
            .for_each(|inputs| {
                blake_round_sigma_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .range_check_7_2_5
            .iter()
            .for_each(|inputs| {
                range_check_7_2_5_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .memory_address_to_id
            .iter()
            .for_each(|inputs| {
                memory_address_to_id_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs
            .memory_id_to_big
            .iter()
            .for_each(|inputs| {
                memory_id_to_big_state.add_packed_inputs(inputs, 0);
            });
        sub_component_inputs.blake_g.iter().for_each(|inputs| {
            blake_g_state.add_packed_inputs(inputs, 0);
        });
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

/// Record the `blake_round` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_blake_round() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("blake_round", 19, Some(20));
    blake_round_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    with_n_rows 850;
    blake_g_0: 21,
    blake_g_1: 21,
    blake_g_2: 21,
    blake_g_3: 21,
    blake_g_4: 21,
    blake_g_5: 21,
    blake_g_6: 21,
    blake_g_7: 21,
    blake_round_0: 36,
    blake_round_1: 36,
    blake_round_sigma_0: 18,
    memory_address_to_id_0: 3,
    memory_address_to_id_1: 3,
    memory_address_to_id_2: 3,
    memory_address_to_id_3: 3,
    memory_address_to_id_4: 3,
    memory_address_to_id_5: 3,
    memory_address_to_id_6: 3,
    memory_address_to_id_7: 3,
    memory_address_to_id_8: 3,
    memory_address_to_id_9: 3,
    memory_address_to_id_10: 3,
    memory_address_to_id_11: 3,
    memory_address_to_id_12: 3,
    memory_address_to_id_13: 3,
    memory_address_to_id_14: 3,
    memory_address_to_id_15: 3,
    memory_id_to_big_0: 30,
    memory_id_to_big_1: 30,
    memory_id_to_big_2: 30,
    memory_id_to_big_3: 30,
    memory_id_to_big_4: 30,
    memory_id_to_big_5: 30,
    memory_id_to_big_6: 30,
    memory_id_to_big_7: 30,
    memory_id_to_big_8: 30,
    memory_id_to_big_9: 30,
    memory_id_to_big_10: 30,
    memory_id_to_big_11: 30,
    memory_id_to_big_12: 30,
    memory_id_to_big_13: 30,
    memory_id_to_big_14: 30,
    memory_id_to_big_15: 30,
    range_check_7_2_5_0: 4,
    range_check_7_2_5_1: 4,
    range_check_7_2_5_2: 4,
    range_check_7_2_5_3: 4,
    range_check_7_2_5_4: 4,
    range_check_7_2_5_5: 4,
    range_check_7_2_5_6: 4,
    range_check_7_2_5_7: 4,
    range_check_7_2_5_8: 4,
    range_check_7_2_5_9: 4,
    range_check_7_2_5_10: 4,
    range_check_7_2_5_11: 4,
    range_check_7_2_5_12: 4,
    range_check_7_2_5_13: 4,
    range_check_7_2_5_14: 4,
    range_check_7_2_5_15: 4,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("blake_round_sigma", 0, "blake_round_sigma_state", 0, 0, 1),
    ("range_check_7_2_5", 0, "range_check_7_2_5_state", 0, 1, 3),
    ("range_check_7_2_5", 1, "range_check_7_2_5_state", 0, 4, 3),
    ("range_check_7_2_5", 2, "range_check_7_2_5_state", 0, 7, 3),
    ("range_check_7_2_5", 3, "range_check_7_2_5_state", 0, 10, 3),
    ("range_check_7_2_5", 4, "range_check_7_2_5_state", 0, 13, 3),
    ("range_check_7_2_5", 5, "range_check_7_2_5_state", 0, 16, 3),
    ("range_check_7_2_5", 6, "range_check_7_2_5_state", 0, 19, 3),
    ("range_check_7_2_5", 7, "range_check_7_2_5_state", 0, 22, 3),
    ("range_check_7_2_5", 8, "range_check_7_2_5_state", 0, 25, 3),
    ("range_check_7_2_5", 9, "range_check_7_2_5_state", 0, 28, 3),
    ("range_check_7_2_5", 10, "range_check_7_2_5_state", 0, 31, 3),
    ("range_check_7_2_5", 11, "range_check_7_2_5_state", 0, 34, 3),
    ("range_check_7_2_5", 12, "range_check_7_2_5_state", 0, 37, 3),
    ("range_check_7_2_5", 13, "range_check_7_2_5_state", 0, 40, 3),
    ("range_check_7_2_5", 14, "range_check_7_2_5_state", 0, 43, 3),
    ("range_check_7_2_5", 15, "range_check_7_2_5_state", 0, 46, 3),
    (
        "memory_address_to_id",
        0,
        "memory_address_to_id_state",
        0,
        49,
        1,
    ),
    (
        "memory_address_to_id",
        1,
        "memory_address_to_id_state",
        0,
        50,
        1,
    ),
    (
        "memory_address_to_id",
        2,
        "memory_address_to_id_state",
        0,
        51,
        1,
    ),
    (
        "memory_address_to_id",
        3,
        "memory_address_to_id_state",
        0,
        52,
        1,
    ),
    (
        "memory_address_to_id",
        4,
        "memory_address_to_id_state",
        0,
        53,
        1,
    ),
    (
        "memory_address_to_id",
        5,
        "memory_address_to_id_state",
        0,
        54,
        1,
    ),
    (
        "memory_address_to_id",
        6,
        "memory_address_to_id_state",
        0,
        55,
        1,
    ),
    (
        "memory_address_to_id",
        7,
        "memory_address_to_id_state",
        0,
        56,
        1,
    ),
    (
        "memory_address_to_id",
        8,
        "memory_address_to_id_state",
        0,
        57,
        1,
    ),
    (
        "memory_address_to_id",
        9,
        "memory_address_to_id_state",
        0,
        58,
        1,
    ),
    (
        "memory_address_to_id",
        10,
        "memory_address_to_id_state",
        0,
        59,
        1,
    ),
    (
        "memory_address_to_id",
        11,
        "memory_address_to_id_state",
        0,
        60,
        1,
    ),
    (
        "memory_address_to_id",
        12,
        "memory_address_to_id_state",
        0,
        61,
        1,
    ),
    (
        "memory_address_to_id",
        13,
        "memory_address_to_id_state",
        0,
        62,
        1,
    ),
    (
        "memory_address_to_id",
        14,
        "memory_address_to_id_state",
        0,
        63,
        1,
    ),
    (
        "memory_address_to_id",
        15,
        "memory_address_to_id_state",
        0,
        64,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 65, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 66, 1),
    ("memory_id_to_big", 2, "memory_id_to_big_state", 0, 67, 1),
    ("memory_id_to_big", 3, "memory_id_to_big_state", 0, 68, 1),
    ("memory_id_to_big", 4, "memory_id_to_big_state", 0, 69, 1),
    ("memory_id_to_big", 5, "memory_id_to_big_state", 0, 70, 1),
    ("memory_id_to_big", 6, "memory_id_to_big_state", 0, 71, 1),
    ("memory_id_to_big", 7, "memory_id_to_big_state", 0, 72, 1),
    ("memory_id_to_big", 8, "memory_id_to_big_state", 0, 73, 1),
    ("memory_id_to_big", 9, "memory_id_to_big_state", 0, 74, 1),
    ("memory_id_to_big", 10, "memory_id_to_big_state", 0, 75, 1),
    ("memory_id_to_big", 11, "memory_id_to_big_state", 0, 76, 1),
    ("memory_id_to_big", 12, "memory_id_to_big_state", 0, 77, 1),
    ("memory_id_to_big", 13, "memory_id_to_big_state", 0, 78, 1),
    ("memory_id_to_big", 14, "memory_id_to_big_state", 0, 79, 1),
    ("memory_id_to_big", 15, "memory_id_to_big_state", 0, 80, 1),
    ("blake_g", 0, "blake_g_state", 0, 81, 6),
    ("blake_g", 1, "blake_g_state", 0, 87, 6),
    ("blake_g", 2, "blake_g_state", 0, 93, 6),
    ("blake_g", 3, "blake_g_state", 0, 99, 6),
    ("blake_g", 4, "blake_g_state", 0, 105, 6),
    ("blake_g", 5, "blake_g_state", 0, 111, 6),
    ("blake_g", 6, "blake_g_state", 0, 117, 6),
    ("blake_g", 7, "blake_g_state", 0, 123, 6),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "blake_round_sigma_0",
        "1",
        false,
        "range_check_7_2_5_0",
        "1",
        false,
    ),
    (
        "memory_address_to_id_0",
        "1",
        false,
        "memory_id_to_big_0",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_1",
        "1",
        false,
        "memory_address_to_id_1",
        "1",
        false,
    ),
    (
        "memory_id_to_big_1",
        "1",
        false,
        "range_check_7_2_5_2",
        "1",
        false,
    ),
    (
        "memory_address_to_id_2",
        "1",
        false,
        "memory_id_to_big_2",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_3",
        "1",
        false,
        "memory_address_to_id_3",
        "1",
        false,
    ),
    (
        "memory_id_to_big_3",
        "1",
        false,
        "range_check_7_2_5_4",
        "1",
        false,
    ),
    (
        "memory_address_to_id_4",
        "1",
        false,
        "memory_id_to_big_4",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_5",
        "1",
        false,
        "memory_address_to_id_5",
        "1",
        false,
    ),
    (
        "memory_id_to_big_5",
        "1",
        false,
        "range_check_7_2_5_6",
        "1",
        false,
    ),
    (
        "memory_address_to_id_6",
        "1",
        false,
        "memory_id_to_big_6",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_7",
        "1",
        false,
        "memory_address_to_id_7",
        "1",
        false,
    ),
    (
        "memory_id_to_big_7",
        "1",
        false,
        "range_check_7_2_5_8",
        "1",
        false,
    ),
    (
        "memory_address_to_id_8",
        "1",
        false,
        "memory_id_to_big_8",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_9",
        "1",
        false,
        "memory_address_to_id_9",
        "1",
        false,
    ),
    (
        "memory_id_to_big_9",
        "1",
        false,
        "range_check_7_2_5_10",
        "1",
        false,
    ),
    (
        "memory_address_to_id_10",
        "1",
        false,
        "memory_id_to_big_10",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_11",
        "1",
        false,
        "memory_address_to_id_11",
        "1",
        false,
    ),
    (
        "memory_id_to_big_11",
        "1",
        false,
        "range_check_7_2_5_12",
        "1",
        false,
    ),
    (
        "memory_address_to_id_12",
        "1",
        false,
        "memory_id_to_big_12",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_13",
        "1",
        false,
        "memory_address_to_id_13",
        "1",
        false,
    ),
    (
        "memory_id_to_big_13",
        "1",
        false,
        "range_check_7_2_5_14",
        "1",
        false,
    ),
    (
        "memory_address_to_id_14",
        "1",
        false,
        "memory_id_to_big_14",
        "1",
        false,
    ),
    (
        "range_check_7_2_5_15",
        "1",
        false,
        "memory_address_to_id_15",
        "1",
        false,
    ),
    ("memory_id_to_big_15", "1", false, "blake_g_0", "1", false),
    ("blake_g_1", "1", false, "blake_g_2", "1", false),
    ("blake_g_3", "1", false, "blake_g_4", "1", false),
    ("blake_g_5", "1", false, "blake_g_6", "1", false),
    ("blake_g_7", "1", false, "blake_round_0", "enabler", false),
    ("blake_round_1", "enabler", true, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.blake_g_0.iter().flatten().copied().collect(),
        ld.blake_g_1.iter().flatten().copied().collect(),
        ld.blake_g_2.iter().flatten().copied().collect(),
        ld.blake_g_3.iter().flatten().copied().collect(),
        ld.blake_g_4.iter().flatten().copied().collect(),
        ld.blake_g_5.iter().flatten().copied().collect(),
        ld.blake_g_6.iter().flatten().copied().collect(),
        ld.blake_g_7.iter().flatten().copied().collect(),
        ld.blake_round_0.iter().flatten().copied().collect(),
        ld.blake_round_1.iter().flatten().copied().collect(),
        ld.blake_round_sigma_0.iter().flatten().copied().collect(),
        ld.memory_address_to_id_0
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_1
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_2
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_3
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_6
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_7
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_8
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_9
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_10
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_11
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_12
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_13
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_14
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_15
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_0.iter().flatten().copied().collect(),
        ld.memory_id_to_big_1.iter().flatten().copied().collect(),
        ld.memory_id_to_big_2.iter().flatten().copied().collect(),
        ld.memory_id_to_big_3.iter().flatten().copied().collect(),
        ld.memory_id_to_big_4.iter().flatten().copied().collect(),
        ld.memory_id_to_big_5.iter().flatten().copied().collect(),
        ld.memory_id_to_big_6.iter().flatten().copied().collect(),
        ld.memory_id_to_big_7.iter().flatten().copied().collect(),
        ld.memory_id_to_big_8.iter().flatten().copied().collect(),
        ld.memory_id_to_big_9.iter().flatten().copied().collect(),
        ld.memory_id_to_big_10.iter().flatten().copied().collect(),
        ld.memory_id_to_big_11.iter().flatten().copied().collect(),
        ld.memory_id_to_big_12.iter().flatten().copied().collect(),
        ld.memory_id_to_big_13.iter().flatten().copied().collect(),
        ld.memory_id_to_big_14.iter().flatten().copied().collect(),
        ld.memory_id_to_big_15.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_0.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_1.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_2.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_3.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_4.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_5.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_6.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_7.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_8.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_9.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_10.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_11.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_12.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_13.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_14.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_15.iter().flatten().copied().collect(),
    ]
}

#[cfg(test)]
pub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator) -> Vec<Vec<PackedM31>> {
    lookup_data_flat(&ig.lookup_data)
}

fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
    vec![
        sci.blake_round_sigma[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[8]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[9]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[10]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[11]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[12]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[13]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[14]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[15]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[1]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[2]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[3]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[4]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[5]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[6]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[7]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[8]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[9]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[10]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[11]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[12]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[13]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[14]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[15]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[1]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[2]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[3]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[4]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[5]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[6]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[7]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[8]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[9]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[10]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[11]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[12]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[13]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[14]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[15]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.blake_g[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[6]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_g[7]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].simd, t[1].simd, t[2].simd, t[3].simd, t[4].simd, t[5].simd,
                ]
            })
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
    blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    blake_g_state: &blake_g::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        blake_round_sigma_state,
        memory_address_to_id_state,
        memory_id_to_big_state,
        range_check_7_2_5_state,
        blake_g_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        blake_round_sigma_state,
        memory_address_to_id_state,
        memory_id_to_big_state,
        range_check_7_2_5_state,
        blake_g_state,
    );
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
    blake_g_0: Vec<[PackedM31; 21]>,
    blake_g_1: Vec<[PackedM31; 21]>,
    blake_g_2: Vec<[PackedM31; 21]>,
    blake_g_3: Vec<[PackedM31; 21]>,
    blake_g_4: Vec<[PackedM31; 21]>,
    blake_g_5: Vec<[PackedM31; 21]>,
    blake_g_6: Vec<[PackedM31; 21]>,
    blake_g_7: Vec<[PackedM31; 21]>,
    blake_round_0: Vec<[PackedM31; 36]>,
    blake_round_1: Vec<[PackedM31; 36]>,
    blake_round_sigma_0: Vec<[PackedM31; 18]>,
    memory_address_to_id_0: Vec<[PackedM31; 3]>,
    memory_address_to_id_1: Vec<[PackedM31; 3]>,
    memory_address_to_id_2: Vec<[PackedM31; 3]>,
    memory_address_to_id_3: Vec<[PackedM31; 3]>,
    memory_address_to_id_4: Vec<[PackedM31; 3]>,
    memory_address_to_id_5: Vec<[PackedM31; 3]>,
    memory_address_to_id_6: Vec<[PackedM31; 3]>,
    memory_address_to_id_7: Vec<[PackedM31; 3]>,
    memory_address_to_id_8: Vec<[PackedM31; 3]>,
    memory_address_to_id_9: Vec<[PackedM31; 3]>,
    memory_address_to_id_10: Vec<[PackedM31; 3]>,
    memory_address_to_id_11: Vec<[PackedM31; 3]>,
    memory_address_to_id_12: Vec<[PackedM31; 3]>,
    memory_address_to_id_13: Vec<[PackedM31; 3]>,
    memory_address_to_id_14: Vec<[PackedM31; 3]>,
    memory_address_to_id_15: Vec<[PackedM31; 3]>,
    memory_id_to_big_0: Vec<[PackedM31; 30]>,
    memory_id_to_big_1: Vec<[PackedM31; 30]>,
    memory_id_to_big_2: Vec<[PackedM31; 30]>,
    memory_id_to_big_3: Vec<[PackedM31; 30]>,
    memory_id_to_big_4: Vec<[PackedM31; 30]>,
    memory_id_to_big_5: Vec<[PackedM31; 30]>,
    memory_id_to_big_6: Vec<[PackedM31; 30]>,
    memory_id_to_big_7: Vec<[PackedM31; 30]>,
    memory_id_to_big_8: Vec<[PackedM31; 30]>,
    memory_id_to_big_9: Vec<[PackedM31; 30]>,
    memory_id_to_big_10: Vec<[PackedM31; 30]>,
    memory_id_to_big_11: Vec<[PackedM31; 30]>,
    memory_id_to_big_12: Vec<[PackedM31; 30]>,
    memory_id_to_big_13: Vec<[PackedM31; 30]>,
    memory_id_to_big_14: Vec<[PackedM31; 30]>,
    memory_id_to_big_15: Vec<[PackedM31; 30]>,
    range_check_7_2_5_0: Vec<[PackedM31; 4]>,
    range_check_7_2_5_1: Vec<[PackedM31; 4]>,
    range_check_7_2_5_2: Vec<[PackedM31; 4]>,
    range_check_7_2_5_3: Vec<[PackedM31; 4]>,
    range_check_7_2_5_4: Vec<[PackedM31; 4]>,
    range_check_7_2_5_5: Vec<[PackedM31; 4]>,
    range_check_7_2_5_6: Vec<[PackedM31; 4]>,
    range_check_7_2_5_7: Vec<[PackedM31; 4]>,
    range_check_7_2_5_8: Vec<[PackedM31; 4]>,
    range_check_7_2_5_9: Vec<[PackedM31; 4]>,
    range_check_7_2_5_10: Vec<[PackedM31; 4]>,
    range_check_7_2_5_11: Vec<[PackedM31; 4]>,
    range_check_7_2_5_12: Vec<[PackedM31; 4]>,
    range_check_7_2_5_13: Vec<[PackedM31; 4]>,
    range_check_7_2_5_14: Vec<[PackedM31; 4]>,
    range_check_7_2_5_15: Vec<[PackedM31; 4]>,
}

pub struct InteractionClaimGenerator {
    n_rows: usize,
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    blake_g_0: 21,
    blake_g_1: 21,
    blake_g_2: 21,
    blake_g_3: 21,
    blake_g_4: 21,
    blake_g_5: 21,
    blake_g_6: 21,
    blake_g_7: 21,
    blake_round_0: 36,
    blake_round_1: 36,
    blake_round_sigma_0: 18,
    memory_address_to_id_0: 3,
    memory_address_to_id_1: 3,
    memory_address_to_id_2: 3,
    memory_address_to_id_3: 3,
    memory_address_to_id_4: 3,
    memory_address_to_id_5: 3,
    memory_address_to_id_6: 3,
    memory_address_to_id_7: 3,
    memory_address_to_id_8: 3,
    memory_address_to_id_9: 3,
    memory_address_to_id_10: 3,
    memory_address_to_id_11: 3,
    memory_address_to_id_12: 3,
    memory_address_to_id_13: 3,
    memory_address_to_id_14: 3,
    memory_address_to_id_15: 3,
    memory_id_to_big_0: 30,
    memory_id_to_big_1: 30,
    memory_id_to_big_2: 30,
    memory_id_to_big_3: 30,
    memory_id_to_big_4: 30,
    memory_id_to_big_5: 30,
    memory_id_to_big_6: 30,
    memory_id_to_big_7: 30,
    memory_id_to_big_8: 30,
    memory_id_to_big_9: 30,
    memory_id_to_big_10: 30,
    memory_id_to_big_11: 30,
    memory_id_to_big_12: 30,
    memory_id_to_big_13: 30,
    memory_id_to_big_14: 30,
    memory_id_to_big_15: 30,
    range_check_7_2_5_0: 4,
    range_check_7_2_5_1: 4,
    range_check_7_2_5_2: 4,
    range_check_7_2_5_3: 4,
    range_check_7_2_5_4: 4,
    range_check_7_2_5_5: 4,
    range_check_7_2_5_6: 4,
    range_check_7_2_5_7: 4,
    range_check_7_2_5_8: 4,
    range_check_7_2_5_9: 4,
    range_check_7_2_5_10: 4,
    range_check_7_2_5_11: 4,
    range_check_7_2_5_12: 4,
    range_check_7_2_5_13: 4,
    range_check_7_2_5_14: 4,
    range_check_7_2_5_15: 4,
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
            &self.lookup_data.blake_round_sigma_0,
            &self.lookup_data.range_check_7_2_5_0,
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
            &self.lookup_data.memory_address_to_id_0,
            &self.lookup_data.memory_id_to_big_0,
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
            &self.lookup_data.range_check_7_2_5_1,
            &self.lookup_data.memory_address_to_id_1,
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
            &self.lookup_data.memory_id_to_big_1,
            &self.lookup_data.range_check_7_2_5_2,
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
            &self.lookup_data.memory_address_to_id_2,
            &self.lookup_data.memory_id_to_big_2,
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
            &self.lookup_data.range_check_7_2_5_3,
            &self.lookup_data.memory_address_to_id_3,
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
            &self.lookup_data.memory_id_to_big_3,
            &self.lookup_data.range_check_7_2_5_4,
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
            &self.lookup_data.memory_address_to_id_4,
            &self.lookup_data.memory_id_to_big_4,
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
            &self.lookup_data.range_check_7_2_5_5,
            &self.lookup_data.memory_address_to_id_5,
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
            &self.lookup_data.memory_id_to_big_5,
            &self.lookup_data.range_check_7_2_5_6,
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
            &self.lookup_data.memory_address_to_id_6,
            &self.lookup_data.memory_id_to_big_6,
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
            &self.lookup_data.range_check_7_2_5_7,
            &self.lookup_data.memory_address_to_id_7,
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
            &self.lookup_data.memory_id_to_big_7,
            &self.lookup_data.range_check_7_2_5_8,
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
            &self.lookup_data.memory_address_to_id_8,
            &self.lookup_data.memory_id_to_big_8,
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
            &self.lookup_data.range_check_7_2_5_9,
            &self.lookup_data.memory_address_to_id_9,
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
            &self.lookup_data.memory_id_to_big_9,
            &self.lookup_data.range_check_7_2_5_10,
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
            &self.lookup_data.memory_address_to_id_10,
            &self.lookup_data.memory_id_to_big_10,
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
            &self.lookup_data.range_check_7_2_5_11,
            &self.lookup_data.memory_address_to_id_11,
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
            &self.lookup_data.memory_id_to_big_11,
            &self.lookup_data.range_check_7_2_5_12,
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
            &self.lookup_data.memory_address_to_id_12,
            &self.lookup_data.memory_id_to_big_12,
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
            &self.lookup_data.range_check_7_2_5_13,
            &self.lookup_data.memory_address_to_id_13,
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
            &self.lookup_data.memory_id_to_big_13,
            &self.lookup_data.range_check_7_2_5_14,
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
            &self.lookup_data.memory_address_to_id_14,
            &self.lookup_data.memory_id_to_big_14,
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
            &self.lookup_data.range_check_7_2_5_15,
            &self.lookup_data.memory_address_to_id_15,
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
            &self.lookup_data.memory_id_to_big_15,
            &self.lookup_data.blake_g_0,
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
            &self.lookup_data.blake_g_1,
            &self.lookup_data.blake_g_2,
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
            &self.lookup_data.blake_g_3,
            &self.lookup_data.blake_g_4,
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
            &self.lookup_data.blake_g_5,
            &self.lookup_data.blake_g_6,
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
            &self.lookup_data.blake_g_7,
            &self.lookup_data.blake_round_0,
        )
            .into_par_iter()
            .enumerate()
            .for_each(|(i, (writer, values0, values1))| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * enabler_col.packed_at(i) + denom1, denom0 * denom1);
            });
        col_gen.finalize_col();

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (col_gen.par_iter_mut(), &self.lookup_data.blake_round_1)
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

// ---- Witness-JIT prove-lane accessors (builtin slot layout; consumed by
// ---- `jit_builtin_prove_backend.rs`; parity-fenced in `differential_test.rs`) ------

/// Feed the decoded sub-inputs into the downstream states — the same entry
/// points, per-relation order (sigma → rc725 ×16 → addr ×16 → mem_big ×16 →
/// blake_g ×8), and full padded extent as the host writer's drain loops. Word
/// layout per instance follows the `SubComponentInputs` declaration; blake_g
/// inputs travel as RAW u32 lanes (message words exceed the M31 modulus).
pub(crate) fn feed_sub_inputs_from_flat(
    words: &[u32],
    n_rows: usize,
    blake_round_sigma_state: &blake_round_sigma::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    blake_g_state: &blake_g::ClaimGenerator,
    skip: &[&str],
) {
    use crate::witness::utils::AddInputs;
    const N_SUB: usize = 1 + 16 * 3 + 16 + 16 + 8 * 6;
    assert_eq!(words.len(), N_SUB * n_rows, "sub layout drift");
    let n_vec = n_rows / N_LANES;
    let m31 = |word: usize, vi: usize| {
        PackedM31::from_array(std::array::from_fn(|l| {
            M31::from_u32_unchecked(words[word * n_rows + vi * N_LANES + l])
        }))
    };
    let raw_u32 = |word: usize, vi: usize| PackedUInt32 {
        simd: std::simd::Simd::from_array(std::array::from_fn(|l| {
            words[word * n_rows + vi * N_LANES + l]
        })),
    };
    if !skip.contains(&"blake_round_sigma_state") {
        let col: Vec<blake_round_sigma::PackedInputType> =
            (0..n_vec).map(|vi| [m31(0, vi)]).collect();
        blake_round_sigma_state.add_packed_inputs(&col, 0);
    }
    if !skip.contains(&"range_check_7_2_5_state") {
        for j in 0..16 {
            let base = 1 + j * 3;
            let col: Vec<range_check_7_2_5::PackedInputType> = (0..n_vec)
                .map(|vi| std::array::from_fn(|i| m31(base + i, vi)))
                .collect();
            range_check_7_2_5_state.add_packed_inputs(&col, 0);
        }
    }
    if !skip.contains(&"memory_address_to_id_state") {
        for j in 0..16 {
            let col: Vec<memory_address_to_id::PackedInputType> =
                (0..n_vec).map(|vi| m31(49 + j, vi)).collect();
            memory_address_to_id_state.add_packed_inputs(&col, 0);
        }
    }
    if !skip.contains(&"memory_id_to_big_state") {
        for j in 0..16 {
            let col: Vec<memory_id_to_big::PackedInputType> =
                (0..n_vec).map(|vi| m31(65 + j, vi)).collect();
            memory_id_to_big_state.add_packed_inputs(&col, 0);
        }
    }
    if !skip.contains(&"blake_g_state") {
        feed_blake_g_inputs_from_flat(words, n_rows, blake_g_state);
    }
}

/// Feed the 8 blake_g input instances from blake_round's word-major sub flat
/// (base 81, 6 raw u32 words each) — the host side of the blake_round->blake_g
/// edge, also the consumer's CPU rebuild path when the device edge fails.
pub(crate) fn feed_blake_g_inputs_from_flat(
    words: &[u32],
    n_rows: usize,
    blake_g_state: &blake_g::ClaimGenerator,
) {
    use crate::witness::utils::AddInputs;
    let n_vec = n_rows / N_LANES;
    let raw_u32 = |word: usize, vi: usize| PackedUInt32 {
        simd: std::simd::Simd::from_array(std::array::from_fn(|l| {
            words[word * n_rows + vi * N_LANES + l]
        })),
    };
    for j in 0..8 {
        let base = 81 + j * 6;
        let col: Vec<blake_g::PackedInputType> = (0..n_vec)
            .map(|vi| std::array::from_fn(|i| raw_u32(base + i, vi)))
            .collect();
        blake_g_state.add_packed_inputs(&col, 0);
    }
}
