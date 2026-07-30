// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::poseidon_aggregator::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    cube_252, memory_id_to_big, poseidon_3_partial_rounds_chain, poseidon_full_round_chain,
    range_check_252_width_27, range_check_3_3_3_3_3, range_check_4_4, range_check_4_4_4_4,
};
use crate::witness::prelude::*;

pub type InputType = ([M31; 3], [M31; 3]);
pub type PackedInputType = ([PackedM31; 3], [PackedM31; 3]);

#[derive(Default)]
pub struct ClaimGenerator {
    pub mults: DashMap<InputType, AtomicU32>,
}

impl ClaimGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_trace(
        self,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        poseidon_full_round_chain_state: &poseidon_full_round_chain::ClaimGenerator,
        range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
        cube_252_state: &cube_252::ClaimGenerator,
        range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
        range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
        range_check_4_4_state: &range_check_4_4::ClaimGenerator,
        poseidon_3_partial_rounds_chain_state: &poseidon_3_partial_rounds_chain::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut inputs_mults = self
            .mults
            .iter()
            .map(|entry| (*entry.key(), M31(entry.value().load(Ordering::Relaxed))))
            .collect::<Vec<_>>();

        inputs_mults.sort_by_key(|(input, _)| input.0);

        let (mut inputs, mut mults) = inputs_mults.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();

        let n_rows = inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();

        inputs.resize(size, *inputs.first().unwrap());
        mults.resize(size, M31::zero());

        let packed_inputs = pack_values(&inputs);
        let packed_mults = pack_values(&mults);

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            packed_inputs,
            vec![packed_mults],
            memory_id_to_big_state,
            poseidon_full_round_chain_state,
            range_check_252_width_27_state,
            cube_252_state,
            range_check_3_3_3_3_3_state,
            range_check_4_4_4_4_state,
            range_check_4_4_state,
            poseidon_3_partial_rounds_chain_state,
        );
        for inputs in sub_component_inputs.memory_id_to_big {
            add_inputs(memory_id_to_big_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_full_round_chain {
            add_inputs(
                poseidon_full_round_chain_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_252_width_27 {
            add_inputs(
                range_check_252_width_27_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_3_3_3_3_3 {
            add_inputs(
                range_check_3_3_3_3_3_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4_4_4 {
            add_inputs(
                range_check_4_4_4_4_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4 {
            add_inputs(range_check_4_4_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_3_partial_rounds_chain {
            add_inputs(
                poseidon_3_partial_rounds_chain_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }

        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                log_size,
                lookup_data,
            },
        )
    }
}

impl AddInputs for ClaimGenerator {
    type PackedInputType = PackedInputType;
    type InputType = InputType;

    fn add_packed_inputs(&self, packed_inputs: &[PackedInputType], _relation_index: usize) {
        let merged: HashMap<InputType, u32> = packed_inputs
            .par_iter()
            .flat_map(|p| p.unpack())
            .fold_with(HashMap::new(), |mut local, input| {
                *local.entry(input).or_insert(0) += 1;
                local
            })
            .reduce(HashMap::new, |mut a, b| {
                for (k, v) in b {
                    *a.entry(k).or_insert(0) += v;
                }
                a
            });

        for (k, v) in merged {
            self.mults
                .entry(k)
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(v, Ordering::Relaxed);
        }
    }
    fn add_input(&self, input: &InputType, _relation_index: usize) {
        self.mults
            .entry(*input)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Uninitialized, IterMut, ParIterMut)]
struct SubComponentInputs {
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 6],
    poseidon_full_round_chain: [Vec<poseidon_full_round_chain::PackedInputType>; 8],
    range_check_252_width_27: [Vec<range_check_252_width_27::PackedInputType>; 2],
    cube_252: [Vec<cube_252::PackedInputType>; 2],
    range_check_3_3_3_3_3: [Vec<range_check_3_3_3_3_3::PackedInputType>; 2],
    range_check_4_4_4_4: [Vec<range_check_4_4_4_4::PackedInputType>; 6],
    range_check_4_4: [Vec<range_check_4_4::PackedInputType>; 3],
    poseidon_3_partial_rounds_chain: [Vec<poseidon_3_partial_rounds_chain::PackedInputType>; 27],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    mults: Vec<Vec<PackedM31>>,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    poseidon_full_round_chain_state: &poseidon_full_round_chain::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    poseidon_3_partial_rounds_chain_state: &poseidon_3_partial_rounds_chain::ClaimGenerator,
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

    let Felt252_0_0_0_0 = PackedFelt252::broadcast(Felt252::from([0, 0, 0, 0]));
    let Felt252_1_0_0_0 = PackedFelt252::broadcast(Felt252::from([1, 0, 0, 0]));
    let Felt252_10310704347937391837_5874215448258336115_2880320859071049537_45350836576946303 =
        PackedFelt252::broadcast(Felt252::from([
            10310704347937391837,
            5874215448258336115,
            2880320859071049537,
            45350836576946303,
        ]));
    let Felt252_10931822301410252833_1475756362763989377_3378552166684303673_348229636055909092 =
        PackedFelt252::broadcast(Felt252::from([
            10931822301410252833,
            1475756362763989377,
            3378552166684303673,
            348229636055909092,
        ]));
    let Felt252_11041071929982523380_7503192613203831446_4943121247101232560_560497091765764140 =
        PackedFelt252::broadcast(Felt252::from([
            11041071929982523380,
            7503192613203831446,
            4943121247101232560,
            560497091765764140,
        ]));
    let Felt252_16477292399064058052_4441744911417641572_18431044672185975386_252894828082060025 =
        PackedFelt252::broadcast(Felt252::from([
            16477292399064058052,
            4441744911417641572,
            18431044672185975386,
            252894828082060025,
        ]));
    let Felt252_2_0_0_0 = PackedFelt252::broadcast(Felt252::from([2, 0, 0, 0]));
    let Felt252_3969818800901670911_10562874008078701503_14906396266795319764_223312371439046257 =
        PackedFelt252::broadcast(Felt252::from([
            3969818800901670911,
            10562874008078701503,
            14906396266795319764,
            223312371439046257,
        ]));
    let Felt252_4_0_0_0 = PackedFelt252::broadcast(Felt252::from([4, 0, 0, 0]));
    let Felt252_8794894655201903369_3219077422080798056_16714934791572408267_262217499501479120 =
        PackedFelt252::broadcast(Felt252::from([
            8794894655201903369,
            3219077422080798056,
            16714934791572408267,
            262217499501479120,
        ]));
    let Felt252_9275160746813554287_16541205595039575623_4169650429605064889_470088886057789987 =
        PackedFelt252::broadcast(Felt252::from([
            9275160746813554287,
            16541205595039575623,
            4169650429605064889,
            470088886057789987,
        ]));
    let M31_0 = PackedM31::broadcast(M31::from(0));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_10 = PackedM31::broadcast(M31::from(10));
    let M31_102193642 = PackedM31::broadcast(M31::from(102193642));
    let M31_1027333874 = PackedM31::broadcast(M31::from(1027333874));
    let M31_103094260 = PackedM31::broadcast(M31::from(103094260));
    let M31_108487870 = PackedM31::broadcast(M31::from(108487870));
    let M31_1090315331 = PackedM31::broadcast(M31::from(1090315331));
    let M31_11 = PackedM31::broadcast(M31::from(11));
    let M31_112479959 = PackedM31::broadcast(M31::from(112479959));
    let M31_112795138 = PackedM31::broadcast(M31::from(112795138));
    let M31_116986206 = PackedM31::broadcast(M31::from(116986206));
    let M31_117420501 = PackedM31::broadcast(M31::from(117420501));
    let M31_119023582 = PackedM31::broadcast(M31::from(119023582));
    let M31_12 = PackedM31::broadcast(M31::from(12));
    let M31_120369218 = PackedM31::broadcast(M31::from(120369218));
    let M31_121146754 = PackedM31::broadcast(M31::from(121146754));
    let M31_121657377 = PackedM31::broadcast(M31::from(121657377));
    let M31_122233508 = PackedM31::broadcast(M31::from(122233508));
    let M31_129717753 = PackedM31::broadcast(M31::from(129717753));
    let M31_13 = PackedM31::broadcast(M31::from(13));
    let M31_130418270 = PackedM31::broadcast(M31::from(130418270));
    let M31_133303902 = PackedM31::broadcast(M31::from(133303902));
    let M31_134217729 = PackedM31::broadcast(M31::from(134217729));
    let M31_1343313504 = PackedM31::broadcast(M31::from(1343313504));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_14 = PackedM31::broadcast(M31::from(14));
    let M31_1480369132 = PackedM31::broadcast(M31::from(1480369132));
    let M31_15 = PackedM31::broadcast(M31::from(15));
    let M31_1551892206 = PackedM31::broadcast(M31::from(1551892206));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_16173996 = PackedM31::broadcast(M31::from(16173996));
    let M31_1651211826 = PackedM31::broadcast(M31::from(1651211826));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_17 = PackedM31::broadcast(M31::from(17));
    let M31_18 = PackedM31::broadcast(M31::from(18));
    let M31_18765944 = PackedM31::broadcast(M31::from(18765944));
    let M31_19 = PackedM31::broadcast(M31::from(19));
    let M31_19292069 = PackedM31::broadcast(M31::from(19292069));
    let M31_1987997202 = PackedM31::broadcast(M31::from(1987997202));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_20 = PackedM31::broadcast(M31::from(20));
    let M31_21 = PackedM31::broadcast(M31::from(21));
    let M31_22 = PackedM31::broadcast(M31::from(22));
    let M31_22899501 = PackedM31::broadcast(M31::from(22899501));
    let M31_23 = PackedM31::broadcast(M31::from(23));
    let M31_24 = PackedM31::broadcast(M31::from(24));
    let M31_25 = PackedM31::broadcast(M31::from(25));
    let M31_26 = PackedM31::broadcast(M31::from(26));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_27 = PackedM31::broadcast(M31::from(27));
    let M31_28 = PackedM31::broadcast(M31::from(28));
    let M31_28820206 = PackedM31::broadcast(M31::from(28820206));
    let M31_29 = PackedM31::broadcast(M31::from(29));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_30 = PackedM31::broadcast(M31::from(30));
    let M31_31 = PackedM31::broadcast(M31::from(31));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_33 = PackedM31::broadcast(M31::from(33));
    let M31_33413160 = PackedM31::broadcast(M31::from(33413160));
    let M31_33439011 = PackedM31::broadcast(M31::from(33439011));
    let M31_34 = PackedM31::broadcast(M31::from(34));
    let M31_35 = PackedM31::broadcast(M31::from(35));
    let M31_36279186 = PackedM31::broadcast(M31::from(36279186));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_402653187 = PackedM31::broadcast(M31::from(402653187));
    let M31_40454143 = PackedM31::broadcast(M31::from(40454143));
    let M31_41224388 = PackedM31::broadcast(M31::from(41224388));
    let M31_41320857 = PackedM31::broadcast(M31::from(41320857));
    let M31_44781849 = PackedM31::broadcast(M31::from(44781849));
    let M31_44848225 = PackedM31::broadcast(M31::from(44848225));
    let M31_45351266 = PackedM31::broadcast(M31::from(45351266));
    let M31_45553283 = PackedM31::broadcast(M31::from(45553283));
    let M31_48193339 = PackedM31::broadcast(M31::from(48193339));
    let M31_48383197 = PackedM31::broadcast(M31::from(48383197));
    let M31_4883209 = PackedM31::broadcast(M31::from(4883209));
    let M31_48945103 = PackedM31::broadcast(M31::from(48945103));
    let M31_49157069 = PackedM31::broadcast(M31::from(49157069));
    let M31_49554771 = PackedM31::broadcast(M31::from(49554771));
    let M31_4974792 = PackedM31::broadcast(M31::from(4974792));
    let M31_5 = PackedM31::broadcast(M31::from(5));
    let M31_502259093 = PackedM31::broadcast(M31::from(502259093));
    let M31_50468641 = PackedM31::broadcast(M31::from(50468641));
    let M31_50758155 = PackedM31::broadcast(M31::from(50758155));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_54415179 = PackedM31::broadcast(M31::from(54415179));
    let M31_55508188 = PackedM31::broadcast(M31::from(55508188));
    let M31_55955004 = PackedM31::broadcast(M31::from(55955004));
    let M31_58475513 = PackedM31::broadcast(M31::from(58475513));
    let M31_59852719 = PackedM31::broadcast(M31::from(59852719));
    let M31_6 = PackedM31::broadcast(M31::from(6));
    let M31_60124463 = PackedM31::broadcast(M31::from(60124463));
    let M31_60709090 = PackedM31::broadcast(M31::from(60709090));
    let M31_62360091 = PackedM31::broadcast(M31::from(62360091));
    let M31_62439890 = PackedM31::broadcast(M31::from(62439890));
    let M31_65659846 = PackedM31::broadcast(M31::from(65659846));
    let M31_68491350 = PackedM31::broadcast(M31::from(68491350));
    let M31_7 = PackedM31::broadcast(M31::from(7));
    let M31_72285071 = PackedM31::broadcast(M31::from(72285071));
    let M31_74972783 = PackedM31::broadcast(M31::from(74972783));
    let M31_75104388 = PackedM31::broadcast(M31::from(75104388));
    let M31_77099918 = PackedM31::broadcast(M31::from(77099918));
    let M31_78826183 = PackedM31::broadcast(M31::from(78826183));
    let M31_79012328 = PackedM31::broadcast(M31::from(79012328));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let M31_8192 = PackedM31::broadcast(M31::from(8192));
    let M31_86573645 = PackedM31::broadcast(M31::from(86573645));
    let M31_88680813 = PackedM31::broadcast(M31::from(88680813));
    let M31_9 = PackedM31::broadcast(M31::from(9));
    let M31_90391646 = PackedM31::broadcast(M31::from(90391646));
    let M31_90842759 = PackedM31::broadcast(M31::from(90842759));
    let M31_91013252 = PackedM31::broadcast(M31::from(91013252));
    let M31_94624323 = PackedM31::broadcast(M31::from(94624323));
    let M31_95050340 = PackedM31::broadcast(M31::from(95050340));
    let seq = Seq::new(log_size);

    (trace.par_iter_mut(),
    lookup_data.par_iter_mut(),sub_component_inputs.par_iter_mut(),inputs.into_par_iter(),)
    .into_par_iter()
    .enumerate()
    .for_each(
        |(row_index,(row, lookup_data,sub_component_inputs,poseidon_aggregator_input,))| {
            let seq = seq.packed_at(row_index);let input_limb_0_col0 = poseidon_aggregator_input.0[0];
            *row[0] = input_limb_0_col0;let input_limb_1_col1 = poseidon_aggregator_input.0[1];
            *row[1] = input_limb_1_col1;let input_limb_2_col2 = poseidon_aggregator_input.0[2];
            *row[2] = input_limb_2_col2;let input_limb_3_col3 = poseidon_aggregator_input.1[0];
            *row[3] = input_limb_3_col3;let input_limb_4_col4 = poseidon_aggregator_input.1[1];
            *row[4] = input_limb_4_col4;let input_limb_5_col5 = poseidon_aggregator_input.1[2];
            *row[5] = input_limb_5_col5;

            // Read Positive Known Id Num Bits 252.

            let memory_id_to_big_value_tmp_3806f_0 = memory_id_to_big_state.deduce_output(input_limb_0_col0);let value_limb_0_col6 = memory_id_to_big_value_tmp_3806f_0.get_m31(0);
            *row[6] = value_limb_0_col6;let value_limb_1_col7 = memory_id_to_big_value_tmp_3806f_0.get_m31(1);
            *row[7] = value_limb_1_col7;let value_limb_2_col8 = memory_id_to_big_value_tmp_3806f_0.get_m31(2);
            *row[8] = value_limb_2_col8;let value_limb_3_col9 = memory_id_to_big_value_tmp_3806f_0.get_m31(3);
            *row[9] = value_limb_3_col9;let value_limb_4_col10 = memory_id_to_big_value_tmp_3806f_0.get_m31(4);
            *row[10] = value_limb_4_col10;let value_limb_5_col11 = memory_id_to_big_value_tmp_3806f_0.get_m31(5);
            *row[11] = value_limb_5_col11;let value_limb_6_col12 = memory_id_to_big_value_tmp_3806f_0.get_m31(6);
            *row[12] = value_limb_6_col12;let value_limb_7_col13 = memory_id_to_big_value_tmp_3806f_0.get_m31(7);
            *row[13] = value_limb_7_col13;let value_limb_8_col14 = memory_id_to_big_value_tmp_3806f_0.get_m31(8);
            *row[14] = value_limb_8_col14;let value_limb_9_col15 = memory_id_to_big_value_tmp_3806f_0.get_m31(9);
            *row[15] = value_limb_9_col15;let value_limb_10_col16 = memory_id_to_big_value_tmp_3806f_0.get_m31(10);
            *row[16] = value_limb_10_col16;let value_limb_11_col17 = memory_id_to_big_value_tmp_3806f_0.get_m31(11);
            *row[17] = value_limb_11_col17;let value_limb_12_col18 = memory_id_to_big_value_tmp_3806f_0.get_m31(12);
            *row[18] = value_limb_12_col18;let value_limb_13_col19 = memory_id_to_big_value_tmp_3806f_0.get_m31(13);
            *row[19] = value_limb_13_col19;let value_limb_14_col20 = memory_id_to_big_value_tmp_3806f_0.get_m31(14);
            *row[20] = value_limb_14_col20;let value_limb_15_col21 = memory_id_to_big_value_tmp_3806f_0.get_m31(15);
            *row[21] = value_limb_15_col21;let value_limb_16_col22 = memory_id_to_big_value_tmp_3806f_0.get_m31(16);
            *row[22] = value_limb_16_col22;let value_limb_17_col23 = memory_id_to_big_value_tmp_3806f_0.get_m31(17);
            *row[23] = value_limb_17_col23;let value_limb_18_col24 = memory_id_to_big_value_tmp_3806f_0.get_m31(18);
            *row[24] = value_limb_18_col24;let value_limb_19_col25 = memory_id_to_big_value_tmp_3806f_0.get_m31(19);
            *row[25] = value_limb_19_col25;let value_limb_20_col26 = memory_id_to_big_value_tmp_3806f_0.get_m31(20);
            *row[26] = value_limb_20_col26;let value_limb_21_col27 = memory_id_to_big_value_tmp_3806f_0.get_m31(21);
            *row[27] = value_limb_21_col27;let value_limb_22_col28 = memory_id_to_big_value_tmp_3806f_0.get_m31(22);
            *row[28] = value_limb_22_col28;let value_limb_23_col29 = memory_id_to_big_value_tmp_3806f_0.get_m31(23);
            *row[29] = value_limb_23_col29;let value_limb_24_col30 = memory_id_to_big_value_tmp_3806f_0.get_m31(24);
            *row[30] = value_limb_24_col30;let value_limb_25_col31 = memory_id_to_big_value_tmp_3806f_0.get_m31(25);
            *row[31] = value_limb_25_col31;let value_limb_26_col32 = memory_id_to_big_value_tmp_3806f_0.get_m31(26);
            *row[32] = value_limb_26_col32;let value_limb_27_col33 = memory_id_to_big_value_tmp_3806f_0.get_m31(27);
            *row[33] = value_limb_27_col33;*sub_component_inputs.memory_id_to_big[0] =
                input_limb_0_col0;
            *lookup_data.memory_id_to_big_0 = [M31_1662111297, input_limb_0_col0, value_limb_0_col6, value_limb_1_col7, value_limb_2_col8, value_limb_3_col9, value_limb_4_col10, value_limb_5_col11, value_limb_6_col12, value_limb_7_col13, value_limb_8_col14, value_limb_9_col15, value_limb_10_col16, value_limb_11_col17, value_limb_12_col18, value_limb_13_col19, value_limb_14_col20, value_limb_15_col21, value_limb_16_col22, value_limb_17_col23, value_limb_18_col24, value_limb_19_col25, value_limb_20_col26, value_limb_21_col27, value_limb_22_col28, value_limb_23_col29, value_limb_24_col30, value_limb_25_col31, value_limb_26_col32, value_limb_27_col33];let read_positive_known_id_num_bits_252_output_tmp_3806f_1 = PackedFelt252::from_limbs([value_limb_0_col6, value_limb_1_col7, value_limb_2_col8, value_limb_3_col9, value_limb_4_col10, value_limb_5_col11, value_limb_6_col12, value_limb_7_col13, value_limb_8_col14, value_limb_9_col15, value_limb_10_col16, value_limb_11_col17, value_limb_12_col18, value_limb_13_col19, value_limb_14_col20, value_limb_15_col21, value_limb_16_col22, value_limb_17_col23, value_limb_18_col24, value_limb_19_col25, value_limb_20_col26, value_limb_21_col27, value_limb_22_col28, value_limb_23_col29, value_limb_24_col30, value_limb_25_col31, value_limb_26_col32, value_limb_27_col33]);

            let packed_input_state_0_tmp_3806f_2 = PackedFelt252Width27::from_limbs([((((value_limb_0_col6) + (((value_limb_1_col7) * (M31_512))))) + (((value_limb_2_col8) * (M31_262144)))), ((((value_limb_3_col9) + (((value_limb_4_col10) * (M31_512))))) + (((value_limb_5_col11) * (M31_262144)))), ((((value_limb_6_col12) + (((value_limb_7_col13) * (M31_512))))) + (((value_limb_8_col14) * (M31_262144)))), ((((value_limb_9_col15) + (((value_limb_10_col16) * (M31_512))))) + (((value_limb_11_col17) * (M31_262144)))), ((((value_limb_12_col18) + (((value_limb_13_col19) * (M31_512))))) + (((value_limb_14_col20) * (M31_262144)))), ((((value_limb_15_col21) + (((value_limb_16_col22) * (M31_512))))) + (((value_limb_17_col23) * (M31_262144)))), ((((value_limb_18_col24) + (((value_limb_19_col25) * (M31_512))))) + (((value_limb_20_col26) * (M31_262144)))), ((((value_limb_21_col27) + (((value_limb_22_col28) * (M31_512))))) + (((value_limb_23_col29) * (M31_262144)))), ((((value_limb_24_col30) + (((value_limb_25_col31) * (M31_512))))) + (((value_limb_26_col32) * (M31_262144)))), value_limb_27_col33]);

            // Read Positive Known Id Num Bits 252.

            let memory_id_to_big_value_tmp_3806f_3 = memory_id_to_big_state.deduce_output(input_limb_1_col1);let value_limb_0_col34 = memory_id_to_big_value_tmp_3806f_3.get_m31(0);
            *row[34] = value_limb_0_col34;let value_limb_1_col35 = memory_id_to_big_value_tmp_3806f_3.get_m31(1);
            *row[35] = value_limb_1_col35;let value_limb_2_col36 = memory_id_to_big_value_tmp_3806f_3.get_m31(2);
            *row[36] = value_limb_2_col36;let value_limb_3_col37 = memory_id_to_big_value_tmp_3806f_3.get_m31(3);
            *row[37] = value_limb_3_col37;let value_limb_4_col38 = memory_id_to_big_value_tmp_3806f_3.get_m31(4);
            *row[38] = value_limb_4_col38;let value_limb_5_col39 = memory_id_to_big_value_tmp_3806f_3.get_m31(5);
            *row[39] = value_limb_5_col39;let value_limb_6_col40 = memory_id_to_big_value_tmp_3806f_3.get_m31(6);
            *row[40] = value_limb_6_col40;let value_limb_7_col41 = memory_id_to_big_value_tmp_3806f_3.get_m31(7);
            *row[41] = value_limb_7_col41;let value_limb_8_col42 = memory_id_to_big_value_tmp_3806f_3.get_m31(8);
            *row[42] = value_limb_8_col42;let value_limb_9_col43 = memory_id_to_big_value_tmp_3806f_3.get_m31(9);
            *row[43] = value_limb_9_col43;let value_limb_10_col44 = memory_id_to_big_value_tmp_3806f_3.get_m31(10);
            *row[44] = value_limb_10_col44;let value_limb_11_col45 = memory_id_to_big_value_tmp_3806f_3.get_m31(11);
            *row[45] = value_limb_11_col45;let value_limb_12_col46 = memory_id_to_big_value_tmp_3806f_3.get_m31(12);
            *row[46] = value_limb_12_col46;let value_limb_13_col47 = memory_id_to_big_value_tmp_3806f_3.get_m31(13);
            *row[47] = value_limb_13_col47;let value_limb_14_col48 = memory_id_to_big_value_tmp_3806f_3.get_m31(14);
            *row[48] = value_limb_14_col48;let value_limb_15_col49 = memory_id_to_big_value_tmp_3806f_3.get_m31(15);
            *row[49] = value_limb_15_col49;let value_limb_16_col50 = memory_id_to_big_value_tmp_3806f_3.get_m31(16);
            *row[50] = value_limb_16_col50;let value_limb_17_col51 = memory_id_to_big_value_tmp_3806f_3.get_m31(17);
            *row[51] = value_limb_17_col51;let value_limb_18_col52 = memory_id_to_big_value_tmp_3806f_3.get_m31(18);
            *row[52] = value_limb_18_col52;let value_limb_19_col53 = memory_id_to_big_value_tmp_3806f_3.get_m31(19);
            *row[53] = value_limb_19_col53;let value_limb_20_col54 = memory_id_to_big_value_tmp_3806f_3.get_m31(20);
            *row[54] = value_limb_20_col54;let value_limb_21_col55 = memory_id_to_big_value_tmp_3806f_3.get_m31(21);
            *row[55] = value_limb_21_col55;let value_limb_22_col56 = memory_id_to_big_value_tmp_3806f_3.get_m31(22);
            *row[56] = value_limb_22_col56;let value_limb_23_col57 = memory_id_to_big_value_tmp_3806f_3.get_m31(23);
            *row[57] = value_limb_23_col57;let value_limb_24_col58 = memory_id_to_big_value_tmp_3806f_3.get_m31(24);
            *row[58] = value_limb_24_col58;let value_limb_25_col59 = memory_id_to_big_value_tmp_3806f_3.get_m31(25);
            *row[59] = value_limb_25_col59;let value_limb_26_col60 = memory_id_to_big_value_tmp_3806f_3.get_m31(26);
            *row[60] = value_limb_26_col60;let value_limb_27_col61 = memory_id_to_big_value_tmp_3806f_3.get_m31(27);
            *row[61] = value_limb_27_col61;*sub_component_inputs.memory_id_to_big[1] =
                input_limb_1_col1;
            *lookup_data.memory_id_to_big_1 = [M31_1662111297, input_limb_1_col1, value_limb_0_col34, value_limb_1_col35, value_limb_2_col36, value_limb_3_col37, value_limb_4_col38, value_limb_5_col39, value_limb_6_col40, value_limb_7_col41, value_limb_8_col42, value_limb_9_col43, value_limb_10_col44, value_limb_11_col45, value_limb_12_col46, value_limb_13_col47, value_limb_14_col48, value_limb_15_col49, value_limb_16_col50, value_limb_17_col51, value_limb_18_col52, value_limb_19_col53, value_limb_20_col54, value_limb_21_col55, value_limb_22_col56, value_limb_23_col57, value_limb_24_col58, value_limb_25_col59, value_limb_26_col60, value_limb_27_col61];let read_positive_known_id_num_bits_252_output_tmp_3806f_4 = PackedFelt252::from_limbs([value_limb_0_col34, value_limb_1_col35, value_limb_2_col36, value_limb_3_col37, value_limb_4_col38, value_limb_5_col39, value_limb_6_col40, value_limb_7_col41, value_limb_8_col42, value_limb_9_col43, value_limb_10_col44, value_limb_11_col45, value_limb_12_col46, value_limb_13_col47, value_limb_14_col48, value_limb_15_col49, value_limb_16_col50, value_limb_17_col51, value_limb_18_col52, value_limb_19_col53, value_limb_20_col54, value_limb_21_col55, value_limb_22_col56, value_limb_23_col57, value_limb_24_col58, value_limb_25_col59, value_limb_26_col60, value_limb_27_col61]);

            let packed_input_state_1_tmp_3806f_5 = PackedFelt252Width27::from_limbs([((((value_limb_0_col34) + (((value_limb_1_col35) * (M31_512))))) + (((value_limb_2_col36) * (M31_262144)))), ((((value_limb_3_col37) + (((value_limb_4_col38) * (M31_512))))) + (((value_limb_5_col39) * (M31_262144)))), ((((value_limb_6_col40) + (((value_limb_7_col41) * (M31_512))))) + (((value_limb_8_col42) * (M31_262144)))), ((((value_limb_9_col43) + (((value_limb_10_col44) * (M31_512))))) + (((value_limb_11_col45) * (M31_262144)))), ((((value_limb_12_col46) + (((value_limb_13_col47) * (M31_512))))) + (((value_limb_14_col48) * (M31_262144)))), ((((value_limb_15_col49) + (((value_limb_16_col50) * (M31_512))))) + (((value_limb_17_col51) * (M31_262144)))), ((((value_limb_18_col52) + (((value_limb_19_col53) * (M31_512))))) + (((value_limb_20_col54) * (M31_262144)))), ((((value_limb_21_col55) + (((value_limb_22_col56) * (M31_512))))) + (((value_limb_23_col57) * (M31_262144)))), ((((value_limb_24_col58) + (((value_limb_25_col59) * (M31_512))))) + (((value_limb_26_col60) * (M31_262144)))), value_limb_27_col61]);

            // Read Positive Known Id Num Bits 252.

            let memory_id_to_big_value_tmp_3806f_6 = memory_id_to_big_state.deduce_output(input_limb_2_col2);let value_limb_0_col62 = memory_id_to_big_value_tmp_3806f_6.get_m31(0);
            *row[62] = value_limb_0_col62;let value_limb_1_col63 = memory_id_to_big_value_tmp_3806f_6.get_m31(1);
            *row[63] = value_limb_1_col63;let value_limb_2_col64 = memory_id_to_big_value_tmp_3806f_6.get_m31(2);
            *row[64] = value_limb_2_col64;let value_limb_3_col65 = memory_id_to_big_value_tmp_3806f_6.get_m31(3);
            *row[65] = value_limb_3_col65;let value_limb_4_col66 = memory_id_to_big_value_tmp_3806f_6.get_m31(4);
            *row[66] = value_limb_4_col66;let value_limb_5_col67 = memory_id_to_big_value_tmp_3806f_6.get_m31(5);
            *row[67] = value_limb_5_col67;let value_limb_6_col68 = memory_id_to_big_value_tmp_3806f_6.get_m31(6);
            *row[68] = value_limb_6_col68;let value_limb_7_col69 = memory_id_to_big_value_tmp_3806f_6.get_m31(7);
            *row[69] = value_limb_7_col69;let value_limb_8_col70 = memory_id_to_big_value_tmp_3806f_6.get_m31(8);
            *row[70] = value_limb_8_col70;let value_limb_9_col71 = memory_id_to_big_value_tmp_3806f_6.get_m31(9);
            *row[71] = value_limb_9_col71;let value_limb_10_col72 = memory_id_to_big_value_tmp_3806f_6.get_m31(10);
            *row[72] = value_limb_10_col72;let value_limb_11_col73 = memory_id_to_big_value_tmp_3806f_6.get_m31(11);
            *row[73] = value_limb_11_col73;let value_limb_12_col74 = memory_id_to_big_value_tmp_3806f_6.get_m31(12);
            *row[74] = value_limb_12_col74;let value_limb_13_col75 = memory_id_to_big_value_tmp_3806f_6.get_m31(13);
            *row[75] = value_limb_13_col75;let value_limb_14_col76 = memory_id_to_big_value_tmp_3806f_6.get_m31(14);
            *row[76] = value_limb_14_col76;let value_limb_15_col77 = memory_id_to_big_value_tmp_3806f_6.get_m31(15);
            *row[77] = value_limb_15_col77;let value_limb_16_col78 = memory_id_to_big_value_tmp_3806f_6.get_m31(16);
            *row[78] = value_limb_16_col78;let value_limb_17_col79 = memory_id_to_big_value_tmp_3806f_6.get_m31(17);
            *row[79] = value_limb_17_col79;let value_limb_18_col80 = memory_id_to_big_value_tmp_3806f_6.get_m31(18);
            *row[80] = value_limb_18_col80;let value_limb_19_col81 = memory_id_to_big_value_tmp_3806f_6.get_m31(19);
            *row[81] = value_limb_19_col81;let value_limb_20_col82 = memory_id_to_big_value_tmp_3806f_6.get_m31(20);
            *row[82] = value_limb_20_col82;let value_limb_21_col83 = memory_id_to_big_value_tmp_3806f_6.get_m31(21);
            *row[83] = value_limb_21_col83;let value_limb_22_col84 = memory_id_to_big_value_tmp_3806f_6.get_m31(22);
            *row[84] = value_limb_22_col84;let value_limb_23_col85 = memory_id_to_big_value_tmp_3806f_6.get_m31(23);
            *row[85] = value_limb_23_col85;let value_limb_24_col86 = memory_id_to_big_value_tmp_3806f_6.get_m31(24);
            *row[86] = value_limb_24_col86;let value_limb_25_col87 = memory_id_to_big_value_tmp_3806f_6.get_m31(25);
            *row[87] = value_limb_25_col87;let value_limb_26_col88 = memory_id_to_big_value_tmp_3806f_6.get_m31(26);
            *row[88] = value_limb_26_col88;let value_limb_27_col89 = memory_id_to_big_value_tmp_3806f_6.get_m31(27);
            *row[89] = value_limb_27_col89;*sub_component_inputs.memory_id_to_big[2] =
                input_limb_2_col2;
            *lookup_data.memory_id_to_big_2 = [M31_1662111297, input_limb_2_col2, value_limb_0_col62, value_limb_1_col63, value_limb_2_col64, value_limb_3_col65, value_limb_4_col66, value_limb_5_col67, value_limb_6_col68, value_limb_7_col69, value_limb_8_col70, value_limb_9_col71, value_limb_10_col72, value_limb_11_col73, value_limb_12_col74, value_limb_13_col75, value_limb_14_col76, value_limb_15_col77, value_limb_16_col78, value_limb_17_col79, value_limb_18_col80, value_limb_19_col81, value_limb_20_col82, value_limb_21_col83, value_limb_22_col84, value_limb_23_col85, value_limb_24_col86, value_limb_25_col87, value_limb_26_col88, value_limb_27_col89];let read_positive_known_id_num_bits_252_output_tmp_3806f_7 = PackedFelt252::from_limbs([value_limb_0_col62, value_limb_1_col63, value_limb_2_col64, value_limb_3_col65, value_limb_4_col66, value_limb_5_col67, value_limb_6_col68, value_limb_7_col69, value_limb_8_col70, value_limb_9_col71, value_limb_10_col72, value_limb_11_col73, value_limb_12_col74, value_limb_13_col75, value_limb_14_col76, value_limb_15_col77, value_limb_16_col78, value_limb_17_col79, value_limb_18_col80, value_limb_19_col81, value_limb_20_col82, value_limb_21_col83, value_limb_22_col84, value_limb_23_col85, value_limb_24_col86, value_limb_25_col87, value_limb_26_col88, value_limb_27_col89]);

            let packed_input_state_2_tmp_3806f_8 = PackedFelt252Width27::from_limbs([((((value_limb_0_col62) + (((value_limb_1_col63) * (M31_512))))) + (((value_limb_2_col64) * (M31_262144)))), ((((value_limb_3_col65) + (((value_limb_4_col66) * (M31_512))))) + (((value_limb_5_col67) * (M31_262144)))), ((((value_limb_6_col68) + (((value_limb_7_col69) * (M31_512))))) + (((value_limb_8_col70) * (M31_262144)))), ((((value_limb_9_col71) + (((value_limb_10_col72) * (M31_512))))) + (((value_limb_11_col73) * (M31_262144)))), ((((value_limb_12_col74) + (((value_limb_13_col75) * (M31_512))))) + (((value_limb_14_col76) * (M31_262144)))), ((((value_limb_15_col77) + (((value_limb_16_col78) * (M31_512))))) + (((value_limb_17_col79) * (M31_262144)))), ((((value_limb_18_col80) + (((value_limb_19_col81) * (M31_512))))) + (((value_limb_20_col82) * (M31_262144)))), ((((value_limb_21_col83) + (((value_limb_22_col84) * (M31_512))))) + (((value_limb_23_col85) * (M31_262144)))), ((((value_limb_24_col86) + (((value_limb_25_col87) * (M31_512))))) + (((value_limb_26_col88) * (M31_262144)))), value_limb_27_col89]);

            // Poseidon Hades Permutation.

            // Linear Combination N 2 Coefs 1 1.

            let combination_tmp_3806f_9 = PackedFelt252Width27::from_packed_felt252(((((Felt252_0_0_0_0) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(packed_input_state_0_tmp_3806f_2)))))) + (Felt252_9275160746813554287_16541205595039575623_4169650429605064889_470088886057789987)));let combination_limb_0_col90 = combination_tmp_3806f_9.get_m31(0);
            *row[90] = combination_limb_0_col90;let combination_limb_1_col91 = combination_tmp_3806f_9.get_m31(1);
            *row[91] = combination_limb_1_col91;let combination_limb_2_col92 = combination_tmp_3806f_9.get_m31(2);
            *row[92] = combination_limb_2_col92;let combination_limb_3_col93 = combination_tmp_3806f_9.get_m31(3);
            *row[93] = combination_limb_3_col93;let combination_limb_4_col94 = combination_tmp_3806f_9.get_m31(4);
            *row[94] = combination_limb_4_col94;let combination_limb_5_col95 = combination_tmp_3806f_9.get_m31(5);
            *row[95] = combination_limb_5_col95;let combination_limb_6_col96 = combination_tmp_3806f_9.get_m31(6);
            *row[96] = combination_limb_6_col96;let combination_limb_7_col97 = combination_tmp_3806f_9.get_m31(7);
            *row[97] = combination_limb_7_col97;let combination_limb_8_col98 = combination_tmp_3806f_9.get_m31(8);
            *row[98] = combination_limb_8_col98;let combination_limb_9_col99 = combination_tmp_3806f_9.get_m31(9);
            *row[99] = combination_limb_9_col99;let biased_limb_accumulator_u32_tmp_3806f_10 = PackedUInt32::from_m31(((((((packed_input_state_0_tmp_3806f_2.get_m31(0)) + (M31_74972783))) - (combination_limb_0_col90))) + (M31_134217729)));let p_coef_col100 = ((biased_limb_accumulator_u32_tmp_3806f_10.low().as_m31()) - (M31_1));
            *row[100] = p_coef_col100;let carry_0_tmp_3806f_11 = ((((((((packed_input_state_0_tmp_3806f_2.get_m31(0)) + (M31_74972783))) - (combination_limb_0_col90))) - (p_coef_col100))) * (M31_16));let carry_1_tmp_3806f_12 = ((((((((carry_0_tmp_3806f_11) + (packed_input_state_0_tmp_3806f_2.get_m31(1)))) + (M31_117420501))) - (combination_limb_1_col91))) * (M31_16));let carry_2_tmp_3806f_13 = ((((((((carry_1_tmp_3806f_12) + (packed_input_state_0_tmp_3806f_2.get_m31(2)))) + (M31_112795138))) - (combination_limb_2_col92))) * (M31_16));let carry_3_tmp_3806f_14 = ((((((((carry_2_tmp_3806f_13) + (packed_input_state_0_tmp_3806f_2.get_m31(3)))) + (M31_91013252))) - (combination_limb_3_col93))) * (M31_16));let carry_4_tmp_3806f_15 = ((((((((carry_3_tmp_3806f_14) + (packed_input_state_0_tmp_3806f_2.get_m31(4)))) + (M31_60709090))) - (combination_limb_4_col94))) * (M31_16));let carry_5_tmp_3806f_16 = ((((((((carry_4_tmp_3806f_15) + (packed_input_state_0_tmp_3806f_2.get_m31(5)))) + (M31_44848225))) - (combination_limb_5_col95))) * (M31_16));let carry_6_tmp_3806f_17 = ((((((((carry_5_tmp_3806f_16) + (packed_input_state_0_tmp_3806f_2.get_m31(6)))) + (M31_108487870))) - (combination_limb_6_col96))) * (M31_16));let carry_7_tmp_3806f_18 = ((((((((((carry_6_tmp_3806f_17) + (packed_input_state_0_tmp_3806f_2.get_m31(7)))) + (M31_44781849))) - (combination_limb_7_col97))) - (((p_coef_col100) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_19 = ((((((((carry_7_tmp_3806f_18) + (packed_input_state_0_tmp_3806f_2.get_m31(8)))) + (M31_102193642))) - (combination_limb_8_col98))) * (M31_16));let linear_combination_n_2_coefs_1_1_output_tmp_3806f_29 = combination_tmp_3806f_9;

            // Linear Combination N 2 Coefs 1 1.

            let combination_tmp_3806f_30 = PackedFelt252Width27::from_packed_felt252(((((Felt252_0_0_0_0) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(packed_input_state_1_tmp_3806f_5)))))) + (Felt252_16477292399064058052_4441744911417641572_18431044672185975386_252894828082060025)));let combination_limb_0_col101 = combination_tmp_3806f_30.get_m31(0);
            *row[101] = combination_limb_0_col101;let combination_limb_1_col102 = combination_tmp_3806f_30.get_m31(1);
            *row[102] = combination_limb_1_col102;let combination_limb_2_col103 = combination_tmp_3806f_30.get_m31(2);
            *row[103] = combination_limb_2_col103;let combination_limb_3_col104 = combination_tmp_3806f_30.get_m31(3);
            *row[104] = combination_limb_3_col104;let combination_limb_4_col105 = combination_tmp_3806f_30.get_m31(4);
            *row[105] = combination_limb_4_col105;let combination_limb_5_col106 = combination_tmp_3806f_30.get_m31(5);
            *row[106] = combination_limb_5_col106;let combination_limb_6_col107 = combination_tmp_3806f_30.get_m31(6);
            *row[107] = combination_limb_6_col107;let combination_limb_7_col108 = combination_tmp_3806f_30.get_m31(7);
            *row[108] = combination_limb_7_col108;let combination_limb_8_col109 = combination_tmp_3806f_30.get_m31(8);
            *row[109] = combination_limb_8_col109;let combination_limb_9_col110 = combination_tmp_3806f_30.get_m31(9);
            *row[110] = combination_limb_9_col110;let biased_limb_accumulator_u32_tmp_3806f_31 = PackedUInt32::from_m31(((((((packed_input_state_1_tmp_3806f_5.get_m31(0)) + (M31_41224388))) - (combination_limb_0_col101))) + (M31_134217729)));let p_coef_col111 = ((biased_limb_accumulator_u32_tmp_3806f_31.low().as_m31()) - (M31_1));
            *row[111] = p_coef_col111;let carry_0_tmp_3806f_32 = ((((((((packed_input_state_1_tmp_3806f_5.get_m31(0)) + (M31_41224388))) - (combination_limb_0_col101))) - (p_coef_col111))) * (M31_16));let carry_1_tmp_3806f_33 = ((((((((carry_0_tmp_3806f_32) + (packed_input_state_1_tmp_3806f_5.get_m31(1)))) + (M31_90391646))) - (combination_limb_1_col102))) * (M31_16));let carry_2_tmp_3806f_34 = ((((((((carry_1_tmp_3806f_33) + (packed_input_state_1_tmp_3806f_5.get_m31(2)))) + (M31_36279186))) - (combination_limb_2_col103))) * (M31_16));let carry_3_tmp_3806f_35 = ((((((((carry_2_tmp_3806f_34) + (packed_input_state_1_tmp_3806f_5.get_m31(3)))) + (M31_129717753))) - (combination_limb_3_col104))) * (M31_16));let carry_4_tmp_3806f_36 = ((((((((carry_3_tmp_3806f_35) + (packed_input_state_1_tmp_3806f_5.get_m31(4)))) + (M31_94624323))) - (combination_limb_4_col105))) * (M31_16));let carry_5_tmp_3806f_37 = ((((((((carry_4_tmp_3806f_36) + (packed_input_state_1_tmp_3806f_5.get_m31(5)))) + (M31_75104388))) - (combination_limb_5_col106))) * (M31_16));let carry_6_tmp_3806f_38 = ((((((((carry_5_tmp_3806f_37) + (packed_input_state_1_tmp_3806f_5.get_m31(6)))) + (M31_133303902))) - (combination_limb_6_col107))) * (M31_16));let carry_7_tmp_3806f_39 = ((((((((((carry_6_tmp_3806f_38) + (packed_input_state_1_tmp_3806f_5.get_m31(7)))) + (M31_48945103))) - (combination_limb_7_col108))) - (((p_coef_col111) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_40 = ((((((((carry_7_tmp_3806f_39) + (packed_input_state_1_tmp_3806f_5.get_m31(8)))) + (M31_41320857))) - (combination_limb_8_col109))) * (M31_16));let linear_combination_n_2_coefs_1_1_output_tmp_3806f_50 = combination_tmp_3806f_30;

            // Linear Combination N 2 Coefs 1 1.

            let combination_tmp_3806f_51 = PackedFelt252Width27::from_packed_felt252(((((Felt252_0_0_0_0) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(packed_input_state_2_tmp_3806f_8)))))) + (Felt252_8794894655201903369_3219077422080798056_16714934791572408267_262217499501479120)));let combination_limb_0_col112 = combination_tmp_3806f_51.get_m31(0);
            *row[112] = combination_limb_0_col112;let combination_limb_1_col113 = combination_tmp_3806f_51.get_m31(1);
            *row[113] = combination_limb_1_col113;let combination_limb_2_col114 = combination_tmp_3806f_51.get_m31(2);
            *row[114] = combination_limb_2_col114;let combination_limb_3_col115 = combination_tmp_3806f_51.get_m31(3);
            *row[115] = combination_limb_3_col115;let combination_limb_4_col116 = combination_tmp_3806f_51.get_m31(4);
            *row[116] = combination_limb_4_col116;let combination_limb_5_col117 = combination_tmp_3806f_51.get_m31(5);
            *row[117] = combination_limb_5_col117;let combination_limb_6_col118 = combination_tmp_3806f_51.get_m31(6);
            *row[118] = combination_limb_6_col118;let combination_limb_7_col119 = combination_tmp_3806f_51.get_m31(7);
            *row[119] = combination_limb_7_col119;let combination_limb_8_col120 = combination_tmp_3806f_51.get_m31(8);
            *row[120] = combination_limb_8_col120;let combination_limb_9_col121 = combination_tmp_3806f_51.get_m31(9);
            *row[121] = combination_limb_9_col121;let biased_limb_accumulator_u32_tmp_3806f_52 = PackedUInt32::from_m31(((((((packed_input_state_2_tmp_3806f_8.get_m31(0)) + (M31_4883209))) - (combination_limb_0_col112))) + (M31_134217729)));let p_coef_col122 = ((biased_limb_accumulator_u32_tmp_3806f_52.low().as_m31()) - (M31_1));
            *row[122] = p_coef_col122;let carry_0_tmp_3806f_53 = ((((((((packed_input_state_2_tmp_3806f_8.get_m31(0)) + (M31_4883209))) - (combination_limb_0_col112))) - (p_coef_col122))) * (M31_16));let carry_1_tmp_3806f_54 = ((((((((carry_0_tmp_3806f_53) + (packed_input_state_2_tmp_3806f_8.get_m31(1)))) + (M31_28820206))) - (combination_limb_1_col113))) * (M31_16));let carry_2_tmp_3806f_55 = ((((((((carry_1_tmp_3806f_54) + (packed_input_state_2_tmp_3806f_8.get_m31(2)))) + (M31_79012328))) - (combination_limb_2_col114))) * (M31_16));let carry_3_tmp_3806f_56 = ((((((((carry_2_tmp_3806f_55) + (packed_input_state_2_tmp_3806f_8.get_m31(3)))) + (M31_49157069))) - (combination_limb_3_col115))) * (M31_16));let carry_4_tmp_3806f_57 = ((((((((carry_3_tmp_3806f_56) + (packed_input_state_2_tmp_3806f_8.get_m31(4)))) + (M31_78826183))) - (combination_limb_4_col116))) * (M31_16));let carry_5_tmp_3806f_58 = ((((((((carry_4_tmp_3806f_57) + (packed_input_state_2_tmp_3806f_8.get_m31(5)))) + (M31_72285071))) - (combination_limb_5_col117))) * (M31_16));let carry_6_tmp_3806f_59 = ((((((((carry_5_tmp_3806f_58) + (packed_input_state_2_tmp_3806f_8.get_m31(6)))) + (M31_33413160))) - (combination_limb_6_col118))) * (M31_16));let carry_7_tmp_3806f_60 = ((((((((((carry_6_tmp_3806f_59) + (packed_input_state_2_tmp_3806f_8.get_m31(7)))) + (M31_90842759))) - (combination_limb_7_col119))) - (((p_coef_col122) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_61 = ((((((((carry_7_tmp_3806f_60) + (packed_input_state_2_tmp_3806f_8.get_m31(8)))) + (M31_60124463))) - (combination_limb_8_col120))) * (M31_16));let linear_combination_n_2_coefs_1_1_output_tmp_3806f_71 = combination_tmp_3806f_51;

            let poseidon_full_round_chain_chain_tmp_tmp_3806f_72 = ((seq) * (M31_2));*lookup_data.poseidon_full_round_chain_3 = [M31_1480369132, poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_0, combination_limb_0_col90, combination_limb_1_col91, combination_limb_2_col92, combination_limb_3_col93, combination_limb_4_col94, combination_limb_5_col95, combination_limb_6_col96, combination_limb_7_col97, combination_limb_8_col98, combination_limb_9_col99, combination_limb_0_col101, combination_limb_1_col102, combination_limb_2_col103, combination_limb_3_col104, combination_limb_4_col105, combination_limb_5_col106, combination_limb_6_col107, combination_limb_7_col108, combination_limb_8_col109, combination_limb_9_col110, combination_limb_0_col112, combination_limb_1_col113, combination_limb_2_col114, combination_limb_3_col115, combination_limb_4_col116, combination_limb_5_col117, combination_limb_6_col118, combination_limb_7_col119, combination_limb_8_col120, combination_limb_9_col121];*sub_component_inputs.poseidon_full_round_chain[0] =
                (poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_0, [linear_combination_n_2_coefs_1_1_output_tmp_3806f_29, linear_combination_n_2_coefs_1_1_output_tmp_3806f_50, linear_combination_n_2_coefs_1_1_output_tmp_3806f_71]);
            let poseidon_full_round_chain_output_round_0_tmp_3806f_73 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_0, [linear_combination_n_2_coefs_1_1_output_tmp_3806f_29, linear_combination_n_2_coefs_1_1_output_tmp_3806f_50, linear_combination_n_2_coefs_1_1_output_tmp_3806f_71]));*sub_component_inputs.poseidon_full_round_chain[1] =
                (poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_1, [poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[0], poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[1], poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[2]]);
            let poseidon_full_round_chain_output_round_1_tmp_3806f_74 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_1, [poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[0], poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[1], poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[2]]));*sub_component_inputs.poseidon_full_round_chain[2] =
                (poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_2, [poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[0], poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[1], poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[2]]);
            let poseidon_full_round_chain_output_round_2_tmp_3806f_75 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_2, [poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[0], poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[1], poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[2]]));*sub_component_inputs.poseidon_full_round_chain[3] =
                (poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_3, [poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[0], poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[1], poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[2]]);
            let poseidon_full_round_chain_output_round_3_tmp_3806f_76 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_3, [poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[0], poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[1], poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[2]]));let poseidon_full_round_chain_output_limb_0_col123 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(0);
            *row[123] = poseidon_full_round_chain_output_limb_0_col123;let poseidon_full_round_chain_output_limb_1_col124 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(1);
            *row[124] = poseidon_full_round_chain_output_limb_1_col124;let poseidon_full_round_chain_output_limb_2_col125 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(2);
            *row[125] = poseidon_full_round_chain_output_limb_2_col125;let poseidon_full_round_chain_output_limb_3_col126 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(3);
            *row[126] = poseidon_full_round_chain_output_limb_3_col126;let poseidon_full_round_chain_output_limb_4_col127 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(4);
            *row[127] = poseidon_full_round_chain_output_limb_4_col127;let poseidon_full_round_chain_output_limb_5_col128 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(5);
            *row[128] = poseidon_full_round_chain_output_limb_5_col128;let poseidon_full_round_chain_output_limb_6_col129 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(6);
            *row[129] = poseidon_full_round_chain_output_limb_6_col129;let poseidon_full_round_chain_output_limb_7_col130 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(7);
            *row[130] = poseidon_full_round_chain_output_limb_7_col130;let poseidon_full_round_chain_output_limb_8_col131 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(8);
            *row[131] = poseidon_full_round_chain_output_limb_8_col131;let poseidon_full_round_chain_output_limb_9_col132 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0].get_m31(9);
            *row[132] = poseidon_full_round_chain_output_limb_9_col132;let poseidon_full_round_chain_output_limb_10_col133 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(0);
            *row[133] = poseidon_full_round_chain_output_limb_10_col133;let poseidon_full_round_chain_output_limb_11_col134 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(1);
            *row[134] = poseidon_full_round_chain_output_limb_11_col134;let poseidon_full_round_chain_output_limb_12_col135 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(2);
            *row[135] = poseidon_full_round_chain_output_limb_12_col135;let poseidon_full_round_chain_output_limb_13_col136 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(3);
            *row[136] = poseidon_full_round_chain_output_limb_13_col136;let poseidon_full_round_chain_output_limb_14_col137 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(4);
            *row[137] = poseidon_full_round_chain_output_limb_14_col137;let poseidon_full_round_chain_output_limb_15_col138 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(5);
            *row[138] = poseidon_full_round_chain_output_limb_15_col138;let poseidon_full_round_chain_output_limb_16_col139 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(6);
            *row[139] = poseidon_full_round_chain_output_limb_16_col139;let poseidon_full_round_chain_output_limb_17_col140 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(7);
            *row[140] = poseidon_full_round_chain_output_limb_17_col140;let poseidon_full_round_chain_output_limb_18_col141 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(8);
            *row[141] = poseidon_full_round_chain_output_limb_18_col141;let poseidon_full_round_chain_output_limb_19_col142 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1].get_m31(9);
            *row[142] = poseidon_full_round_chain_output_limb_19_col142;let poseidon_full_round_chain_output_limb_20_col143 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(0);
            *row[143] = poseidon_full_round_chain_output_limb_20_col143;let poseidon_full_round_chain_output_limb_21_col144 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(1);
            *row[144] = poseidon_full_round_chain_output_limb_21_col144;let poseidon_full_round_chain_output_limb_22_col145 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(2);
            *row[145] = poseidon_full_round_chain_output_limb_22_col145;let poseidon_full_round_chain_output_limb_23_col146 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(3);
            *row[146] = poseidon_full_round_chain_output_limb_23_col146;let poseidon_full_round_chain_output_limb_24_col147 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(4);
            *row[147] = poseidon_full_round_chain_output_limb_24_col147;let poseidon_full_round_chain_output_limb_25_col148 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(5);
            *row[148] = poseidon_full_round_chain_output_limb_25_col148;let poseidon_full_round_chain_output_limb_26_col149 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(6);
            *row[149] = poseidon_full_round_chain_output_limb_26_col149;let poseidon_full_round_chain_output_limb_27_col150 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(7);
            *row[150] = poseidon_full_round_chain_output_limb_27_col150;let poseidon_full_round_chain_output_limb_28_col151 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(8);
            *row[151] = poseidon_full_round_chain_output_limb_28_col151;let poseidon_full_round_chain_output_limb_29_col152 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2].get_m31(9);
            *row[152] = poseidon_full_round_chain_output_limb_29_col152;*lookup_data.poseidon_full_round_chain_4 = [M31_1480369132, poseidon_full_round_chain_chain_tmp_tmp_3806f_72, M31_4, poseidon_full_round_chain_output_limb_0_col123, poseidon_full_round_chain_output_limb_1_col124, poseidon_full_round_chain_output_limb_2_col125, poseidon_full_round_chain_output_limb_3_col126, poseidon_full_round_chain_output_limb_4_col127, poseidon_full_round_chain_output_limb_5_col128, poseidon_full_round_chain_output_limb_6_col129, poseidon_full_round_chain_output_limb_7_col130, poseidon_full_round_chain_output_limb_8_col131, poseidon_full_round_chain_output_limb_9_col132, poseidon_full_round_chain_output_limb_10_col133, poseidon_full_round_chain_output_limb_11_col134, poseidon_full_round_chain_output_limb_12_col135, poseidon_full_round_chain_output_limb_13_col136, poseidon_full_round_chain_output_limb_14_col137, poseidon_full_round_chain_output_limb_15_col138, poseidon_full_round_chain_output_limb_16_col139, poseidon_full_round_chain_output_limb_17_col140, poseidon_full_round_chain_output_limb_18_col141, poseidon_full_round_chain_output_limb_19_col142, poseidon_full_round_chain_output_limb_20_col143, poseidon_full_round_chain_output_limb_21_col144, poseidon_full_round_chain_output_limb_22_col145, poseidon_full_round_chain_output_limb_23_col146, poseidon_full_round_chain_output_limb_24_col147, poseidon_full_round_chain_output_limb_25_col148, poseidon_full_round_chain_output_limb_26_col149, poseidon_full_round_chain_output_limb_27_col150, poseidon_full_round_chain_output_limb_28_col151, poseidon_full_round_chain_output_limb_29_col152];*sub_component_inputs.range_check_252_width_27[0] =
                poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0];
            *lookup_data.range_check_252_width_27_5 = [M31_1090315331, poseidon_full_round_chain_output_limb_0_col123, poseidon_full_round_chain_output_limb_1_col124, poseidon_full_round_chain_output_limb_2_col125, poseidon_full_round_chain_output_limb_3_col126, poseidon_full_round_chain_output_limb_4_col127, poseidon_full_round_chain_output_limb_5_col128, poseidon_full_round_chain_output_limb_6_col129, poseidon_full_round_chain_output_limb_7_col130, poseidon_full_round_chain_output_limb_8_col131, poseidon_full_round_chain_output_limb_9_col132];*sub_component_inputs.range_check_252_width_27[1] =
                poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1];
            *lookup_data.range_check_252_width_27_6 = [M31_1090315331, poseidon_full_round_chain_output_limb_10_col133, poseidon_full_round_chain_output_limb_11_col134, poseidon_full_round_chain_output_limb_12_col135, poseidon_full_round_chain_output_limb_13_col136, poseidon_full_round_chain_output_limb_14_col137, poseidon_full_round_chain_output_limb_15_col138, poseidon_full_round_chain_output_limb_16_col139, poseidon_full_round_chain_output_limb_17_col140, poseidon_full_round_chain_output_limb_18_col141, poseidon_full_round_chain_output_limb_19_col142];*sub_component_inputs.cube_252[0] =
                poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2];
            let cube_252_output_tmp_3806f_77 = PackedCube252::deduce_output(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2]);let cube_252_output_limb_0_col153 = cube_252_output_tmp_3806f_77.get_m31(0);
            *row[153] = cube_252_output_limb_0_col153;let cube_252_output_limb_1_col154 = cube_252_output_tmp_3806f_77.get_m31(1);
            *row[154] = cube_252_output_limb_1_col154;let cube_252_output_limb_2_col155 = cube_252_output_tmp_3806f_77.get_m31(2);
            *row[155] = cube_252_output_limb_2_col155;let cube_252_output_limb_3_col156 = cube_252_output_tmp_3806f_77.get_m31(3);
            *row[156] = cube_252_output_limb_3_col156;let cube_252_output_limb_4_col157 = cube_252_output_tmp_3806f_77.get_m31(4);
            *row[157] = cube_252_output_limb_4_col157;let cube_252_output_limb_5_col158 = cube_252_output_tmp_3806f_77.get_m31(5);
            *row[158] = cube_252_output_limb_5_col158;let cube_252_output_limb_6_col159 = cube_252_output_tmp_3806f_77.get_m31(6);
            *row[159] = cube_252_output_limb_6_col159;let cube_252_output_limb_7_col160 = cube_252_output_tmp_3806f_77.get_m31(7);
            *row[160] = cube_252_output_limb_7_col160;let cube_252_output_limb_8_col161 = cube_252_output_tmp_3806f_77.get_m31(8);
            *row[161] = cube_252_output_limb_8_col161;let cube_252_output_limb_9_col162 = cube_252_output_tmp_3806f_77.get_m31(9);
            *row[162] = cube_252_output_limb_9_col162;*lookup_data.cube_252_7 = [M31_1987997202, poseidon_full_round_chain_output_limb_20_col143, poseidon_full_round_chain_output_limb_21_col144, poseidon_full_round_chain_output_limb_22_col145, poseidon_full_round_chain_output_limb_23_col146, poseidon_full_round_chain_output_limb_24_col147, poseidon_full_round_chain_output_limb_25_col148, poseidon_full_round_chain_output_limb_26_col149, poseidon_full_round_chain_output_limb_27_col150, poseidon_full_round_chain_output_limb_28_col151, poseidon_full_round_chain_output_limb_29_col152, cube_252_output_limb_0_col153, cube_252_output_limb_1_col154, cube_252_output_limb_2_col155, cube_252_output_limb_3_col156, cube_252_output_limb_4_col157, cube_252_output_limb_5_col158, cube_252_output_limb_6_col159, cube_252_output_limb_7_col160, cube_252_output_limb_8_col161, cube_252_output_limb_9_col162];

            // Linear Combination N 4 Coefs 1 1 M 2 1.

            let combination_tmp_3806f_78 = PackedFelt252Width27::from_packed_felt252(((((((((Felt252_0_0_0_0) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0])))))) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1])))))) - (((Felt252_2_0_0_0) * (PackedFelt252::from_packed_felt252width27(cube_252_output_tmp_3806f_77)))))) + (Felt252_11041071929982523380_7503192613203831446_4943121247101232560_560497091765764140)));let combination_limb_0_col163 = combination_tmp_3806f_78.get_m31(0);
            *row[163] = combination_limb_0_col163;let combination_limb_1_col164 = combination_tmp_3806f_78.get_m31(1);
            *row[164] = combination_limb_1_col164;let combination_limb_2_col165 = combination_tmp_3806f_78.get_m31(2);
            *row[165] = combination_limb_2_col165;let combination_limb_3_col166 = combination_tmp_3806f_78.get_m31(3);
            *row[166] = combination_limb_3_col166;let combination_limb_4_col167 = combination_tmp_3806f_78.get_m31(4);
            *row[167] = combination_limb_4_col167;let combination_limb_5_col168 = combination_tmp_3806f_78.get_m31(5);
            *row[168] = combination_limb_5_col168;let combination_limb_6_col169 = combination_tmp_3806f_78.get_m31(6);
            *row[169] = combination_limb_6_col169;let combination_limb_7_col170 = combination_tmp_3806f_78.get_m31(7);
            *row[170] = combination_limb_7_col170;let combination_limb_8_col171 = combination_tmp_3806f_78.get_m31(8);
            *row[171] = combination_limb_8_col171;let combination_limb_9_col172 = combination_tmp_3806f_78.get_m31(9);
            *row[172] = combination_limb_9_col172;let biased_limb_accumulator_u32_tmp_3806f_79 = PackedUInt32::from_m31(((((((((((poseidon_full_round_chain_output_limb_0_col123) + (poseidon_full_round_chain_output_limb_10_col133))) - (((M31_2) * (cube_252_output_limb_0_col153))))) + (M31_103094260))) - (combination_limb_0_col163))) + (M31_402653187)));let p_coef_col173 = ((biased_limb_accumulator_u32_tmp_3806f_79.low().as_m31()) - (M31_3));
            *row[173] = p_coef_col173;let carry_0_tmp_3806f_80 = ((((((((((((poseidon_full_round_chain_output_limb_0_col123) + (poseidon_full_round_chain_output_limb_10_col133))) - (((M31_2) * (cube_252_output_limb_0_col153))))) + (M31_103094260))) - (combination_limb_0_col163))) - (p_coef_col173))) * (M31_16));let carry_1_tmp_3806f_81 = ((((((((((((carry_0_tmp_3806f_80) + (poseidon_full_round_chain_output_limb_1_col124))) + (poseidon_full_round_chain_output_limb_11_col134))) - (((M31_2) * (cube_252_output_limb_1_col154))))) + (M31_121146754))) - (combination_limb_1_col164))) * (M31_16));let carry_2_tmp_3806f_82 = ((((((((((((carry_1_tmp_3806f_81) + (poseidon_full_round_chain_output_limb_2_col125))) + (poseidon_full_round_chain_output_limb_12_col135))) - (((M31_2) * (cube_252_output_limb_2_col155))))) + (M31_95050340))) - (combination_limb_2_col165))) * (M31_16));let carry_3_tmp_3806f_83 = ((((((((((((carry_2_tmp_3806f_82) + (poseidon_full_round_chain_output_limb_3_col126))) + (poseidon_full_round_chain_output_limb_13_col136))) - (((M31_2) * (cube_252_output_limb_3_col156))))) + (M31_16173996))) - (combination_limb_3_col166))) * (M31_16));let carry_4_tmp_3806f_84 = ((((((((((((carry_3_tmp_3806f_83) + (poseidon_full_round_chain_output_limb_4_col127))) + (poseidon_full_round_chain_output_limb_14_col137))) - (((M31_2) * (cube_252_output_limb_4_col157))))) + (M31_50758155))) - (combination_limb_4_col167))) * (M31_16));let carry_5_tmp_3806f_85 = ((((((((((((carry_4_tmp_3806f_84) + (poseidon_full_round_chain_output_limb_5_col128))) + (poseidon_full_round_chain_output_limb_15_col138))) - (((M31_2) * (cube_252_output_limb_5_col158))))) + (M31_54415179))) - (combination_limb_5_col168))) * (M31_16));let carry_6_tmp_3806f_86 = ((((((((((((carry_5_tmp_3806f_85) + (poseidon_full_round_chain_output_limb_6_col129))) + (poseidon_full_round_chain_output_limb_16_col139))) - (((M31_2) * (cube_252_output_limb_6_col159))))) + (M31_19292069))) - (combination_limb_6_col169))) * (M31_16));let carry_7_tmp_3806f_87 = ((((((((((((((carry_6_tmp_3806f_86) + (poseidon_full_round_chain_output_limb_7_col130))) + (poseidon_full_round_chain_output_limb_17_col140))) - (((M31_2) * (cube_252_output_limb_7_col160))))) + (M31_45351266))) - (combination_limb_7_col170))) - (((p_coef_col173) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_88 = ((((((((((((carry_7_tmp_3806f_87) + (poseidon_full_round_chain_output_limb_8_col131))) + (poseidon_full_round_chain_output_limb_18_col141))) - (((M31_2) * (cube_252_output_limb_8_col161))))) + (M31_122233508))) - (combination_limb_8_col171))) * (M31_16));*sub_component_inputs.range_check_3_3_3_3_3[0] =
                [((p_coef_col173) + (M31_3)), ((carry_0_tmp_3806f_80) + (M31_3)), ((carry_1_tmp_3806f_81) + (M31_3)), ((carry_2_tmp_3806f_82) + (M31_3)), ((carry_3_tmp_3806f_83) + (M31_3))];
            *lookup_data.range_check_3_3_3_3_3_8 = [M31_502259093, ((p_coef_col173) + (M31_3)), ((carry_0_tmp_3806f_80) + (M31_3)), ((carry_1_tmp_3806f_81) + (M31_3)), ((carry_2_tmp_3806f_82) + (M31_3)), ((carry_3_tmp_3806f_83) + (M31_3))];*sub_component_inputs.range_check_3_3_3_3_3[1] =
                [((carry_4_tmp_3806f_84) + (M31_3)), ((carry_5_tmp_3806f_85) + (M31_3)), ((carry_6_tmp_3806f_86) + (M31_3)), ((carry_7_tmp_3806f_87) + (M31_3)), ((carry_8_tmp_3806f_88) + (M31_3))];
            *lookup_data.range_check_3_3_3_3_3_9 = [M31_502259093, ((carry_4_tmp_3806f_84) + (M31_3)), ((carry_5_tmp_3806f_85) + (M31_3)), ((carry_6_tmp_3806f_86) + (M31_3)), ((carry_7_tmp_3806f_87) + (M31_3)), ((carry_8_tmp_3806f_88) + (M31_3))];let linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89 = combination_tmp_3806f_78;

            *sub_component_inputs.cube_252[1] =
                linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89;
            let cube_252_output_tmp_3806f_90 = PackedCube252::deduce_output(linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89);let cube_252_output_limb_0_col174 = cube_252_output_tmp_3806f_90.get_m31(0);
            *row[174] = cube_252_output_limb_0_col174;let cube_252_output_limb_1_col175 = cube_252_output_tmp_3806f_90.get_m31(1);
            *row[175] = cube_252_output_limb_1_col175;let cube_252_output_limb_2_col176 = cube_252_output_tmp_3806f_90.get_m31(2);
            *row[176] = cube_252_output_limb_2_col176;let cube_252_output_limb_3_col177 = cube_252_output_tmp_3806f_90.get_m31(3);
            *row[177] = cube_252_output_limb_3_col177;let cube_252_output_limb_4_col178 = cube_252_output_tmp_3806f_90.get_m31(4);
            *row[178] = cube_252_output_limb_4_col178;let cube_252_output_limb_5_col179 = cube_252_output_tmp_3806f_90.get_m31(5);
            *row[179] = cube_252_output_limb_5_col179;let cube_252_output_limb_6_col180 = cube_252_output_tmp_3806f_90.get_m31(6);
            *row[180] = cube_252_output_limb_6_col180;let cube_252_output_limb_7_col181 = cube_252_output_tmp_3806f_90.get_m31(7);
            *row[181] = cube_252_output_limb_7_col181;let cube_252_output_limb_8_col182 = cube_252_output_tmp_3806f_90.get_m31(8);
            *row[182] = cube_252_output_limb_8_col182;let cube_252_output_limb_9_col183 = cube_252_output_tmp_3806f_90.get_m31(9);
            *row[183] = cube_252_output_limb_9_col183;*lookup_data.cube_252_10 = [M31_1987997202, combination_limb_0_col163, combination_limb_1_col164, combination_limb_2_col165, combination_limb_3_col166, combination_limb_4_col167, combination_limb_5_col168, combination_limb_6_col169, combination_limb_7_col170, combination_limb_8_col171, combination_limb_9_col172, cube_252_output_limb_0_col174, cube_252_output_limb_1_col175, cube_252_output_limb_2_col176, cube_252_output_limb_3_col177, cube_252_output_limb_4_col178, cube_252_output_limb_5_col179, cube_252_output_limb_6_col180, cube_252_output_limb_7_col181, cube_252_output_limb_8_col182, cube_252_output_limb_9_col183];

            // Linear Combination N 4 Coefs 4 2 M 2 1.

            let combination_tmp_3806f_91 = PackedFelt252Width27::from_packed_felt252(((((((((Felt252_0_0_0_0) + (((Felt252_4_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0])))))) + (((Felt252_2_0_0_0) * (PackedFelt252::from_packed_felt252width27(cube_252_output_tmp_3806f_77)))))) - (((Felt252_2_0_0_0) * (PackedFelt252::from_packed_felt252width27(cube_252_output_tmp_3806f_90)))))) + (Felt252_10931822301410252833_1475756362763989377_3378552166684303673_348229636055909092)));let combination_limb_0_col184 = combination_tmp_3806f_91.get_m31(0);
            *row[184] = combination_limb_0_col184;let combination_limb_1_col185 = combination_tmp_3806f_91.get_m31(1);
            *row[185] = combination_limb_1_col185;let combination_limb_2_col186 = combination_tmp_3806f_91.get_m31(2);
            *row[186] = combination_limb_2_col186;let combination_limb_3_col187 = combination_tmp_3806f_91.get_m31(3);
            *row[187] = combination_limb_3_col187;let combination_limb_4_col188 = combination_tmp_3806f_91.get_m31(4);
            *row[188] = combination_limb_4_col188;let combination_limb_5_col189 = combination_tmp_3806f_91.get_m31(5);
            *row[189] = combination_limb_5_col189;let combination_limb_6_col190 = combination_tmp_3806f_91.get_m31(6);
            *row[190] = combination_limb_6_col190;let combination_limb_7_col191 = combination_tmp_3806f_91.get_m31(7);
            *row[191] = combination_limb_7_col191;let combination_limb_8_col192 = combination_tmp_3806f_91.get_m31(8);
            *row[192] = combination_limb_8_col192;let combination_limb_9_col193 = combination_tmp_3806f_91.get_m31(9);
            *row[193] = combination_limb_9_col193;let biased_limb_accumulator_u32_tmp_3806f_92 = PackedUInt32::from_m31(((((((((((((M31_4) * (poseidon_full_round_chain_output_limb_0_col123))) + (((M31_2) * (cube_252_output_limb_0_col153))))) - (((M31_2) * (cube_252_output_limb_0_col174))))) + (M31_121657377))) - (combination_limb_0_col184))) + (M31_402653187)));let p_coef_col194 = ((biased_limb_accumulator_u32_tmp_3806f_92.low().as_m31()) - (M31_3));
            *row[194] = p_coef_col194;let carry_0_tmp_3806f_93 = ((((((((((((((M31_4) * (poseidon_full_round_chain_output_limb_0_col123))) + (((M31_2) * (cube_252_output_limb_0_col153))))) - (((M31_2) * (cube_252_output_limb_0_col174))))) + (M31_121657377))) - (combination_limb_0_col184))) - (p_coef_col194))) * (M31_16));let carry_1_tmp_3806f_94 = ((((((((((((carry_0_tmp_3806f_93) + (((M31_4) * (poseidon_full_round_chain_output_limb_1_col124))))) + (((M31_2) * (cube_252_output_limb_1_col154))))) - (((M31_2) * (cube_252_output_limb_1_col175))))) + (M31_112479959))) - (combination_limb_1_col185))) * (M31_16));let carry_2_tmp_3806f_95 = ((((((((((((carry_1_tmp_3806f_94) + (((M31_4) * (poseidon_full_round_chain_output_limb_2_col125))))) + (((M31_2) * (cube_252_output_limb_2_col155))))) - (((M31_2) * (cube_252_output_limb_2_col176))))) + (M31_130418270))) - (combination_limb_2_col186))) * (M31_16));let carry_3_tmp_3806f_96 = ((((((((((((carry_2_tmp_3806f_95) + (((M31_4) * (poseidon_full_round_chain_output_limb_3_col126))))) + (((M31_2) * (cube_252_output_limb_3_col156))))) - (((M31_2) * (cube_252_output_limb_3_col177))))) + (M31_4974792))) - (combination_limb_3_col187))) * (M31_16));let carry_4_tmp_3806f_97 = ((((((((((((carry_3_tmp_3806f_96) + (((M31_4) * (poseidon_full_round_chain_output_limb_4_col127))))) + (((M31_2) * (cube_252_output_limb_4_col157))))) - (((M31_2) * (cube_252_output_limb_4_col178))))) + (M31_59852719))) - (combination_limb_4_col188))) * (M31_16));let carry_5_tmp_3806f_98 = ((((((((((((carry_4_tmp_3806f_97) + (((M31_4) * (poseidon_full_round_chain_output_limb_5_col128))))) + (((M31_2) * (cube_252_output_limb_5_col158))))) - (((M31_2) * (cube_252_output_limb_5_col179))))) + (M31_120369218))) - (combination_limb_5_col189))) * (M31_16));let carry_6_tmp_3806f_99 = ((((((((((((carry_5_tmp_3806f_98) + (((M31_4) * (poseidon_full_round_chain_output_limb_6_col129))))) + (((M31_2) * (cube_252_output_limb_6_col159))))) - (((M31_2) * (cube_252_output_limb_6_col180))))) + (M31_62439890))) - (combination_limb_6_col190))) * (M31_16));let carry_7_tmp_3806f_100 = ((((((((((((((carry_6_tmp_3806f_99) + (((M31_4) * (poseidon_full_round_chain_output_limb_7_col130))))) + (((M31_2) * (cube_252_output_limb_7_col160))))) - (((M31_2) * (cube_252_output_limb_7_col181))))) + (M31_50468641))) - (combination_limb_7_col191))) - (((p_coef_col194) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_101 = ((((((((((((carry_7_tmp_3806f_100) + (((M31_4) * (poseidon_full_round_chain_output_limb_8_col131))))) + (((M31_2) * (cube_252_output_limb_8_col161))))) - (((M31_2) * (cube_252_output_limb_8_col182))))) + (M31_86573645))) - (combination_limb_8_col192))) * (M31_16));*sub_component_inputs.range_check_4_4_4_4[0] =
                [((p_coef_col194) + (M31_3)), ((carry_0_tmp_3806f_93) + (M31_3)), ((carry_1_tmp_3806f_94) + (M31_3)), ((carry_2_tmp_3806f_95) + (M31_3))];
            *lookup_data.range_check_4_4_4_4_11 = [M31_1027333874, ((p_coef_col194) + (M31_3)), ((carry_0_tmp_3806f_93) + (M31_3)), ((carry_1_tmp_3806f_94) + (M31_3)), ((carry_2_tmp_3806f_95) + (M31_3))];*sub_component_inputs.range_check_4_4_4_4[1] =
                [((carry_3_tmp_3806f_96) + (M31_3)), ((carry_4_tmp_3806f_97) + (M31_3)), ((carry_5_tmp_3806f_98) + (M31_3)), ((carry_6_tmp_3806f_99) + (M31_3))];
            *lookup_data.range_check_4_4_4_4_12 = [M31_1027333874, ((carry_3_tmp_3806f_96) + (M31_3)), ((carry_4_tmp_3806f_97) + (M31_3)), ((carry_5_tmp_3806f_98) + (M31_3)), ((carry_6_tmp_3806f_99) + (M31_3))];*sub_component_inputs.range_check_4_4[0] =
                [((carry_7_tmp_3806f_100) + (M31_3)), ((carry_8_tmp_3806f_101) + (M31_3))];
            *lookup_data.range_check_4_4_13 = [M31_1651211826, ((carry_7_tmp_3806f_100) + (M31_3)), ((carry_8_tmp_3806f_101) + (M31_3))];let linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102 = combination_tmp_3806f_91;

            *lookup_data.poseidon_3_partial_rounds_chain_14 = [M31_1343313504, seq, M31_4, cube_252_output_limb_0_col153, cube_252_output_limb_1_col154, cube_252_output_limb_2_col155, cube_252_output_limb_3_col156, cube_252_output_limb_4_col157, cube_252_output_limb_5_col158, cube_252_output_limb_6_col159, cube_252_output_limb_7_col160, cube_252_output_limb_8_col161, cube_252_output_limb_9_col162, combination_limb_0_col163, combination_limb_1_col164, combination_limb_2_col165, combination_limb_3_col166, combination_limb_4_col167, combination_limb_5_col168, combination_limb_6_col169, combination_limb_7_col170, combination_limb_8_col171, combination_limb_9_col172, cube_252_output_limb_0_col174, cube_252_output_limb_1_col175, cube_252_output_limb_2_col176, cube_252_output_limb_3_col177, cube_252_output_limb_4_col178, cube_252_output_limb_5_col179, cube_252_output_limb_6_col180, cube_252_output_limb_7_col181, cube_252_output_limb_8_col182, cube_252_output_limb_9_col183, combination_limb_0_col184, combination_limb_1_col185, combination_limb_2_col186, combination_limb_3_col187, combination_limb_4_col188, combination_limb_5_col189, combination_limb_6_col190, combination_limb_7_col191, combination_limb_8_col192, combination_limb_9_col193];*sub_component_inputs.poseidon_3_partial_rounds_chain[0] =
                (seq, M31_4, [cube_252_output_tmp_3806f_77, linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89, cube_252_output_tmp_3806f_90, linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102]);
            let poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_4, [cube_252_output_tmp_3806f_77, linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89, cube_252_output_tmp_3806f_90, linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102]));*sub_component_inputs.poseidon_3_partial_rounds_chain[1] =
                (seq, M31_5, [poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[0], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[1], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[2], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_5, [poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[0], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[1], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[2], poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[2] =
                (seq, M31_6, [poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[0], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[1], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[2], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_6, [poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[0], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[1], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[2], poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[3] =
                (seq, M31_7, [poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[0], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[1], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[2], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_7, [poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[0], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[1], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[2], poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[4] =
                (seq, M31_8, [poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[0], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[1], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[2], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_8, [poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[0], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[1], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[2], poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[5] =
                (seq, M31_9, [poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[0], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[1], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[2], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_9, [poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[0], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[1], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[2], poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[6] =
                (seq, M31_10, [poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[0], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[1], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[2], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_10, [poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[0], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[1], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[2], poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[7] =
                (seq, M31_11, [poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[0], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[1], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[2], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_11, [poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[0], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[1], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[2], poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[8] =
                (seq, M31_12, [poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[0], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[1], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[2], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_12, [poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[0], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[1], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[2], poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[9] =
                (seq, M31_13, [poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[0], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[1], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[2], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_13, [poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[0], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[1], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[2], poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[10] =
                (seq, M31_14, [poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[0], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[1], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[2], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_14, [poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[0], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[1], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[2], poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[11] =
                (seq, M31_15, [poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[0], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[1], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[2], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_15, [poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[0], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[1], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[2], poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[12] =
                (seq, M31_16, [poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[0], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[1], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[2], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_16, [poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[0], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[1], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[2], poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[13] =
                (seq, M31_17, [poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[0], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[1], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[2], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_17, [poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[0], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[1], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[2], poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[14] =
                (seq, M31_18, [poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[0], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[1], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[2], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_18, [poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[0], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[1], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[2], poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[15] =
                (seq, M31_19, [poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[0], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[1], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[2], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_19, [poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[0], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[1], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[2], poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[16] =
                (seq, M31_20, [poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[0], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[1], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[2], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_20, [poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[0], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[1], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[2], poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[17] =
                (seq, M31_21, [poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[0], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[1], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[2], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_21, [poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[0], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[1], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[2], poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[18] =
                (seq, M31_22, [poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[0], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[1], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[2], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_22, [poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[0], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[1], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[2], poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[19] =
                (seq, M31_23, [poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[0], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[1], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[2], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_23, [poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[0], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[1], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[2], poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[20] =
                (seq, M31_24, [poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[0], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[1], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[2], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_24, [poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[0], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[1], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[2], poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[21] =
                (seq, M31_25, [poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[0], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[1], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[2], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_25, [poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[0], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[1], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[2], poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[22] =
                (seq, M31_26, [poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[0], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[1], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[2], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_26, [poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[0], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[1], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[2], poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[23] =
                (seq, M31_27, [poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[0], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[1], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[2], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_27, [poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[0], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[1], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[2], poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[24] =
                (seq, M31_28, [poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[0], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[1], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[2], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_28, [poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[0], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[1], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[2], poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[25] =
                (seq, M31_29, [poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[0], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[1], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[2], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_29, [poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[0], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[1], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[2], poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[3]]));*sub_component_inputs.poseidon_3_partial_rounds_chain[26] =
                (seq, M31_30, [poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[0], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[1], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[2], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[3]]);
            let poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130 = PackedPoseidon3PartialRoundsChain::deduce_output((seq, M31_30, [poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[0], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[1], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[2], poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[3]]));let poseidon_3_partial_rounds_chain_output_limb_0_col195 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(0);
            *row[195] = poseidon_3_partial_rounds_chain_output_limb_0_col195;let poseidon_3_partial_rounds_chain_output_limb_1_col196 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(1);
            *row[196] = poseidon_3_partial_rounds_chain_output_limb_1_col196;let poseidon_3_partial_rounds_chain_output_limb_2_col197 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(2);
            *row[197] = poseidon_3_partial_rounds_chain_output_limb_2_col197;let poseidon_3_partial_rounds_chain_output_limb_3_col198 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(3);
            *row[198] = poseidon_3_partial_rounds_chain_output_limb_3_col198;let poseidon_3_partial_rounds_chain_output_limb_4_col199 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(4);
            *row[199] = poseidon_3_partial_rounds_chain_output_limb_4_col199;let poseidon_3_partial_rounds_chain_output_limb_5_col200 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(5);
            *row[200] = poseidon_3_partial_rounds_chain_output_limb_5_col200;let poseidon_3_partial_rounds_chain_output_limb_6_col201 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(6);
            *row[201] = poseidon_3_partial_rounds_chain_output_limb_6_col201;let poseidon_3_partial_rounds_chain_output_limb_7_col202 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(7);
            *row[202] = poseidon_3_partial_rounds_chain_output_limb_7_col202;let poseidon_3_partial_rounds_chain_output_limb_8_col203 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(8);
            *row[203] = poseidon_3_partial_rounds_chain_output_limb_8_col203;let poseidon_3_partial_rounds_chain_output_limb_9_col204 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0].get_m31(9);
            *row[204] = poseidon_3_partial_rounds_chain_output_limb_9_col204;let poseidon_3_partial_rounds_chain_output_limb_10_col205 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(0);
            *row[205] = poseidon_3_partial_rounds_chain_output_limb_10_col205;let poseidon_3_partial_rounds_chain_output_limb_11_col206 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(1);
            *row[206] = poseidon_3_partial_rounds_chain_output_limb_11_col206;let poseidon_3_partial_rounds_chain_output_limb_12_col207 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(2);
            *row[207] = poseidon_3_partial_rounds_chain_output_limb_12_col207;let poseidon_3_partial_rounds_chain_output_limb_13_col208 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(3);
            *row[208] = poseidon_3_partial_rounds_chain_output_limb_13_col208;let poseidon_3_partial_rounds_chain_output_limb_14_col209 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(4);
            *row[209] = poseidon_3_partial_rounds_chain_output_limb_14_col209;let poseidon_3_partial_rounds_chain_output_limb_15_col210 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(5);
            *row[210] = poseidon_3_partial_rounds_chain_output_limb_15_col210;let poseidon_3_partial_rounds_chain_output_limb_16_col211 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(6);
            *row[211] = poseidon_3_partial_rounds_chain_output_limb_16_col211;let poseidon_3_partial_rounds_chain_output_limb_17_col212 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(7);
            *row[212] = poseidon_3_partial_rounds_chain_output_limb_17_col212;let poseidon_3_partial_rounds_chain_output_limb_18_col213 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(8);
            *row[213] = poseidon_3_partial_rounds_chain_output_limb_18_col213;let poseidon_3_partial_rounds_chain_output_limb_19_col214 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1].get_m31(9);
            *row[214] = poseidon_3_partial_rounds_chain_output_limb_19_col214;let poseidon_3_partial_rounds_chain_output_limb_20_col215 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(0);
            *row[215] = poseidon_3_partial_rounds_chain_output_limb_20_col215;let poseidon_3_partial_rounds_chain_output_limb_21_col216 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(1);
            *row[216] = poseidon_3_partial_rounds_chain_output_limb_21_col216;let poseidon_3_partial_rounds_chain_output_limb_22_col217 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(2);
            *row[217] = poseidon_3_partial_rounds_chain_output_limb_22_col217;let poseidon_3_partial_rounds_chain_output_limb_23_col218 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(3);
            *row[218] = poseidon_3_partial_rounds_chain_output_limb_23_col218;let poseidon_3_partial_rounds_chain_output_limb_24_col219 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(4);
            *row[219] = poseidon_3_partial_rounds_chain_output_limb_24_col219;let poseidon_3_partial_rounds_chain_output_limb_25_col220 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(5);
            *row[220] = poseidon_3_partial_rounds_chain_output_limb_25_col220;let poseidon_3_partial_rounds_chain_output_limb_26_col221 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(6);
            *row[221] = poseidon_3_partial_rounds_chain_output_limb_26_col221;let poseidon_3_partial_rounds_chain_output_limb_27_col222 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(7);
            *row[222] = poseidon_3_partial_rounds_chain_output_limb_27_col222;let poseidon_3_partial_rounds_chain_output_limb_28_col223 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(8);
            *row[223] = poseidon_3_partial_rounds_chain_output_limb_28_col223;let poseidon_3_partial_rounds_chain_output_limb_29_col224 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2].get_m31(9);
            *row[224] = poseidon_3_partial_rounds_chain_output_limb_29_col224;let poseidon_3_partial_rounds_chain_output_limb_30_col225 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(0);
            *row[225] = poseidon_3_partial_rounds_chain_output_limb_30_col225;let poseidon_3_partial_rounds_chain_output_limb_31_col226 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(1);
            *row[226] = poseidon_3_partial_rounds_chain_output_limb_31_col226;let poseidon_3_partial_rounds_chain_output_limb_32_col227 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(2);
            *row[227] = poseidon_3_partial_rounds_chain_output_limb_32_col227;let poseidon_3_partial_rounds_chain_output_limb_33_col228 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(3);
            *row[228] = poseidon_3_partial_rounds_chain_output_limb_33_col228;let poseidon_3_partial_rounds_chain_output_limb_34_col229 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(4);
            *row[229] = poseidon_3_partial_rounds_chain_output_limb_34_col229;let poseidon_3_partial_rounds_chain_output_limb_35_col230 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(5);
            *row[230] = poseidon_3_partial_rounds_chain_output_limb_35_col230;let poseidon_3_partial_rounds_chain_output_limb_36_col231 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(6);
            *row[231] = poseidon_3_partial_rounds_chain_output_limb_36_col231;let poseidon_3_partial_rounds_chain_output_limb_37_col232 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(7);
            *row[232] = poseidon_3_partial_rounds_chain_output_limb_37_col232;let poseidon_3_partial_rounds_chain_output_limb_38_col233 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(8);
            *row[233] = poseidon_3_partial_rounds_chain_output_limb_38_col233;let poseidon_3_partial_rounds_chain_output_limb_39_col234 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3].get_m31(9);
            *row[234] = poseidon_3_partial_rounds_chain_output_limb_39_col234;*lookup_data.poseidon_3_partial_rounds_chain_15 = [M31_1343313504, seq, M31_31, poseidon_3_partial_rounds_chain_output_limb_0_col195, poseidon_3_partial_rounds_chain_output_limb_1_col196, poseidon_3_partial_rounds_chain_output_limb_2_col197, poseidon_3_partial_rounds_chain_output_limb_3_col198, poseidon_3_partial_rounds_chain_output_limb_4_col199, poseidon_3_partial_rounds_chain_output_limb_5_col200, poseidon_3_partial_rounds_chain_output_limb_6_col201, poseidon_3_partial_rounds_chain_output_limb_7_col202, poseidon_3_partial_rounds_chain_output_limb_8_col203, poseidon_3_partial_rounds_chain_output_limb_9_col204, poseidon_3_partial_rounds_chain_output_limb_10_col205, poseidon_3_partial_rounds_chain_output_limb_11_col206, poseidon_3_partial_rounds_chain_output_limb_12_col207, poseidon_3_partial_rounds_chain_output_limb_13_col208, poseidon_3_partial_rounds_chain_output_limb_14_col209, poseidon_3_partial_rounds_chain_output_limb_15_col210, poseidon_3_partial_rounds_chain_output_limb_16_col211, poseidon_3_partial_rounds_chain_output_limb_17_col212, poseidon_3_partial_rounds_chain_output_limb_18_col213, poseidon_3_partial_rounds_chain_output_limb_19_col214, poseidon_3_partial_rounds_chain_output_limb_20_col215, poseidon_3_partial_rounds_chain_output_limb_21_col216, poseidon_3_partial_rounds_chain_output_limb_22_col217, poseidon_3_partial_rounds_chain_output_limb_23_col218, poseidon_3_partial_rounds_chain_output_limb_24_col219, poseidon_3_partial_rounds_chain_output_limb_25_col220, poseidon_3_partial_rounds_chain_output_limb_26_col221, poseidon_3_partial_rounds_chain_output_limb_27_col222, poseidon_3_partial_rounds_chain_output_limb_28_col223, poseidon_3_partial_rounds_chain_output_limb_29_col224, poseidon_3_partial_rounds_chain_output_limb_30_col225, poseidon_3_partial_rounds_chain_output_limb_31_col226, poseidon_3_partial_rounds_chain_output_limb_32_col227, poseidon_3_partial_rounds_chain_output_limb_33_col228, poseidon_3_partial_rounds_chain_output_limb_34_col229, poseidon_3_partial_rounds_chain_output_limb_35_col230, poseidon_3_partial_rounds_chain_output_limb_36_col231, poseidon_3_partial_rounds_chain_output_limb_37_col232, poseidon_3_partial_rounds_chain_output_limb_38_col233, poseidon_3_partial_rounds_chain_output_limb_39_col234];

            // Linear Combination N 4 Coefs 4 2 1 1.

            let combination_tmp_3806f_131 = PackedFelt252Width27::from_packed_felt252(((((((((Felt252_0_0_0_0) + (((Felt252_4_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0])))))) + (((Felt252_2_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1])))))) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2])))))) + (Felt252_3969818800901670911_10562874008078701503_14906396266795319764_223312371439046257)));let combination_limb_0_col235 = combination_tmp_3806f_131.get_m31(0);
            *row[235] = combination_limb_0_col235;let combination_limb_1_col236 = combination_tmp_3806f_131.get_m31(1);
            *row[236] = combination_limb_1_col236;let combination_limb_2_col237 = combination_tmp_3806f_131.get_m31(2);
            *row[237] = combination_limb_2_col237;let combination_limb_3_col238 = combination_tmp_3806f_131.get_m31(3);
            *row[238] = combination_limb_3_col238;let combination_limb_4_col239 = combination_tmp_3806f_131.get_m31(4);
            *row[239] = combination_limb_4_col239;let combination_limb_5_col240 = combination_tmp_3806f_131.get_m31(5);
            *row[240] = combination_limb_5_col240;let combination_limb_6_col241 = combination_tmp_3806f_131.get_m31(6);
            *row[241] = combination_limb_6_col241;let combination_limb_7_col242 = combination_tmp_3806f_131.get_m31(7);
            *row[242] = combination_limb_7_col242;let combination_limb_8_col243 = combination_tmp_3806f_131.get_m31(8);
            *row[243] = combination_limb_8_col243;let combination_limb_9_col244 = combination_tmp_3806f_131.get_m31(9);
            *row[244] = combination_limb_9_col244;let biased_limb_accumulator_u32_tmp_3806f_132 = PackedUInt32::from_m31(((((((((((((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_0_col195))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_10_col205))))) + (poseidon_3_partial_rounds_chain_output_limb_20_col215))) + (M31_40454143))) - (combination_limb_0_col235))) + (M31_134217729)));let p_coef_col245 = ((biased_limb_accumulator_u32_tmp_3806f_132.low().as_m31()) - (M31_1));
            *row[245] = p_coef_col245;let carry_0_tmp_3806f_133 = ((((((((((((((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_0_col195))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_10_col205))))) + (poseidon_3_partial_rounds_chain_output_limb_20_col215))) + (M31_40454143))) - (combination_limb_0_col235))) - (p_coef_col245))) * (M31_16));let carry_1_tmp_3806f_134 = ((((((((((((carry_0_tmp_3806f_133) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_1_col196))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_11_col206))))) + (poseidon_3_partial_rounds_chain_output_limb_21_col216))) + (M31_49554771))) - (combination_limb_1_col236))) * (M31_16));let carry_2_tmp_3806f_135 = ((((((((((((carry_1_tmp_3806f_134) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_2_col197))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_12_col207))))) + (poseidon_3_partial_rounds_chain_output_limb_22_col217))) + (M31_55508188))) - (combination_limb_2_col237))) * (M31_16));let carry_3_tmp_3806f_136 = ((((((((((((carry_2_tmp_3806f_135) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_3_col198))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_13_col208))))) + (poseidon_3_partial_rounds_chain_output_limb_23_col218))) + (M31_116986206))) - (combination_limb_3_col238))) * (M31_16));let carry_4_tmp_3806f_137 = ((((((((((((carry_3_tmp_3806f_136) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_4_col199))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_14_col209))))) + (poseidon_3_partial_rounds_chain_output_limb_24_col219))) + (M31_88680813))) - (combination_limb_4_col239))) * (M31_16));let carry_5_tmp_3806f_138 = ((((((((((((carry_4_tmp_3806f_137) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_5_col200))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_15_col210))))) + (poseidon_3_partial_rounds_chain_output_limb_25_col220))) + (M31_45553283))) - (combination_limb_5_col240))) * (M31_16));let carry_6_tmp_3806f_139 = ((((((((((((carry_5_tmp_3806f_138) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_6_col201))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_16_col211))))) + (poseidon_3_partial_rounds_chain_output_limb_26_col221))) + (M31_62360091))) - (combination_limb_6_col241))) * (M31_16));let carry_7_tmp_3806f_140 = ((((((((((((((carry_6_tmp_3806f_139) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_7_col202))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_17_col212))))) + (poseidon_3_partial_rounds_chain_output_limb_27_col222))) + (M31_77099918))) - (combination_limb_7_col242))) - (((p_coef_col245) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_141 = ((((((((((((carry_7_tmp_3806f_140) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_8_col203))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_18_col213))))) + (poseidon_3_partial_rounds_chain_output_limb_28_col223))) + (M31_22899501))) - (combination_limb_8_col243))) * (M31_16));*sub_component_inputs.range_check_4_4_4_4[2] =
                [((p_coef_col245) + (M31_1)), ((carry_0_tmp_3806f_133) + (M31_1)), ((carry_1_tmp_3806f_134) + (M31_1)), ((carry_2_tmp_3806f_135) + (M31_1))];
            *lookup_data.range_check_4_4_4_4_16 = [M31_1027333874, ((p_coef_col245) + (M31_1)), ((carry_0_tmp_3806f_133) + (M31_1)), ((carry_1_tmp_3806f_134) + (M31_1)), ((carry_2_tmp_3806f_135) + (M31_1))];*sub_component_inputs.range_check_4_4_4_4[3] =
                [((carry_3_tmp_3806f_136) + (M31_1)), ((carry_4_tmp_3806f_137) + (M31_1)), ((carry_5_tmp_3806f_138) + (M31_1)), ((carry_6_tmp_3806f_139) + (M31_1))];
            *lookup_data.range_check_4_4_4_4_17 = [M31_1027333874, ((carry_3_tmp_3806f_136) + (M31_1)), ((carry_4_tmp_3806f_137) + (M31_1)), ((carry_5_tmp_3806f_138) + (M31_1)), ((carry_6_tmp_3806f_139) + (M31_1))];*sub_component_inputs.range_check_4_4[1] =
                [((carry_7_tmp_3806f_140) + (M31_1)), ((carry_8_tmp_3806f_141) + (M31_1))];
            *lookup_data.range_check_4_4_18 = [M31_1651211826, ((carry_7_tmp_3806f_140) + (M31_1)), ((carry_8_tmp_3806f_141) + (M31_1))];let linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142 = combination_tmp_3806f_131;

            // Linear Combination N 4 Coefs 4 2 1 1.

            let combination_tmp_3806f_143 = PackedFelt252Width27::from_packed_felt252(((((((((Felt252_0_0_0_0) + (((Felt252_4_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2])))))) + (((Felt252_2_0_0_0) * (PackedFelt252::from_packed_felt252width27(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3])))))) + (((Felt252_1_0_0_0) * (PackedFelt252::from_packed_felt252width27(linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142)))))) + (Felt252_10310704347937391837_5874215448258336115_2880320859071049537_45350836576946303)));let combination_limb_0_col246 = combination_tmp_3806f_143.get_m31(0);
            *row[246] = combination_limb_0_col246;let combination_limb_1_col247 = combination_tmp_3806f_143.get_m31(1);
            *row[247] = combination_limb_1_col247;let combination_limb_2_col248 = combination_tmp_3806f_143.get_m31(2);
            *row[248] = combination_limb_2_col248;let combination_limb_3_col249 = combination_tmp_3806f_143.get_m31(3);
            *row[249] = combination_limb_3_col249;let combination_limb_4_col250 = combination_tmp_3806f_143.get_m31(4);
            *row[250] = combination_limb_4_col250;let combination_limb_5_col251 = combination_tmp_3806f_143.get_m31(5);
            *row[251] = combination_limb_5_col251;let combination_limb_6_col252 = combination_tmp_3806f_143.get_m31(6);
            *row[252] = combination_limb_6_col252;let combination_limb_7_col253 = combination_tmp_3806f_143.get_m31(7);
            *row[253] = combination_limb_7_col253;let combination_limb_8_col254 = combination_tmp_3806f_143.get_m31(8);
            *row[254] = combination_limb_8_col254;let combination_limb_9_col255 = combination_tmp_3806f_143.get_m31(9);
            *row[255] = combination_limb_9_col255;let biased_limb_accumulator_u32_tmp_3806f_144 = PackedUInt32::from_m31(((((((((((((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_20_col215))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_30_col225))))) + (combination_limb_0_col235))) + (M31_48383197))) - (combination_limb_0_col246))) + (M31_134217729)));let p_coef_col256 = ((biased_limb_accumulator_u32_tmp_3806f_144.low().as_m31()) - (M31_1));
            *row[256] = p_coef_col256;let carry_0_tmp_3806f_145 = ((((((((((((((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_20_col215))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_30_col225))))) + (combination_limb_0_col235))) + (M31_48383197))) - (combination_limb_0_col246))) - (p_coef_col256))) * (M31_16));let carry_1_tmp_3806f_146 = ((((((((((((carry_0_tmp_3806f_145) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_21_col216))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_31_col226))))) + (combination_limb_1_col236))) + (M31_48193339))) - (combination_limb_1_col247))) * (M31_16));let carry_2_tmp_3806f_147 = ((((((((((((carry_1_tmp_3806f_146) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_22_col217))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_32_col227))))) + (combination_limb_2_col237))) + (M31_55955004))) - (combination_limb_2_col248))) * (M31_16));let carry_3_tmp_3806f_148 = ((((((((((((carry_2_tmp_3806f_147) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_23_col218))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_33_col228))))) + (combination_limb_3_col238))) + (M31_65659846))) - (combination_limb_3_col249))) * (M31_16));let carry_4_tmp_3806f_149 = ((((((((((((carry_3_tmp_3806f_148) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_24_col219))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_34_col229))))) + (combination_limb_4_col239))) + (M31_68491350))) - (combination_limb_4_col250))) * (M31_16));let carry_5_tmp_3806f_150 = ((((((((((((carry_4_tmp_3806f_149) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_25_col220))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_35_col230))))) + (combination_limb_5_col240))) + (M31_119023582))) - (combination_limb_5_col251))) * (M31_16));let carry_6_tmp_3806f_151 = ((((((((((((carry_5_tmp_3806f_150) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_26_col221))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_36_col231))))) + (combination_limb_6_col241))) + (M31_33439011))) - (combination_limb_6_col252))) * (M31_16));let carry_7_tmp_3806f_152 = ((((((((((((((carry_6_tmp_3806f_151) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_27_col222))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_37_col232))))) + (combination_limb_7_col242))) + (M31_58475513))) - (combination_limb_7_col253))) - (((p_coef_col256) * (M31_136))))) * (M31_16));let carry_8_tmp_3806f_153 = ((((((((((((carry_7_tmp_3806f_152) + (((M31_4) * (poseidon_3_partial_rounds_chain_output_limb_28_col223))))) + (((M31_2) * (poseidon_3_partial_rounds_chain_output_limb_38_col233))))) + (combination_limb_8_col243))) + (M31_18765944))) - (combination_limb_8_col254))) * (M31_16));*sub_component_inputs.range_check_4_4_4_4[4] =
                [((p_coef_col256) + (M31_1)), ((carry_0_tmp_3806f_145) + (M31_1)), ((carry_1_tmp_3806f_146) + (M31_1)), ((carry_2_tmp_3806f_147) + (M31_1))];
            *lookup_data.range_check_4_4_4_4_19 = [M31_1027333874, ((p_coef_col256) + (M31_1)), ((carry_0_tmp_3806f_145) + (M31_1)), ((carry_1_tmp_3806f_146) + (M31_1)), ((carry_2_tmp_3806f_147) + (M31_1))];*sub_component_inputs.range_check_4_4_4_4[5] =
                [((carry_3_tmp_3806f_148) + (M31_1)), ((carry_4_tmp_3806f_149) + (M31_1)), ((carry_5_tmp_3806f_150) + (M31_1)), ((carry_6_tmp_3806f_151) + (M31_1))];
            *lookup_data.range_check_4_4_4_4_20 = [M31_1027333874, ((carry_3_tmp_3806f_148) + (M31_1)), ((carry_4_tmp_3806f_149) + (M31_1)), ((carry_5_tmp_3806f_150) + (M31_1)), ((carry_6_tmp_3806f_151) + (M31_1))];*sub_component_inputs.range_check_4_4[2] =
                [((carry_7_tmp_3806f_152) + (M31_1)), ((carry_8_tmp_3806f_153) + (M31_1))];
            *lookup_data.range_check_4_4_21 = [M31_1651211826, ((carry_7_tmp_3806f_152) + (M31_1)), ((carry_8_tmp_3806f_153) + (M31_1))];let linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154 = combination_tmp_3806f_143;

            let poseidon_full_round_chain_chain_id_tmp_3806f_155 = ((poseidon_full_round_chain_chain_tmp_tmp_3806f_72) + (M31_1));*lookup_data.poseidon_full_round_chain_22 = [M31_1480369132, poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_31, combination_limb_0_col246, combination_limb_1_col247, combination_limb_2_col248, combination_limb_3_col249, combination_limb_4_col250, combination_limb_5_col251, combination_limb_6_col252, combination_limb_7_col253, combination_limb_8_col254, combination_limb_9_col255, combination_limb_0_col235, combination_limb_1_col236, combination_limb_2_col237, combination_limb_3_col238, combination_limb_4_col239, combination_limb_5_col240, combination_limb_6_col241, combination_limb_7_col242, combination_limb_8_col243, combination_limb_9_col244, poseidon_3_partial_rounds_chain_output_limb_30_col225, poseidon_3_partial_rounds_chain_output_limb_31_col226, poseidon_3_partial_rounds_chain_output_limb_32_col227, poseidon_3_partial_rounds_chain_output_limb_33_col228, poseidon_3_partial_rounds_chain_output_limb_34_col229, poseidon_3_partial_rounds_chain_output_limb_35_col230, poseidon_3_partial_rounds_chain_output_limb_36_col231, poseidon_3_partial_rounds_chain_output_limb_37_col232, poseidon_3_partial_rounds_chain_output_limb_38_col233, poseidon_3_partial_rounds_chain_output_limb_39_col234];*sub_component_inputs.poseidon_full_round_chain[4] =
                (poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_31, [linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154, linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142, poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3]]);
            let poseidon_full_round_chain_output_round_31_tmp_3806f_156 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_31, [linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154, linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142, poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3]]));*sub_component_inputs.poseidon_full_round_chain[5] =
                (poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_32, [poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[0], poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[1], poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[2]]);
            let poseidon_full_round_chain_output_round_32_tmp_3806f_157 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_32, [poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[0], poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[1], poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[2]]));*sub_component_inputs.poseidon_full_round_chain[6] =
                (poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_33, [poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[0], poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[1], poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[2]]);
            let poseidon_full_round_chain_output_round_33_tmp_3806f_158 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_33, [poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[0], poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[1], poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[2]]));*sub_component_inputs.poseidon_full_round_chain[7] =
                (poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_34, [poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[0], poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[1], poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[2]]);
            let poseidon_full_round_chain_output_round_34_tmp_3806f_159 = PackedPoseidonFullRoundChain::deduce_output((poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_34, [poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[0], poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[1], poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[2]]));let poseidon_full_round_chain_output_limb_0_col257 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(0);
            *row[257] = poseidon_full_round_chain_output_limb_0_col257;let poseidon_full_round_chain_output_limb_1_col258 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(1);
            *row[258] = poseidon_full_round_chain_output_limb_1_col258;let poseidon_full_round_chain_output_limb_2_col259 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(2);
            *row[259] = poseidon_full_round_chain_output_limb_2_col259;let poseidon_full_round_chain_output_limb_3_col260 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(3);
            *row[260] = poseidon_full_round_chain_output_limb_3_col260;let poseidon_full_round_chain_output_limb_4_col261 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(4);
            *row[261] = poseidon_full_round_chain_output_limb_4_col261;let poseidon_full_round_chain_output_limb_5_col262 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(5);
            *row[262] = poseidon_full_round_chain_output_limb_5_col262;let poseidon_full_round_chain_output_limb_6_col263 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(6);
            *row[263] = poseidon_full_round_chain_output_limb_6_col263;let poseidon_full_round_chain_output_limb_7_col264 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(7);
            *row[264] = poseidon_full_round_chain_output_limb_7_col264;let poseidon_full_round_chain_output_limb_8_col265 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(8);
            *row[265] = poseidon_full_round_chain_output_limb_8_col265;let poseidon_full_round_chain_output_limb_9_col266 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0].get_m31(9);
            *row[266] = poseidon_full_round_chain_output_limb_9_col266;let poseidon_full_round_chain_output_limb_10_col267 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(0);
            *row[267] = poseidon_full_round_chain_output_limb_10_col267;let poseidon_full_round_chain_output_limb_11_col268 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(1);
            *row[268] = poseidon_full_round_chain_output_limb_11_col268;let poseidon_full_round_chain_output_limb_12_col269 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(2);
            *row[269] = poseidon_full_round_chain_output_limb_12_col269;let poseidon_full_round_chain_output_limb_13_col270 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(3);
            *row[270] = poseidon_full_round_chain_output_limb_13_col270;let poseidon_full_round_chain_output_limb_14_col271 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(4);
            *row[271] = poseidon_full_round_chain_output_limb_14_col271;let poseidon_full_round_chain_output_limb_15_col272 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(5);
            *row[272] = poseidon_full_round_chain_output_limb_15_col272;let poseidon_full_round_chain_output_limb_16_col273 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(6);
            *row[273] = poseidon_full_round_chain_output_limb_16_col273;let poseidon_full_round_chain_output_limb_17_col274 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(7);
            *row[274] = poseidon_full_round_chain_output_limb_17_col274;let poseidon_full_round_chain_output_limb_18_col275 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(8);
            *row[275] = poseidon_full_round_chain_output_limb_18_col275;let poseidon_full_round_chain_output_limb_19_col276 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1].get_m31(9);
            *row[276] = poseidon_full_round_chain_output_limb_19_col276;let poseidon_full_round_chain_output_limb_20_col277 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(0);
            *row[277] = poseidon_full_round_chain_output_limb_20_col277;let poseidon_full_round_chain_output_limb_21_col278 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(1);
            *row[278] = poseidon_full_round_chain_output_limb_21_col278;let poseidon_full_round_chain_output_limb_22_col279 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(2);
            *row[279] = poseidon_full_round_chain_output_limb_22_col279;let poseidon_full_round_chain_output_limb_23_col280 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(3);
            *row[280] = poseidon_full_round_chain_output_limb_23_col280;let poseidon_full_round_chain_output_limb_24_col281 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(4);
            *row[281] = poseidon_full_round_chain_output_limb_24_col281;let poseidon_full_round_chain_output_limb_25_col282 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(5);
            *row[282] = poseidon_full_round_chain_output_limb_25_col282;let poseidon_full_round_chain_output_limb_26_col283 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(6);
            *row[283] = poseidon_full_round_chain_output_limb_26_col283;let poseidon_full_round_chain_output_limb_27_col284 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(7);
            *row[284] = poseidon_full_round_chain_output_limb_27_col284;let poseidon_full_round_chain_output_limb_28_col285 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(8);
            *row[285] = poseidon_full_round_chain_output_limb_28_col285;let poseidon_full_round_chain_output_limb_29_col286 = poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2].get_m31(9);
            *row[286] = poseidon_full_round_chain_output_limb_29_col286;*lookup_data.poseidon_full_round_chain_23 = [M31_1480369132, poseidon_full_round_chain_chain_id_tmp_3806f_155, M31_35, poseidon_full_round_chain_output_limb_0_col257, poseidon_full_round_chain_output_limb_1_col258, poseidon_full_round_chain_output_limb_2_col259, poseidon_full_round_chain_output_limb_3_col260, poseidon_full_round_chain_output_limb_4_col261, poseidon_full_round_chain_output_limb_5_col262, poseidon_full_round_chain_output_limb_6_col263, poseidon_full_round_chain_output_limb_7_col264, poseidon_full_round_chain_output_limb_8_col265, poseidon_full_round_chain_output_limb_9_col266, poseidon_full_round_chain_output_limb_10_col267, poseidon_full_round_chain_output_limb_11_col268, poseidon_full_round_chain_output_limb_12_col269, poseidon_full_round_chain_output_limb_13_col270, poseidon_full_round_chain_output_limb_14_col271, poseidon_full_round_chain_output_limb_15_col272, poseidon_full_round_chain_output_limb_16_col273, poseidon_full_round_chain_output_limb_17_col274, poseidon_full_round_chain_output_limb_18_col275, poseidon_full_round_chain_output_limb_19_col276, poseidon_full_round_chain_output_limb_20_col277, poseidon_full_round_chain_output_limb_21_col278, poseidon_full_round_chain_output_limb_22_col279, poseidon_full_round_chain_output_limb_23_col280, poseidon_full_round_chain_output_limb_24_col281, poseidon_full_round_chain_output_limb_25_col282, poseidon_full_round_chain_output_limb_26_col283, poseidon_full_round_chain_output_limb_27_col284, poseidon_full_round_chain_output_limb_28_col285, poseidon_full_round_chain_output_limb_29_col286];let poseidon_hades_permutation_output_tmp_3806f_160 = [poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0], poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1], poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2]];

            // Felt 252 Unpack From 27.

            let input_as_felt252_tmp_3806f_161 = PackedFelt252::from_packed_felt252width27(poseidon_hades_permutation_output_tmp_3806f_160[0]);let unpacked_limb_0_col287 = input_as_felt252_tmp_3806f_161.get_m31(0);
            *row[287] = unpacked_limb_0_col287;let unpacked_limb_1_col288 = input_as_felt252_tmp_3806f_161.get_m31(1);
            *row[288] = unpacked_limb_1_col288;let unpacked_limb_3_col289 = input_as_felt252_tmp_3806f_161.get_m31(3);
            *row[289] = unpacked_limb_3_col289;let unpacked_limb_4_col290 = input_as_felt252_tmp_3806f_161.get_m31(4);
            *row[290] = unpacked_limb_4_col290;let unpacked_limb_6_col291 = input_as_felt252_tmp_3806f_161.get_m31(6);
            *row[291] = unpacked_limb_6_col291;let unpacked_limb_7_col292 = input_as_felt252_tmp_3806f_161.get_m31(7);
            *row[292] = unpacked_limb_7_col292;let unpacked_limb_9_col293 = input_as_felt252_tmp_3806f_161.get_m31(9);
            *row[293] = unpacked_limb_9_col293;let unpacked_limb_10_col294 = input_as_felt252_tmp_3806f_161.get_m31(10);
            *row[294] = unpacked_limb_10_col294;let unpacked_limb_12_col295 = input_as_felt252_tmp_3806f_161.get_m31(12);
            *row[295] = unpacked_limb_12_col295;let unpacked_limb_13_col296 = input_as_felt252_tmp_3806f_161.get_m31(13);
            *row[296] = unpacked_limb_13_col296;let unpacked_limb_15_col297 = input_as_felt252_tmp_3806f_161.get_m31(15);
            *row[297] = unpacked_limb_15_col297;let unpacked_limb_16_col298 = input_as_felt252_tmp_3806f_161.get_m31(16);
            *row[298] = unpacked_limb_16_col298;let unpacked_limb_18_col299 = input_as_felt252_tmp_3806f_161.get_m31(18);
            *row[299] = unpacked_limb_18_col299;let unpacked_limb_19_col300 = input_as_felt252_tmp_3806f_161.get_m31(19);
            *row[300] = unpacked_limb_19_col300;let unpacked_limb_21_col301 = input_as_felt252_tmp_3806f_161.get_m31(21);
            *row[301] = unpacked_limb_21_col301;let unpacked_limb_22_col302 = input_as_felt252_tmp_3806f_161.get_m31(22);
            *row[302] = unpacked_limb_22_col302;let unpacked_limb_24_col303 = input_as_felt252_tmp_3806f_161.get_m31(24);
            *row[303] = unpacked_limb_24_col303;let unpacked_limb_25_col304 = input_as_felt252_tmp_3806f_161.get_m31(25);
            *row[304] = unpacked_limb_25_col304;let felt_252_unpack_from_27_output_tmp_3806f_162 = PackedFelt252::from_limbs([unpacked_limb_0_col287, unpacked_limb_1_col288, ((((((poseidon_full_round_chain_output_limb_0_col257) - (unpacked_limb_0_col287))) - (((unpacked_limb_1_col288) * (M31_512))))) * (M31_8192)), unpacked_limb_3_col289, unpacked_limb_4_col290, ((((((poseidon_full_round_chain_output_limb_1_col258) - (unpacked_limb_3_col289))) - (((unpacked_limb_4_col290) * (M31_512))))) * (M31_8192)), unpacked_limb_6_col291, unpacked_limb_7_col292, ((((((poseidon_full_round_chain_output_limb_2_col259) - (unpacked_limb_6_col291))) - (((unpacked_limb_7_col292) * (M31_512))))) * (M31_8192)), unpacked_limb_9_col293, unpacked_limb_10_col294, ((((((poseidon_full_round_chain_output_limb_3_col260) - (unpacked_limb_9_col293))) - (((unpacked_limb_10_col294) * (M31_512))))) * (M31_8192)), unpacked_limb_12_col295, unpacked_limb_13_col296, ((((((poseidon_full_round_chain_output_limb_4_col261) - (unpacked_limb_12_col295))) - (((unpacked_limb_13_col296) * (M31_512))))) * (M31_8192)), unpacked_limb_15_col297, unpacked_limb_16_col298, ((((((poseidon_full_round_chain_output_limb_5_col262) - (unpacked_limb_15_col297))) - (((unpacked_limb_16_col298) * (M31_512))))) * (M31_8192)), unpacked_limb_18_col299, unpacked_limb_19_col300, ((((((poseidon_full_round_chain_output_limb_6_col263) - (unpacked_limb_18_col299))) - (((unpacked_limb_19_col300) * (M31_512))))) * (M31_8192)), unpacked_limb_21_col301, unpacked_limb_22_col302, ((((((poseidon_full_round_chain_output_limb_7_col264) - (unpacked_limb_21_col301))) - (((unpacked_limb_22_col302) * (M31_512))))) * (M31_8192)), unpacked_limb_24_col303, unpacked_limb_25_col304, ((((((poseidon_full_round_chain_output_limb_8_col265) - (unpacked_limb_24_col303))) - (((unpacked_limb_25_col304) * (M31_512))))) * (M31_8192)), poseidon_full_round_chain_output_limb_9_col266]);

            *sub_component_inputs.memory_id_to_big[3] =
                input_limb_3_col3;
            *lookup_data.memory_id_to_big_24 = [M31_1662111297, input_limb_3_col3, unpacked_limb_0_col287, unpacked_limb_1_col288, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(2), unpacked_limb_3_col289, unpacked_limb_4_col290, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(5), unpacked_limb_6_col291, unpacked_limb_7_col292, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(8), unpacked_limb_9_col293, unpacked_limb_10_col294, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(11), unpacked_limb_12_col295, unpacked_limb_13_col296, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(14), unpacked_limb_15_col297, unpacked_limb_16_col298, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(17), unpacked_limb_18_col299, unpacked_limb_19_col300, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(20), unpacked_limb_21_col301, unpacked_limb_22_col302, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(23), unpacked_limb_24_col303, unpacked_limb_25_col304, felt_252_unpack_from_27_output_tmp_3806f_162.get_m31(26), poseidon_full_round_chain_output_limb_9_col266];

            // Felt 252 Unpack From 27.

            let input_as_felt252_tmp_3806f_163 = PackedFelt252::from_packed_felt252width27(poseidon_hades_permutation_output_tmp_3806f_160[1]);let unpacked_limb_0_col305 = input_as_felt252_tmp_3806f_163.get_m31(0);
            *row[305] = unpacked_limb_0_col305;let unpacked_limb_1_col306 = input_as_felt252_tmp_3806f_163.get_m31(1);
            *row[306] = unpacked_limb_1_col306;let unpacked_limb_3_col307 = input_as_felt252_tmp_3806f_163.get_m31(3);
            *row[307] = unpacked_limb_3_col307;let unpacked_limb_4_col308 = input_as_felt252_tmp_3806f_163.get_m31(4);
            *row[308] = unpacked_limb_4_col308;let unpacked_limb_6_col309 = input_as_felt252_tmp_3806f_163.get_m31(6);
            *row[309] = unpacked_limb_6_col309;let unpacked_limb_7_col310 = input_as_felt252_tmp_3806f_163.get_m31(7);
            *row[310] = unpacked_limb_7_col310;let unpacked_limb_9_col311 = input_as_felt252_tmp_3806f_163.get_m31(9);
            *row[311] = unpacked_limb_9_col311;let unpacked_limb_10_col312 = input_as_felt252_tmp_3806f_163.get_m31(10);
            *row[312] = unpacked_limb_10_col312;let unpacked_limb_12_col313 = input_as_felt252_tmp_3806f_163.get_m31(12);
            *row[313] = unpacked_limb_12_col313;let unpacked_limb_13_col314 = input_as_felt252_tmp_3806f_163.get_m31(13);
            *row[314] = unpacked_limb_13_col314;let unpacked_limb_15_col315 = input_as_felt252_tmp_3806f_163.get_m31(15);
            *row[315] = unpacked_limb_15_col315;let unpacked_limb_16_col316 = input_as_felt252_tmp_3806f_163.get_m31(16);
            *row[316] = unpacked_limb_16_col316;let unpacked_limb_18_col317 = input_as_felt252_tmp_3806f_163.get_m31(18);
            *row[317] = unpacked_limb_18_col317;let unpacked_limb_19_col318 = input_as_felt252_tmp_3806f_163.get_m31(19);
            *row[318] = unpacked_limb_19_col318;let unpacked_limb_21_col319 = input_as_felt252_tmp_3806f_163.get_m31(21);
            *row[319] = unpacked_limb_21_col319;let unpacked_limb_22_col320 = input_as_felt252_tmp_3806f_163.get_m31(22);
            *row[320] = unpacked_limb_22_col320;let unpacked_limb_24_col321 = input_as_felt252_tmp_3806f_163.get_m31(24);
            *row[321] = unpacked_limb_24_col321;let unpacked_limb_25_col322 = input_as_felt252_tmp_3806f_163.get_m31(25);
            *row[322] = unpacked_limb_25_col322;let felt_252_unpack_from_27_output_tmp_3806f_164 = PackedFelt252::from_limbs([unpacked_limb_0_col305, unpacked_limb_1_col306, ((((((poseidon_full_round_chain_output_limb_10_col267) - (unpacked_limb_0_col305))) - (((unpacked_limb_1_col306) * (M31_512))))) * (M31_8192)), unpacked_limb_3_col307, unpacked_limb_4_col308, ((((((poseidon_full_round_chain_output_limb_11_col268) - (unpacked_limb_3_col307))) - (((unpacked_limb_4_col308) * (M31_512))))) * (M31_8192)), unpacked_limb_6_col309, unpacked_limb_7_col310, ((((((poseidon_full_round_chain_output_limb_12_col269) - (unpacked_limb_6_col309))) - (((unpacked_limb_7_col310) * (M31_512))))) * (M31_8192)), unpacked_limb_9_col311, unpacked_limb_10_col312, ((((((poseidon_full_round_chain_output_limb_13_col270) - (unpacked_limb_9_col311))) - (((unpacked_limb_10_col312) * (M31_512))))) * (M31_8192)), unpacked_limb_12_col313, unpacked_limb_13_col314, ((((((poseidon_full_round_chain_output_limb_14_col271) - (unpacked_limb_12_col313))) - (((unpacked_limb_13_col314) * (M31_512))))) * (M31_8192)), unpacked_limb_15_col315, unpacked_limb_16_col316, ((((((poseidon_full_round_chain_output_limb_15_col272) - (unpacked_limb_15_col315))) - (((unpacked_limb_16_col316) * (M31_512))))) * (M31_8192)), unpacked_limb_18_col317, unpacked_limb_19_col318, ((((((poseidon_full_round_chain_output_limb_16_col273) - (unpacked_limb_18_col317))) - (((unpacked_limb_19_col318) * (M31_512))))) * (M31_8192)), unpacked_limb_21_col319, unpacked_limb_22_col320, ((((((poseidon_full_round_chain_output_limb_17_col274) - (unpacked_limb_21_col319))) - (((unpacked_limb_22_col320) * (M31_512))))) * (M31_8192)), unpacked_limb_24_col321, unpacked_limb_25_col322, ((((((poseidon_full_round_chain_output_limb_18_col275) - (unpacked_limb_24_col321))) - (((unpacked_limb_25_col322) * (M31_512))))) * (M31_8192)), poseidon_full_round_chain_output_limb_19_col276]);

            *sub_component_inputs.memory_id_to_big[4] =
                input_limb_4_col4;
            *lookup_data.memory_id_to_big_25 = [M31_1662111297, input_limb_4_col4, unpacked_limb_0_col305, unpacked_limb_1_col306, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(2), unpacked_limb_3_col307, unpacked_limb_4_col308, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(5), unpacked_limb_6_col309, unpacked_limb_7_col310, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(8), unpacked_limb_9_col311, unpacked_limb_10_col312, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(11), unpacked_limb_12_col313, unpacked_limb_13_col314, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(14), unpacked_limb_15_col315, unpacked_limb_16_col316, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(17), unpacked_limb_18_col317, unpacked_limb_19_col318, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(20), unpacked_limb_21_col319, unpacked_limb_22_col320, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(23), unpacked_limb_24_col321, unpacked_limb_25_col322, felt_252_unpack_from_27_output_tmp_3806f_164.get_m31(26), poseidon_full_round_chain_output_limb_19_col276];

            // Felt 252 Unpack From 27.

            let input_as_felt252_tmp_3806f_165 = PackedFelt252::from_packed_felt252width27(poseidon_hades_permutation_output_tmp_3806f_160[2]);let unpacked_limb_0_col323 = input_as_felt252_tmp_3806f_165.get_m31(0);
            *row[323] = unpacked_limb_0_col323;let unpacked_limb_1_col324 = input_as_felt252_tmp_3806f_165.get_m31(1);
            *row[324] = unpacked_limb_1_col324;let unpacked_limb_3_col325 = input_as_felt252_tmp_3806f_165.get_m31(3);
            *row[325] = unpacked_limb_3_col325;let unpacked_limb_4_col326 = input_as_felt252_tmp_3806f_165.get_m31(4);
            *row[326] = unpacked_limb_4_col326;let unpacked_limb_6_col327 = input_as_felt252_tmp_3806f_165.get_m31(6);
            *row[327] = unpacked_limb_6_col327;let unpacked_limb_7_col328 = input_as_felt252_tmp_3806f_165.get_m31(7);
            *row[328] = unpacked_limb_7_col328;let unpacked_limb_9_col329 = input_as_felt252_tmp_3806f_165.get_m31(9);
            *row[329] = unpacked_limb_9_col329;let unpacked_limb_10_col330 = input_as_felt252_tmp_3806f_165.get_m31(10);
            *row[330] = unpacked_limb_10_col330;let unpacked_limb_12_col331 = input_as_felt252_tmp_3806f_165.get_m31(12);
            *row[331] = unpacked_limb_12_col331;let unpacked_limb_13_col332 = input_as_felt252_tmp_3806f_165.get_m31(13);
            *row[332] = unpacked_limb_13_col332;let unpacked_limb_15_col333 = input_as_felt252_tmp_3806f_165.get_m31(15);
            *row[333] = unpacked_limb_15_col333;let unpacked_limb_16_col334 = input_as_felt252_tmp_3806f_165.get_m31(16);
            *row[334] = unpacked_limb_16_col334;let unpacked_limb_18_col335 = input_as_felt252_tmp_3806f_165.get_m31(18);
            *row[335] = unpacked_limb_18_col335;let unpacked_limb_19_col336 = input_as_felt252_tmp_3806f_165.get_m31(19);
            *row[336] = unpacked_limb_19_col336;let unpacked_limb_21_col337 = input_as_felt252_tmp_3806f_165.get_m31(21);
            *row[337] = unpacked_limb_21_col337;let unpacked_limb_22_col338 = input_as_felt252_tmp_3806f_165.get_m31(22);
            *row[338] = unpacked_limb_22_col338;let unpacked_limb_24_col339 = input_as_felt252_tmp_3806f_165.get_m31(24);
            *row[339] = unpacked_limb_24_col339;let unpacked_limb_25_col340 = input_as_felt252_tmp_3806f_165.get_m31(25);
            *row[340] = unpacked_limb_25_col340;let felt_252_unpack_from_27_output_tmp_3806f_166 = PackedFelt252::from_limbs([unpacked_limb_0_col323, unpacked_limb_1_col324, ((((((poseidon_full_round_chain_output_limb_20_col277) - (unpacked_limb_0_col323))) - (((unpacked_limb_1_col324) * (M31_512))))) * (M31_8192)), unpacked_limb_3_col325, unpacked_limb_4_col326, ((((((poseidon_full_round_chain_output_limb_21_col278) - (unpacked_limb_3_col325))) - (((unpacked_limb_4_col326) * (M31_512))))) * (M31_8192)), unpacked_limb_6_col327, unpacked_limb_7_col328, ((((((poseidon_full_round_chain_output_limb_22_col279) - (unpacked_limb_6_col327))) - (((unpacked_limb_7_col328) * (M31_512))))) * (M31_8192)), unpacked_limb_9_col329, unpacked_limb_10_col330, ((((((poseidon_full_round_chain_output_limb_23_col280) - (unpacked_limb_9_col329))) - (((unpacked_limb_10_col330) * (M31_512))))) * (M31_8192)), unpacked_limb_12_col331, unpacked_limb_13_col332, ((((((poseidon_full_round_chain_output_limb_24_col281) - (unpacked_limb_12_col331))) - (((unpacked_limb_13_col332) * (M31_512))))) * (M31_8192)), unpacked_limb_15_col333, unpacked_limb_16_col334, ((((((poseidon_full_round_chain_output_limb_25_col282) - (unpacked_limb_15_col333))) - (((unpacked_limb_16_col334) * (M31_512))))) * (M31_8192)), unpacked_limb_18_col335, unpacked_limb_19_col336, ((((((poseidon_full_round_chain_output_limb_26_col283) - (unpacked_limb_18_col335))) - (((unpacked_limb_19_col336) * (M31_512))))) * (M31_8192)), unpacked_limb_21_col337, unpacked_limb_22_col338, ((((((poseidon_full_round_chain_output_limb_27_col284) - (unpacked_limb_21_col337))) - (((unpacked_limb_22_col338) * (M31_512))))) * (M31_8192)), unpacked_limb_24_col339, unpacked_limb_25_col340, ((((((poseidon_full_round_chain_output_limb_28_col285) - (unpacked_limb_24_col339))) - (((unpacked_limb_25_col340) * (M31_512))))) * (M31_8192)), poseidon_full_round_chain_output_limb_29_col286]);

            *sub_component_inputs.memory_id_to_big[5] =
                input_limb_5_col5;
            *lookup_data.memory_id_to_big_26 = [M31_1662111297, input_limb_5_col5, unpacked_limb_0_col323, unpacked_limb_1_col324, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(2), unpacked_limb_3_col325, unpacked_limb_4_col326, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(5), unpacked_limb_6_col327, unpacked_limb_7_col328, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(8), unpacked_limb_9_col329, unpacked_limb_10_col330, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(11), unpacked_limb_12_col331, unpacked_limb_13_col332, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(14), unpacked_limb_15_col333, unpacked_limb_16_col334, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(17), unpacked_limb_18_col335, unpacked_limb_19_col336, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(20), unpacked_limb_21_col337, unpacked_limb_22_col338, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(23), unpacked_limb_24_col339, unpacked_limb_25_col340, felt_252_unpack_from_27_output_tmp_3806f_166.get_m31(26), poseidon_full_round_chain_output_limb_29_col286];let multiplicity_0_col341 = *mults[0].get(row_index).unwrap_or(&PackedM31::zero());
            *row[341] = multiplicity_0_col341;*lookup_data.poseidon_aggregator_27 = [M31_1551892206, input_limb_0_col0, input_limb_1_col1, input_limb_2_col2, input_limb_3_col3, input_limb_4_col4, input_limb_5_col5];*lookup_data.mults_0 = M31_1;*lookup_data.mults_1 = multiplicity_0_col341;
        });

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `poseidon_aggregator` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     memory_id_to_big_0[30] 0..29
//     memory_id_to_big_1[30] 30..59
//     memory_id_to_big_2[30] 60..89
//     poseidon_full_round_chain_3[33] 90..122
//     poseidon_full_round_chain_4[33] 123..155
//     range_check_252_width_27_5[11] 156..166
//     range_check_252_width_27_6[11] 167..177
//     cube_252_7[21] 178..198
//     range_check_3_3_3_3_3_8[6] 199..204
//     range_check_3_3_3_3_3_9[6] 205..210
//     cube_252_10[21] 211..231
//     range_check_4_4_4_4_11[5] 232..236
//     range_check_4_4_4_4_12[5] 237..241
//     range_check_4_4_13[3] 242..244
//     poseidon_3_partial_rounds_chain_14[43] 245..287
//     poseidon_3_partial_rounds_chain_15[43] 288..330
//     range_check_4_4_4_4_16[5] 331..335
//     range_check_4_4_4_4_17[5] 336..340
//     range_check_4_4_18[3] 341..343
//     range_check_4_4_4_4_19[5] 344..348
//     range_check_4_4_4_4_20[5] 349..353
//     range_check_4_4_21[3] 354..356
//     poseidon_full_round_chain_22[33] 357..389
//     poseidon_full_round_chain_23[33] 390..422
//     memory_id_to_big_24[30] 423..452
//     memory_id_to_big_25[30] 453..482
//     memory_id_to_big_26[30] 483..512
//     poseidon_aggregator_27[7] 513..519
//     mults_0 520
//     mults_1 521
//     (522 words)
//   SUB-INPUT words:
//     memory_id_to_big[0] 0
//     memory_id_to_big[1] 1
//     memory_id_to_big[2] 2
//     memory_id_to_big[3] 3
//     memory_id_to_big[4] 4
//     memory_id_to_big[5] 5
//     poseidon_full_round_chain[0] 6..37
//     poseidon_full_round_chain[1] 38..69
//     poseidon_full_round_chain[2] 70..101
//     poseidon_full_round_chain[3] 102..133
//     poseidon_full_round_chain[4] 134..165
//     poseidon_full_round_chain[5] 166..197
//     poseidon_full_round_chain[6] 198..229
//     poseidon_full_round_chain[7] 230..261
//     range_check_252_width_27[0] 262..271
//     range_check_252_width_27[1] 272..281
//     cube_252[0] 282..291
//     cube_252[1] 292..301
//     range_check_3_3_3_3_3[0] 302..306
//     range_check_3_3_3_3_3[1] 307..311
//     range_check_4_4_4_4[0] 312..315
//     range_check_4_4_4_4[1] 316..319
//     range_check_4_4_4_4[2] 320..323
//     range_check_4_4_4_4[3] 324..327
//     range_check_4_4_4_4[4] 328..331
//     range_check_4_4_4_4[5] 332..335
//     range_check_4_4[0] 336..337
//     range_check_4_4[1] 338..339
//     range_check_4_4[2] 340..341
//     poseidon_3_partial_rounds_chain[0] 342..383
//     poseidon_3_partial_rounds_chain[1] 384..425
//     poseidon_3_partial_rounds_chain[2] 426..467
//     poseidon_3_partial_rounds_chain[3] 468..509
//     poseidon_3_partial_rounds_chain[4] 510..551
//     poseidon_3_partial_rounds_chain[5] 552..593
//     poseidon_3_partial_rounds_chain[6] 594..635
//     poseidon_3_partial_rounds_chain[7] 636..677
//     poseidon_3_partial_rounds_chain[8] 678..719
//     poseidon_3_partial_rounds_chain[9] 720..761
//     poseidon_3_partial_rounds_chain[10] 762..803
//     poseidon_3_partial_rounds_chain[11] 804..845
//     poseidon_3_partial_rounds_chain[12] 846..887
//     poseidon_3_partial_rounds_chain[13] 888..929
//     poseidon_3_partial_rounds_chain[14] 930..971
//     poseidon_3_partial_rounds_chain[15] 972..1013
//     poseidon_3_partial_rounds_chain[16] 1014..1055
//     poseidon_3_partial_rounds_chain[17] 1056..1097
//     poseidon_3_partial_rounds_chain[18] 1098..1139
//     poseidon_3_partial_rounds_chain[19] 1140..1181
//     poseidon_3_partial_rounds_chain[20] 1182..1223
//     poseidon_3_partial_rounds_chain[21] 1224..1265
//     poseidon_3_partial_rounds_chain[22] 1266..1307
//     poseidon_3_partial_rounds_chain[23] 1308..1349
//     poseidon_3_partial_rounds_chain[24] 1350..1391
//     poseidon_3_partial_rounds_chain[25] 1392..1433
//     poseidon_3_partial_rounds_chain[26] 1434..1475
//     (1476 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 522;
pub(crate) const N_SUB_INPUT_WORDS: usize = 1476;

/// The per-row `poseidon_aggregator` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn poseidon_aggregator_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_4 = eval.m31_const(4);
    let m31_5 = eval.m31_const(5);
    let m31_6 = eval.m31_const(6);
    let m31_7 = eval.m31_const(7);
    let m31_8 = eval.m31_const(8);
    let m31_9 = eval.m31_const(9);
    let m31_10 = eval.m31_const(10);
    let m31_11 = eval.m31_const(11);
    let m31_12 = eval.m31_const(12);
    let m31_13 = eval.m31_const(13);
    let m31_14 = eval.m31_const(14);
    let m31_15 = eval.m31_const(15);
    let m31_16 = eval.m31_const(16);
    let m31_17 = eval.m31_const(17);
    let m31_18 = eval.m31_const(18);
    let m31_19 = eval.m31_const(19);
    let m31_20 = eval.m31_const(20);
    let m31_21 = eval.m31_const(21);
    let m31_22 = eval.m31_const(22);
    let m31_23 = eval.m31_const(23);
    let m31_24 = eval.m31_const(24);
    let m31_25 = eval.m31_const(25);
    let m31_26 = eval.m31_const(26);
    let m31_27 = eval.m31_const(27);
    let m31_28 = eval.m31_const(28);
    let m31_29 = eval.m31_const(29);
    let m31_30 = eval.m31_const(30);
    let m31_31 = eval.m31_const(31);
    let m31_32 = eval.m31_const(32);
    let m31_33 = eval.m31_const(33);
    let m31_34 = eval.m31_const(34);
    let m31_35 = eval.m31_const(35);
    let m31_39 = eval.m31_const(39);
    let m31_40 = eval.m31_const(40);
    let m31_42 = eval.m31_const(42);
    let m31_44 = eval.m31_const(44);
    let m31_57 = eval.m31_const(57);
    let m31_60 = eval.m31_const(60);
    let m31_61 = eval.m31_const(61);
    let m31_66 = eval.m31_const(66);
    let m31_67 = eval.m31_const(67);
    let m31_70 = eval.m31_const(70);
    let m31_71 = eval.m31_const(71);
    let m31_73 = eval.m31_const(73);
    let m31_77 = eval.m31_const(77);
    let m31_86 = eval.m31_const(86);
    let m31_87 = eval.m31_const(87);
    let m31_88 = eval.m31_const(88);
    let m31_94 = eval.m31_const(94);
    let m31_96 = eval.m31_const(96);
    let m31_97 = eval.m31_const(97);
    let m31_99 = eval.m31_const(99);
    let m31_100 = eval.m31_const(100);
    let m31_109 = eval.m31_const(109);
    let m31_111 = eval.m31_const(111);
    let m31_112 = eval.m31_const(112);
    let m31_116 = eval.m31_const(116);
    let m31_120 = eval.m31_const(120);
    let m31_127 = eval.m31_const(127);
    let m31_129 = eval.m31_const(129);
    let m31_131 = eval.m31_const(131);
    let m31_132 = eval.m31_const(132);
    let m31_135 = eval.m31_const(135);
    let m31_136 = eval.m31_const(136);
    let m31_138 = eval.m31_const(138);
    let m31_139 = eval.m31_const(139);
    let m31_140 = eval.m31_const(140);
    let m31_143 = eval.m31_const(143);
    let m31_145 = eval.m31_const(145);
    let m31_148 = eval.m31_const(148);
    let m31_154 = eval.m31_const(154);
    let m31_157 = eval.m31_const(157);
    let m31_163 = eval.m31_const(163);
    let m31_164 = eval.m31_const(164);
    let m31_170 = eval.m31_const(170);
    let m31_171 = eval.m31_const(171);
    let m31_173 = eval.m31_const(173);
    let m31_181 = eval.m31_const(181);
    let m31_182 = eval.m31_const(182);
    let m31_183 = eval.m31_const(183);
    let m31_184 = eval.m31_const(184);
    let m31_186 = eval.m31_const(186);
    let m31_187 = eval.m31_const(187);
    let m31_189 = eval.m31_const(189);
    let m31_190 = eval.m31_const(190);
    let m31_192 = eval.m31_const(192);
    let m31_193 = eval.m31_const(193);
    let m31_196 = eval.m31_const(196);
    let m31_199 = eval.m31_const(199);
    let m31_200 = eval.m31_const(200);
    let m31_201 = eval.m31_const(201);
    let m31_207 = eval.m31_const(207);
    let m31_208 = eval.m31_const(208);
    let m31_211 = eval.m31_const(211);
    let m31_213 = eval.m31_const(213);
    let m31_215 = eval.m31_const(215);
    let m31_220 = eval.m31_const(220);
    let m31_221 = eval.m31_const(221);
    let m31_223 = eval.m31_const(223);
    let m31_226 = eval.m31_const(226);
    let m31_228 = eval.m31_const(228);
    let m31_229 = eval.m31_const(229);
    let m31_231 = eval.m31_const(231);
    let m31_236 = eval.m31_const(236);
    let m31_237 = eval.m31_const(237);
    let m31_238 = eval.m31_const(238);
    let m31_241 = eval.m31_const(241);
    let m31_248 = eval.m31_const(248);
    let m31_250 = eval.m31_const(250);
    let m31_256 = eval.m31_const(256);
    let m31_259 = eval.m31_const(259);
    let m31_261 = eval.m31_const(261);
    let m31_263 = eval.m31_const(263);
    let m31_265 = eval.m31_const(265);
    let m31_267 = eval.m31_const(267);
    let m31_275 = eval.m31_const(275);
    let m31_281 = eval.m31_const(281);
    let m31_285 = eval.m31_const(285);
    let m31_286 = eval.m31_const(286);
    let m31_289 = eval.m31_const(289);
    let m31_290 = eval.m31_const(290);
    let m31_291 = eval.m31_const(291);
    let m31_294 = eval.m31_const(294);
    let m31_295 = eval.m31_const(295);
    let m31_300 = eval.m31_const(300);
    let m31_301 = eval.m31_const(301);
    let m31_303 = eval.m31_const(303);
    let m31_315 = eval.m31_const(315);
    let m31_320 = eval.m31_const(320);
    let m31_321 = eval.m31_const(321);
    let m31_330 = eval.m31_const(330);
    let m31_331 = eval.m31_const(331);
    let m31_338 = eval.m31_const(338);
    let m31_339 = eval.m31_const(339);
    let m31_344 = eval.m31_const(344);
    let m31_346 = eval.m31_const(346);
    let m31_347 = eval.m31_const(347);
    let m31_350 = eval.m31_const(350);
    let m31_354 = eval.m31_const(354);
    let m31_357 = eval.m31_const(357);
    let m31_360 = eval.m31_const(360);
    let m31_362 = eval.m31_const(362);
    let m31_363 = eval.m31_const(363);
    let m31_365 = eval.m31_const(365);
    let m31_381 = eval.m31_const(381);
    let m31_382 = eval.m31_const(382);
    let m31_386 = eval.m31_const(386);
    let m31_389 = eval.m31_const(389);
    let m31_393 = eval.m31_const(393);
    let m31_395 = eval.m31_const(395);
    let m31_398 = eval.m31_const(398);
    let m31_399 = eval.m31_const(399);
    let m31_402 = eval.m31_const(402);
    let m31_409 = eval.m31_const(409);
    let m31_413 = eval.m31_const(413);
    let m31_418 = eval.m31_const(418);
    let m31_421 = eval.m31_const(421);
    let m31_424 = eval.m31_const(424);
    let m31_426 = eval.m31_const(426);
    let m31_428 = eval.m31_const(428);
    let m31_429 = eval.m31_const(429);
    let m31_430 = eval.m31_const(430);
    let m31_431 = eval.m31_const(431);
    let m31_434 = eval.m31_const(434);
    let m31_446 = eval.m31_const(446);
    let m31_447 = eval.m31_const(447);
    let m31_453 = eval.m31_const(453);
    let m31_454 = eval.m31_const(454);
    let m31_459 = eval.m31_const(459);
    let m31_461 = eval.m31_const(461);
    let m31_462 = eval.m31_const(462);
    let m31_463 = eval.m31_const(463);
    let m31_464 = eval.m31_const(464);
    let m31_466 = eval.m31_const(466);
    let m31_469 = eval.m31_const(469);
    let m31_472 = eval.m31_const(472);
    let m31_478 = eval.m31_const(478);
    let m31_481 = eval.m31_const(481);
    let m31_488 = eval.m31_const(488);
    let m31_490 = eval.m31_const(490);
    let m31_493 = eval.m31_const(493);
    let m31_494 = eval.m31_const(494);
    let m31_497 = eval.m31_const(497);
    let m31_500 = eval.m31_const(500);
    let m31_505 = eval.m31_const(505);
    let m31_508 = eval.m31_const(508);
    let m31_511 = eval.m31_const(511);
    let m31_512 = eval.m31_const(512);
    let m31_8192 = eval.m31_const(8192);
    let m31_262144 = eval.m31_const(262144);
    let m31_4883209 = eval.m31_const(4883209);
    let m31_4974792 = eval.m31_const(4974792);
    let m31_16173996 = eval.m31_const(16173996);
    let m31_18765944 = eval.m31_const(18765944);
    let m31_19292069 = eval.m31_const(19292069);
    let m31_22899501 = eval.m31_const(22899501);
    let m31_28820206 = eval.m31_const(28820206);
    let m31_33413160 = eval.m31_const(33413160);
    let m31_33439011 = eval.m31_const(33439011);
    let m31_36279186 = eval.m31_const(36279186);
    let m31_40454143 = eval.m31_const(40454143);
    let m31_41224388 = eval.m31_const(41224388);
    let m31_41320857 = eval.m31_const(41320857);
    let m31_44781849 = eval.m31_const(44781849);
    let m31_44848225 = eval.m31_const(44848225);
    let m31_45351266 = eval.m31_const(45351266);
    let m31_45553283 = eval.m31_const(45553283);
    let m31_48193339 = eval.m31_const(48193339);
    let m31_48383197 = eval.m31_const(48383197);
    let m31_48945103 = eval.m31_const(48945103);
    let m31_49157069 = eval.m31_const(49157069);
    let m31_49554771 = eval.m31_const(49554771);
    let m31_50468641 = eval.m31_const(50468641);
    let m31_50758155 = eval.m31_const(50758155);
    let m31_54415179 = eval.m31_const(54415179);
    let m31_55508188 = eval.m31_const(55508188);
    let m31_55955004 = eval.m31_const(55955004);
    let m31_58475513 = eval.m31_const(58475513);
    let m31_59852719 = eval.m31_const(59852719);
    let m31_60124463 = eval.m31_const(60124463);
    let m31_60709090 = eval.m31_const(60709090);
    let m31_62360091 = eval.m31_const(62360091);
    let m31_62439890 = eval.m31_const(62439890);
    let m31_65659846 = eval.m31_const(65659846);
    let m31_68491350 = eval.m31_const(68491350);
    let m31_72285071 = eval.m31_const(72285071);
    let m31_74972783 = eval.m31_const(74972783);
    let m31_75104388 = eval.m31_const(75104388);
    let m31_77099918 = eval.m31_const(77099918);
    let m31_78826183 = eval.m31_const(78826183);
    let m31_79012328 = eval.m31_const(79012328);
    let m31_86573645 = eval.m31_const(86573645);
    let m31_88680813 = eval.m31_const(88680813);
    let m31_90391646 = eval.m31_const(90391646);
    let m31_90842759 = eval.m31_const(90842759);
    let m31_91013252 = eval.m31_const(91013252);
    let m31_94624323 = eval.m31_const(94624323);
    let m31_95050340 = eval.m31_const(95050340);
    let m31_102193642 = eval.m31_const(102193642);
    let m31_103094260 = eval.m31_const(103094260);
    let m31_108487870 = eval.m31_const(108487870);
    let m31_112479959 = eval.m31_const(112479959);
    let m31_112795138 = eval.m31_const(112795138);
    let m31_116986206 = eval.m31_const(116986206);
    let m31_117420501 = eval.m31_const(117420501);
    let m31_119023582 = eval.m31_const(119023582);
    let m31_120369218 = eval.m31_const(120369218);
    let m31_121146754 = eval.m31_const(121146754);
    let m31_121657377 = eval.m31_const(121657377);
    let m31_122233508 = eval.m31_const(122233508);
    let m31_129717753 = eval.m31_const(129717753);
    let m31_130418270 = eval.m31_const(130418270);
    let m31_133303902 = eval.m31_const(133303902);
    let m31_134217729 = eval.m31_const(134217729);
    let m31_402653187 = eval.m31_const(402653187);
    let m31_502259093 = eval.m31_const(502259093);
    let m31_1027333874 = eval.m31_const(1027333874);
    let m31_1090315331 = eval.m31_const(1090315331);
    let m31_1343313504 = eval.m31_const(1343313504);
    let m31_1480369132 = eval.m31_const(1480369132);
    let m31_1551892206 = eval.m31_const(1551892206);
    let m31_1651211826 = eval.m31_const(1651211826);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1987997202 = eval.m31_const(1987997202);
    let seq = eval.iota();
    let input_limb_0_col0 = eval.input(0);
    eval.set_col(0, input_limb_0_col0);
    let input_limb_1_col1 = eval.input(1);
    eval.set_col(1, input_limb_1_col1);
    let input_limb_2_col2 = eval.input(2);
    eval.set_col(2, input_limb_2_col2);
    let input_limb_3_col3 = eval.input(3);
    eval.set_col(3, input_limb_3_col3);
    let input_limb_4_col4 = eval.input(4);
    eval.set_col(4, input_limb_4_col4);
    let input_limb_5_col5 = eval.input(5);
    eval.set_col(5, input_limb_5_col5);
    let memory_id_to_big_value_tmp_3806f_0 = eval.mem_id_to_value(input_limb_0_col0);
    let value_limb_0_col6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 0);
    eval.set_col(6, value_limb_0_col6);
    let value_limb_1_col7 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 1);
    eval.set_col(7, value_limb_1_col7);
    let value_limb_2_col8 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 2);
    eval.set_col(8, value_limb_2_col8);
    let value_limb_3_col9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 3);
    eval.set_col(9, value_limb_3_col9);
    let value_limb_4_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 4);
    eval.set_col(10, value_limb_4_col10);
    let value_limb_5_col11 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 5);
    eval.set_col(11, value_limb_5_col11);
    let value_limb_6_col12 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 6);
    eval.set_col(12, value_limb_6_col12);
    let value_limb_7_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 7);
    eval.set_col(13, value_limb_7_col13);
    let value_limb_8_col14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 8);
    eval.set_col(14, value_limb_8_col14);
    let value_limb_9_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 9);
    eval.set_col(15, value_limb_9_col15);
    let value_limb_10_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 10);
    eval.set_col(16, value_limb_10_col16);
    let value_limb_11_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 11);
    eval.set_col(17, value_limb_11_col17);
    let value_limb_12_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 12);
    eval.set_col(18, value_limb_12_col18);
    let value_limb_13_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 13);
    eval.set_col(19, value_limb_13_col19);
    let value_limb_14_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 14);
    eval.set_col(20, value_limb_14_col20);
    let value_limb_15_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 15);
    eval.set_col(21, value_limb_15_col21);
    let value_limb_16_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 16);
    eval.set_col(22, value_limb_16_col22);
    let value_limb_17_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 17);
    eval.set_col(23, value_limb_17_col23);
    let value_limb_18_col24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 18);
    eval.set_col(24, value_limb_18_col24);
    let value_limb_19_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 19);
    eval.set_col(25, value_limb_19_col25);
    let value_limb_20_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 20);
    eval.set_col(26, value_limb_20_col26);
    let value_limb_21_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 21);
    eval.set_col(27, value_limb_21_col27);
    let value_limb_22_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 22);
    eval.set_col(28, value_limb_22_col28);
    let value_limb_23_col29 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 23);
    eval.set_col(29, value_limb_23_col29);
    let value_limb_24_col30 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 24);
    eval.set_col(30, value_limb_24_col30);
    let value_limb_25_col31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 25);
    eval.set_col(31, value_limb_25_col31);
    let value_limb_26_col32 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 26);
    eval.set_col(32, value_limb_26_col32);
    let value_limb_27_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_0.clone(), 27);
    eval.set_col(33, value_limb_27_col33);
    eval.set_sub_input_word(0, input_limb_0_col0);
    eval.set_lookup_word(0, m31_1662111297);
    eval.set_lookup_word(1, input_limb_0_col0);
    eval.set_lookup_word(2, value_limb_0_col6);
    eval.set_lookup_word(3, value_limb_1_col7);
    eval.set_lookup_word(4, value_limb_2_col8);
    eval.set_lookup_word(5, value_limb_3_col9);
    eval.set_lookup_word(6, value_limb_4_col10);
    eval.set_lookup_word(7, value_limb_5_col11);
    eval.set_lookup_word(8, value_limb_6_col12);
    eval.set_lookup_word(9, value_limb_7_col13);
    eval.set_lookup_word(10, value_limb_8_col14);
    eval.set_lookup_word(11, value_limb_9_col15);
    eval.set_lookup_word(12, value_limb_10_col16);
    eval.set_lookup_word(13, value_limb_11_col17);
    eval.set_lookup_word(14, value_limb_12_col18);
    eval.set_lookup_word(15, value_limb_13_col19);
    eval.set_lookup_word(16, value_limb_14_col20);
    eval.set_lookup_word(17, value_limb_15_col21);
    eval.set_lookup_word(18, value_limb_16_col22);
    eval.set_lookup_word(19, value_limb_17_col23);
    eval.set_lookup_word(20, value_limb_18_col24);
    eval.set_lookup_word(21, value_limb_19_col25);
    eval.set_lookup_word(22, value_limb_20_col26);
    eval.set_lookup_word(23, value_limb_21_col27);
    eval.set_lookup_word(24, value_limb_22_col28);
    eval.set_lookup_word(25, value_limb_23_col29);
    eval.set_lookup_word(26, value_limb_24_col30);
    eval.set_lookup_word(27, value_limb_25_col31);
    eval.set_lookup_word(28, value_limb_26_col32);
    eval.set_lookup_word(29, value_limb_27_col33);
    let read_positive_known_id_num_bits_252_output_tmp_3806f_1 = eval.felt_from_limbs([
        value_limb_0_col6,
        value_limb_1_col7,
        value_limb_2_col8,
        value_limb_3_col9,
        value_limb_4_col10,
        value_limb_5_col11,
        value_limb_6_col12,
        value_limb_7_col13,
        value_limb_8_col14,
        value_limb_9_col15,
        value_limb_10_col16,
        value_limb_11_col17,
        value_limb_12_col18,
        value_limb_13_col19,
        value_limb_14_col20,
        value_limb_15_col21,
        value_limb_16_col22,
        value_limb_17_col23,
        value_limb_18_col24,
        value_limb_19_col25,
        value_limb_20_col26,
        value_limb_21_col27,
        value_limb_22_col28,
        value_limb_23_col29,
        value_limb_24_col30,
        value_limb_25_col31,
        value_limb_26_col32,
        value_limb_27_col33,
    ]);
    let wg_v0 = eval.m31_mul(value_limb_1_col7, m31_512);
    let wg_v1 = eval.m31_add(value_limb_0_col6, wg_v0);
    let wg_v2 = eval.m31_mul(value_limb_2_col8, m31_262144);
    let wg_v3 = eval.m31_add(wg_v1, wg_v2);
    let wg_v4 = eval.m31_mul(value_limb_4_col10, m31_512);
    let wg_v5 = eval.m31_add(value_limb_3_col9, wg_v4);
    let wg_v6 = eval.m31_mul(value_limb_5_col11, m31_262144);
    let wg_v7 = eval.m31_add(wg_v5, wg_v6);
    let wg_v8 = eval.m31_mul(value_limb_7_col13, m31_512);
    let wg_v9 = eval.m31_add(value_limb_6_col12, wg_v8);
    let wg_v10 = eval.m31_mul(value_limb_8_col14, m31_262144);
    let wg_v11 = eval.m31_add(wg_v9, wg_v10);
    let wg_v12 = eval.m31_mul(value_limb_10_col16, m31_512);
    let wg_v13 = eval.m31_add(value_limb_9_col15, wg_v12);
    let wg_v14 = eval.m31_mul(value_limb_11_col17, m31_262144);
    let wg_v15 = eval.m31_add(wg_v13, wg_v14);
    let wg_v16 = eval.m31_mul(value_limb_13_col19, m31_512);
    let wg_v17 = eval.m31_add(value_limb_12_col18, wg_v16);
    let wg_v18 = eval.m31_mul(value_limb_14_col20, m31_262144);
    let wg_v19 = eval.m31_add(wg_v17, wg_v18);
    let wg_v20 = eval.m31_mul(value_limb_16_col22, m31_512);
    let wg_v21 = eval.m31_add(value_limb_15_col21, wg_v20);
    let wg_v22 = eval.m31_mul(value_limb_17_col23, m31_262144);
    let wg_v23 = eval.m31_add(wg_v21, wg_v22);
    let wg_v24 = eval.m31_mul(value_limb_19_col25, m31_512);
    let wg_v25 = eval.m31_add(value_limb_18_col24, wg_v24);
    let wg_v26 = eval.m31_mul(value_limb_20_col26, m31_262144);
    let wg_v27 = eval.m31_add(wg_v25, wg_v26);
    let wg_v28 = eval.m31_mul(value_limb_22_col28, m31_512);
    let wg_v29 = eval.m31_add(value_limb_21_col27, wg_v28);
    let wg_v30 = eval.m31_mul(value_limb_23_col29, m31_262144);
    let wg_v31 = eval.m31_add(wg_v29, wg_v30);
    let wg_v32 = eval.m31_mul(value_limb_25_col31, m31_512);
    let wg_v33 = eval.m31_add(value_limb_24_col30, wg_v32);
    let wg_v34 = eval.m31_mul(value_limb_26_col32, m31_262144);
    let wg_v35 = eval.m31_add(wg_v33, wg_v34);
    let packed_input_state_0_tmp_3806f_2 = [
        wg_v3,
        wg_v7,
        wg_v11,
        wg_v15,
        wg_v19,
        wg_v23,
        wg_v27,
        wg_v31,
        wg_v35,
        value_limb_27_col33,
    ];
    let memory_id_to_big_value_tmp_3806f_3 = eval.mem_id_to_value(input_limb_1_col1);
    let value_limb_0_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 0);
    eval.set_col(34, value_limb_0_col34);
    let value_limb_1_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 1);
    eval.set_col(35, value_limb_1_col35);
    let value_limb_2_col36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 2);
    eval.set_col(36, value_limb_2_col36);
    let value_limb_3_col37 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 3);
    eval.set_col(37, value_limb_3_col37);
    let value_limb_4_col38 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 4);
    eval.set_col(38, value_limb_4_col38);
    let value_limb_5_col39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 5);
    eval.set_col(39, value_limb_5_col39);
    let value_limb_6_col40 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 6);
    eval.set_col(40, value_limb_6_col40);
    let value_limb_7_col41 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 7);
    eval.set_col(41, value_limb_7_col41);
    let value_limb_8_col42 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 8);
    eval.set_col(42, value_limb_8_col42);
    let value_limb_9_col43 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 9);
    eval.set_col(43, value_limb_9_col43);
    let value_limb_10_col44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 10);
    eval.set_col(44, value_limb_10_col44);
    let value_limb_11_col45 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 11);
    eval.set_col(45, value_limb_11_col45);
    let value_limb_12_col46 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 12);
    eval.set_col(46, value_limb_12_col46);
    let value_limb_13_col47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 13);
    eval.set_col(47, value_limb_13_col47);
    let value_limb_14_col48 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 14);
    eval.set_col(48, value_limb_14_col48);
    let value_limb_15_col49 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 15);
    eval.set_col(49, value_limb_15_col49);
    let value_limb_16_col50 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 16);
    eval.set_col(50, value_limb_16_col50);
    let value_limb_17_col51 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 17);
    eval.set_col(51, value_limb_17_col51);
    let value_limb_18_col52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 18);
    eval.set_col(52, value_limb_18_col52);
    let value_limb_19_col53 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 19);
    eval.set_col(53, value_limb_19_col53);
    let value_limb_20_col54 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 20);
    eval.set_col(54, value_limb_20_col54);
    let value_limb_21_col55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 21);
    eval.set_col(55, value_limb_21_col55);
    let value_limb_22_col56 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 22);
    eval.set_col(56, value_limb_22_col56);
    let value_limb_23_col57 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 23);
    eval.set_col(57, value_limb_23_col57);
    let value_limb_24_col58 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 24);
    eval.set_col(58, value_limb_24_col58);
    let value_limb_25_col59 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 25);
    eval.set_col(59, value_limb_25_col59);
    let value_limb_26_col60 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 26);
    eval.set_col(60, value_limb_26_col60);
    let value_limb_27_col61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_3.clone(), 27);
    eval.set_col(61, value_limb_27_col61);
    eval.set_sub_input_word(1, input_limb_1_col1);
    eval.set_lookup_word(30, m31_1662111297);
    eval.set_lookup_word(31, input_limb_1_col1);
    eval.set_lookup_word(32, value_limb_0_col34);
    eval.set_lookup_word(33, value_limb_1_col35);
    eval.set_lookup_word(34, value_limb_2_col36);
    eval.set_lookup_word(35, value_limb_3_col37);
    eval.set_lookup_word(36, value_limb_4_col38);
    eval.set_lookup_word(37, value_limb_5_col39);
    eval.set_lookup_word(38, value_limb_6_col40);
    eval.set_lookup_word(39, value_limb_7_col41);
    eval.set_lookup_word(40, value_limb_8_col42);
    eval.set_lookup_word(41, value_limb_9_col43);
    eval.set_lookup_word(42, value_limb_10_col44);
    eval.set_lookup_word(43, value_limb_11_col45);
    eval.set_lookup_word(44, value_limb_12_col46);
    eval.set_lookup_word(45, value_limb_13_col47);
    eval.set_lookup_word(46, value_limb_14_col48);
    eval.set_lookup_word(47, value_limb_15_col49);
    eval.set_lookup_word(48, value_limb_16_col50);
    eval.set_lookup_word(49, value_limb_17_col51);
    eval.set_lookup_word(50, value_limb_18_col52);
    eval.set_lookup_word(51, value_limb_19_col53);
    eval.set_lookup_word(52, value_limb_20_col54);
    eval.set_lookup_word(53, value_limb_21_col55);
    eval.set_lookup_word(54, value_limb_22_col56);
    eval.set_lookup_word(55, value_limb_23_col57);
    eval.set_lookup_word(56, value_limb_24_col58);
    eval.set_lookup_word(57, value_limb_25_col59);
    eval.set_lookup_word(58, value_limb_26_col60);
    eval.set_lookup_word(59, value_limb_27_col61);
    let read_positive_known_id_num_bits_252_output_tmp_3806f_4 = eval.felt_from_limbs([
        value_limb_0_col34,
        value_limb_1_col35,
        value_limb_2_col36,
        value_limb_3_col37,
        value_limb_4_col38,
        value_limb_5_col39,
        value_limb_6_col40,
        value_limb_7_col41,
        value_limb_8_col42,
        value_limb_9_col43,
        value_limb_10_col44,
        value_limb_11_col45,
        value_limb_12_col46,
        value_limb_13_col47,
        value_limb_14_col48,
        value_limb_15_col49,
        value_limb_16_col50,
        value_limb_17_col51,
        value_limb_18_col52,
        value_limb_19_col53,
        value_limb_20_col54,
        value_limb_21_col55,
        value_limb_22_col56,
        value_limb_23_col57,
        value_limb_24_col58,
        value_limb_25_col59,
        value_limb_26_col60,
        value_limb_27_col61,
    ]);
    let wg_v36 = eval.m31_mul(value_limb_1_col35, m31_512);
    let wg_v37 = eval.m31_add(value_limb_0_col34, wg_v36);
    let wg_v38 = eval.m31_mul(value_limb_2_col36, m31_262144);
    let wg_v39 = eval.m31_add(wg_v37, wg_v38);
    let wg_v40 = eval.m31_mul(value_limb_4_col38, m31_512);
    let wg_v41 = eval.m31_add(value_limb_3_col37, wg_v40);
    let wg_v42 = eval.m31_mul(value_limb_5_col39, m31_262144);
    let wg_v43 = eval.m31_add(wg_v41, wg_v42);
    let wg_v44 = eval.m31_mul(value_limb_7_col41, m31_512);
    let wg_v45 = eval.m31_add(value_limb_6_col40, wg_v44);
    let wg_v46 = eval.m31_mul(value_limb_8_col42, m31_262144);
    let wg_v47 = eval.m31_add(wg_v45, wg_v46);
    let wg_v48 = eval.m31_mul(value_limb_10_col44, m31_512);
    let wg_v49 = eval.m31_add(value_limb_9_col43, wg_v48);
    let wg_v50 = eval.m31_mul(value_limb_11_col45, m31_262144);
    let wg_v51 = eval.m31_add(wg_v49, wg_v50);
    let wg_v52 = eval.m31_mul(value_limb_13_col47, m31_512);
    let wg_v53 = eval.m31_add(value_limb_12_col46, wg_v52);
    let wg_v54 = eval.m31_mul(value_limb_14_col48, m31_262144);
    let wg_v55 = eval.m31_add(wg_v53, wg_v54);
    let wg_v56 = eval.m31_mul(value_limb_16_col50, m31_512);
    let wg_v57 = eval.m31_add(value_limb_15_col49, wg_v56);
    let wg_v58 = eval.m31_mul(value_limb_17_col51, m31_262144);
    let wg_v59 = eval.m31_add(wg_v57, wg_v58);
    let wg_v60 = eval.m31_mul(value_limb_19_col53, m31_512);
    let wg_v61 = eval.m31_add(value_limb_18_col52, wg_v60);
    let wg_v62 = eval.m31_mul(value_limb_20_col54, m31_262144);
    let wg_v63 = eval.m31_add(wg_v61, wg_v62);
    let wg_v64 = eval.m31_mul(value_limb_22_col56, m31_512);
    let wg_v65 = eval.m31_add(value_limb_21_col55, wg_v64);
    let wg_v66 = eval.m31_mul(value_limb_23_col57, m31_262144);
    let wg_v67 = eval.m31_add(wg_v65, wg_v66);
    let wg_v68 = eval.m31_mul(value_limb_25_col59, m31_512);
    let wg_v69 = eval.m31_add(value_limb_24_col58, wg_v68);
    let wg_v70 = eval.m31_mul(value_limb_26_col60, m31_262144);
    let wg_v71 = eval.m31_add(wg_v69, wg_v70);
    let packed_input_state_1_tmp_3806f_5 = [
        wg_v39,
        wg_v43,
        wg_v47,
        wg_v51,
        wg_v55,
        wg_v59,
        wg_v63,
        wg_v67,
        wg_v71,
        value_limb_27_col61,
    ];
    let memory_id_to_big_value_tmp_3806f_6 = eval.mem_id_to_value(input_limb_2_col2);
    let value_limb_0_col62 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 0);
    eval.set_col(62, value_limb_0_col62);
    let value_limb_1_col63 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 1);
    eval.set_col(63, value_limb_1_col63);
    let value_limb_2_col64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 2);
    eval.set_col(64, value_limb_2_col64);
    let value_limb_3_col65 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 3);
    eval.set_col(65, value_limb_3_col65);
    let value_limb_4_col66 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 4);
    eval.set_col(66, value_limb_4_col66);
    let value_limb_5_col67 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 5);
    eval.set_col(67, value_limb_5_col67);
    let value_limb_6_col68 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 6);
    eval.set_col(68, value_limb_6_col68);
    let value_limb_7_col69 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 7);
    eval.set_col(69, value_limb_7_col69);
    let value_limb_8_col70 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 8);
    eval.set_col(70, value_limb_8_col70);
    let value_limb_9_col71 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 9);
    eval.set_col(71, value_limb_9_col71);
    let value_limb_10_col72 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 10);
    eval.set_col(72, value_limb_10_col72);
    let value_limb_11_col73 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 11);
    eval.set_col(73, value_limb_11_col73);
    let value_limb_12_col74 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 12);
    eval.set_col(74, value_limb_12_col74);
    let value_limb_13_col75 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 13);
    eval.set_col(75, value_limb_13_col75);
    let value_limb_14_col76 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 14);
    eval.set_col(76, value_limb_14_col76);
    let value_limb_15_col77 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 15);
    eval.set_col(77, value_limb_15_col77);
    let value_limb_16_col78 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 16);
    eval.set_col(78, value_limb_16_col78);
    let value_limb_17_col79 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 17);
    eval.set_col(79, value_limb_17_col79);
    let value_limb_18_col80 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 18);
    eval.set_col(80, value_limb_18_col80);
    let value_limb_19_col81 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 19);
    eval.set_col(81, value_limb_19_col81);
    let value_limb_20_col82 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 20);
    eval.set_col(82, value_limb_20_col82);
    let value_limb_21_col83 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 21);
    eval.set_col(83, value_limb_21_col83);
    let value_limb_22_col84 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 22);
    eval.set_col(84, value_limb_22_col84);
    let value_limb_23_col85 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 23);
    eval.set_col(85, value_limb_23_col85);
    let value_limb_24_col86 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 24);
    eval.set_col(86, value_limb_24_col86);
    let value_limb_25_col87 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 25);
    eval.set_col(87, value_limb_25_col87);
    let value_limb_26_col88 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 26);
    eval.set_col(88, value_limb_26_col88);
    let value_limb_27_col89 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3806f_6.clone(), 27);
    eval.set_col(89, value_limb_27_col89);
    eval.set_sub_input_word(2, input_limb_2_col2);
    eval.set_lookup_word(60, m31_1662111297);
    eval.set_lookup_word(61, input_limb_2_col2);
    eval.set_lookup_word(62, value_limb_0_col62);
    eval.set_lookup_word(63, value_limb_1_col63);
    eval.set_lookup_word(64, value_limb_2_col64);
    eval.set_lookup_word(65, value_limb_3_col65);
    eval.set_lookup_word(66, value_limb_4_col66);
    eval.set_lookup_word(67, value_limb_5_col67);
    eval.set_lookup_word(68, value_limb_6_col68);
    eval.set_lookup_word(69, value_limb_7_col69);
    eval.set_lookup_word(70, value_limb_8_col70);
    eval.set_lookup_word(71, value_limb_9_col71);
    eval.set_lookup_word(72, value_limb_10_col72);
    eval.set_lookup_word(73, value_limb_11_col73);
    eval.set_lookup_word(74, value_limb_12_col74);
    eval.set_lookup_word(75, value_limb_13_col75);
    eval.set_lookup_word(76, value_limb_14_col76);
    eval.set_lookup_word(77, value_limb_15_col77);
    eval.set_lookup_word(78, value_limb_16_col78);
    eval.set_lookup_word(79, value_limb_17_col79);
    eval.set_lookup_word(80, value_limb_18_col80);
    eval.set_lookup_word(81, value_limb_19_col81);
    eval.set_lookup_word(82, value_limb_20_col82);
    eval.set_lookup_word(83, value_limb_21_col83);
    eval.set_lookup_word(84, value_limb_22_col84);
    eval.set_lookup_word(85, value_limb_23_col85);
    eval.set_lookup_word(86, value_limb_24_col86);
    eval.set_lookup_word(87, value_limb_25_col87);
    eval.set_lookup_word(88, value_limb_26_col88);
    eval.set_lookup_word(89, value_limb_27_col89);
    let read_positive_known_id_num_bits_252_output_tmp_3806f_7 = eval.felt_from_limbs([
        value_limb_0_col62,
        value_limb_1_col63,
        value_limb_2_col64,
        value_limb_3_col65,
        value_limb_4_col66,
        value_limb_5_col67,
        value_limb_6_col68,
        value_limb_7_col69,
        value_limb_8_col70,
        value_limb_9_col71,
        value_limb_10_col72,
        value_limb_11_col73,
        value_limb_12_col74,
        value_limb_13_col75,
        value_limb_14_col76,
        value_limb_15_col77,
        value_limb_16_col78,
        value_limb_17_col79,
        value_limb_18_col80,
        value_limb_19_col81,
        value_limb_20_col82,
        value_limb_21_col83,
        value_limb_22_col84,
        value_limb_23_col85,
        value_limb_24_col86,
        value_limb_25_col87,
        value_limb_26_col88,
        value_limb_27_col89,
    ]);
    let wg_v72 = eval.m31_mul(value_limb_1_col63, m31_512);
    let wg_v73 = eval.m31_add(value_limb_0_col62, wg_v72);
    let wg_v74 = eval.m31_mul(value_limb_2_col64, m31_262144);
    let wg_v75 = eval.m31_add(wg_v73, wg_v74);
    let wg_v76 = eval.m31_mul(value_limb_4_col66, m31_512);
    let wg_v77 = eval.m31_add(value_limb_3_col65, wg_v76);
    let wg_v78 = eval.m31_mul(value_limb_5_col67, m31_262144);
    let wg_v79 = eval.m31_add(wg_v77, wg_v78);
    let wg_v80 = eval.m31_mul(value_limb_7_col69, m31_512);
    let wg_v81 = eval.m31_add(value_limb_6_col68, wg_v80);
    let wg_v82 = eval.m31_mul(value_limb_8_col70, m31_262144);
    let wg_v83 = eval.m31_add(wg_v81, wg_v82);
    let wg_v84 = eval.m31_mul(value_limb_10_col72, m31_512);
    let wg_v85 = eval.m31_add(value_limb_9_col71, wg_v84);
    let wg_v86 = eval.m31_mul(value_limb_11_col73, m31_262144);
    let wg_v87 = eval.m31_add(wg_v85, wg_v86);
    let wg_v88 = eval.m31_mul(value_limb_13_col75, m31_512);
    let wg_v89 = eval.m31_add(value_limb_12_col74, wg_v88);
    let wg_v90 = eval.m31_mul(value_limb_14_col76, m31_262144);
    let wg_v91 = eval.m31_add(wg_v89, wg_v90);
    let wg_v92 = eval.m31_mul(value_limb_16_col78, m31_512);
    let wg_v93 = eval.m31_add(value_limb_15_col77, wg_v92);
    let wg_v94 = eval.m31_mul(value_limb_17_col79, m31_262144);
    let wg_v95 = eval.m31_add(wg_v93, wg_v94);
    let wg_v96 = eval.m31_mul(value_limb_19_col81, m31_512);
    let wg_v97 = eval.m31_add(value_limb_18_col80, wg_v96);
    let wg_v98 = eval.m31_mul(value_limb_20_col82, m31_262144);
    let wg_v99 = eval.m31_add(wg_v97, wg_v98);
    let wg_v100 = eval.m31_mul(value_limb_22_col84, m31_512);
    let wg_v101 = eval.m31_add(value_limb_21_col83, wg_v100);
    let wg_v102 = eval.m31_mul(value_limb_23_col85, m31_262144);
    let wg_v103 = eval.m31_add(wg_v101, wg_v102);
    let wg_v104 = eval.m31_mul(value_limb_25_col87, m31_512);
    let wg_v105 = eval.m31_add(value_limb_24_col86, wg_v104);
    let wg_v106 = eval.m31_mul(value_limb_26_col88, m31_262144);
    let wg_v107 = eval.m31_add(wg_v105, wg_v106);
    let packed_input_state_2_tmp_3806f_8 = [
        wg_v75,
        wg_v79,
        wg_v83,
        wg_v87,
        wg_v91,
        wg_v95,
        wg_v99,
        wg_v103,
        wg_v107,
        value_limb_27_col89,
    ];
    let wg_v108 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v109 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v110 = eval.felt_from_w27_words(packed_input_state_0_tmp_3806f_2);
    let wg_v111 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v112 = eval.felt_mul(wg_v111.clone(), wg_v110.clone());
    let wg_v113 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v114 = eval.felt_add(wg_v113.clone(), wg_v112.clone());
    let wg_v115 = eval.felt_from_limbs([
        m31_111, m31_511, m31_285, m31_469, m31_472, m31_447, m31_2, m31_143, m31_430, m31_132,
        m31_96, m31_347, m31_226, m31_300, m31_231, m31_97, m31_42, m31_171, m31_190, m31_434,
        m31_413, m31_281, m31_424, m31_170, m31_490, m31_428, m31_389, m31_208,
    ]);
    let wg_v116 = eval.felt_from_limbs([
        m31_111, m31_511, m31_285, m31_469, m31_472, m31_447, m31_2, m31_143, m31_430, m31_132,
        m31_96, m31_347, m31_226, m31_300, m31_231, m31_97, m31_42, m31_171, m31_190, m31_434,
        m31_413, m31_281, m31_424, m31_170, m31_490, m31_428, m31_389, m31_208,
    ]);
    let wg_v117 = eval.felt_add(wg_v114.clone(), wg_v116.clone());
    let wg_v118 = eval.felt_get_m31(&wg_v117, 0);
    let wg_v119 = eval.felt_get_m31(&wg_v117, 1);
    let wg_v120 = eval.m31_mul(wg_v119, m31_512);
    let wg_v121 = eval.m31_add(wg_v118, wg_v120);
    let wg_v122 = eval.felt_get_m31(&wg_v117, 2);
    let wg_v123 = eval.m31_mul(wg_v122, m31_262144);
    let wg_v124 = eval.m31_add(wg_v121, wg_v123);
    let wg_v125 = eval.felt_get_m31(&wg_v117, 3);
    let wg_v126 = eval.felt_get_m31(&wg_v117, 4);
    let wg_v127 = eval.m31_mul(wg_v126, m31_512);
    let wg_v128 = eval.m31_add(wg_v125, wg_v127);
    let wg_v129 = eval.felt_get_m31(&wg_v117, 5);
    let wg_v130 = eval.m31_mul(wg_v129, m31_262144);
    let wg_v131 = eval.m31_add(wg_v128, wg_v130);
    let wg_v132 = eval.felt_get_m31(&wg_v117, 6);
    let wg_v133 = eval.felt_get_m31(&wg_v117, 7);
    let wg_v134 = eval.m31_mul(wg_v133, m31_512);
    let wg_v135 = eval.m31_add(wg_v132, wg_v134);
    let wg_v136 = eval.felt_get_m31(&wg_v117, 8);
    let wg_v137 = eval.m31_mul(wg_v136, m31_262144);
    let wg_v138 = eval.m31_add(wg_v135, wg_v137);
    let wg_v139 = eval.felt_get_m31(&wg_v117, 9);
    let wg_v140 = eval.felt_get_m31(&wg_v117, 10);
    let wg_v141 = eval.m31_mul(wg_v140, m31_512);
    let wg_v142 = eval.m31_add(wg_v139, wg_v141);
    let wg_v143 = eval.felt_get_m31(&wg_v117, 11);
    let wg_v144 = eval.m31_mul(wg_v143, m31_262144);
    let wg_v145 = eval.m31_add(wg_v142, wg_v144);
    let wg_v146 = eval.felt_get_m31(&wg_v117, 12);
    let wg_v147 = eval.felt_get_m31(&wg_v117, 13);
    let wg_v148 = eval.m31_mul(wg_v147, m31_512);
    let wg_v149 = eval.m31_add(wg_v146, wg_v148);
    let wg_v150 = eval.felt_get_m31(&wg_v117, 14);
    let wg_v151 = eval.m31_mul(wg_v150, m31_262144);
    let wg_v152 = eval.m31_add(wg_v149, wg_v151);
    let wg_v153 = eval.felt_get_m31(&wg_v117, 15);
    let wg_v154 = eval.felt_get_m31(&wg_v117, 16);
    let wg_v155 = eval.m31_mul(wg_v154, m31_512);
    let wg_v156 = eval.m31_add(wg_v153, wg_v155);
    let wg_v157 = eval.felt_get_m31(&wg_v117, 17);
    let wg_v158 = eval.m31_mul(wg_v157, m31_262144);
    let wg_v159 = eval.m31_add(wg_v156, wg_v158);
    let wg_v160 = eval.felt_get_m31(&wg_v117, 18);
    let wg_v161 = eval.felt_get_m31(&wg_v117, 19);
    let wg_v162 = eval.m31_mul(wg_v161, m31_512);
    let wg_v163 = eval.m31_add(wg_v160, wg_v162);
    let wg_v164 = eval.felt_get_m31(&wg_v117, 20);
    let wg_v165 = eval.m31_mul(wg_v164, m31_262144);
    let wg_v166 = eval.m31_add(wg_v163, wg_v165);
    let wg_v167 = eval.felt_get_m31(&wg_v117, 21);
    let wg_v168 = eval.felt_get_m31(&wg_v117, 22);
    let wg_v169 = eval.m31_mul(wg_v168, m31_512);
    let wg_v170 = eval.m31_add(wg_v167, wg_v169);
    let wg_v171 = eval.felt_get_m31(&wg_v117, 23);
    let wg_v172 = eval.m31_mul(wg_v171, m31_262144);
    let wg_v173 = eval.m31_add(wg_v170, wg_v172);
    let wg_v174 = eval.felt_get_m31(&wg_v117, 24);
    let wg_v175 = eval.felt_get_m31(&wg_v117, 25);
    let wg_v176 = eval.m31_mul(wg_v175, m31_512);
    let wg_v177 = eval.m31_add(wg_v174, wg_v176);
    let wg_v178 = eval.felt_get_m31(&wg_v117, 26);
    let wg_v179 = eval.m31_mul(wg_v178, m31_262144);
    let wg_v180 = eval.m31_add(wg_v177, wg_v179);
    let wg_v181 = eval.felt_get_m31(&wg_v117, 27);
    let combination_tmp_3806f_9 = [
        wg_v124, wg_v131, wg_v138, wg_v145, wg_v152, wg_v159, wg_v166, wg_v173, wg_v180, wg_v181,
    ];
    let combination_limb_0_col90 = combination_tmp_3806f_9[0];
    eval.set_col(90, combination_limb_0_col90);
    let combination_limb_1_col91 = combination_tmp_3806f_9[1];
    eval.set_col(91, combination_limb_1_col91);
    let combination_limb_2_col92 = combination_tmp_3806f_9[2];
    eval.set_col(92, combination_limb_2_col92);
    let combination_limb_3_col93 = combination_tmp_3806f_9[3];
    eval.set_col(93, combination_limb_3_col93);
    let combination_limb_4_col94 = combination_tmp_3806f_9[4];
    eval.set_col(94, combination_limb_4_col94);
    let combination_limb_5_col95 = combination_tmp_3806f_9[5];
    eval.set_col(95, combination_limb_5_col95);
    let combination_limb_6_col96 = combination_tmp_3806f_9[6];
    eval.set_col(96, combination_limb_6_col96);
    let combination_limb_7_col97 = combination_tmp_3806f_9[7];
    eval.set_col(97, combination_limb_7_col97);
    let combination_limb_8_col98 = combination_tmp_3806f_9[8];
    eval.set_col(98, combination_limb_8_col98);
    let combination_limb_9_col99 = combination_tmp_3806f_9[9];
    eval.set_col(99, combination_limb_9_col99);
    let wg_v182 = eval.m31_add(packed_input_state_0_tmp_3806f_2[0], m31_74972783);
    let wg_v183 = eval.m31_sub(wg_v182, combination_limb_0_col90);
    let wg_v184 = eval.m31_add(wg_v183, m31_134217729);
    let biased_limb_accumulator_u32_tmp_3806f_10 = eval.u32_from_m31(wg_v184);
    let wg_v185 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_10);
    let wg_v186 = eval.u16_as_m31(wg_v185);
    let p_coef_col100 = eval.m31_sub(wg_v186, m31_1);
    eval.set_col(100, p_coef_col100);
    let wg_v187 = eval.m31_add(packed_input_state_0_tmp_3806f_2[0], m31_74972783);
    let wg_v188 = eval.m31_sub(wg_v187, combination_limb_0_col90);
    let wg_v189 = eval.m31_sub(wg_v188, p_coef_col100);
    let carry_0_tmp_3806f_11 = eval.m31_mul(wg_v189, m31_16);
    let wg_v190 = eval.m31_add(carry_0_tmp_3806f_11, packed_input_state_0_tmp_3806f_2[1]);
    let wg_v191 = eval.m31_add(wg_v190, m31_117420501);
    let wg_v192 = eval.m31_sub(wg_v191, combination_limb_1_col91);
    let carry_1_tmp_3806f_12 = eval.m31_mul(wg_v192, m31_16);
    let wg_v193 = eval.m31_add(carry_1_tmp_3806f_12, packed_input_state_0_tmp_3806f_2[2]);
    let wg_v194 = eval.m31_add(wg_v193, m31_112795138);
    let wg_v195 = eval.m31_sub(wg_v194, combination_limb_2_col92);
    let carry_2_tmp_3806f_13 = eval.m31_mul(wg_v195, m31_16);
    let wg_v196 = eval.m31_add(carry_2_tmp_3806f_13, packed_input_state_0_tmp_3806f_2[3]);
    let wg_v197 = eval.m31_add(wg_v196, m31_91013252);
    let wg_v198 = eval.m31_sub(wg_v197, combination_limb_3_col93);
    let carry_3_tmp_3806f_14 = eval.m31_mul(wg_v198, m31_16);
    let wg_v199 = eval.m31_add(carry_3_tmp_3806f_14, packed_input_state_0_tmp_3806f_2[4]);
    let wg_v200 = eval.m31_add(wg_v199, m31_60709090);
    let wg_v201 = eval.m31_sub(wg_v200, combination_limb_4_col94);
    let carry_4_tmp_3806f_15 = eval.m31_mul(wg_v201, m31_16);
    let wg_v202 = eval.m31_add(carry_4_tmp_3806f_15, packed_input_state_0_tmp_3806f_2[5]);
    let wg_v203 = eval.m31_add(wg_v202, m31_44848225);
    let wg_v204 = eval.m31_sub(wg_v203, combination_limb_5_col95);
    let carry_5_tmp_3806f_16 = eval.m31_mul(wg_v204, m31_16);
    let wg_v205 = eval.m31_add(carry_5_tmp_3806f_16, packed_input_state_0_tmp_3806f_2[6]);
    let wg_v206 = eval.m31_add(wg_v205, m31_108487870);
    let wg_v207 = eval.m31_sub(wg_v206, combination_limb_6_col96);
    let carry_6_tmp_3806f_17 = eval.m31_mul(wg_v207, m31_16);
    let wg_v208 = eval.m31_add(carry_6_tmp_3806f_17, packed_input_state_0_tmp_3806f_2[7]);
    let wg_v209 = eval.m31_add(wg_v208, m31_44781849);
    let wg_v210 = eval.m31_sub(wg_v209, combination_limb_7_col97);
    let wg_v211 = eval.m31_mul(p_coef_col100, m31_136);
    let wg_v212 = eval.m31_sub(wg_v210, wg_v211);
    let carry_7_tmp_3806f_18 = eval.m31_mul(wg_v212, m31_16);
    let wg_v213 = eval.m31_add(carry_7_tmp_3806f_18, packed_input_state_0_tmp_3806f_2[8]);
    let wg_v214 = eval.m31_add(wg_v213, m31_102193642);
    let wg_v215 = eval.m31_sub(wg_v214, combination_limb_8_col98);
    let carry_8_tmp_3806f_19 = eval.m31_mul(wg_v215, m31_16);
    let linear_combination_n_2_coefs_1_1_output_tmp_3806f_29 = combination_tmp_3806f_9;
    let wg_v216 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v217 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v218 = eval.felt_from_w27_words(packed_input_state_1_tmp_3806f_5);
    let wg_v219 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v220 = eval.felt_mul(wg_v219.clone(), wg_v218.clone());
    let wg_v221 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v222 = eval.felt_add(wg_v221.clone(), wg_v220.clone());
    let wg_v223 = eval.felt_from_limbs([
        m31_196, m31_132, m31_157, m31_94, m31_418, m31_344, m31_402, m31_201, m31_138, m31_505,
        m31_426, m31_494, m31_67, m31_493, m31_360, m31_132, m31_256, m31_286, m31_94, m31_263,
        m31_508, m31_463, m31_363, m31_186, m31_409, m31_320, m31_157, m31_112,
    ]);
    let wg_v224 = eval.felt_from_limbs([
        m31_196, m31_132, m31_157, m31_94, m31_418, m31_344, m31_402, m31_201, m31_138, m31_505,
        m31_426, m31_494, m31_67, m31_493, m31_360, m31_132, m31_256, m31_286, m31_94, m31_263,
        m31_508, m31_463, m31_363, m31_186, m31_409, m31_320, m31_157, m31_112,
    ]);
    let wg_v225 = eval.felt_add(wg_v222.clone(), wg_v224.clone());
    let wg_v226 = eval.felt_get_m31(&wg_v225, 0);
    let wg_v227 = eval.felt_get_m31(&wg_v225, 1);
    let wg_v228 = eval.m31_mul(wg_v227, m31_512);
    let wg_v229 = eval.m31_add(wg_v226, wg_v228);
    let wg_v230 = eval.felt_get_m31(&wg_v225, 2);
    let wg_v231 = eval.m31_mul(wg_v230, m31_262144);
    let wg_v232 = eval.m31_add(wg_v229, wg_v231);
    let wg_v233 = eval.felt_get_m31(&wg_v225, 3);
    let wg_v234 = eval.felt_get_m31(&wg_v225, 4);
    let wg_v235 = eval.m31_mul(wg_v234, m31_512);
    let wg_v236 = eval.m31_add(wg_v233, wg_v235);
    let wg_v237 = eval.felt_get_m31(&wg_v225, 5);
    let wg_v238 = eval.m31_mul(wg_v237, m31_262144);
    let wg_v239 = eval.m31_add(wg_v236, wg_v238);
    let wg_v240 = eval.felt_get_m31(&wg_v225, 6);
    let wg_v241 = eval.felt_get_m31(&wg_v225, 7);
    let wg_v242 = eval.m31_mul(wg_v241, m31_512);
    let wg_v243 = eval.m31_add(wg_v240, wg_v242);
    let wg_v244 = eval.felt_get_m31(&wg_v225, 8);
    let wg_v245 = eval.m31_mul(wg_v244, m31_262144);
    let wg_v246 = eval.m31_add(wg_v243, wg_v245);
    let wg_v247 = eval.felt_get_m31(&wg_v225, 9);
    let wg_v248 = eval.felt_get_m31(&wg_v225, 10);
    let wg_v249 = eval.m31_mul(wg_v248, m31_512);
    let wg_v250 = eval.m31_add(wg_v247, wg_v249);
    let wg_v251 = eval.felt_get_m31(&wg_v225, 11);
    let wg_v252 = eval.m31_mul(wg_v251, m31_262144);
    let wg_v253 = eval.m31_add(wg_v250, wg_v252);
    let wg_v254 = eval.felt_get_m31(&wg_v225, 12);
    let wg_v255 = eval.felt_get_m31(&wg_v225, 13);
    let wg_v256 = eval.m31_mul(wg_v255, m31_512);
    let wg_v257 = eval.m31_add(wg_v254, wg_v256);
    let wg_v258 = eval.felt_get_m31(&wg_v225, 14);
    let wg_v259 = eval.m31_mul(wg_v258, m31_262144);
    let wg_v260 = eval.m31_add(wg_v257, wg_v259);
    let wg_v261 = eval.felt_get_m31(&wg_v225, 15);
    let wg_v262 = eval.felt_get_m31(&wg_v225, 16);
    let wg_v263 = eval.m31_mul(wg_v262, m31_512);
    let wg_v264 = eval.m31_add(wg_v261, wg_v263);
    let wg_v265 = eval.felt_get_m31(&wg_v225, 17);
    let wg_v266 = eval.m31_mul(wg_v265, m31_262144);
    let wg_v267 = eval.m31_add(wg_v264, wg_v266);
    let wg_v268 = eval.felt_get_m31(&wg_v225, 18);
    let wg_v269 = eval.felt_get_m31(&wg_v225, 19);
    let wg_v270 = eval.m31_mul(wg_v269, m31_512);
    let wg_v271 = eval.m31_add(wg_v268, wg_v270);
    let wg_v272 = eval.felt_get_m31(&wg_v225, 20);
    let wg_v273 = eval.m31_mul(wg_v272, m31_262144);
    let wg_v274 = eval.m31_add(wg_v271, wg_v273);
    let wg_v275 = eval.felt_get_m31(&wg_v225, 21);
    let wg_v276 = eval.felt_get_m31(&wg_v225, 22);
    let wg_v277 = eval.m31_mul(wg_v276, m31_512);
    let wg_v278 = eval.m31_add(wg_v275, wg_v277);
    let wg_v279 = eval.felt_get_m31(&wg_v225, 23);
    let wg_v280 = eval.m31_mul(wg_v279, m31_262144);
    let wg_v281 = eval.m31_add(wg_v278, wg_v280);
    let wg_v282 = eval.felt_get_m31(&wg_v225, 24);
    let wg_v283 = eval.felt_get_m31(&wg_v225, 25);
    let wg_v284 = eval.m31_mul(wg_v283, m31_512);
    let wg_v285 = eval.m31_add(wg_v282, wg_v284);
    let wg_v286 = eval.felt_get_m31(&wg_v225, 26);
    let wg_v287 = eval.m31_mul(wg_v286, m31_262144);
    let wg_v288 = eval.m31_add(wg_v285, wg_v287);
    let wg_v289 = eval.felt_get_m31(&wg_v225, 27);
    let combination_tmp_3806f_30 = [
        wg_v232, wg_v239, wg_v246, wg_v253, wg_v260, wg_v267, wg_v274, wg_v281, wg_v288, wg_v289,
    ];
    let combination_limb_0_col101 = combination_tmp_3806f_30[0];
    eval.set_col(101, combination_limb_0_col101);
    let combination_limb_1_col102 = combination_tmp_3806f_30[1];
    eval.set_col(102, combination_limb_1_col102);
    let combination_limb_2_col103 = combination_tmp_3806f_30[2];
    eval.set_col(103, combination_limb_2_col103);
    let combination_limb_3_col104 = combination_tmp_3806f_30[3];
    eval.set_col(104, combination_limb_3_col104);
    let combination_limb_4_col105 = combination_tmp_3806f_30[4];
    eval.set_col(105, combination_limb_4_col105);
    let combination_limb_5_col106 = combination_tmp_3806f_30[5];
    eval.set_col(106, combination_limb_5_col106);
    let combination_limb_6_col107 = combination_tmp_3806f_30[6];
    eval.set_col(107, combination_limb_6_col107);
    let combination_limb_7_col108 = combination_tmp_3806f_30[7];
    eval.set_col(108, combination_limb_7_col108);
    let combination_limb_8_col109 = combination_tmp_3806f_30[8];
    eval.set_col(109, combination_limb_8_col109);
    let combination_limb_9_col110 = combination_tmp_3806f_30[9];
    eval.set_col(110, combination_limb_9_col110);
    let wg_v290 = eval.m31_add(packed_input_state_1_tmp_3806f_5[0], m31_41224388);
    let wg_v291 = eval.m31_sub(wg_v290, combination_limb_0_col101);
    let wg_v292 = eval.m31_add(wg_v291, m31_134217729);
    let biased_limb_accumulator_u32_tmp_3806f_31 = eval.u32_from_m31(wg_v292);
    let wg_v293 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_31);
    let wg_v294 = eval.u16_as_m31(wg_v293);
    let p_coef_col111 = eval.m31_sub(wg_v294, m31_1);
    eval.set_col(111, p_coef_col111);
    let wg_v295 = eval.m31_add(packed_input_state_1_tmp_3806f_5[0], m31_41224388);
    let wg_v296 = eval.m31_sub(wg_v295, combination_limb_0_col101);
    let wg_v297 = eval.m31_sub(wg_v296, p_coef_col111);
    let carry_0_tmp_3806f_32 = eval.m31_mul(wg_v297, m31_16);
    let wg_v298 = eval.m31_add(carry_0_tmp_3806f_32, packed_input_state_1_tmp_3806f_5[1]);
    let wg_v299 = eval.m31_add(wg_v298, m31_90391646);
    let wg_v300 = eval.m31_sub(wg_v299, combination_limb_1_col102);
    let carry_1_tmp_3806f_33 = eval.m31_mul(wg_v300, m31_16);
    let wg_v301 = eval.m31_add(carry_1_tmp_3806f_33, packed_input_state_1_tmp_3806f_5[2]);
    let wg_v302 = eval.m31_add(wg_v301, m31_36279186);
    let wg_v303 = eval.m31_sub(wg_v302, combination_limb_2_col103);
    let carry_2_tmp_3806f_34 = eval.m31_mul(wg_v303, m31_16);
    let wg_v304 = eval.m31_add(carry_2_tmp_3806f_34, packed_input_state_1_tmp_3806f_5[3]);
    let wg_v305 = eval.m31_add(wg_v304, m31_129717753);
    let wg_v306 = eval.m31_sub(wg_v305, combination_limb_3_col104);
    let carry_3_tmp_3806f_35 = eval.m31_mul(wg_v306, m31_16);
    let wg_v307 = eval.m31_add(carry_3_tmp_3806f_35, packed_input_state_1_tmp_3806f_5[4]);
    let wg_v308 = eval.m31_add(wg_v307, m31_94624323);
    let wg_v309 = eval.m31_sub(wg_v308, combination_limb_4_col105);
    let carry_4_tmp_3806f_36 = eval.m31_mul(wg_v309, m31_16);
    let wg_v310 = eval.m31_add(carry_4_tmp_3806f_36, packed_input_state_1_tmp_3806f_5[5]);
    let wg_v311 = eval.m31_add(wg_v310, m31_75104388);
    let wg_v312 = eval.m31_sub(wg_v311, combination_limb_5_col106);
    let carry_5_tmp_3806f_37 = eval.m31_mul(wg_v312, m31_16);
    let wg_v313 = eval.m31_add(carry_5_tmp_3806f_37, packed_input_state_1_tmp_3806f_5[6]);
    let wg_v314 = eval.m31_add(wg_v313, m31_133303902);
    let wg_v315 = eval.m31_sub(wg_v314, combination_limb_6_col107);
    let carry_6_tmp_3806f_38 = eval.m31_mul(wg_v315, m31_16);
    let wg_v316 = eval.m31_add(carry_6_tmp_3806f_38, packed_input_state_1_tmp_3806f_5[7]);
    let wg_v317 = eval.m31_add(wg_v316, m31_48945103);
    let wg_v318 = eval.m31_sub(wg_v317, combination_limb_7_col108);
    let wg_v319 = eval.m31_mul(p_coef_col111, m31_136);
    let wg_v320 = eval.m31_sub(wg_v318, wg_v319);
    let carry_7_tmp_3806f_39 = eval.m31_mul(wg_v320, m31_16);
    let wg_v321 = eval.m31_add(carry_7_tmp_3806f_39, packed_input_state_1_tmp_3806f_5[8]);
    let wg_v322 = eval.m31_add(wg_v321, m31_41320857);
    let wg_v323 = eval.m31_sub(wg_v322, combination_limb_8_col109);
    let carry_8_tmp_3806f_40 = eval.m31_mul(wg_v323, m31_16);
    let linear_combination_n_2_coefs_1_1_output_tmp_3806f_50 = combination_tmp_3806f_30;
    let wg_v324 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v325 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v326 = eval.felt_from_w27_words(packed_input_state_2_tmp_3806f_8);
    let wg_v327 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v328 = eval.felt_mul(wg_v327.clone(), wg_v326.clone());
    let wg_v329 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v330 = eval.felt_add(wg_v329.clone(), wg_v328.clone());
    let wg_v331 = eval.felt_from_limbs([
        m31_265, m31_321, m31_18, m31_238, m31_481, m31_109, m31_488, m31_208, m31_301, m31_461,
        m31_265, m31_187, m31_199, m31_357, m31_300, m31_399, m31_381, m31_275, m31_40, m31_236,
        m31_127, m31_135, m31_275, m31_346, m31_303, m31_182, m31_229, m31_116,
    ]);
    let wg_v332 = eval.felt_from_limbs([
        m31_265, m31_321, m31_18, m31_238, m31_481, m31_109, m31_488, m31_208, m31_301, m31_461,
        m31_265, m31_187, m31_199, m31_357, m31_300, m31_399, m31_381, m31_275, m31_40, m31_236,
        m31_127, m31_135, m31_275, m31_346, m31_303, m31_182, m31_229, m31_116,
    ]);
    let wg_v333 = eval.felt_add(wg_v330.clone(), wg_v332.clone());
    let wg_v334 = eval.felt_get_m31(&wg_v333, 0);
    let wg_v335 = eval.felt_get_m31(&wg_v333, 1);
    let wg_v336 = eval.m31_mul(wg_v335, m31_512);
    let wg_v337 = eval.m31_add(wg_v334, wg_v336);
    let wg_v338 = eval.felt_get_m31(&wg_v333, 2);
    let wg_v339 = eval.m31_mul(wg_v338, m31_262144);
    let wg_v340 = eval.m31_add(wg_v337, wg_v339);
    let wg_v341 = eval.felt_get_m31(&wg_v333, 3);
    let wg_v342 = eval.felt_get_m31(&wg_v333, 4);
    let wg_v343 = eval.m31_mul(wg_v342, m31_512);
    let wg_v344 = eval.m31_add(wg_v341, wg_v343);
    let wg_v345 = eval.felt_get_m31(&wg_v333, 5);
    let wg_v346 = eval.m31_mul(wg_v345, m31_262144);
    let wg_v347 = eval.m31_add(wg_v344, wg_v346);
    let wg_v348 = eval.felt_get_m31(&wg_v333, 6);
    let wg_v349 = eval.felt_get_m31(&wg_v333, 7);
    let wg_v350 = eval.m31_mul(wg_v349, m31_512);
    let wg_v351 = eval.m31_add(wg_v348, wg_v350);
    let wg_v352 = eval.felt_get_m31(&wg_v333, 8);
    let wg_v353 = eval.m31_mul(wg_v352, m31_262144);
    let wg_v354 = eval.m31_add(wg_v351, wg_v353);
    let wg_v355 = eval.felt_get_m31(&wg_v333, 9);
    let wg_v356 = eval.felt_get_m31(&wg_v333, 10);
    let wg_v357 = eval.m31_mul(wg_v356, m31_512);
    let wg_v358 = eval.m31_add(wg_v355, wg_v357);
    let wg_v359 = eval.felt_get_m31(&wg_v333, 11);
    let wg_v360 = eval.m31_mul(wg_v359, m31_262144);
    let wg_v361 = eval.m31_add(wg_v358, wg_v360);
    let wg_v362 = eval.felt_get_m31(&wg_v333, 12);
    let wg_v363 = eval.felt_get_m31(&wg_v333, 13);
    let wg_v364 = eval.m31_mul(wg_v363, m31_512);
    let wg_v365 = eval.m31_add(wg_v362, wg_v364);
    let wg_v366 = eval.felt_get_m31(&wg_v333, 14);
    let wg_v367 = eval.m31_mul(wg_v366, m31_262144);
    let wg_v368 = eval.m31_add(wg_v365, wg_v367);
    let wg_v369 = eval.felt_get_m31(&wg_v333, 15);
    let wg_v370 = eval.felt_get_m31(&wg_v333, 16);
    let wg_v371 = eval.m31_mul(wg_v370, m31_512);
    let wg_v372 = eval.m31_add(wg_v369, wg_v371);
    let wg_v373 = eval.felt_get_m31(&wg_v333, 17);
    let wg_v374 = eval.m31_mul(wg_v373, m31_262144);
    let wg_v375 = eval.m31_add(wg_v372, wg_v374);
    let wg_v376 = eval.felt_get_m31(&wg_v333, 18);
    let wg_v377 = eval.felt_get_m31(&wg_v333, 19);
    let wg_v378 = eval.m31_mul(wg_v377, m31_512);
    let wg_v379 = eval.m31_add(wg_v376, wg_v378);
    let wg_v380 = eval.felt_get_m31(&wg_v333, 20);
    let wg_v381 = eval.m31_mul(wg_v380, m31_262144);
    let wg_v382 = eval.m31_add(wg_v379, wg_v381);
    let wg_v383 = eval.felt_get_m31(&wg_v333, 21);
    let wg_v384 = eval.felt_get_m31(&wg_v333, 22);
    let wg_v385 = eval.m31_mul(wg_v384, m31_512);
    let wg_v386 = eval.m31_add(wg_v383, wg_v385);
    let wg_v387 = eval.felt_get_m31(&wg_v333, 23);
    let wg_v388 = eval.m31_mul(wg_v387, m31_262144);
    let wg_v389 = eval.m31_add(wg_v386, wg_v388);
    let wg_v390 = eval.felt_get_m31(&wg_v333, 24);
    let wg_v391 = eval.felt_get_m31(&wg_v333, 25);
    let wg_v392 = eval.m31_mul(wg_v391, m31_512);
    let wg_v393 = eval.m31_add(wg_v390, wg_v392);
    let wg_v394 = eval.felt_get_m31(&wg_v333, 26);
    let wg_v395 = eval.m31_mul(wg_v394, m31_262144);
    let wg_v396 = eval.m31_add(wg_v393, wg_v395);
    let wg_v397 = eval.felt_get_m31(&wg_v333, 27);
    let combination_tmp_3806f_51 = [
        wg_v340, wg_v347, wg_v354, wg_v361, wg_v368, wg_v375, wg_v382, wg_v389, wg_v396, wg_v397,
    ];
    let combination_limb_0_col112 = combination_tmp_3806f_51[0];
    eval.set_col(112, combination_limb_0_col112);
    let combination_limb_1_col113 = combination_tmp_3806f_51[1];
    eval.set_col(113, combination_limb_1_col113);
    let combination_limb_2_col114 = combination_tmp_3806f_51[2];
    eval.set_col(114, combination_limb_2_col114);
    let combination_limb_3_col115 = combination_tmp_3806f_51[3];
    eval.set_col(115, combination_limb_3_col115);
    let combination_limb_4_col116 = combination_tmp_3806f_51[4];
    eval.set_col(116, combination_limb_4_col116);
    let combination_limb_5_col117 = combination_tmp_3806f_51[5];
    eval.set_col(117, combination_limb_5_col117);
    let combination_limb_6_col118 = combination_tmp_3806f_51[6];
    eval.set_col(118, combination_limb_6_col118);
    let combination_limb_7_col119 = combination_tmp_3806f_51[7];
    eval.set_col(119, combination_limb_7_col119);
    let combination_limb_8_col120 = combination_tmp_3806f_51[8];
    eval.set_col(120, combination_limb_8_col120);
    let combination_limb_9_col121 = combination_tmp_3806f_51[9];
    eval.set_col(121, combination_limb_9_col121);
    let wg_v398 = eval.m31_add(packed_input_state_2_tmp_3806f_8[0], m31_4883209);
    let wg_v399 = eval.m31_sub(wg_v398, combination_limb_0_col112);
    let wg_v400 = eval.m31_add(wg_v399, m31_134217729);
    let biased_limb_accumulator_u32_tmp_3806f_52 = eval.u32_from_m31(wg_v400);
    let wg_v401 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_52);
    let wg_v402 = eval.u16_as_m31(wg_v401);
    let p_coef_col122 = eval.m31_sub(wg_v402, m31_1);
    eval.set_col(122, p_coef_col122);
    let wg_v403 = eval.m31_add(packed_input_state_2_tmp_3806f_8[0], m31_4883209);
    let wg_v404 = eval.m31_sub(wg_v403, combination_limb_0_col112);
    let wg_v405 = eval.m31_sub(wg_v404, p_coef_col122);
    let carry_0_tmp_3806f_53 = eval.m31_mul(wg_v405, m31_16);
    let wg_v406 = eval.m31_add(carry_0_tmp_3806f_53, packed_input_state_2_tmp_3806f_8[1]);
    let wg_v407 = eval.m31_add(wg_v406, m31_28820206);
    let wg_v408 = eval.m31_sub(wg_v407, combination_limb_1_col113);
    let carry_1_tmp_3806f_54 = eval.m31_mul(wg_v408, m31_16);
    let wg_v409 = eval.m31_add(carry_1_tmp_3806f_54, packed_input_state_2_tmp_3806f_8[2]);
    let wg_v410 = eval.m31_add(wg_v409, m31_79012328);
    let wg_v411 = eval.m31_sub(wg_v410, combination_limb_2_col114);
    let carry_2_tmp_3806f_55 = eval.m31_mul(wg_v411, m31_16);
    let wg_v412 = eval.m31_add(carry_2_tmp_3806f_55, packed_input_state_2_tmp_3806f_8[3]);
    let wg_v413 = eval.m31_add(wg_v412, m31_49157069);
    let wg_v414 = eval.m31_sub(wg_v413, combination_limb_3_col115);
    let carry_3_tmp_3806f_56 = eval.m31_mul(wg_v414, m31_16);
    let wg_v415 = eval.m31_add(carry_3_tmp_3806f_56, packed_input_state_2_tmp_3806f_8[4]);
    let wg_v416 = eval.m31_add(wg_v415, m31_78826183);
    let wg_v417 = eval.m31_sub(wg_v416, combination_limb_4_col116);
    let carry_4_tmp_3806f_57 = eval.m31_mul(wg_v417, m31_16);
    let wg_v418 = eval.m31_add(carry_4_tmp_3806f_57, packed_input_state_2_tmp_3806f_8[5]);
    let wg_v419 = eval.m31_add(wg_v418, m31_72285071);
    let wg_v420 = eval.m31_sub(wg_v419, combination_limb_5_col117);
    let carry_5_tmp_3806f_58 = eval.m31_mul(wg_v420, m31_16);
    let wg_v421 = eval.m31_add(carry_5_tmp_3806f_58, packed_input_state_2_tmp_3806f_8[6]);
    let wg_v422 = eval.m31_add(wg_v421, m31_33413160);
    let wg_v423 = eval.m31_sub(wg_v422, combination_limb_6_col118);
    let carry_6_tmp_3806f_59 = eval.m31_mul(wg_v423, m31_16);
    let wg_v424 = eval.m31_add(carry_6_tmp_3806f_59, packed_input_state_2_tmp_3806f_8[7]);
    let wg_v425 = eval.m31_add(wg_v424, m31_90842759);
    let wg_v426 = eval.m31_sub(wg_v425, combination_limb_7_col119);
    let wg_v427 = eval.m31_mul(p_coef_col122, m31_136);
    let wg_v428 = eval.m31_sub(wg_v426, wg_v427);
    let carry_7_tmp_3806f_60 = eval.m31_mul(wg_v428, m31_16);
    let wg_v429 = eval.m31_add(carry_7_tmp_3806f_60, packed_input_state_2_tmp_3806f_8[8]);
    let wg_v430 = eval.m31_add(wg_v429, m31_60124463);
    let wg_v431 = eval.m31_sub(wg_v430, combination_limb_8_col120);
    let carry_8_tmp_3806f_61 = eval.m31_mul(wg_v431, m31_16);
    let linear_combination_n_2_coefs_1_1_output_tmp_3806f_71 = combination_tmp_3806f_51;
    let poseidon_full_round_chain_chain_tmp_tmp_3806f_72 = eval.m31_mul(seq, m31_2);
    eval.set_lookup_word(90, m31_1480369132);
    eval.set_lookup_word(91, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_lookup_word(92, m31_0);
    eval.set_lookup_word(93, combination_limb_0_col90);
    eval.set_lookup_word(94, combination_limb_1_col91);
    eval.set_lookup_word(95, combination_limb_2_col92);
    eval.set_lookup_word(96, combination_limb_3_col93);
    eval.set_lookup_word(97, combination_limb_4_col94);
    eval.set_lookup_word(98, combination_limb_5_col95);
    eval.set_lookup_word(99, combination_limb_6_col96);
    eval.set_lookup_word(100, combination_limb_7_col97);
    eval.set_lookup_word(101, combination_limb_8_col98);
    eval.set_lookup_word(102, combination_limb_9_col99);
    eval.set_lookup_word(103, combination_limb_0_col101);
    eval.set_lookup_word(104, combination_limb_1_col102);
    eval.set_lookup_word(105, combination_limb_2_col103);
    eval.set_lookup_word(106, combination_limb_3_col104);
    eval.set_lookup_word(107, combination_limb_4_col105);
    eval.set_lookup_word(108, combination_limb_5_col106);
    eval.set_lookup_word(109, combination_limb_6_col107);
    eval.set_lookup_word(110, combination_limb_7_col108);
    eval.set_lookup_word(111, combination_limb_8_col109);
    eval.set_lookup_word(112, combination_limb_9_col110);
    eval.set_lookup_word(113, combination_limb_0_col112);
    eval.set_lookup_word(114, combination_limb_1_col113);
    eval.set_lookup_word(115, combination_limb_2_col114);
    eval.set_lookup_word(116, combination_limb_3_col115);
    eval.set_lookup_word(117, combination_limb_4_col116);
    eval.set_lookup_word(118, combination_limb_5_col117);
    eval.set_lookup_word(119, combination_limb_6_col118);
    eval.set_lookup_word(120, combination_limb_7_col119);
    eval.set_lookup_word(121, combination_limb_8_col120);
    eval.set_lookup_word(122, combination_limb_9_col121);
    let wg_v432 = linear_combination_n_2_coefs_1_1_output_tmp_3806f_29;
    let wg_v433 = wg_v432[0];
    let wg_v434 = wg_v432[1];
    let wg_v435 = wg_v432[2];
    let wg_v436 = wg_v432[3];
    let wg_v437 = wg_v432[4];
    let wg_v438 = wg_v432[5];
    let wg_v439 = wg_v432[6];
    let wg_v440 = wg_v432[7];
    let wg_v441 = wg_v432[8];
    let wg_v442 = wg_v432[9];
    let wg_v443 = linear_combination_n_2_coefs_1_1_output_tmp_3806f_50;
    let wg_v444 = wg_v443[0];
    let wg_v445 = wg_v443[1];
    let wg_v446 = wg_v443[2];
    let wg_v447 = wg_v443[3];
    let wg_v448 = wg_v443[4];
    let wg_v449 = wg_v443[5];
    let wg_v450 = wg_v443[6];
    let wg_v451 = wg_v443[7];
    let wg_v452 = wg_v443[8];
    let wg_v453 = wg_v443[9];
    let wg_v454 = linear_combination_n_2_coefs_1_1_output_tmp_3806f_71;
    let wg_v455 = wg_v454[0];
    let wg_v456 = wg_v454[1];
    let wg_v457 = wg_v454[2];
    let wg_v458 = wg_v454[3];
    let wg_v459 = wg_v454[4];
    let wg_v460 = wg_v454[5];
    let wg_v461 = wg_v454[6];
    let wg_v462 = wg_v454[7];
    let wg_v463 = wg_v454[8];
    let wg_v464 = wg_v454[9];
    eval.set_sub_input_word(6, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_sub_input_word(7, m31_0);
    eval.set_sub_input_word(8, wg_v433);
    eval.set_sub_input_word(9, wg_v434);
    eval.set_sub_input_word(10, wg_v435);
    eval.set_sub_input_word(11, wg_v436);
    eval.set_sub_input_word(12, wg_v437);
    eval.set_sub_input_word(13, wg_v438);
    eval.set_sub_input_word(14, wg_v439);
    eval.set_sub_input_word(15, wg_v440);
    eval.set_sub_input_word(16, wg_v441);
    eval.set_sub_input_word(17, wg_v442);
    eval.set_sub_input_word(18, wg_v444);
    eval.set_sub_input_word(19, wg_v445);
    eval.set_sub_input_word(20, wg_v446);
    eval.set_sub_input_word(21, wg_v447);
    eval.set_sub_input_word(22, wg_v448);
    eval.set_sub_input_word(23, wg_v449);
    eval.set_sub_input_word(24, wg_v450);
    eval.set_sub_input_word(25, wg_v451);
    eval.set_sub_input_word(26, wg_v452);
    eval.set_sub_input_word(27, wg_v453);
    eval.set_sub_input_word(28, wg_v455);
    eval.set_sub_input_word(29, wg_v456);
    eval.set_sub_input_word(30, wg_v457);
    eval.set_sub_input_word(31, wg_v458);
    eval.set_sub_input_word(32, wg_v459);
    eval.set_sub_input_word(33, wg_v460);
    eval.set_sub_input_word(34, wg_v461);
    eval.set_sub_input_word(35, wg_v462);
    eval.set_sub_input_word(36, wg_v463);
    eval.set_sub_input_word(37, wg_v464);
    let poseidon_full_round_chain_output_round_0_tmp_3806f_73 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_tmp_tmp_3806f_72,
            m31_0,
            [
                linear_combination_n_2_coefs_1_1_output_tmp_3806f_29,
                linear_combination_n_2_coefs_1_1_output_tmp_3806f_50,
                linear_combination_n_2_coefs_1_1_output_tmp_3806f_71,
            ],
        );
    let wg_v465 = poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[0];
    let wg_v466 = wg_v465[0];
    let wg_v467 = wg_v465[1];
    let wg_v468 = wg_v465[2];
    let wg_v469 = wg_v465[3];
    let wg_v470 = wg_v465[4];
    let wg_v471 = wg_v465[5];
    let wg_v472 = wg_v465[6];
    let wg_v473 = wg_v465[7];
    let wg_v474 = wg_v465[8];
    let wg_v475 = wg_v465[9];
    let wg_v476 = poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[1];
    let wg_v477 = wg_v476[0];
    let wg_v478 = wg_v476[1];
    let wg_v479 = wg_v476[2];
    let wg_v480 = wg_v476[3];
    let wg_v481 = wg_v476[4];
    let wg_v482 = wg_v476[5];
    let wg_v483 = wg_v476[6];
    let wg_v484 = wg_v476[7];
    let wg_v485 = wg_v476[8];
    let wg_v486 = wg_v476[9];
    let wg_v487 = poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[2];
    let wg_v488 = wg_v487[0];
    let wg_v489 = wg_v487[1];
    let wg_v490 = wg_v487[2];
    let wg_v491 = wg_v487[3];
    let wg_v492 = wg_v487[4];
    let wg_v493 = wg_v487[5];
    let wg_v494 = wg_v487[6];
    let wg_v495 = wg_v487[7];
    let wg_v496 = wg_v487[8];
    let wg_v497 = wg_v487[9];
    eval.set_sub_input_word(38, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_sub_input_word(39, m31_1);
    eval.set_sub_input_word(40, wg_v466);
    eval.set_sub_input_word(41, wg_v467);
    eval.set_sub_input_word(42, wg_v468);
    eval.set_sub_input_word(43, wg_v469);
    eval.set_sub_input_word(44, wg_v470);
    eval.set_sub_input_word(45, wg_v471);
    eval.set_sub_input_word(46, wg_v472);
    eval.set_sub_input_word(47, wg_v473);
    eval.set_sub_input_word(48, wg_v474);
    eval.set_sub_input_word(49, wg_v475);
    eval.set_sub_input_word(50, wg_v477);
    eval.set_sub_input_word(51, wg_v478);
    eval.set_sub_input_word(52, wg_v479);
    eval.set_sub_input_word(53, wg_v480);
    eval.set_sub_input_word(54, wg_v481);
    eval.set_sub_input_word(55, wg_v482);
    eval.set_sub_input_word(56, wg_v483);
    eval.set_sub_input_word(57, wg_v484);
    eval.set_sub_input_word(58, wg_v485);
    eval.set_sub_input_word(59, wg_v486);
    eval.set_sub_input_word(60, wg_v488);
    eval.set_sub_input_word(61, wg_v489);
    eval.set_sub_input_word(62, wg_v490);
    eval.set_sub_input_word(63, wg_v491);
    eval.set_sub_input_word(64, wg_v492);
    eval.set_sub_input_word(65, wg_v493);
    eval.set_sub_input_word(66, wg_v494);
    eval.set_sub_input_word(67, wg_v495);
    eval.set_sub_input_word(68, wg_v496);
    eval.set_sub_input_word(69, wg_v497);
    let poseidon_full_round_chain_output_round_1_tmp_3806f_74 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_tmp_tmp_3806f_72,
            m31_1,
            [
                poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[0],
                poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[1],
                poseidon_full_round_chain_output_round_0_tmp_3806f_73.2[2],
            ],
        );
    let wg_v498 = poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[0];
    let wg_v499 = wg_v498[0];
    let wg_v500 = wg_v498[1];
    let wg_v501 = wg_v498[2];
    let wg_v502 = wg_v498[3];
    let wg_v503 = wg_v498[4];
    let wg_v504 = wg_v498[5];
    let wg_v505 = wg_v498[6];
    let wg_v506 = wg_v498[7];
    let wg_v507 = wg_v498[8];
    let wg_v508 = wg_v498[9];
    let wg_v509 = poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[1];
    let wg_v510 = wg_v509[0];
    let wg_v511 = wg_v509[1];
    let wg_v512 = wg_v509[2];
    let wg_v513 = wg_v509[3];
    let wg_v514 = wg_v509[4];
    let wg_v515 = wg_v509[5];
    let wg_v516 = wg_v509[6];
    let wg_v517 = wg_v509[7];
    let wg_v518 = wg_v509[8];
    let wg_v519 = wg_v509[9];
    let wg_v520 = poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[2];
    let wg_v521 = wg_v520[0];
    let wg_v522 = wg_v520[1];
    let wg_v523 = wg_v520[2];
    let wg_v524 = wg_v520[3];
    let wg_v525 = wg_v520[4];
    let wg_v526 = wg_v520[5];
    let wg_v527 = wg_v520[6];
    let wg_v528 = wg_v520[7];
    let wg_v529 = wg_v520[8];
    let wg_v530 = wg_v520[9];
    eval.set_sub_input_word(70, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_sub_input_word(71, m31_2);
    eval.set_sub_input_word(72, wg_v499);
    eval.set_sub_input_word(73, wg_v500);
    eval.set_sub_input_word(74, wg_v501);
    eval.set_sub_input_word(75, wg_v502);
    eval.set_sub_input_word(76, wg_v503);
    eval.set_sub_input_word(77, wg_v504);
    eval.set_sub_input_word(78, wg_v505);
    eval.set_sub_input_word(79, wg_v506);
    eval.set_sub_input_word(80, wg_v507);
    eval.set_sub_input_word(81, wg_v508);
    eval.set_sub_input_word(82, wg_v510);
    eval.set_sub_input_word(83, wg_v511);
    eval.set_sub_input_word(84, wg_v512);
    eval.set_sub_input_word(85, wg_v513);
    eval.set_sub_input_word(86, wg_v514);
    eval.set_sub_input_word(87, wg_v515);
    eval.set_sub_input_word(88, wg_v516);
    eval.set_sub_input_word(89, wg_v517);
    eval.set_sub_input_word(90, wg_v518);
    eval.set_sub_input_word(91, wg_v519);
    eval.set_sub_input_word(92, wg_v521);
    eval.set_sub_input_word(93, wg_v522);
    eval.set_sub_input_word(94, wg_v523);
    eval.set_sub_input_word(95, wg_v524);
    eval.set_sub_input_word(96, wg_v525);
    eval.set_sub_input_word(97, wg_v526);
    eval.set_sub_input_word(98, wg_v527);
    eval.set_sub_input_word(99, wg_v528);
    eval.set_sub_input_word(100, wg_v529);
    eval.set_sub_input_word(101, wg_v530);
    let poseidon_full_round_chain_output_round_2_tmp_3806f_75 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_tmp_tmp_3806f_72,
            m31_2,
            [
                poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[0],
                poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[1],
                poseidon_full_round_chain_output_round_1_tmp_3806f_74.2[2],
            ],
        );
    let wg_v531 = poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[0];
    let wg_v532 = wg_v531[0];
    let wg_v533 = wg_v531[1];
    let wg_v534 = wg_v531[2];
    let wg_v535 = wg_v531[3];
    let wg_v536 = wg_v531[4];
    let wg_v537 = wg_v531[5];
    let wg_v538 = wg_v531[6];
    let wg_v539 = wg_v531[7];
    let wg_v540 = wg_v531[8];
    let wg_v541 = wg_v531[9];
    let wg_v542 = poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[1];
    let wg_v543 = wg_v542[0];
    let wg_v544 = wg_v542[1];
    let wg_v545 = wg_v542[2];
    let wg_v546 = wg_v542[3];
    let wg_v547 = wg_v542[4];
    let wg_v548 = wg_v542[5];
    let wg_v549 = wg_v542[6];
    let wg_v550 = wg_v542[7];
    let wg_v551 = wg_v542[8];
    let wg_v552 = wg_v542[9];
    let wg_v553 = poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[2];
    let wg_v554 = wg_v553[0];
    let wg_v555 = wg_v553[1];
    let wg_v556 = wg_v553[2];
    let wg_v557 = wg_v553[3];
    let wg_v558 = wg_v553[4];
    let wg_v559 = wg_v553[5];
    let wg_v560 = wg_v553[6];
    let wg_v561 = wg_v553[7];
    let wg_v562 = wg_v553[8];
    let wg_v563 = wg_v553[9];
    eval.set_sub_input_word(102, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_sub_input_word(103, m31_3);
    eval.set_sub_input_word(104, wg_v532);
    eval.set_sub_input_word(105, wg_v533);
    eval.set_sub_input_word(106, wg_v534);
    eval.set_sub_input_word(107, wg_v535);
    eval.set_sub_input_word(108, wg_v536);
    eval.set_sub_input_word(109, wg_v537);
    eval.set_sub_input_word(110, wg_v538);
    eval.set_sub_input_word(111, wg_v539);
    eval.set_sub_input_word(112, wg_v540);
    eval.set_sub_input_word(113, wg_v541);
    eval.set_sub_input_word(114, wg_v543);
    eval.set_sub_input_word(115, wg_v544);
    eval.set_sub_input_word(116, wg_v545);
    eval.set_sub_input_word(117, wg_v546);
    eval.set_sub_input_word(118, wg_v547);
    eval.set_sub_input_word(119, wg_v548);
    eval.set_sub_input_word(120, wg_v549);
    eval.set_sub_input_word(121, wg_v550);
    eval.set_sub_input_word(122, wg_v551);
    eval.set_sub_input_word(123, wg_v552);
    eval.set_sub_input_word(124, wg_v554);
    eval.set_sub_input_word(125, wg_v555);
    eval.set_sub_input_word(126, wg_v556);
    eval.set_sub_input_word(127, wg_v557);
    eval.set_sub_input_word(128, wg_v558);
    eval.set_sub_input_word(129, wg_v559);
    eval.set_sub_input_word(130, wg_v560);
    eval.set_sub_input_word(131, wg_v561);
    eval.set_sub_input_word(132, wg_v562);
    eval.set_sub_input_word(133, wg_v563);
    let poseidon_full_round_chain_output_round_3_tmp_3806f_76 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_tmp_tmp_3806f_72,
            m31_3,
            [
                poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[0],
                poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[1],
                poseidon_full_round_chain_output_round_2_tmp_3806f_75.2[2],
            ],
        );
    let poseidon_full_round_chain_output_limb_0_col123 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][0];
    eval.set_col(123, poseidon_full_round_chain_output_limb_0_col123);
    let poseidon_full_round_chain_output_limb_1_col124 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][1];
    eval.set_col(124, poseidon_full_round_chain_output_limb_1_col124);
    let poseidon_full_round_chain_output_limb_2_col125 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][2];
    eval.set_col(125, poseidon_full_round_chain_output_limb_2_col125);
    let poseidon_full_round_chain_output_limb_3_col126 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][3];
    eval.set_col(126, poseidon_full_round_chain_output_limb_3_col126);
    let poseidon_full_round_chain_output_limb_4_col127 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][4];
    eval.set_col(127, poseidon_full_round_chain_output_limb_4_col127);
    let poseidon_full_round_chain_output_limb_5_col128 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][5];
    eval.set_col(128, poseidon_full_round_chain_output_limb_5_col128);
    let poseidon_full_round_chain_output_limb_6_col129 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][6];
    eval.set_col(129, poseidon_full_round_chain_output_limb_6_col129);
    let poseidon_full_round_chain_output_limb_7_col130 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][7];
    eval.set_col(130, poseidon_full_round_chain_output_limb_7_col130);
    let poseidon_full_round_chain_output_limb_8_col131 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][8];
    eval.set_col(131, poseidon_full_round_chain_output_limb_8_col131);
    let poseidon_full_round_chain_output_limb_9_col132 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0][9];
    eval.set_col(132, poseidon_full_round_chain_output_limb_9_col132);
    let poseidon_full_round_chain_output_limb_10_col133 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][0];
    eval.set_col(133, poseidon_full_round_chain_output_limb_10_col133);
    let poseidon_full_round_chain_output_limb_11_col134 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][1];
    eval.set_col(134, poseidon_full_round_chain_output_limb_11_col134);
    let poseidon_full_round_chain_output_limb_12_col135 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][2];
    eval.set_col(135, poseidon_full_round_chain_output_limb_12_col135);
    let poseidon_full_round_chain_output_limb_13_col136 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][3];
    eval.set_col(136, poseidon_full_round_chain_output_limb_13_col136);
    let poseidon_full_round_chain_output_limb_14_col137 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][4];
    eval.set_col(137, poseidon_full_round_chain_output_limb_14_col137);
    let poseidon_full_round_chain_output_limb_15_col138 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][5];
    eval.set_col(138, poseidon_full_round_chain_output_limb_15_col138);
    let poseidon_full_round_chain_output_limb_16_col139 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][6];
    eval.set_col(139, poseidon_full_round_chain_output_limb_16_col139);
    let poseidon_full_round_chain_output_limb_17_col140 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][7];
    eval.set_col(140, poseidon_full_round_chain_output_limb_17_col140);
    let poseidon_full_round_chain_output_limb_18_col141 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][8];
    eval.set_col(141, poseidon_full_round_chain_output_limb_18_col141);
    let poseidon_full_round_chain_output_limb_19_col142 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1][9];
    eval.set_col(142, poseidon_full_round_chain_output_limb_19_col142);
    let poseidon_full_round_chain_output_limb_20_col143 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][0];
    eval.set_col(143, poseidon_full_round_chain_output_limb_20_col143);
    let poseidon_full_round_chain_output_limb_21_col144 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][1];
    eval.set_col(144, poseidon_full_round_chain_output_limb_21_col144);
    let poseidon_full_round_chain_output_limb_22_col145 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][2];
    eval.set_col(145, poseidon_full_round_chain_output_limb_22_col145);
    let poseidon_full_round_chain_output_limb_23_col146 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][3];
    eval.set_col(146, poseidon_full_round_chain_output_limb_23_col146);
    let poseidon_full_round_chain_output_limb_24_col147 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][4];
    eval.set_col(147, poseidon_full_round_chain_output_limb_24_col147);
    let poseidon_full_round_chain_output_limb_25_col148 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][5];
    eval.set_col(148, poseidon_full_round_chain_output_limb_25_col148);
    let poseidon_full_round_chain_output_limb_26_col149 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][6];
    eval.set_col(149, poseidon_full_round_chain_output_limb_26_col149);
    let poseidon_full_round_chain_output_limb_27_col150 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][7];
    eval.set_col(150, poseidon_full_round_chain_output_limb_27_col150);
    let poseidon_full_round_chain_output_limb_28_col151 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][8];
    eval.set_col(151, poseidon_full_round_chain_output_limb_28_col151);
    let poseidon_full_round_chain_output_limb_29_col152 =
        poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2][9];
    eval.set_col(152, poseidon_full_round_chain_output_limb_29_col152);
    eval.set_lookup_word(123, m31_1480369132);
    eval.set_lookup_word(124, poseidon_full_round_chain_chain_tmp_tmp_3806f_72);
    eval.set_lookup_word(125, m31_4);
    eval.set_lookup_word(126, poseidon_full_round_chain_output_limb_0_col123);
    eval.set_lookup_word(127, poseidon_full_round_chain_output_limb_1_col124);
    eval.set_lookup_word(128, poseidon_full_round_chain_output_limb_2_col125);
    eval.set_lookup_word(129, poseidon_full_round_chain_output_limb_3_col126);
    eval.set_lookup_word(130, poseidon_full_round_chain_output_limb_4_col127);
    eval.set_lookup_word(131, poseidon_full_round_chain_output_limb_5_col128);
    eval.set_lookup_word(132, poseidon_full_round_chain_output_limb_6_col129);
    eval.set_lookup_word(133, poseidon_full_round_chain_output_limb_7_col130);
    eval.set_lookup_word(134, poseidon_full_round_chain_output_limb_8_col131);
    eval.set_lookup_word(135, poseidon_full_round_chain_output_limb_9_col132);
    eval.set_lookup_word(136, poseidon_full_round_chain_output_limb_10_col133);
    eval.set_lookup_word(137, poseidon_full_round_chain_output_limb_11_col134);
    eval.set_lookup_word(138, poseidon_full_round_chain_output_limb_12_col135);
    eval.set_lookup_word(139, poseidon_full_round_chain_output_limb_13_col136);
    eval.set_lookup_word(140, poseidon_full_round_chain_output_limb_14_col137);
    eval.set_lookup_word(141, poseidon_full_round_chain_output_limb_15_col138);
    eval.set_lookup_word(142, poseidon_full_round_chain_output_limb_16_col139);
    eval.set_lookup_word(143, poseidon_full_round_chain_output_limb_17_col140);
    eval.set_lookup_word(144, poseidon_full_round_chain_output_limb_18_col141);
    eval.set_lookup_word(145, poseidon_full_round_chain_output_limb_19_col142);
    eval.set_lookup_word(146, poseidon_full_round_chain_output_limb_20_col143);
    eval.set_lookup_word(147, poseidon_full_round_chain_output_limb_21_col144);
    eval.set_lookup_word(148, poseidon_full_round_chain_output_limb_22_col145);
    eval.set_lookup_word(149, poseidon_full_round_chain_output_limb_23_col146);
    eval.set_lookup_word(150, poseidon_full_round_chain_output_limb_24_col147);
    eval.set_lookup_word(151, poseidon_full_round_chain_output_limb_25_col148);
    eval.set_lookup_word(152, poseidon_full_round_chain_output_limb_26_col149);
    eval.set_lookup_word(153, poseidon_full_round_chain_output_limb_27_col150);
    eval.set_lookup_word(154, poseidon_full_round_chain_output_limb_28_col151);
    eval.set_lookup_word(155, poseidon_full_round_chain_output_limb_29_col152);
    let wg_v564 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0];
    let wg_v565 = wg_v564[0];
    let wg_v566 = wg_v564[1];
    let wg_v567 = wg_v564[2];
    let wg_v568 = wg_v564[3];
    let wg_v569 = wg_v564[4];
    let wg_v570 = wg_v564[5];
    let wg_v571 = wg_v564[6];
    let wg_v572 = wg_v564[7];
    let wg_v573 = wg_v564[8];
    let wg_v574 = wg_v564[9];
    eval.set_sub_input_word(262, wg_v565);
    eval.set_sub_input_word(263, wg_v566);
    eval.set_sub_input_word(264, wg_v567);
    eval.set_sub_input_word(265, wg_v568);
    eval.set_sub_input_word(266, wg_v569);
    eval.set_sub_input_word(267, wg_v570);
    eval.set_sub_input_word(268, wg_v571);
    eval.set_sub_input_word(269, wg_v572);
    eval.set_sub_input_word(270, wg_v573);
    eval.set_sub_input_word(271, wg_v574);
    eval.set_lookup_word(156, m31_1090315331);
    eval.set_lookup_word(157, poseidon_full_round_chain_output_limb_0_col123);
    eval.set_lookup_word(158, poseidon_full_round_chain_output_limb_1_col124);
    eval.set_lookup_word(159, poseidon_full_round_chain_output_limb_2_col125);
    eval.set_lookup_word(160, poseidon_full_round_chain_output_limb_3_col126);
    eval.set_lookup_word(161, poseidon_full_round_chain_output_limb_4_col127);
    eval.set_lookup_word(162, poseidon_full_round_chain_output_limb_5_col128);
    eval.set_lookup_word(163, poseidon_full_round_chain_output_limb_6_col129);
    eval.set_lookup_word(164, poseidon_full_round_chain_output_limb_7_col130);
    eval.set_lookup_word(165, poseidon_full_round_chain_output_limb_8_col131);
    eval.set_lookup_word(166, poseidon_full_round_chain_output_limb_9_col132);
    let wg_v575 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1];
    let wg_v576 = wg_v575[0];
    let wg_v577 = wg_v575[1];
    let wg_v578 = wg_v575[2];
    let wg_v579 = wg_v575[3];
    let wg_v580 = wg_v575[4];
    let wg_v581 = wg_v575[5];
    let wg_v582 = wg_v575[6];
    let wg_v583 = wg_v575[7];
    let wg_v584 = wg_v575[8];
    let wg_v585 = wg_v575[9];
    eval.set_sub_input_word(272, wg_v576);
    eval.set_sub_input_word(273, wg_v577);
    eval.set_sub_input_word(274, wg_v578);
    eval.set_sub_input_word(275, wg_v579);
    eval.set_sub_input_word(276, wg_v580);
    eval.set_sub_input_word(277, wg_v581);
    eval.set_sub_input_word(278, wg_v582);
    eval.set_sub_input_word(279, wg_v583);
    eval.set_sub_input_word(280, wg_v584);
    eval.set_sub_input_word(281, wg_v585);
    eval.set_lookup_word(167, m31_1090315331);
    eval.set_lookup_word(168, poseidon_full_round_chain_output_limb_10_col133);
    eval.set_lookup_word(169, poseidon_full_round_chain_output_limb_11_col134);
    eval.set_lookup_word(170, poseidon_full_round_chain_output_limb_12_col135);
    eval.set_lookup_word(171, poseidon_full_round_chain_output_limb_13_col136);
    eval.set_lookup_word(172, poseidon_full_round_chain_output_limb_14_col137);
    eval.set_lookup_word(173, poseidon_full_round_chain_output_limb_15_col138);
    eval.set_lookup_word(174, poseidon_full_round_chain_output_limb_16_col139);
    eval.set_lookup_word(175, poseidon_full_round_chain_output_limb_17_col140);
    eval.set_lookup_word(176, poseidon_full_round_chain_output_limb_18_col141);
    eval.set_lookup_word(177, poseidon_full_round_chain_output_limb_19_col142);
    let wg_v586 = poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2];
    let wg_v587 = wg_v586[0];
    let wg_v588 = wg_v586[1];
    let wg_v589 = wg_v586[2];
    let wg_v590 = wg_v586[3];
    let wg_v591 = wg_v586[4];
    let wg_v592 = wg_v586[5];
    let wg_v593 = wg_v586[6];
    let wg_v594 = wg_v586[7];
    let wg_v595 = wg_v586[8];
    let wg_v596 = wg_v586[9];
    eval.set_sub_input_word(282, wg_v587);
    eval.set_sub_input_word(283, wg_v588);
    eval.set_sub_input_word(284, wg_v589);
    eval.set_sub_input_word(285, wg_v590);
    eval.set_sub_input_word(286, wg_v591);
    eval.set_sub_input_word(287, wg_v592);
    eval.set_sub_input_word(288, wg_v593);
    eval.set_sub_input_word(289, wg_v594);
    eval.set_sub_input_word(290, wg_v595);
    eval.set_sub_input_word(291, wg_v596);
    let cube_252_output_tmp_3806f_77 =
        eval.deduce_cube_252(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[2]);
    let cube_252_output_limb_0_col153 = cube_252_output_tmp_3806f_77[0];
    eval.set_col(153, cube_252_output_limb_0_col153);
    let cube_252_output_limb_1_col154 = cube_252_output_tmp_3806f_77[1];
    eval.set_col(154, cube_252_output_limb_1_col154);
    let cube_252_output_limb_2_col155 = cube_252_output_tmp_3806f_77[2];
    eval.set_col(155, cube_252_output_limb_2_col155);
    let cube_252_output_limb_3_col156 = cube_252_output_tmp_3806f_77[3];
    eval.set_col(156, cube_252_output_limb_3_col156);
    let cube_252_output_limb_4_col157 = cube_252_output_tmp_3806f_77[4];
    eval.set_col(157, cube_252_output_limb_4_col157);
    let cube_252_output_limb_5_col158 = cube_252_output_tmp_3806f_77[5];
    eval.set_col(158, cube_252_output_limb_5_col158);
    let cube_252_output_limb_6_col159 = cube_252_output_tmp_3806f_77[6];
    eval.set_col(159, cube_252_output_limb_6_col159);
    let cube_252_output_limb_7_col160 = cube_252_output_tmp_3806f_77[7];
    eval.set_col(160, cube_252_output_limb_7_col160);
    let cube_252_output_limb_8_col161 = cube_252_output_tmp_3806f_77[8];
    eval.set_col(161, cube_252_output_limb_8_col161);
    let cube_252_output_limb_9_col162 = cube_252_output_tmp_3806f_77[9];
    eval.set_col(162, cube_252_output_limb_9_col162);
    eval.set_lookup_word(178, m31_1987997202);
    eval.set_lookup_word(179, poseidon_full_round_chain_output_limb_20_col143);
    eval.set_lookup_word(180, poseidon_full_round_chain_output_limb_21_col144);
    eval.set_lookup_word(181, poseidon_full_round_chain_output_limb_22_col145);
    eval.set_lookup_word(182, poseidon_full_round_chain_output_limb_23_col146);
    eval.set_lookup_word(183, poseidon_full_round_chain_output_limb_24_col147);
    eval.set_lookup_word(184, poseidon_full_round_chain_output_limb_25_col148);
    eval.set_lookup_word(185, poseidon_full_round_chain_output_limb_26_col149);
    eval.set_lookup_word(186, poseidon_full_round_chain_output_limb_27_col150);
    eval.set_lookup_word(187, poseidon_full_round_chain_output_limb_28_col151);
    eval.set_lookup_word(188, poseidon_full_round_chain_output_limb_29_col152);
    eval.set_lookup_word(189, cube_252_output_limb_0_col153);
    eval.set_lookup_word(190, cube_252_output_limb_1_col154);
    eval.set_lookup_word(191, cube_252_output_limb_2_col155);
    eval.set_lookup_word(192, cube_252_output_limb_3_col156);
    eval.set_lookup_word(193, cube_252_output_limb_4_col157);
    eval.set_lookup_word(194, cube_252_output_limb_5_col158);
    eval.set_lookup_word(195, cube_252_output_limb_6_col159);
    eval.set_lookup_word(196, cube_252_output_limb_7_col160);
    eval.set_lookup_word(197, cube_252_output_limb_8_col161);
    eval.set_lookup_word(198, cube_252_output_limb_9_col162);
    let wg_v597 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v598 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v599 =
        eval.felt_from_w27_words(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0]);
    let wg_v600 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v601 = eval.felt_mul(wg_v600.clone(), wg_v599.clone());
    let wg_v602 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v603 = eval.felt_add(wg_v602.clone(), wg_v601.clone());
    let wg_v604 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v605 =
        eval.felt_from_w27_words(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[1]);
    let wg_v606 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v607 = eval.felt_mul(wg_v606.clone(), wg_v605.clone());
    let wg_v608 = eval.felt_add(wg_v603.clone(), wg_v607.clone());
    let wg_v609 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v610 = eval.felt_from_w27_words(cube_252_output_tmp_3806f_77);
    let wg_v611 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v612 = eval.felt_mul(wg_v611.clone(), wg_v610.clone());
    let wg_v613 = eval.felt_sub(wg_v608.clone(), wg_v612.clone());
    let wg_v614 = eval.felt_from_limbs([
        m31_500, m31_139, m31_393, m31_386, m31_70, m31_462, m31_100, m31_301, m31_362, m31_428,
        m31_357, m31_61, m31_11, m31_321, m31_193, m31_331, m31_295, m31_207, m31_421, m31_303,
        m31_73, m31_354, m31_0, m31_173, m31_164, m31_145, m31_466, m31_248,
    ]);
    let wg_v615 = eval.felt_from_limbs([
        m31_500, m31_139, m31_393, m31_386, m31_70, m31_462, m31_100, m31_301, m31_362, m31_428,
        m31_357, m31_61, m31_11, m31_321, m31_193, m31_331, m31_295, m31_207, m31_421, m31_303,
        m31_73, m31_354, m31_0, m31_173, m31_164, m31_145, m31_466, m31_248,
    ]);
    let wg_v616 = eval.felt_add(wg_v613.clone(), wg_v615.clone());
    let wg_v617 = eval.felt_get_m31(&wg_v616, 0);
    let wg_v618 = eval.felt_get_m31(&wg_v616, 1);
    let wg_v619 = eval.m31_mul(wg_v618, m31_512);
    let wg_v620 = eval.m31_add(wg_v617, wg_v619);
    let wg_v621 = eval.felt_get_m31(&wg_v616, 2);
    let wg_v622 = eval.m31_mul(wg_v621, m31_262144);
    let wg_v623 = eval.m31_add(wg_v620, wg_v622);
    let wg_v624 = eval.felt_get_m31(&wg_v616, 3);
    let wg_v625 = eval.felt_get_m31(&wg_v616, 4);
    let wg_v626 = eval.m31_mul(wg_v625, m31_512);
    let wg_v627 = eval.m31_add(wg_v624, wg_v626);
    let wg_v628 = eval.felt_get_m31(&wg_v616, 5);
    let wg_v629 = eval.m31_mul(wg_v628, m31_262144);
    let wg_v630 = eval.m31_add(wg_v627, wg_v629);
    let wg_v631 = eval.felt_get_m31(&wg_v616, 6);
    let wg_v632 = eval.felt_get_m31(&wg_v616, 7);
    let wg_v633 = eval.m31_mul(wg_v632, m31_512);
    let wg_v634 = eval.m31_add(wg_v631, wg_v633);
    let wg_v635 = eval.felt_get_m31(&wg_v616, 8);
    let wg_v636 = eval.m31_mul(wg_v635, m31_262144);
    let wg_v637 = eval.m31_add(wg_v634, wg_v636);
    let wg_v638 = eval.felt_get_m31(&wg_v616, 9);
    let wg_v639 = eval.felt_get_m31(&wg_v616, 10);
    let wg_v640 = eval.m31_mul(wg_v639, m31_512);
    let wg_v641 = eval.m31_add(wg_v638, wg_v640);
    let wg_v642 = eval.felt_get_m31(&wg_v616, 11);
    let wg_v643 = eval.m31_mul(wg_v642, m31_262144);
    let wg_v644 = eval.m31_add(wg_v641, wg_v643);
    let wg_v645 = eval.felt_get_m31(&wg_v616, 12);
    let wg_v646 = eval.felt_get_m31(&wg_v616, 13);
    let wg_v647 = eval.m31_mul(wg_v646, m31_512);
    let wg_v648 = eval.m31_add(wg_v645, wg_v647);
    let wg_v649 = eval.felt_get_m31(&wg_v616, 14);
    let wg_v650 = eval.m31_mul(wg_v649, m31_262144);
    let wg_v651 = eval.m31_add(wg_v648, wg_v650);
    let wg_v652 = eval.felt_get_m31(&wg_v616, 15);
    let wg_v653 = eval.felt_get_m31(&wg_v616, 16);
    let wg_v654 = eval.m31_mul(wg_v653, m31_512);
    let wg_v655 = eval.m31_add(wg_v652, wg_v654);
    let wg_v656 = eval.felt_get_m31(&wg_v616, 17);
    let wg_v657 = eval.m31_mul(wg_v656, m31_262144);
    let wg_v658 = eval.m31_add(wg_v655, wg_v657);
    let wg_v659 = eval.felt_get_m31(&wg_v616, 18);
    let wg_v660 = eval.felt_get_m31(&wg_v616, 19);
    let wg_v661 = eval.m31_mul(wg_v660, m31_512);
    let wg_v662 = eval.m31_add(wg_v659, wg_v661);
    let wg_v663 = eval.felt_get_m31(&wg_v616, 20);
    let wg_v664 = eval.m31_mul(wg_v663, m31_262144);
    let wg_v665 = eval.m31_add(wg_v662, wg_v664);
    let wg_v666 = eval.felt_get_m31(&wg_v616, 21);
    let wg_v667 = eval.felt_get_m31(&wg_v616, 22);
    let wg_v668 = eval.m31_mul(wg_v667, m31_512);
    let wg_v669 = eval.m31_add(wg_v666, wg_v668);
    let wg_v670 = eval.felt_get_m31(&wg_v616, 23);
    let wg_v671 = eval.m31_mul(wg_v670, m31_262144);
    let wg_v672 = eval.m31_add(wg_v669, wg_v671);
    let wg_v673 = eval.felt_get_m31(&wg_v616, 24);
    let wg_v674 = eval.felt_get_m31(&wg_v616, 25);
    let wg_v675 = eval.m31_mul(wg_v674, m31_512);
    let wg_v676 = eval.m31_add(wg_v673, wg_v675);
    let wg_v677 = eval.felt_get_m31(&wg_v616, 26);
    let wg_v678 = eval.m31_mul(wg_v677, m31_262144);
    let wg_v679 = eval.m31_add(wg_v676, wg_v678);
    let wg_v680 = eval.felt_get_m31(&wg_v616, 27);
    let combination_tmp_3806f_78 = [
        wg_v623, wg_v630, wg_v637, wg_v644, wg_v651, wg_v658, wg_v665, wg_v672, wg_v679, wg_v680,
    ];
    let combination_limb_0_col163 = combination_tmp_3806f_78[0];
    eval.set_col(163, combination_limb_0_col163);
    let combination_limb_1_col164 = combination_tmp_3806f_78[1];
    eval.set_col(164, combination_limb_1_col164);
    let combination_limb_2_col165 = combination_tmp_3806f_78[2];
    eval.set_col(165, combination_limb_2_col165);
    let combination_limb_3_col166 = combination_tmp_3806f_78[3];
    eval.set_col(166, combination_limb_3_col166);
    let combination_limb_4_col167 = combination_tmp_3806f_78[4];
    eval.set_col(167, combination_limb_4_col167);
    let combination_limb_5_col168 = combination_tmp_3806f_78[5];
    eval.set_col(168, combination_limb_5_col168);
    let combination_limb_6_col169 = combination_tmp_3806f_78[6];
    eval.set_col(169, combination_limb_6_col169);
    let combination_limb_7_col170 = combination_tmp_3806f_78[7];
    eval.set_col(170, combination_limb_7_col170);
    let combination_limb_8_col171 = combination_tmp_3806f_78[8];
    eval.set_col(171, combination_limb_8_col171);
    let combination_limb_9_col172 = combination_tmp_3806f_78[9];
    eval.set_col(172, combination_limb_9_col172);
    let wg_v681 = eval.m31_add(
        poseidon_full_round_chain_output_limb_0_col123,
        poseidon_full_round_chain_output_limb_10_col133,
    );
    let wg_v682 = eval.m31_mul(m31_2, cube_252_output_limb_0_col153);
    let wg_v683 = eval.m31_sub(wg_v681, wg_v682);
    let wg_v684 = eval.m31_add(wg_v683, m31_103094260);
    let wg_v685 = eval.m31_sub(wg_v684, combination_limb_0_col163);
    let wg_v686 = eval.m31_add(wg_v685, m31_402653187);
    let biased_limb_accumulator_u32_tmp_3806f_79 = eval.u32_from_m31(wg_v686);
    let wg_v687 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_79);
    let wg_v688 = eval.u16_as_m31(wg_v687);
    let p_coef_col173 = eval.m31_sub(wg_v688, m31_3);
    eval.set_col(173, p_coef_col173);
    let wg_v689 = eval.m31_add(
        poseidon_full_round_chain_output_limb_0_col123,
        poseidon_full_round_chain_output_limb_10_col133,
    );
    let wg_v690 = eval.m31_mul(m31_2, cube_252_output_limb_0_col153);
    let wg_v691 = eval.m31_sub(wg_v689, wg_v690);
    let wg_v692 = eval.m31_add(wg_v691, m31_103094260);
    let wg_v693 = eval.m31_sub(wg_v692, combination_limb_0_col163);
    let wg_v694 = eval.m31_sub(wg_v693, p_coef_col173);
    let carry_0_tmp_3806f_80 = eval.m31_mul(wg_v694, m31_16);
    let wg_v695 = eval.m31_add(
        carry_0_tmp_3806f_80,
        poseidon_full_round_chain_output_limb_1_col124,
    );
    let wg_v696 = eval.m31_add(wg_v695, poseidon_full_round_chain_output_limb_11_col134);
    let wg_v697 = eval.m31_mul(m31_2, cube_252_output_limb_1_col154);
    let wg_v698 = eval.m31_sub(wg_v696, wg_v697);
    let wg_v699 = eval.m31_add(wg_v698, m31_121146754);
    let wg_v700 = eval.m31_sub(wg_v699, combination_limb_1_col164);
    let carry_1_tmp_3806f_81 = eval.m31_mul(wg_v700, m31_16);
    let wg_v701 = eval.m31_add(
        carry_1_tmp_3806f_81,
        poseidon_full_round_chain_output_limb_2_col125,
    );
    let wg_v702 = eval.m31_add(wg_v701, poseidon_full_round_chain_output_limb_12_col135);
    let wg_v703 = eval.m31_mul(m31_2, cube_252_output_limb_2_col155);
    let wg_v704 = eval.m31_sub(wg_v702, wg_v703);
    let wg_v705 = eval.m31_add(wg_v704, m31_95050340);
    let wg_v706 = eval.m31_sub(wg_v705, combination_limb_2_col165);
    let carry_2_tmp_3806f_82 = eval.m31_mul(wg_v706, m31_16);
    let wg_v707 = eval.m31_add(
        carry_2_tmp_3806f_82,
        poseidon_full_round_chain_output_limb_3_col126,
    );
    let wg_v708 = eval.m31_add(wg_v707, poseidon_full_round_chain_output_limb_13_col136);
    let wg_v709 = eval.m31_mul(m31_2, cube_252_output_limb_3_col156);
    let wg_v710 = eval.m31_sub(wg_v708, wg_v709);
    let wg_v711 = eval.m31_add(wg_v710, m31_16173996);
    let wg_v712 = eval.m31_sub(wg_v711, combination_limb_3_col166);
    let carry_3_tmp_3806f_83 = eval.m31_mul(wg_v712, m31_16);
    let wg_v713 = eval.m31_add(
        carry_3_tmp_3806f_83,
        poseidon_full_round_chain_output_limb_4_col127,
    );
    let wg_v714 = eval.m31_add(wg_v713, poseidon_full_round_chain_output_limb_14_col137);
    let wg_v715 = eval.m31_mul(m31_2, cube_252_output_limb_4_col157);
    let wg_v716 = eval.m31_sub(wg_v714, wg_v715);
    let wg_v717 = eval.m31_add(wg_v716, m31_50758155);
    let wg_v718 = eval.m31_sub(wg_v717, combination_limb_4_col167);
    let carry_4_tmp_3806f_84 = eval.m31_mul(wg_v718, m31_16);
    let wg_v719 = eval.m31_add(
        carry_4_tmp_3806f_84,
        poseidon_full_round_chain_output_limb_5_col128,
    );
    let wg_v720 = eval.m31_add(wg_v719, poseidon_full_round_chain_output_limb_15_col138);
    let wg_v721 = eval.m31_mul(m31_2, cube_252_output_limb_5_col158);
    let wg_v722 = eval.m31_sub(wg_v720, wg_v721);
    let wg_v723 = eval.m31_add(wg_v722, m31_54415179);
    let wg_v724 = eval.m31_sub(wg_v723, combination_limb_5_col168);
    let carry_5_tmp_3806f_85 = eval.m31_mul(wg_v724, m31_16);
    let wg_v725 = eval.m31_add(
        carry_5_tmp_3806f_85,
        poseidon_full_round_chain_output_limb_6_col129,
    );
    let wg_v726 = eval.m31_add(wg_v725, poseidon_full_round_chain_output_limb_16_col139);
    let wg_v727 = eval.m31_mul(m31_2, cube_252_output_limb_6_col159);
    let wg_v728 = eval.m31_sub(wg_v726, wg_v727);
    let wg_v729 = eval.m31_add(wg_v728, m31_19292069);
    let wg_v730 = eval.m31_sub(wg_v729, combination_limb_6_col169);
    let carry_6_tmp_3806f_86 = eval.m31_mul(wg_v730, m31_16);
    let wg_v731 = eval.m31_add(
        carry_6_tmp_3806f_86,
        poseidon_full_round_chain_output_limb_7_col130,
    );
    let wg_v732 = eval.m31_add(wg_v731, poseidon_full_round_chain_output_limb_17_col140);
    let wg_v733 = eval.m31_mul(m31_2, cube_252_output_limb_7_col160);
    let wg_v734 = eval.m31_sub(wg_v732, wg_v733);
    let wg_v735 = eval.m31_add(wg_v734, m31_45351266);
    let wg_v736 = eval.m31_sub(wg_v735, combination_limb_7_col170);
    let wg_v737 = eval.m31_mul(p_coef_col173, m31_136);
    let wg_v738 = eval.m31_sub(wg_v736, wg_v737);
    let carry_7_tmp_3806f_87 = eval.m31_mul(wg_v738, m31_16);
    let wg_v739 = eval.m31_add(
        carry_7_tmp_3806f_87,
        poseidon_full_round_chain_output_limb_8_col131,
    );
    let wg_v740 = eval.m31_add(wg_v739, poseidon_full_round_chain_output_limb_18_col141);
    let wg_v741 = eval.m31_mul(m31_2, cube_252_output_limb_8_col161);
    let wg_v742 = eval.m31_sub(wg_v740, wg_v741);
    let wg_v743 = eval.m31_add(wg_v742, m31_122233508);
    let wg_v744 = eval.m31_sub(wg_v743, combination_limb_8_col171);
    let carry_8_tmp_3806f_88 = eval.m31_mul(wg_v744, m31_16);
    let wg_v745 = eval.m31_add(p_coef_col173, m31_3);
    let wg_v746 = eval.m31_add(carry_0_tmp_3806f_80, m31_3);
    let wg_v747 = eval.m31_add(carry_1_tmp_3806f_81, m31_3);
    let wg_v748 = eval.m31_add(carry_2_tmp_3806f_82, m31_3);
    let wg_v749 = eval.m31_add(carry_3_tmp_3806f_83, m31_3);
    eval.set_sub_input_word(302, wg_v745);
    eval.set_sub_input_word(303, wg_v746);
    eval.set_sub_input_word(304, wg_v747);
    eval.set_sub_input_word(305, wg_v748);
    eval.set_sub_input_word(306, wg_v749);
    eval.set_lookup_word(199, m31_502259093);
    let wg_v750 = eval.m31_add(p_coef_col173, m31_3);
    eval.set_lookup_word(200, wg_v750);
    let wg_v751 = eval.m31_add(carry_0_tmp_3806f_80, m31_3);
    eval.set_lookup_word(201, wg_v751);
    let wg_v752 = eval.m31_add(carry_1_tmp_3806f_81, m31_3);
    eval.set_lookup_word(202, wg_v752);
    let wg_v753 = eval.m31_add(carry_2_tmp_3806f_82, m31_3);
    eval.set_lookup_word(203, wg_v753);
    let wg_v754 = eval.m31_add(carry_3_tmp_3806f_83, m31_3);
    eval.set_lookup_word(204, wg_v754);
    let wg_v755 = eval.m31_add(carry_4_tmp_3806f_84, m31_3);
    let wg_v756 = eval.m31_add(carry_5_tmp_3806f_85, m31_3);
    let wg_v757 = eval.m31_add(carry_6_tmp_3806f_86, m31_3);
    let wg_v758 = eval.m31_add(carry_7_tmp_3806f_87, m31_3);
    let wg_v759 = eval.m31_add(carry_8_tmp_3806f_88, m31_3);
    eval.set_sub_input_word(307, wg_v755);
    eval.set_sub_input_word(308, wg_v756);
    eval.set_sub_input_word(309, wg_v757);
    eval.set_sub_input_word(310, wg_v758);
    eval.set_sub_input_word(311, wg_v759);
    eval.set_lookup_word(205, m31_502259093);
    let wg_v760 = eval.m31_add(carry_4_tmp_3806f_84, m31_3);
    eval.set_lookup_word(206, wg_v760);
    let wg_v761 = eval.m31_add(carry_5_tmp_3806f_85, m31_3);
    eval.set_lookup_word(207, wg_v761);
    let wg_v762 = eval.m31_add(carry_6_tmp_3806f_86, m31_3);
    eval.set_lookup_word(208, wg_v762);
    let wg_v763 = eval.m31_add(carry_7_tmp_3806f_87, m31_3);
    eval.set_lookup_word(209, wg_v763);
    let wg_v764 = eval.m31_add(carry_8_tmp_3806f_88, m31_3);
    eval.set_lookup_word(210, wg_v764);
    let linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89 = combination_tmp_3806f_78;
    let wg_v765 = linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89;
    let wg_v766 = wg_v765[0];
    let wg_v767 = wg_v765[1];
    let wg_v768 = wg_v765[2];
    let wg_v769 = wg_v765[3];
    let wg_v770 = wg_v765[4];
    let wg_v771 = wg_v765[5];
    let wg_v772 = wg_v765[6];
    let wg_v773 = wg_v765[7];
    let wg_v774 = wg_v765[8];
    let wg_v775 = wg_v765[9];
    eval.set_sub_input_word(292, wg_v766);
    eval.set_sub_input_word(293, wg_v767);
    eval.set_sub_input_word(294, wg_v768);
    eval.set_sub_input_word(295, wg_v769);
    eval.set_sub_input_word(296, wg_v770);
    eval.set_sub_input_word(297, wg_v771);
    eval.set_sub_input_word(298, wg_v772);
    eval.set_sub_input_word(299, wg_v773);
    eval.set_sub_input_word(300, wg_v774);
    eval.set_sub_input_word(301, wg_v775);
    let cube_252_output_tmp_3806f_90 =
        eval.deduce_cube_252(linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89);
    let cube_252_output_limb_0_col174 = cube_252_output_tmp_3806f_90[0];
    eval.set_col(174, cube_252_output_limb_0_col174);
    let cube_252_output_limb_1_col175 = cube_252_output_tmp_3806f_90[1];
    eval.set_col(175, cube_252_output_limb_1_col175);
    let cube_252_output_limb_2_col176 = cube_252_output_tmp_3806f_90[2];
    eval.set_col(176, cube_252_output_limb_2_col176);
    let cube_252_output_limb_3_col177 = cube_252_output_tmp_3806f_90[3];
    eval.set_col(177, cube_252_output_limb_3_col177);
    let cube_252_output_limb_4_col178 = cube_252_output_tmp_3806f_90[4];
    eval.set_col(178, cube_252_output_limb_4_col178);
    let cube_252_output_limb_5_col179 = cube_252_output_tmp_3806f_90[5];
    eval.set_col(179, cube_252_output_limb_5_col179);
    let cube_252_output_limb_6_col180 = cube_252_output_tmp_3806f_90[6];
    eval.set_col(180, cube_252_output_limb_6_col180);
    let cube_252_output_limb_7_col181 = cube_252_output_tmp_3806f_90[7];
    eval.set_col(181, cube_252_output_limb_7_col181);
    let cube_252_output_limb_8_col182 = cube_252_output_tmp_3806f_90[8];
    eval.set_col(182, cube_252_output_limb_8_col182);
    let cube_252_output_limb_9_col183 = cube_252_output_tmp_3806f_90[9];
    eval.set_col(183, cube_252_output_limb_9_col183);
    eval.set_lookup_word(211, m31_1987997202);
    eval.set_lookup_word(212, combination_limb_0_col163);
    eval.set_lookup_word(213, combination_limb_1_col164);
    eval.set_lookup_word(214, combination_limb_2_col165);
    eval.set_lookup_word(215, combination_limb_3_col166);
    eval.set_lookup_word(216, combination_limb_4_col167);
    eval.set_lookup_word(217, combination_limb_5_col168);
    eval.set_lookup_word(218, combination_limb_6_col169);
    eval.set_lookup_word(219, combination_limb_7_col170);
    eval.set_lookup_word(220, combination_limb_8_col171);
    eval.set_lookup_word(221, combination_limb_9_col172);
    eval.set_lookup_word(222, cube_252_output_limb_0_col174);
    eval.set_lookup_word(223, cube_252_output_limb_1_col175);
    eval.set_lookup_word(224, cube_252_output_limb_2_col176);
    eval.set_lookup_word(225, cube_252_output_limb_3_col177);
    eval.set_lookup_word(226, cube_252_output_limb_4_col178);
    eval.set_lookup_word(227, cube_252_output_limb_5_col179);
    eval.set_lookup_word(228, cube_252_output_limb_6_col180);
    eval.set_lookup_word(229, cube_252_output_limb_7_col181);
    eval.set_lookup_word(230, cube_252_output_limb_8_col182);
    eval.set_lookup_word(231, cube_252_output_limb_9_col183);
    let wg_v776 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v777 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v778 =
        eval.felt_from_w27_words(poseidon_full_round_chain_output_round_3_tmp_3806f_76.2[0]);
    let wg_v779 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v780 = eval.felt_mul(wg_v779.clone(), wg_v778.clone());
    let wg_v781 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v782 = eval.felt_add(wg_v781.clone(), wg_v780.clone());
    let wg_v783 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v784 = eval.felt_from_w27_words(cube_252_output_tmp_3806f_77);
    let wg_v785 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v786 = eval.felt_mul(wg_v785.clone(), wg_v784.clone());
    let wg_v787 = eval.felt_add(wg_v782.clone(), wg_v786.clone());
    let wg_v788 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v789 = eval.felt_from_w27_words(cube_252_output_tmp_3806f_90);
    let wg_v790 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v791 = eval.felt_mul(wg_v790.clone(), wg_v789.clone());
    let wg_v792 = eval.felt_sub(wg_v787.clone(), wg_v791.clone());
    let wg_v793 = eval.felt_from_limbs([
        m31_33, m31_44, m31_464, m31_215, m31_39, m31_429, m31_94, m31_259, m31_497, m31_200,
        m31_500, m31_18, m31_431, m31_163, m31_228, m31_66, m31_88, m31_459, m31_466, m31_96,
        m31_238, m31_289, m31_267, m31_192, m31_77, m31_129, m31_330, m31_154,
    ]);
    let wg_v794 = eval.felt_from_limbs([
        m31_33, m31_44, m31_464, m31_215, m31_39, m31_429, m31_94, m31_259, m31_497, m31_200,
        m31_500, m31_18, m31_431, m31_163, m31_228, m31_66, m31_88, m31_459, m31_466, m31_96,
        m31_238, m31_289, m31_267, m31_192, m31_77, m31_129, m31_330, m31_154,
    ]);
    let wg_v795 = eval.felt_add(wg_v792.clone(), wg_v794.clone());
    let wg_v796 = eval.felt_get_m31(&wg_v795, 0);
    let wg_v797 = eval.felt_get_m31(&wg_v795, 1);
    let wg_v798 = eval.m31_mul(wg_v797, m31_512);
    let wg_v799 = eval.m31_add(wg_v796, wg_v798);
    let wg_v800 = eval.felt_get_m31(&wg_v795, 2);
    let wg_v801 = eval.m31_mul(wg_v800, m31_262144);
    let wg_v802 = eval.m31_add(wg_v799, wg_v801);
    let wg_v803 = eval.felt_get_m31(&wg_v795, 3);
    let wg_v804 = eval.felt_get_m31(&wg_v795, 4);
    let wg_v805 = eval.m31_mul(wg_v804, m31_512);
    let wg_v806 = eval.m31_add(wg_v803, wg_v805);
    let wg_v807 = eval.felt_get_m31(&wg_v795, 5);
    let wg_v808 = eval.m31_mul(wg_v807, m31_262144);
    let wg_v809 = eval.m31_add(wg_v806, wg_v808);
    let wg_v810 = eval.felt_get_m31(&wg_v795, 6);
    let wg_v811 = eval.felt_get_m31(&wg_v795, 7);
    let wg_v812 = eval.m31_mul(wg_v811, m31_512);
    let wg_v813 = eval.m31_add(wg_v810, wg_v812);
    let wg_v814 = eval.felt_get_m31(&wg_v795, 8);
    let wg_v815 = eval.m31_mul(wg_v814, m31_262144);
    let wg_v816 = eval.m31_add(wg_v813, wg_v815);
    let wg_v817 = eval.felt_get_m31(&wg_v795, 9);
    let wg_v818 = eval.felt_get_m31(&wg_v795, 10);
    let wg_v819 = eval.m31_mul(wg_v818, m31_512);
    let wg_v820 = eval.m31_add(wg_v817, wg_v819);
    let wg_v821 = eval.felt_get_m31(&wg_v795, 11);
    let wg_v822 = eval.m31_mul(wg_v821, m31_262144);
    let wg_v823 = eval.m31_add(wg_v820, wg_v822);
    let wg_v824 = eval.felt_get_m31(&wg_v795, 12);
    let wg_v825 = eval.felt_get_m31(&wg_v795, 13);
    let wg_v826 = eval.m31_mul(wg_v825, m31_512);
    let wg_v827 = eval.m31_add(wg_v824, wg_v826);
    let wg_v828 = eval.felt_get_m31(&wg_v795, 14);
    let wg_v829 = eval.m31_mul(wg_v828, m31_262144);
    let wg_v830 = eval.m31_add(wg_v827, wg_v829);
    let wg_v831 = eval.felt_get_m31(&wg_v795, 15);
    let wg_v832 = eval.felt_get_m31(&wg_v795, 16);
    let wg_v833 = eval.m31_mul(wg_v832, m31_512);
    let wg_v834 = eval.m31_add(wg_v831, wg_v833);
    let wg_v835 = eval.felt_get_m31(&wg_v795, 17);
    let wg_v836 = eval.m31_mul(wg_v835, m31_262144);
    let wg_v837 = eval.m31_add(wg_v834, wg_v836);
    let wg_v838 = eval.felt_get_m31(&wg_v795, 18);
    let wg_v839 = eval.felt_get_m31(&wg_v795, 19);
    let wg_v840 = eval.m31_mul(wg_v839, m31_512);
    let wg_v841 = eval.m31_add(wg_v838, wg_v840);
    let wg_v842 = eval.felt_get_m31(&wg_v795, 20);
    let wg_v843 = eval.m31_mul(wg_v842, m31_262144);
    let wg_v844 = eval.m31_add(wg_v841, wg_v843);
    let wg_v845 = eval.felt_get_m31(&wg_v795, 21);
    let wg_v846 = eval.felt_get_m31(&wg_v795, 22);
    let wg_v847 = eval.m31_mul(wg_v846, m31_512);
    let wg_v848 = eval.m31_add(wg_v845, wg_v847);
    let wg_v849 = eval.felt_get_m31(&wg_v795, 23);
    let wg_v850 = eval.m31_mul(wg_v849, m31_262144);
    let wg_v851 = eval.m31_add(wg_v848, wg_v850);
    let wg_v852 = eval.felt_get_m31(&wg_v795, 24);
    let wg_v853 = eval.felt_get_m31(&wg_v795, 25);
    let wg_v854 = eval.m31_mul(wg_v853, m31_512);
    let wg_v855 = eval.m31_add(wg_v852, wg_v854);
    let wg_v856 = eval.felt_get_m31(&wg_v795, 26);
    let wg_v857 = eval.m31_mul(wg_v856, m31_262144);
    let wg_v858 = eval.m31_add(wg_v855, wg_v857);
    let wg_v859 = eval.felt_get_m31(&wg_v795, 27);
    let combination_tmp_3806f_91 = [
        wg_v802, wg_v809, wg_v816, wg_v823, wg_v830, wg_v837, wg_v844, wg_v851, wg_v858, wg_v859,
    ];
    let combination_limb_0_col184 = combination_tmp_3806f_91[0];
    eval.set_col(184, combination_limb_0_col184);
    let combination_limb_1_col185 = combination_tmp_3806f_91[1];
    eval.set_col(185, combination_limb_1_col185);
    let combination_limb_2_col186 = combination_tmp_3806f_91[2];
    eval.set_col(186, combination_limb_2_col186);
    let combination_limb_3_col187 = combination_tmp_3806f_91[3];
    eval.set_col(187, combination_limb_3_col187);
    let combination_limb_4_col188 = combination_tmp_3806f_91[4];
    eval.set_col(188, combination_limb_4_col188);
    let combination_limb_5_col189 = combination_tmp_3806f_91[5];
    eval.set_col(189, combination_limb_5_col189);
    let combination_limb_6_col190 = combination_tmp_3806f_91[6];
    eval.set_col(190, combination_limb_6_col190);
    let combination_limb_7_col191 = combination_tmp_3806f_91[7];
    eval.set_col(191, combination_limb_7_col191);
    let combination_limb_8_col192 = combination_tmp_3806f_91[8];
    eval.set_col(192, combination_limb_8_col192);
    let combination_limb_9_col193 = combination_tmp_3806f_91[9];
    eval.set_col(193, combination_limb_9_col193);
    let wg_v860 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_0_col123);
    let wg_v861 = eval.m31_mul(m31_2, cube_252_output_limb_0_col153);
    let wg_v862 = eval.m31_add(wg_v860, wg_v861);
    let wg_v863 = eval.m31_mul(m31_2, cube_252_output_limb_0_col174);
    let wg_v864 = eval.m31_sub(wg_v862, wg_v863);
    let wg_v865 = eval.m31_add(wg_v864, m31_121657377);
    let wg_v866 = eval.m31_sub(wg_v865, combination_limb_0_col184);
    let wg_v867 = eval.m31_add(wg_v866, m31_402653187);
    let biased_limb_accumulator_u32_tmp_3806f_92 = eval.u32_from_m31(wg_v867);
    let wg_v868 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_92);
    let wg_v869 = eval.u16_as_m31(wg_v868);
    let p_coef_col194 = eval.m31_sub(wg_v869, m31_3);
    eval.set_col(194, p_coef_col194);
    let wg_v870 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_0_col123);
    let wg_v871 = eval.m31_mul(m31_2, cube_252_output_limb_0_col153);
    let wg_v872 = eval.m31_add(wg_v870, wg_v871);
    let wg_v873 = eval.m31_mul(m31_2, cube_252_output_limb_0_col174);
    let wg_v874 = eval.m31_sub(wg_v872, wg_v873);
    let wg_v875 = eval.m31_add(wg_v874, m31_121657377);
    let wg_v876 = eval.m31_sub(wg_v875, combination_limb_0_col184);
    let wg_v877 = eval.m31_sub(wg_v876, p_coef_col194);
    let carry_0_tmp_3806f_93 = eval.m31_mul(wg_v877, m31_16);
    let wg_v878 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_1_col124);
    let wg_v879 = eval.m31_add(carry_0_tmp_3806f_93, wg_v878);
    let wg_v880 = eval.m31_mul(m31_2, cube_252_output_limb_1_col154);
    let wg_v881 = eval.m31_add(wg_v879, wg_v880);
    let wg_v882 = eval.m31_mul(m31_2, cube_252_output_limb_1_col175);
    let wg_v883 = eval.m31_sub(wg_v881, wg_v882);
    let wg_v884 = eval.m31_add(wg_v883, m31_112479959);
    let wg_v885 = eval.m31_sub(wg_v884, combination_limb_1_col185);
    let carry_1_tmp_3806f_94 = eval.m31_mul(wg_v885, m31_16);
    let wg_v886 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_2_col125);
    let wg_v887 = eval.m31_add(carry_1_tmp_3806f_94, wg_v886);
    let wg_v888 = eval.m31_mul(m31_2, cube_252_output_limb_2_col155);
    let wg_v889 = eval.m31_add(wg_v887, wg_v888);
    let wg_v890 = eval.m31_mul(m31_2, cube_252_output_limb_2_col176);
    let wg_v891 = eval.m31_sub(wg_v889, wg_v890);
    let wg_v892 = eval.m31_add(wg_v891, m31_130418270);
    let wg_v893 = eval.m31_sub(wg_v892, combination_limb_2_col186);
    let carry_2_tmp_3806f_95 = eval.m31_mul(wg_v893, m31_16);
    let wg_v894 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_3_col126);
    let wg_v895 = eval.m31_add(carry_2_tmp_3806f_95, wg_v894);
    let wg_v896 = eval.m31_mul(m31_2, cube_252_output_limb_3_col156);
    let wg_v897 = eval.m31_add(wg_v895, wg_v896);
    let wg_v898 = eval.m31_mul(m31_2, cube_252_output_limb_3_col177);
    let wg_v899 = eval.m31_sub(wg_v897, wg_v898);
    let wg_v900 = eval.m31_add(wg_v899, m31_4974792);
    let wg_v901 = eval.m31_sub(wg_v900, combination_limb_3_col187);
    let carry_3_tmp_3806f_96 = eval.m31_mul(wg_v901, m31_16);
    let wg_v902 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_4_col127);
    let wg_v903 = eval.m31_add(carry_3_tmp_3806f_96, wg_v902);
    let wg_v904 = eval.m31_mul(m31_2, cube_252_output_limb_4_col157);
    let wg_v905 = eval.m31_add(wg_v903, wg_v904);
    let wg_v906 = eval.m31_mul(m31_2, cube_252_output_limb_4_col178);
    let wg_v907 = eval.m31_sub(wg_v905, wg_v906);
    let wg_v908 = eval.m31_add(wg_v907, m31_59852719);
    let wg_v909 = eval.m31_sub(wg_v908, combination_limb_4_col188);
    let carry_4_tmp_3806f_97 = eval.m31_mul(wg_v909, m31_16);
    let wg_v910 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_5_col128);
    let wg_v911 = eval.m31_add(carry_4_tmp_3806f_97, wg_v910);
    let wg_v912 = eval.m31_mul(m31_2, cube_252_output_limb_5_col158);
    let wg_v913 = eval.m31_add(wg_v911, wg_v912);
    let wg_v914 = eval.m31_mul(m31_2, cube_252_output_limb_5_col179);
    let wg_v915 = eval.m31_sub(wg_v913, wg_v914);
    let wg_v916 = eval.m31_add(wg_v915, m31_120369218);
    let wg_v917 = eval.m31_sub(wg_v916, combination_limb_5_col189);
    let carry_5_tmp_3806f_98 = eval.m31_mul(wg_v917, m31_16);
    let wg_v918 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_6_col129);
    let wg_v919 = eval.m31_add(carry_5_tmp_3806f_98, wg_v918);
    let wg_v920 = eval.m31_mul(m31_2, cube_252_output_limb_6_col159);
    let wg_v921 = eval.m31_add(wg_v919, wg_v920);
    let wg_v922 = eval.m31_mul(m31_2, cube_252_output_limb_6_col180);
    let wg_v923 = eval.m31_sub(wg_v921, wg_v922);
    let wg_v924 = eval.m31_add(wg_v923, m31_62439890);
    let wg_v925 = eval.m31_sub(wg_v924, combination_limb_6_col190);
    let carry_6_tmp_3806f_99 = eval.m31_mul(wg_v925, m31_16);
    let wg_v926 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_7_col130);
    let wg_v927 = eval.m31_add(carry_6_tmp_3806f_99, wg_v926);
    let wg_v928 = eval.m31_mul(m31_2, cube_252_output_limb_7_col160);
    let wg_v929 = eval.m31_add(wg_v927, wg_v928);
    let wg_v930 = eval.m31_mul(m31_2, cube_252_output_limb_7_col181);
    let wg_v931 = eval.m31_sub(wg_v929, wg_v930);
    let wg_v932 = eval.m31_add(wg_v931, m31_50468641);
    let wg_v933 = eval.m31_sub(wg_v932, combination_limb_7_col191);
    let wg_v934 = eval.m31_mul(p_coef_col194, m31_136);
    let wg_v935 = eval.m31_sub(wg_v933, wg_v934);
    let carry_7_tmp_3806f_100 = eval.m31_mul(wg_v935, m31_16);
    let wg_v936 = eval.m31_mul(m31_4, poseidon_full_round_chain_output_limb_8_col131);
    let wg_v937 = eval.m31_add(carry_7_tmp_3806f_100, wg_v936);
    let wg_v938 = eval.m31_mul(m31_2, cube_252_output_limb_8_col161);
    let wg_v939 = eval.m31_add(wg_v937, wg_v938);
    let wg_v940 = eval.m31_mul(m31_2, cube_252_output_limb_8_col182);
    let wg_v941 = eval.m31_sub(wg_v939, wg_v940);
    let wg_v942 = eval.m31_add(wg_v941, m31_86573645);
    let wg_v943 = eval.m31_sub(wg_v942, combination_limb_8_col192);
    let carry_8_tmp_3806f_101 = eval.m31_mul(wg_v943, m31_16);
    let wg_v944 = eval.m31_add(p_coef_col194, m31_3);
    let wg_v945 = eval.m31_add(carry_0_tmp_3806f_93, m31_3);
    let wg_v946 = eval.m31_add(carry_1_tmp_3806f_94, m31_3);
    let wg_v947 = eval.m31_add(carry_2_tmp_3806f_95, m31_3);
    eval.set_sub_input_word(312, wg_v944);
    eval.set_sub_input_word(313, wg_v945);
    eval.set_sub_input_word(314, wg_v946);
    eval.set_sub_input_word(315, wg_v947);
    eval.set_lookup_word(232, m31_1027333874);
    let wg_v948 = eval.m31_add(p_coef_col194, m31_3);
    eval.set_lookup_word(233, wg_v948);
    let wg_v949 = eval.m31_add(carry_0_tmp_3806f_93, m31_3);
    eval.set_lookup_word(234, wg_v949);
    let wg_v950 = eval.m31_add(carry_1_tmp_3806f_94, m31_3);
    eval.set_lookup_word(235, wg_v950);
    let wg_v951 = eval.m31_add(carry_2_tmp_3806f_95, m31_3);
    eval.set_lookup_word(236, wg_v951);
    let wg_v952 = eval.m31_add(carry_3_tmp_3806f_96, m31_3);
    let wg_v953 = eval.m31_add(carry_4_tmp_3806f_97, m31_3);
    let wg_v954 = eval.m31_add(carry_5_tmp_3806f_98, m31_3);
    let wg_v955 = eval.m31_add(carry_6_tmp_3806f_99, m31_3);
    eval.set_sub_input_word(316, wg_v952);
    eval.set_sub_input_word(317, wg_v953);
    eval.set_sub_input_word(318, wg_v954);
    eval.set_sub_input_word(319, wg_v955);
    eval.set_lookup_word(237, m31_1027333874);
    let wg_v956 = eval.m31_add(carry_3_tmp_3806f_96, m31_3);
    eval.set_lookup_word(238, wg_v956);
    let wg_v957 = eval.m31_add(carry_4_tmp_3806f_97, m31_3);
    eval.set_lookup_word(239, wg_v957);
    let wg_v958 = eval.m31_add(carry_5_tmp_3806f_98, m31_3);
    eval.set_lookup_word(240, wg_v958);
    let wg_v959 = eval.m31_add(carry_6_tmp_3806f_99, m31_3);
    eval.set_lookup_word(241, wg_v959);
    let wg_v960 = eval.m31_add(carry_7_tmp_3806f_100, m31_3);
    let wg_v961 = eval.m31_add(carry_8_tmp_3806f_101, m31_3);
    eval.set_sub_input_word(336, wg_v960);
    eval.set_sub_input_word(337, wg_v961);
    eval.set_lookup_word(242, m31_1651211826);
    let wg_v962 = eval.m31_add(carry_7_tmp_3806f_100, m31_3);
    eval.set_lookup_word(243, wg_v962);
    let wg_v963 = eval.m31_add(carry_8_tmp_3806f_101, m31_3);
    eval.set_lookup_word(244, wg_v963);
    let linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102 = combination_tmp_3806f_91;
    eval.set_lookup_word(245, m31_1343313504);
    eval.set_lookup_word(246, seq);
    eval.set_lookup_word(247, m31_4);
    eval.set_lookup_word(248, cube_252_output_limb_0_col153);
    eval.set_lookup_word(249, cube_252_output_limb_1_col154);
    eval.set_lookup_word(250, cube_252_output_limb_2_col155);
    eval.set_lookup_word(251, cube_252_output_limb_3_col156);
    eval.set_lookup_word(252, cube_252_output_limb_4_col157);
    eval.set_lookup_word(253, cube_252_output_limb_5_col158);
    eval.set_lookup_word(254, cube_252_output_limb_6_col159);
    eval.set_lookup_word(255, cube_252_output_limb_7_col160);
    eval.set_lookup_word(256, cube_252_output_limb_8_col161);
    eval.set_lookup_word(257, cube_252_output_limb_9_col162);
    eval.set_lookup_word(258, combination_limb_0_col163);
    eval.set_lookup_word(259, combination_limb_1_col164);
    eval.set_lookup_word(260, combination_limb_2_col165);
    eval.set_lookup_word(261, combination_limb_3_col166);
    eval.set_lookup_word(262, combination_limb_4_col167);
    eval.set_lookup_word(263, combination_limb_5_col168);
    eval.set_lookup_word(264, combination_limb_6_col169);
    eval.set_lookup_word(265, combination_limb_7_col170);
    eval.set_lookup_word(266, combination_limb_8_col171);
    eval.set_lookup_word(267, combination_limb_9_col172);
    eval.set_lookup_word(268, cube_252_output_limb_0_col174);
    eval.set_lookup_word(269, cube_252_output_limb_1_col175);
    eval.set_lookup_word(270, cube_252_output_limb_2_col176);
    eval.set_lookup_word(271, cube_252_output_limb_3_col177);
    eval.set_lookup_word(272, cube_252_output_limb_4_col178);
    eval.set_lookup_word(273, cube_252_output_limb_5_col179);
    eval.set_lookup_word(274, cube_252_output_limb_6_col180);
    eval.set_lookup_word(275, cube_252_output_limb_7_col181);
    eval.set_lookup_word(276, cube_252_output_limb_8_col182);
    eval.set_lookup_word(277, cube_252_output_limb_9_col183);
    eval.set_lookup_word(278, combination_limb_0_col184);
    eval.set_lookup_word(279, combination_limb_1_col185);
    eval.set_lookup_word(280, combination_limb_2_col186);
    eval.set_lookup_word(281, combination_limb_3_col187);
    eval.set_lookup_word(282, combination_limb_4_col188);
    eval.set_lookup_word(283, combination_limb_5_col189);
    eval.set_lookup_word(284, combination_limb_6_col190);
    eval.set_lookup_word(285, combination_limb_7_col191);
    eval.set_lookup_word(286, combination_limb_8_col192);
    eval.set_lookup_word(287, combination_limb_9_col193);
    let wg_v964 = cube_252_output_tmp_3806f_77;
    let wg_v965 = wg_v964[0];
    let wg_v966 = wg_v964[1];
    let wg_v967 = wg_v964[2];
    let wg_v968 = wg_v964[3];
    let wg_v969 = wg_v964[4];
    let wg_v970 = wg_v964[5];
    let wg_v971 = wg_v964[6];
    let wg_v972 = wg_v964[7];
    let wg_v973 = wg_v964[8];
    let wg_v974 = wg_v964[9];
    let wg_v975 = linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89;
    let wg_v976 = wg_v975[0];
    let wg_v977 = wg_v975[1];
    let wg_v978 = wg_v975[2];
    let wg_v979 = wg_v975[3];
    let wg_v980 = wg_v975[4];
    let wg_v981 = wg_v975[5];
    let wg_v982 = wg_v975[6];
    let wg_v983 = wg_v975[7];
    let wg_v984 = wg_v975[8];
    let wg_v985 = wg_v975[9];
    let wg_v986 = cube_252_output_tmp_3806f_90;
    let wg_v987 = wg_v986[0];
    let wg_v988 = wg_v986[1];
    let wg_v989 = wg_v986[2];
    let wg_v990 = wg_v986[3];
    let wg_v991 = wg_v986[4];
    let wg_v992 = wg_v986[5];
    let wg_v993 = wg_v986[6];
    let wg_v994 = wg_v986[7];
    let wg_v995 = wg_v986[8];
    let wg_v996 = wg_v986[9];
    let wg_v997 = linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102;
    let wg_v998 = wg_v997[0];
    let wg_v999 = wg_v997[1];
    let wg_v1000 = wg_v997[2];
    let wg_v1001 = wg_v997[3];
    let wg_v1002 = wg_v997[4];
    let wg_v1003 = wg_v997[5];
    let wg_v1004 = wg_v997[6];
    let wg_v1005 = wg_v997[7];
    let wg_v1006 = wg_v997[8];
    let wg_v1007 = wg_v997[9];
    eval.set_sub_input_word(342, seq);
    eval.set_sub_input_word(343, m31_4);
    eval.set_sub_input_word(344, wg_v965);
    eval.set_sub_input_word(345, wg_v966);
    eval.set_sub_input_word(346, wg_v967);
    eval.set_sub_input_word(347, wg_v968);
    eval.set_sub_input_word(348, wg_v969);
    eval.set_sub_input_word(349, wg_v970);
    eval.set_sub_input_word(350, wg_v971);
    eval.set_sub_input_word(351, wg_v972);
    eval.set_sub_input_word(352, wg_v973);
    eval.set_sub_input_word(353, wg_v974);
    eval.set_sub_input_word(354, wg_v976);
    eval.set_sub_input_word(355, wg_v977);
    eval.set_sub_input_word(356, wg_v978);
    eval.set_sub_input_word(357, wg_v979);
    eval.set_sub_input_word(358, wg_v980);
    eval.set_sub_input_word(359, wg_v981);
    eval.set_sub_input_word(360, wg_v982);
    eval.set_sub_input_word(361, wg_v983);
    eval.set_sub_input_word(362, wg_v984);
    eval.set_sub_input_word(363, wg_v985);
    eval.set_sub_input_word(364, wg_v987);
    eval.set_sub_input_word(365, wg_v988);
    eval.set_sub_input_word(366, wg_v989);
    eval.set_sub_input_word(367, wg_v990);
    eval.set_sub_input_word(368, wg_v991);
    eval.set_sub_input_word(369, wg_v992);
    eval.set_sub_input_word(370, wg_v993);
    eval.set_sub_input_word(371, wg_v994);
    eval.set_sub_input_word(372, wg_v995);
    eval.set_sub_input_word(373, wg_v996);
    eval.set_sub_input_word(374, wg_v998);
    eval.set_sub_input_word(375, wg_v999);
    eval.set_sub_input_word(376, wg_v1000);
    eval.set_sub_input_word(377, wg_v1001);
    eval.set_sub_input_word(378, wg_v1002);
    eval.set_sub_input_word(379, wg_v1003);
    eval.set_sub_input_word(380, wg_v1004);
    eval.set_sub_input_word(381, wg_v1005);
    eval.set_sub_input_word(382, wg_v1006);
    eval.set_sub_input_word(383, wg_v1007);
    let poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_4,
            [
                cube_252_output_tmp_3806f_77,
                linear_combination_n_4_coefs_1_1_m2_1_output_tmp_3806f_89,
                cube_252_output_tmp_3806f_90,
                linear_combination_n_4_coefs_4_2_m2_1_output_tmp_3806f_102,
            ],
        );
    let wg_v1008 = poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[0];
    let wg_v1009 = wg_v1008[0];
    let wg_v1010 = wg_v1008[1];
    let wg_v1011 = wg_v1008[2];
    let wg_v1012 = wg_v1008[3];
    let wg_v1013 = wg_v1008[4];
    let wg_v1014 = wg_v1008[5];
    let wg_v1015 = wg_v1008[6];
    let wg_v1016 = wg_v1008[7];
    let wg_v1017 = wg_v1008[8];
    let wg_v1018 = wg_v1008[9];
    let wg_v1019 = poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[1];
    let wg_v1020 = wg_v1019[0];
    let wg_v1021 = wg_v1019[1];
    let wg_v1022 = wg_v1019[2];
    let wg_v1023 = wg_v1019[3];
    let wg_v1024 = wg_v1019[4];
    let wg_v1025 = wg_v1019[5];
    let wg_v1026 = wg_v1019[6];
    let wg_v1027 = wg_v1019[7];
    let wg_v1028 = wg_v1019[8];
    let wg_v1029 = wg_v1019[9];
    let wg_v1030 = poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[2];
    let wg_v1031 = wg_v1030[0];
    let wg_v1032 = wg_v1030[1];
    let wg_v1033 = wg_v1030[2];
    let wg_v1034 = wg_v1030[3];
    let wg_v1035 = wg_v1030[4];
    let wg_v1036 = wg_v1030[5];
    let wg_v1037 = wg_v1030[6];
    let wg_v1038 = wg_v1030[7];
    let wg_v1039 = wg_v1030[8];
    let wg_v1040 = wg_v1030[9];
    let wg_v1041 = poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[3];
    let wg_v1042 = wg_v1041[0];
    let wg_v1043 = wg_v1041[1];
    let wg_v1044 = wg_v1041[2];
    let wg_v1045 = wg_v1041[3];
    let wg_v1046 = wg_v1041[4];
    let wg_v1047 = wg_v1041[5];
    let wg_v1048 = wg_v1041[6];
    let wg_v1049 = wg_v1041[7];
    let wg_v1050 = wg_v1041[8];
    let wg_v1051 = wg_v1041[9];
    eval.set_sub_input_word(384, seq);
    eval.set_sub_input_word(385, m31_5);
    eval.set_sub_input_word(386, wg_v1009);
    eval.set_sub_input_word(387, wg_v1010);
    eval.set_sub_input_word(388, wg_v1011);
    eval.set_sub_input_word(389, wg_v1012);
    eval.set_sub_input_word(390, wg_v1013);
    eval.set_sub_input_word(391, wg_v1014);
    eval.set_sub_input_word(392, wg_v1015);
    eval.set_sub_input_word(393, wg_v1016);
    eval.set_sub_input_word(394, wg_v1017);
    eval.set_sub_input_word(395, wg_v1018);
    eval.set_sub_input_word(396, wg_v1020);
    eval.set_sub_input_word(397, wg_v1021);
    eval.set_sub_input_word(398, wg_v1022);
    eval.set_sub_input_word(399, wg_v1023);
    eval.set_sub_input_word(400, wg_v1024);
    eval.set_sub_input_word(401, wg_v1025);
    eval.set_sub_input_word(402, wg_v1026);
    eval.set_sub_input_word(403, wg_v1027);
    eval.set_sub_input_word(404, wg_v1028);
    eval.set_sub_input_word(405, wg_v1029);
    eval.set_sub_input_word(406, wg_v1031);
    eval.set_sub_input_word(407, wg_v1032);
    eval.set_sub_input_word(408, wg_v1033);
    eval.set_sub_input_word(409, wg_v1034);
    eval.set_sub_input_word(410, wg_v1035);
    eval.set_sub_input_word(411, wg_v1036);
    eval.set_sub_input_word(412, wg_v1037);
    eval.set_sub_input_word(413, wg_v1038);
    eval.set_sub_input_word(414, wg_v1039);
    eval.set_sub_input_word(415, wg_v1040);
    eval.set_sub_input_word(416, wg_v1042);
    eval.set_sub_input_word(417, wg_v1043);
    eval.set_sub_input_word(418, wg_v1044);
    eval.set_sub_input_word(419, wg_v1045);
    eval.set_sub_input_word(420, wg_v1046);
    eval.set_sub_input_word(421, wg_v1047);
    eval.set_sub_input_word(422, wg_v1048);
    eval.set_sub_input_word(423, wg_v1049);
    eval.set_sub_input_word(424, wg_v1050);
    eval.set_sub_input_word(425, wg_v1051);
    let poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_5,
            [
                poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[0],
                poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[1],
                poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[2],
                poseidon_3_partial_rounds_chain_output_round_4_tmp_3806f_104.2[3],
            ],
        );
    let wg_v1052 = poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[0];
    let wg_v1053 = wg_v1052[0];
    let wg_v1054 = wg_v1052[1];
    let wg_v1055 = wg_v1052[2];
    let wg_v1056 = wg_v1052[3];
    let wg_v1057 = wg_v1052[4];
    let wg_v1058 = wg_v1052[5];
    let wg_v1059 = wg_v1052[6];
    let wg_v1060 = wg_v1052[7];
    let wg_v1061 = wg_v1052[8];
    let wg_v1062 = wg_v1052[9];
    let wg_v1063 = poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[1];
    let wg_v1064 = wg_v1063[0];
    let wg_v1065 = wg_v1063[1];
    let wg_v1066 = wg_v1063[2];
    let wg_v1067 = wg_v1063[3];
    let wg_v1068 = wg_v1063[4];
    let wg_v1069 = wg_v1063[5];
    let wg_v1070 = wg_v1063[6];
    let wg_v1071 = wg_v1063[7];
    let wg_v1072 = wg_v1063[8];
    let wg_v1073 = wg_v1063[9];
    let wg_v1074 = poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[2];
    let wg_v1075 = wg_v1074[0];
    let wg_v1076 = wg_v1074[1];
    let wg_v1077 = wg_v1074[2];
    let wg_v1078 = wg_v1074[3];
    let wg_v1079 = wg_v1074[4];
    let wg_v1080 = wg_v1074[5];
    let wg_v1081 = wg_v1074[6];
    let wg_v1082 = wg_v1074[7];
    let wg_v1083 = wg_v1074[8];
    let wg_v1084 = wg_v1074[9];
    let wg_v1085 = poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[3];
    let wg_v1086 = wg_v1085[0];
    let wg_v1087 = wg_v1085[1];
    let wg_v1088 = wg_v1085[2];
    let wg_v1089 = wg_v1085[3];
    let wg_v1090 = wg_v1085[4];
    let wg_v1091 = wg_v1085[5];
    let wg_v1092 = wg_v1085[6];
    let wg_v1093 = wg_v1085[7];
    let wg_v1094 = wg_v1085[8];
    let wg_v1095 = wg_v1085[9];
    eval.set_sub_input_word(426, seq);
    eval.set_sub_input_word(427, m31_6);
    eval.set_sub_input_word(428, wg_v1053);
    eval.set_sub_input_word(429, wg_v1054);
    eval.set_sub_input_word(430, wg_v1055);
    eval.set_sub_input_word(431, wg_v1056);
    eval.set_sub_input_word(432, wg_v1057);
    eval.set_sub_input_word(433, wg_v1058);
    eval.set_sub_input_word(434, wg_v1059);
    eval.set_sub_input_word(435, wg_v1060);
    eval.set_sub_input_word(436, wg_v1061);
    eval.set_sub_input_word(437, wg_v1062);
    eval.set_sub_input_word(438, wg_v1064);
    eval.set_sub_input_word(439, wg_v1065);
    eval.set_sub_input_word(440, wg_v1066);
    eval.set_sub_input_word(441, wg_v1067);
    eval.set_sub_input_word(442, wg_v1068);
    eval.set_sub_input_word(443, wg_v1069);
    eval.set_sub_input_word(444, wg_v1070);
    eval.set_sub_input_word(445, wg_v1071);
    eval.set_sub_input_word(446, wg_v1072);
    eval.set_sub_input_word(447, wg_v1073);
    eval.set_sub_input_word(448, wg_v1075);
    eval.set_sub_input_word(449, wg_v1076);
    eval.set_sub_input_word(450, wg_v1077);
    eval.set_sub_input_word(451, wg_v1078);
    eval.set_sub_input_word(452, wg_v1079);
    eval.set_sub_input_word(453, wg_v1080);
    eval.set_sub_input_word(454, wg_v1081);
    eval.set_sub_input_word(455, wg_v1082);
    eval.set_sub_input_word(456, wg_v1083);
    eval.set_sub_input_word(457, wg_v1084);
    eval.set_sub_input_word(458, wg_v1086);
    eval.set_sub_input_word(459, wg_v1087);
    eval.set_sub_input_word(460, wg_v1088);
    eval.set_sub_input_word(461, wg_v1089);
    eval.set_sub_input_word(462, wg_v1090);
    eval.set_sub_input_word(463, wg_v1091);
    eval.set_sub_input_word(464, wg_v1092);
    eval.set_sub_input_word(465, wg_v1093);
    eval.set_sub_input_word(466, wg_v1094);
    eval.set_sub_input_word(467, wg_v1095);
    let poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_6,
            [
                poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[0],
                poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[1],
                poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[2],
                poseidon_3_partial_rounds_chain_output_round_5_tmp_3806f_105.2[3],
            ],
        );
    let wg_v1096 = poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[0];
    let wg_v1097 = wg_v1096[0];
    let wg_v1098 = wg_v1096[1];
    let wg_v1099 = wg_v1096[2];
    let wg_v1100 = wg_v1096[3];
    let wg_v1101 = wg_v1096[4];
    let wg_v1102 = wg_v1096[5];
    let wg_v1103 = wg_v1096[6];
    let wg_v1104 = wg_v1096[7];
    let wg_v1105 = wg_v1096[8];
    let wg_v1106 = wg_v1096[9];
    let wg_v1107 = poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[1];
    let wg_v1108 = wg_v1107[0];
    let wg_v1109 = wg_v1107[1];
    let wg_v1110 = wg_v1107[2];
    let wg_v1111 = wg_v1107[3];
    let wg_v1112 = wg_v1107[4];
    let wg_v1113 = wg_v1107[5];
    let wg_v1114 = wg_v1107[6];
    let wg_v1115 = wg_v1107[7];
    let wg_v1116 = wg_v1107[8];
    let wg_v1117 = wg_v1107[9];
    let wg_v1118 = poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[2];
    let wg_v1119 = wg_v1118[0];
    let wg_v1120 = wg_v1118[1];
    let wg_v1121 = wg_v1118[2];
    let wg_v1122 = wg_v1118[3];
    let wg_v1123 = wg_v1118[4];
    let wg_v1124 = wg_v1118[5];
    let wg_v1125 = wg_v1118[6];
    let wg_v1126 = wg_v1118[7];
    let wg_v1127 = wg_v1118[8];
    let wg_v1128 = wg_v1118[9];
    let wg_v1129 = poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[3];
    let wg_v1130 = wg_v1129[0];
    let wg_v1131 = wg_v1129[1];
    let wg_v1132 = wg_v1129[2];
    let wg_v1133 = wg_v1129[3];
    let wg_v1134 = wg_v1129[4];
    let wg_v1135 = wg_v1129[5];
    let wg_v1136 = wg_v1129[6];
    let wg_v1137 = wg_v1129[7];
    let wg_v1138 = wg_v1129[8];
    let wg_v1139 = wg_v1129[9];
    eval.set_sub_input_word(468, seq);
    eval.set_sub_input_word(469, m31_7);
    eval.set_sub_input_word(470, wg_v1097);
    eval.set_sub_input_word(471, wg_v1098);
    eval.set_sub_input_word(472, wg_v1099);
    eval.set_sub_input_word(473, wg_v1100);
    eval.set_sub_input_word(474, wg_v1101);
    eval.set_sub_input_word(475, wg_v1102);
    eval.set_sub_input_word(476, wg_v1103);
    eval.set_sub_input_word(477, wg_v1104);
    eval.set_sub_input_word(478, wg_v1105);
    eval.set_sub_input_word(479, wg_v1106);
    eval.set_sub_input_word(480, wg_v1108);
    eval.set_sub_input_word(481, wg_v1109);
    eval.set_sub_input_word(482, wg_v1110);
    eval.set_sub_input_word(483, wg_v1111);
    eval.set_sub_input_word(484, wg_v1112);
    eval.set_sub_input_word(485, wg_v1113);
    eval.set_sub_input_word(486, wg_v1114);
    eval.set_sub_input_word(487, wg_v1115);
    eval.set_sub_input_word(488, wg_v1116);
    eval.set_sub_input_word(489, wg_v1117);
    eval.set_sub_input_word(490, wg_v1119);
    eval.set_sub_input_word(491, wg_v1120);
    eval.set_sub_input_word(492, wg_v1121);
    eval.set_sub_input_word(493, wg_v1122);
    eval.set_sub_input_word(494, wg_v1123);
    eval.set_sub_input_word(495, wg_v1124);
    eval.set_sub_input_word(496, wg_v1125);
    eval.set_sub_input_word(497, wg_v1126);
    eval.set_sub_input_word(498, wg_v1127);
    eval.set_sub_input_word(499, wg_v1128);
    eval.set_sub_input_word(500, wg_v1130);
    eval.set_sub_input_word(501, wg_v1131);
    eval.set_sub_input_word(502, wg_v1132);
    eval.set_sub_input_word(503, wg_v1133);
    eval.set_sub_input_word(504, wg_v1134);
    eval.set_sub_input_word(505, wg_v1135);
    eval.set_sub_input_word(506, wg_v1136);
    eval.set_sub_input_word(507, wg_v1137);
    eval.set_sub_input_word(508, wg_v1138);
    eval.set_sub_input_word(509, wg_v1139);
    let poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_7,
            [
                poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[0],
                poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[1],
                poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[2],
                poseidon_3_partial_rounds_chain_output_round_6_tmp_3806f_106.2[3],
            ],
        );
    let wg_v1140 = poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[0];
    let wg_v1141 = wg_v1140[0];
    let wg_v1142 = wg_v1140[1];
    let wg_v1143 = wg_v1140[2];
    let wg_v1144 = wg_v1140[3];
    let wg_v1145 = wg_v1140[4];
    let wg_v1146 = wg_v1140[5];
    let wg_v1147 = wg_v1140[6];
    let wg_v1148 = wg_v1140[7];
    let wg_v1149 = wg_v1140[8];
    let wg_v1150 = wg_v1140[9];
    let wg_v1151 = poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[1];
    let wg_v1152 = wg_v1151[0];
    let wg_v1153 = wg_v1151[1];
    let wg_v1154 = wg_v1151[2];
    let wg_v1155 = wg_v1151[3];
    let wg_v1156 = wg_v1151[4];
    let wg_v1157 = wg_v1151[5];
    let wg_v1158 = wg_v1151[6];
    let wg_v1159 = wg_v1151[7];
    let wg_v1160 = wg_v1151[8];
    let wg_v1161 = wg_v1151[9];
    let wg_v1162 = poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[2];
    let wg_v1163 = wg_v1162[0];
    let wg_v1164 = wg_v1162[1];
    let wg_v1165 = wg_v1162[2];
    let wg_v1166 = wg_v1162[3];
    let wg_v1167 = wg_v1162[4];
    let wg_v1168 = wg_v1162[5];
    let wg_v1169 = wg_v1162[6];
    let wg_v1170 = wg_v1162[7];
    let wg_v1171 = wg_v1162[8];
    let wg_v1172 = wg_v1162[9];
    let wg_v1173 = poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[3];
    let wg_v1174 = wg_v1173[0];
    let wg_v1175 = wg_v1173[1];
    let wg_v1176 = wg_v1173[2];
    let wg_v1177 = wg_v1173[3];
    let wg_v1178 = wg_v1173[4];
    let wg_v1179 = wg_v1173[5];
    let wg_v1180 = wg_v1173[6];
    let wg_v1181 = wg_v1173[7];
    let wg_v1182 = wg_v1173[8];
    let wg_v1183 = wg_v1173[9];
    eval.set_sub_input_word(510, seq);
    eval.set_sub_input_word(511, m31_8);
    eval.set_sub_input_word(512, wg_v1141);
    eval.set_sub_input_word(513, wg_v1142);
    eval.set_sub_input_word(514, wg_v1143);
    eval.set_sub_input_word(515, wg_v1144);
    eval.set_sub_input_word(516, wg_v1145);
    eval.set_sub_input_word(517, wg_v1146);
    eval.set_sub_input_word(518, wg_v1147);
    eval.set_sub_input_word(519, wg_v1148);
    eval.set_sub_input_word(520, wg_v1149);
    eval.set_sub_input_word(521, wg_v1150);
    eval.set_sub_input_word(522, wg_v1152);
    eval.set_sub_input_word(523, wg_v1153);
    eval.set_sub_input_word(524, wg_v1154);
    eval.set_sub_input_word(525, wg_v1155);
    eval.set_sub_input_word(526, wg_v1156);
    eval.set_sub_input_word(527, wg_v1157);
    eval.set_sub_input_word(528, wg_v1158);
    eval.set_sub_input_word(529, wg_v1159);
    eval.set_sub_input_word(530, wg_v1160);
    eval.set_sub_input_word(531, wg_v1161);
    eval.set_sub_input_word(532, wg_v1163);
    eval.set_sub_input_word(533, wg_v1164);
    eval.set_sub_input_word(534, wg_v1165);
    eval.set_sub_input_word(535, wg_v1166);
    eval.set_sub_input_word(536, wg_v1167);
    eval.set_sub_input_word(537, wg_v1168);
    eval.set_sub_input_word(538, wg_v1169);
    eval.set_sub_input_word(539, wg_v1170);
    eval.set_sub_input_word(540, wg_v1171);
    eval.set_sub_input_word(541, wg_v1172);
    eval.set_sub_input_word(542, wg_v1174);
    eval.set_sub_input_word(543, wg_v1175);
    eval.set_sub_input_word(544, wg_v1176);
    eval.set_sub_input_word(545, wg_v1177);
    eval.set_sub_input_word(546, wg_v1178);
    eval.set_sub_input_word(547, wg_v1179);
    eval.set_sub_input_word(548, wg_v1180);
    eval.set_sub_input_word(549, wg_v1181);
    eval.set_sub_input_word(550, wg_v1182);
    eval.set_sub_input_word(551, wg_v1183);
    let poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_8,
            [
                poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[0],
                poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[1],
                poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[2],
                poseidon_3_partial_rounds_chain_output_round_7_tmp_3806f_107.2[3],
            ],
        );
    let wg_v1184 = poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[0];
    let wg_v1185 = wg_v1184[0];
    let wg_v1186 = wg_v1184[1];
    let wg_v1187 = wg_v1184[2];
    let wg_v1188 = wg_v1184[3];
    let wg_v1189 = wg_v1184[4];
    let wg_v1190 = wg_v1184[5];
    let wg_v1191 = wg_v1184[6];
    let wg_v1192 = wg_v1184[7];
    let wg_v1193 = wg_v1184[8];
    let wg_v1194 = wg_v1184[9];
    let wg_v1195 = poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[1];
    let wg_v1196 = wg_v1195[0];
    let wg_v1197 = wg_v1195[1];
    let wg_v1198 = wg_v1195[2];
    let wg_v1199 = wg_v1195[3];
    let wg_v1200 = wg_v1195[4];
    let wg_v1201 = wg_v1195[5];
    let wg_v1202 = wg_v1195[6];
    let wg_v1203 = wg_v1195[7];
    let wg_v1204 = wg_v1195[8];
    let wg_v1205 = wg_v1195[9];
    let wg_v1206 = poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[2];
    let wg_v1207 = wg_v1206[0];
    let wg_v1208 = wg_v1206[1];
    let wg_v1209 = wg_v1206[2];
    let wg_v1210 = wg_v1206[3];
    let wg_v1211 = wg_v1206[4];
    let wg_v1212 = wg_v1206[5];
    let wg_v1213 = wg_v1206[6];
    let wg_v1214 = wg_v1206[7];
    let wg_v1215 = wg_v1206[8];
    let wg_v1216 = wg_v1206[9];
    let wg_v1217 = poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[3];
    let wg_v1218 = wg_v1217[0];
    let wg_v1219 = wg_v1217[1];
    let wg_v1220 = wg_v1217[2];
    let wg_v1221 = wg_v1217[3];
    let wg_v1222 = wg_v1217[4];
    let wg_v1223 = wg_v1217[5];
    let wg_v1224 = wg_v1217[6];
    let wg_v1225 = wg_v1217[7];
    let wg_v1226 = wg_v1217[8];
    let wg_v1227 = wg_v1217[9];
    eval.set_sub_input_word(552, seq);
    eval.set_sub_input_word(553, m31_9);
    eval.set_sub_input_word(554, wg_v1185);
    eval.set_sub_input_word(555, wg_v1186);
    eval.set_sub_input_word(556, wg_v1187);
    eval.set_sub_input_word(557, wg_v1188);
    eval.set_sub_input_word(558, wg_v1189);
    eval.set_sub_input_word(559, wg_v1190);
    eval.set_sub_input_word(560, wg_v1191);
    eval.set_sub_input_word(561, wg_v1192);
    eval.set_sub_input_word(562, wg_v1193);
    eval.set_sub_input_word(563, wg_v1194);
    eval.set_sub_input_word(564, wg_v1196);
    eval.set_sub_input_word(565, wg_v1197);
    eval.set_sub_input_word(566, wg_v1198);
    eval.set_sub_input_word(567, wg_v1199);
    eval.set_sub_input_word(568, wg_v1200);
    eval.set_sub_input_word(569, wg_v1201);
    eval.set_sub_input_word(570, wg_v1202);
    eval.set_sub_input_word(571, wg_v1203);
    eval.set_sub_input_word(572, wg_v1204);
    eval.set_sub_input_word(573, wg_v1205);
    eval.set_sub_input_word(574, wg_v1207);
    eval.set_sub_input_word(575, wg_v1208);
    eval.set_sub_input_word(576, wg_v1209);
    eval.set_sub_input_word(577, wg_v1210);
    eval.set_sub_input_word(578, wg_v1211);
    eval.set_sub_input_word(579, wg_v1212);
    eval.set_sub_input_word(580, wg_v1213);
    eval.set_sub_input_word(581, wg_v1214);
    eval.set_sub_input_word(582, wg_v1215);
    eval.set_sub_input_word(583, wg_v1216);
    eval.set_sub_input_word(584, wg_v1218);
    eval.set_sub_input_word(585, wg_v1219);
    eval.set_sub_input_word(586, wg_v1220);
    eval.set_sub_input_word(587, wg_v1221);
    eval.set_sub_input_word(588, wg_v1222);
    eval.set_sub_input_word(589, wg_v1223);
    eval.set_sub_input_word(590, wg_v1224);
    eval.set_sub_input_word(591, wg_v1225);
    eval.set_sub_input_word(592, wg_v1226);
    eval.set_sub_input_word(593, wg_v1227);
    let poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_9,
            [
                poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[0],
                poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[1],
                poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[2],
                poseidon_3_partial_rounds_chain_output_round_8_tmp_3806f_108.2[3],
            ],
        );
    let wg_v1228 = poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[0];
    let wg_v1229 = wg_v1228[0];
    let wg_v1230 = wg_v1228[1];
    let wg_v1231 = wg_v1228[2];
    let wg_v1232 = wg_v1228[3];
    let wg_v1233 = wg_v1228[4];
    let wg_v1234 = wg_v1228[5];
    let wg_v1235 = wg_v1228[6];
    let wg_v1236 = wg_v1228[7];
    let wg_v1237 = wg_v1228[8];
    let wg_v1238 = wg_v1228[9];
    let wg_v1239 = poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[1];
    let wg_v1240 = wg_v1239[0];
    let wg_v1241 = wg_v1239[1];
    let wg_v1242 = wg_v1239[2];
    let wg_v1243 = wg_v1239[3];
    let wg_v1244 = wg_v1239[4];
    let wg_v1245 = wg_v1239[5];
    let wg_v1246 = wg_v1239[6];
    let wg_v1247 = wg_v1239[7];
    let wg_v1248 = wg_v1239[8];
    let wg_v1249 = wg_v1239[9];
    let wg_v1250 = poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[2];
    let wg_v1251 = wg_v1250[0];
    let wg_v1252 = wg_v1250[1];
    let wg_v1253 = wg_v1250[2];
    let wg_v1254 = wg_v1250[3];
    let wg_v1255 = wg_v1250[4];
    let wg_v1256 = wg_v1250[5];
    let wg_v1257 = wg_v1250[6];
    let wg_v1258 = wg_v1250[7];
    let wg_v1259 = wg_v1250[8];
    let wg_v1260 = wg_v1250[9];
    let wg_v1261 = poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[3];
    let wg_v1262 = wg_v1261[0];
    let wg_v1263 = wg_v1261[1];
    let wg_v1264 = wg_v1261[2];
    let wg_v1265 = wg_v1261[3];
    let wg_v1266 = wg_v1261[4];
    let wg_v1267 = wg_v1261[5];
    let wg_v1268 = wg_v1261[6];
    let wg_v1269 = wg_v1261[7];
    let wg_v1270 = wg_v1261[8];
    let wg_v1271 = wg_v1261[9];
    eval.set_sub_input_word(594, seq);
    eval.set_sub_input_word(595, m31_10);
    eval.set_sub_input_word(596, wg_v1229);
    eval.set_sub_input_word(597, wg_v1230);
    eval.set_sub_input_word(598, wg_v1231);
    eval.set_sub_input_word(599, wg_v1232);
    eval.set_sub_input_word(600, wg_v1233);
    eval.set_sub_input_word(601, wg_v1234);
    eval.set_sub_input_word(602, wg_v1235);
    eval.set_sub_input_word(603, wg_v1236);
    eval.set_sub_input_word(604, wg_v1237);
    eval.set_sub_input_word(605, wg_v1238);
    eval.set_sub_input_word(606, wg_v1240);
    eval.set_sub_input_word(607, wg_v1241);
    eval.set_sub_input_word(608, wg_v1242);
    eval.set_sub_input_word(609, wg_v1243);
    eval.set_sub_input_word(610, wg_v1244);
    eval.set_sub_input_word(611, wg_v1245);
    eval.set_sub_input_word(612, wg_v1246);
    eval.set_sub_input_word(613, wg_v1247);
    eval.set_sub_input_word(614, wg_v1248);
    eval.set_sub_input_word(615, wg_v1249);
    eval.set_sub_input_word(616, wg_v1251);
    eval.set_sub_input_word(617, wg_v1252);
    eval.set_sub_input_word(618, wg_v1253);
    eval.set_sub_input_word(619, wg_v1254);
    eval.set_sub_input_word(620, wg_v1255);
    eval.set_sub_input_word(621, wg_v1256);
    eval.set_sub_input_word(622, wg_v1257);
    eval.set_sub_input_word(623, wg_v1258);
    eval.set_sub_input_word(624, wg_v1259);
    eval.set_sub_input_word(625, wg_v1260);
    eval.set_sub_input_word(626, wg_v1262);
    eval.set_sub_input_word(627, wg_v1263);
    eval.set_sub_input_word(628, wg_v1264);
    eval.set_sub_input_word(629, wg_v1265);
    eval.set_sub_input_word(630, wg_v1266);
    eval.set_sub_input_word(631, wg_v1267);
    eval.set_sub_input_word(632, wg_v1268);
    eval.set_sub_input_word(633, wg_v1269);
    eval.set_sub_input_word(634, wg_v1270);
    eval.set_sub_input_word(635, wg_v1271);
    let poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_10,
            [
                poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[0],
                poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[1],
                poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[2],
                poseidon_3_partial_rounds_chain_output_round_9_tmp_3806f_109.2[3],
            ],
        );
    let wg_v1272 = poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[0];
    let wg_v1273 = wg_v1272[0];
    let wg_v1274 = wg_v1272[1];
    let wg_v1275 = wg_v1272[2];
    let wg_v1276 = wg_v1272[3];
    let wg_v1277 = wg_v1272[4];
    let wg_v1278 = wg_v1272[5];
    let wg_v1279 = wg_v1272[6];
    let wg_v1280 = wg_v1272[7];
    let wg_v1281 = wg_v1272[8];
    let wg_v1282 = wg_v1272[9];
    let wg_v1283 = poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[1];
    let wg_v1284 = wg_v1283[0];
    let wg_v1285 = wg_v1283[1];
    let wg_v1286 = wg_v1283[2];
    let wg_v1287 = wg_v1283[3];
    let wg_v1288 = wg_v1283[4];
    let wg_v1289 = wg_v1283[5];
    let wg_v1290 = wg_v1283[6];
    let wg_v1291 = wg_v1283[7];
    let wg_v1292 = wg_v1283[8];
    let wg_v1293 = wg_v1283[9];
    let wg_v1294 = poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[2];
    let wg_v1295 = wg_v1294[0];
    let wg_v1296 = wg_v1294[1];
    let wg_v1297 = wg_v1294[2];
    let wg_v1298 = wg_v1294[3];
    let wg_v1299 = wg_v1294[4];
    let wg_v1300 = wg_v1294[5];
    let wg_v1301 = wg_v1294[6];
    let wg_v1302 = wg_v1294[7];
    let wg_v1303 = wg_v1294[8];
    let wg_v1304 = wg_v1294[9];
    let wg_v1305 = poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[3];
    let wg_v1306 = wg_v1305[0];
    let wg_v1307 = wg_v1305[1];
    let wg_v1308 = wg_v1305[2];
    let wg_v1309 = wg_v1305[3];
    let wg_v1310 = wg_v1305[4];
    let wg_v1311 = wg_v1305[5];
    let wg_v1312 = wg_v1305[6];
    let wg_v1313 = wg_v1305[7];
    let wg_v1314 = wg_v1305[8];
    let wg_v1315 = wg_v1305[9];
    eval.set_sub_input_word(636, seq);
    eval.set_sub_input_word(637, m31_11);
    eval.set_sub_input_word(638, wg_v1273);
    eval.set_sub_input_word(639, wg_v1274);
    eval.set_sub_input_word(640, wg_v1275);
    eval.set_sub_input_word(641, wg_v1276);
    eval.set_sub_input_word(642, wg_v1277);
    eval.set_sub_input_word(643, wg_v1278);
    eval.set_sub_input_word(644, wg_v1279);
    eval.set_sub_input_word(645, wg_v1280);
    eval.set_sub_input_word(646, wg_v1281);
    eval.set_sub_input_word(647, wg_v1282);
    eval.set_sub_input_word(648, wg_v1284);
    eval.set_sub_input_word(649, wg_v1285);
    eval.set_sub_input_word(650, wg_v1286);
    eval.set_sub_input_word(651, wg_v1287);
    eval.set_sub_input_word(652, wg_v1288);
    eval.set_sub_input_word(653, wg_v1289);
    eval.set_sub_input_word(654, wg_v1290);
    eval.set_sub_input_word(655, wg_v1291);
    eval.set_sub_input_word(656, wg_v1292);
    eval.set_sub_input_word(657, wg_v1293);
    eval.set_sub_input_word(658, wg_v1295);
    eval.set_sub_input_word(659, wg_v1296);
    eval.set_sub_input_word(660, wg_v1297);
    eval.set_sub_input_word(661, wg_v1298);
    eval.set_sub_input_word(662, wg_v1299);
    eval.set_sub_input_word(663, wg_v1300);
    eval.set_sub_input_word(664, wg_v1301);
    eval.set_sub_input_word(665, wg_v1302);
    eval.set_sub_input_word(666, wg_v1303);
    eval.set_sub_input_word(667, wg_v1304);
    eval.set_sub_input_word(668, wg_v1306);
    eval.set_sub_input_word(669, wg_v1307);
    eval.set_sub_input_word(670, wg_v1308);
    eval.set_sub_input_word(671, wg_v1309);
    eval.set_sub_input_word(672, wg_v1310);
    eval.set_sub_input_word(673, wg_v1311);
    eval.set_sub_input_word(674, wg_v1312);
    eval.set_sub_input_word(675, wg_v1313);
    eval.set_sub_input_word(676, wg_v1314);
    eval.set_sub_input_word(677, wg_v1315);
    let poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_11,
            [
                poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[0],
                poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[1],
                poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[2],
                poseidon_3_partial_rounds_chain_output_round_10_tmp_3806f_110.2[3],
            ],
        );
    let wg_v1316 = poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[0];
    let wg_v1317 = wg_v1316[0];
    let wg_v1318 = wg_v1316[1];
    let wg_v1319 = wg_v1316[2];
    let wg_v1320 = wg_v1316[3];
    let wg_v1321 = wg_v1316[4];
    let wg_v1322 = wg_v1316[5];
    let wg_v1323 = wg_v1316[6];
    let wg_v1324 = wg_v1316[7];
    let wg_v1325 = wg_v1316[8];
    let wg_v1326 = wg_v1316[9];
    let wg_v1327 = poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[1];
    let wg_v1328 = wg_v1327[0];
    let wg_v1329 = wg_v1327[1];
    let wg_v1330 = wg_v1327[2];
    let wg_v1331 = wg_v1327[3];
    let wg_v1332 = wg_v1327[4];
    let wg_v1333 = wg_v1327[5];
    let wg_v1334 = wg_v1327[6];
    let wg_v1335 = wg_v1327[7];
    let wg_v1336 = wg_v1327[8];
    let wg_v1337 = wg_v1327[9];
    let wg_v1338 = poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[2];
    let wg_v1339 = wg_v1338[0];
    let wg_v1340 = wg_v1338[1];
    let wg_v1341 = wg_v1338[2];
    let wg_v1342 = wg_v1338[3];
    let wg_v1343 = wg_v1338[4];
    let wg_v1344 = wg_v1338[5];
    let wg_v1345 = wg_v1338[6];
    let wg_v1346 = wg_v1338[7];
    let wg_v1347 = wg_v1338[8];
    let wg_v1348 = wg_v1338[9];
    let wg_v1349 = poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[3];
    let wg_v1350 = wg_v1349[0];
    let wg_v1351 = wg_v1349[1];
    let wg_v1352 = wg_v1349[2];
    let wg_v1353 = wg_v1349[3];
    let wg_v1354 = wg_v1349[4];
    let wg_v1355 = wg_v1349[5];
    let wg_v1356 = wg_v1349[6];
    let wg_v1357 = wg_v1349[7];
    let wg_v1358 = wg_v1349[8];
    let wg_v1359 = wg_v1349[9];
    eval.set_sub_input_word(678, seq);
    eval.set_sub_input_word(679, m31_12);
    eval.set_sub_input_word(680, wg_v1317);
    eval.set_sub_input_word(681, wg_v1318);
    eval.set_sub_input_word(682, wg_v1319);
    eval.set_sub_input_word(683, wg_v1320);
    eval.set_sub_input_word(684, wg_v1321);
    eval.set_sub_input_word(685, wg_v1322);
    eval.set_sub_input_word(686, wg_v1323);
    eval.set_sub_input_word(687, wg_v1324);
    eval.set_sub_input_word(688, wg_v1325);
    eval.set_sub_input_word(689, wg_v1326);
    eval.set_sub_input_word(690, wg_v1328);
    eval.set_sub_input_word(691, wg_v1329);
    eval.set_sub_input_word(692, wg_v1330);
    eval.set_sub_input_word(693, wg_v1331);
    eval.set_sub_input_word(694, wg_v1332);
    eval.set_sub_input_word(695, wg_v1333);
    eval.set_sub_input_word(696, wg_v1334);
    eval.set_sub_input_word(697, wg_v1335);
    eval.set_sub_input_word(698, wg_v1336);
    eval.set_sub_input_word(699, wg_v1337);
    eval.set_sub_input_word(700, wg_v1339);
    eval.set_sub_input_word(701, wg_v1340);
    eval.set_sub_input_word(702, wg_v1341);
    eval.set_sub_input_word(703, wg_v1342);
    eval.set_sub_input_word(704, wg_v1343);
    eval.set_sub_input_word(705, wg_v1344);
    eval.set_sub_input_word(706, wg_v1345);
    eval.set_sub_input_word(707, wg_v1346);
    eval.set_sub_input_word(708, wg_v1347);
    eval.set_sub_input_word(709, wg_v1348);
    eval.set_sub_input_word(710, wg_v1350);
    eval.set_sub_input_word(711, wg_v1351);
    eval.set_sub_input_word(712, wg_v1352);
    eval.set_sub_input_word(713, wg_v1353);
    eval.set_sub_input_word(714, wg_v1354);
    eval.set_sub_input_word(715, wg_v1355);
    eval.set_sub_input_word(716, wg_v1356);
    eval.set_sub_input_word(717, wg_v1357);
    eval.set_sub_input_word(718, wg_v1358);
    eval.set_sub_input_word(719, wg_v1359);
    let poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_12,
            [
                poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[0],
                poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[1],
                poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[2],
                poseidon_3_partial_rounds_chain_output_round_11_tmp_3806f_111.2[3],
            ],
        );
    let wg_v1360 = poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[0];
    let wg_v1361 = wg_v1360[0];
    let wg_v1362 = wg_v1360[1];
    let wg_v1363 = wg_v1360[2];
    let wg_v1364 = wg_v1360[3];
    let wg_v1365 = wg_v1360[4];
    let wg_v1366 = wg_v1360[5];
    let wg_v1367 = wg_v1360[6];
    let wg_v1368 = wg_v1360[7];
    let wg_v1369 = wg_v1360[8];
    let wg_v1370 = wg_v1360[9];
    let wg_v1371 = poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[1];
    let wg_v1372 = wg_v1371[0];
    let wg_v1373 = wg_v1371[1];
    let wg_v1374 = wg_v1371[2];
    let wg_v1375 = wg_v1371[3];
    let wg_v1376 = wg_v1371[4];
    let wg_v1377 = wg_v1371[5];
    let wg_v1378 = wg_v1371[6];
    let wg_v1379 = wg_v1371[7];
    let wg_v1380 = wg_v1371[8];
    let wg_v1381 = wg_v1371[9];
    let wg_v1382 = poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[2];
    let wg_v1383 = wg_v1382[0];
    let wg_v1384 = wg_v1382[1];
    let wg_v1385 = wg_v1382[2];
    let wg_v1386 = wg_v1382[3];
    let wg_v1387 = wg_v1382[4];
    let wg_v1388 = wg_v1382[5];
    let wg_v1389 = wg_v1382[6];
    let wg_v1390 = wg_v1382[7];
    let wg_v1391 = wg_v1382[8];
    let wg_v1392 = wg_v1382[9];
    let wg_v1393 = poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[3];
    let wg_v1394 = wg_v1393[0];
    let wg_v1395 = wg_v1393[1];
    let wg_v1396 = wg_v1393[2];
    let wg_v1397 = wg_v1393[3];
    let wg_v1398 = wg_v1393[4];
    let wg_v1399 = wg_v1393[5];
    let wg_v1400 = wg_v1393[6];
    let wg_v1401 = wg_v1393[7];
    let wg_v1402 = wg_v1393[8];
    let wg_v1403 = wg_v1393[9];
    eval.set_sub_input_word(720, seq);
    eval.set_sub_input_word(721, m31_13);
    eval.set_sub_input_word(722, wg_v1361);
    eval.set_sub_input_word(723, wg_v1362);
    eval.set_sub_input_word(724, wg_v1363);
    eval.set_sub_input_word(725, wg_v1364);
    eval.set_sub_input_word(726, wg_v1365);
    eval.set_sub_input_word(727, wg_v1366);
    eval.set_sub_input_word(728, wg_v1367);
    eval.set_sub_input_word(729, wg_v1368);
    eval.set_sub_input_word(730, wg_v1369);
    eval.set_sub_input_word(731, wg_v1370);
    eval.set_sub_input_word(732, wg_v1372);
    eval.set_sub_input_word(733, wg_v1373);
    eval.set_sub_input_word(734, wg_v1374);
    eval.set_sub_input_word(735, wg_v1375);
    eval.set_sub_input_word(736, wg_v1376);
    eval.set_sub_input_word(737, wg_v1377);
    eval.set_sub_input_word(738, wg_v1378);
    eval.set_sub_input_word(739, wg_v1379);
    eval.set_sub_input_word(740, wg_v1380);
    eval.set_sub_input_word(741, wg_v1381);
    eval.set_sub_input_word(742, wg_v1383);
    eval.set_sub_input_word(743, wg_v1384);
    eval.set_sub_input_word(744, wg_v1385);
    eval.set_sub_input_word(745, wg_v1386);
    eval.set_sub_input_word(746, wg_v1387);
    eval.set_sub_input_word(747, wg_v1388);
    eval.set_sub_input_word(748, wg_v1389);
    eval.set_sub_input_word(749, wg_v1390);
    eval.set_sub_input_word(750, wg_v1391);
    eval.set_sub_input_word(751, wg_v1392);
    eval.set_sub_input_word(752, wg_v1394);
    eval.set_sub_input_word(753, wg_v1395);
    eval.set_sub_input_word(754, wg_v1396);
    eval.set_sub_input_word(755, wg_v1397);
    eval.set_sub_input_word(756, wg_v1398);
    eval.set_sub_input_word(757, wg_v1399);
    eval.set_sub_input_word(758, wg_v1400);
    eval.set_sub_input_word(759, wg_v1401);
    eval.set_sub_input_word(760, wg_v1402);
    eval.set_sub_input_word(761, wg_v1403);
    let poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_13,
            [
                poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[0],
                poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[1],
                poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[2],
                poseidon_3_partial_rounds_chain_output_round_12_tmp_3806f_112.2[3],
            ],
        );
    let wg_v1404 = poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[0];
    let wg_v1405 = wg_v1404[0];
    let wg_v1406 = wg_v1404[1];
    let wg_v1407 = wg_v1404[2];
    let wg_v1408 = wg_v1404[3];
    let wg_v1409 = wg_v1404[4];
    let wg_v1410 = wg_v1404[5];
    let wg_v1411 = wg_v1404[6];
    let wg_v1412 = wg_v1404[7];
    let wg_v1413 = wg_v1404[8];
    let wg_v1414 = wg_v1404[9];
    let wg_v1415 = poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[1];
    let wg_v1416 = wg_v1415[0];
    let wg_v1417 = wg_v1415[1];
    let wg_v1418 = wg_v1415[2];
    let wg_v1419 = wg_v1415[3];
    let wg_v1420 = wg_v1415[4];
    let wg_v1421 = wg_v1415[5];
    let wg_v1422 = wg_v1415[6];
    let wg_v1423 = wg_v1415[7];
    let wg_v1424 = wg_v1415[8];
    let wg_v1425 = wg_v1415[9];
    let wg_v1426 = poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[2];
    let wg_v1427 = wg_v1426[0];
    let wg_v1428 = wg_v1426[1];
    let wg_v1429 = wg_v1426[2];
    let wg_v1430 = wg_v1426[3];
    let wg_v1431 = wg_v1426[4];
    let wg_v1432 = wg_v1426[5];
    let wg_v1433 = wg_v1426[6];
    let wg_v1434 = wg_v1426[7];
    let wg_v1435 = wg_v1426[8];
    let wg_v1436 = wg_v1426[9];
    let wg_v1437 = poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[3];
    let wg_v1438 = wg_v1437[0];
    let wg_v1439 = wg_v1437[1];
    let wg_v1440 = wg_v1437[2];
    let wg_v1441 = wg_v1437[3];
    let wg_v1442 = wg_v1437[4];
    let wg_v1443 = wg_v1437[5];
    let wg_v1444 = wg_v1437[6];
    let wg_v1445 = wg_v1437[7];
    let wg_v1446 = wg_v1437[8];
    let wg_v1447 = wg_v1437[9];
    eval.set_sub_input_word(762, seq);
    eval.set_sub_input_word(763, m31_14);
    eval.set_sub_input_word(764, wg_v1405);
    eval.set_sub_input_word(765, wg_v1406);
    eval.set_sub_input_word(766, wg_v1407);
    eval.set_sub_input_word(767, wg_v1408);
    eval.set_sub_input_word(768, wg_v1409);
    eval.set_sub_input_word(769, wg_v1410);
    eval.set_sub_input_word(770, wg_v1411);
    eval.set_sub_input_word(771, wg_v1412);
    eval.set_sub_input_word(772, wg_v1413);
    eval.set_sub_input_word(773, wg_v1414);
    eval.set_sub_input_word(774, wg_v1416);
    eval.set_sub_input_word(775, wg_v1417);
    eval.set_sub_input_word(776, wg_v1418);
    eval.set_sub_input_word(777, wg_v1419);
    eval.set_sub_input_word(778, wg_v1420);
    eval.set_sub_input_word(779, wg_v1421);
    eval.set_sub_input_word(780, wg_v1422);
    eval.set_sub_input_word(781, wg_v1423);
    eval.set_sub_input_word(782, wg_v1424);
    eval.set_sub_input_word(783, wg_v1425);
    eval.set_sub_input_word(784, wg_v1427);
    eval.set_sub_input_word(785, wg_v1428);
    eval.set_sub_input_word(786, wg_v1429);
    eval.set_sub_input_word(787, wg_v1430);
    eval.set_sub_input_word(788, wg_v1431);
    eval.set_sub_input_word(789, wg_v1432);
    eval.set_sub_input_word(790, wg_v1433);
    eval.set_sub_input_word(791, wg_v1434);
    eval.set_sub_input_word(792, wg_v1435);
    eval.set_sub_input_word(793, wg_v1436);
    eval.set_sub_input_word(794, wg_v1438);
    eval.set_sub_input_word(795, wg_v1439);
    eval.set_sub_input_word(796, wg_v1440);
    eval.set_sub_input_word(797, wg_v1441);
    eval.set_sub_input_word(798, wg_v1442);
    eval.set_sub_input_word(799, wg_v1443);
    eval.set_sub_input_word(800, wg_v1444);
    eval.set_sub_input_word(801, wg_v1445);
    eval.set_sub_input_word(802, wg_v1446);
    eval.set_sub_input_word(803, wg_v1447);
    let poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_14,
            [
                poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[0],
                poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[1],
                poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[2],
                poseidon_3_partial_rounds_chain_output_round_13_tmp_3806f_113.2[3],
            ],
        );
    let wg_v1448 = poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[0];
    let wg_v1449 = wg_v1448[0];
    let wg_v1450 = wg_v1448[1];
    let wg_v1451 = wg_v1448[2];
    let wg_v1452 = wg_v1448[3];
    let wg_v1453 = wg_v1448[4];
    let wg_v1454 = wg_v1448[5];
    let wg_v1455 = wg_v1448[6];
    let wg_v1456 = wg_v1448[7];
    let wg_v1457 = wg_v1448[8];
    let wg_v1458 = wg_v1448[9];
    let wg_v1459 = poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[1];
    let wg_v1460 = wg_v1459[0];
    let wg_v1461 = wg_v1459[1];
    let wg_v1462 = wg_v1459[2];
    let wg_v1463 = wg_v1459[3];
    let wg_v1464 = wg_v1459[4];
    let wg_v1465 = wg_v1459[5];
    let wg_v1466 = wg_v1459[6];
    let wg_v1467 = wg_v1459[7];
    let wg_v1468 = wg_v1459[8];
    let wg_v1469 = wg_v1459[9];
    let wg_v1470 = poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[2];
    let wg_v1471 = wg_v1470[0];
    let wg_v1472 = wg_v1470[1];
    let wg_v1473 = wg_v1470[2];
    let wg_v1474 = wg_v1470[3];
    let wg_v1475 = wg_v1470[4];
    let wg_v1476 = wg_v1470[5];
    let wg_v1477 = wg_v1470[6];
    let wg_v1478 = wg_v1470[7];
    let wg_v1479 = wg_v1470[8];
    let wg_v1480 = wg_v1470[9];
    let wg_v1481 = poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[3];
    let wg_v1482 = wg_v1481[0];
    let wg_v1483 = wg_v1481[1];
    let wg_v1484 = wg_v1481[2];
    let wg_v1485 = wg_v1481[3];
    let wg_v1486 = wg_v1481[4];
    let wg_v1487 = wg_v1481[5];
    let wg_v1488 = wg_v1481[6];
    let wg_v1489 = wg_v1481[7];
    let wg_v1490 = wg_v1481[8];
    let wg_v1491 = wg_v1481[9];
    eval.set_sub_input_word(804, seq);
    eval.set_sub_input_word(805, m31_15);
    eval.set_sub_input_word(806, wg_v1449);
    eval.set_sub_input_word(807, wg_v1450);
    eval.set_sub_input_word(808, wg_v1451);
    eval.set_sub_input_word(809, wg_v1452);
    eval.set_sub_input_word(810, wg_v1453);
    eval.set_sub_input_word(811, wg_v1454);
    eval.set_sub_input_word(812, wg_v1455);
    eval.set_sub_input_word(813, wg_v1456);
    eval.set_sub_input_word(814, wg_v1457);
    eval.set_sub_input_word(815, wg_v1458);
    eval.set_sub_input_word(816, wg_v1460);
    eval.set_sub_input_word(817, wg_v1461);
    eval.set_sub_input_word(818, wg_v1462);
    eval.set_sub_input_word(819, wg_v1463);
    eval.set_sub_input_word(820, wg_v1464);
    eval.set_sub_input_word(821, wg_v1465);
    eval.set_sub_input_word(822, wg_v1466);
    eval.set_sub_input_word(823, wg_v1467);
    eval.set_sub_input_word(824, wg_v1468);
    eval.set_sub_input_word(825, wg_v1469);
    eval.set_sub_input_word(826, wg_v1471);
    eval.set_sub_input_word(827, wg_v1472);
    eval.set_sub_input_word(828, wg_v1473);
    eval.set_sub_input_word(829, wg_v1474);
    eval.set_sub_input_word(830, wg_v1475);
    eval.set_sub_input_word(831, wg_v1476);
    eval.set_sub_input_word(832, wg_v1477);
    eval.set_sub_input_word(833, wg_v1478);
    eval.set_sub_input_word(834, wg_v1479);
    eval.set_sub_input_word(835, wg_v1480);
    eval.set_sub_input_word(836, wg_v1482);
    eval.set_sub_input_word(837, wg_v1483);
    eval.set_sub_input_word(838, wg_v1484);
    eval.set_sub_input_word(839, wg_v1485);
    eval.set_sub_input_word(840, wg_v1486);
    eval.set_sub_input_word(841, wg_v1487);
    eval.set_sub_input_word(842, wg_v1488);
    eval.set_sub_input_word(843, wg_v1489);
    eval.set_sub_input_word(844, wg_v1490);
    eval.set_sub_input_word(845, wg_v1491);
    let poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_15,
            [
                poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[0],
                poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[1],
                poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[2],
                poseidon_3_partial_rounds_chain_output_round_14_tmp_3806f_114.2[3],
            ],
        );
    let wg_v1492 = poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[0];
    let wg_v1493 = wg_v1492[0];
    let wg_v1494 = wg_v1492[1];
    let wg_v1495 = wg_v1492[2];
    let wg_v1496 = wg_v1492[3];
    let wg_v1497 = wg_v1492[4];
    let wg_v1498 = wg_v1492[5];
    let wg_v1499 = wg_v1492[6];
    let wg_v1500 = wg_v1492[7];
    let wg_v1501 = wg_v1492[8];
    let wg_v1502 = wg_v1492[9];
    let wg_v1503 = poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[1];
    let wg_v1504 = wg_v1503[0];
    let wg_v1505 = wg_v1503[1];
    let wg_v1506 = wg_v1503[2];
    let wg_v1507 = wg_v1503[3];
    let wg_v1508 = wg_v1503[4];
    let wg_v1509 = wg_v1503[5];
    let wg_v1510 = wg_v1503[6];
    let wg_v1511 = wg_v1503[7];
    let wg_v1512 = wg_v1503[8];
    let wg_v1513 = wg_v1503[9];
    let wg_v1514 = poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[2];
    let wg_v1515 = wg_v1514[0];
    let wg_v1516 = wg_v1514[1];
    let wg_v1517 = wg_v1514[2];
    let wg_v1518 = wg_v1514[3];
    let wg_v1519 = wg_v1514[4];
    let wg_v1520 = wg_v1514[5];
    let wg_v1521 = wg_v1514[6];
    let wg_v1522 = wg_v1514[7];
    let wg_v1523 = wg_v1514[8];
    let wg_v1524 = wg_v1514[9];
    let wg_v1525 = poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[3];
    let wg_v1526 = wg_v1525[0];
    let wg_v1527 = wg_v1525[1];
    let wg_v1528 = wg_v1525[2];
    let wg_v1529 = wg_v1525[3];
    let wg_v1530 = wg_v1525[4];
    let wg_v1531 = wg_v1525[5];
    let wg_v1532 = wg_v1525[6];
    let wg_v1533 = wg_v1525[7];
    let wg_v1534 = wg_v1525[8];
    let wg_v1535 = wg_v1525[9];
    eval.set_sub_input_word(846, seq);
    eval.set_sub_input_word(847, m31_16);
    eval.set_sub_input_word(848, wg_v1493);
    eval.set_sub_input_word(849, wg_v1494);
    eval.set_sub_input_word(850, wg_v1495);
    eval.set_sub_input_word(851, wg_v1496);
    eval.set_sub_input_word(852, wg_v1497);
    eval.set_sub_input_word(853, wg_v1498);
    eval.set_sub_input_word(854, wg_v1499);
    eval.set_sub_input_word(855, wg_v1500);
    eval.set_sub_input_word(856, wg_v1501);
    eval.set_sub_input_word(857, wg_v1502);
    eval.set_sub_input_word(858, wg_v1504);
    eval.set_sub_input_word(859, wg_v1505);
    eval.set_sub_input_word(860, wg_v1506);
    eval.set_sub_input_word(861, wg_v1507);
    eval.set_sub_input_word(862, wg_v1508);
    eval.set_sub_input_word(863, wg_v1509);
    eval.set_sub_input_word(864, wg_v1510);
    eval.set_sub_input_word(865, wg_v1511);
    eval.set_sub_input_word(866, wg_v1512);
    eval.set_sub_input_word(867, wg_v1513);
    eval.set_sub_input_word(868, wg_v1515);
    eval.set_sub_input_word(869, wg_v1516);
    eval.set_sub_input_word(870, wg_v1517);
    eval.set_sub_input_word(871, wg_v1518);
    eval.set_sub_input_word(872, wg_v1519);
    eval.set_sub_input_word(873, wg_v1520);
    eval.set_sub_input_word(874, wg_v1521);
    eval.set_sub_input_word(875, wg_v1522);
    eval.set_sub_input_word(876, wg_v1523);
    eval.set_sub_input_word(877, wg_v1524);
    eval.set_sub_input_word(878, wg_v1526);
    eval.set_sub_input_word(879, wg_v1527);
    eval.set_sub_input_word(880, wg_v1528);
    eval.set_sub_input_word(881, wg_v1529);
    eval.set_sub_input_word(882, wg_v1530);
    eval.set_sub_input_word(883, wg_v1531);
    eval.set_sub_input_word(884, wg_v1532);
    eval.set_sub_input_word(885, wg_v1533);
    eval.set_sub_input_word(886, wg_v1534);
    eval.set_sub_input_word(887, wg_v1535);
    let poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_16,
            [
                poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[0],
                poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[1],
                poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[2],
                poseidon_3_partial_rounds_chain_output_round_15_tmp_3806f_115.2[3],
            ],
        );
    let wg_v1536 = poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[0];
    let wg_v1537 = wg_v1536[0];
    let wg_v1538 = wg_v1536[1];
    let wg_v1539 = wg_v1536[2];
    let wg_v1540 = wg_v1536[3];
    let wg_v1541 = wg_v1536[4];
    let wg_v1542 = wg_v1536[5];
    let wg_v1543 = wg_v1536[6];
    let wg_v1544 = wg_v1536[7];
    let wg_v1545 = wg_v1536[8];
    let wg_v1546 = wg_v1536[9];
    let wg_v1547 = poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[1];
    let wg_v1548 = wg_v1547[0];
    let wg_v1549 = wg_v1547[1];
    let wg_v1550 = wg_v1547[2];
    let wg_v1551 = wg_v1547[3];
    let wg_v1552 = wg_v1547[4];
    let wg_v1553 = wg_v1547[5];
    let wg_v1554 = wg_v1547[6];
    let wg_v1555 = wg_v1547[7];
    let wg_v1556 = wg_v1547[8];
    let wg_v1557 = wg_v1547[9];
    let wg_v1558 = poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[2];
    let wg_v1559 = wg_v1558[0];
    let wg_v1560 = wg_v1558[1];
    let wg_v1561 = wg_v1558[2];
    let wg_v1562 = wg_v1558[3];
    let wg_v1563 = wg_v1558[4];
    let wg_v1564 = wg_v1558[5];
    let wg_v1565 = wg_v1558[6];
    let wg_v1566 = wg_v1558[7];
    let wg_v1567 = wg_v1558[8];
    let wg_v1568 = wg_v1558[9];
    let wg_v1569 = poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[3];
    let wg_v1570 = wg_v1569[0];
    let wg_v1571 = wg_v1569[1];
    let wg_v1572 = wg_v1569[2];
    let wg_v1573 = wg_v1569[3];
    let wg_v1574 = wg_v1569[4];
    let wg_v1575 = wg_v1569[5];
    let wg_v1576 = wg_v1569[6];
    let wg_v1577 = wg_v1569[7];
    let wg_v1578 = wg_v1569[8];
    let wg_v1579 = wg_v1569[9];
    eval.set_sub_input_word(888, seq);
    eval.set_sub_input_word(889, m31_17);
    eval.set_sub_input_word(890, wg_v1537);
    eval.set_sub_input_word(891, wg_v1538);
    eval.set_sub_input_word(892, wg_v1539);
    eval.set_sub_input_word(893, wg_v1540);
    eval.set_sub_input_word(894, wg_v1541);
    eval.set_sub_input_word(895, wg_v1542);
    eval.set_sub_input_word(896, wg_v1543);
    eval.set_sub_input_word(897, wg_v1544);
    eval.set_sub_input_word(898, wg_v1545);
    eval.set_sub_input_word(899, wg_v1546);
    eval.set_sub_input_word(900, wg_v1548);
    eval.set_sub_input_word(901, wg_v1549);
    eval.set_sub_input_word(902, wg_v1550);
    eval.set_sub_input_word(903, wg_v1551);
    eval.set_sub_input_word(904, wg_v1552);
    eval.set_sub_input_word(905, wg_v1553);
    eval.set_sub_input_word(906, wg_v1554);
    eval.set_sub_input_word(907, wg_v1555);
    eval.set_sub_input_word(908, wg_v1556);
    eval.set_sub_input_word(909, wg_v1557);
    eval.set_sub_input_word(910, wg_v1559);
    eval.set_sub_input_word(911, wg_v1560);
    eval.set_sub_input_word(912, wg_v1561);
    eval.set_sub_input_word(913, wg_v1562);
    eval.set_sub_input_word(914, wg_v1563);
    eval.set_sub_input_word(915, wg_v1564);
    eval.set_sub_input_word(916, wg_v1565);
    eval.set_sub_input_word(917, wg_v1566);
    eval.set_sub_input_word(918, wg_v1567);
    eval.set_sub_input_word(919, wg_v1568);
    eval.set_sub_input_word(920, wg_v1570);
    eval.set_sub_input_word(921, wg_v1571);
    eval.set_sub_input_word(922, wg_v1572);
    eval.set_sub_input_word(923, wg_v1573);
    eval.set_sub_input_word(924, wg_v1574);
    eval.set_sub_input_word(925, wg_v1575);
    eval.set_sub_input_word(926, wg_v1576);
    eval.set_sub_input_word(927, wg_v1577);
    eval.set_sub_input_word(928, wg_v1578);
    eval.set_sub_input_word(929, wg_v1579);
    let poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_17,
            [
                poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[0],
                poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[1],
                poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[2],
                poseidon_3_partial_rounds_chain_output_round_16_tmp_3806f_116.2[3],
            ],
        );
    let wg_v1580 = poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[0];
    let wg_v1581 = wg_v1580[0];
    let wg_v1582 = wg_v1580[1];
    let wg_v1583 = wg_v1580[2];
    let wg_v1584 = wg_v1580[3];
    let wg_v1585 = wg_v1580[4];
    let wg_v1586 = wg_v1580[5];
    let wg_v1587 = wg_v1580[6];
    let wg_v1588 = wg_v1580[7];
    let wg_v1589 = wg_v1580[8];
    let wg_v1590 = wg_v1580[9];
    let wg_v1591 = poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[1];
    let wg_v1592 = wg_v1591[0];
    let wg_v1593 = wg_v1591[1];
    let wg_v1594 = wg_v1591[2];
    let wg_v1595 = wg_v1591[3];
    let wg_v1596 = wg_v1591[4];
    let wg_v1597 = wg_v1591[5];
    let wg_v1598 = wg_v1591[6];
    let wg_v1599 = wg_v1591[7];
    let wg_v1600 = wg_v1591[8];
    let wg_v1601 = wg_v1591[9];
    let wg_v1602 = poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[2];
    let wg_v1603 = wg_v1602[0];
    let wg_v1604 = wg_v1602[1];
    let wg_v1605 = wg_v1602[2];
    let wg_v1606 = wg_v1602[3];
    let wg_v1607 = wg_v1602[4];
    let wg_v1608 = wg_v1602[5];
    let wg_v1609 = wg_v1602[6];
    let wg_v1610 = wg_v1602[7];
    let wg_v1611 = wg_v1602[8];
    let wg_v1612 = wg_v1602[9];
    let wg_v1613 = poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[3];
    let wg_v1614 = wg_v1613[0];
    let wg_v1615 = wg_v1613[1];
    let wg_v1616 = wg_v1613[2];
    let wg_v1617 = wg_v1613[3];
    let wg_v1618 = wg_v1613[4];
    let wg_v1619 = wg_v1613[5];
    let wg_v1620 = wg_v1613[6];
    let wg_v1621 = wg_v1613[7];
    let wg_v1622 = wg_v1613[8];
    let wg_v1623 = wg_v1613[9];
    eval.set_sub_input_word(930, seq);
    eval.set_sub_input_word(931, m31_18);
    eval.set_sub_input_word(932, wg_v1581);
    eval.set_sub_input_word(933, wg_v1582);
    eval.set_sub_input_word(934, wg_v1583);
    eval.set_sub_input_word(935, wg_v1584);
    eval.set_sub_input_word(936, wg_v1585);
    eval.set_sub_input_word(937, wg_v1586);
    eval.set_sub_input_word(938, wg_v1587);
    eval.set_sub_input_word(939, wg_v1588);
    eval.set_sub_input_word(940, wg_v1589);
    eval.set_sub_input_word(941, wg_v1590);
    eval.set_sub_input_word(942, wg_v1592);
    eval.set_sub_input_word(943, wg_v1593);
    eval.set_sub_input_word(944, wg_v1594);
    eval.set_sub_input_word(945, wg_v1595);
    eval.set_sub_input_word(946, wg_v1596);
    eval.set_sub_input_word(947, wg_v1597);
    eval.set_sub_input_word(948, wg_v1598);
    eval.set_sub_input_word(949, wg_v1599);
    eval.set_sub_input_word(950, wg_v1600);
    eval.set_sub_input_word(951, wg_v1601);
    eval.set_sub_input_word(952, wg_v1603);
    eval.set_sub_input_word(953, wg_v1604);
    eval.set_sub_input_word(954, wg_v1605);
    eval.set_sub_input_word(955, wg_v1606);
    eval.set_sub_input_word(956, wg_v1607);
    eval.set_sub_input_word(957, wg_v1608);
    eval.set_sub_input_word(958, wg_v1609);
    eval.set_sub_input_word(959, wg_v1610);
    eval.set_sub_input_word(960, wg_v1611);
    eval.set_sub_input_word(961, wg_v1612);
    eval.set_sub_input_word(962, wg_v1614);
    eval.set_sub_input_word(963, wg_v1615);
    eval.set_sub_input_word(964, wg_v1616);
    eval.set_sub_input_word(965, wg_v1617);
    eval.set_sub_input_word(966, wg_v1618);
    eval.set_sub_input_word(967, wg_v1619);
    eval.set_sub_input_word(968, wg_v1620);
    eval.set_sub_input_word(969, wg_v1621);
    eval.set_sub_input_word(970, wg_v1622);
    eval.set_sub_input_word(971, wg_v1623);
    let poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_18,
            [
                poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[0],
                poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[1],
                poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[2],
                poseidon_3_partial_rounds_chain_output_round_17_tmp_3806f_117.2[3],
            ],
        );
    let wg_v1624 = poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[0];
    let wg_v1625 = wg_v1624[0];
    let wg_v1626 = wg_v1624[1];
    let wg_v1627 = wg_v1624[2];
    let wg_v1628 = wg_v1624[3];
    let wg_v1629 = wg_v1624[4];
    let wg_v1630 = wg_v1624[5];
    let wg_v1631 = wg_v1624[6];
    let wg_v1632 = wg_v1624[7];
    let wg_v1633 = wg_v1624[8];
    let wg_v1634 = wg_v1624[9];
    let wg_v1635 = poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[1];
    let wg_v1636 = wg_v1635[0];
    let wg_v1637 = wg_v1635[1];
    let wg_v1638 = wg_v1635[2];
    let wg_v1639 = wg_v1635[3];
    let wg_v1640 = wg_v1635[4];
    let wg_v1641 = wg_v1635[5];
    let wg_v1642 = wg_v1635[6];
    let wg_v1643 = wg_v1635[7];
    let wg_v1644 = wg_v1635[8];
    let wg_v1645 = wg_v1635[9];
    let wg_v1646 = poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[2];
    let wg_v1647 = wg_v1646[0];
    let wg_v1648 = wg_v1646[1];
    let wg_v1649 = wg_v1646[2];
    let wg_v1650 = wg_v1646[3];
    let wg_v1651 = wg_v1646[4];
    let wg_v1652 = wg_v1646[5];
    let wg_v1653 = wg_v1646[6];
    let wg_v1654 = wg_v1646[7];
    let wg_v1655 = wg_v1646[8];
    let wg_v1656 = wg_v1646[9];
    let wg_v1657 = poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[3];
    let wg_v1658 = wg_v1657[0];
    let wg_v1659 = wg_v1657[1];
    let wg_v1660 = wg_v1657[2];
    let wg_v1661 = wg_v1657[3];
    let wg_v1662 = wg_v1657[4];
    let wg_v1663 = wg_v1657[5];
    let wg_v1664 = wg_v1657[6];
    let wg_v1665 = wg_v1657[7];
    let wg_v1666 = wg_v1657[8];
    let wg_v1667 = wg_v1657[9];
    eval.set_sub_input_word(972, seq);
    eval.set_sub_input_word(973, m31_19);
    eval.set_sub_input_word(974, wg_v1625);
    eval.set_sub_input_word(975, wg_v1626);
    eval.set_sub_input_word(976, wg_v1627);
    eval.set_sub_input_word(977, wg_v1628);
    eval.set_sub_input_word(978, wg_v1629);
    eval.set_sub_input_word(979, wg_v1630);
    eval.set_sub_input_word(980, wg_v1631);
    eval.set_sub_input_word(981, wg_v1632);
    eval.set_sub_input_word(982, wg_v1633);
    eval.set_sub_input_word(983, wg_v1634);
    eval.set_sub_input_word(984, wg_v1636);
    eval.set_sub_input_word(985, wg_v1637);
    eval.set_sub_input_word(986, wg_v1638);
    eval.set_sub_input_word(987, wg_v1639);
    eval.set_sub_input_word(988, wg_v1640);
    eval.set_sub_input_word(989, wg_v1641);
    eval.set_sub_input_word(990, wg_v1642);
    eval.set_sub_input_word(991, wg_v1643);
    eval.set_sub_input_word(992, wg_v1644);
    eval.set_sub_input_word(993, wg_v1645);
    eval.set_sub_input_word(994, wg_v1647);
    eval.set_sub_input_word(995, wg_v1648);
    eval.set_sub_input_word(996, wg_v1649);
    eval.set_sub_input_word(997, wg_v1650);
    eval.set_sub_input_word(998, wg_v1651);
    eval.set_sub_input_word(999, wg_v1652);
    eval.set_sub_input_word(1000, wg_v1653);
    eval.set_sub_input_word(1001, wg_v1654);
    eval.set_sub_input_word(1002, wg_v1655);
    eval.set_sub_input_word(1003, wg_v1656);
    eval.set_sub_input_word(1004, wg_v1658);
    eval.set_sub_input_word(1005, wg_v1659);
    eval.set_sub_input_word(1006, wg_v1660);
    eval.set_sub_input_word(1007, wg_v1661);
    eval.set_sub_input_word(1008, wg_v1662);
    eval.set_sub_input_word(1009, wg_v1663);
    eval.set_sub_input_word(1010, wg_v1664);
    eval.set_sub_input_word(1011, wg_v1665);
    eval.set_sub_input_word(1012, wg_v1666);
    eval.set_sub_input_word(1013, wg_v1667);
    let poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_19,
            [
                poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[0],
                poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[1],
                poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[2],
                poseidon_3_partial_rounds_chain_output_round_18_tmp_3806f_118.2[3],
            ],
        );
    let wg_v1668 = poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[0];
    let wg_v1669 = wg_v1668[0];
    let wg_v1670 = wg_v1668[1];
    let wg_v1671 = wg_v1668[2];
    let wg_v1672 = wg_v1668[3];
    let wg_v1673 = wg_v1668[4];
    let wg_v1674 = wg_v1668[5];
    let wg_v1675 = wg_v1668[6];
    let wg_v1676 = wg_v1668[7];
    let wg_v1677 = wg_v1668[8];
    let wg_v1678 = wg_v1668[9];
    let wg_v1679 = poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[1];
    let wg_v1680 = wg_v1679[0];
    let wg_v1681 = wg_v1679[1];
    let wg_v1682 = wg_v1679[2];
    let wg_v1683 = wg_v1679[3];
    let wg_v1684 = wg_v1679[4];
    let wg_v1685 = wg_v1679[5];
    let wg_v1686 = wg_v1679[6];
    let wg_v1687 = wg_v1679[7];
    let wg_v1688 = wg_v1679[8];
    let wg_v1689 = wg_v1679[9];
    let wg_v1690 = poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[2];
    let wg_v1691 = wg_v1690[0];
    let wg_v1692 = wg_v1690[1];
    let wg_v1693 = wg_v1690[2];
    let wg_v1694 = wg_v1690[3];
    let wg_v1695 = wg_v1690[4];
    let wg_v1696 = wg_v1690[5];
    let wg_v1697 = wg_v1690[6];
    let wg_v1698 = wg_v1690[7];
    let wg_v1699 = wg_v1690[8];
    let wg_v1700 = wg_v1690[9];
    let wg_v1701 = poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[3];
    let wg_v1702 = wg_v1701[0];
    let wg_v1703 = wg_v1701[1];
    let wg_v1704 = wg_v1701[2];
    let wg_v1705 = wg_v1701[3];
    let wg_v1706 = wg_v1701[4];
    let wg_v1707 = wg_v1701[5];
    let wg_v1708 = wg_v1701[6];
    let wg_v1709 = wg_v1701[7];
    let wg_v1710 = wg_v1701[8];
    let wg_v1711 = wg_v1701[9];
    eval.set_sub_input_word(1014, seq);
    eval.set_sub_input_word(1015, m31_20);
    eval.set_sub_input_word(1016, wg_v1669);
    eval.set_sub_input_word(1017, wg_v1670);
    eval.set_sub_input_word(1018, wg_v1671);
    eval.set_sub_input_word(1019, wg_v1672);
    eval.set_sub_input_word(1020, wg_v1673);
    eval.set_sub_input_word(1021, wg_v1674);
    eval.set_sub_input_word(1022, wg_v1675);
    eval.set_sub_input_word(1023, wg_v1676);
    eval.set_sub_input_word(1024, wg_v1677);
    eval.set_sub_input_word(1025, wg_v1678);
    eval.set_sub_input_word(1026, wg_v1680);
    eval.set_sub_input_word(1027, wg_v1681);
    eval.set_sub_input_word(1028, wg_v1682);
    eval.set_sub_input_word(1029, wg_v1683);
    eval.set_sub_input_word(1030, wg_v1684);
    eval.set_sub_input_word(1031, wg_v1685);
    eval.set_sub_input_word(1032, wg_v1686);
    eval.set_sub_input_word(1033, wg_v1687);
    eval.set_sub_input_word(1034, wg_v1688);
    eval.set_sub_input_word(1035, wg_v1689);
    eval.set_sub_input_word(1036, wg_v1691);
    eval.set_sub_input_word(1037, wg_v1692);
    eval.set_sub_input_word(1038, wg_v1693);
    eval.set_sub_input_word(1039, wg_v1694);
    eval.set_sub_input_word(1040, wg_v1695);
    eval.set_sub_input_word(1041, wg_v1696);
    eval.set_sub_input_word(1042, wg_v1697);
    eval.set_sub_input_word(1043, wg_v1698);
    eval.set_sub_input_word(1044, wg_v1699);
    eval.set_sub_input_word(1045, wg_v1700);
    eval.set_sub_input_word(1046, wg_v1702);
    eval.set_sub_input_word(1047, wg_v1703);
    eval.set_sub_input_word(1048, wg_v1704);
    eval.set_sub_input_word(1049, wg_v1705);
    eval.set_sub_input_word(1050, wg_v1706);
    eval.set_sub_input_word(1051, wg_v1707);
    eval.set_sub_input_word(1052, wg_v1708);
    eval.set_sub_input_word(1053, wg_v1709);
    eval.set_sub_input_word(1054, wg_v1710);
    eval.set_sub_input_word(1055, wg_v1711);
    let poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_20,
            [
                poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[0],
                poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[1],
                poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[2],
                poseidon_3_partial_rounds_chain_output_round_19_tmp_3806f_119.2[3],
            ],
        );
    let wg_v1712 = poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[0];
    let wg_v1713 = wg_v1712[0];
    let wg_v1714 = wg_v1712[1];
    let wg_v1715 = wg_v1712[2];
    let wg_v1716 = wg_v1712[3];
    let wg_v1717 = wg_v1712[4];
    let wg_v1718 = wg_v1712[5];
    let wg_v1719 = wg_v1712[6];
    let wg_v1720 = wg_v1712[7];
    let wg_v1721 = wg_v1712[8];
    let wg_v1722 = wg_v1712[9];
    let wg_v1723 = poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[1];
    let wg_v1724 = wg_v1723[0];
    let wg_v1725 = wg_v1723[1];
    let wg_v1726 = wg_v1723[2];
    let wg_v1727 = wg_v1723[3];
    let wg_v1728 = wg_v1723[4];
    let wg_v1729 = wg_v1723[5];
    let wg_v1730 = wg_v1723[6];
    let wg_v1731 = wg_v1723[7];
    let wg_v1732 = wg_v1723[8];
    let wg_v1733 = wg_v1723[9];
    let wg_v1734 = poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[2];
    let wg_v1735 = wg_v1734[0];
    let wg_v1736 = wg_v1734[1];
    let wg_v1737 = wg_v1734[2];
    let wg_v1738 = wg_v1734[3];
    let wg_v1739 = wg_v1734[4];
    let wg_v1740 = wg_v1734[5];
    let wg_v1741 = wg_v1734[6];
    let wg_v1742 = wg_v1734[7];
    let wg_v1743 = wg_v1734[8];
    let wg_v1744 = wg_v1734[9];
    let wg_v1745 = poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[3];
    let wg_v1746 = wg_v1745[0];
    let wg_v1747 = wg_v1745[1];
    let wg_v1748 = wg_v1745[2];
    let wg_v1749 = wg_v1745[3];
    let wg_v1750 = wg_v1745[4];
    let wg_v1751 = wg_v1745[5];
    let wg_v1752 = wg_v1745[6];
    let wg_v1753 = wg_v1745[7];
    let wg_v1754 = wg_v1745[8];
    let wg_v1755 = wg_v1745[9];
    eval.set_sub_input_word(1056, seq);
    eval.set_sub_input_word(1057, m31_21);
    eval.set_sub_input_word(1058, wg_v1713);
    eval.set_sub_input_word(1059, wg_v1714);
    eval.set_sub_input_word(1060, wg_v1715);
    eval.set_sub_input_word(1061, wg_v1716);
    eval.set_sub_input_word(1062, wg_v1717);
    eval.set_sub_input_word(1063, wg_v1718);
    eval.set_sub_input_word(1064, wg_v1719);
    eval.set_sub_input_word(1065, wg_v1720);
    eval.set_sub_input_word(1066, wg_v1721);
    eval.set_sub_input_word(1067, wg_v1722);
    eval.set_sub_input_word(1068, wg_v1724);
    eval.set_sub_input_word(1069, wg_v1725);
    eval.set_sub_input_word(1070, wg_v1726);
    eval.set_sub_input_word(1071, wg_v1727);
    eval.set_sub_input_word(1072, wg_v1728);
    eval.set_sub_input_word(1073, wg_v1729);
    eval.set_sub_input_word(1074, wg_v1730);
    eval.set_sub_input_word(1075, wg_v1731);
    eval.set_sub_input_word(1076, wg_v1732);
    eval.set_sub_input_word(1077, wg_v1733);
    eval.set_sub_input_word(1078, wg_v1735);
    eval.set_sub_input_word(1079, wg_v1736);
    eval.set_sub_input_word(1080, wg_v1737);
    eval.set_sub_input_word(1081, wg_v1738);
    eval.set_sub_input_word(1082, wg_v1739);
    eval.set_sub_input_word(1083, wg_v1740);
    eval.set_sub_input_word(1084, wg_v1741);
    eval.set_sub_input_word(1085, wg_v1742);
    eval.set_sub_input_word(1086, wg_v1743);
    eval.set_sub_input_word(1087, wg_v1744);
    eval.set_sub_input_word(1088, wg_v1746);
    eval.set_sub_input_word(1089, wg_v1747);
    eval.set_sub_input_word(1090, wg_v1748);
    eval.set_sub_input_word(1091, wg_v1749);
    eval.set_sub_input_word(1092, wg_v1750);
    eval.set_sub_input_word(1093, wg_v1751);
    eval.set_sub_input_word(1094, wg_v1752);
    eval.set_sub_input_word(1095, wg_v1753);
    eval.set_sub_input_word(1096, wg_v1754);
    eval.set_sub_input_word(1097, wg_v1755);
    let poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_21,
            [
                poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[0],
                poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[1],
                poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[2],
                poseidon_3_partial_rounds_chain_output_round_20_tmp_3806f_120.2[3],
            ],
        );
    let wg_v1756 = poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[0];
    let wg_v1757 = wg_v1756[0];
    let wg_v1758 = wg_v1756[1];
    let wg_v1759 = wg_v1756[2];
    let wg_v1760 = wg_v1756[3];
    let wg_v1761 = wg_v1756[4];
    let wg_v1762 = wg_v1756[5];
    let wg_v1763 = wg_v1756[6];
    let wg_v1764 = wg_v1756[7];
    let wg_v1765 = wg_v1756[8];
    let wg_v1766 = wg_v1756[9];
    let wg_v1767 = poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[1];
    let wg_v1768 = wg_v1767[0];
    let wg_v1769 = wg_v1767[1];
    let wg_v1770 = wg_v1767[2];
    let wg_v1771 = wg_v1767[3];
    let wg_v1772 = wg_v1767[4];
    let wg_v1773 = wg_v1767[5];
    let wg_v1774 = wg_v1767[6];
    let wg_v1775 = wg_v1767[7];
    let wg_v1776 = wg_v1767[8];
    let wg_v1777 = wg_v1767[9];
    let wg_v1778 = poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[2];
    let wg_v1779 = wg_v1778[0];
    let wg_v1780 = wg_v1778[1];
    let wg_v1781 = wg_v1778[2];
    let wg_v1782 = wg_v1778[3];
    let wg_v1783 = wg_v1778[4];
    let wg_v1784 = wg_v1778[5];
    let wg_v1785 = wg_v1778[6];
    let wg_v1786 = wg_v1778[7];
    let wg_v1787 = wg_v1778[8];
    let wg_v1788 = wg_v1778[9];
    let wg_v1789 = poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[3];
    let wg_v1790 = wg_v1789[0];
    let wg_v1791 = wg_v1789[1];
    let wg_v1792 = wg_v1789[2];
    let wg_v1793 = wg_v1789[3];
    let wg_v1794 = wg_v1789[4];
    let wg_v1795 = wg_v1789[5];
    let wg_v1796 = wg_v1789[6];
    let wg_v1797 = wg_v1789[7];
    let wg_v1798 = wg_v1789[8];
    let wg_v1799 = wg_v1789[9];
    eval.set_sub_input_word(1098, seq);
    eval.set_sub_input_word(1099, m31_22);
    eval.set_sub_input_word(1100, wg_v1757);
    eval.set_sub_input_word(1101, wg_v1758);
    eval.set_sub_input_word(1102, wg_v1759);
    eval.set_sub_input_word(1103, wg_v1760);
    eval.set_sub_input_word(1104, wg_v1761);
    eval.set_sub_input_word(1105, wg_v1762);
    eval.set_sub_input_word(1106, wg_v1763);
    eval.set_sub_input_word(1107, wg_v1764);
    eval.set_sub_input_word(1108, wg_v1765);
    eval.set_sub_input_word(1109, wg_v1766);
    eval.set_sub_input_word(1110, wg_v1768);
    eval.set_sub_input_word(1111, wg_v1769);
    eval.set_sub_input_word(1112, wg_v1770);
    eval.set_sub_input_word(1113, wg_v1771);
    eval.set_sub_input_word(1114, wg_v1772);
    eval.set_sub_input_word(1115, wg_v1773);
    eval.set_sub_input_word(1116, wg_v1774);
    eval.set_sub_input_word(1117, wg_v1775);
    eval.set_sub_input_word(1118, wg_v1776);
    eval.set_sub_input_word(1119, wg_v1777);
    eval.set_sub_input_word(1120, wg_v1779);
    eval.set_sub_input_word(1121, wg_v1780);
    eval.set_sub_input_word(1122, wg_v1781);
    eval.set_sub_input_word(1123, wg_v1782);
    eval.set_sub_input_word(1124, wg_v1783);
    eval.set_sub_input_word(1125, wg_v1784);
    eval.set_sub_input_word(1126, wg_v1785);
    eval.set_sub_input_word(1127, wg_v1786);
    eval.set_sub_input_word(1128, wg_v1787);
    eval.set_sub_input_word(1129, wg_v1788);
    eval.set_sub_input_word(1130, wg_v1790);
    eval.set_sub_input_word(1131, wg_v1791);
    eval.set_sub_input_word(1132, wg_v1792);
    eval.set_sub_input_word(1133, wg_v1793);
    eval.set_sub_input_word(1134, wg_v1794);
    eval.set_sub_input_word(1135, wg_v1795);
    eval.set_sub_input_word(1136, wg_v1796);
    eval.set_sub_input_word(1137, wg_v1797);
    eval.set_sub_input_word(1138, wg_v1798);
    eval.set_sub_input_word(1139, wg_v1799);
    let poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_22,
            [
                poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[0],
                poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[1],
                poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[2],
                poseidon_3_partial_rounds_chain_output_round_21_tmp_3806f_121.2[3],
            ],
        );
    let wg_v1800 = poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[0];
    let wg_v1801 = wg_v1800[0];
    let wg_v1802 = wg_v1800[1];
    let wg_v1803 = wg_v1800[2];
    let wg_v1804 = wg_v1800[3];
    let wg_v1805 = wg_v1800[4];
    let wg_v1806 = wg_v1800[5];
    let wg_v1807 = wg_v1800[6];
    let wg_v1808 = wg_v1800[7];
    let wg_v1809 = wg_v1800[8];
    let wg_v1810 = wg_v1800[9];
    let wg_v1811 = poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[1];
    let wg_v1812 = wg_v1811[0];
    let wg_v1813 = wg_v1811[1];
    let wg_v1814 = wg_v1811[2];
    let wg_v1815 = wg_v1811[3];
    let wg_v1816 = wg_v1811[4];
    let wg_v1817 = wg_v1811[5];
    let wg_v1818 = wg_v1811[6];
    let wg_v1819 = wg_v1811[7];
    let wg_v1820 = wg_v1811[8];
    let wg_v1821 = wg_v1811[9];
    let wg_v1822 = poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[2];
    let wg_v1823 = wg_v1822[0];
    let wg_v1824 = wg_v1822[1];
    let wg_v1825 = wg_v1822[2];
    let wg_v1826 = wg_v1822[3];
    let wg_v1827 = wg_v1822[4];
    let wg_v1828 = wg_v1822[5];
    let wg_v1829 = wg_v1822[6];
    let wg_v1830 = wg_v1822[7];
    let wg_v1831 = wg_v1822[8];
    let wg_v1832 = wg_v1822[9];
    let wg_v1833 = poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[3];
    let wg_v1834 = wg_v1833[0];
    let wg_v1835 = wg_v1833[1];
    let wg_v1836 = wg_v1833[2];
    let wg_v1837 = wg_v1833[3];
    let wg_v1838 = wg_v1833[4];
    let wg_v1839 = wg_v1833[5];
    let wg_v1840 = wg_v1833[6];
    let wg_v1841 = wg_v1833[7];
    let wg_v1842 = wg_v1833[8];
    let wg_v1843 = wg_v1833[9];
    eval.set_sub_input_word(1140, seq);
    eval.set_sub_input_word(1141, m31_23);
    eval.set_sub_input_word(1142, wg_v1801);
    eval.set_sub_input_word(1143, wg_v1802);
    eval.set_sub_input_word(1144, wg_v1803);
    eval.set_sub_input_word(1145, wg_v1804);
    eval.set_sub_input_word(1146, wg_v1805);
    eval.set_sub_input_word(1147, wg_v1806);
    eval.set_sub_input_word(1148, wg_v1807);
    eval.set_sub_input_word(1149, wg_v1808);
    eval.set_sub_input_word(1150, wg_v1809);
    eval.set_sub_input_word(1151, wg_v1810);
    eval.set_sub_input_word(1152, wg_v1812);
    eval.set_sub_input_word(1153, wg_v1813);
    eval.set_sub_input_word(1154, wg_v1814);
    eval.set_sub_input_word(1155, wg_v1815);
    eval.set_sub_input_word(1156, wg_v1816);
    eval.set_sub_input_word(1157, wg_v1817);
    eval.set_sub_input_word(1158, wg_v1818);
    eval.set_sub_input_word(1159, wg_v1819);
    eval.set_sub_input_word(1160, wg_v1820);
    eval.set_sub_input_word(1161, wg_v1821);
    eval.set_sub_input_word(1162, wg_v1823);
    eval.set_sub_input_word(1163, wg_v1824);
    eval.set_sub_input_word(1164, wg_v1825);
    eval.set_sub_input_word(1165, wg_v1826);
    eval.set_sub_input_word(1166, wg_v1827);
    eval.set_sub_input_word(1167, wg_v1828);
    eval.set_sub_input_word(1168, wg_v1829);
    eval.set_sub_input_word(1169, wg_v1830);
    eval.set_sub_input_word(1170, wg_v1831);
    eval.set_sub_input_word(1171, wg_v1832);
    eval.set_sub_input_word(1172, wg_v1834);
    eval.set_sub_input_word(1173, wg_v1835);
    eval.set_sub_input_word(1174, wg_v1836);
    eval.set_sub_input_word(1175, wg_v1837);
    eval.set_sub_input_word(1176, wg_v1838);
    eval.set_sub_input_word(1177, wg_v1839);
    eval.set_sub_input_word(1178, wg_v1840);
    eval.set_sub_input_word(1179, wg_v1841);
    eval.set_sub_input_word(1180, wg_v1842);
    eval.set_sub_input_word(1181, wg_v1843);
    let poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_23,
            [
                poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[0],
                poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[1],
                poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[2],
                poseidon_3_partial_rounds_chain_output_round_22_tmp_3806f_122.2[3],
            ],
        );
    let wg_v1844 = poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[0];
    let wg_v1845 = wg_v1844[0];
    let wg_v1846 = wg_v1844[1];
    let wg_v1847 = wg_v1844[2];
    let wg_v1848 = wg_v1844[3];
    let wg_v1849 = wg_v1844[4];
    let wg_v1850 = wg_v1844[5];
    let wg_v1851 = wg_v1844[6];
    let wg_v1852 = wg_v1844[7];
    let wg_v1853 = wg_v1844[8];
    let wg_v1854 = wg_v1844[9];
    let wg_v1855 = poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[1];
    let wg_v1856 = wg_v1855[0];
    let wg_v1857 = wg_v1855[1];
    let wg_v1858 = wg_v1855[2];
    let wg_v1859 = wg_v1855[3];
    let wg_v1860 = wg_v1855[4];
    let wg_v1861 = wg_v1855[5];
    let wg_v1862 = wg_v1855[6];
    let wg_v1863 = wg_v1855[7];
    let wg_v1864 = wg_v1855[8];
    let wg_v1865 = wg_v1855[9];
    let wg_v1866 = poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[2];
    let wg_v1867 = wg_v1866[0];
    let wg_v1868 = wg_v1866[1];
    let wg_v1869 = wg_v1866[2];
    let wg_v1870 = wg_v1866[3];
    let wg_v1871 = wg_v1866[4];
    let wg_v1872 = wg_v1866[5];
    let wg_v1873 = wg_v1866[6];
    let wg_v1874 = wg_v1866[7];
    let wg_v1875 = wg_v1866[8];
    let wg_v1876 = wg_v1866[9];
    let wg_v1877 = poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[3];
    let wg_v1878 = wg_v1877[0];
    let wg_v1879 = wg_v1877[1];
    let wg_v1880 = wg_v1877[2];
    let wg_v1881 = wg_v1877[3];
    let wg_v1882 = wg_v1877[4];
    let wg_v1883 = wg_v1877[5];
    let wg_v1884 = wg_v1877[6];
    let wg_v1885 = wg_v1877[7];
    let wg_v1886 = wg_v1877[8];
    let wg_v1887 = wg_v1877[9];
    eval.set_sub_input_word(1182, seq);
    eval.set_sub_input_word(1183, m31_24);
    eval.set_sub_input_word(1184, wg_v1845);
    eval.set_sub_input_word(1185, wg_v1846);
    eval.set_sub_input_word(1186, wg_v1847);
    eval.set_sub_input_word(1187, wg_v1848);
    eval.set_sub_input_word(1188, wg_v1849);
    eval.set_sub_input_word(1189, wg_v1850);
    eval.set_sub_input_word(1190, wg_v1851);
    eval.set_sub_input_word(1191, wg_v1852);
    eval.set_sub_input_word(1192, wg_v1853);
    eval.set_sub_input_word(1193, wg_v1854);
    eval.set_sub_input_word(1194, wg_v1856);
    eval.set_sub_input_word(1195, wg_v1857);
    eval.set_sub_input_word(1196, wg_v1858);
    eval.set_sub_input_word(1197, wg_v1859);
    eval.set_sub_input_word(1198, wg_v1860);
    eval.set_sub_input_word(1199, wg_v1861);
    eval.set_sub_input_word(1200, wg_v1862);
    eval.set_sub_input_word(1201, wg_v1863);
    eval.set_sub_input_word(1202, wg_v1864);
    eval.set_sub_input_word(1203, wg_v1865);
    eval.set_sub_input_word(1204, wg_v1867);
    eval.set_sub_input_word(1205, wg_v1868);
    eval.set_sub_input_word(1206, wg_v1869);
    eval.set_sub_input_word(1207, wg_v1870);
    eval.set_sub_input_word(1208, wg_v1871);
    eval.set_sub_input_word(1209, wg_v1872);
    eval.set_sub_input_word(1210, wg_v1873);
    eval.set_sub_input_word(1211, wg_v1874);
    eval.set_sub_input_word(1212, wg_v1875);
    eval.set_sub_input_word(1213, wg_v1876);
    eval.set_sub_input_word(1214, wg_v1878);
    eval.set_sub_input_word(1215, wg_v1879);
    eval.set_sub_input_word(1216, wg_v1880);
    eval.set_sub_input_word(1217, wg_v1881);
    eval.set_sub_input_word(1218, wg_v1882);
    eval.set_sub_input_word(1219, wg_v1883);
    eval.set_sub_input_word(1220, wg_v1884);
    eval.set_sub_input_word(1221, wg_v1885);
    eval.set_sub_input_word(1222, wg_v1886);
    eval.set_sub_input_word(1223, wg_v1887);
    let poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_24,
            [
                poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[0],
                poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[1],
                poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[2],
                poseidon_3_partial_rounds_chain_output_round_23_tmp_3806f_123.2[3],
            ],
        );
    let wg_v1888 = poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[0];
    let wg_v1889 = wg_v1888[0];
    let wg_v1890 = wg_v1888[1];
    let wg_v1891 = wg_v1888[2];
    let wg_v1892 = wg_v1888[3];
    let wg_v1893 = wg_v1888[4];
    let wg_v1894 = wg_v1888[5];
    let wg_v1895 = wg_v1888[6];
    let wg_v1896 = wg_v1888[7];
    let wg_v1897 = wg_v1888[8];
    let wg_v1898 = wg_v1888[9];
    let wg_v1899 = poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[1];
    let wg_v1900 = wg_v1899[0];
    let wg_v1901 = wg_v1899[1];
    let wg_v1902 = wg_v1899[2];
    let wg_v1903 = wg_v1899[3];
    let wg_v1904 = wg_v1899[4];
    let wg_v1905 = wg_v1899[5];
    let wg_v1906 = wg_v1899[6];
    let wg_v1907 = wg_v1899[7];
    let wg_v1908 = wg_v1899[8];
    let wg_v1909 = wg_v1899[9];
    let wg_v1910 = poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[2];
    let wg_v1911 = wg_v1910[0];
    let wg_v1912 = wg_v1910[1];
    let wg_v1913 = wg_v1910[2];
    let wg_v1914 = wg_v1910[3];
    let wg_v1915 = wg_v1910[4];
    let wg_v1916 = wg_v1910[5];
    let wg_v1917 = wg_v1910[6];
    let wg_v1918 = wg_v1910[7];
    let wg_v1919 = wg_v1910[8];
    let wg_v1920 = wg_v1910[9];
    let wg_v1921 = poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[3];
    let wg_v1922 = wg_v1921[0];
    let wg_v1923 = wg_v1921[1];
    let wg_v1924 = wg_v1921[2];
    let wg_v1925 = wg_v1921[3];
    let wg_v1926 = wg_v1921[4];
    let wg_v1927 = wg_v1921[5];
    let wg_v1928 = wg_v1921[6];
    let wg_v1929 = wg_v1921[7];
    let wg_v1930 = wg_v1921[8];
    let wg_v1931 = wg_v1921[9];
    eval.set_sub_input_word(1224, seq);
    eval.set_sub_input_word(1225, m31_25);
    eval.set_sub_input_word(1226, wg_v1889);
    eval.set_sub_input_word(1227, wg_v1890);
    eval.set_sub_input_word(1228, wg_v1891);
    eval.set_sub_input_word(1229, wg_v1892);
    eval.set_sub_input_word(1230, wg_v1893);
    eval.set_sub_input_word(1231, wg_v1894);
    eval.set_sub_input_word(1232, wg_v1895);
    eval.set_sub_input_word(1233, wg_v1896);
    eval.set_sub_input_word(1234, wg_v1897);
    eval.set_sub_input_word(1235, wg_v1898);
    eval.set_sub_input_word(1236, wg_v1900);
    eval.set_sub_input_word(1237, wg_v1901);
    eval.set_sub_input_word(1238, wg_v1902);
    eval.set_sub_input_word(1239, wg_v1903);
    eval.set_sub_input_word(1240, wg_v1904);
    eval.set_sub_input_word(1241, wg_v1905);
    eval.set_sub_input_word(1242, wg_v1906);
    eval.set_sub_input_word(1243, wg_v1907);
    eval.set_sub_input_word(1244, wg_v1908);
    eval.set_sub_input_word(1245, wg_v1909);
    eval.set_sub_input_word(1246, wg_v1911);
    eval.set_sub_input_word(1247, wg_v1912);
    eval.set_sub_input_word(1248, wg_v1913);
    eval.set_sub_input_word(1249, wg_v1914);
    eval.set_sub_input_word(1250, wg_v1915);
    eval.set_sub_input_word(1251, wg_v1916);
    eval.set_sub_input_word(1252, wg_v1917);
    eval.set_sub_input_word(1253, wg_v1918);
    eval.set_sub_input_word(1254, wg_v1919);
    eval.set_sub_input_word(1255, wg_v1920);
    eval.set_sub_input_word(1256, wg_v1922);
    eval.set_sub_input_word(1257, wg_v1923);
    eval.set_sub_input_word(1258, wg_v1924);
    eval.set_sub_input_word(1259, wg_v1925);
    eval.set_sub_input_word(1260, wg_v1926);
    eval.set_sub_input_word(1261, wg_v1927);
    eval.set_sub_input_word(1262, wg_v1928);
    eval.set_sub_input_word(1263, wg_v1929);
    eval.set_sub_input_word(1264, wg_v1930);
    eval.set_sub_input_word(1265, wg_v1931);
    let poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_25,
            [
                poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[0],
                poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[1],
                poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[2],
                poseidon_3_partial_rounds_chain_output_round_24_tmp_3806f_124.2[3],
            ],
        );
    let wg_v1932 = poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[0];
    let wg_v1933 = wg_v1932[0];
    let wg_v1934 = wg_v1932[1];
    let wg_v1935 = wg_v1932[2];
    let wg_v1936 = wg_v1932[3];
    let wg_v1937 = wg_v1932[4];
    let wg_v1938 = wg_v1932[5];
    let wg_v1939 = wg_v1932[6];
    let wg_v1940 = wg_v1932[7];
    let wg_v1941 = wg_v1932[8];
    let wg_v1942 = wg_v1932[9];
    let wg_v1943 = poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[1];
    let wg_v1944 = wg_v1943[0];
    let wg_v1945 = wg_v1943[1];
    let wg_v1946 = wg_v1943[2];
    let wg_v1947 = wg_v1943[3];
    let wg_v1948 = wg_v1943[4];
    let wg_v1949 = wg_v1943[5];
    let wg_v1950 = wg_v1943[6];
    let wg_v1951 = wg_v1943[7];
    let wg_v1952 = wg_v1943[8];
    let wg_v1953 = wg_v1943[9];
    let wg_v1954 = poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[2];
    let wg_v1955 = wg_v1954[0];
    let wg_v1956 = wg_v1954[1];
    let wg_v1957 = wg_v1954[2];
    let wg_v1958 = wg_v1954[3];
    let wg_v1959 = wg_v1954[4];
    let wg_v1960 = wg_v1954[5];
    let wg_v1961 = wg_v1954[6];
    let wg_v1962 = wg_v1954[7];
    let wg_v1963 = wg_v1954[8];
    let wg_v1964 = wg_v1954[9];
    let wg_v1965 = poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[3];
    let wg_v1966 = wg_v1965[0];
    let wg_v1967 = wg_v1965[1];
    let wg_v1968 = wg_v1965[2];
    let wg_v1969 = wg_v1965[3];
    let wg_v1970 = wg_v1965[4];
    let wg_v1971 = wg_v1965[5];
    let wg_v1972 = wg_v1965[6];
    let wg_v1973 = wg_v1965[7];
    let wg_v1974 = wg_v1965[8];
    let wg_v1975 = wg_v1965[9];
    eval.set_sub_input_word(1266, seq);
    eval.set_sub_input_word(1267, m31_26);
    eval.set_sub_input_word(1268, wg_v1933);
    eval.set_sub_input_word(1269, wg_v1934);
    eval.set_sub_input_word(1270, wg_v1935);
    eval.set_sub_input_word(1271, wg_v1936);
    eval.set_sub_input_word(1272, wg_v1937);
    eval.set_sub_input_word(1273, wg_v1938);
    eval.set_sub_input_word(1274, wg_v1939);
    eval.set_sub_input_word(1275, wg_v1940);
    eval.set_sub_input_word(1276, wg_v1941);
    eval.set_sub_input_word(1277, wg_v1942);
    eval.set_sub_input_word(1278, wg_v1944);
    eval.set_sub_input_word(1279, wg_v1945);
    eval.set_sub_input_word(1280, wg_v1946);
    eval.set_sub_input_word(1281, wg_v1947);
    eval.set_sub_input_word(1282, wg_v1948);
    eval.set_sub_input_word(1283, wg_v1949);
    eval.set_sub_input_word(1284, wg_v1950);
    eval.set_sub_input_word(1285, wg_v1951);
    eval.set_sub_input_word(1286, wg_v1952);
    eval.set_sub_input_word(1287, wg_v1953);
    eval.set_sub_input_word(1288, wg_v1955);
    eval.set_sub_input_word(1289, wg_v1956);
    eval.set_sub_input_word(1290, wg_v1957);
    eval.set_sub_input_word(1291, wg_v1958);
    eval.set_sub_input_word(1292, wg_v1959);
    eval.set_sub_input_word(1293, wg_v1960);
    eval.set_sub_input_word(1294, wg_v1961);
    eval.set_sub_input_word(1295, wg_v1962);
    eval.set_sub_input_word(1296, wg_v1963);
    eval.set_sub_input_word(1297, wg_v1964);
    eval.set_sub_input_word(1298, wg_v1966);
    eval.set_sub_input_word(1299, wg_v1967);
    eval.set_sub_input_word(1300, wg_v1968);
    eval.set_sub_input_word(1301, wg_v1969);
    eval.set_sub_input_word(1302, wg_v1970);
    eval.set_sub_input_word(1303, wg_v1971);
    eval.set_sub_input_word(1304, wg_v1972);
    eval.set_sub_input_word(1305, wg_v1973);
    eval.set_sub_input_word(1306, wg_v1974);
    eval.set_sub_input_word(1307, wg_v1975);
    let poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_26,
            [
                poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[0],
                poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[1],
                poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[2],
                poseidon_3_partial_rounds_chain_output_round_25_tmp_3806f_125.2[3],
            ],
        );
    let wg_v1976 = poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[0];
    let wg_v1977 = wg_v1976[0];
    let wg_v1978 = wg_v1976[1];
    let wg_v1979 = wg_v1976[2];
    let wg_v1980 = wg_v1976[3];
    let wg_v1981 = wg_v1976[4];
    let wg_v1982 = wg_v1976[5];
    let wg_v1983 = wg_v1976[6];
    let wg_v1984 = wg_v1976[7];
    let wg_v1985 = wg_v1976[8];
    let wg_v1986 = wg_v1976[9];
    let wg_v1987 = poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[1];
    let wg_v1988 = wg_v1987[0];
    let wg_v1989 = wg_v1987[1];
    let wg_v1990 = wg_v1987[2];
    let wg_v1991 = wg_v1987[3];
    let wg_v1992 = wg_v1987[4];
    let wg_v1993 = wg_v1987[5];
    let wg_v1994 = wg_v1987[6];
    let wg_v1995 = wg_v1987[7];
    let wg_v1996 = wg_v1987[8];
    let wg_v1997 = wg_v1987[9];
    let wg_v1998 = poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[2];
    let wg_v1999 = wg_v1998[0];
    let wg_v2000 = wg_v1998[1];
    let wg_v2001 = wg_v1998[2];
    let wg_v2002 = wg_v1998[3];
    let wg_v2003 = wg_v1998[4];
    let wg_v2004 = wg_v1998[5];
    let wg_v2005 = wg_v1998[6];
    let wg_v2006 = wg_v1998[7];
    let wg_v2007 = wg_v1998[8];
    let wg_v2008 = wg_v1998[9];
    let wg_v2009 = poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[3];
    let wg_v2010 = wg_v2009[0];
    let wg_v2011 = wg_v2009[1];
    let wg_v2012 = wg_v2009[2];
    let wg_v2013 = wg_v2009[3];
    let wg_v2014 = wg_v2009[4];
    let wg_v2015 = wg_v2009[5];
    let wg_v2016 = wg_v2009[6];
    let wg_v2017 = wg_v2009[7];
    let wg_v2018 = wg_v2009[8];
    let wg_v2019 = wg_v2009[9];
    eval.set_sub_input_word(1308, seq);
    eval.set_sub_input_word(1309, m31_27);
    eval.set_sub_input_word(1310, wg_v1977);
    eval.set_sub_input_word(1311, wg_v1978);
    eval.set_sub_input_word(1312, wg_v1979);
    eval.set_sub_input_word(1313, wg_v1980);
    eval.set_sub_input_word(1314, wg_v1981);
    eval.set_sub_input_word(1315, wg_v1982);
    eval.set_sub_input_word(1316, wg_v1983);
    eval.set_sub_input_word(1317, wg_v1984);
    eval.set_sub_input_word(1318, wg_v1985);
    eval.set_sub_input_word(1319, wg_v1986);
    eval.set_sub_input_word(1320, wg_v1988);
    eval.set_sub_input_word(1321, wg_v1989);
    eval.set_sub_input_word(1322, wg_v1990);
    eval.set_sub_input_word(1323, wg_v1991);
    eval.set_sub_input_word(1324, wg_v1992);
    eval.set_sub_input_word(1325, wg_v1993);
    eval.set_sub_input_word(1326, wg_v1994);
    eval.set_sub_input_word(1327, wg_v1995);
    eval.set_sub_input_word(1328, wg_v1996);
    eval.set_sub_input_word(1329, wg_v1997);
    eval.set_sub_input_word(1330, wg_v1999);
    eval.set_sub_input_word(1331, wg_v2000);
    eval.set_sub_input_word(1332, wg_v2001);
    eval.set_sub_input_word(1333, wg_v2002);
    eval.set_sub_input_word(1334, wg_v2003);
    eval.set_sub_input_word(1335, wg_v2004);
    eval.set_sub_input_word(1336, wg_v2005);
    eval.set_sub_input_word(1337, wg_v2006);
    eval.set_sub_input_word(1338, wg_v2007);
    eval.set_sub_input_word(1339, wg_v2008);
    eval.set_sub_input_word(1340, wg_v2010);
    eval.set_sub_input_word(1341, wg_v2011);
    eval.set_sub_input_word(1342, wg_v2012);
    eval.set_sub_input_word(1343, wg_v2013);
    eval.set_sub_input_word(1344, wg_v2014);
    eval.set_sub_input_word(1345, wg_v2015);
    eval.set_sub_input_word(1346, wg_v2016);
    eval.set_sub_input_word(1347, wg_v2017);
    eval.set_sub_input_word(1348, wg_v2018);
    eval.set_sub_input_word(1349, wg_v2019);
    let poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_27,
            [
                poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[0],
                poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[1],
                poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[2],
                poseidon_3_partial_rounds_chain_output_round_26_tmp_3806f_126.2[3],
            ],
        );
    let wg_v2020 = poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[0];
    let wg_v2021 = wg_v2020[0];
    let wg_v2022 = wg_v2020[1];
    let wg_v2023 = wg_v2020[2];
    let wg_v2024 = wg_v2020[3];
    let wg_v2025 = wg_v2020[4];
    let wg_v2026 = wg_v2020[5];
    let wg_v2027 = wg_v2020[6];
    let wg_v2028 = wg_v2020[7];
    let wg_v2029 = wg_v2020[8];
    let wg_v2030 = wg_v2020[9];
    let wg_v2031 = poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[1];
    let wg_v2032 = wg_v2031[0];
    let wg_v2033 = wg_v2031[1];
    let wg_v2034 = wg_v2031[2];
    let wg_v2035 = wg_v2031[3];
    let wg_v2036 = wg_v2031[4];
    let wg_v2037 = wg_v2031[5];
    let wg_v2038 = wg_v2031[6];
    let wg_v2039 = wg_v2031[7];
    let wg_v2040 = wg_v2031[8];
    let wg_v2041 = wg_v2031[9];
    let wg_v2042 = poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[2];
    let wg_v2043 = wg_v2042[0];
    let wg_v2044 = wg_v2042[1];
    let wg_v2045 = wg_v2042[2];
    let wg_v2046 = wg_v2042[3];
    let wg_v2047 = wg_v2042[4];
    let wg_v2048 = wg_v2042[5];
    let wg_v2049 = wg_v2042[6];
    let wg_v2050 = wg_v2042[7];
    let wg_v2051 = wg_v2042[8];
    let wg_v2052 = wg_v2042[9];
    let wg_v2053 = poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[3];
    let wg_v2054 = wg_v2053[0];
    let wg_v2055 = wg_v2053[1];
    let wg_v2056 = wg_v2053[2];
    let wg_v2057 = wg_v2053[3];
    let wg_v2058 = wg_v2053[4];
    let wg_v2059 = wg_v2053[5];
    let wg_v2060 = wg_v2053[6];
    let wg_v2061 = wg_v2053[7];
    let wg_v2062 = wg_v2053[8];
    let wg_v2063 = wg_v2053[9];
    eval.set_sub_input_word(1350, seq);
    eval.set_sub_input_word(1351, m31_28);
    eval.set_sub_input_word(1352, wg_v2021);
    eval.set_sub_input_word(1353, wg_v2022);
    eval.set_sub_input_word(1354, wg_v2023);
    eval.set_sub_input_word(1355, wg_v2024);
    eval.set_sub_input_word(1356, wg_v2025);
    eval.set_sub_input_word(1357, wg_v2026);
    eval.set_sub_input_word(1358, wg_v2027);
    eval.set_sub_input_word(1359, wg_v2028);
    eval.set_sub_input_word(1360, wg_v2029);
    eval.set_sub_input_word(1361, wg_v2030);
    eval.set_sub_input_word(1362, wg_v2032);
    eval.set_sub_input_word(1363, wg_v2033);
    eval.set_sub_input_word(1364, wg_v2034);
    eval.set_sub_input_word(1365, wg_v2035);
    eval.set_sub_input_word(1366, wg_v2036);
    eval.set_sub_input_word(1367, wg_v2037);
    eval.set_sub_input_word(1368, wg_v2038);
    eval.set_sub_input_word(1369, wg_v2039);
    eval.set_sub_input_word(1370, wg_v2040);
    eval.set_sub_input_word(1371, wg_v2041);
    eval.set_sub_input_word(1372, wg_v2043);
    eval.set_sub_input_word(1373, wg_v2044);
    eval.set_sub_input_word(1374, wg_v2045);
    eval.set_sub_input_word(1375, wg_v2046);
    eval.set_sub_input_word(1376, wg_v2047);
    eval.set_sub_input_word(1377, wg_v2048);
    eval.set_sub_input_word(1378, wg_v2049);
    eval.set_sub_input_word(1379, wg_v2050);
    eval.set_sub_input_word(1380, wg_v2051);
    eval.set_sub_input_word(1381, wg_v2052);
    eval.set_sub_input_word(1382, wg_v2054);
    eval.set_sub_input_word(1383, wg_v2055);
    eval.set_sub_input_word(1384, wg_v2056);
    eval.set_sub_input_word(1385, wg_v2057);
    eval.set_sub_input_word(1386, wg_v2058);
    eval.set_sub_input_word(1387, wg_v2059);
    eval.set_sub_input_word(1388, wg_v2060);
    eval.set_sub_input_word(1389, wg_v2061);
    eval.set_sub_input_word(1390, wg_v2062);
    eval.set_sub_input_word(1391, wg_v2063);
    let poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_28,
            [
                poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[0],
                poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[1],
                poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[2],
                poseidon_3_partial_rounds_chain_output_round_27_tmp_3806f_127.2[3],
            ],
        );
    let wg_v2064 = poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[0];
    let wg_v2065 = wg_v2064[0];
    let wg_v2066 = wg_v2064[1];
    let wg_v2067 = wg_v2064[2];
    let wg_v2068 = wg_v2064[3];
    let wg_v2069 = wg_v2064[4];
    let wg_v2070 = wg_v2064[5];
    let wg_v2071 = wg_v2064[6];
    let wg_v2072 = wg_v2064[7];
    let wg_v2073 = wg_v2064[8];
    let wg_v2074 = wg_v2064[9];
    let wg_v2075 = poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[1];
    let wg_v2076 = wg_v2075[0];
    let wg_v2077 = wg_v2075[1];
    let wg_v2078 = wg_v2075[2];
    let wg_v2079 = wg_v2075[3];
    let wg_v2080 = wg_v2075[4];
    let wg_v2081 = wg_v2075[5];
    let wg_v2082 = wg_v2075[6];
    let wg_v2083 = wg_v2075[7];
    let wg_v2084 = wg_v2075[8];
    let wg_v2085 = wg_v2075[9];
    let wg_v2086 = poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[2];
    let wg_v2087 = wg_v2086[0];
    let wg_v2088 = wg_v2086[1];
    let wg_v2089 = wg_v2086[2];
    let wg_v2090 = wg_v2086[3];
    let wg_v2091 = wg_v2086[4];
    let wg_v2092 = wg_v2086[5];
    let wg_v2093 = wg_v2086[6];
    let wg_v2094 = wg_v2086[7];
    let wg_v2095 = wg_v2086[8];
    let wg_v2096 = wg_v2086[9];
    let wg_v2097 = poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[3];
    let wg_v2098 = wg_v2097[0];
    let wg_v2099 = wg_v2097[1];
    let wg_v2100 = wg_v2097[2];
    let wg_v2101 = wg_v2097[3];
    let wg_v2102 = wg_v2097[4];
    let wg_v2103 = wg_v2097[5];
    let wg_v2104 = wg_v2097[6];
    let wg_v2105 = wg_v2097[7];
    let wg_v2106 = wg_v2097[8];
    let wg_v2107 = wg_v2097[9];
    eval.set_sub_input_word(1392, seq);
    eval.set_sub_input_word(1393, m31_29);
    eval.set_sub_input_word(1394, wg_v2065);
    eval.set_sub_input_word(1395, wg_v2066);
    eval.set_sub_input_word(1396, wg_v2067);
    eval.set_sub_input_word(1397, wg_v2068);
    eval.set_sub_input_word(1398, wg_v2069);
    eval.set_sub_input_word(1399, wg_v2070);
    eval.set_sub_input_word(1400, wg_v2071);
    eval.set_sub_input_word(1401, wg_v2072);
    eval.set_sub_input_word(1402, wg_v2073);
    eval.set_sub_input_word(1403, wg_v2074);
    eval.set_sub_input_word(1404, wg_v2076);
    eval.set_sub_input_word(1405, wg_v2077);
    eval.set_sub_input_word(1406, wg_v2078);
    eval.set_sub_input_word(1407, wg_v2079);
    eval.set_sub_input_word(1408, wg_v2080);
    eval.set_sub_input_word(1409, wg_v2081);
    eval.set_sub_input_word(1410, wg_v2082);
    eval.set_sub_input_word(1411, wg_v2083);
    eval.set_sub_input_word(1412, wg_v2084);
    eval.set_sub_input_word(1413, wg_v2085);
    eval.set_sub_input_word(1414, wg_v2087);
    eval.set_sub_input_word(1415, wg_v2088);
    eval.set_sub_input_word(1416, wg_v2089);
    eval.set_sub_input_word(1417, wg_v2090);
    eval.set_sub_input_word(1418, wg_v2091);
    eval.set_sub_input_word(1419, wg_v2092);
    eval.set_sub_input_word(1420, wg_v2093);
    eval.set_sub_input_word(1421, wg_v2094);
    eval.set_sub_input_word(1422, wg_v2095);
    eval.set_sub_input_word(1423, wg_v2096);
    eval.set_sub_input_word(1424, wg_v2098);
    eval.set_sub_input_word(1425, wg_v2099);
    eval.set_sub_input_word(1426, wg_v2100);
    eval.set_sub_input_word(1427, wg_v2101);
    eval.set_sub_input_word(1428, wg_v2102);
    eval.set_sub_input_word(1429, wg_v2103);
    eval.set_sub_input_word(1430, wg_v2104);
    eval.set_sub_input_word(1431, wg_v2105);
    eval.set_sub_input_word(1432, wg_v2106);
    eval.set_sub_input_word(1433, wg_v2107);
    let poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_29,
            [
                poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[0],
                poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[1],
                poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[2],
                poseidon_3_partial_rounds_chain_output_round_28_tmp_3806f_128.2[3],
            ],
        );
    let wg_v2108 = poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[0];
    let wg_v2109 = wg_v2108[0];
    let wg_v2110 = wg_v2108[1];
    let wg_v2111 = wg_v2108[2];
    let wg_v2112 = wg_v2108[3];
    let wg_v2113 = wg_v2108[4];
    let wg_v2114 = wg_v2108[5];
    let wg_v2115 = wg_v2108[6];
    let wg_v2116 = wg_v2108[7];
    let wg_v2117 = wg_v2108[8];
    let wg_v2118 = wg_v2108[9];
    let wg_v2119 = poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[1];
    let wg_v2120 = wg_v2119[0];
    let wg_v2121 = wg_v2119[1];
    let wg_v2122 = wg_v2119[2];
    let wg_v2123 = wg_v2119[3];
    let wg_v2124 = wg_v2119[4];
    let wg_v2125 = wg_v2119[5];
    let wg_v2126 = wg_v2119[6];
    let wg_v2127 = wg_v2119[7];
    let wg_v2128 = wg_v2119[8];
    let wg_v2129 = wg_v2119[9];
    let wg_v2130 = poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[2];
    let wg_v2131 = wg_v2130[0];
    let wg_v2132 = wg_v2130[1];
    let wg_v2133 = wg_v2130[2];
    let wg_v2134 = wg_v2130[3];
    let wg_v2135 = wg_v2130[4];
    let wg_v2136 = wg_v2130[5];
    let wg_v2137 = wg_v2130[6];
    let wg_v2138 = wg_v2130[7];
    let wg_v2139 = wg_v2130[8];
    let wg_v2140 = wg_v2130[9];
    let wg_v2141 = poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[3];
    let wg_v2142 = wg_v2141[0];
    let wg_v2143 = wg_v2141[1];
    let wg_v2144 = wg_v2141[2];
    let wg_v2145 = wg_v2141[3];
    let wg_v2146 = wg_v2141[4];
    let wg_v2147 = wg_v2141[5];
    let wg_v2148 = wg_v2141[6];
    let wg_v2149 = wg_v2141[7];
    let wg_v2150 = wg_v2141[8];
    let wg_v2151 = wg_v2141[9];
    eval.set_sub_input_word(1434, seq);
    eval.set_sub_input_word(1435, m31_30);
    eval.set_sub_input_word(1436, wg_v2109);
    eval.set_sub_input_word(1437, wg_v2110);
    eval.set_sub_input_word(1438, wg_v2111);
    eval.set_sub_input_word(1439, wg_v2112);
    eval.set_sub_input_word(1440, wg_v2113);
    eval.set_sub_input_word(1441, wg_v2114);
    eval.set_sub_input_word(1442, wg_v2115);
    eval.set_sub_input_word(1443, wg_v2116);
    eval.set_sub_input_word(1444, wg_v2117);
    eval.set_sub_input_word(1445, wg_v2118);
    eval.set_sub_input_word(1446, wg_v2120);
    eval.set_sub_input_word(1447, wg_v2121);
    eval.set_sub_input_word(1448, wg_v2122);
    eval.set_sub_input_word(1449, wg_v2123);
    eval.set_sub_input_word(1450, wg_v2124);
    eval.set_sub_input_word(1451, wg_v2125);
    eval.set_sub_input_word(1452, wg_v2126);
    eval.set_sub_input_word(1453, wg_v2127);
    eval.set_sub_input_word(1454, wg_v2128);
    eval.set_sub_input_word(1455, wg_v2129);
    eval.set_sub_input_word(1456, wg_v2131);
    eval.set_sub_input_word(1457, wg_v2132);
    eval.set_sub_input_word(1458, wg_v2133);
    eval.set_sub_input_word(1459, wg_v2134);
    eval.set_sub_input_word(1460, wg_v2135);
    eval.set_sub_input_word(1461, wg_v2136);
    eval.set_sub_input_word(1462, wg_v2137);
    eval.set_sub_input_word(1463, wg_v2138);
    eval.set_sub_input_word(1464, wg_v2139);
    eval.set_sub_input_word(1465, wg_v2140);
    eval.set_sub_input_word(1466, wg_v2142);
    eval.set_sub_input_word(1467, wg_v2143);
    eval.set_sub_input_word(1468, wg_v2144);
    eval.set_sub_input_word(1469, wg_v2145);
    eval.set_sub_input_word(1470, wg_v2146);
    eval.set_sub_input_word(1471, wg_v2147);
    eval.set_sub_input_word(1472, wg_v2148);
    eval.set_sub_input_word(1473, wg_v2149);
    eval.set_sub_input_word(1474, wg_v2150);
    eval.set_sub_input_word(1475, wg_v2151);
    let poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130 = eval
        .deduce_poseidon_3_partial_rounds_chain(
            seq,
            m31_30,
            [
                poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[0],
                poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[1],
                poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[2],
                poseidon_3_partial_rounds_chain_output_round_29_tmp_3806f_129.2[3],
            ],
        );
    let poseidon_3_partial_rounds_chain_output_limb_0_col195 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][0];
    eval.set_col(195, poseidon_3_partial_rounds_chain_output_limb_0_col195);
    let poseidon_3_partial_rounds_chain_output_limb_1_col196 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][1];
    eval.set_col(196, poseidon_3_partial_rounds_chain_output_limb_1_col196);
    let poseidon_3_partial_rounds_chain_output_limb_2_col197 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][2];
    eval.set_col(197, poseidon_3_partial_rounds_chain_output_limb_2_col197);
    let poseidon_3_partial_rounds_chain_output_limb_3_col198 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][3];
    eval.set_col(198, poseidon_3_partial_rounds_chain_output_limb_3_col198);
    let poseidon_3_partial_rounds_chain_output_limb_4_col199 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][4];
    eval.set_col(199, poseidon_3_partial_rounds_chain_output_limb_4_col199);
    let poseidon_3_partial_rounds_chain_output_limb_5_col200 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][5];
    eval.set_col(200, poseidon_3_partial_rounds_chain_output_limb_5_col200);
    let poseidon_3_partial_rounds_chain_output_limb_6_col201 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][6];
    eval.set_col(201, poseidon_3_partial_rounds_chain_output_limb_6_col201);
    let poseidon_3_partial_rounds_chain_output_limb_7_col202 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][7];
    eval.set_col(202, poseidon_3_partial_rounds_chain_output_limb_7_col202);
    let poseidon_3_partial_rounds_chain_output_limb_8_col203 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][8];
    eval.set_col(203, poseidon_3_partial_rounds_chain_output_limb_8_col203);
    let poseidon_3_partial_rounds_chain_output_limb_9_col204 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0][9];
    eval.set_col(204, poseidon_3_partial_rounds_chain_output_limb_9_col204);
    let poseidon_3_partial_rounds_chain_output_limb_10_col205 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][0];
    eval.set_col(205, poseidon_3_partial_rounds_chain_output_limb_10_col205);
    let poseidon_3_partial_rounds_chain_output_limb_11_col206 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][1];
    eval.set_col(206, poseidon_3_partial_rounds_chain_output_limb_11_col206);
    let poseidon_3_partial_rounds_chain_output_limb_12_col207 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][2];
    eval.set_col(207, poseidon_3_partial_rounds_chain_output_limb_12_col207);
    let poseidon_3_partial_rounds_chain_output_limb_13_col208 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][3];
    eval.set_col(208, poseidon_3_partial_rounds_chain_output_limb_13_col208);
    let poseidon_3_partial_rounds_chain_output_limb_14_col209 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][4];
    eval.set_col(209, poseidon_3_partial_rounds_chain_output_limb_14_col209);
    let poseidon_3_partial_rounds_chain_output_limb_15_col210 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][5];
    eval.set_col(210, poseidon_3_partial_rounds_chain_output_limb_15_col210);
    let poseidon_3_partial_rounds_chain_output_limb_16_col211 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][6];
    eval.set_col(211, poseidon_3_partial_rounds_chain_output_limb_16_col211);
    let poseidon_3_partial_rounds_chain_output_limb_17_col212 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][7];
    eval.set_col(212, poseidon_3_partial_rounds_chain_output_limb_17_col212);
    let poseidon_3_partial_rounds_chain_output_limb_18_col213 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][8];
    eval.set_col(213, poseidon_3_partial_rounds_chain_output_limb_18_col213);
    let poseidon_3_partial_rounds_chain_output_limb_19_col214 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1][9];
    eval.set_col(214, poseidon_3_partial_rounds_chain_output_limb_19_col214);
    let poseidon_3_partial_rounds_chain_output_limb_20_col215 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][0];
    eval.set_col(215, poseidon_3_partial_rounds_chain_output_limb_20_col215);
    let poseidon_3_partial_rounds_chain_output_limb_21_col216 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][1];
    eval.set_col(216, poseidon_3_partial_rounds_chain_output_limb_21_col216);
    let poseidon_3_partial_rounds_chain_output_limb_22_col217 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][2];
    eval.set_col(217, poseidon_3_partial_rounds_chain_output_limb_22_col217);
    let poseidon_3_partial_rounds_chain_output_limb_23_col218 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][3];
    eval.set_col(218, poseidon_3_partial_rounds_chain_output_limb_23_col218);
    let poseidon_3_partial_rounds_chain_output_limb_24_col219 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][4];
    eval.set_col(219, poseidon_3_partial_rounds_chain_output_limb_24_col219);
    let poseidon_3_partial_rounds_chain_output_limb_25_col220 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][5];
    eval.set_col(220, poseidon_3_partial_rounds_chain_output_limb_25_col220);
    let poseidon_3_partial_rounds_chain_output_limb_26_col221 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][6];
    eval.set_col(221, poseidon_3_partial_rounds_chain_output_limb_26_col221);
    let poseidon_3_partial_rounds_chain_output_limb_27_col222 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][7];
    eval.set_col(222, poseidon_3_partial_rounds_chain_output_limb_27_col222);
    let poseidon_3_partial_rounds_chain_output_limb_28_col223 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][8];
    eval.set_col(223, poseidon_3_partial_rounds_chain_output_limb_28_col223);
    let poseidon_3_partial_rounds_chain_output_limb_29_col224 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2][9];
    eval.set_col(224, poseidon_3_partial_rounds_chain_output_limb_29_col224);
    let poseidon_3_partial_rounds_chain_output_limb_30_col225 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][0];
    eval.set_col(225, poseidon_3_partial_rounds_chain_output_limb_30_col225);
    let poseidon_3_partial_rounds_chain_output_limb_31_col226 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][1];
    eval.set_col(226, poseidon_3_partial_rounds_chain_output_limb_31_col226);
    let poseidon_3_partial_rounds_chain_output_limb_32_col227 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][2];
    eval.set_col(227, poseidon_3_partial_rounds_chain_output_limb_32_col227);
    let poseidon_3_partial_rounds_chain_output_limb_33_col228 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][3];
    eval.set_col(228, poseidon_3_partial_rounds_chain_output_limb_33_col228);
    let poseidon_3_partial_rounds_chain_output_limb_34_col229 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][4];
    eval.set_col(229, poseidon_3_partial_rounds_chain_output_limb_34_col229);
    let poseidon_3_partial_rounds_chain_output_limb_35_col230 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][5];
    eval.set_col(230, poseidon_3_partial_rounds_chain_output_limb_35_col230);
    let poseidon_3_partial_rounds_chain_output_limb_36_col231 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][6];
    eval.set_col(231, poseidon_3_partial_rounds_chain_output_limb_36_col231);
    let poseidon_3_partial_rounds_chain_output_limb_37_col232 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][7];
    eval.set_col(232, poseidon_3_partial_rounds_chain_output_limb_37_col232);
    let poseidon_3_partial_rounds_chain_output_limb_38_col233 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][8];
    eval.set_col(233, poseidon_3_partial_rounds_chain_output_limb_38_col233);
    let poseidon_3_partial_rounds_chain_output_limb_39_col234 =
        poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3][9];
    eval.set_col(234, poseidon_3_partial_rounds_chain_output_limb_39_col234);
    eval.set_lookup_word(288, m31_1343313504);
    eval.set_lookup_word(289, seq);
    eval.set_lookup_word(290, m31_31);
    eval.set_lookup_word(291, poseidon_3_partial_rounds_chain_output_limb_0_col195);
    eval.set_lookup_word(292, poseidon_3_partial_rounds_chain_output_limb_1_col196);
    eval.set_lookup_word(293, poseidon_3_partial_rounds_chain_output_limb_2_col197);
    eval.set_lookup_word(294, poseidon_3_partial_rounds_chain_output_limb_3_col198);
    eval.set_lookup_word(295, poseidon_3_partial_rounds_chain_output_limb_4_col199);
    eval.set_lookup_word(296, poseidon_3_partial_rounds_chain_output_limb_5_col200);
    eval.set_lookup_word(297, poseidon_3_partial_rounds_chain_output_limb_6_col201);
    eval.set_lookup_word(298, poseidon_3_partial_rounds_chain_output_limb_7_col202);
    eval.set_lookup_word(299, poseidon_3_partial_rounds_chain_output_limb_8_col203);
    eval.set_lookup_word(300, poseidon_3_partial_rounds_chain_output_limb_9_col204);
    eval.set_lookup_word(301, poseidon_3_partial_rounds_chain_output_limb_10_col205);
    eval.set_lookup_word(302, poseidon_3_partial_rounds_chain_output_limb_11_col206);
    eval.set_lookup_word(303, poseidon_3_partial_rounds_chain_output_limb_12_col207);
    eval.set_lookup_word(304, poseidon_3_partial_rounds_chain_output_limb_13_col208);
    eval.set_lookup_word(305, poseidon_3_partial_rounds_chain_output_limb_14_col209);
    eval.set_lookup_word(306, poseidon_3_partial_rounds_chain_output_limb_15_col210);
    eval.set_lookup_word(307, poseidon_3_partial_rounds_chain_output_limb_16_col211);
    eval.set_lookup_word(308, poseidon_3_partial_rounds_chain_output_limb_17_col212);
    eval.set_lookup_word(309, poseidon_3_partial_rounds_chain_output_limb_18_col213);
    eval.set_lookup_word(310, poseidon_3_partial_rounds_chain_output_limb_19_col214);
    eval.set_lookup_word(311, poseidon_3_partial_rounds_chain_output_limb_20_col215);
    eval.set_lookup_word(312, poseidon_3_partial_rounds_chain_output_limb_21_col216);
    eval.set_lookup_word(313, poseidon_3_partial_rounds_chain_output_limb_22_col217);
    eval.set_lookup_word(314, poseidon_3_partial_rounds_chain_output_limb_23_col218);
    eval.set_lookup_word(315, poseidon_3_partial_rounds_chain_output_limb_24_col219);
    eval.set_lookup_word(316, poseidon_3_partial_rounds_chain_output_limb_25_col220);
    eval.set_lookup_word(317, poseidon_3_partial_rounds_chain_output_limb_26_col221);
    eval.set_lookup_word(318, poseidon_3_partial_rounds_chain_output_limb_27_col222);
    eval.set_lookup_word(319, poseidon_3_partial_rounds_chain_output_limb_28_col223);
    eval.set_lookup_word(320, poseidon_3_partial_rounds_chain_output_limb_29_col224);
    eval.set_lookup_word(321, poseidon_3_partial_rounds_chain_output_limb_30_col225);
    eval.set_lookup_word(322, poseidon_3_partial_rounds_chain_output_limb_31_col226);
    eval.set_lookup_word(323, poseidon_3_partial_rounds_chain_output_limb_32_col227);
    eval.set_lookup_word(324, poseidon_3_partial_rounds_chain_output_limb_33_col228);
    eval.set_lookup_word(325, poseidon_3_partial_rounds_chain_output_limb_34_col229);
    eval.set_lookup_word(326, poseidon_3_partial_rounds_chain_output_limb_35_col230);
    eval.set_lookup_word(327, poseidon_3_partial_rounds_chain_output_limb_36_col231);
    eval.set_lookup_word(328, poseidon_3_partial_rounds_chain_output_limb_37_col232);
    eval.set_lookup_word(329, poseidon_3_partial_rounds_chain_output_limb_38_col233);
    eval.set_lookup_word(330, poseidon_3_partial_rounds_chain_output_limb_39_col234);
    let wg_v2152 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2153 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2154 = eval
        .felt_from_w27_words(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[0]);
    let wg_v2155 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2156 = eval.felt_mul(wg_v2155.clone(), wg_v2154.clone());
    let wg_v2157 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2158 = eval.felt_add(wg_v2157.clone(), wg_v2156.clone());
    let wg_v2159 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2160 = eval
        .felt_from_w27_words(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[1]);
    let wg_v2161 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2162 = eval.felt_mul(wg_v2161.clone(), wg_v2160.clone());
    let wg_v2163 = eval.felt_add(wg_v2158.clone(), wg_v2162.clone());
    let wg_v2164 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2165 = eval
        .felt_from_w27_words(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2]);
    let wg_v2166 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2167 = eval.felt_mul(wg_v2166.clone(), wg_v2165.clone());
    let wg_v2168 = eval.felt_add(wg_v2163.clone(), wg_v2167.clone());
    let wg_v2169 = eval.felt_from_limbs([
        m31_511, m31_163, m31_154, m31_339, m31_18, m31_189, m31_220, m31_382, m31_211, m31_350,
        m31_136, m31_446, m31_365, m31_148, m31_338, m31_131, m31_395, m31_173, m31_27, m31_453,
        m31_237, m31_398, m31_57, m31_294, m31_301, m31_181, m31_87, m31_99,
    ]);
    let wg_v2170 = eval.felt_from_limbs([
        m31_511, m31_163, m31_154, m31_339, m31_18, m31_189, m31_220, m31_382, m31_211, m31_350,
        m31_136, m31_446, m31_365, m31_148, m31_338, m31_131, m31_395, m31_173, m31_27, m31_453,
        m31_237, m31_398, m31_57, m31_294, m31_301, m31_181, m31_87, m31_99,
    ]);
    let wg_v2171 = eval.felt_add(wg_v2168.clone(), wg_v2170.clone());
    let wg_v2172 = eval.felt_get_m31(&wg_v2171, 0);
    let wg_v2173 = eval.felt_get_m31(&wg_v2171, 1);
    let wg_v2174 = eval.m31_mul(wg_v2173, m31_512);
    let wg_v2175 = eval.m31_add(wg_v2172, wg_v2174);
    let wg_v2176 = eval.felt_get_m31(&wg_v2171, 2);
    let wg_v2177 = eval.m31_mul(wg_v2176, m31_262144);
    let wg_v2178 = eval.m31_add(wg_v2175, wg_v2177);
    let wg_v2179 = eval.felt_get_m31(&wg_v2171, 3);
    let wg_v2180 = eval.felt_get_m31(&wg_v2171, 4);
    let wg_v2181 = eval.m31_mul(wg_v2180, m31_512);
    let wg_v2182 = eval.m31_add(wg_v2179, wg_v2181);
    let wg_v2183 = eval.felt_get_m31(&wg_v2171, 5);
    let wg_v2184 = eval.m31_mul(wg_v2183, m31_262144);
    let wg_v2185 = eval.m31_add(wg_v2182, wg_v2184);
    let wg_v2186 = eval.felt_get_m31(&wg_v2171, 6);
    let wg_v2187 = eval.felt_get_m31(&wg_v2171, 7);
    let wg_v2188 = eval.m31_mul(wg_v2187, m31_512);
    let wg_v2189 = eval.m31_add(wg_v2186, wg_v2188);
    let wg_v2190 = eval.felt_get_m31(&wg_v2171, 8);
    let wg_v2191 = eval.m31_mul(wg_v2190, m31_262144);
    let wg_v2192 = eval.m31_add(wg_v2189, wg_v2191);
    let wg_v2193 = eval.felt_get_m31(&wg_v2171, 9);
    let wg_v2194 = eval.felt_get_m31(&wg_v2171, 10);
    let wg_v2195 = eval.m31_mul(wg_v2194, m31_512);
    let wg_v2196 = eval.m31_add(wg_v2193, wg_v2195);
    let wg_v2197 = eval.felt_get_m31(&wg_v2171, 11);
    let wg_v2198 = eval.m31_mul(wg_v2197, m31_262144);
    let wg_v2199 = eval.m31_add(wg_v2196, wg_v2198);
    let wg_v2200 = eval.felt_get_m31(&wg_v2171, 12);
    let wg_v2201 = eval.felt_get_m31(&wg_v2171, 13);
    let wg_v2202 = eval.m31_mul(wg_v2201, m31_512);
    let wg_v2203 = eval.m31_add(wg_v2200, wg_v2202);
    let wg_v2204 = eval.felt_get_m31(&wg_v2171, 14);
    let wg_v2205 = eval.m31_mul(wg_v2204, m31_262144);
    let wg_v2206 = eval.m31_add(wg_v2203, wg_v2205);
    let wg_v2207 = eval.felt_get_m31(&wg_v2171, 15);
    let wg_v2208 = eval.felt_get_m31(&wg_v2171, 16);
    let wg_v2209 = eval.m31_mul(wg_v2208, m31_512);
    let wg_v2210 = eval.m31_add(wg_v2207, wg_v2209);
    let wg_v2211 = eval.felt_get_m31(&wg_v2171, 17);
    let wg_v2212 = eval.m31_mul(wg_v2211, m31_262144);
    let wg_v2213 = eval.m31_add(wg_v2210, wg_v2212);
    let wg_v2214 = eval.felt_get_m31(&wg_v2171, 18);
    let wg_v2215 = eval.felt_get_m31(&wg_v2171, 19);
    let wg_v2216 = eval.m31_mul(wg_v2215, m31_512);
    let wg_v2217 = eval.m31_add(wg_v2214, wg_v2216);
    let wg_v2218 = eval.felt_get_m31(&wg_v2171, 20);
    let wg_v2219 = eval.m31_mul(wg_v2218, m31_262144);
    let wg_v2220 = eval.m31_add(wg_v2217, wg_v2219);
    let wg_v2221 = eval.felt_get_m31(&wg_v2171, 21);
    let wg_v2222 = eval.felt_get_m31(&wg_v2171, 22);
    let wg_v2223 = eval.m31_mul(wg_v2222, m31_512);
    let wg_v2224 = eval.m31_add(wg_v2221, wg_v2223);
    let wg_v2225 = eval.felt_get_m31(&wg_v2171, 23);
    let wg_v2226 = eval.m31_mul(wg_v2225, m31_262144);
    let wg_v2227 = eval.m31_add(wg_v2224, wg_v2226);
    let wg_v2228 = eval.felt_get_m31(&wg_v2171, 24);
    let wg_v2229 = eval.felt_get_m31(&wg_v2171, 25);
    let wg_v2230 = eval.m31_mul(wg_v2229, m31_512);
    let wg_v2231 = eval.m31_add(wg_v2228, wg_v2230);
    let wg_v2232 = eval.felt_get_m31(&wg_v2171, 26);
    let wg_v2233 = eval.m31_mul(wg_v2232, m31_262144);
    let wg_v2234 = eval.m31_add(wg_v2231, wg_v2233);
    let wg_v2235 = eval.felt_get_m31(&wg_v2171, 27);
    let combination_tmp_3806f_131 = [
        wg_v2178, wg_v2185, wg_v2192, wg_v2199, wg_v2206, wg_v2213, wg_v2220, wg_v2227, wg_v2234,
        wg_v2235,
    ];
    let combination_limb_0_col235 = combination_tmp_3806f_131[0];
    eval.set_col(235, combination_limb_0_col235);
    let combination_limb_1_col236 = combination_tmp_3806f_131[1];
    eval.set_col(236, combination_limb_1_col236);
    let combination_limb_2_col237 = combination_tmp_3806f_131[2];
    eval.set_col(237, combination_limb_2_col237);
    let combination_limb_3_col238 = combination_tmp_3806f_131[3];
    eval.set_col(238, combination_limb_3_col238);
    let combination_limb_4_col239 = combination_tmp_3806f_131[4];
    eval.set_col(239, combination_limb_4_col239);
    let combination_limb_5_col240 = combination_tmp_3806f_131[5];
    eval.set_col(240, combination_limb_5_col240);
    let combination_limb_6_col241 = combination_tmp_3806f_131[6];
    eval.set_col(241, combination_limb_6_col241);
    let combination_limb_7_col242 = combination_tmp_3806f_131[7];
    eval.set_col(242, combination_limb_7_col242);
    let combination_limb_8_col243 = combination_tmp_3806f_131[8];
    eval.set_col(243, combination_limb_8_col243);
    let combination_limb_9_col244 = combination_tmp_3806f_131[9];
    eval.set_col(244, combination_limb_9_col244);
    let wg_v2236 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_0_col195);
    let wg_v2237 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_10_col205);
    let wg_v2238 = eval.m31_add(wg_v2236, wg_v2237);
    let wg_v2239 = eval.m31_add(
        wg_v2238,
        poseidon_3_partial_rounds_chain_output_limb_20_col215,
    );
    let wg_v2240 = eval.m31_add(wg_v2239, m31_40454143);
    let wg_v2241 = eval.m31_sub(wg_v2240, combination_limb_0_col235);
    let wg_v2242 = eval.m31_add(wg_v2241, m31_134217729);
    let biased_limb_accumulator_u32_tmp_3806f_132 = eval.u32_from_m31(wg_v2242);
    let wg_v2243 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_132);
    let wg_v2244 = eval.u16_as_m31(wg_v2243);
    let p_coef_col245 = eval.m31_sub(wg_v2244, m31_1);
    eval.set_col(245, p_coef_col245);
    let wg_v2245 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_0_col195);
    let wg_v2246 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_10_col205);
    let wg_v2247 = eval.m31_add(wg_v2245, wg_v2246);
    let wg_v2248 = eval.m31_add(
        wg_v2247,
        poseidon_3_partial_rounds_chain_output_limb_20_col215,
    );
    let wg_v2249 = eval.m31_add(wg_v2248, m31_40454143);
    let wg_v2250 = eval.m31_sub(wg_v2249, combination_limb_0_col235);
    let wg_v2251 = eval.m31_sub(wg_v2250, p_coef_col245);
    let carry_0_tmp_3806f_133 = eval.m31_mul(wg_v2251, m31_16);
    let wg_v2252 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_1_col196);
    let wg_v2253 = eval.m31_add(carry_0_tmp_3806f_133, wg_v2252);
    let wg_v2254 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_11_col206);
    let wg_v2255 = eval.m31_add(wg_v2253, wg_v2254);
    let wg_v2256 = eval.m31_add(
        wg_v2255,
        poseidon_3_partial_rounds_chain_output_limb_21_col216,
    );
    let wg_v2257 = eval.m31_add(wg_v2256, m31_49554771);
    let wg_v2258 = eval.m31_sub(wg_v2257, combination_limb_1_col236);
    let carry_1_tmp_3806f_134 = eval.m31_mul(wg_v2258, m31_16);
    let wg_v2259 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_2_col197);
    let wg_v2260 = eval.m31_add(carry_1_tmp_3806f_134, wg_v2259);
    let wg_v2261 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_12_col207);
    let wg_v2262 = eval.m31_add(wg_v2260, wg_v2261);
    let wg_v2263 = eval.m31_add(
        wg_v2262,
        poseidon_3_partial_rounds_chain_output_limb_22_col217,
    );
    let wg_v2264 = eval.m31_add(wg_v2263, m31_55508188);
    let wg_v2265 = eval.m31_sub(wg_v2264, combination_limb_2_col237);
    let carry_2_tmp_3806f_135 = eval.m31_mul(wg_v2265, m31_16);
    let wg_v2266 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_3_col198);
    let wg_v2267 = eval.m31_add(carry_2_tmp_3806f_135, wg_v2266);
    let wg_v2268 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_13_col208);
    let wg_v2269 = eval.m31_add(wg_v2267, wg_v2268);
    let wg_v2270 = eval.m31_add(
        wg_v2269,
        poseidon_3_partial_rounds_chain_output_limb_23_col218,
    );
    let wg_v2271 = eval.m31_add(wg_v2270, m31_116986206);
    let wg_v2272 = eval.m31_sub(wg_v2271, combination_limb_3_col238);
    let carry_3_tmp_3806f_136 = eval.m31_mul(wg_v2272, m31_16);
    let wg_v2273 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_4_col199);
    let wg_v2274 = eval.m31_add(carry_3_tmp_3806f_136, wg_v2273);
    let wg_v2275 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_14_col209);
    let wg_v2276 = eval.m31_add(wg_v2274, wg_v2275);
    let wg_v2277 = eval.m31_add(
        wg_v2276,
        poseidon_3_partial_rounds_chain_output_limb_24_col219,
    );
    let wg_v2278 = eval.m31_add(wg_v2277, m31_88680813);
    let wg_v2279 = eval.m31_sub(wg_v2278, combination_limb_4_col239);
    let carry_4_tmp_3806f_137 = eval.m31_mul(wg_v2279, m31_16);
    let wg_v2280 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_5_col200);
    let wg_v2281 = eval.m31_add(carry_4_tmp_3806f_137, wg_v2280);
    let wg_v2282 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_15_col210);
    let wg_v2283 = eval.m31_add(wg_v2281, wg_v2282);
    let wg_v2284 = eval.m31_add(
        wg_v2283,
        poseidon_3_partial_rounds_chain_output_limb_25_col220,
    );
    let wg_v2285 = eval.m31_add(wg_v2284, m31_45553283);
    let wg_v2286 = eval.m31_sub(wg_v2285, combination_limb_5_col240);
    let carry_5_tmp_3806f_138 = eval.m31_mul(wg_v2286, m31_16);
    let wg_v2287 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_6_col201);
    let wg_v2288 = eval.m31_add(carry_5_tmp_3806f_138, wg_v2287);
    let wg_v2289 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_16_col211);
    let wg_v2290 = eval.m31_add(wg_v2288, wg_v2289);
    let wg_v2291 = eval.m31_add(
        wg_v2290,
        poseidon_3_partial_rounds_chain_output_limb_26_col221,
    );
    let wg_v2292 = eval.m31_add(wg_v2291, m31_62360091);
    let wg_v2293 = eval.m31_sub(wg_v2292, combination_limb_6_col241);
    let carry_6_tmp_3806f_139 = eval.m31_mul(wg_v2293, m31_16);
    let wg_v2294 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_7_col202);
    let wg_v2295 = eval.m31_add(carry_6_tmp_3806f_139, wg_v2294);
    let wg_v2296 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_17_col212);
    let wg_v2297 = eval.m31_add(wg_v2295, wg_v2296);
    let wg_v2298 = eval.m31_add(
        wg_v2297,
        poseidon_3_partial_rounds_chain_output_limb_27_col222,
    );
    let wg_v2299 = eval.m31_add(wg_v2298, m31_77099918);
    let wg_v2300 = eval.m31_sub(wg_v2299, combination_limb_7_col242);
    let wg_v2301 = eval.m31_mul(p_coef_col245, m31_136);
    let wg_v2302 = eval.m31_sub(wg_v2300, wg_v2301);
    let carry_7_tmp_3806f_140 = eval.m31_mul(wg_v2302, m31_16);
    let wg_v2303 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_8_col203);
    let wg_v2304 = eval.m31_add(carry_7_tmp_3806f_140, wg_v2303);
    let wg_v2305 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_18_col213);
    let wg_v2306 = eval.m31_add(wg_v2304, wg_v2305);
    let wg_v2307 = eval.m31_add(
        wg_v2306,
        poseidon_3_partial_rounds_chain_output_limb_28_col223,
    );
    let wg_v2308 = eval.m31_add(wg_v2307, m31_22899501);
    let wg_v2309 = eval.m31_sub(wg_v2308, combination_limb_8_col243);
    let carry_8_tmp_3806f_141 = eval.m31_mul(wg_v2309, m31_16);
    let wg_v2310 = eval.m31_add(p_coef_col245, m31_1);
    let wg_v2311 = eval.m31_add(carry_0_tmp_3806f_133, m31_1);
    let wg_v2312 = eval.m31_add(carry_1_tmp_3806f_134, m31_1);
    let wg_v2313 = eval.m31_add(carry_2_tmp_3806f_135, m31_1);
    eval.set_sub_input_word(320, wg_v2310);
    eval.set_sub_input_word(321, wg_v2311);
    eval.set_sub_input_word(322, wg_v2312);
    eval.set_sub_input_word(323, wg_v2313);
    eval.set_lookup_word(331, m31_1027333874);
    let wg_v2314 = eval.m31_add(p_coef_col245, m31_1);
    eval.set_lookup_word(332, wg_v2314);
    let wg_v2315 = eval.m31_add(carry_0_tmp_3806f_133, m31_1);
    eval.set_lookup_word(333, wg_v2315);
    let wg_v2316 = eval.m31_add(carry_1_tmp_3806f_134, m31_1);
    eval.set_lookup_word(334, wg_v2316);
    let wg_v2317 = eval.m31_add(carry_2_tmp_3806f_135, m31_1);
    eval.set_lookup_word(335, wg_v2317);
    let wg_v2318 = eval.m31_add(carry_3_tmp_3806f_136, m31_1);
    let wg_v2319 = eval.m31_add(carry_4_tmp_3806f_137, m31_1);
    let wg_v2320 = eval.m31_add(carry_5_tmp_3806f_138, m31_1);
    let wg_v2321 = eval.m31_add(carry_6_tmp_3806f_139, m31_1);
    eval.set_sub_input_word(324, wg_v2318);
    eval.set_sub_input_word(325, wg_v2319);
    eval.set_sub_input_word(326, wg_v2320);
    eval.set_sub_input_word(327, wg_v2321);
    eval.set_lookup_word(336, m31_1027333874);
    let wg_v2322 = eval.m31_add(carry_3_tmp_3806f_136, m31_1);
    eval.set_lookup_word(337, wg_v2322);
    let wg_v2323 = eval.m31_add(carry_4_tmp_3806f_137, m31_1);
    eval.set_lookup_word(338, wg_v2323);
    let wg_v2324 = eval.m31_add(carry_5_tmp_3806f_138, m31_1);
    eval.set_lookup_word(339, wg_v2324);
    let wg_v2325 = eval.m31_add(carry_6_tmp_3806f_139, m31_1);
    eval.set_lookup_word(340, wg_v2325);
    let wg_v2326 = eval.m31_add(carry_7_tmp_3806f_140, m31_1);
    let wg_v2327 = eval.m31_add(carry_8_tmp_3806f_141, m31_1);
    eval.set_sub_input_word(338, wg_v2326);
    eval.set_sub_input_word(339, wg_v2327);
    eval.set_lookup_word(341, m31_1651211826);
    let wg_v2328 = eval.m31_add(carry_7_tmp_3806f_140, m31_1);
    eval.set_lookup_word(342, wg_v2328);
    let wg_v2329 = eval.m31_add(carry_8_tmp_3806f_141, m31_1);
    eval.set_lookup_word(343, wg_v2329);
    let linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142 = combination_tmp_3806f_131;
    let wg_v2330 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2331 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2332 = eval
        .felt_from_w27_words(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[2]);
    let wg_v2333 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2334 = eval.felt_mul(wg_v2333.clone(), wg_v2332.clone());
    let wg_v2335 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2336 = eval.felt_add(wg_v2335.clone(), wg_v2334.clone());
    let wg_v2337 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2338 = eval
        .felt_from_w27_words(poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3]);
    let wg_v2339 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2340 = eval.felt_mul(wg_v2339.clone(), wg_v2338.clone());
    let wg_v2341 = eval.felt_add(wg_v2336.clone(), wg_v2340.clone());
    let wg_v2342 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2343 =
        eval.felt_from_w27_words(linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142);
    let wg_v2344 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v2345 = eval.felt_mul(wg_v2344.clone(), wg_v2343.clone());
    let wg_v2346 = eval.felt_add(wg_v2341.clone(), wg_v2345.clone());
    let wg_v2347 = eval.felt_from_limbs([
        m31_221, m31_290, m31_184, m31_315, m31_431, m31_183, m31_60, m31_231, m31_213, m31_454,
        m31_241, m31_250, m31_86, m31_140, m31_261, m31_478, m31_19, m31_454, m31_291, m31_286,
        m31_127, m31_505, m31_33, m31_223, m31_120, m31_300, m31_71, m31_20,
    ]);
    let wg_v2348 = eval.felt_from_limbs([
        m31_221, m31_290, m31_184, m31_315, m31_431, m31_183, m31_60, m31_231, m31_213, m31_454,
        m31_241, m31_250, m31_86, m31_140, m31_261, m31_478, m31_19, m31_454, m31_291, m31_286,
        m31_127, m31_505, m31_33, m31_223, m31_120, m31_300, m31_71, m31_20,
    ]);
    let wg_v2349 = eval.felt_add(wg_v2346.clone(), wg_v2348.clone());
    let wg_v2350 = eval.felt_get_m31(&wg_v2349, 0);
    let wg_v2351 = eval.felt_get_m31(&wg_v2349, 1);
    let wg_v2352 = eval.m31_mul(wg_v2351, m31_512);
    let wg_v2353 = eval.m31_add(wg_v2350, wg_v2352);
    let wg_v2354 = eval.felt_get_m31(&wg_v2349, 2);
    let wg_v2355 = eval.m31_mul(wg_v2354, m31_262144);
    let wg_v2356 = eval.m31_add(wg_v2353, wg_v2355);
    let wg_v2357 = eval.felt_get_m31(&wg_v2349, 3);
    let wg_v2358 = eval.felt_get_m31(&wg_v2349, 4);
    let wg_v2359 = eval.m31_mul(wg_v2358, m31_512);
    let wg_v2360 = eval.m31_add(wg_v2357, wg_v2359);
    let wg_v2361 = eval.felt_get_m31(&wg_v2349, 5);
    let wg_v2362 = eval.m31_mul(wg_v2361, m31_262144);
    let wg_v2363 = eval.m31_add(wg_v2360, wg_v2362);
    let wg_v2364 = eval.felt_get_m31(&wg_v2349, 6);
    let wg_v2365 = eval.felt_get_m31(&wg_v2349, 7);
    let wg_v2366 = eval.m31_mul(wg_v2365, m31_512);
    let wg_v2367 = eval.m31_add(wg_v2364, wg_v2366);
    let wg_v2368 = eval.felt_get_m31(&wg_v2349, 8);
    let wg_v2369 = eval.m31_mul(wg_v2368, m31_262144);
    let wg_v2370 = eval.m31_add(wg_v2367, wg_v2369);
    let wg_v2371 = eval.felt_get_m31(&wg_v2349, 9);
    let wg_v2372 = eval.felt_get_m31(&wg_v2349, 10);
    let wg_v2373 = eval.m31_mul(wg_v2372, m31_512);
    let wg_v2374 = eval.m31_add(wg_v2371, wg_v2373);
    let wg_v2375 = eval.felt_get_m31(&wg_v2349, 11);
    let wg_v2376 = eval.m31_mul(wg_v2375, m31_262144);
    let wg_v2377 = eval.m31_add(wg_v2374, wg_v2376);
    let wg_v2378 = eval.felt_get_m31(&wg_v2349, 12);
    let wg_v2379 = eval.felt_get_m31(&wg_v2349, 13);
    let wg_v2380 = eval.m31_mul(wg_v2379, m31_512);
    let wg_v2381 = eval.m31_add(wg_v2378, wg_v2380);
    let wg_v2382 = eval.felt_get_m31(&wg_v2349, 14);
    let wg_v2383 = eval.m31_mul(wg_v2382, m31_262144);
    let wg_v2384 = eval.m31_add(wg_v2381, wg_v2383);
    let wg_v2385 = eval.felt_get_m31(&wg_v2349, 15);
    let wg_v2386 = eval.felt_get_m31(&wg_v2349, 16);
    let wg_v2387 = eval.m31_mul(wg_v2386, m31_512);
    let wg_v2388 = eval.m31_add(wg_v2385, wg_v2387);
    let wg_v2389 = eval.felt_get_m31(&wg_v2349, 17);
    let wg_v2390 = eval.m31_mul(wg_v2389, m31_262144);
    let wg_v2391 = eval.m31_add(wg_v2388, wg_v2390);
    let wg_v2392 = eval.felt_get_m31(&wg_v2349, 18);
    let wg_v2393 = eval.felt_get_m31(&wg_v2349, 19);
    let wg_v2394 = eval.m31_mul(wg_v2393, m31_512);
    let wg_v2395 = eval.m31_add(wg_v2392, wg_v2394);
    let wg_v2396 = eval.felt_get_m31(&wg_v2349, 20);
    let wg_v2397 = eval.m31_mul(wg_v2396, m31_262144);
    let wg_v2398 = eval.m31_add(wg_v2395, wg_v2397);
    let wg_v2399 = eval.felt_get_m31(&wg_v2349, 21);
    let wg_v2400 = eval.felt_get_m31(&wg_v2349, 22);
    let wg_v2401 = eval.m31_mul(wg_v2400, m31_512);
    let wg_v2402 = eval.m31_add(wg_v2399, wg_v2401);
    let wg_v2403 = eval.felt_get_m31(&wg_v2349, 23);
    let wg_v2404 = eval.m31_mul(wg_v2403, m31_262144);
    let wg_v2405 = eval.m31_add(wg_v2402, wg_v2404);
    let wg_v2406 = eval.felt_get_m31(&wg_v2349, 24);
    let wg_v2407 = eval.felt_get_m31(&wg_v2349, 25);
    let wg_v2408 = eval.m31_mul(wg_v2407, m31_512);
    let wg_v2409 = eval.m31_add(wg_v2406, wg_v2408);
    let wg_v2410 = eval.felt_get_m31(&wg_v2349, 26);
    let wg_v2411 = eval.m31_mul(wg_v2410, m31_262144);
    let wg_v2412 = eval.m31_add(wg_v2409, wg_v2411);
    let wg_v2413 = eval.felt_get_m31(&wg_v2349, 27);
    let combination_tmp_3806f_143 = [
        wg_v2356, wg_v2363, wg_v2370, wg_v2377, wg_v2384, wg_v2391, wg_v2398, wg_v2405, wg_v2412,
        wg_v2413,
    ];
    let combination_limb_0_col246 = combination_tmp_3806f_143[0];
    eval.set_col(246, combination_limb_0_col246);
    let combination_limb_1_col247 = combination_tmp_3806f_143[1];
    eval.set_col(247, combination_limb_1_col247);
    let combination_limb_2_col248 = combination_tmp_3806f_143[2];
    eval.set_col(248, combination_limb_2_col248);
    let combination_limb_3_col249 = combination_tmp_3806f_143[3];
    eval.set_col(249, combination_limb_3_col249);
    let combination_limb_4_col250 = combination_tmp_3806f_143[4];
    eval.set_col(250, combination_limb_4_col250);
    let combination_limb_5_col251 = combination_tmp_3806f_143[5];
    eval.set_col(251, combination_limb_5_col251);
    let combination_limb_6_col252 = combination_tmp_3806f_143[6];
    eval.set_col(252, combination_limb_6_col252);
    let combination_limb_7_col253 = combination_tmp_3806f_143[7];
    eval.set_col(253, combination_limb_7_col253);
    let combination_limb_8_col254 = combination_tmp_3806f_143[8];
    eval.set_col(254, combination_limb_8_col254);
    let combination_limb_9_col255 = combination_tmp_3806f_143[9];
    eval.set_col(255, combination_limb_9_col255);
    let wg_v2414 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_20_col215);
    let wg_v2415 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_30_col225);
    let wg_v2416 = eval.m31_add(wg_v2414, wg_v2415);
    let wg_v2417 = eval.m31_add(wg_v2416, combination_limb_0_col235);
    let wg_v2418 = eval.m31_add(wg_v2417, m31_48383197);
    let wg_v2419 = eval.m31_sub(wg_v2418, combination_limb_0_col246);
    let wg_v2420 = eval.m31_add(wg_v2419, m31_134217729);
    let biased_limb_accumulator_u32_tmp_3806f_144 = eval.u32_from_m31(wg_v2420);
    let wg_v2421 = eval.u32_low(biased_limb_accumulator_u32_tmp_3806f_144);
    let wg_v2422 = eval.u16_as_m31(wg_v2421);
    let p_coef_col256 = eval.m31_sub(wg_v2422, m31_1);
    eval.set_col(256, p_coef_col256);
    let wg_v2423 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_20_col215);
    let wg_v2424 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_30_col225);
    let wg_v2425 = eval.m31_add(wg_v2423, wg_v2424);
    let wg_v2426 = eval.m31_add(wg_v2425, combination_limb_0_col235);
    let wg_v2427 = eval.m31_add(wg_v2426, m31_48383197);
    let wg_v2428 = eval.m31_sub(wg_v2427, combination_limb_0_col246);
    let wg_v2429 = eval.m31_sub(wg_v2428, p_coef_col256);
    let carry_0_tmp_3806f_145 = eval.m31_mul(wg_v2429, m31_16);
    let wg_v2430 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_21_col216);
    let wg_v2431 = eval.m31_add(carry_0_tmp_3806f_145, wg_v2430);
    let wg_v2432 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_31_col226);
    let wg_v2433 = eval.m31_add(wg_v2431, wg_v2432);
    let wg_v2434 = eval.m31_add(wg_v2433, combination_limb_1_col236);
    let wg_v2435 = eval.m31_add(wg_v2434, m31_48193339);
    let wg_v2436 = eval.m31_sub(wg_v2435, combination_limb_1_col247);
    let carry_1_tmp_3806f_146 = eval.m31_mul(wg_v2436, m31_16);
    let wg_v2437 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_22_col217);
    let wg_v2438 = eval.m31_add(carry_1_tmp_3806f_146, wg_v2437);
    let wg_v2439 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_32_col227);
    let wg_v2440 = eval.m31_add(wg_v2438, wg_v2439);
    let wg_v2441 = eval.m31_add(wg_v2440, combination_limb_2_col237);
    let wg_v2442 = eval.m31_add(wg_v2441, m31_55955004);
    let wg_v2443 = eval.m31_sub(wg_v2442, combination_limb_2_col248);
    let carry_2_tmp_3806f_147 = eval.m31_mul(wg_v2443, m31_16);
    let wg_v2444 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_23_col218);
    let wg_v2445 = eval.m31_add(carry_2_tmp_3806f_147, wg_v2444);
    let wg_v2446 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_33_col228);
    let wg_v2447 = eval.m31_add(wg_v2445, wg_v2446);
    let wg_v2448 = eval.m31_add(wg_v2447, combination_limb_3_col238);
    let wg_v2449 = eval.m31_add(wg_v2448, m31_65659846);
    let wg_v2450 = eval.m31_sub(wg_v2449, combination_limb_3_col249);
    let carry_3_tmp_3806f_148 = eval.m31_mul(wg_v2450, m31_16);
    let wg_v2451 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_24_col219);
    let wg_v2452 = eval.m31_add(carry_3_tmp_3806f_148, wg_v2451);
    let wg_v2453 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_34_col229);
    let wg_v2454 = eval.m31_add(wg_v2452, wg_v2453);
    let wg_v2455 = eval.m31_add(wg_v2454, combination_limb_4_col239);
    let wg_v2456 = eval.m31_add(wg_v2455, m31_68491350);
    let wg_v2457 = eval.m31_sub(wg_v2456, combination_limb_4_col250);
    let carry_4_tmp_3806f_149 = eval.m31_mul(wg_v2457, m31_16);
    let wg_v2458 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_25_col220);
    let wg_v2459 = eval.m31_add(carry_4_tmp_3806f_149, wg_v2458);
    let wg_v2460 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_35_col230);
    let wg_v2461 = eval.m31_add(wg_v2459, wg_v2460);
    let wg_v2462 = eval.m31_add(wg_v2461, combination_limb_5_col240);
    let wg_v2463 = eval.m31_add(wg_v2462, m31_119023582);
    let wg_v2464 = eval.m31_sub(wg_v2463, combination_limb_5_col251);
    let carry_5_tmp_3806f_150 = eval.m31_mul(wg_v2464, m31_16);
    let wg_v2465 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_26_col221);
    let wg_v2466 = eval.m31_add(carry_5_tmp_3806f_150, wg_v2465);
    let wg_v2467 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_36_col231);
    let wg_v2468 = eval.m31_add(wg_v2466, wg_v2467);
    let wg_v2469 = eval.m31_add(wg_v2468, combination_limb_6_col241);
    let wg_v2470 = eval.m31_add(wg_v2469, m31_33439011);
    let wg_v2471 = eval.m31_sub(wg_v2470, combination_limb_6_col252);
    let carry_6_tmp_3806f_151 = eval.m31_mul(wg_v2471, m31_16);
    let wg_v2472 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_27_col222);
    let wg_v2473 = eval.m31_add(carry_6_tmp_3806f_151, wg_v2472);
    let wg_v2474 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_37_col232);
    let wg_v2475 = eval.m31_add(wg_v2473, wg_v2474);
    let wg_v2476 = eval.m31_add(wg_v2475, combination_limb_7_col242);
    let wg_v2477 = eval.m31_add(wg_v2476, m31_58475513);
    let wg_v2478 = eval.m31_sub(wg_v2477, combination_limb_7_col253);
    let wg_v2479 = eval.m31_mul(p_coef_col256, m31_136);
    let wg_v2480 = eval.m31_sub(wg_v2478, wg_v2479);
    let carry_7_tmp_3806f_152 = eval.m31_mul(wg_v2480, m31_16);
    let wg_v2481 = eval.m31_mul(m31_4, poseidon_3_partial_rounds_chain_output_limb_28_col223);
    let wg_v2482 = eval.m31_add(carry_7_tmp_3806f_152, wg_v2481);
    let wg_v2483 = eval.m31_mul(m31_2, poseidon_3_partial_rounds_chain_output_limb_38_col233);
    let wg_v2484 = eval.m31_add(wg_v2482, wg_v2483);
    let wg_v2485 = eval.m31_add(wg_v2484, combination_limb_8_col243);
    let wg_v2486 = eval.m31_add(wg_v2485, m31_18765944);
    let wg_v2487 = eval.m31_sub(wg_v2486, combination_limb_8_col254);
    let carry_8_tmp_3806f_153 = eval.m31_mul(wg_v2487, m31_16);
    let wg_v2488 = eval.m31_add(p_coef_col256, m31_1);
    let wg_v2489 = eval.m31_add(carry_0_tmp_3806f_145, m31_1);
    let wg_v2490 = eval.m31_add(carry_1_tmp_3806f_146, m31_1);
    let wg_v2491 = eval.m31_add(carry_2_tmp_3806f_147, m31_1);
    eval.set_sub_input_word(328, wg_v2488);
    eval.set_sub_input_word(329, wg_v2489);
    eval.set_sub_input_word(330, wg_v2490);
    eval.set_sub_input_word(331, wg_v2491);
    eval.set_lookup_word(344, m31_1027333874);
    let wg_v2492 = eval.m31_add(p_coef_col256, m31_1);
    eval.set_lookup_word(345, wg_v2492);
    let wg_v2493 = eval.m31_add(carry_0_tmp_3806f_145, m31_1);
    eval.set_lookup_word(346, wg_v2493);
    let wg_v2494 = eval.m31_add(carry_1_tmp_3806f_146, m31_1);
    eval.set_lookup_word(347, wg_v2494);
    let wg_v2495 = eval.m31_add(carry_2_tmp_3806f_147, m31_1);
    eval.set_lookup_word(348, wg_v2495);
    let wg_v2496 = eval.m31_add(carry_3_tmp_3806f_148, m31_1);
    let wg_v2497 = eval.m31_add(carry_4_tmp_3806f_149, m31_1);
    let wg_v2498 = eval.m31_add(carry_5_tmp_3806f_150, m31_1);
    let wg_v2499 = eval.m31_add(carry_6_tmp_3806f_151, m31_1);
    eval.set_sub_input_word(332, wg_v2496);
    eval.set_sub_input_word(333, wg_v2497);
    eval.set_sub_input_word(334, wg_v2498);
    eval.set_sub_input_word(335, wg_v2499);
    eval.set_lookup_word(349, m31_1027333874);
    let wg_v2500 = eval.m31_add(carry_3_tmp_3806f_148, m31_1);
    eval.set_lookup_word(350, wg_v2500);
    let wg_v2501 = eval.m31_add(carry_4_tmp_3806f_149, m31_1);
    eval.set_lookup_word(351, wg_v2501);
    let wg_v2502 = eval.m31_add(carry_5_tmp_3806f_150, m31_1);
    eval.set_lookup_word(352, wg_v2502);
    let wg_v2503 = eval.m31_add(carry_6_tmp_3806f_151, m31_1);
    eval.set_lookup_word(353, wg_v2503);
    let wg_v2504 = eval.m31_add(carry_7_tmp_3806f_152, m31_1);
    let wg_v2505 = eval.m31_add(carry_8_tmp_3806f_153, m31_1);
    eval.set_sub_input_word(340, wg_v2504);
    eval.set_sub_input_word(341, wg_v2505);
    eval.set_lookup_word(354, m31_1651211826);
    let wg_v2506 = eval.m31_add(carry_7_tmp_3806f_152, m31_1);
    eval.set_lookup_word(355, wg_v2506);
    let wg_v2507 = eval.m31_add(carry_8_tmp_3806f_153, m31_1);
    eval.set_lookup_word(356, wg_v2507);
    let linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154 = combination_tmp_3806f_143;
    let poseidon_full_round_chain_chain_id_tmp_3806f_155 =
        eval.m31_add(poseidon_full_round_chain_chain_tmp_tmp_3806f_72, m31_1);
    eval.set_lookup_word(357, m31_1480369132);
    eval.set_lookup_word(358, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_lookup_word(359, m31_31);
    eval.set_lookup_word(360, combination_limb_0_col246);
    eval.set_lookup_word(361, combination_limb_1_col247);
    eval.set_lookup_word(362, combination_limb_2_col248);
    eval.set_lookup_word(363, combination_limb_3_col249);
    eval.set_lookup_word(364, combination_limb_4_col250);
    eval.set_lookup_word(365, combination_limb_5_col251);
    eval.set_lookup_word(366, combination_limb_6_col252);
    eval.set_lookup_word(367, combination_limb_7_col253);
    eval.set_lookup_word(368, combination_limb_8_col254);
    eval.set_lookup_word(369, combination_limb_9_col255);
    eval.set_lookup_word(370, combination_limb_0_col235);
    eval.set_lookup_word(371, combination_limb_1_col236);
    eval.set_lookup_word(372, combination_limb_2_col237);
    eval.set_lookup_word(373, combination_limb_3_col238);
    eval.set_lookup_word(374, combination_limb_4_col239);
    eval.set_lookup_word(375, combination_limb_5_col240);
    eval.set_lookup_word(376, combination_limb_6_col241);
    eval.set_lookup_word(377, combination_limb_7_col242);
    eval.set_lookup_word(378, combination_limb_8_col243);
    eval.set_lookup_word(379, combination_limb_9_col244);
    eval.set_lookup_word(380, poseidon_3_partial_rounds_chain_output_limb_30_col225);
    eval.set_lookup_word(381, poseidon_3_partial_rounds_chain_output_limb_31_col226);
    eval.set_lookup_word(382, poseidon_3_partial_rounds_chain_output_limb_32_col227);
    eval.set_lookup_word(383, poseidon_3_partial_rounds_chain_output_limb_33_col228);
    eval.set_lookup_word(384, poseidon_3_partial_rounds_chain_output_limb_34_col229);
    eval.set_lookup_word(385, poseidon_3_partial_rounds_chain_output_limb_35_col230);
    eval.set_lookup_word(386, poseidon_3_partial_rounds_chain_output_limb_36_col231);
    eval.set_lookup_word(387, poseidon_3_partial_rounds_chain_output_limb_37_col232);
    eval.set_lookup_word(388, poseidon_3_partial_rounds_chain_output_limb_38_col233);
    eval.set_lookup_word(389, poseidon_3_partial_rounds_chain_output_limb_39_col234);
    let wg_v2508 = linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154;
    let wg_v2509 = wg_v2508[0];
    let wg_v2510 = wg_v2508[1];
    let wg_v2511 = wg_v2508[2];
    let wg_v2512 = wg_v2508[3];
    let wg_v2513 = wg_v2508[4];
    let wg_v2514 = wg_v2508[5];
    let wg_v2515 = wg_v2508[6];
    let wg_v2516 = wg_v2508[7];
    let wg_v2517 = wg_v2508[8];
    let wg_v2518 = wg_v2508[9];
    let wg_v2519 = linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142;
    let wg_v2520 = wg_v2519[0];
    let wg_v2521 = wg_v2519[1];
    let wg_v2522 = wg_v2519[2];
    let wg_v2523 = wg_v2519[3];
    let wg_v2524 = wg_v2519[4];
    let wg_v2525 = wg_v2519[5];
    let wg_v2526 = wg_v2519[6];
    let wg_v2527 = wg_v2519[7];
    let wg_v2528 = wg_v2519[8];
    let wg_v2529 = wg_v2519[9];
    let wg_v2530 = poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3];
    let wg_v2531 = wg_v2530[0];
    let wg_v2532 = wg_v2530[1];
    let wg_v2533 = wg_v2530[2];
    let wg_v2534 = wg_v2530[3];
    let wg_v2535 = wg_v2530[4];
    let wg_v2536 = wg_v2530[5];
    let wg_v2537 = wg_v2530[6];
    let wg_v2538 = wg_v2530[7];
    let wg_v2539 = wg_v2530[8];
    let wg_v2540 = wg_v2530[9];
    eval.set_sub_input_word(134, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_sub_input_word(135, m31_31);
    eval.set_sub_input_word(136, wg_v2509);
    eval.set_sub_input_word(137, wg_v2510);
    eval.set_sub_input_word(138, wg_v2511);
    eval.set_sub_input_word(139, wg_v2512);
    eval.set_sub_input_word(140, wg_v2513);
    eval.set_sub_input_word(141, wg_v2514);
    eval.set_sub_input_word(142, wg_v2515);
    eval.set_sub_input_word(143, wg_v2516);
    eval.set_sub_input_word(144, wg_v2517);
    eval.set_sub_input_word(145, wg_v2518);
    eval.set_sub_input_word(146, wg_v2520);
    eval.set_sub_input_word(147, wg_v2521);
    eval.set_sub_input_word(148, wg_v2522);
    eval.set_sub_input_word(149, wg_v2523);
    eval.set_sub_input_word(150, wg_v2524);
    eval.set_sub_input_word(151, wg_v2525);
    eval.set_sub_input_word(152, wg_v2526);
    eval.set_sub_input_word(153, wg_v2527);
    eval.set_sub_input_word(154, wg_v2528);
    eval.set_sub_input_word(155, wg_v2529);
    eval.set_sub_input_word(156, wg_v2531);
    eval.set_sub_input_word(157, wg_v2532);
    eval.set_sub_input_word(158, wg_v2533);
    eval.set_sub_input_word(159, wg_v2534);
    eval.set_sub_input_word(160, wg_v2535);
    eval.set_sub_input_word(161, wg_v2536);
    eval.set_sub_input_word(162, wg_v2537);
    eval.set_sub_input_word(163, wg_v2538);
    eval.set_sub_input_word(164, wg_v2539);
    eval.set_sub_input_word(165, wg_v2540);
    let poseidon_full_round_chain_output_round_31_tmp_3806f_156 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_id_tmp_3806f_155,
            m31_31,
            [
                linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_154,
                linear_combination_n_4_coefs_4_2_1_1_output_tmp_3806f_142,
                poseidon_3_partial_rounds_chain_output_round_30_tmp_3806f_130.2[3],
            ],
        );
    let wg_v2541 = poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[0];
    let wg_v2542 = wg_v2541[0];
    let wg_v2543 = wg_v2541[1];
    let wg_v2544 = wg_v2541[2];
    let wg_v2545 = wg_v2541[3];
    let wg_v2546 = wg_v2541[4];
    let wg_v2547 = wg_v2541[5];
    let wg_v2548 = wg_v2541[6];
    let wg_v2549 = wg_v2541[7];
    let wg_v2550 = wg_v2541[8];
    let wg_v2551 = wg_v2541[9];
    let wg_v2552 = poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[1];
    let wg_v2553 = wg_v2552[0];
    let wg_v2554 = wg_v2552[1];
    let wg_v2555 = wg_v2552[2];
    let wg_v2556 = wg_v2552[3];
    let wg_v2557 = wg_v2552[4];
    let wg_v2558 = wg_v2552[5];
    let wg_v2559 = wg_v2552[6];
    let wg_v2560 = wg_v2552[7];
    let wg_v2561 = wg_v2552[8];
    let wg_v2562 = wg_v2552[9];
    let wg_v2563 = poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[2];
    let wg_v2564 = wg_v2563[0];
    let wg_v2565 = wg_v2563[1];
    let wg_v2566 = wg_v2563[2];
    let wg_v2567 = wg_v2563[3];
    let wg_v2568 = wg_v2563[4];
    let wg_v2569 = wg_v2563[5];
    let wg_v2570 = wg_v2563[6];
    let wg_v2571 = wg_v2563[7];
    let wg_v2572 = wg_v2563[8];
    let wg_v2573 = wg_v2563[9];
    eval.set_sub_input_word(166, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_sub_input_word(167, m31_32);
    eval.set_sub_input_word(168, wg_v2542);
    eval.set_sub_input_word(169, wg_v2543);
    eval.set_sub_input_word(170, wg_v2544);
    eval.set_sub_input_word(171, wg_v2545);
    eval.set_sub_input_word(172, wg_v2546);
    eval.set_sub_input_word(173, wg_v2547);
    eval.set_sub_input_word(174, wg_v2548);
    eval.set_sub_input_word(175, wg_v2549);
    eval.set_sub_input_word(176, wg_v2550);
    eval.set_sub_input_word(177, wg_v2551);
    eval.set_sub_input_word(178, wg_v2553);
    eval.set_sub_input_word(179, wg_v2554);
    eval.set_sub_input_word(180, wg_v2555);
    eval.set_sub_input_word(181, wg_v2556);
    eval.set_sub_input_word(182, wg_v2557);
    eval.set_sub_input_word(183, wg_v2558);
    eval.set_sub_input_word(184, wg_v2559);
    eval.set_sub_input_word(185, wg_v2560);
    eval.set_sub_input_word(186, wg_v2561);
    eval.set_sub_input_word(187, wg_v2562);
    eval.set_sub_input_word(188, wg_v2564);
    eval.set_sub_input_word(189, wg_v2565);
    eval.set_sub_input_word(190, wg_v2566);
    eval.set_sub_input_word(191, wg_v2567);
    eval.set_sub_input_word(192, wg_v2568);
    eval.set_sub_input_word(193, wg_v2569);
    eval.set_sub_input_word(194, wg_v2570);
    eval.set_sub_input_word(195, wg_v2571);
    eval.set_sub_input_word(196, wg_v2572);
    eval.set_sub_input_word(197, wg_v2573);
    let poseidon_full_round_chain_output_round_32_tmp_3806f_157 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_id_tmp_3806f_155,
            m31_32,
            [
                poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[0],
                poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[1],
                poseidon_full_round_chain_output_round_31_tmp_3806f_156.2[2],
            ],
        );
    let wg_v2574 = poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[0];
    let wg_v2575 = wg_v2574[0];
    let wg_v2576 = wg_v2574[1];
    let wg_v2577 = wg_v2574[2];
    let wg_v2578 = wg_v2574[3];
    let wg_v2579 = wg_v2574[4];
    let wg_v2580 = wg_v2574[5];
    let wg_v2581 = wg_v2574[6];
    let wg_v2582 = wg_v2574[7];
    let wg_v2583 = wg_v2574[8];
    let wg_v2584 = wg_v2574[9];
    let wg_v2585 = poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[1];
    let wg_v2586 = wg_v2585[0];
    let wg_v2587 = wg_v2585[1];
    let wg_v2588 = wg_v2585[2];
    let wg_v2589 = wg_v2585[3];
    let wg_v2590 = wg_v2585[4];
    let wg_v2591 = wg_v2585[5];
    let wg_v2592 = wg_v2585[6];
    let wg_v2593 = wg_v2585[7];
    let wg_v2594 = wg_v2585[8];
    let wg_v2595 = wg_v2585[9];
    let wg_v2596 = poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[2];
    let wg_v2597 = wg_v2596[0];
    let wg_v2598 = wg_v2596[1];
    let wg_v2599 = wg_v2596[2];
    let wg_v2600 = wg_v2596[3];
    let wg_v2601 = wg_v2596[4];
    let wg_v2602 = wg_v2596[5];
    let wg_v2603 = wg_v2596[6];
    let wg_v2604 = wg_v2596[7];
    let wg_v2605 = wg_v2596[8];
    let wg_v2606 = wg_v2596[9];
    eval.set_sub_input_word(198, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_sub_input_word(199, m31_33);
    eval.set_sub_input_word(200, wg_v2575);
    eval.set_sub_input_word(201, wg_v2576);
    eval.set_sub_input_word(202, wg_v2577);
    eval.set_sub_input_word(203, wg_v2578);
    eval.set_sub_input_word(204, wg_v2579);
    eval.set_sub_input_word(205, wg_v2580);
    eval.set_sub_input_word(206, wg_v2581);
    eval.set_sub_input_word(207, wg_v2582);
    eval.set_sub_input_word(208, wg_v2583);
    eval.set_sub_input_word(209, wg_v2584);
    eval.set_sub_input_word(210, wg_v2586);
    eval.set_sub_input_word(211, wg_v2587);
    eval.set_sub_input_word(212, wg_v2588);
    eval.set_sub_input_word(213, wg_v2589);
    eval.set_sub_input_word(214, wg_v2590);
    eval.set_sub_input_word(215, wg_v2591);
    eval.set_sub_input_word(216, wg_v2592);
    eval.set_sub_input_word(217, wg_v2593);
    eval.set_sub_input_word(218, wg_v2594);
    eval.set_sub_input_word(219, wg_v2595);
    eval.set_sub_input_word(220, wg_v2597);
    eval.set_sub_input_word(221, wg_v2598);
    eval.set_sub_input_word(222, wg_v2599);
    eval.set_sub_input_word(223, wg_v2600);
    eval.set_sub_input_word(224, wg_v2601);
    eval.set_sub_input_word(225, wg_v2602);
    eval.set_sub_input_word(226, wg_v2603);
    eval.set_sub_input_word(227, wg_v2604);
    eval.set_sub_input_word(228, wg_v2605);
    eval.set_sub_input_word(229, wg_v2606);
    let poseidon_full_round_chain_output_round_33_tmp_3806f_158 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_id_tmp_3806f_155,
            m31_33,
            [
                poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[0],
                poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[1],
                poseidon_full_round_chain_output_round_32_tmp_3806f_157.2[2],
            ],
        );
    let wg_v2607 = poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[0];
    let wg_v2608 = wg_v2607[0];
    let wg_v2609 = wg_v2607[1];
    let wg_v2610 = wg_v2607[2];
    let wg_v2611 = wg_v2607[3];
    let wg_v2612 = wg_v2607[4];
    let wg_v2613 = wg_v2607[5];
    let wg_v2614 = wg_v2607[6];
    let wg_v2615 = wg_v2607[7];
    let wg_v2616 = wg_v2607[8];
    let wg_v2617 = wg_v2607[9];
    let wg_v2618 = poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[1];
    let wg_v2619 = wg_v2618[0];
    let wg_v2620 = wg_v2618[1];
    let wg_v2621 = wg_v2618[2];
    let wg_v2622 = wg_v2618[3];
    let wg_v2623 = wg_v2618[4];
    let wg_v2624 = wg_v2618[5];
    let wg_v2625 = wg_v2618[6];
    let wg_v2626 = wg_v2618[7];
    let wg_v2627 = wg_v2618[8];
    let wg_v2628 = wg_v2618[9];
    let wg_v2629 = poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[2];
    let wg_v2630 = wg_v2629[0];
    let wg_v2631 = wg_v2629[1];
    let wg_v2632 = wg_v2629[2];
    let wg_v2633 = wg_v2629[3];
    let wg_v2634 = wg_v2629[4];
    let wg_v2635 = wg_v2629[5];
    let wg_v2636 = wg_v2629[6];
    let wg_v2637 = wg_v2629[7];
    let wg_v2638 = wg_v2629[8];
    let wg_v2639 = wg_v2629[9];
    eval.set_sub_input_word(230, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_sub_input_word(231, m31_34);
    eval.set_sub_input_word(232, wg_v2608);
    eval.set_sub_input_word(233, wg_v2609);
    eval.set_sub_input_word(234, wg_v2610);
    eval.set_sub_input_word(235, wg_v2611);
    eval.set_sub_input_word(236, wg_v2612);
    eval.set_sub_input_word(237, wg_v2613);
    eval.set_sub_input_word(238, wg_v2614);
    eval.set_sub_input_word(239, wg_v2615);
    eval.set_sub_input_word(240, wg_v2616);
    eval.set_sub_input_word(241, wg_v2617);
    eval.set_sub_input_word(242, wg_v2619);
    eval.set_sub_input_word(243, wg_v2620);
    eval.set_sub_input_word(244, wg_v2621);
    eval.set_sub_input_word(245, wg_v2622);
    eval.set_sub_input_word(246, wg_v2623);
    eval.set_sub_input_word(247, wg_v2624);
    eval.set_sub_input_word(248, wg_v2625);
    eval.set_sub_input_word(249, wg_v2626);
    eval.set_sub_input_word(250, wg_v2627);
    eval.set_sub_input_word(251, wg_v2628);
    eval.set_sub_input_word(252, wg_v2630);
    eval.set_sub_input_word(253, wg_v2631);
    eval.set_sub_input_word(254, wg_v2632);
    eval.set_sub_input_word(255, wg_v2633);
    eval.set_sub_input_word(256, wg_v2634);
    eval.set_sub_input_word(257, wg_v2635);
    eval.set_sub_input_word(258, wg_v2636);
    eval.set_sub_input_word(259, wg_v2637);
    eval.set_sub_input_word(260, wg_v2638);
    eval.set_sub_input_word(261, wg_v2639);
    let poseidon_full_round_chain_output_round_34_tmp_3806f_159 = eval
        .deduce_poseidon_full_round_chain(
            poseidon_full_round_chain_chain_id_tmp_3806f_155,
            m31_34,
            [
                poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[0],
                poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[1],
                poseidon_full_round_chain_output_round_33_tmp_3806f_158.2[2],
            ],
        );
    let poseidon_full_round_chain_output_limb_0_col257 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][0];
    eval.set_col(257, poseidon_full_round_chain_output_limb_0_col257);
    let poseidon_full_round_chain_output_limb_1_col258 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][1];
    eval.set_col(258, poseidon_full_round_chain_output_limb_1_col258);
    let poseidon_full_round_chain_output_limb_2_col259 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][2];
    eval.set_col(259, poseidon_full_round_chain_output_limb_2_col259);
    let poseidon_full_round_chain_output_limb_3_col260 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][3];
    eval.set_col(260, poseidon_full_round_chain_output_limb_3_col260);
    let poseidon_full_round_chain_output_limb_4_col261 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][4];
    eval.set_col(261, poseidon_full_round_chain_output_limb_4_col261);
    let poseidon_full_round_chain_output_limb_5_col262 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][5];
    eval.set_col(262, poseidon_full_round_chain_output_limb_5_col262);
    let poseidon_full_round_chain_output_limb_6_col263 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][6];
    eval.set_col(263, poseidon_full_round_chain_output_limb_6_col263);
    let poseidon_full_round_chain_output_limb_7_col264 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][7];
    eval.set_col(264, poseidon_full_round_chain_output_limb_7_col264);
    let poseidon_full_round_chain_output_limb_8_col265 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][8];
    eval.set_col(265, poseidon_full_round_chain_output_limb_8_col265);
    let poseidon_full_round_chain_output_limb_9_col266 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0][9];
    eval.set_col(266, poseidon_full_round_chain_output_limb_9_col266);
    let poseidon_full_round_chain_output_limb_10_col267 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][0];
    eval.set_col(267, poseidon_full_round_chain_output_limb_10_col267);
    let poseidon_full_round_chain_output_limb_11_col268 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][1];
    eval.set_col(268, poseidon_full_round_chain_output_limb_11_col268);
    let poseidon_full_round_chain_output_limb_12_col269 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][2];
    eval.set_col(269, poseidon_full_round_chain_output_limb_12_col269);
    let poseidon_full_round_chain_output_limb_13_col270 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][3];
    eval.set_col(270, poseidon_full_round_chain_output_limb_13_col270);
    let poseidon_full_round_chain_output_limb_14_col271 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][4];
    eval.set_col(271, poseidon_full_round_chain_output_limb_14_col271);
    let poseidon_full_round_chain_output_limb_15_col272 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][5];
    eval.set_col(272, poseidon_full_round_chain_output_limb_15_col272);
    let poseidon_full_round_chain_output_limb_16_col273 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][6];
    eval.set_col(273, poseidon_full_round_chain_output_limb_16_col273);
    let poseidon_full_round_chain_output_limb_17_col274 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][7];
    eval.set_col(274, poseidon_full_round_chain_output_limb_17_col274);
    let poseidon_full_round_chain_output_limb_18_col275 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][8];
    eval.set_col(275, poseidon_full_round_chain_output_limb_18_col275);
    let poseidon_full_round_chain_output_limb_19_col276 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1][9];
    eval.set_col(276, poseidon_full_round_chain_output_limb_19_col276);
    let poseidon_full_round_chain_output_limb_20_col277 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][0];
    eval.set_col(277, poseidon_full_round_chain_output_limb_20_col277);
    let poseidon_full_round_chain_output_limb_21_col278 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][1];
    eval.set_col(278, poseidon_full_round_chain_output_limb_21_col278);
    let poseidon_full_round_chain_output_limb_22_col279 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][2];
    eval.set_col(279, poseidon_full_round_chain_output_limb_22_col279);
    let poseidon_full_round_chain_output_limb_23_col280 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][3];
    eval.set_col(280, poseidon_full_round_chain_output_limb_23_col280);
    let poseidon_full_round_chain_output_limb_24_col281 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][4];
    eval.set_col(281, poseidon_full_round_chain_output_limb_24_col281);
    let poseidon_full_round_chain_output_limb_25_col282 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][5];
    eval.set_col(282, poseidon_full_round_chain_output_limb_25_col282);
    let poseidon_full_round_chain_output_limb_26_col283 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][6];
    eval.set_col(283, poseidon_full_round_chain_output_limb_26_col283);
    let poseidon_full_round_chain_output_limb_27_col284 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][7];
    eval.set_col(284, poseidon_full_round_chain_output_limb_27_col284);
    let poseidon_full_round_chain_output_limb_28_col285 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][8];
    eval.set_col(285, poseidon_full_round_chain_output_limb_28_col285);
    let poseidon_full_round_chain_output_limb_29_col286 =
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2][9];
    eval.set_col(286, poseidon_full_round_chain_output_limb_29_col286);
    eval.set_lookup_word(390, m31_1480369132);
    eval.set_lookup_word(391, poseidon_full_round_chain_chain_id_tmp_3806f_155);
    eval.set_lookup_word(392, m31_35);
    eval.set_lookup_word(393, poseidon_full_round_chain_output_limb_0_col257);
    eval.set_lookup_word(394, poseidon_full_round_chain_output_limb_1_col258);
    eval.set_lookup_word(395, poseidon_full_round_chain_output_limb_2_col259);
    eval.set_lookup_word(396, poseidon_full_round_chain_output_limb_3_col260);
    eval.set_lookup_word(397, poseidon_full_round_chain_output_limb_4_col261);
    eval.set_lookup_word(398, poseidon_full_round_chain_output_limb_5_col262);
    eval.set_lookup_word(399, poseidon_full_round_chain_output_limb_6_col263);
    eval.set_lookup_word(400, poseidon_full_round_chain_output_limb_7_col264);
    eval.set_lookup_word(401, poseidon_full_round_chain_output_limb_8_col265);
    eval.set_lookup_word(402, poseidon_full_round_chain_output_limb_9_col266);
    eval.set_lookup_word(403, poseidon_full_round_chain_output_limb_10_col267);
    eval.set_lookup_word(404, poseidon_full_round_chain_output_limb_11_col268);
    eval.set_lookup_word(405, poseidon_full_round_chain_output_limb_12_col269);
    eval.set_lookup_word(406, poseidon_full_round_chain_output_limb_13_col270);
    eval.set_lookup_word(407, poseidon_full_round_chain_output_limb_14_col271);
    eval.set_lookup_word(408, poseidon_full_round_chain_output_limb_15_col272);
    eval.set_lookup_word(409, poseidon_full_round_chain_output_limb_16_col273);
    eval.set_lookup_word(410, poseidon_full_round_chain_output_limb_17_col274);
    eval.set_lookup_word(411, poseidon_full_round_chain_output_limb_18_col275);
    eval.set_lookup_word(412, poseidon_full_round_chain_output_limb_19_col276);
    eval.set_lookup_word(413, poseidon_full_round_chain_output_limb_20_col277);
    eval.set_lookup_word(414, poseidon_full_round_chain_output_limb_21_col278);
    eval.set_lookup_word(415, poseidon_full_round_chain_output_limb_22_col279);
    eval.set_lookup_word(416, poseidon_full_round_chain_output_limb_23_col280);
    eval.set_lookup_word(417, poseidon_full_round_chain_output_limb_24_col281);
    eval.set_lookup_word(418, poseidon_full_round_chain_output_limb_25_col282);
    eval.set_lookup_word(419, poseidon_full_round_chain_output_limb_26_col283);
    eval.set_lookup_word(420, poseidon_full_round_chain_output_limb_27_col284);
    eval.set_lookup_word(421, poseidon_full_round_chain_output_limb_28_col285);
    eval.set_lookup_word(422, poseidon_full_round_chain_output_limb_29_col286);
    let poseidon_hades_permutation_output_tmp_3806f_160 = [
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[0],
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[1],
        poseidon_full_round_chain_output_round_34_tmp_3806f_159.2[2],
    ];
    let input_as_felt252_tmp_3806f_161 =
        eval.felt_from_w27_words(poseidon_hades_permutation_output_tmp_3806f_160[0]);
    let unpacked_limb_0_col287 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 0);
    eval.set_col(287, unpacked_limb_0_col287);
    let unpacked_limb_1_col288 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 1);
    eval.set_col(288, unpacked_limb_1_col288);
    let unpacked_limb_3_col289 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 3);
    eval.set_col(289, unpacked_limb_3_col289);
    let unpacked_limb_4_col290 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 4);
    eval.set_col(290, unpacked_limb_4_col290);
    let unpacked_limb_6_col291 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 6);
    eval.set_col(291, unpacked_limb_6_col291);
    let unpacked_limb_7_col292 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 7);
    eval.set_col(292, unpacked_limb_7_col292);
    let unpacked_limb_9_col293 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 9);
    eval.set_col(293, unpacked_limb_9_col293);
    let unpacked_limb_10_col294 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 10);
    eval.set_col(294, unpacked_limb_10_col294);
    let unpacked_limb_12_col295 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 12);
    eval.set_col(295, unpacked_limb_12_col295);
    let unpacked_limb_13_col296 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 13);
    eval.set_col(296, unpacked_limb_13_col296);
    let unpacked_limb_15_col297 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 15);
    eval.set_col(297, unpacked_limb_15_col297);
    let unpacked_limb_16_col298 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 16);
    eval.set_col(298, unpacked_limb_16_col298);
    let unpacked_limb_18_col299 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 18);
    eval.set_col(299, unpacked_limb_18_col299);
    let unpacked_limb_19_col300 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 19);
    eval.set_col(300, unpacked_limb_19_col300);
    let unpacked_limb_21_col301 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 21);
    eval.set_col(301, unpacked_limb_21_col301);
    let unpacked_limb_22_col302 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 22);
    eval.set_col(302, unpacked_limb_22_col302);
    let unpacked_limb_24_col303 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 24);
    eval.set_col(303, unpacked_limb_24_col303);
    let unpacked_limb_25_col304 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_161.clone(), 25);
    eval.set_col(304, unpacked_limb_25_col304);
    let wg_v2640 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_0_col257,
        unpacked_limb_0_col287,
    );
    let wg_v2641 = eval.m31_mul(unpacked_limb_1_col288, m31_512);
    let wg_v2642 = eval.m31_sub(wg_v2640, wg_v2641);
    let wg_v2643 = eval.m31_mul(wg_v2642, m31_8192);
    let wg_v2644 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_1_col258,
        unpacked_limb_3_col289,
    );
    let wg_v2645 = eval.m31_mul(unpacked_limb_4_col290, m31_512);
    let wg_v2646 = eval.m31_sub(wg_v2644, wg_v2645);
    let wg_v2647 = eval.m31_mul(wg_v2646, m31_8192);
    let wg_v2648 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_2_col259,
        unpacked_limb_6_col291,
    );
    let wg_v2649 = eval.m31_mul(unpacked_limb_7_col292, m31_512);
    let wg_v2650 = eval.m31_sub(wg_v2648, wg_v2649);
    let wg_v2651 = eval.m31_mul(wg_v2650, m31_8192);
    let wg_v2652 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_3_col260,
        unpacked_limb_9_col293,
    );
    let wg_v2653 = eval.m31_mul(unpacked_limb_10_col294, m31_512);
    let wg_v2654 = eval.m31_sub(wg_v2652, wg_v2653);
    let wg_v2655 = eval.m31_mul(wg_v2654, m31_8192);
    let wg_v2656 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_4_col261,
        unpacked_limb_12_col295,
    );
    let wg_v2657 = eval.m31_mul(unpacked_limb_13_col296, m31_512);
    let wg_v2658 = eval.m31_sub(wg_v2656, wg_v2657);
    let wg_v2659 = eval.m31_mul(wg_v2658, m31_8192);
    let wg_v2660 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_5_col262,
        unpacked_limb_15_col297,
    );
    let wg_v2661 = eval.m31_mul(unpacked_limb_16_col298, m31_512);
    let wg_v2662 = eval.m31_sub(wg_v2660, wg_v2661);
    let wg_v2663 = eval.m31_mul(wg_v2662, m31_8192);
    let wg_v2664 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_6_col263,
        unpacked_limb_18_col299,
    );
    let wg_v2665 = eval.m31_mul(unpacked_limb_19_col300, m31_512);
    let wg_v2666 = eval.m31_sub(wg_v2664, wg_v2665);
    let wg_v2667 = eval.m31_mul(wg_v2666, m31_8192);
    let wg_v2668 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_7_col264,
        unpacked_limb_21_col301,
    );
    let wg_v2669 = eval.m31_mul(unpacked_limb_22_col302, m31_512);
    let wg_v2670 = eval.m31_sub(wg_v2668, wg_v2669);
    let wg_v2671 = eval.m31_mul(wg_v2670, m31_8192);
    let wg_v2672 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_8_col265,
        unpacked_limb_24_col303,
    );
    let wg_v2673 = eval.m31_mul(unpacked_limb_25_col304, m31_512);
    let wg_v2674 = eval.m31_sub(wg_v2672, wg_v2673);
    let wg_v2675 = eval.m31_mul(wg_v2674, m31_8192);
    let felt_252_unpack_from_27_output_tmp_3806f_162 = eval.felt_from_limbs([
        unpacked_limb_0_col287,
        unpacked_limb_1_col288,
        wg_v2643,
        unpacked_limb_3_col289,
        unpacked_limb_4_col290,
        wg_v2647,
        unpacked_limb_6_col291,
        unpacked_limb_7_col292,
        wg_v2651,
        unpacked_limb_9_col293,
        unpacked_limb_10_col294,
        wg_v2655,
        unpacked_limb_12_col295,
        unpacked_limb_13_col296,
        wg_v2659,
        unpacked_limb_15_col297,
        unpacked_limb_16_col298,
        wg_v2663,
        unpacked_limb_18_col299,
        unpacked_limb_19_col300,
        wg_v2667,
        unpacked_limb_21_col301,
        unpacked_limb_22_col302,
        wg_v2671,
        unpacked_limb_24_col303,
        unpacked_limb_25_col304,
        wg_v2675,
        poseidon_full_round_chain_output_limb_9_col266,
    ]);
    eval.set_sub_input_word(3, input_limb_3_col3);
    eval.set_lookup_word(423, m31_1662111297);
    eval.set_lookup_word(424, input_limb_3_col3);
    eval.set_lookup_word(425, unpacked_limb_0_col287);
    eval.set_lookup_word(426, unpacked_limb_1_col288);
    let wg_v2676 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 2);
    eval.set_lookup_word(427, wg_v2676);
    eval.set_lookup_word(428, unpacked_limb_3_col289);
    eval.set_lookup_word(429, unpacked_limb_4_col290);
    let wg_v2677 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 5);
    eval.set_lookup_word(430, wg_v2677);
    eval.set_lookup_word(431, unpacked_limb_6_col291);
    eval.set_lookup_word(432, unpacked_limb_7_col292);
    let wg_v2678 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 8);
    eval.set_lookup_word(433, wg_v2678);
    eval.set_lookup_word(434, unpacked_limb_9_col293);
    eval.set_lookup_word(435, unpacked_limb_10_col294);
    let wg_v2679 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 11);
    eval.set_lookup_word(436, wg_v2679);
    eval.set_lookup_word(437, unpacked_limb_12_col295);
    eval.set_lookup_word(438, unpacked_limb_13_col296);
    let wg_v2680 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 14);
    eval.set_lookup_word(439, wg_v2680);
    eval.set_lookup_word(440, unpacked_limb_15_col297);
    eval.set_lookup_word(441, unpacked_limb_16_col298);
    let wg_v2681 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 17);
    eval.set_lookup_word(442, wg_v2681);
    eval.set_lookup_word(443, unpacked_limb_18_col299);
    eval.set_lookup_word(444, unpacked_limb_19_col300);
    let wg_v2682 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 20);
    eval.set_lookup_word(445, wg_v2682);
    eval.set_lookup_word(446, unpacked_limb_21_col301);
    eval.set_lookup_word(447, unpacked_limb_22_col302);
    let wg_v2683 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 23);
    eval.set_lookup_word(448, wg_v2683);
    eval.set_lookup_word(449, unpacked_limb_24_col303);
    eval.set_lookup_word(450, unpacked_limb_25_col304);
    let wg_v2684 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_162.clone(), 26);
    eval.set_lookup_word(451, wg_v2684);
    eval.set_lookup_word(452, poseidon_full_round_chain_output_limb_9_col266);
    let input_as_felt252_tmp_3806f_163 =
        eval.felt_from_w27_words(poseidon_hades_permutation_output_tmp_3806f_160[1]);
    let unpacked_limb_0_col305 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 0);
    eval.set_col(305, unpacked_limb_0_col305);
    let unpacked_limb_1_col306 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 1);
    eval.set_col(306, unpacked_limb_1_col306);
    let unpacked_limb_3_col307 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 3);
    eval.set_col(307, unpacked_limb_3_col307);
    let unpacked_limb_4_col308 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 4);
    eval.set_col(308, unpacked_limb_4_col308);
    let unpacked_limb_6_col309 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 6);
    eval.set_col(309, unpacked_limb_6_col309);
    let unpacked_limb_7_col310 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 7);
    eval.set_col(310, unpacked_limb_7_col310);
    let unpacked_limb_9_col311 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 9);
    eval.set_col(311, unpacked_limb_9_col311);
    let unpacked_limb_10_col312 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 10);
    eval.set_col(312, unpacked_limb_10_col312);
    let unpacked_limb_12_col313 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 12);
    eval.set_col(313, unpacked_limb_12_col313);
    let unpacked_limb_13_col314 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 13);
    eval.set_col(314, unpacked_limb_13_col314);
    let unpacked_limb_15_col315 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 15);
    eval.set_col(315, unpacked_limb_15_col315);
    let unpacked_limb_16_col316 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 16);
    eval.set_col(316, unpacked_limb_16_col316);
    let unpacked_limb_18_col317 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 18);
    eval.set_col(317, unpacked_limb_18_col317);
    let unpacked_limb_19_col318 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 19);
    eval.set_col(318, unpacked_limb_19_col318);
    let unpacked_limb_21_col319 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 21);
    eval.set_col(319, unpacked_limb_21_col319);
    let unpacked_limb_22_col320 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 22);
    eval.set_col(320, unpacked_limb_22_col320);
    let unpacked_limb_24_col321 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 24);
    eval.set_col(321, unpacked_limb_24_col321);
    let unpacked_limb_25_col322 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_163.clone(), 25);
    eval.set_col(322, unpacked_limb_25_col322);
    let wg_v2685 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_10_col267,
        unpacked_limb_0_col305,
    );
    let wg_v2686 = eval.m31_mul(unpacked_limb_1_col306, m31_512);
    let wg_v2687 = eval.m31_sub(wg_v2685, wg_v2686);
    let wg_v2688 = eval.m31_mul(wg_v2687, m31_8192);
    let wg_v2689 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_11_col268,
        unpacked_limb_3_col307,
    );
    let wg_v2690 = eval.m31_mul(unpacked_limb_4_col308, m31_512);
    let wg_v2691 = eval.m31_sub(wg_v2689, wg_v2690);
    let wg_v2692 = eval.m31_mul(wg_v2691, m31_8192);
    let wg_v2693 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_12_col269,
        unpacked_limb_6_col309,
    );
    let wg_v2694 = eval.m31_mul(unpacked_limb_7_col310, m31_512);
    let wg_v2695 = eval.m31_sub(wg_v2693, wg_v2694);
    let wg_v2696 = eval.m31_mul(wg_v2695, m31_8192);
    let wg_v2697 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_13_col270,
        unpacked_limb_9_col311,
    );
    let wg_v2698 = eval.m31_mul(unpacked_limb_10_col312, m31_512);
    let wg_v2699 = eval.m31_sub(wg_v2697, wg_v2698);
    let wg_v2700 = eval.m31_mul(wg_v2699, m31_8192);
    let wg_v2701 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_14_col271,
        unpacked_limb_12_col313,
    );
    let wg_v2702 = eval.m31_mul(unpacked_limb_13_col314, m31_512);
    let wg_v2703 = eval.m31_sub(wg_v2701, wg_v2702);
    let wg_v2704 = eval.m31_mul(wg_v2703, m31_8192);
    let wg_v2705 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_15_col272,
        unpacked_limb_15_col315,
    );
    let wg_v2706 = eval.m31_mul(unpacked_limb_16_col316, m31_512);
    let wg_v2707 = eval.m31_sub(wg_v2705, wg_v2706);
    let wg_v2708 = eval.m31_mul(wg_v2707, m31_8192);
    let wg_v2709 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_16_col273,
        unpacked_limb_18_col317,
    );
    let wg_v2710 = eval.m31_mul(unpacked_limb_19_col318, m31_512);
    let wg_v2711 = eval.m31_sub(wg_v2709, wg_v2710);
    let wg_v2712 = eval.m31_mul(wg_v2711, m31_8192);
    let wg_v2713 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_17_col274,
        unpacked_limb_21_col319,
    );
    let wg_v2714 = eval.m31_mul(unpacked_limb_22_col320, m31_512);
    let wg_v2715 = eval.m31_sub(wg_v2713, wg_v2714);
    let wg_v2716 = eval.m31_mul(wg_v2715, m31_8192);
    let wg_v2717 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_18_col275,
        unpacked_limb_24_col321,
    );
    let wg_v2718 = eval.m31_mul(unpacked_limb_25_col322, m31_512);
    let wg_v2719 = eval.m31_sub(wg_v2717, wg_v2718);
    let wg_v2720 = eval.m31_mul(wg_v2719, m31_8192);
    let felt_252_unpack_from_27_output_tmp_3806f_164 = eval.felt_from_limbs([
        unpacked_limb_0_col305,
        unpacked_limb_1_col306,
        wg_v2688,
        unpacked_limb_3_col307,
        unpacked_limb_4_col308,
        wg_v2692,
        unpacked_limb_6_col309,
        unpacked_limb_7_col310,
        wg_v2696,
        unpacked_limb_9_col311,
        unpacked_limb_10_col312,
        wg_v2700,
        unpacked_limb_12_col313,
        unpacked_limb_13_col314,
        wg_v2704,
        unpacked_limb_15_col315,
        unpacked_limb_16_col316,
        wg_v2708,
        unpacked_limb_18_col317,
        unpacked_limb_19_col318,
        wg_v2712,
        unpacked_limb_21_col319,
        unpacked_limb_22_col320,
        wg_v2716,
        unpacked_limb_24_col321,
        unpacked_limb_25_col322,
        wg_v2720,
        poseidon_full_round_chain_output_limb_19_col276,
    ]);
    eval.set_sub_input_word(4, input_limb_4_col4);
    eval.set_lookup_word(453, m31_1662111297);
    eval.set_lookup_word(454, input_limb_4_col4);
    eval.set_lookup_word(455, unpacked_limb_0_col305);
    eval.set_lookup_word(456, unpacked_limb_1_col306);
    let wg_v2721 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 2);
    eval.set_lookup_word(457, wg_v2721);
    eval.set_lookup_word(458, unpacked_limb_3_col307);
    eval.set_lookup_word(459, unpacked_limb_4_col308);
    let wg_v2722 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 5);
    eval.set_lookup_word(460, wg_v2722);
    eval.set_lookup_word(461, unpacked_limb_6_col309);
    eval.set_lookup_word(462, unpacked_limb_7_col310);
    let wg_v2723 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 8);
    eval.set_lookup_word(463, wg_v2723);
    eval.set_lookup_word(464, unpacked_limb_9_col311);
    eval.set_lookup_word(465, unpacked_limb_10_col312);
    let wg_v2724 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 11);
    eval.set_lookup_word(466, wg_v2724);
    eval.set_lookup_word(467, unpacked_limb_12_col313);
    eval.set_lookup_word(468, unpacked_limb_13_col314);
    let wg_v2725 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 14);
    eval.set_lookup_word(469, wg_v2725);
    eval.set_lookup_word(470, unpacked_limb_15_col315);
    eval.set_lookup_word(471, unpacked_limb_16_col316);
    let wg_v2726 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 17);
    eval.set_lookup_word(472, wg_v2726);
    eval.set_lookup_word(473, unpacked_limb_18_col317);
    eval.set_lookup_word(474, unpacked_limb_19_col318);
    let wg_v2727 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 20);
    eval.set_lookup_word(475, wg_v2727);
    eval.set_lookup_word(476, unpacked_limb_21_col319);
    eval.set_lookup_word(477, unpacked_limb_22_col320);
    let wg_v2728 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 23);
    eval.set_lookup_word(478, wg_v2728);
    eval.set_lookup_word(479, unpacked_limb_24_col321);
    eval.set_lookup_word(480, unpacked_limb_25_col322);
    let wg_v2729 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_164.clone(), 26);
    eval.set_lookup_word(481, wg_v2729);
    eval.set_lookup_word(482, poseidon_full_round_chain_output_limb_19_col276);
    let input_as_felt252_tmp_3806f_165 =
        eval.felt_from_w27_words(poseidon_hades_permutation_output_tmp_3806f_160[2]);
    let unpacked_limb_0_col323 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 0);
    eval.set_col(323, unpacked_limb_0_col323);
    let unpacked_limb_1_col324 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 1);
    eval.set_col(324, unpacked_limb_1_col324);
    let unpacked_limb_3_col325 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 3);
    eval.set_col(325, unpacked_limb_3_col325);
    let unpacked_limb_4_col326 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 4);
    eval.set_col(326, unpacked_limb_4_col326);
    let unpacked_limb_6_col327 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 6);
    eval.set_col(327, unpacked_limb_6_col327);
    let unpacked_limb_7_col328 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 7);
    eval.set_col(328, unpacked_limb_7_col328);
    let unpacked_limb_9_col329 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 9);
    eval.set_col(329, unpacked_limb_9_col329);
    let unpacked_limb_10_col330 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 10);
    eval.set_col(330, unpacked_limb_10_col330);
    let unpacked_limb_12_col331 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 12);
    eval.set_col(331, unpacked_limb_12_col331);
    let unpacked_limb_13_col332 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 13);
    eval.set_col(332, unpacked_limb_13_col332);
    let unpacked_limb_15_col333 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 15);
    eval.set_col(333, unpacked_limb_15_col333);
    let unpacked_limb_16_col334 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 16);
    eval.set_col(334, unpacked_limb_16_col334);
    let unpacked_limb_18_col335 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 18);
    eval.set_col(335, unpacked_limb_18_col335);
    let unpacked_limb_19_col336 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 19);
    eval.set_col(336, unpacked_limb_19_col336);
    let unpacked_limb_21_col337 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 21);
    eval.set_col(337, unpacked_limb_21_col337);
    let unpacked_limb_22_col338 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 22);
    eval.set_col(338, unpacked_limb_22_col338);
    let unpacked_limb_24_col339 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 24);
    eval.set_col(339, unpacked_limb_24_col339);
    let unpacked_limb_25_col340 = eval.felt_get_m31(&input_as_felt252_tmp_3806f_165.clone(), 25);
    eval.set_col(340, unpacked_limb_25_col340);
    let wg_v2730 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_20_col277,
        unpacked_limb_0_col323,
    );
    let wg_v2731 = eval.m31_mul(unpacked_limb_1_col324, m31_512);
    let wg_v2732 = eval.m31_sub(wg_v2730, wg_v2731);
    let wg_v2733 = eval.m31_mul(wg_v2732, m31_8192);
    let wg_v2734 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_21_col278,
        unpacked_limb_3_col325,
    );
    let wg_v2735 = eval.m31_mul(unpacked_limb_4_col326, m31_512);
    let wg_v2736 = eval.m31_sub(wg_v2734, wg_v2735);
    let wg_v2737 = eval.m31_mul(wg_v2736, m31_8192);
    let wg_v2738 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_22_col279,
        unpacked_limb_6_col327,
    );
    let wg_v2739 = eval.m31_mul(unpacked_limb_7_col328, m31_512);
    let wg_v2740 = eval.m31_sub(wg_v2738, wg_v2739);
    let wg_v2741 = eval.m31_mul(wg_v2740, m31_8192);
    let wg_v2742 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_23_col280,
        unpacked_limb_9_col329,
    );
    let wg_v2743 = eval.m31_mul(unpacked_limb_10_col330, m31_512);
    let wg_v2744 = eval.m31_sub(wg_v2742, wg_v2743);
    let wg_v2745 = eval.m31_mul(wg_v2744, m31_8192);
    let wg_v2746 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_24_col281,
        unpacked_limb_12_col331,
    );
    let wg_v2747 = eval.m31_mul(unpacked_limb_13_col332, m31_512);
    let wg_v2748 = eval.m31_sub(wg_v2746, wg_v2747);
    let wg_v2749 = eval.m31_mul(wg_v2748, m31_8192);
    let wg_v2750 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_25_col282,
        unpacked_limb_15_col333,
    );
    let wg_v2751 = eval.m31_mul(unpacked_limb_16_col334, m31_512);
    let wg_v2752 = eval.m31_sub(wg_v2750, wg_v2751);
    let wg_v2753 = eval.m31_mul(wg_v2752, m31_8192);
    let wg_v2754 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_26_col283,
        unpacked_limb_18_col335,
    );
    let wg_v2755 = eval.m31_mul(unpacked_limb_19_col336, m31_512);
    let wg_v2756 = eval.m31_sub(wg_v2754, wg_v2755);
    let wg_v2757 = eval.m31_mul(wg_v2756, m31_8192);
    let wg_v2758 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_27_col284,
        unpacked_limb_21_col337,
    );
    let wg_v2759 = eval.m31_mul(unpacked_limb_22_col338, m31_512);
    let wg_v2760 = eval.m31_sub(wg_v2758, wg_v2759);
    let wg_v2761 = eval.m31_mul(wg_v2760, m31_8192);
    let wg_v2762 = eval.m31_sub(
        poseidon_full_round_chain_output_limb_28_col285,
        unpacked_limb_24_col339,
    );
    let wg_v2763 = eval.m31_mul(unpacked_limb_25_col340, m31_512);
    let wg_v2764 = eval.m31_sub(wg_v2762, wg_v2763);
    let wg_v2765 = eval.m31_mul(wg_v2764, m31_8192);
    let felt_252_unpack_from_27_output_tmp_3806f_166 = eval.felt_from_limbs([
        unpacked_limb_0_col323,
        unpacked_limb_1_col324,
        wg_v2733,
        unpacked_limb_3_col325,
        unpacked_limb_4_col326,
        wg_v2737,
        unpacked_limb_6_col327,
        unpacked_limb_7_col328,
        wg_v2741,
        unpacked_limb_9_col329,
        unpacked_limb_10_col330,
        wg_v2745,
        unpacked_limb_12_col331,
        unpacked_limb_13_col332,
        wg_v2749,
        unpacked_limb_15_col333,
        unpacked_limb_16_col334,
        wg_v2753,
        unpacked_limb_18_col335,
        unpacked_limb_19_col336,
        wg_v2757,
        unpacked_limb_21_col337,
        unpacked_limb_22_col338,
        wg_v2761,
        unpacked_limb_24_col339,
        unpacked_limb_25_col340,
        wg_v2765,
        poseidon_full_round_chain_output_limb_29_col286,
    ]);
    eval.set_sub_input_word(5, input_limb_5_col5);
    eval.set_lookup_word(483, m31_1662111297);
    eval.set_lookup_word(484, input_limb_5_col5);
    eval.set_lookup_word(485, unpacked_limb_0_col323);
    eval.set_lookup_word(486, unpacked_limb_1_col324);
    let wg_v2766 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 2);
    eval.set_lookup_word(487, wg_v2766);
    eval.set_lookup_word(488, unpacked_limb_3_col325);
    eval.set_lookup_word(489, unpacked_limb_4_col326);
    let wg_v2767 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 5);
    eval.set_lookup_word(490, wg_v2767);
    eval.set_lookup_word(491, unpacked_limb_6_col327);
    eval.set_lookup_word(492, unpacked_limb_7_col328);
    let wg_v2768 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 8);
    eval.set_lookup_word(493, wg_v2768);
    eval.set_lookup_word(494, unpacked_limb_9_col329);
    eval.set_lookup_word(495, unpacked_limb_10_col330);
    let wg_v2769 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 11);
    eval.set_lookup_word(496, wg_v2769);
    eval.set_lookup_word(497, unpacked_limb_12_col331);
    eval.set_lookup_word(498, unpacked_limb_13_col332);
    let wg_v2770 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 14);
    eval.set_lookup_word(499, wg_v2770);
    eval.set_lookup_word(500, unpacked_limb_15_col333);
    eval.set_lookup_word(501, unpacked_limb_16_col334);
    let wg_v2771 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 17);
    eval.set_lookup_word(502, wg_v2771);
    eval.set_lookup_word(503, unpacked_limb_18_col335);
    eval.set_lookup_word(504, unpacked_limb_19_col336);
    let wg_v2772 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 20);
    eval.set_lookup_word(505, wg_v2772);
    eval.set_lookup_word(506, unpacked_limb_21_col337);
    eval.set_lookup_word(507, unpacked_limb_22_col338);
    let wg_v2773 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 23);
    eval.set_lookup_word(508, wg_v2773);
    eval.set_lookup_word(509, unpacked_limb_24_col339);
    eval.set_lookup_word(510, unpacked_limb_25_col340);
    let wg_v2774 = eval.felt_get_m31(&felt_252_unpack_from_27_output_tmp_3806f_166.clone(), 26);
    eval.set_lookup_word(511, wg_v2774);
    eval.set_lookup_word(512, poseidon_full_round_chain_output_limb_29_col286);
    let multiplicity_0_col341 = eval.input(8);
    eval.set_col(341, multiplicity_0_col341);
    eval.set_lookup_word(513, m31_1551892206);
    eval.set_lookup_word(514, input_limb_0_col0);
    eval.set_lookup_word(515, input_limb_1_col1);
    eval.set_lookup_word(516, input_limb_2_col2);
    eval.set_lookup_word(517, input_limb_3_col3);
    eval.set_lookup_word(518, input_limb_4_col4);
    eval.set_lookup_word(519, input_limb_5_col5);
    eval.set_lookup_word(520, m31_1);
    eval.set_lookup_word(521, multiplicity_0_col341);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `poseidon_aggregator_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    inputs: Vec<PackedInputType>,
    mults: Vec<Vec<PackedM31>>,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    poseidon_full_round_chain_state: &poseidon_full_round_chain::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    poseidon_3_partial_rounds_chain_state: &poseidon_3_partial_rounds_chain::ClaimGenerator,
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
    let Felt252_0_0_0_0 = PackedFelt252::broadcast(Felt252::from([0, 0, 0, 0]));
    let Felt252_1_0_0_0 = PackedFelt252::broadcast(Felt252::from([1, 0, 0, 0]));
    let Felt252_10310704347937391837_5874215448258336115_2880320859071049537_45350836576946303 =
        PackedFelt252::broadcast(Felt252::from([
            10310704347937391837,
            5874215448258336115,
            2880320859071049537,
            45350836576946303,
        ]));
    let Felt252_10931822301410252833_1475756362763989377_3378552166684303673_348229636055909092 =
        PackedFelt252::broadcast(Felt252::from([
            10931822301410252833,
            1475756362763989377,
            3378552166684303673,
            348229636055909092,
        ]));
    let Felt252_11041071929982523380_7503192613203831446_4943121247101232560_560497091765764140 =
        PackedFelt252::broadcast(Felt252::from([
            11041071929982523380,
            7503192613203831446,
            4943121247101232560,
            560497091765764140,
        ]));
    let Felt252_16477292399064058052_4441744911417641572_18431044672185975386_252894828082060025 =
        PackedFelt252::broadcast(Felt252::from([
            16477292399064058052,
            4441744911417641572,
            18431044672185975386,
            252894828082060025,
        ]));
    let Felt252_2_0_0_0 = PackedFelt252::broadcast(Felt252::from([2, 0, 0, 0]));
    let Felt252_3969818800901670911_10562874008078701503_14906396266795319764_223312371439046257 =
        PackedFelt252::broadcast(Felt252::from([
            3969818800901670911,
            10562874008078701503,
            14906396266795319764,
            223312371439046257,
        ]));
    let Felt252_4_0_0_0 = PackedFelt252::broadcast(Felt252::from([4, 0, 0, 0]));
    let Felt252_8794894655201903369_3219077422080798056_16714934791572408267_262217499501479120 =
        PackedFelt252::broadcast(Felt252::from([
            8794894655201903369,
            3219077422080798056,
            16714934791572408267,
            262217499501479120,
        ]));
    let Felt252_9275160746813554287_16541205595039575623_4169650429605064889_470088886057789987 =
        PackedFelt252::broadcast(Felt252::from([
            9275160746813554287,
            16541205595039575623,
            4169650429605064889,
            470088886057789987,
        ]));
    let seq = Seq::new(log_size);
    let enabler_col = Enabler::new(0);
    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, poseidon_aggregator_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    memory_id_to_big_state,
                    vec![
                        poseidon_aggregator_input.0[0].into_simd(),
                        poseidon_aggregator_input.0[1].into_simd(),
                        poseidon_aggregator_input.0[2].into_simd(),
                        poseidon_aggregator_input.1[0].into_simd(),
                        poseidon_aggregator_input.1[1].into_simd(),
                        poseidon_aggregator_input.1[2].into_simd(),
                        Simd::splat(0),
                        Simd::splat(0),
                        mults[0]
                            .get(row_index)
                            .copied()
                            .unwrap_or(PackedM31::zero())
                            .into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                poseidon_aggregator_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.memory_id_to_big_0 = [
                    lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10],
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29],
                ];
                *lookup_data.memory_id_to_big_1 = [
                    lw[30], lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39],
                    lw[40], lw[41], lw[42], lw[43], lw[44], lw[45], lw[46], lw[47], lw[48], lw[49],
                    lw[50], lw[51], lw[52], lw[53], lw[54], lw[55], lw[56], lw[57], lw[58], lw[59],
                ];
                *lookup_data.memory_id_to_big_2 = [
                    lw[60], lw[61], lw[62], lw[63], lw[64], lw[65], lw[66], lw[67], lw[68], lw[69],
                    lw[70], lw[71], lw[72], lw[73], lw[74], lw[75], lw[76], lw[77], lw[78], lw[79],
                    lw[80], lw[81], lw[82], lw[83], lw[84], lw[85], lw[86], lw[87], lw[88], lw[89],
                ];
                *lookup_data.poseidon_full_round_chain_3 = [
                    lw[90], lw[91], lw[92], lw[93], lw[94], lw[95], lw[96], lw[97], lw[98], lw[99],
                    lw[100], lw[101], lw[102], lw[103], lw[104], lw[105], lw[106], lw[107],
                    lw[108], lw[109], lw[110], lw[111], lw[112], lw[113], lw[114], lw[115],
                    lw[116], lw[117], lw[118], lw[119], lw[120], lw[121], lw[122],
                ];
                *lookup_data.poseidon_full_round_chain_4 = [
                    lw[123], lw[124], lw[125], lw[126], lw[127], lw[128], lw[129], lw[130],
                    lw[131], lw[132], lw[133], lw[134], lw[135], lw[136], lw[137], lw[138],
                    lw[139], lw[140], lw[141], lw[142], lw[143], lw[144], lw[145], lw[146],
                    lw[147], lw[148], lw[149], lw[150], lw[151], lw[152], lw[153], lw[154],
                    lw[155],
                ];
                *lookup_data.range_check_252_width_27_5 = [
                    lw[156], lw[157], lw[158], lw[159], lw[160], lw[161], lw[162], lw[163],
                    lw[164], lw[165], lw[166],
                ];
                *lookup_data.range_check_252_width_27_6 = [
                    lw[167], lw[168], lw[169], lw[170], lw[171], lw[172], lw[173], lw[174],
                    lw[175], lw[176], lw[177],
                ];
                *lookup_data.cube_252_7 = [
                    lw[178], lw[179], lw[180], lw[181], lw[182], lw[183], lw[184], lw[185],
                    lw[186], lw[187], lw[188], lw[189], lw[190], lw[191], lw[192], lw[193],
                    lw[194], lw[195], lw[196], lw[197], lw[198],
                ];
                *lookup_data.range_check_3_3_3_3_3_8 =
                    [lw[199], lw[200], lw[201], lw[202], lw[203], lw[204]];
                *lookup_data.range_check_3_3_3_3_3_9 =
                    [lw[205], lw[206], lw[207], lw[208], lw[209], lw[210]];
                *lookup_data.cube_252_10 = [
                    lw[211], lw[212], lw[213], lw[214], lw[215], lw[216], lw[217], lw[218],
                    lw[219], lw[220], lw[221], lw[222], lw[223], lw[224], lw[225], lw[226],
                    lw[227], lw[228], lw[229], lw[230], lw[231],
                ];
                *lookup_data.range_check_4_4_4_4_11 = [lw[232], lw[233], lw[234], lw[235], lw[236]];
                *lookup_data.range_check_4_4_4_4_12 = [lw[237], lw[238], lw[239], lw[240], lw[241]];
                *lookup_data.range_check_4_4_13 = [lw[242], lw[243], lw[244]];
                *lookup_data.poseidon_3_partial_rounds_chain_14 = [
                    lw[245], lw[246], lw[247], lw[248], lw[249], lw[250], lw[251], lw[252],
                    lw[253], lw[254], lw[255], lw[256], lw[257], lw[258], lw[259], lw[260],
                    lw[261], lw[262], lw[263], lw[264], lw[265], lw[266], lw[267], lw[268],
                    lw[269], lw[270], lw[271], lw[272], lw[273], lw[274], lw[275], lw[276],
                    lw[277], lw[278], lw[279], lw[280], lw[281], lw[282], lw[283], lw[284],
                    lw[285], lw[286], lw[287],
                ];
                *lookup_data.poseidon_3_partial_rounds_chain_15 = [
                    lw[288], lw[289], lw[290], lw[291], lw[292], lw[293], lw[294], lw[295],
                    lw[296], lw[297], lw[298], lw[299], lw[300], lw[301], lw[302], lw[303],
                    lw[304], lw[305], lw[306], lw[307], lw[308], lw[309], lw[310], lw[311],
                    lw[312], lw[313], lw[314], lw[315], lw[316], lw[317], lw[318], lw[319],
                    lw[320], lw[321], lw[322], lw[323], lw[324], lw[325], lw[326], lw[327],
                    lw[328], lw[329], lw[330],
                ];
                *lookup_data.range_check_4_4_4_4_16 = [lw[331], lw[332], lw[333], lw[334], lw[335]];
                *lookup_data.range_check_4_4_4_4_17 = [lw[336], lw[337], lw[338], lw[339], lw[340]];
                *lookup_data.range_check_4_4_18 = [lw[341], lw[342], lw[343]];
                *lookup_data.range_check_4_4_4_4_19 = [lw[344], lw[345], lw[346], lw[347], lw[348]];
                *lookup_data.range_check_4_4_4_4_20 = [lw[349], lw[350], lw[351], lw[352], lw[353]];
                *lookup_data.range_check_4_4_21 = [lw[354], lw[355], lw[356]];
                *lookup_data.poseidon_full_round_chain_22 = [
                    lw[357], lw[358], lw[359], lw[360], lw[361], lw[362], lw[363], lw[364],
                    lw[365], lw[366], lw[367], lw[368], lw[369], lw[370], lw[371], lw[372],
                    lw[373], lw[374], lw[375], lw[376], lw[377], lw[378], lw[379], lw[380],
                    lw[381], lw[382], lw[383], lw[384], lw[385], lw[386], lw[387], lw[388],
                    lw[389],
                ];
                *lookup_data.poseidon_full_round_chain_23 = [
                    lw[390], lw[391], lw[392], lw[393], lw[394], lw[395], lw[396], lw[397],
                    lw[398], lw[399], lw[400], lw[401], lw[402], lw[403], lw[404], lw[405],
                    lw[406], lw[407], lw[408], lw[409], lw[410], lw[411], lw[412], lw[413],
                    lw[414], lw[415], lw[416], lw[417], lw[418], lw[419], lw[420], lw[421],
                    lw[422],
                ];
                *lookup_data.memory_id_to_big_24 = [
                    lw[423], lw[424], lw[425], lw[426], lw[427], lw[428], lw[429], lw[430],
                    lw[431], lw[432], lw[433], lw[434], lw[435], lw[436], lw[437], lw[438],
                    lw[439], lw[440], lw[441], lw[442], lw[443], lw[444], lw[445], lw[446],
                    lw[447], lw[448], lw[449], lw[450], lw[451], lw[452],
                ];
                *lookup_data.memory_id_to_big_25 = [
                    lw[453], lw[454], lw[455], lw[456], lw[457], lw[458], lw[459], lw[460],
                    lw[461], lw[462], lw[463], lw[464], lw[465], lw[466], lw[467], lw[468],
                    lw[469], lw[470], lw[471], lw[472], lw[473], lw[474], lw[475], lw[476],
                    lw[477], lw[478], lw[479], lw[480], lw[481], lw[482],
                ];
                *lookup_data.memory_id_to_big_26 = [
                    lw[483], lw[484], lw[485], lw[486], lw[487], lw[488], lw[489], lw[490],
                    lw[491], lw[492], lw[493], lw[494], lw[495], lw[496], lw[497], lw[498],
                    lw[499], lw[500], lw[501], lw[502], lw[503], lw[504], lw[505], lw[506],
                    lw[507], lw[508], lw[509], lw[510], lw[511], lw[512],
                ];
                *lookup_data.poseidon_aggregator_27 = [
                    lw[513], lw[514], lw[515], lw[516], lw[517], lw[518], lw[519],
                ];
                *lookup_data.mults_0 = lw[520];
                *lookup_data.mults_1 = lw[521];
                let sw = eval.sub_scratch();
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[0]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) };
                *sub_component_inputs.memory_id_to_big[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) };
                *sub_component_inputs.memory_id_to_big[3] =
                    unsafe { PackedM31::from_simd_unchecked(sw[3]) };
                *sub_component_inputs.memory_id_to_big[4] =
                    unsafe { PackedM31::from_simd_unchecked(sw[4]) };
                *sub_component_inputs.memory_id_to_big[5] =
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) };
                *sub_component_inputs.poseidon_full_round_chain[0] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[12]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[15]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[18]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[21]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[23]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[24]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[25]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[26]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[27]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[28]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[29]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[30]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[31]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[32]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[33]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[34]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[35]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[36]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[37]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[1] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[38]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[39]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[40]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[41]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[42]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[43]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[44]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[45]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[46]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[48]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[49]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[50]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[51]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[52]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[53]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[54]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[55]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[56]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[57]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[58]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[59]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[60]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[61]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[62]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[63]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[64]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[65]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[66]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[67]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[68]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[69]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[2] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[70]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[71]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[72]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[73]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[74]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[75]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[76]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[77]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[78]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[79]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[80]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[81]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[82]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[83]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[84]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[85]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[86]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[87]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[88]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[89]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[90]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[91]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[92]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[93]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[94]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[95]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[96]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[97]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[98]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[99]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[100]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[101]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[3] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[102]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[103]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[104]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[105]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[106]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[107]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[108]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[109]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[110]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[111]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[112]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[113]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[114]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[115]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[116]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[117]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[118]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[119]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[120]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[121]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[122]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[123]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[124]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[125]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[126]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[127]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[128]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[129]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[130]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[131]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[132]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[133]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[4] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[134]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[135]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[136]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[137]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[138]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[139]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[140]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[141]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[142]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[143]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[144]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[145]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[146]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[147]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[148]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[149]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[150]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[151]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[152]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[153]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[154]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[155]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[156]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[157]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[158]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[159]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[160]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[161]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[162]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[163]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[164]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[165]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[5] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[166]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[167]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[168]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[169]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[170]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[171]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[172]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[173]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[174]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[175]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[176]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[177]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[178]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[179]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[180]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[181]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[182]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[183]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[184]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[185]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[186]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[187]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[188]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[189]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[190]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[191]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[192]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[193]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[194]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[195]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[196]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[197]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[6] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[198]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[199]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[200]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[201]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[202]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[203]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[204]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[205]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[206]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[207]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[208]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[209]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[210]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[211]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[212]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[213]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[214]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[215]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[216]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[217]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[218]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[219]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[220]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[221]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[222]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[223]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[224]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[225]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[226]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[227]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[228]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[229]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_full_round_chain[7] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[230]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[231]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[232]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[233]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[234]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[235]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[236]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[237]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[238]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[239]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[240]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[241]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[242]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[243]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[244]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[245]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[246]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[247]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[248]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[249]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[250]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[251]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[252]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[253]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[254]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[255]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[256]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[257]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[258]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[259]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[260]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[261]) },
                        ]),
                    ],
                );
                *sub_component_inputs.range_check_252_width_27[0] =
                    PackedFelt252Width27::from_limbs([
                        unsafe { PackedM31::from_simd_unchecked(sw[262]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[263]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[264]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[265]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[266]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[267]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[268]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[269]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[270]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[271]) },
                    ]);
                *sub_component_inputs.range_check_252_width_27[1] =
                    PackedFelt252Width27::from_limbs([
                        unsafe { PackedM31::from_simd_unchecked(sw[272]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[273]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[274]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[275]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[276]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[277]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[278]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[279]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[280]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[281]) },
                    ]);
                *sub_component_inputs.cube_252[0] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[282]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[283]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[284]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[285]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[286]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[287]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[288]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[289]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[290]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[291]) },
                ]);
                *sub_component_inputs.cube_252[1] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[292]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[293]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[294]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[295]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[296]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[297]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[298]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[299]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[300]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[301]) },
                ]);
                *sub_component_inputs.range_check_3_3_3_3_3[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[302]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[303]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[304]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[305]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[306]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[307]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[308]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[309]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[310]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[311]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[312]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[313]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[314]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[315]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[316]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[317]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[318]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[319]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[320]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[321]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[322]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[323]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[324]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[325]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[326]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[327]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[4] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[328]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[329]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[330]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[331]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[5] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[332]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[333]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[334]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[335]) },
                ];
                *sub_component_inputs.range_check_4_4[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[336]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[337])
                    }];
                *sub_component_inputs.range_check_4_4[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[338]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[339])
                    }];
                *sub_component_inputs.range_check_4_4[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[340]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[341])
                    }];
                *sub_component_inputs.poseidon_3_partial_rounds_chain[0] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[342]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[343]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[344]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[345]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[346]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[347]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[348]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[349]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[350]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[351]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[352]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[353]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[354]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[355]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[356]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[357]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[358]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[359]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[360]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[361]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[362]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[363]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[364]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[365]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[366]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[367]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[368]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[369]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[370]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[371]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[372]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[373]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[374]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[375]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[376]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[377]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[378]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[379]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[380]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[381]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[382]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[383]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[1] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[384]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[385]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[386]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[387]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[388]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[389]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[390]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[391]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[392]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[393]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[394]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[395]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[396]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[397]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[398]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[399]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[400]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[401]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[402]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[403]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[404]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[405]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[406]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[407]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[408]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[409]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[410]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[411]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[412]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[413]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[414]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[415]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[416]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[417]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[418]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[419]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[420]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[421]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[422]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[423]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[424]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[425]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[2] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[426]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[427]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[428]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[429]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[430]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[431]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[432]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[433]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[434]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[435]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[436]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[437]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[438]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[439]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[440]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[441]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[442]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[443]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[444]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[445]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[446]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[447]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[448]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[449]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[450]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[451]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[452]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[453]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[454]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[455]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[456]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[457]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[458]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[459]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[460]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[461]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[462]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[463]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[464]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[465]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[466]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[467]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[3] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[468]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[469]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[470]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[471]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[472]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[473]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[474]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[475]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[476]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[477]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[478]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[479]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[480]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[481]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[482]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[483]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[484]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[485]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[486]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[487]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[488]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[489]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[490]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[491]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[492]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[493]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[494]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[495]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[496]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[497]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[498]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[499]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[500]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[501]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[502]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[503]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[504]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[505]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[506]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[507]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[508]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[509]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[4] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[510]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[511]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[512]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[513]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[514]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[515]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[516]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[517]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[518]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[519]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[520]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[521]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[522]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[523]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[524]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[525]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[526]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[527]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[528]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[529]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[530]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[531]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[532]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[533]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[534]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[535]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[536]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[537]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[538]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[539]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[540]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[541]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[542]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[543]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[544]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[545]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[546]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[547]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[548]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[549]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[550]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[551]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[5] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[552]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[553]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[554]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[555]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[556]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[557]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[558]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[559]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[560]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[561]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[562]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[563]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[564]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[565]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[566]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[567]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[568]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[569]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[570]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[571]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[572]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[573]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[574]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[575]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[576]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[577]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[578]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[579]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[580]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[581]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[582]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[583]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[584]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[585]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[586]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[587]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[588]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[589]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[590]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[591]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[592]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[593]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[6] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[594]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[595]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[596]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[597]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[598]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[599]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[600]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[601]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[602]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[603]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[604]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[605]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[606]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[607]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[608]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[609]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[610]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[611]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[612]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[613]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[614]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[615]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[616]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[617]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[618]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[619]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[620]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[621]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[622]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[623]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[624]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[625]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[626]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[627]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[628]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[629]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[630]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[631]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[632]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[633]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[634]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[635]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[7] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[636]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[637]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[638]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[639]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[640]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[641]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[642]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[643]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[644]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[645]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[646]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[647]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[648]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[649]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[650]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[651]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[652]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[653]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[654]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[655]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[656]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[657]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[658]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[659]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[660]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[661]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[662]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[663]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[664]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[665]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[666]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[667]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[668]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[669]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[670]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[671]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[672]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[673]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[674]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[675]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[676]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[677]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[8] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[678]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[679]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[680]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[681]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[682]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[683]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[684]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[685]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[686]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[687]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[688]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[689]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[690]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[691]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[692]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[693]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[694]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[695]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[696]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[697]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[698]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[699]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[700]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[701]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[702]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[703]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[704]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[705]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[706]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[707]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[708]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[709]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[710]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[711]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[712]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[713]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[714]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[715]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[716]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[717]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[718]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[719]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[9] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[720]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[721]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[722]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[723]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[724]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[725]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[726]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[727]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[728]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[729]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[730]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[731]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[732]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[733]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[734]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[735]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[736]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[737]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[738]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[739]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[740]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[741]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[742]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[743]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[744]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[745]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[746]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[747]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[748]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[749]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[750]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[751]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[752]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[753]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[754]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[755]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[756]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[757]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[758]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[759]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[760]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[761]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[10] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[762]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[763]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[764]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[765]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[766]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[767]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[768]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[769]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[770]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[771]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[772]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[773]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[774]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[775]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[776]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[777]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[778]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[779]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[780]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[781]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[782]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[783]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[784]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[785]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[786]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[787]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[788]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[789]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[790]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[791]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[792]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[793]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[794]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[795]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[796]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[797]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[798]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[799]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[800]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[801]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[802]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[803]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[11] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[804]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[805]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[806]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[807]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[808]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[809]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[810]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[811]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[812]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[813]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[814]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[815]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[816]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[817]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[818]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[819]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[820]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[821]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[822]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[823]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[824]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[825]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[826]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[827]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[828]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[829]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[830]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[831]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[832]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[833]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[834]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[835]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[836]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[837]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[838]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[839]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[840]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[841]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[842]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[843]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[844]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[845]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[12] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[846]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[847]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[848]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[849]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[850]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[851]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[852]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[853]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[854]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[855]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[856]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[857]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[858]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[859]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[860]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[861]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[862]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[863]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[864]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[865]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[866]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[867]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[868]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[869]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[870]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[871]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[872]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[873]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[874]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[875]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[876]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[877]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[878]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[879]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[880]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[881]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[882]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[883]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[884]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[885]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[886]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[887]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[13] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[888]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[889]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[890]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[891]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[892]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[893]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[894]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[895]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[896]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[897]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[898]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[899]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[900]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[901]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[902]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[903]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[904]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[905]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[906]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[907]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[908]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[909]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[910]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[911]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[912]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[913]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[914]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[915]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[916]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[917]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[918]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[919]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[920]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[921]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[922]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[923]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[924]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[925]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[926]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[927]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[928]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[929]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[14] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[930]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[931]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[932]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[933]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[934]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[935]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[936]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[937]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[938]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[939]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[940]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[941]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[942]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[943]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[944]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[945]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[946]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[947]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[948]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[949]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[950]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[951]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[952]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[953]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[954]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[955]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[956]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[957]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[958]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[959]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[960]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[961]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[962]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[963]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[964]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[965]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[966]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[967]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[968]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[969]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[970]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[971]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[15] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[972]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[973]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[974]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[975]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[976]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[977]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[978]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[979]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[980]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[981]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[982]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[983]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[984]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[985]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[986]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[987]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[988]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[989]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[990]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[991]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[992]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[993]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[994]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[995]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[996]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[997]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[998]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[999]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1000]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1001]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1002]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1003]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1004]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1005]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1006]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1007]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1008]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1009]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1010]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1011]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1012]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1013]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[16] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1014]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1015]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1016]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1017]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1018]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1019]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1020]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1021]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1022]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1023]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1024]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1025]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1026]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1027]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1028]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1029]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1030]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1031]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1032]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1033]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1034]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1035]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1036]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1037]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1038]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1039]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1040]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1041]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1042]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1043]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1044]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1045]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1046]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1047]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1048]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1049]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1050]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1051]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1052]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1053]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1054]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1055]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[17] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1056]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1057]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1058]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1059]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1060]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1061]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1062]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1063]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1064]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1065]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1066]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1067]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1068]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1069]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1070]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1071]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1072]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1073]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1074]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1075]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1076]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1077]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1078]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1079]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1080]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1081]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1082]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1083]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1084]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1085]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1086]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1087]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1088]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1089]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1090]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1091]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1092]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1093]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1094]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1095]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1096]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1097]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[18] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1098]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1099]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1100]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1101]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1102]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1103]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1104]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1105]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1106]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1107]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1108]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1109]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1110]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1111]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1112]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1113]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1114]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1115]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1116]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1117]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1118]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1119]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1120]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1121]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1122]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1123]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1124]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1125]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1126]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1127]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1128]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1129]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1130]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1131]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1132]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1133]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1134]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1135]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1136]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1137]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1138]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1139]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[19] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1140]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1141]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1142]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1143]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1144]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1145]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1146]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1147]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1148]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1149]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1150]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1151]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1152]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1153]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1154]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1155]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1156]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1157]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1158]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1159]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1160]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1161]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1162]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1163]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1164]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1165]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1166]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1167]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1168]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1169]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1170]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1171]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1172]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1173]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1174]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1175]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1176]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1177]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1178]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1179]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1180]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1181]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[20] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1182]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1183]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1184]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1185]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1186]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1187]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1188]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1189]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1190]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1191]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1192]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1193]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1194]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1195]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1196]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1197]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1198]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1199]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1200]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1201]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1202]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1203]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1204]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1205]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1206]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1207]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1208]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1209]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1210]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1211]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1212]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1213]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1214]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1215]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1216]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1217]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1218]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1219]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1220]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1221]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1222]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1223]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[21] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1224]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1225]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1226]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1227]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1228]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1229]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1230]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1231]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1232]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1233]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1234]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1235]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1236]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1237]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1238]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1239]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1240]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1241]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1242]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1243]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1244]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1245]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1246]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1247]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1248]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1249]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1250]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1251]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1252]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1253]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1254]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1255]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1256]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1257]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1258]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1259]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1260]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1261]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1262]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1263]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1264]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1265]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[22] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1266]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1267]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1268]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1269]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1270]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1271]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1272]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1273]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1274]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1275]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1276]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1277]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1278]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1279]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1280]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1281]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1282]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1283]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1284]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1285]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1286]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1287]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1288]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1289]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1290]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1291]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1292]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1293]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1294]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1295]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1296]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1297]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1298]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1299]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1300]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1301]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1302]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1303]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1304]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1305]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1306]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1307]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[23] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1308]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1309]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1310]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1311]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1312]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1313]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1314]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1315]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1316]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1317]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1318]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1319]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1320]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1321]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1322]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1323]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1324]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1325]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1326]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1327]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1328]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1329]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1330]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1331]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1332]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1333]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1334]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1335]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1336]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1337]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1338]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1339]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1340]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1341]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1342]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1343]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1344]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1345]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1346]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1347]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1348]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1349]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[24] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1350]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1351]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1352]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1353]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1354]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1355]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1356]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1357]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1358]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1359]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1360]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1361]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1362]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1363]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1364]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1365]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1366]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1367]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1368]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1369]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1370]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1371]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1372]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1373]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1374]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1375]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1376]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1377]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1378]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1379]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1380]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1381]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1382]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1383]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1384]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1385]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1386]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1387]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1388]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1389]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1390]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1391]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[25] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1392]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1393]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1394]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1395]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1396]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1397]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1398]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1399]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1400]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1401]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1402]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1403]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1404]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1405]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1406]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1407]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1408]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1409]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1410]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1411]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1412]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1413]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1414]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1415]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1416]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1417]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1418]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1419]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1420]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1421]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1422]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1423]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1424]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1425]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1426]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1427]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1428]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1429]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1430]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1431]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1432]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1433]) },
                        ]),
                    ],
                );
                *sub_component_inputs.poseidon_3_partial_rounds_chain[26] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[1434]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1435]) },
                    [
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1436]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1437]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1438]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1439]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1440]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1441]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1442]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1443]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1444]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1445]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1446]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1447]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1448]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1449]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1450]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1451]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1452]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1453]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1454]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1455]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1456]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1457]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1458]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1459]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1460]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1461]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1462]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1463]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1464]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1465]) },
                        ]),
                        PackedFelt252Width27::from_limbs([
                            unsafe { PackedM31::from_simd_unchecked(sw[1466]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1467]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1468]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1469]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1470]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1471]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1472]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1473]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1474]) },
                            unsafe { PackedM31::from_simd_unchecked(sw[1475]) },
                        ]),
                    ],
                );
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
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        poseidon_full_round_chain_state: &poseidon_full_round_chain::ClaimGenerator,
        range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
        cube_252_state: &cube_252::ClaimGenerator,
        range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
        range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
        range_check_4_4_state: &range_check_4_4::ClaimGenerator,
        poseidon_3_partial_rounds_chain_state: &poseidon_3_partial_rounds_chain::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut inputs_mults = self
            .mults
            .iter()
            .map(|entry| (*entry.key(), M31(entry.value().load(Ordering::Relaxed))))
            .collect::<Vec<_>>();
        inputs_mults.sort_by_key(|(input, _)| input.0);
        let (mut inputs, mut mults) = inputs_mults.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
        let n_rows = inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();
        inputs.resize(size, *inputs.first().unwrap());
        mults.resize(size, M31::zero());
        let packed_inputs = pack_values(&inputs);
        let packed_mults = pack_values(&mults);
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            packed_inputs,
            vec![packed_mults],
            memory_id_to_big_state,
            poseidon_full_round_chain_state,
            range_check_252_width_27_state,
            cube_252_state,
            range_check_3_3_3_3_3_state,
            range_check_4_4_4_4_state,
            range_check_4_4_state,
            poseidon_3_partial_rounds_chain_state,
        );
        for inputs in sub_component_inputs.memory_id_to_big {
            add_inputs(memory_id_to_big_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_full_round_chain {
            add_inputs(
                poseidon_full_round_chain_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_252_width_27 {
            add_inputs(
                range_check_252_width_27_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_3_3_3_3_3 {
            add_inputs(
                range_check_3_3_3_3_3_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4_4_4 {
            add_inputs(
                range_check_4_4_4_4_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4 {
            add_inputs(range_check_4_4_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_3_partial_rounds_chain {
            add_inputs(
                poseidon_3_partial_rounds_chain_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                log_size,
                lookup_data,
            },
        )
    }
}

/// Record the `poseidon_aggregator` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_poseidon_aggregator() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("poseidon_aggregator", 6, Some(7));
    poseidon_aggregator_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    522;
    memory_id_to_big_0: 30,
    memory_id_to_big_1: 30,
    memory_id_to_big_2: 30,
    poseidon_full_round_chain_3: 33,
    poseidon_full_round_chain_4: 33,
    range_check_252_width_27_5: 11,
    range_check_252_width_27_6: 11,
    cube_252_7: 21,
    range_check_3_3_3_3_3_8: 6,
    range_check_3_3_3_3_3_9: 6,
    cube_252_10: 21,
    range_check_4_4_4_4_11: 5,
    range_check_4_4_4_4_12: 5,
    range_check_4_4_13: 3,
    poseidon_3_partial_rounds_chain_14: 43,
    poseidon_3_partial_rounds_chain_15: 43,
    range_check_4_4_4_4_16: 5,
    range_check_4_4_4_4_17: 5,
    range_check_4_4_18: 3,
    range_check_4_4_4_4_19: 5,
    range_check_4_4_4_4_20: 5,
    range_check_4_4_21: 3,
    poseidon_full_round_chain_22: 33,
    poseidon_full_round_chain_23: 33,
    memory_id_to_big_24: 30,
    memory_id_to_big_25: 30,
    memory_id_to_big_26: 30,
    poseidon_aggregator_27: 7,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 0, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 1, 1),
    ("memory_id_to_big", 2, "memory_id_to_big_state", 0, 2, 1),
    ("memory_id_to_big", 3, "memory_id_to_big_state", 0, 3, 1),
    ("memory_id_to_big", 4, "memory_id_to_big_state", 0, 4, 1),
    ("memory_id_to_big", 5, "memory_id_to_big_state", 0, 5, 1),
    (
        "poseidon_full_round_chain",
        0,
        "poseidon_full_round_chain_state",
        0,
        6,
        32,
    ),
    (
        "poseidon_full_round_chain",
        1,
        "poseidon_full_round_chain_state",
        0,
        38,
        32,
    ),
    (
        "poseidon_full_round_chain",
        2,
        "poseidon_full_round_chain_state",
        0,
        70,
        32,
    ),
    (
        "poseidon_full_round_chain",
        3,
        "poseidon_full_round_chain_state",
        0,
        102,
        32,
    ),
    (
        "poseidon_full_round_chain",
        4,
        "poseidon_full_round_chain_state",
        0,
        134,
        32,
    ),
    (
        "poseidon_full_round_chain",
        5,
        "poseidon_full_round_chain_state",
        0,
        166,
        32,
    ),
    (
        "poseidon_full_round_chain",
        6,
        "poseidon_full_round_chain_state",
        0,
        198,
        32,
    ),
    (
        "poseidon_full_round_chain",
        7,
        "poseidon_full_round_chain_state",
        0,
        230,
        32,
    ),
    (
        "range_check_252_width_27",
        0,
        "range_check_252_width_27_state",
        0,
        262,
        10,
    ),
    (
        "range_check_252_width_27",
        1,
        "range_check_252_width_27_state",
        0,
        272,
        10,
    ),
    ("cube_252", 0, "cube_252_state", 0, 282, 10),
    ("cube_252", 1, "cube_252_state", 0, 292, 10),
    (
        "range_check_3_3_3_3_3",
        0,
        "range_check_3_3_3_3_3_state",
        0,
        302,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        1,
        "range_check_3_3_3_3_3_state",
        0,
        307,
        5,
    ),
    (
        "range_check_4_4_4_4",
        0,
        "range_check_4_4_4_4_state",
        0,
        312,
        4,
    ),
    (
        "range_check_4_4_4_4",
        1,
        "range_check_4_4_4_4_state",
        0,
        316,
        4,
    ),
    (
        "range_check_4_4_4_4",
        2,
        "range_check_4_4_4_4_state",
        0,
        320,
        4,
    ),
    (
        "range_check_4_4_4_4",
        3,
        "range_check_4_4_4_4_state",
        0,
        324,
        4,
    ),
    (
        "range_check_4_4_4_4",
        4,
        "range_check_4_4_4_4_state",
        0,
        328,
        4,
    ),
    (
        "range_check_4_4_4_4",
        5,
        "range_check_4_4_4_4_state",
        0,
        332,
        4,
    ),
    ("range_check_4_4", 0, "range_check_4_4_state", 0, 336, 2),
    ("range_check_4_4", 1, "range_check_4_4_state", 0, 338, 2),
    ("range_check_4_4", 2, "range_check_4_4_state", 0, 340, 2),
    (
        "poseidon_3_partial_rounds_chain",
        0,
        "poseidon_3_partial_rounds_chain_state",
        0,
        342,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        1,
        "poseidon_3_partial_rounds_chain_state",
        0,
        384,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        2,
        "poseidon_3_partial_rounds_chain_state",
        0,
        426,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        3,
        "poseidon_3_partial_rounds_chain_state",
        0,
        468,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        4,
        "poseidon_3_partial_rounds_chain_state",
        0,
        510,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        5,
        "poseidon_3_partial_rounds_chain_state",
        0,
        552,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        6,
        "poseidon_3_partial_rounds_chain_state",
        0,
        594,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        7,
        "poseidon_3_partial_rounds_chain_state",
        0,
        636,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        8,
        "poseidon_3_partial_rounds_chain_state",
        0,
        678,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        9,
        "poseidon_3_partial_rounds_chain_state",
        0,
        720,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        10,
        "poseidon_3_partial_rounds_chain_state",
        0,
        762,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        11,
        "poseidon_3_partial_rounds_chain_state",
        0,
        804,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        12,
        "poseidon_3_partial_rounds_chain_state",
        0,
        846,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        13,
        "poseidon_3_partial_rounds_chain_state",
        0,
        888,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        14,
        "poseidon_3_partial_rounds_chain_state",
        0,
        930,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        15,
        "poseidon_3_partial_rounds_chain_state",
        0,
        972,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        16,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1014,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        17,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1056,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        18,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1098,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        19,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1140,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        20,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1182,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        21,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1224,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        22,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1266,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        23,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1308,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        24,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1350,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        25,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1392,
        42,
    ),
    (
        "poseidon_3_partial_rounds_chain",
        26,
        "poseidon_3_partial_rounds_chain_state",
        0,
        1434,
        42,
    ),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "memory_id_to_big_0",
        "mults_0",
        false,
        "memory_id_to_big_1",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_2",
        "mults_0",
        false,
        "poseidon_full_round_chain_3",
        "mults_0",
        true,
    ),
    (
        "poseidon_full_round_chain_4",
        "mults_0",
        false,
        "range_check_252_width_27_5",
        "mults_0",
        false,
    ),
    (
        "range_check_252_width_27_6",
        "mults_0",
        false,
        "cube_252_7",
        "mults_0",
        false,
    ),
    (
        "range_check_3_3_3_3_3_8",
        "mults_0",
        false,
        "range_check_3_3_3_3_3_9",
        "mults_0",
        false,
    ),
    (
        "cube_252_10",
        "mults_0",
        false,
        "range_check_4_4_4_4_11",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_12",
        "mults_0",
        false,
        "range_check_4_4_13",
        "mults_0",
        false,
    ),
    (
        "poseidon_3_partial_rounds_chain_14",
        "mults_0",
        true,
        "poseidon_3_partial_rounds_chain_15",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_16",
        "mults_0",
        false,
        "range_check_4_4_4_4_17",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_18",
        "mults_0",
        false,
        "range_check_4_4_4_4_19",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_20",
        "mults_0",
        false,
        "range_check_4_4_21",
        "mults_0",
        false,
    ),
    (
        "poseidon_full_round_chain_22",
        "mults_0",
        true,
        "poseidon_full_round_chain_23",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_24",
        "mults_0",
        false,
        "memory_id_to_big_25",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_26",
        "mults_0",
        false,
        "poseidon_aggregator_27",
        "mults_1",
        true,
    ),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.memory_id_to_big_0.iter().flatten().copied().collect(),
        ld.memory_id_to_big_1.iter().flatten().copied().collect(),
        ld.memory_id_to_big_2.iter().flatten().copied().collect(),
        ld.poseidon_full_round_chain_3
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_full_round_chain_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_252_width_27_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_252_width_27_6
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.cube_252_7.iter().flatten().copied().collect(),
        ld.range_check_3_3_3_3_3_8
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_9
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.cube_252_10.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_11
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_4_4_12
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_13.iter().flatten().copied().collect(),
        ld.poseidon_3_partial_rounds_chain_14
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_3_partial_rounds_chain_15
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_4_4_16
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_4_4_17
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_18.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_19
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_4_4_20
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_21.iter().flatten().copied().collect(),
        ld.poseidon_full_round_chain_22
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_full_round_chain_23
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_24.iter().flatten().copied().collect(),
        ld.memory_id_to_big_25.iter().flatten().copied().collect(),
        ld.memory_id_to_big_26.iter().flatten().copied().collect(),
        ld.poseidon_aggregator_27
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.mults_0.clone(),
        ld.mults_1.clone(),
    ]
}

#[cfg(test)]
pub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator) -> Vec<Vec<PackedM31>> {
    lookup_data_flat(&ig.lookup_data)
}

fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
    vec![
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
        sci.poseidon_full_round_chain[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[6]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_full_round_chain[7]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_252_width_27[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_252_width_27[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.cube_252[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.cube_252[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_4_4[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_4_4[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[6]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[7]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[8]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[9]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[10]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[11]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[12]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[13]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[14]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[15]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[16]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[17]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[18]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[19]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[20]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[21]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[22]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[23]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[24]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[25]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_3_partial_rounds_chain[26]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2[0].get_m31(0).into_simd(),
                    t.2[0].get_m31(1).into_simd(),
                    t.2[0].get_m31(2).into_simd(),
                    t.2[0].get_m31(3).into_simd(),
                    t.2[0].get_m31(4).into_simd(),
                    t.2[0].get_m31(5).into_simd(),
                    t.2[0].get_m31(6).into_simd(),
                    t.2[0].get_m31(7).into_simd(),
                    t.2[0].get_m31(8).into_simd(),
                    t.2[0].get_m31(9).into_simd(),
                    t.2[1].get_m31(0).into_simd(),
                    t.2[1].get_m31(1).into_simd(),
                    t.2[1].get_m31(2).into_simd(),
                    t.2[1].get_m31(3).into_simd(),
                    t.2[1].get_m31(4).into_simd(),
                    t.2[1].get_m31(5).into_simd(),
                    t.2[1].get_m31(6).into_simd(),
                    t.2[1].get_m31(7).into_simd(),
                    t.2[1].get_m31(8).into_simd(),
                    t.2[1].get_m31(9).into_simd(),
                    t.2[2].get_m31(0).into_simd(),
                    t.2[2].get_m31(1).into_simd(),
                    t.2[2].get_m31(2).into_simd(),
                    t.2[2].get_m31(3).into_simd(),
                    t.2[2].get_m31(4).into_simd(),
                    t.2[2].get_m31(5).into_simd(),
                    t.2[2].get_m31(6).into_simd(),
                    t.2[2].get_m31(7).into_simd(),
                    t.2[2].get_m31(8).into_simd(),
                    t.2[2].get_m31(9).into_simd(),
                    t.2[3].get_m31(0).into_simd(),
                    t.2[3].get_m31(1).into_simd(),
                    t.2[3].get_m31(2).into_simd(),
                    t.2[3].get_m31(3).into_simd(),
                    t.2[3].get_m31(4).into_simd(),
                    t.2[3].get_m31(5).into_simd(),
                    t.2[3].get_m31(6).into_simd(),
                    t.2[3].get_m31(7).into_simd(),
                    t.2[3].get_m31(8).into_simd(),
                    t.2[3].get_m31(9).into_simd(),
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
    mults: Vec<Vec<PackedM31>>,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    poseidon_full_round_chain_state: &poseidon_full_round_chain::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    poseidon_3_partial_rounds_chain_state: &poseidon_3_partial_rounds_chain::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        mults.clone(),
        memory_id_to_big_state,
        poseidon_full_round_chain_state,
        range_check_252_width_27_state,
        cube_252_state,
        range_check_3_3_3_3_3_state,
        range_check_4_4_4_4_state,
        range_check_4_4_state,
        poseidon_3_partial_rounds_chain_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        mults,
        memory_id_to_big_state,
        poseidon_full_round_chain_state,
        range_check_252_width_27_state,
        cube_252_state,
        range_check_3_3_3_3_3_state,
        range_check_4_4_4_4_state,
        range_check_4_4_state,
        poseidon_3_partial_rounds_chain_state,
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
        lookup_data: ld_o,
    }
    .write_interaction_trace(&common);
    let (raw_g, _) = InteractionClaimGenerator {
        log_size,
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
    memory_id_to_big_0: Vec<[PackedM31; 30]>,
    memory_id_to_big_1: Vec<[PackedM31; 30]>,
    memory_id_to_big_2: Vec<[PackedM31; 30]>,
    poseidon_full_round_chain_3: Vec<[PackedM31; 33]>,
    poseidon_full_round_chain_4: Vec<[PackedM31; 33]>,
    range_check_252_width_27_5: Vec<[PackedM31; 11]>,
    range_check_252_width_27_6: Vec<[PackedM31; 11]>,
    cube_252_7: Vec<[PackedM31; 21]>,
    range_check_3_3_3_3_3_8: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_9: Vec<[PackedM31; 6]>,
    cube_252_10: Vec<[PackedM31; 21]>,
    range_check_4_4_4_4_11: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_12: Vec<[PackedM31; 5]>,
    range_check_4_4_13: Vec<[PackedM31; 3]>,
    poseidon_3_partial_rounds_chain_14: Vec<[PackedM31; 43]>,
    poseidon_3_partial_rounds_chain_15: Vec<[PackedM31; 43]>,
    range_check_4_4_4_4_16: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_17: Vec<[PackedM31; 5]>,
    range_check_4_4_18: Vec<[PackedM31; 3]>,
    range_check_4_4_4_4_19: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_20: Vec<[PackedM31; 5]>,
    range_check_4_4_21: Vec<[PackedM31; 3]>,
    poseidon_full_round_chain_22: Vec<[PackedM31; 33]>,
    poseidon_full_round_chain_23: Vec<[PackedM31; 33]>,
    memory_id_to_big_24: Vec<[PackedM31; 30]>,
    memory_id_to_big_25: Vec<[PackedM31; 30]>,
    memory_id_to_big_26: Vec<[PackedM31; 30]>,
    poseidon_aggregator_27: Vec<[PackedM31; 7]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    memory_id_to_big_0: 30,
    memory_id_to_big_1: 30,
    memory_id_to_big_2: 30,
    poseidon_full_round_chain_3: 33,
    poseidon_full_round_chain_4: 33,
    range_check_252_width_27_5: 11,
    range_check_252_width_27_6: 11,
    cube_252_7: 21,
    range_check_3_3_3_3_3_8: 6,
    range_check_3_3_3_3_3_9: 6,
    cube_252_10: 21,
    range_check_4_4_4_4_11: 5,
    range_check_4_4_4_4_12: 5,
    range_check_4_4_13: 3,
    poseidon_3_partial_rounds_chain_14: 43,
    poseidon_3_partial_rounds_chain_15: 43,
    range_check_4_4_4_4_16: 5,
    range_check_4_4_4_4_17: 5,
    range_check_4_4_18: 3,
    range_check_4_4_4_4_19: 5,
    range_check_4_4_4_4_20: 5,
    range_check_4_4_21: 3,
    poseidon_full_round_chain_22: 33,
    poseidon_full_round_chain_23: 33,
    memory_id_to_big_24: 30,
    memory_id_to_big_25: 30,
    memory_id_to_big_26: 30,
    poseidon_aggregator_27: 7,
    mults_0: scalar,
    mults_1: scalar,
}
// === END relation_lookup_source_codegen ===
impl InteractionClaimGenerator {
    pub fn write_interaction_trace(
        self,
        common_lookup_elements: &relations::CommonLookupElements,
    ) -> (RawLogupTrace, impl FnOnce(SecureField) -> InteractionClaim) {
        let mut logup_gen = unsafe { RawLogupTraceGenerator::uninitialized(self.log_size) };

        // Sum logup terms in pairs.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_0,
            &self.lookup_data.memory_id_to_big_1,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_2,
            &self.lookup_data.poseidon_full_round_chain_3,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom1 * *mult0 - denom0 * *mult1, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.poseidon_full_round_chain_4,
            &self.lookup_data.range_check_252_width_27_5,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_252_width_27_6,
            &self.lookup_data.cube_252_7,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_3_3_3_3_3_8,
            &self.lookup_data.range_check_3_3_3_3_3_9,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.cube_252_10,
            &self.lookup_data.range_check_4_4_4_4_11,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_4_4_4_4_12,
            &self.lookup_data.range_check_4_4_13,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.poseidon_3_partial_rounds_chain_14,
            &self.lookup_data.poseidon_3_partial_rounds_chain_15,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 - denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_4_4_4_4_16,
            &self.lookup_data.range_check_4_4_4_4_17,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_4_4_18,
            &self.lookup_data.range_check_4_4_4_4_19,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_4_4_4_4_20,
            &self.lookup_data.range_check_4_4_21,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.poseidon_full_round_chain_22,
            &self.lookup_data.poseidon_full_round_chain_23,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 - denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_24,
            &self.lookup_data.memory_id_to_big_25,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_26,
            &self.lookup_data.poseidon_aggregator_27,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom1 * *mult0 - denom0 * *mult1, denom0 * denom1);
            });
        col_gen.finalize_col();

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
