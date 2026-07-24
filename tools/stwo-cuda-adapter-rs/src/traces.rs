use crate::model::{
    BlakeStatement, PoseidonStatement, BLAKE_ROUND_INPUT_FELTS, POSEIDON_COLUMNS,
    POSEIDON_HALF_FULL_ROUNDS, POSEIDON_INSTANCES_PER_ROW, POSEIDON_LOG_INSTANCES_PER_ROW,
    POSEIDON_PARTIAL_ROUNDS, POSEIDON_STATE,
};
use anyhow::{anyhow, bail, Result};
use num_traits::{One, Zero};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::ColumnOps;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

pub(crate) fn backend_eval<B: ColumnOps<M31>>(
    log_size: u32,
    values: Vec<M31>,
) -> CircleEvaluation<B, M31, BitReversedOrder> {
    CircleEvaluation::new(
        CanonicCoset::new(log_size).circle_domain(),
        values.into_iter().collect(),
    )
}

pub(crate) fn checked_pow2(log_size: u32) -> Result<usize> {
    if log_size >= usize::BITS {
        bail!("invalid log_size {log_size}");
    }
    Ok(1usize << log_size)
}

pub(crate) fn gen_is_first(log_size: u32) -> Result<Vec<M31>> {
    let n = checked_pow2(log_size)?;
    let mut values = vec![M31::zero(); n];
    values[0] = M31::one();
    Ok(values)
}

pub(crate) fn gen_trace(
    log_size: u32,
    initial_state: [M31; 2],
    inc_index: usize,
) -> Result<[Vec<M31>; 2]> {
    if inc_index >= 2 {
        bail!("invalid inc_index {inc_index}");
    }
    let n = checked_pow2(log_size)?;

    let mut col0 = vec![M31::zero(); n];
    let mut col1 = vec![M31::zero(); n];

    let mut curr_state = initial_state;
    for i in 0..n {
        let bit_rev_index =
            bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
        col0[bit_rev_index] = curr_state[0];
        col1[bit_rev_index] = curr_state[1];
        curr_state[inc_index] += M31::one();
    }

    Ok([col0, col1])
}

pub(crate) fn gen_wide_fibonacci_trace(
    log_n_rows: u32,
    sequence_len: u32,
) -> Result<Vec<Vec<M31>>> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows");
    }
    if sequence_len < 2 {
        bail!("invalid sequence_len");
    }

    let n = checked_pow2(log_n_rows)?;
    let n_cols = sequence_len as usize;
    let mut trace = vec![vec![M31::zero(); n]; n_cols];

    for row in 0..n {
        let bit_rev_index = bit_reverse_index(
            coset_index_to_circle_domain_index(row, log_n_rows),
            log_n_rows,
        );
        let mut a = M31::one();
        let mut b = M31::from(row as u32);
        trace[0][bit_rev_index] = a;
        trace[1][bit_rev_index] = b;
        for col in trace.iter_mut().skip(2) {
            let c = a.square() + b.square();
            col[bit_rev_index] = c;
            a = b;
            b = c;
        }
    }

    Ok(trace)
}

pub(crate) fn gen_is_step_with_offset(
    log_size: u32,
    log_step: u32,
    offset: usize,
) -> Result<Vec<M31>> {
    if log_step > log_size {
        bail!("invalid step");
    }
    let n = checked_pow2(log_size)?;
    let step = checked_pow2(log_step)?;

    let mut values = vec![M31::zero(); n];
    let mut i = offset % step;
    while i < n {
        let circle_domain_index = coset_index_to_circle_domain_index(i, log_size);
        let bit_rev_index = bit_reverse_index(circle_domain_index, log_size);
        values[bit_rev_index] = M31::one();
        i += step;
    }

    Ok(values)
}

pub(crate) fn gen_xor_main(log_size: u32) -> Result<Vec<M31>> {
    let n = checked_pow2(log_size)?;
    let mut values = vec![M31::zero(); n];
    for i in 0..n {
        let circle_domain_index = coset_index_to_circle_domain_index(i, log_size);
        let bit_rev_index = bit_reverse_index(circle_domain_index, log_size);
        values[bit_rev_index] = if (i & 1) == 0 {
            M31::one()
        } else {
            M31::zero()
        };
    }
    Ok(values)
}

pub(crate) fn gen_plonk_trace(log_n_rows: u32) -> Result<([Vec<M31>; 4], [Vec<M31>; 4])> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }
    let n = checked_pow2(log_n_rows)?;

    let mut preprocessed = std::array::from_fn(|_| vec![M31::zero(); n]);
    let mut main = std::array::from_fn(|_| vec![M31::zero(); n]);

    let mut fib = vec![M31::zero(); n + 2];
    fib[0] = M31::one();
    fib[1] = M31::one();
    for i in 2..fib.len() {
        fib[i] = fib[i - 1] + fib[i - 2];
    }

    for i in 0..n {
        preprocessed[0][i] = M31::from(i as u32);
        preprocessed[1][i] = M31::from((i + 1) as u32);
        preprocessed[2][i] = M31::from((i + 2) as u32);
        preprocessed[3][i] = M31::one();

        main[0][i] = M31::one();
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }

    if n >= 2 {
        main[0][n - 1] = M31::zero();
        main[0][n - 2] = M31::one();
    }

    Ok((preprocessed, main))
}

pub(crate) fn poseidon_log_n_rows(statement: PoseidonStatement) -> Result<u32> {
    if statement.log_n_instances < POSEIDON_LOG_INSTANCES_PER_ROW {
        bail!("invalid poseidon log_n_instances");
    }
    let log_n_rows = statement.log_n_instances - POSEIDON_LOG_INSTANCES_PER_ROW;
    if log_n_rows >= 31 {
        bail!("invalid poseidon log_n_rows");
    }
    Ok(log_n_rows)
}

pub(crate) fn poseidon_external_round_const(round: usize, state_i: usize) -> M31 {
    M31::from(((1234u64 + (round as u64 * 37) + state_i as u64) % P as u64) as u32)
}

pub(crate) fn poseidon_internal_round_const(round: usize) -> M31 {
    M31::from(((9876u64 + (round as u64 * 17)) % P as u64) as u32)
}

pub(crate) fn poseidon_pow5(x: M31) -> M31 {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

pub(crate) fn poseidon_apply_m4(x: [M31; 4]) -> [M31; 4] {
    let t0 = x[0] + x[1];
    let t02 = t0 + t0;
    let t1 = x[2] + x[3];
    let t12 = t1 + t1;
    let t2 = x[1] + x[1] + t1;
    let t3 = x[3] + x[3] + t0;
    let t4 = t12 + t12 + t3;
    let t5 = t02 + t02 + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
}

pub(crate) fn poseidon_apply_external_round_matrix(state: &mut [M31; POSEIDON_STATE]) {
    for i in 0..4 {
        let offset = i * 4;
        let mixed = poseidon_apply_m4([
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ]);
        state[offset] = mixed[0];
        state[offset + 1] = mixed[1];
        state[offset + 2] = mixed[2];
        state[offset + 3] = mixed[3];
    }

    for j in 0..4 {
        let s = state[j] + state[j + 4] + state[j + 8] + state[j + 12];
        for i in 0..4 {
            let idx = i * 4 + j;
            state[idx] += s;
        }
    }
}

pub(crate) fn poseidon_apply_internal_round_matrix(state: &mut [M31; POSEIDON_STATE]) {
    let sum = state
        .iter()
        .copied()
        .fold(M31::zero(), |acc, item| acc + item);
    for (i, value) in state.iter_mut().enumerate() {
        let coeff = M31::from_u32_unchecked(1u32 << ((i + 1) as u32));
        *value = *value * coeff + sum;
    }
}

pub(crate) fn gen_poseidon_trace(log_n_rows: u32) -> Result<Vec<Vec<M31>>> {
    if log_n_rows >= 31 {
        bail!("invalid poseidon log_n_rows");
    }
    let n = checked_pow2(log_n_rows)?;
    let mut trace = vec![vec![M31::zero(); n]; POSEIDON_COLUMNS];

    for row in 0..n {
        let mut col_index = 0usize;
        for rep_i in 0..POSEIDON_INSTANCES_PER_ROW {
            let mut state = std::array::from_fn(|state_i| {
                M31::from(((row * POSEIDON_STATE + state_i + rep_i) % P as usize) as u32)
            });

            for value in state {
                trace[col_index][row] = value;
                col_index += 1;
            }

            for round in 0..POSEIDON_HALF_FULL_ROUNDS {
                for (state_i, value) in state.iter_mut().enumerate() {
                    *value += poseidon_external_round_const(round, state_i);
                }
                poseidon_apply_external_round_matrix(&mut state);
                for value in state.iter_mut() {
                    *value = poseidon_pow5(*value);
                    trace[col_index][row] = *value;
                    col_index += 1;
                }
            }

            for round in 0..POSEIDON_PARTIAL_ROUNDS {
                state[0] += poseidon_internal_round_const(round);
                poseidon_apply_internal_round_matrix(&mut state);
                state[0] = poseidon_pow5(state[0]);
                trace[col_index][row] = state[0];
                col_index += 1;
            }

            for half_round in 0..POSEIDON_HALF_FULL_ROUNDS {
                let round = half_round + POSEIDON_HALF_FULL_ROUNDS;
                for (state_i, value) in state.iter_mut().enumerate() {
                    *value += poseidon_external_round_const(round, state_i);
                }
                poseidon_apply_external_round_matrix(&mut state);
                for value in state.iter_mut() {
                    *value = poseidon_pow5(*value);
                    trace[col_index][row] = *value;
                    col_index += 1;
                }
            }
        }
        debug_assert_eq!(col_index, POSEIDON_COLUMNS);
    }

    Ok(trace)
}

pub(crate) fn blake_validate_statement(statement: BlakeStatement) -> Result<()> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid blake log_n_rows");
    }
    if statement.n_rounds == 0 {
        bail!("invalid blake n_rounds");
    }
    let _ = blake_n_columns(statement)?;
    Ok(())
}

pub(crate) fn blake_n_columns(statement: BlakeStatement) -> Result<usize> {
    (statement.n_rounds as usize)
        .checked_mul(BLAKE_ROUND_INPUT_FELTS)
        .ok_or_else(|| anyhow!("blake column count overflow"))
}

pub(crate) fn blake_next_seed(seed: u64) -> u64 {
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

pub(crate) fn gen_blake_trace(statement: BlakeStatement) -> Result<Vec<Vec<M31>>> {
    blake_validate_statement(statement)?;
    let n = checked_pow2(statement.log_n_rows)?;
    let n_columns = blake_n_columns(statement)?;
    let mut trace = vec![vec![M31::zero(); n]; n_columns];

    for row in 0..n {
        let mut col_index = 0usize;
        let mut seed = row as u64 + 1;
        for round in 0..statement.n_rounds as usize {
            for cell in 0..BLAKE_ROUND_INPUT_FELTS {
                seed = blake_next_seed(seed);
                let mixed = seed
                    ^ ((round as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
                    ^ (((cell + 1) as u64).wrapping_mul(0x517c_c1b7_2722_0a95));
                trace[col_index][row] = M31::from((mixed % P as u64) as u32);
                col_index += 1;
            }
        }
        debug_assert_eq!(col_index, n_columns);
    }

    Ok(trace)
}
