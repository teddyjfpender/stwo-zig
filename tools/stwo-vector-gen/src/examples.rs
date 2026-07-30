use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::FieldExpOps;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};

use crate::common::*;
use crate::model::*;

pub(crate) fn generate_example_state_machine_trace_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleStateMachineTraceVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_size = 2 + ((next_u64(state) as u32) % 9);
        let n = 1usize << log_size;
        let inc_index = (next_u64(state) as usize) % 2;

        let initial_state = [sample_m31(state, false), sample_m31(state, false)];
        let mut curr_state = initial_state;

        let mut columns = vec![vec![M31::from(0); n], vec![M31::from(0); n]];
        for i in 0..n {
            let idx = bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
            columns[0][idx] = curr_state[0];
            columns[1][idx] = curr_state[1];
            curr_state[inc_index] += M31::from(1);
        }

        out.push(ExampleStateMachineTraceVector {
            log_size,
            initial_state: encode_state(initial_state),
            inc_index,
            columns: columns
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
        });
    }
    out
}

pub(crate) fn generate_example_state_machine_transition_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleStateMachineTransitionVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_n_rows = 1 + ((next_u64(state) as u32) % 30);
        let initial_state = [sample_m31(state, false), sample_m31(state, false)];

        let mut intermediate_state = initial_state;
        intermediate_state[0] += M31::from(1u32 << log_n_rows);

        let mut final_state = intermediate_state;
        final_state[1] += M31::from(1u32 << (log_n_rows - 1));

        out.push(ExampleStateMachineTransitionVector {
            log_n_rows,
            initial_state: encode_state(initial_state),
            intermediate_state: encode_state(intermediate_state),
            final_state: encode_state(final_state),
        });
    }
    out
}

pub(crate) fn generate_example_state_machine_claimed_sum_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleStateMachineClaimedSumVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let log_size = 2 + ((next_u64(state) as u32) % 9);
        let n = 1usize << log_size;
        let inc_index = (next_u64(state) as usize) % 2;
        let initial_state = [sample_m31(state, false), sample_m31(state, false)];

        let z = sample_qm31(state, false);
        let alpha = sample_qm31(state, false);

        let mut curr_state = initial_state;
        let mut claimed_sum = QM31::from(0);
        let mut degenerate = false;

        for _ in 0..n {
            let input = combine_state(curr_state, z, alpha);
            curr_state[inc_index] += M31::from(1);
            let output = combine_state(curr_state, z, alpha);

            if input == QM31::from(0) || output == QM31::from(0) {
                degenerate = true;
                break;
            }

            let numerator = output - input;
            let denominator = input * output;
            claimed_sum += numerator / denominator;
        }
        if degenerate {
            continue;
        }

        let mut final_state = initial_state;
        final_state[inc_index] += M31::from(n as u32);
        let initial_combined = combine_state(initial_state, z, alpha);
        let final_combined = combine_state(final_state, z, alpha);
        if initial_combined == QM31::from(0) || final_combined == QM31::from(0) {
            continue;
        }

        let telescoping_claim = initial_combined.inverse() - final_combined.inverse();

        out.push(ExampleStateMachineClaimedSumVector {
            log_size,
            initial_state: encode_state(initial_state),
            inc_index,
            z: encode_qm31(z),
            alpha: encode_qm31(alpha),
            claimed_sum: encode_qm31(claimed_sum),
            telescoping_claim: encode_qm31(telescoping_claim),
        });
    }
    out
}

pub(crate) fn generate_example_state_machine_lookup_draw_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleStateMachineLookupDrawVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mix_u64 = next_u64(state);
        let n_u32s = 1 + ((next_u64(state) as usize) % 6);
        let mix_u32s = (0..n_u32s)
            .map(|_| next_u64(state) as u32)
            .collect::<Vec<_>>();

        let mut channel = Blake2sChannel::default();
        channel.mix_u64(mix_u64);
        channel.mix_u32s(&mix_u32s);
        let elements = channel.draw_secure_felts(2);
        let [z, alpha]: [QM31; 2] = elements.try_into().unwrap();

        out.push(ExampleStateMachineLookupDrawVector {
            mix_u64,
            mix_u32s,
            z: encode_qm31(z),
            alpha: encode_qm31(alpha),
        });
    }
    out
}

pub(crate) fn generate_example_state_machine_statement_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleStateMachineStatementVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let log_n_rows = 2 + ((next_u64(state) as u32) % 9);
        let initial_state = [sample_m31(state, false), sample_m31(state, false)];
        let z = sample_qm31(state, false);
        let alpha = sample_qm31(state, false);

        let mut intermediate_state = initial_state;
        intermediate_state[0] += M31::from(1u32 << log_n_rows);

        let mut final_state = intermediate_state;
        final_state[1] += M31::from(1u32 << (log_n_rows - 1));

        let initial_comb = combine_state(initial_state, z, alpha);
        let intermediate_comb = combine_state(intermediate_state, z, alpha);
        let final_comb = combine_state(final_state, z, alpha);
        if initial_comb == QM31::from(0)
            || intermediate_comb == QM31::from(0)
            || final_comb == QM31::from(0)
        {
            continue;
        }

        let x_axis_claimed_sum = initial_comb.inverse() - intermediate_comb.inverse();
        let y_axis_claimed_sum = intermediate_comb.inverse() - final_comb.inverse();

        out.push(ExampleStateMachineStatementVector {
            log_n_rows,
            initial_state: encode_state(initial_state),
            z: encode_qm31(z),
            alpha: encode_qm31(alpha),
            intermediate_state: encode_state(intermediate_state),
            final_state: encode_state(final_state),
            x_axis_claimed_sum: encode_qm31(x_axis_claimed_sum),
            y_axis_claimed_sum: encode_qm31(y_axis_claimed_sum),
        });
    }
    out
}

pub(crate) fn generate_example_xor_is_first_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleXorIsFirstVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_size = 1 + ((next_u64(state) as u32) % 10);
        let n = 1usize << log_size;
        let mut values = vec![0u32; n];
        values[0] = 1;

        out.push(ExampleXorIsFirstVector { log_size, values });
    }
    out
}

pub(crate) fn generate_example_xor_is_step_with_offset_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleXorIsStepWithOffsetVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_size = 1 + ((next_u64(state) as u32) % 10);
        let n = 1usize << log_size;
        let log_step = (next_u64(state) as u32) % (log_size + 1);
        let step = 1usize << log_step;
        let offset = (next_u64(state) as usize) % (n.saturating_mul(2).max(1));

        let mut values = vec![0u32; n];
        let mut i = offset % step;
        while i < n {
            let circle_domain_idx = coset_index_to_circle_domain_index(i, log_size);
            let bit_rev_idx = bit_reverse_index(circle_domain_idx, log_size);
            values[bit_rev_idx] = 1;
            i += step;
        }

        out.push(ExampleXorIsStepWithOffsetVector {
            log_size,
            log_step,
            offset,
            values,
        });
    }
    out
}

pub(crate) fn generate_example_wide_fibonacci_trace_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExampleWideFibonacciTraceVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_n_rows = 2 + ((next_u64(state) as u32) % 9);
        let sequence_len = 2 + ((next_u64(state) as u32) % 15);
        let n = 1usize << log_n_rows;
        let n_cols = sequence_len as usize;

        let mut trace = vec![vec![M31::from(0); n]; n_cols];
        for row in 0..n {
            let bit_rev = bit_reverse_index(
                coset_index_to_circle_domain_index(row, log_n_rows),
                log_n_rows,
            );

            let mut a = M31::from(1);
            let mut b = M31::from(row as u32);
            trace[0][bit_rev] = a;
            trace[1][bit_rev] = b;
            for col in trace.iter_mut().skip(2) {
                let c = a.square() + b.square();
                col[bit_rev] = c;
                a = b;
                b = c;
            }
        }

        out.push(ExampleWideFibonacciTraceVector {
            log_n_rows,
            sequence_len,
            columns: trace
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect::<Vec<u32>>())
                .collect(),
        });
    }
    out
}

pub(crate) fn generate_example_plonk_trace_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<ExamplePlonkTraceVector> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let log_n_rows = 2 + ((next_u64(state) as u32) % 9);
        let n = 1usize << log_n_rows;

        let mut preprocessed = vec![vec![M31::from(0); n]; 4];
        let mut main = vec![vec![M31::from(0); n]; 4];
        let mut fib = vec![M31::from(0); n + 2];
        fib[0] = M31::from(1);
        fib[1] = M31::from(1);
        for i in 2..fib.len() {
            fib[i] = fib[i - 1] + fib[i - 2];
        }

        for i in 0..n {
            preprocessed[0][i] = M31::from(i as u32);
            preprocessed[1][i] = M31::from((i + 1) as u32);
            preprocessed[2][i] = M31::from((i + 2) as u32);
            preprocessed[3][i] = M31::from(1);

            main[0][i] = M31::from(1);
            main[1][i] = fib[i];
            main[2][i] = fib[i + 1];
            main[3][i] = fib[i + 2];
        }
        if n >= 2 {
            main[0][n - 1] = M31::from(0);
            main[0][n - 2] = M31::from(1);
        }

        out.push(ExamplePlonkTraceVector {
            log_n_rows,
            preprocessed: preprocessed
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect::<Vec<u32>>())
                .collect(),
            main: main
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect::<Vec<u32>>())
                .collect(),
        });
    }
    out
}
