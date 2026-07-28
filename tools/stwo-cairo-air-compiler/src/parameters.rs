use anyhow::{Result, anyhow, ensure};
use cairo_air::relations::CommonLookupElements;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use crate::program::ExtParameterPair;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExtSource {
    LookupZ,
    LookupAlphaPower(u32),
    LookupAlphaPowerScaled { power: u32, scale: BaseField },
    ClaimedSumScaled,
}

pub struct LookupProbe {
    pub elements: CommonLookupElements,
    z: SecureField,
    alpha_powers: Vec<SecureField>,
}

impl LookupProbe {
    pub fn from_seed(seed: &[u32]) -> Result<Self> {
        let mut channel = Blake2sChannel::default();
        channel.mix_u32s(seed);
        let mut mirror = channel.clone();
        let draws = mirror.draw_secure_felts(2);
        let [z, alpha]: [SecureField; 2] = draws
            .try_into()
            .map_err(|_| anyhow!("lookup channel did not return two draws"))?;
        let mut current = SecureField::from(1u32);
        let alpha_powers = (0..128)
            .map(|_| {
                let value = current;
                current *= alpha;
                value
            })
            .collect();
        Ok(Self {
            elements: CommonLookupElements::draw(&mut channel),
            z,
            alpha_powers,
        })
    }
}

pub fn classify(
    component: &str,
    log_size: u32,
    claimed_sum: SecureField,
    probe_claimed_sum: SecureField,
    lookup: &LookupProbe,
    probe_lookup: &LookupProbe,
    parameters: &[ExtParameterPair],
) -> Result<Vec<ExtSource>> {
    let mut dynamic = Vec::with_capacity(lookup.alpha_powers.len() + 2);
    dynamic.push(((lookup.z, probe_lookup.z), ExtSource::LookupZ));
    for (power, (&value, &probe)) in lookup
        .alpha_powers
        .iter()
        .zip(&probe_lookup.alpha_powers)
        .enumerate()
        .skip(1)
    {
        dynamic.push((
            (value, probe),
            ExtSource::LookupAlphaPower(u32::try_from(power)?),
        ));
    }
    let rows = BaseField::from_u32_unchecked(1u32 << log_size);
    dynamic.push((
        (claimed_sum / rows, probe_claimed_sum / rows),
        ExtSource::ClaimedSumScaled,
    ));
    for (index, (pair, _)) in dynamic.iter().enumerate() {
        ensure!(
            pair.0 != pair.1
                && !dynamic[..index]
                    .iter()
                    .any(|(candidate, _)| candidate == pair),
            "{component}: ambiguous dynamic AIR parameter probe"
        );
    }

    parameters
        .iter()
        .enumerate()
        .map(|(slot, parameter)| {
            let pair = (parameter.primary, parameter.probe);
            let exact = dynamic
                .iter()
                .filter_map(|&(candidate, source)| (candidate == pair).then_some(source));
            let scaled = probe_lookup
                .alpha_powers
                .iter()
                .copied()
                .enumerate()
                .skip(1)
                .filter_map(|(power_index, probe_power)| {
                    if probe_power
                        .to_m31_array()
                        .iter()
                        .all(|coordinate| coordinate.0 == 0)
                    {
                        return None;
                    }
                    let coordinates = (pair.1 / probe_power).to_m31_array();
                    if coordinates[1..].iter().any(|coordinate| coordinate.0 != 0)
                        || coordinates[0].0 <= 1
                    {
                        return None;
                    }
                    let scale = coordinates[0];
                    let candidate = (
                        lookup.alpha_powers[power_index] * scale,
                        probe_power * scale,
                    );
                    let power = u32::try_from(power_index).ok()?;
                    (candidate == pair)
                        .then_some(ExtSource::LookupAlphaPowerScaled { power, scale })
                });
            let matches = exact.chain(scaled).collect::<Vec<_>>();
            match matches.as_slice() {
                [source] => Ok(*source),
                [] => Err(anyhow!(
                    "{component}: unclassified extension parameter {slot}: {:?} -> {:?}",
                    pair.0,
                    pair.1
                )),
                _ => Err(anyhow!(
                    "{component}: ambiguous extension parameter {slot}: {:?} -> {:?}",
                    pair.0,
                    pair.1
                )),
            }
        })
        .collect()
}
