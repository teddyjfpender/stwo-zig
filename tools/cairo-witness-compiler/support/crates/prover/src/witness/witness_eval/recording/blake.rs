use super::{DeduceKind, RecVal, RecordingWitnessEval};

impl RecordingWitnessEval {
    pub(super) fn record_blake_round(
        &mut self,
        chain: RecVal,
        round: RecVal,
        state: [RecVal; 16],
        message_pointer: RecVal,
    ) -> (RecVal, RecVal, ([RecVal; 16], RecVal)) {
        let args = (|| {
            let mut args = Self::plain_args(&[chain, round])?;
            args.extend(Self::plain_args(&state)?);
            args.extend(Self::plain_args(&[message_pointer])?);
            Some(args)
        })();
        let Some(args) = args else {
            let poison = self.poison("deduce_blake_round");
            return (poison, poison, ([poison; 16], poison));
        };
        let outputs = self.recorder.deduce(DeduceKind::BlakeRound, &args);
        let value = |index| RecVal::Ok(outputs[index]);
        (
            value(0),
            value(1),
            (std::array::from_fn(|index| value(index + 2)), value(18)),
        )
    }
}
