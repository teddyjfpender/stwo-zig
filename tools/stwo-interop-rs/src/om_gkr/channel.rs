//! Diagnostic public-state replay, NOT admission of an execution transcript.
use super::{Channel, SecureField as O};
use stwo::core::{
    channel::{Blake2sChannel, Channel as NativeChannel},
    fields::m31::P,
    vcs::blake2_hash::Blake2sHash,
};
pub struct RawMod {
    pub inner: Blake2sChannel,
    pub draws: u32,
}
impl RawMod {
    pub fn seeded(digest: [u8; 32], draws: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(draws <= 1 << 20, "initial draw bound");
        let mut inner = Blake2sChannel::default();
        inner.update_digest(Blake2sHash(digest));
        for _ in 0..draws {
            inner.draw_u32s();
        }
        Ok(Self { inner, draws })
    }
    pub fn digest(&self) -> [u8; 32] {
        self.inner.digest().0
    }
}
impl Channel for RawMod {
    fn mix_felts(&mut self, v: &[O]) {
        let words: Vec<u32> = v.iter().flat_map(|x| x.words()).collect();
        self.inner.mix_u32s(&words);
        self.draws = 0;
    }
    fn draw_secure_felt(&mut self) -> O {
        assert!(self.draws < 1 << 20, "draw budget");
        let words = self.inner.draw_u32s();
        self.draws += 1;
        O::from_words(std::array::from_fn(|i| words[i] % P))
    }
}
