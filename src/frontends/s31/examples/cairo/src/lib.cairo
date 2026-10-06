// The computation performed by affine4.s31.json. The executable publishes the
// same four inputs and four results as the S31 proof's eight public words.
pub fn affine4(x0: u16, x1: u16, x2: u16, x3: u16) -> (u32, u32, u32, u32) {
    let a: u32 = x0.into();
    let b: u32 = x1.into();
    let c: u32 = x2.into();
    let d: u32 = x3.into();
    (7_u32 * a + 11_u32, 7_u32 * b + 11_u32, 7_u32 * c + 11_u32, 7_u32 * d + 11_u32)
}

#[executable]
fn main(x0: u16, x1: u16, x2: u16, x3: u16) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    let (y0, y1, y2, y3) = affine4(x0, x1, x2, x3);
    (x0.into(), x1.into(), x2.into(), x3.into(), y0, y1, y2, y3)
}

#[cfg(test)]
mod tests {
    use super::affine4;

    #[test]
    fn same_example_values() {
        assert_eq!(affine4(1, 2, 3, 65535), (18, 25, 32, 458756));
    }
}
